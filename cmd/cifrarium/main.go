package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
	syncvault "github.com/teelabs/cifrarium/internal/sync"
	"github.com/zalando/go-keyring"
)

type stringList []string

type setupChoices struct {
	Provider bool
	Capture  bool
	Activate bool
}

var version = "dev"

func (s *stringList) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	commandName, commandArgs, commandErr := canonicalCommand(os.Args[1:])
	if commandErr != nil {
		fmt.Fprintln(os.Stderr, "cifrarium:", commandErr)
		os.Exit(2)
	}
	os.Args = append([]string{os.Args[0]}, commandArgs...)
	home, _ := os.UserHomeDir()
	fileProvider, providerConfigErr := loadProviderConfig(home)
	if providerConfigErr != nil && (commandName == "doctor" || commandName == "provider-health") {
		fmt.Fprintln(os.Stderr, "cifrarium:", providerConfigErr)
		os.Exit(1)
	}
	root := flag.String("root", "", "vault directory (setup only on a new computer; otherwise must match configuration)")
	cmd := commandName
	providerDirDefault := os.Getenv("CIFRARIUM_PROVIDER_DIR")
	if providerDirDefault == "" {
		providerDirDefault = fileProvider.Dir
	}
	providerRemoteDefault := os.Getenv("CIFRARIUM_PROVIDER_REMOTE")
	if providerRemoteDefault == "" {
		providerRemoteDefault = fileProvider.Remote
	}
	providerDir := flag.String("provider-dir", "", "local Git provider directory (resolved from protected configuration when omitted)")
	providerRemote := flag.String("provider-remote", "", "HTTPS GitHub remote URL (resolved from protected configuration when omitted)")
	verifyPrivate := flag.Bool("verify-private", false, "verify GitHub repository privacy with gh (provider-health only)")
	showVersion := flag.Bool("version", false, "print the Cifrarium version")
	nonInteractive := flag.Bool("non-interactive", false, "never prompt, capture, upload, or enable services")
	formatValue := flag.String("format", "human", "output format: human or json (status and doctor)")
	var recoveryValues stringList
	flag.Var(&recoveryValues, "recovery-share", "recovery share label:value (repeat twice before remote upload)")
	for _, name := range []string{"CIFRARIUM_RECOVERY_SHARE_1", "CIFRARIUM_RECOVERY_SHARE_2"} {
		if value := os.Getenv(name); value != "" {
			recoveryValues = append(recoveryValues, value)
		}
	}
	flag.Usage = func() { writeCifrariumUsage(flag.CommandLine.Output(), flag.CommandLine, "cifrarium") }
	flag.Parse()
	if *providerDir == "" {
		*providerDir = providerDirDefault
	}
	if *providerRemote == "" {
		*providerRemote = providerRemoteDefault
	}
	format, err := parseOutputFormat(*formatValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cifrarium:", err)
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if cmd == "help" {
		writeCifrariumUsage(os.Stdout, flag.CommandLine, "cifrarium")
		return
	}
	if *nonInteractive && commandMutatesOrHandlesSecrets(cmd) {
		fmt.Fprintf(os.Stderr, "cifrarium: --non-interactive cannot run %s because it may mutate local or remote state or handle secrets\n", cmd)
		os.Exit(1)
	}
	if cmd == "provider-setup" {
		if err := runProviderSetup(home, *root, *nonInteractive, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if cmd == "provider-health" {
		if *providerDir == "" || *providerRemote == "" {
			fmt.Fprintln(os.Stderr, "cifrarium: provider-health requires -provider-dir and -provider-remote")
			os.Exit(2)
		}
		gitProvider := provider.Git{Dir: *providerDir, Remote: *providerRemote}
		if err := gitProvider.CheckRemoteAccess(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(1)
		}
		if *verifyPrivate {
			if err := gitProvider.VerifyPrivate(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Printf("{\"provider\":\"github\",\"remote\":%q,\"status\":\"ok\"}\n", *providerRemote)
		return
	}
	if cmd == "doctor" {
		resolvedRoot, rootErr := resolveVaultRoot(cmd, *root, home)
		if rootErr != nil && !errors.Is(rootErr, errRootNotConfigured) {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", rootErr)
			os.Exit(1)
		}
		report, err := runDoctor(resolvedRoot, home, *providerDir, *providerRemote, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: doctor failed: %v\n", err)
			os.Exit(1)
		}
		if err := renderDoctor(os.Stdout, report, format); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(2)
		}
		if code := report.exitCode(); code != 0 {
			os.Exit(code)
		}
		return
	}
	if cmd == "setup" {
		configPath := config.ConfigPathForHome(home)
		_, configErr := config.LoadFrom(configPath)
		if errors.Is(configErr, os.ErrNotExist) && *nonInteractive {
			fmt.Fprintln(os.Stderr, "cifrarium: non-interactive setup cannot configure a new vault root; run cifrarium setup in a terminal")
			os.Exit(1)
		}
		setupRoot, err := resolveVaultRoot(cmd, *root, home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(1)
		}
		renderSetupDiagnostics(os.Stdout, setupRoot, home, configErr == nil)
		if err := runSetup(setupRoot, home, *nonInteractive, os.Stdout); err != nil {
			renderSetupFailure(os.Stderr, home, err)
			os.Exit(1)
		}
		return
	}
	resolvedRoot, err := resolveVaultRoot(cmd, *root, home)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root = &resolvedRoot
	keyringStore := store.NewKeyring()
	if cmd == "recover" {
		shares, err := parseRecoveryShares(recoveryValues)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := keyringStore.ImportRecovery(*root, shares); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: recovery failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("recovery imported; run status to verify the vault")
		return
	}
	op, sign, err := keyringStore.LoadExistingForRoot(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
		os.Exit(1)
	}
	if cmd == "migrate-catalog" {
		changed, err := store.MigrateCatalog(*root, op, sign.Public().(ed25519.PublicKey))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: catalog migration failed: %v\n", err)
			os.Exit(1)
		}
		if changed {
			fmt.Println("catalog migration complete; run status to verify the keyring guard")
		} else {
			fmt.Println("catalog already uses encrypted metadata")
		}
		return
	}
	v, err := store.OpenWithGuard(*root, op, sign, keyringStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: vault integrity check failed: %v\n", err)
		os.Exit(1)
	}
	switch cmd {
	case "status":
		report := statusReport{
			Vault:        *root,
			Configured:   true,
			VaultState:   "ready",
			KeyringState: "available",
			Snapshots:    countSnapshots(*root),
			Head:         v.Head,
			Pending:      countPending(*root, op),
			Signer:       fmt.Sprintf("%x", sign.Public()),
		}
		if err := renderStatus(os.Stdout, report, format); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(2)
		}
	case "recovery-shares":
		shares, err := store.RecoveryShares(op, sign)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, share := range shares {
			fmt.Printf("%s:%s\n", share.Label, share.Value)
		}
	case "snapshot":
		var all []store.Record
		for _, a := range []adapters.Adapter{adapters.Config{}, adapters.Zsh{}, adapters.Starship{}} {
			files, err := a.Collect(home)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, f := range files {
				all = append(all, store.Record{Path: f.Relative, Mode: uint32(f.Mode), Data: f.Data})
			}
		}
		m, err := v.Save(all)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("snapshot %s\n", m.Snapshot)
	case "daemon":
		socket := filepath.Join(*root, "cifrarium.sock")
		queuePath := filepath.Join(*root, "pending.queue")
		queue := &daemon.Queue{}
		if _, err := os.Stat(queuePath); err == nil {
			queue, err = daemon.Load(queuePath, op)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		var shares []recovery.Share
		for _, value := range recoveryValues {
			share, err := recovery.ParseShare(value)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			shares = append(shares, share)
		}
		snapshot := func(context.Context) (daemon.Item, error) { return captureSnapshot(home, v) }
		uploader := func(ctx context.Context, item daemon.Item) error {
			if *providerDir == "" {
				return fmt.Errorf("provider is not configured")
			}
			activeShares, err := daemonRecoveryShares(home, shares)
			if err != nil {
				return err
			}
			return syncvault.UploadGate{OperationalKey: op}.UploadSnapshot(ctx, provider.Git{Dir: *providerDir, Remote: *providerRemote}, item.ID, item.Ciphertext, item.Manifest, activeShares)
		}
		scheduler := newDaemonScheduler(snapshot, uploader, queue)
		scheduler.Persist = func() error { return queue.Save(queuePath, op) }
		scheduler.Report = func(err error) {
			newTerminalUI(os.Stderr).Text(colorIdentity, "cifrarium daemon")
			renderDaemonFailure(os.Stderr, home, err)
		}
		retryController := newDaemonRetryController(home, os.Stderr)
		defer retryController.Close()
		scheduler.RetryHandler = retryController.Handle
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		mcpErrors := make(chan error, 1)
		mcpReady := make(chan struct{})
		go func() {
			server := mcp.Server{Socket: socket, Handler: newMCPHandler(*root, *providerDir), Ready: func() { close(mcpReady) }}
			if err := server.Listen(); err != nil {
				mcpErrors <- fmt.Errorf("MCP listener failed: %w", err)
				cancel()
			}
		}()
		select {
		case <-mcpReady:
		case err := <-mcpErrors:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		case <-ctx.Done():
			if ctx.Err() != context.Canceled {
				fmt.Fprintln(os.Stderr, ctx.Err())
			}
			os.Exit(1)
		}
		newTerminalUI(os.Stdout).Text(colorIdentity, fmt.Sprintf("cifrarium daemon listening on %s", socket))
		if err := (daemon.Service{Scheduler: scheduler}).Run(ctx); err != nil && ctx.Err() == nil {
			writeDaemonServiceError(os.Stderr, err)
			_ = os.Remove(socket)
			os.Exit(1)
		}
		select {
		case err := <-mcpErrors:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		default:
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: cifrarium setup | status | doctor | snapshot | daemon | migrate-catalog | provider setup|health | recovery shares|import")
		os.Exit(2)
	}
}

func daemonRecoveryShares(home string, fallback []recovery.Share) ([]recovery.Share, error) {
	_, values, err := readDaemonEnv(home)
	if err != nil {
		return nil, fmt.Errorf("recovery configuration unavailable: %w", err)
	}
	first, second := values["CIFRARIUM_RECOVERY_SHARE_1"], values["CIFRARIUM_RECOVERY_SHARE_2"]
	if first == "" && second == "" {
		return fallback, nil
	}
	if first == "" || second == "" {
		return nil, fmt.Errorf("recovery configuration requires two protected shares")
	}
	shares, err := parseRecoveryShares([]string{first, second})
	if err != nil {
		return nil, fmt.Errorf("recovery configuration is invalid")
	}
	return shares, nil
}

func canonicalCommand(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "status", args, nil
	}
	if strings.HasPrefix(args[0], "-command=") || args[0] == "-command" {
		return "", nil, fmt.Errorf("-command is no longer supported; use a subcommand")
	}
	if strings.HasPrefix(args[0], "-") {
		return "status", args, nil
	}
	switch args[0] {
	case "provider":
		if len(args) < 2 {
			return "", nil, fmt.Errorf("provider requires setup or health")
		}
		switch args[1] {
		case "setup":
			return "provider-setup", append([]string{}, args[2:]...), nil
		case "health":
			return "provider-health", append([]string{}, args[2:]...), nil
		default:
			return "", nil, fmt.Errorf("unknown provider command %q", args[1])
		}
	case "recovery":
		if len(args) < 2 {
			return "", nil, fmt.Errorf("recovery requires shares or import")
		}
		switch args[1] {
		case "shares":
			return "recovery-shares", append([]string{}, args[2:]...), nil
		case "import":
			return "recover", append([]string{}, args[2:]...), nil
		default:
			return "", nil, fmt.Errorf("unknown recovery command %q", args[1])
		}
	case "status", "doctor", "setup", "snapshot", "daemon", "migrate-catalog":
		return args[0], append([]string{}, args[1:]...), nil
	case "help":
		return "help", append([]string{}, args[1:]...), nil
	default:
		return "", nil, fmt.Errorf("unknown command %q; use cifrarium --help", args[0])
	}
}

func writeCifrariumUsage(w io.Writer, fs *flag.FlagSet, program string) {
	fmt.Fprintf(w, "Usage: %s <command> [flags]\n\n", program)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  status                  Show vault, daemon, and provider status")
	fmt.Fprintln(w, "  doctor                  Run a read-only installation diagnostic")
	fmt.Fprintln(w, "  setup                   Configure the local vault")
	fmt.Fprintln(w, "  snapshot                Capture a local encrypted snapshot")
	fmt.Fprintln(w, "  daemon                  Run the user daemon")
	fmt.Fprintln(w, "  migrate-catalog         Encrypt legacy catalog metadata")
	fmt.Fprintln(w, "  provider setup          Configure the provider interactively")
	fmt.Fprintln(w, "  provider health         Check provider access and privacy")
	fmt.Fprintln(w, "  recovery shares         Generate recovery shares")
	fmt.Fprintln(w, "  recovery import         Import recovery material")
	fmt.Fprintln(w, "  help                    Show this help")
	fmt.Fprintln(w, "\nGlobal options:")
	previousOutput := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(previousOutput)
}

func parseOutputFormat(value string) (outputFormat, error) {
	format := outputFormat(value)
	if format != outputHuman && format != outputJSON {
		return "", fmt.Errorf("unsupported output format %q; use human or json", value)
	}
	return format, nil
}

func commandMutatesOrHandlesSecrets(command string) bool {
	switch command {
	case "provider-setup", "provider-health", "snapshot", "recovery-shares", "recover", "migrate-catalog", "daemon":
		return true
	default:
		return false
	}
}

func runSetup(root, home string, nonInteractive bool, output io.Writer) error {
	keyringStore := store.NewKeyring()
	// Setup is idempotent: retries and upgrades never rotate keys or print
	// another recovery-share set for an already configured vault.
	if _, err := os.Stat(root); err == nil {
		if op, signing, keyErr := keyringStore.LoadExistingForRoot(root); keyErr == nil {
			if _, openErr := store.Open(root, op, signing); openErr == nil {
				fmt.Fprintf(output, "Cifrarium is already configured at %s; existing keyring, vault history, and recovery shares were preserved.\n", root)
				return nil
			}
		}
	}
	if nonInteractive {
		op, signing, err := keyringStore.LoadExistingForRoot(root)
		if err != nil {
			return err
		}
		return runSetupWithCommit(root, home, true, output, op, signing, keyringStore, nil)
	}
	op, signing, err := keyringStore.LoadExisting()
	if errors.Is(err, keyring.ErrNotFound) {
		op, signing, err = store.GenerateKeyMaterial()
	}
	if err != nil {
		return err
	}
	commit := func() error {
		if _, err := ensureConfiguredRoot(home, root); err != nil {
			return err
		}
		return keyringStore.SaveForRoot(root, op, signing)
	}
	return runSetupWithCommit(root, home, false, output, op, signing, keyringStore, commit)
}

func runSetupWithKeys(root, home string, nonInteractive bool, output io.Writer, op []byte, signing ed25519.PrivateKey, guard store.HeadGuard) error {
	return runSetupWithCommit(root, home, nonInteractive, output, op, signing, guard, nil)
}

func runSetupWithCommit(root, home string, nonInteractive bool, output io.Writer, op []byte, signing ed25519.PrivateKey, guard store.HeadGuard, commit func() error) error {
	ui := newTerminalUI(output)
	if nonInteractive {
		fmt.Fprintln(output, "Non-interactive mode: no recovery shares were shown, no capture was made, no remote provider was changed, and no daemon was enabled.")
		return nil
	}
	tty, err := openSetupTTY()
	if err != nil {
		return err
	}
	defer tty.Close()
	ui.Section("Recovery shares")
	fmt.Fprintln(output, "Save two different shares in private locations.")
	shares, err := store.RecoveryShares(op, signing)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "They are shown only on the controlling terminal and will not be printed again.")
	for _, share := range shares {
		if _, err := fmt.Fprintf(tty, "%s:%s\n", share.Label, share.Value); err != nil {
			return err
		}
	}
	choices, err := collectSetupChoicesWithFeedback(askSetup, ui.Decision)
	if err != nil {
		return err
	}
	if commit != nil {
		if err := commit(); err != nil {
			return fmt.Errorf("setup commit: %w", err)
		}
	}
	vault, err := store.OpenWithGuard(root, op, signing, guard)
	if err != nil {
		return err
	}
	ui.Section("Local vault")
	fmt.Fprintf(output, "Ready at %s.\n", root)
	if choices.Provider {
		ui.Section("Private backup")
		initialShares := map[string]string{}
		if len(shares) >= 2 {
			initialShares["CIFRARIUM_RECOVERY_SHARE_1"] = shares[0].Label + ":" + shares[0].Value
			initialShares["CIFRARIUM_RECOVERY_SHARE_2"] = shares[1].Label + ":" + shares[1].Value
		}
		if err := runProviderSetupWithInitialShares(home, root, false, output, initialShares); err != nil {
			return err
		}
	}
	if choices.Capture {
		ui.Section("First local capture")
		fmt.Fprintln(output, "Encrypted data will be written locally. No remote upload will happen in this step.")
		ui.Section("Detected adapters")
		for _, adapter := range inspectAdapters(home) {
			fmt.Fprintf(output, "- %s: %d detected paths\n", adapter.Name, len(adapter.Paths))
		}
		if _, err := captureSnapshot(home, vault); err != nil {
			return fmt.Errorf("first capture: %w", err)
		}
		fmt.Fprintln(output, "First local encrypted capture completed.")
	}
	if choices.Activate {
		ui.Section("Automatic backup")
		command := exec.Command("systemctl", "--user", "enable", "--now", "cifrarium.service")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("daemon activation: %w", err)
		}
		fmt.Fprintln(output, "Automatic backup enabled.")
	} else {
		ui.Section("Automatic backup")
		fmt.Fprintln(output, "Automatic backup remains disabled.")
	}
	return nil
}

func collectSetupChoices(ask func(string) (bool, error)) (setupChoices, error) {
	return collectSetupChoicesWithFeedback(ask, func(setupDecision) {})
}

func collectSetupChoicesWithFeedback(ask func(string) (bool, error), feedback func(setupDecision)) (setupChoices, error) {
	saved, err := ask("Have you saved two different recovery shares? [y/N] ")
	if err != nil {
		return setupChoices{}, err
	}
	if !saved {
		return setupChoices{}, fmt.Errorf("setup cancelled; run cifrarium setup again")
	}
	feedback(setupDecision{
		Title:    "Recovery shares",
		Decision: "saved",
		Effect:   "Two different shares were confirmed.",
		Next:     "private backup",
	})
	provider, err := ask("Configure a private GitHub backup now? [y/N] ")
	if err != nil {
		return setupChoices{}, err
	}
	feedback(setupDecision{
		Title:    "Private backup",
		Decision: decisionLabel(provider),
		Effect:   decisionEffect(provider, "Backup commands will be prepared; no remote repository changes.", "The vault will remain local-only."),
		Next:     "first local encrypted capture",
	})
	capture, err := ask("Make the first local encrypted capture now? [y/N] ")
	if err != nil {
		return setupChoices{}, err
	}
	feedback(setupDecision{
		Title:    "First local capture",
		Decision: decisionLabel(capture),
		Effect:   decisionEffect(capture, "Encrypted data will be written locally; no remote upload.", "No snapshot will be created yet."),
		Next:     "automatic backup",
	})
	activate, err := ask("Enable automatic backup now? [y/N] ")
	if err != nil {
		return setupChoices{}, err
	}
	feedback(setupDecision{
		Title:    "Automatic backup",
		Decision: decisionLabel(activate),
		Effect:   decisionEffect(activate, "The user daemon will be enabled after setup.", "Automatic backup will remain disabled."),
	})
	return setupChoices{Provider: provider, Capture: capture, Activate: activate}, nil
}

func decisionLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "skipped"
}

func decisionEffect(enabled bool, enabledEffect, skippedEffect string) string {
	if enabled {
		return enabledEffect
	}
	return skippedEffect
}

func renderSetupDiagnostics(output io.Writer, root, home string, configured bool) {
	ui := newTerminalUI(output)
	current, _ := user.Current()
	username := "unknown"
	if current != nil && current.Username != "" {
		username = current.Username
	}
	ghState := "not authenticated"
	if command := exec.Command("gh", "auth", "status", "--hostname", "github.com"); command.Run() == nil {
		ghState = "authenticated"
	}
	gitState := "unavailable"
	if _, err := exec.LookPath("git"); err == nil {
		gitState = "available"
	}
	systemdState := "unavailable"
	if _, err := exec.LookPath("systemctl"); err == nil {
		systemdState = "available"
	}
	providerState := "not configured"
	configuredProvider, _ := loadProviderConfig(home)
	if os.Getenv("CIFRARIUM_PROVIDER_DIR") != "" || os.Getenv("CIFRARIUM_PROVIDER_REMOTE") != "" || configuredProvider.Dir != "" || configuredProvider.Remote != "" {
		providerState = "configured"
	}
	daemonState := "not enabled"
	if command := exec.Command("systemctl", "--user", "is-enabled", "cifrarium.service"); command.Run() == nil {
		daemonState = "enabled"
	}
	ui.Header("Cifrarium setup")
	fmt.Fprintln(output, "Let's prepare Cifrarium on this computer.")
	ui.Section("Environment")
	ui.Value("System", fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH))
	ui.Value("User", username)
	configuredRoot := "not configured"
	if configured {
		configuredRoot = root
	}
	ui.Value("Configured vault", configuredRoot)
	ui.Value("GitHub CLI", ghState)
	ui.Value("Git", gitState)
	ui.Value("systemd", systemdState)
	ui.Value("Private provider", providerState)
	ui.Value("Daemon", daemonState)
}

func providerSetupCommands(home string) string {
	providerDir := filepath.Join(home, ".local", "share", "cifrarium-provider")
	owner := "USER"
	if output, err := exec.Command("gh", "api", "user", "--jq", ".login").Output(); err == nil {
		if value := strings.TrimSpace(string(output)); value != "" && !strings.ContainsAny(value, "\r\n") {
			owner = value
		}
	}
	return fmt.Sprintf("PROVIDER_DIR=%s\nmkdir -p \"$PROVIDER_DIR\"\ngit -C \"$PROVIDER_DIR\" init --initial-branch=main\ngh repo create %s --private --source=\"$PROVIDER_DIR\" --remote=origin", shellQuote(providerDir), shellQuote(owner+"/cifrarium-backup"))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func openSetupTTY() (*os.File, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no controlling terminal is available; run setup in a terminal or use --non-interactive")
	}
	return tty, nil
}

func askSetup(prompt string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("não há terminal disponível; execute setup em um terminal ou use --non-interactive")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return false, err
	}
	var answer string
	if _, err := fmt.Fscanln(tty, &answer); err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "s" || answer == "sim" || answer == "y" || answer == "yes", nil
}

func captureSnapshot(home string, vault *store.Vault) (daemon.Item, error) {
	var records []store.Record
	for _, a := range []adapters.Adapter{adapters.Config{}, adapters.Zsh{}, adapters.Starship{}} {
		files, err := a.Collect(home)
		if err != nil {
			return daemon.Item{}, &daemon.CaptureError{Err: err}
		}
		for _, f := range files {
			records = append(records, store.Record{Path: f.Relative, Mode: uint32(f.Mode), Data: f.Data})
		}
	}
	m, err := vault.Save(records)
	if err != nil {
		return daemon.Item{}, err
	}
	ciphertext, err := vault.SnapshotCiphertext(m.Snapshot)
	if err != nil {
		return daemon.Item{}, err
	}
	manifest, err := store.SealManifest(m, vault.Operational)
	if err != nil {
		return daemon.Item{}, err
	}
	return daemon.Item{ID: m.Snapshot, Ciphertext: ciphertext, Manifest: manifest}, nil
}

func writeDaemonServiceError(w io.Writer, err error) {
	var captureErr interface{ CaptureFailure() }
	if errors.As(err, &captureErr) {
		return
	}
	var reportedErr interface{ ReportedFailure() }
	if errors.As(err, &reportedErr) {
		return
	}
	fmt.Fprintln(w, err)
}

func newDaemonScheduler(snapshot daemon.Snapshotter, uploader daemon.Uploader, queue *daemon.Queue) *daemon.Scheduler {
	scheduler := daemon.NewScheduler(snapshot, uploader, queue)
	scheduler.RecoverySnapshot = snapshot
	return scheduler
}

func newMCPHandler(root, providerDir string) mcp.Handler {
	return mcp.HandlerFunc(func(_ context.Context, request mcp.Request) (any, error) {
		result := map[string]any{
			"method":   request.Method,
			"readOnly": true,
		}
		switch request.Method {
		case "status":
			result["daemon"] = "running"
			result["vault"] = root
			result["providerConfigured"] = providerDir != ""
			return result, nil
		case "snapshot.plan":
			result["action"] = "capture"
			result["adapters"] = []string{"codex", "oh-my-zsh", "starship"}
			result["requiresCliConfirmation"] = true
			return result, nil
		case "restore.plan":
			var params struct {
				Snapshot string `json:"snapshot"`
			}
			if len(request.Params) > 0 && string(request.Params) != "null" {
				if err := json.Unmarshal(request.Params, &params); err != nil {
					return nil, fmt.Errorf("invalid restore plan parameters: %w", err)
				}
			}
			if params.Snapshot == "" {
				return nil, fmt.Errorf("restore plan requires a snapshot")
			}
			result["action"] = "restore"
			result["snapshot"] = params.Snapshot
			result["requiresCliConfirmation"] = true
			return result, nil
		default:
			return nil, fmt.Errorf("method %q is not available", request.Method)
		}
	})
}

func parseRecoveryShares(values []string) ([]recovery.Share, error) {
	if len(values) != 2 {
		return nil, fmt.Errorf("exactly two -recovery-share values are required")
	}
	shares := make([]recovery.Share, 0, 2)
	for _, value := range values {
		share, err := recovery.ParseShare(value)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}
