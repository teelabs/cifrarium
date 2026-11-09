package main

import (
	"bufio"
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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/rpc"
	"github.com/teelabs/cifrarium/internal/store"
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
	formatValue := flag.String("format", "human", "output format: human or json (status, doctor, and snapshot audit)")
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
	if cmd == "restore" {
		if format != outputHuman {
			fmt.Fprintln(os.Stderr, "cifrarium: restore is interactive and supports human output only")
			os.Exit(2)
		}
		if len(recoveryValues) != 0 {
			fmt.Fprintln(os.Stderr, "cifrarium: restore reads shares only from the hidden terminal prompt")
			os.Exit(2)
		}
		if err := runFileRestore(home, *root, *providerDir, *providerRemote, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if cmd == "restore-history" {
		if format != outputHuman {
			fmt.Fprintln(os.Stderr, "cifrarium: restore history is interactive and supports human output only")
			os.Exit(2)
		}
		if len(recoveryValues) != 0 {
			fmt.Fprintln(os.Stderr, "cifrarium: restore history never accepts recovery shares as command-line arguments")
			os.Exit(2)
		}
		if err := runHistoryReconcile(home, *root, *providerDir, *providerRemote, os.Stdout); err != nil {
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
	if cmd == "daemon-refresh" {
		resolvedRoot, rootErr := resolveVaultRoot(cmd, *root, home)
		if rootErr != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", rootErr)
			os.Exit(1)
		}
		readiness, err := runDaemonRefresh(resolvedRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: daemon refresh failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(daemonRefreshMessage(readiness))
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
	if cmd == "snapshot-audit" {
		result, err := runSnapshotAudit(*root, home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: snapshot audit failed: %v\n", daemonBackendNotReadyAdvice(err))
			os.Exit(1)
		}
		if err := renderSnapshotAudit(os.Stdout, result, format); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(2)
		}
		return
	}
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
		if report, ok, err := callDaemonStatus(*root); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: daemon status failed: %v\n", daemonBackendNotReadyAdvice(err))
			os.Exit(1)
		} else if ok {
			if err := renderStatus(os.Stdout, report, format); err != nil {
				fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
				os.Exit(2)
			}
			return
		}
		localBackend := daemon.Backend{Home: home, Vault: v, Operational: op, Signing: sign}
		backendStatus, err := localBackend.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: status failed: %v\n", err)
			os.Exit(1)
		}
		report := statusReport(backendStatus)
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
		if result, ok, err := callDaemonSnapshot(*root); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: daemon snapshot failed: %v\n", daemonBackendNotReadyAdvice(err))
			os.Exit(1)
		} else if ok {
			writeSnapshotResult(os.Stdout, result.Snapshot, result.Unchanged)
			return
		}
		localBackend := daemon.Backend{Home: home, Vault: v}
		item, err := localBackend.CaptureSnapshot(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		writeSnapshotResult(os.Stdout, item.ID, item.Unchanged)
	case "daemon":
		if daemonAlreadyRunning(*root) {
			fmt.Fprintln(os.Stdout, "cifrarium daemon is already running")
			fmt.Fprintln(os.Stdout, "Use systemctl --user status cifrarium.service to inspect it or cifrarium daemon refresh after configuration changes.")
			return
		}
		socket := filepath.Join(*root, "cifrarium.sock")
		controlSocket := filepath.Join(*root, "control.sock")
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
		activeShares, err := daemonRecoveryShares(home, shares)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
			os.Exit(1)
		}
		backend := &daemon.Backend{
			Home:               home,
			Vault:              v,
			Guard:              keyringStore,
			Operational:        op,
			Signing:            sign,
			Pending:            queue,
			QueuePath:          queuePath,
			RecoveryShares:     activeShares,
			ProviderConfigured: *providerDir != "",
		}
		if *providerDir != "" {
			backend.Provider = provider.Git{Dir: *providerDir, Remote: *providerRemote}
		}
		scheduler := newDaemonScheduler(backend.CaptureSnapshot, backend.UploadSnapshot, queue)
		scheduler.Persist = backend.PersistQueue
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
		mcpReadyState := &atomic.Bool{}
		backendReadyState := &atomic.Bool{}
		controlServer, err := rpc.ListenUnix(controlSocket, newDaemonControlHandler(backend, backend.CaptureSnapshot, backendReadyState, mcpReadyState, cancel), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: control listener failed: %v\n", err)
			os.Exit(1)
		}
		defer controlServer.Close()
		controlErrors := make(chan error, 1)
		go func() {
			if err := controlServer.Serve(ctx); err != nil && ctx.Err() == nil {
				controlErrors <- err
				cancel()
			}
		}()
		mcpErrors := make(chan error, 1)
		mcpReady := make(chan struct{})
		go func() {
			server := mcp.Server{Socket: socket, Handler: newMCPHandlerWithReadiness(*root, *providerDir, backend, backendReadyState), Context: ctx, Ready: func() { close(mcpReady) }}
			if err := server.Listen(); err != nil && ctx.Err() == nil {
				mcpErrors <- fmt.Errorf("MCP listener failed: %w", err)
				cancel()
			}
		}()
		select {
		case <-mcpReady:
			mcpReadyState.Store(true)
		case err := <-mcpErrors:
			_ = controlServer.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		case <-ctx.Done():
			_ = controlServer.Close()
			if ctx.Err() != context.Canceled {
				fmt.Fprintln(os.Stderr, ctx.Err())
			}
			os.Exit(1)
		}
		newTerminalUI(os.Stdout).Text(colorIdentity, fmt.Sprintf("cifrarium daemon listening on %s", socket))
		service := daemon.Service{Scheduler: scheduler, Ready: func() { backendReadyState.Store(true) }}
		if err := service.Run(ctx); err != nil && ctx.Err() == nil {
			writeDaemonServiceError(os.Stderr, err)
			_ = os.Remove(socket)
			_ = controlServer.Close()
			os.Exit(1)
		}
		select {
		case err := <-controlErrors:
			if ctx.Err() == nil {
				_ = controlServer.Close()
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		case err := <-mcpErrors:
			_ = controlServer.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		default:
		}
		_ = os.Remove(controlSocket)
	default:
		fmt.Fprintln(os.Stderr, "usage: cifrarium setup | status | doctor | snapshot | daemon [refresh] | migrate-catalog | provider setup|health | recovery shares|import")
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
	case "snapshot":
		if len(args) >= 2 && args[1] == "audit" {
			return "snapshot-audit", append([]string{}, args[2:]...), nil
		}
		if len(args) > 1 {
			return "", nil, fmt.Errorf("unknown snapshot command %q", args[1])
		}
		return "snapshot", append([]string{}, args[1:]...), nil
	case "restore":
		if len(args) >= 2 && args[1] == "history" {
			return "restore-history", append([]string{}, args[2:]...), nil
		}
		if len(args) > 1 {
			return "", nil, fmt.Errorf("unknown restore command %q", args[1])
		}
		return "restore", append([]string{}, args[1:]...), nil
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
	case "daemon":
		if len(args) >= 2 && args[1] == "refresh" {
			return "daemon-refresh", append([]string{}, args[2:]...), nil
		}
		if len(args) > 1 {
			return "", nil, fmt.Errorf("unknown daemon command %q", args[1])
		}
		return "daemon", append([]string{}, args[1:]...), nil
	case "status", "doctor", "setup", "migrate-catalog":
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
	fmt.Fprintln(w, "  restore                 Recover selected files from a private GitHub backup")
	fmt.Fprintln(w, "  restore history         Verify and interactively select a canonical remote branch")
	fmt.Fprintln(w, "  snapshot                Capture a local encrypted snapshot")
	fmt.Fprintln(w, "  snapshot audit          Compare adapter files with the latest verified snapshot")
	fmt.Fprintln(w, "  daemon                  Run the user daemon")
	fmt.Fprintln(w, "  daemon refresh          Reload configuration and restart the user daemon")
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
	case "provider-setup", "provider-health", "snapshot", "recovery-shares", "recover", "restore", "restore-history", "migrate-catalog", "daemon", "daemon-refresh":
		return true
	default:
		return false
	}
}

func runSnapshotAudit(root, home string) (store.AuditResult, error) {
	if result, ok, err := callDaemonAudit(root); err != nil {
		return store.AuditResult{}, safeSnapshotAuditError(err)
	} else if ok {
		return result, nil
	}
	keyringStore := store.NewKeyring()
	op, signing, err := keyringStore.LoadExistingForRoot(root)
	if err != nil {
		return store.AuditResult{}, safeSnapshotAuditError(err)
	}
	vault := store.NewWithGuard(root, op, signing, keyringStore)
	backend := daemon.Backend{Home: home, Vault: vault}
	result, err := backend.AuditSnapshot(context.Background())
	if err != nil {
		return store.AuditResult{}, safeSnapshotAuditError(err)
	}
	return result, nil
}

func safeSnapshotAuditError(err error) error {
	var rpcErr *rpc.Error
	if errors.As(err, &rpcErr) && rpcErr.Code == -32002 && rpcErr.Message == "daemon backend is not ready" {
		return daemonBackendNotReadyAdvice(err)
	}
	return errors.New("audit could not be completed; check vault integrity, file access, and daemon logs")
}

func renderSnapshotAudit(out io.Writer, result store.AuditResult, format outputFormat) error {
	if format == outputJSON {
		return json.NewEncoder(out).Encode(result)
	}
	fmt.Fprintln(out, "Cifrarium snapshot audit")
	fmt.Fprintf(out, "Status: %s\n", result.Status)
	if result.Snapshot != "" {
		fmt.Fprintf(out, "Snapshot: %s\n", result.Snapshot)
	}
	writePaths := func(label string, paths []string) {
		fmt.Fprintf(out, "%s:\n", label)
		if len(paths) == 0 {
			fmt.Fprintln(out, "  (none)")
			return
		}
		for _, path := range paths {
			fmt.Fprintf(out, "  %s\n", strconv.QuoteToGraphic(path))
		}
	}
	writePaths("Added", result.Added)
	writePaths("Missing", result.Missing)
	writePaths("Content changed", result.ContentChanged)
	writePaths("Mode changed", result.ModeChanged)
	return nil
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
		if !nonInteractive {
			tty, ttyErr := openSetupTTY()
			if ttyErr != nil {
				return ttyErr
			}
			reader := bufio.NewReader(tty)
			restoreExisting, askErr := promptYesNo(reader, tty, "Recover an existing private backup with two recovery shares?", false)
			_ = tty.Close()
			if askErr != nil {
				return askErr
			}
			if restoreExisting {
				providerConfig, _ := loadProviderConfig(home)
				return runFileRestore(home, root, providerConfig.Dir, providerConfig.Remote, output)
			}
		}
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
		backend := daemon.Backend{Home: home, Vault: vault}
		if _, err := backend.CaptureSnapshot(context.Background()); err != nil {
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

func writeDaemonServiceError(w io.Writer, err error) {
	var recoverySnapshotErr *daemon.RecoverySnapshotError
	if errors.As(err, &recoverySnapshotErr) {
		return
	}
	var persistenceErr *daemon.PersistenceError
	if errors.As(err, &persistenceErr) {
		renderDaemonFailure(w, "", err)
		return
	}
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
	return newMCPHandlerWithReadiness(root, providerDir, nil, nil)
}

func newMCPHandlerWithReadiness(root, providerDir string, backend *daemon.Backend, backendReady *atomic.Bool) mcp.Handler {
	return mcp.HandlerFunc(func(ctx context.Context, request mcp.Request) (any, error) {
		result := map[string]any{
			"method":   request.Method,
			"readOnly": true,
		}
		switch request.Method {
		case "status":
			result["daemon"] = "running"
			if backendReady != nil {
				result["backend"] = "starting"
				if backendReady.Load() {
					result["backend"] = "ready"
				}
			}
			if backend != nil && (backendReady == nil || backendReady.Load()) {
				status, err := backend.Status()
				if err != nil {
					return nil, err
				}
				result["vault"] = status.Vault
				result["vaultState"] = status.VaultState
				result["snapshots"] = status.Snapshots
				result["pending"] = status.Pending
			} else {
				result["vault"] = root
			}
			if backend != nil {
				result["providerConfigured"] = backend.ProviderConfigured
			} else {
				result["providerConfigured"] = providerDir != ""
			}
			return result, nil
		case "snapshot.plan":
			if backend != nil {
				for key, value := range backend.SnapshotPlan() {
					result[key] = value
				}
			} else {
				result["action"] = "capture"
				result["adapters"] = []string{"codex", "oh-my-zsh", "starship"}
				result["requiresCliConfirmation"] = true
			}
			return result, nil
		case "snapshot.audit":
			if backend == nil || (backendReady != nil && !backendReady.Load()) {
				return nil, errors.New("daemon backend is not ready")
			}
			result, err := backend.AuditSnapshot(ctx)
			if err != nil {
				return nil, errors.New("snapshot audit failed")
			}
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
			var plan map[string]any
			if backend != nil {
				var err error
				plan, err = backend.RestorePlan(params.Snapshot)
				if err != nil {
					return nil, err
				}
			} else {
				if params.Snapshot == "" {
					return nil, fmt.Errorf("restore plan requires a snapshot")
				}
				plan = map[string]any{"action": "restore", "snapshot": params.Snapshot, "requiresCliConfirmation": true}
			}
			for key, value := range plan {
				result[key] = value
			}
			return result, nil
		default:
			return nil, fmt.Errorf("method %q is not available", request.Method)
		}
	})
}

func daemonBackendNotReadyAdvice(err error) error {
	var rpcErr *rpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32002 || rpcErr.Message != "daemon backend is not ready" {
		return err
	}
	return errors.New("daemon backend is still starting. Run `cifrarium doctor -format=json` to inspect MCP and backend readiness. For a local snapshot, exit a foreground `cifrarium daemon` with `n` at Retry?; for a systemd-managed daemon, run `systemctl --user stop cifrarium.service` first. The CLI does not bypass an active daemon.")
}

func callDaemonStatus(root string) (statusReport, bool, error) {
	var report statusReport
	socket := filepath.Join(root, "control.sock")
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return statusReport{}, false, nil
		}
		return report, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rpc.Call(ctx, socket, "daemon.status", nil, &report); err != nil {
		return report, true, err
	}
	return report, true, nil
}

type daemonSnapshotResult struct {
	Snapshot  string `json:"snapshot"`
	Unchanged bool   `json:"unchanged"`
}

func writeSnapshotResult(out io.Writer, id string, unchanged bool) {
	if unchanged {
		fmt.Fprintf(out, "snapshot %s (unchanged; reused current)\n", id)
		return
	}
	fmt.Fprintf(out, "snapshot %s\n", id)
}

func callDaemonSnapshot(root string) (daemonSnapshotResult, bool, error) {
	socket := filepath.Join(root, "control.sock")
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return daemonSnapshotResult{}, false, nil
		}
		return daemonSnapshotResult{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result daemonSnapshotResult
	if err := rpc.Call(ctx, socket, "snapshot.create", nil, &result); err != nil {
		return daemonSnapshotResult{}, true, err
	}
	if result.Snapshot == "" {
		return daemonSnapshotResult{}, true, errors.New("daemon returned an empty snapshot identifier")
	}
	return result, true, nil
}

func callDaemonAudit(root string) (store.AuditResult, bool, error) {
	socket := filepath.Join(root, "control.sock")
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store.AuditResult{}, false, nil
		}
		return store.AuditResult{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result store.AuditResult
	if err := rpc.Call(ctx, socket, "snapshot.audit", nil, &result); err != nil {
		return store.AuditResult{}, true, err
	}
	if result.Status != store.AuditMatches && result.Status != store.AuditDiffers && result.Status != store.AuditNoSnapshot {
		return store.AuditResult{}, true, errors.New("daemon returned an invalid snapshot audit result")
	}
	if result.Status != store.AuditNoSnapshot && result.Snapshot == "" {
		return store.AuditResult{}, true, errors.New("daemon returned an incomplete snapshot audit result")
	}
	if err := validateAuditResultPaths(result); err != nil {
		return store.AuditResult{}, true, errors.New("daemon returned an invalid snapshot audit result")
	}
	return result, true, nil
}

func validateAuditResultPaths(result store.AuditResult) error {
	for _, paths := range [][]string{result.Added, result.Missing, result.ContentChanged, result.ModeChanged} {
		for _, path := range paths {
			if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
				return errors.New("invalid audit result path")
			}
		}
	}
	return nil
}

func newDaemonControlHandler(backend *daemon.Backend, snapshot func(context.Context) (daemon.Item, error), backendReady, mcpReady *atomic.Bool, afterRestore ...func()) rpc.Handler {
	return func(ctx context.Context, request rpc.Request) (any, *rpc.Error) {
		switch request.Method {
		case "daemon.status":
			if !backendReady.Load() {
				return nil, &rpc.Error{Code: -32002, Message: "daemon backend is not ready"}
			}
			status, err := backend.Status()
			if err != nil {
				return nil, &rpc.Error{Code: -32001, Message: "daemon status unavailable"}
			}
			return status, nil
		case "mcp.status":
			backendState := "starting"
			if backendReady.Load() {
				backendState = "ready"
			}
			mcpState := "starting"
			if mcpReady.Load() {
				mcpState = "ready"
			}
			return map[string]any{"backend": backendState, "mcp": map[string]any{"state": mcpState}}, nil
		case "snapshot.create":
			if !backendReady.Load() {
				return nil, &rpc.Error{Code: -32002, Message: "daemon backend is not ready"}
			}
			item, err := snapshot(ctx)
			if err != nil {
				return nil, &rpc.Error{Code: -32010, Message: "snapshot failed"}
			}
			return map[string]any{"snapshot": item.ID, "unchanged": item.Unchanged}, nil
		case "snapshot.audit":
			if !backendReady.Load() {
				return nil, &rpc.Error{Code: -32002, Message: "daemon backend is not ready"}
			}
			if backend == nil {
				return nil, &rpc.Error{Code: -32011, Message: "snapshot audit failed"}
			}
			result, err := backend.AuditSnapshot(ctx)
			if err != nil {
				return nil, &rpc.Error{Code: -32011, Message: "snapshot audit failed"}
			}
			return result, nil
		case "restore.apply":
			if !backendReady.Load() {
				return nil, &rpc.Error{Code: -32002, Message: "daemon backend is not ready"}
			}
			if backend == nil {
				return nil, &rpc.Error{Code: -32012, Message: "daemon restore failed"}
			}
			var restoreRequest daemon.FileRestoreRequest
			if err := json.Unmarshal(request.Params, &restoreRequest); err != nil {
				return nil, &rpc.Error{Code: -32602, Message: "invalid restore request"}
			}
			if err := backend.RestoreFiles(ctx, restoreRequest); err != nil {
				return nil, &rpc.Error{Code: -32012, Message: "daemon restore failed; review the terminal and retry"}
			}
			if len(afterRestore) > 0 && afterRestore[0] != nil {
				time.AfterFunc(300*time.Millisecond, afterRestore[0])
			}
			return map[string]any{"restored": true}, nil
		default:
			return nil, &rpc.Error{Code: -32601, Message: "method not found"}
		}
	}
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
