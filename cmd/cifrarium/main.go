package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
	syncvault "github.com/teelabs/cifrarium/internal/sync"
)

type stringList []string

var version = "dev"

func (s *stringList) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		os.Args = append([]string{os.Args[0], "-command=setup"}, os.Args[2:]...)
	}
	home, _ := os.UserHomeDir()
	root := flag.String("root", filepath.Join(home, ".local", "share", "cifrarium"), "encrypted vault directory")
	cmd := flag.String("command", "status", "status, doctor, or snapshot")
	providerDir := flag.String("provider-dir", os.Getenv("CIFRARIUM_PROVIDER_DIR"), "local Git provider directory (daemon only)")
	providerRemote := flag.String("provider-remote", os.Getenv("CIFRARIUM_PROVIDER_REMOTE"), "HTTPS GitHub remote URL (daemon only; no embedded credentials)")
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
	flag.Parse()
	format, err := parseOutputFormat(*formatValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cifrarium:", err)
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *cmd == "provider-health" {
		if *providerDir == "" || *providerRemote == "" {
			fmt.Fprintln(os.Stderr, "cifrarium: provider-health requires -provider-dir and -provider-remote")
			os.Exit(2)
		}
		gitProvider := provider.Git{Dir: *providerDir, Remote: *providerRemote}
		if err := gitProvider.Ensure(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: provider setup failed: %v\n", err)
			os.Exit(1)
		}
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
	if *cmd == "doctor" {
		report, err := runDoctor(*root, home, *providerDir, *providerRemote, os.Stdout)
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
	keyringStore := store.NewKeyring()
	if *cmd == "recover" {
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
	op, sign, err := keyringStore.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
		os.Exit(1)
	}
	if *cmd == "migrate-catalog" {
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
	if *cmd == "setup" {
		if err := runSetup(*root, home, *nonInteractive, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "cifrarium: setup failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	v, err := store.OpenWithGuard(*root, op, sign, keyringStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: vault integrity check failed: %v\n", err)
		os.Exit(1)
	}
	switch *cmd {
	case "status":
		report := statusReport{
			Vault:        *root,
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
			return syncvault.UploadGate{OperationalKey: op}.UploadSnapshot(ctx, provider.Git{Dir: *providerDir, Remote: *providerRemote}, item.ID, item.Ciphertext, item.Manifest, shares)
		}
		scheduler := newDaemonScheduler(snapshot, uploader, queue)
		scheduler.Persist = func() error { return queue.Save(queuePath, op) }
		scheduler.Report = func(err error) { fmt.Fprintf(os.Stderr, "cifrarium daemon: %v\n", err) }
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
		fmt.Printf("cifrarium daemon listening on %s\n", socket)
		if err := (daemon.Service{Scheduler: scheduler}).Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		select {
		case err := <-mcpErrors:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		default:
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: cifrarium setup | -command=status|doctor|snapshot|recovery-shares|recover|migrate-catalog|provider-health -format=human|json -recovery-share label:value")
		os.Exit(2)
	}
}

func parseOutputFormat(value string) (outputFormat, error) {
	format := outputFormat(value)
	if format != outputHuman && format != outputJSON {
		return "", fmt.Errorf("unsupported output format %q; use human or json", value)
	}
	return format, nil
}

func runSetup(root, home string, nonInteractive bool, output io.Writer) error {
	keyringStore := store.NewKeyring()
	op, signing, err := keyringStore.LoadOrCreate()
	if err != nil {
		return err
	}
	return runSetupWithKeys(root, home, nonInteractive, output, op, signing, keyringStore)
}

func runSetupWithKeys(root, home string, nonInteractive bool, output io.Writer, op []byte, signing ed25519.PrivateKey, guard store.HeadGuard) error {
	vault, err := store.OpenWithGuard(root, op, signing, guard)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "O vault local está pronto.")
	if nonInteractive {
		fmt.Fprintln(output, "Modo não interativo: nenhuma chave de recuperação foi exibida, captura feita, conexão remota ou ativação de daemon.")
		return nil
	}
	fmt.Fprintln(output, "Agora vamos guardar suas chaves de recuperação.")
	shares, err := store.RecoveryShares(op, signing)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Guarde duas linhas diferentes em locais privados separados. Elas não serão gravadas pelo Cifrarium:")
	for _, share := range shares {
		fmt.Fprintf(output, "%s:%s\n", share.Label, share.Value)
	}
	if err := requireTTY(); err != nil {
		return err
	}
	ok, err := askSetup("Você já guardou duas chaves de recuperação? [s/N] ")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("configuração cancelada; execute cifrarium setup novamente")
	}
	provider, err := askSetup("Você quer configurar backup privado no GitHub agora? [s/N] ")
	if err != nil {
		return err
	}
	if provider {
		fmt.Fprintln(output, "Configure um repositório GitHub privado e a pasta local conforme o guia operacional.")
		fmt.Fprintln(output, "Nenhum dado remoto será enviado sem configuração e confirmação posteriores.")
	}
	capture, err := askSetup("Você quer fazer a primeira captura agora? [s/N] ")
	if err != nil {
		return err
	}
	if capture {
		if _, err := captureSnapshot(home, vault); err != nil {
			return fmt.Errorf("primeira captura: %w", err)
		}
		fmt.Fprintln(output, "Primeira captura local concluída.")
	}
	activate, err := askSetup("Você quer ativar o backup automático? [s/N] ")
	if err != nil {
		return err
	}
	if activate {
		command := exec.Command("systemctl", "--user", "enable", "--now", "cifrarium.service")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("ativação do daemon: %w", err)
		}
		fmt.Fprintln(output, "Backup automático ativado.")
	} else {
		fmt.Fprintln(output, "O daemon continua desativado.")
	}
	return nil
}

func requireTTY() error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("não há terminal disponível; execute setup em um terminal ou use --non-interactive")
	}
	return tty.Close()
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
			return daemon.Item{}, err
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
