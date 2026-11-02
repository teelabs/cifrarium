package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

func (s *stringList) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	home, _ := os.UserHomeDir()
	root := flag.String("root", filepath.Join(home, ".local", "share", "cifrarium"), "encrypted vault directory")
	cmd := flag.String("command", "status", "status or snapshot")
	providerDir := flag.String("provider-dir", os.Getenv("CIFRARIUM_PROVIDER_DIR"), "local Git provider directory (daemon only)")
	providerRemote := flag.String("provider-remote", os.Getenv("CIFRARIUM_PROVIDER_REMOTE"), "HTTPS GitHub remote URL (daemon only; no embedded credentials)")
	verifyPrivate := flag.Bool("verify-private", false, "verify GitHub repository privacy with gh (provider-health only)")
	var recoveryValues stringList
	flag.Var(&recoveryValues, "recovery-share", "recovery share label:value (repeat twice before remote upload)")
	for _, name := range []string{"CIFRARIUM_RECOVERY_SHARE_1", "CIFRARIUM_RECOVERY_SHARE_2"} {
		if value := os.Getenv(name); value != "" {
			recoveryValues = append(recoveryValues, value)
		}
	}
	flag.Parse()
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
	keyringStore := store.NewKeyring()
	if *cmd == "recover" {
		shares, err := parseRecoveryShares(recoveryValues)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := keyringStore.ImportRecovery(shares); err != nil {
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
	v, err := store.OpenWithGuard(*root, op, sign, keyringStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: vault integrity check failed: %v\n", err)
		os.Exit(1)
	}
	switch *cmd {
	case "status":
		b, _ := json.Marshal(map[string]string{"vault": *root, "signer": fmt.Sprintf("%x", sign.Public())})
		fmt.Println(string(b))
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
		snapshot := func(ctx context.Context) (daemon.Item, error) {
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
			m, err := v.Save(records)
			if err != nil {
				return daemon.Item{}, err
			}
			ciphertext, err := os.ReadFile(filepath.Join(*root, "snapshots", m.Snapshot))
			manifest, marshalErr := store.SealManifest(m, op)
			if err == nil {
				err = marshalErr
			}
			return daemon.Item{ID: m.Snapshot, Ciphertext: ciphertext, Manifest: manifest}, err
		}
		uploader := func(ctx context.Context, item daemon.Item) error {
			if *providerDir == "" {
				return fmt.Errorf("provider is not configured")
			}
			return syncvault.UploadGate{OperationalKey: op}.UploadSnapshot(ctx, provider.Git{Dir: *providerDir, Remote: *providerRemote}, item.ID, item.Ciphertext, item.Manifest, shares)
		}
		scheduler := daemon.NewScheduler(snapshot, uploader, queue)
		scheduler.Persist = func() error { return queue.Save(queuePath, op) }
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		go func() { _ = (mcp.Server{Socket: socket}).Listen() }()
		fmt.Printf("cifrarium daemon listening on %s\n", socket)
		if err := (daemon.Service{Scheduler: scheduler}).Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: cifrarium -command=status|snapshot|recovery-shares|recover|migrate-catalog|provider-health -recovery-share label:value")
		os.Exit(2)
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
