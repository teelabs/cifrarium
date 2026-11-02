package main

import (
	"context"
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
	providerDir := flag.String("provider-dir", "", "local Git provider directory (daemon only)")
	providerRemote := flag.String("provider-remote", "", "HTTPS GitHub remote URL (daemon only; no embedded credentials)")
	var recoveryValues stringList
	flag.Var(&recoveryValues, "recovery-share", "recovery share label:value (repeat twice before remote upload)")
	flag.Parse()
	op, sign, err := store.NewKeyring().LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cifrarium: %v\n", err)
		os.Exit(1)
	}
	v := store.New(*root, op, sign)
	switch *cmd {
	case "status":
		b, _ := json.Marshal(map[string]string{"vault": *root, "signer": fmt.Sprintf("%x", sign.Public())})
		fmt.Println(string(b))
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
			return daemon.Item{ID: m.Snapshot, Ciphertext: ciphertext}, err
		}
		uploader := func(ctx context.Context, item daemon.Item) error {
			if *providerDir == "" {
				return fmt.Errorf("provider is not configured")
			}
			return syncvault.UploadGate{OperationalKey: op}.Upload(ctx, provider.Git{Dir: *providerDir, Remote: *providerRemote}, item.ID, item.Ciphertext, shares)
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
		fmt.Fprintln(os.Stderr, "usage: cifrarium -command=status|snapshot")
		os.Exit(2)
	}
}
