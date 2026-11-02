package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/store"
)

func main() {
	home, _ := os.UserHomeDir()
	root := flag.String("root", filepath.Join(home, ".local", "share", "cifrarium"), "encrypted vault directory")
	cmd := flag.String("command", "status", "status or snapshot")
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
		fmt.Printf("cifrarium daemon listening on %s\n", socket)
		if err := (mcp.Server{Socket: socket}).Listen(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: cifrarium -command=status|snapshot")
		os.Exit(2)
	}
}
