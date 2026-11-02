package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/store"
)

func TestDaemonWiresRecoverySnapshotAndQueuesIt(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"test\""), 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(root, op, signing)
	snapshot := func(context.Context) (daemon.Item, error) {
		return captureSnapshot(home, vault)
	}
	scheduler := newDaemonScheduler(snapshot, func(context.Context, daemon.Item) error {
		return errors.New("offline")
	}, &daemon.Queue{})
	scheduler.Retry.MaxAttempts = 1

	if err := scheduler.Cycle(context.Background()); err == nil {
		t.Fatal("offline cycle succeeded")
	}
	if scheduler.Pending.Len() != 2 {
		t.Fatalf("pending=%d, want normal and recovery snapshots", scheduler.Pending.Len())
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("snapshots=%d, want 2", len(entries))
	}
}
