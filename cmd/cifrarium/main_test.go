package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/store"
)

func TestVersionFlag(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "dev\n" {
		t.Fatalf("version output = %q", out)
	}
}

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

func TestMCPHandlerReturnsReadOnlyRestorePlan(t *testing.T) {
	handler := newMCPHandler("/vault", "/provider")
	result, err := handler.Handle(context.Background(), mcp.Request{
		Method: "restore.plan",
		Params: json.RawMessage(`{"snapshot":"snapshot-id"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result=%#v", result)
	}
	if plan["readOnly"] != true || plan["requiresCliConfirmation"] != true || plan["snapshot"] != "snapshot-id" {
		t.Fatalf("unexpected plan=%#v", plan)
	}
}

func TestSetupNonInteractiveDoesNotLeakSharesOrCapture(t *testing.T) {
	root := t.TempDir()
	var output strings.Builder
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSetupWithKeys(root, t.TempDir(), true, &output, op, signing, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Modo não interativo") {
		t.Fatalf("output=%q", output.String())
	}
	if strings.Contains(output.String(), "cifrarium-1:") {
		t.Fatalf("recovery share leaked: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("non-interactive setup captured data: %v", err)
	}
}
