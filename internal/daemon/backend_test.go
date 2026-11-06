package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/teelabs/cifrarium/internal/store"
)

func TestBackendPlansAreReadOnlyAndUseTheSharedAdapterContract(t *testing.T) {
	backend := Backend{}
	snapshot := backend.SnapshotPlan()
	if snapshot["action"] != "capture" || snapshot["readOnly"] != true {
		t.Fatalf("snapshot plan = %#v", snapshot)
	}
	if _, err := backend.RestorePlan(""); err == nil {
		t.Fatal("empty restore plan was accepted")
	}
	restore, err := backend.RestorePlan("snapshot-id")
	if err != nil {
		t.Fatal(err)
	}
	if restore["action"] != "restore" || restore["snapshot"] != "snapshot-id" || restore["requiresCliConfirmation"] != true {
		t.Fatalf("restore plan = %#v", restore)
	}
}

func TestBackendStatusIsTheSharedOperationalView(t *testing.T) {
	root := t.TempDir()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := Backend{
		Vault:       store.New(root, []byte("operational-key"), signing),
		Pending:     &Queue{},
		Operational: []byte("operational-key"),
		Signing:     signing,
	}
	status, err := backend.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Vault != root || !status.Configured || status.VaultState != "ready" || status.KeyringState != "available" {
		t.Fatalf("unexpected backend status: %#v", status)
	}
	if status.Pending != 0 || status.Snapshots != 0 || status.Signer == "" {
		t.Fatalf("unexpected backend counters: %#v", status)
	}
}

func TestBackendCaptureClassifiesVaultWriteFailure(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := Backend{Home: home, Vault: store.New(root, make([]byte, 32), signing)}
	_, err = backend.CaptureSnapshot(context.Background())
	var captureErr *CaptureError
	if !errors.As(err, &captureErr) || captureErr.Stage != CaptureStageVaultWrite {
		t.Fatalf("capture error = %#v (%v), want typed vault-write failure", captureErr, err)
	}
	var marker interface{ CaptureFailure() }
	if !errors.As(err, &marker) {
		t.Fatal("vault write failure was not classified as a local capture failure")
	}
}

func TestBackendCaptureReusesIdenticalSnapshotAndStoredManifestBytes(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"same\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	backend := &Backend{Home: home, Vault: store.New(root, make([]byte, 32), signing)}

	first, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Unchanged {
		t.Fatal("initial capture was reported unchanged")
	}
	storedManifest, err := os.ReadFile(filepath.Join(root, "catalog", first.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedManifest, first.Manifest) {
		t.Fatal("capture returned manifest bytes different from the stored catalog")
	}

	second, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.Unchanged || second.ID != first.ID {
		t.Fatalf("second capture = (unchanged=%t, id=%q), want same head %q", second.Unchanged, second.ID, first.ID)
	}
	if !bytes.Equal(first.Ciphertext, second.Ciphertext) || !bytes.Equal(first.Manifest, second.Manifest) {
		t.Fatal("unchanged capture did not return exact stored encrypted bytes")
	}
	if _, err := os.Stat(filepath.Join(root, "snapshots", second.ID)); err != nil {
		t.Fatalf("current snapshot missing: %v", err)
	}
	status, err := backend.Status()
	if err != nil || status.Snapshots != 1 {
		t.Fatalf("snapshot count=%d err=%v, want exactly one", status.Snapshots, err)
	}

	if err := os.WriteFile(configPath, []byte("model = \"changed\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	third, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.Unchanged || third.ID == second.ID {
		t.Fatalf("changed capture = (unchanged=%t, id=%q), want a new snapshot", third.Unchanged, third.ID)
	}
}

func TestBackendOwnsQueuePersistenceAndProviderGate(t *testing.T) {
	root := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	queue := &Queue{}
	if err := queue.Push(Item{ID: "snapshot-id", Ciphertext: []byte("ciphertext")}); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{
		Vault:       store.New(root, key, signing),
		Operational: key,
		Pending:     queue,
		QueuePath:   filepath.Join(root, "pending.queue"),
	}
	if err := backend.PersistQueue(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(backend.QueuePath, key)
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("persisted queue = %#v, %v", loaded, err)
	}
	if err := backend.UploadSnapshot(context.Background(), Item{ID: "snapshot-id", Ciphertext: []byte("ciphertext")}); err == nil {
		t.Fatal("backend uploaded without a configured provider")
	}
}
