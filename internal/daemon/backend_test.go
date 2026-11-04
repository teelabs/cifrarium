package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
