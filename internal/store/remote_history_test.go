package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRemoteHistoryReturnsTypedForkError(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	makeSnapshot := func(content string) SnapshotResult {
		t.Helper()
		vault := New(t.TempDir(), op, signing)
		result, err := vault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte(content), Mode: 0600}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	left, right := makeSnapshot("left"), makeSnapshot("right")
	_, err = VerifyRemoteHistory([]RemoteSnapshot{
		{ID: left.Manifest.Snapshot, Ciphertext: left.Ciphertext, Catalog: left.ManifestBytes},
		{ID: right.Manifest.Snapshot, Ciphertext: right.Ciphertext, Catalog: right.ManifestBytes},
	}, op, signing)
	if !errors.Is(err, ErrRemoteHistoryForked) {
		t.Fatalf("forked history error = %v, want ErrRemoteHistoryForked", err)
	}
}

type historyGuard struct {
	head string
	fail bool
}

func (g *historyGuard) CatalogHead() (string, error) { return g.head, nil }
func (g *historyGuard) SetCatalogHead(head string) error {
	if g.fail {
		return os.ErrPermission
	}
	g.head = head
	return nil
}

func TestInstallVerifiedHistoryRestoresFreshVaultAndGuard(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	source := New(t.TempDir(), op, signing)
	snapshot, err := source.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("restored\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyRemoteHistory([]RemoteSnapshot{{ID: snapshot.Manifest.Snapshot, Ciphertext: snapshot.Ciphertext, Catalog: snapshot.ManifestBytes}}, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	guard := &historyGuard{}
	if err := InstallVerifiedHistory(root, history, op, signing, guard); err != nil {
		t.Fatal(err)
	}
	if guard.head != history.Head {
		t.Fatalf("guard=%q, want %q", guard.head, history.Head)
	}
	opened, err := OpenWithGuard(root, op, signing, guard)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Head != history.Head {
		t.Fatalf("head=%q, want %q", opened.Head, history.Head)
	}
}

func TestInstallVerifiedHistoryRollsBackFilesWhenGuardCommitFails(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	source := New(t.TempDir(), op, signing)
	snapshot, err := source.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("restored\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyRemoteHistory([]RemoteSnapshot{{ID: snapshot.Manifest.Snapshot, Ciphertext: snapshot.Ciphertext, Catalog: snapshot.ManifestBytes}}, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	guard := &historyGuard{fail: true}
	if err := InstallVerifiedHistory(root, history, op, signing, guard); err == nil {
		t.Fatal("failing guard commit unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("head persisted after rollback: %v", err)
	}
}

func TestInstallVerifiedHistoryRejectsUnverifiedInput(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallVerifiedHistory(t.TempDir(), VerifiedHistory{Head: "untrusted"}, op, signing, nil); err == nil {
		t.Fatal("unverified history accepted")
	}
}

func TestInstallVerifiedHistoryRollsBackWhenFinalValidationFails(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	source := New(t.TempDir(), op, signing)
	snapshot, err := source.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("restored"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyRemoteHistory([]RemoteSnapshot{{ID: snapshot.Manifest.Snapshot, Ciphertext: snapshot.Ciphertext, Catalog: snapshot.ManifestBytes}}, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	guard := &historyGuard{}
	err = InstallVerifiedHistoryWithCommit(root, history, op, signing, guard, func() error { return os.ErrInvalid })
	if err == nil {
		t.Fatal("final validation failure ignored")
	}
	if guard.head != "" {
		t.Fatalf("guard head after rollback=%q", guard.head)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("head persisted after rollback: %v", err)
	}
}
