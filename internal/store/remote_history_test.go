package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestInspectRemoteHistoryVerifiesEachForkedBranch(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}

	baseVault := New(t.TempDir(), op, signing)
	base, err := baseVault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("base\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	left, err := baseVault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("left\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}

	rightRoot := t.TempDir()
	for _, dir := range []string{"snapshots", "catalog"} {
		if err := os.Mkdir(filepath.Join(rightRoot, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []struct {
		path string
		data []byte
	}{
		{filepath.Join("snapshots", base.Manifest.Snapshot), base.Ciphertext},
		{filepath.Join("catalog", base.Manifest.Snapshot+".json"), base.ManifestBytes},
		{filepath.Join("head.json"), base.ManifestBytes},
	} {
		if err := os.WriteFile(filepath.Join(rightRoot, file.path), file.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	rightVault := New(rightRoot, op, signing)
	right, err := rightVault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("right\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}

	remote := []RemoteSnapshot{
		{ID: base.Manifest.Snapshot, Ciphertext: base.Ciphertext, Catalog: base.ManifestBytes},
		{ID: left.Manifest.Snapshot, Ciphertext: left.Ciphertext, Catalog: left.ManifestBytes},
		{ID: right.Manifest.Snapshot, Ciphertext: right.Ciphertext, Catalog: right.ManifestBytes},
	}
	inspection, err := InspectRemoteHistory(remote, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Branches) != 2 {
		t.Fatalf("branches=%d, want 2", len(inspection.Branches))
	}
	for _, branch := range inspection.Branches {
		if len(branch.Entries) != 2 || branch.Entries[1].ID != base.Manifest.Snapshot {
			t.Fatalf("branch %q entries=%v; want selected tip and shared base", branch.Head, branch.Entries)
		}
	}
	if inspection.Branches[0].Head >= inspection.Branches[1].Head {
		t.Fatalf("branches are not deterministically ordered: %q, %q", inspection.Branches[0].Head, inspection.Branches[1].Head)
	}
}

func TestInspectRemoteHistoryWithResolverLoadsEachMissingAncestorOnce(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := New(t.TempDir(), op, signing)
	var chain []RemoteSnapshot
	for _, content := range []string{"root", "middle", "tip"} {
		result, err := vault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte(content), Mode: 0600}})
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, RemoteSnapshot{ID: result.Manifest.Snapshot, Ciphertext: result.Ciphertext, Catalog: result.ManifestBytes})
	}
	byID := make(map[string]RemoteSnapshot, 2)
	byID[chain[0].ID], byID[chain[1].ID] = chain[0], chain[1]
	calls := make(map[string]int)
	inspection, err := InspectRemoteHistoryWithResolver(chain[2:], op, signing, func(id string) (RemoteSnapshot, bool, error) {
		calls[id]++
		item, ok := byID[id]
		return item, ok, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Branches) != 1 || inspection.Branches[0].Head != chain[2].ID || len(inspection.Branches[0].Entries) != 3 {
		t.Fatalf("inspection=%+v; want complete three-snapshot chain", inspection)
	}
	if calls[chain[1].ID] != 1 || calls[chain[0].ID] != 1 || len(calls) != 2 {
		t.Fatalf("resolver calls=%v; want each missing ancestor exactly once", calls)
	}
}

func TestInspectRemoteHistoryWithResolverReturnsSafeMissingAncestorError(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := New(t.TempDir(), op, signing)
	first, err := vault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("first"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("second"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectRemoteHistoryWithResolver([]RemoteSnapshot{{ID: second.Manifest.Snapshot, Ciphertext: second.Ciphertext, Catalog: second.ManifestBytes}}, op, signing, func(string) (RemoteSnapshot, bool, error) {
		return RemoteSnapshot{}, false, nil
	})
	var missing *MissingHistorySnapshotsError
	if !errors.As(err, &missing) || len(missing.SnapshotIDs) != 1 || missing.SnapshotIDs[0] != first.Manifest.Snapshot {
		t.Fatalf("error=%v missing=%+v; want generic incomplete-history error with requested ancestor available internally", err, missing)
	}
	if strings.Contains(err.Error(), first.Manifest.Snapshot) {
		t.Fatal("missing snapshot identifier leaked in error text")
	}
}

func TestRemoteHistorySnapshotCountLimit(t *testing.T) {
	if err := checkRemoteHistorySnapshotCount(maxRemoteHistorySnapshots - 1); err != nil {
		t.Fatalf("count below limit rejected: %v", err)
	}
	if err := checkRemoteHistorySnapshotCount(maxRemoteHistorySnapshots); err == nil || !strings.Contains(err.Error(), "supported limit") {
		t.Fatalf("count at limit error=%v; want supported-limit error", err)
	}
}

func TestCanonicalHistorySelectionIsEncryptedAndAuthenticated(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 64)
	raw, err := SealHistorySelection(head, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(head)) {
		t.Fatal("encrypted selection exposes the snapshot head")
	}
	selection, err := OpenHistorySelection(raw, op, signing.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if selection.Head != head {
		t.Fatalf("selection head=%q, want selected head", selection.Head)
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenHistorySelection(tampered, op, signing.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("tampered selection accepted")
	}
	if _, err := OpenHistorySelection(raw, make([]byte, 32), signing.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("selection encrypted with another key was accepted")
	}
}

func TestVerifyRemoteHistoryUsesSignedCanonicalSelection(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	makeRoot := func(content string) SnapshotResult {
		vault := New(t.TempDir(), op, signing)
		result, err := vault.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte(content), Mode: 0600}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	left, right := makeRoot("left\n"), makeRoot("right\n")
	remote := []RemoteSnapshot{
		{ID: left.Manifest.Snapshot, Ciphertext: left.Ciphertext, Catalog: left.ManifestBytes},
		{ID: right.Manifest.Snapshot, Ciphertext: right.Ciphertext, Catalog: right.ManifestBytes},
	}
	selection, err := SealHistorySelection(right.Manifest.Snapshot, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyRemoteHistoryWithSelection(remote, selection, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if history.Head != right.Manifest.Snapshot || string(history.Entries[0].Records[0].Data) != "right\n" {
		t.Fatalf("selected history=%+v", history)
	}
	if _, err := VerifyRemoteHistoryWithSelection(remote, []byte("invalid"), op, signing); err == nil {
		t.Fatal("invalid canonical selection accepted")
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

func TestInstallVerifiedHistoryRejectsMutationAfterVerification(t *testing.T) {
	op, signing, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	source := New(t.TempDir(), op, signing)
	snapshot, err := source.SaveIfChanged([]Record{{Path: ".zshrc", Data: []byte("verified"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyRemoteHistory([]RemoteSnapshot{{ID: snapshot.Manifest.Snapshot, Ciphertext: snapshot.Ciphertext, Catalog: snapshot.ManifestBytes}}, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	history.Entries[0].Ciphertext[len(history.Entries[0].Ciphertext)-1] ^= 0xff
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	guard := &historyGuard{}
	callbackCalled := false
	err = InstallVerifiedHistoryWithCommit(root, history, op, signing, guard, func() error { callbackCalled = true; return nil })
	if err == nil {
		t.Fatal("mutated verified ciphertext was accepted")
	}
	if callbackCalled || guard.head != "" {
		t.Fatalf("callback=%v guard=%q after rejecting mutated history", callbackCalled, guard.head)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("head written from mutated history: %v", err)
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
