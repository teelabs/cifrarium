package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type auditGuard struct {
	head   string
	writes int
}

func (g *auditGuard) CatalogHead() (string, error) { return g.head, nil }
func (g *auditGuard) SetCatalogHead(head string) error {
	g.writes++
	g.head = head
	return nil
}

func newAuditVault(t *testing.T, root string, guard *auditGuard) *Vault {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithGuard(root, key, signing, guard)
}

func TestAuditCurrentWithoutSnapshotDoesNotCollectOrCreateLock(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)

	result, err := vault.AuditCurrent(func() ([]Record, error) {
		t.Fatal("audit captured adapter files without a baseline")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != AuditNoSnapshot || result.Snapshot != "" || len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) != 0 {
		t.Fatalf("no-snapshot result = %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(root, ".recovery.lock")); !os.IsNotExist(err) {
		t.Fatalf("no-snapshot audit created recovery lock: %v", err)
	}
	if guard.writes != 0 || guard.head != "" {
		t.Fatalf("audit changed keyring guard: %#v", guard)
	}
}

func TestAuditCurrentReportsSortedPathContentAndModeDifferencesWithoutMutation(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	baseline := []Record{
		{Path: "z-missing", Mode: 0600, Data: []byte("gone")},
		{Path: "changed", Mode: 0644, Data: []byte("old bytes")},
		{Path: "content-only", Mode: 0644, Data: []byte("old content")},
		{Path: "mode-only", Mode: 0644, Data: []byte("same content")},
		{Path: "b-missing", Mode: 0600, Data: []byte("gone")},
		{Path: "same", Mode: 0600, Data: []byte("same bytes")},
	}
	snapshot, err := vault.SaveIfChanged(baseline)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	guardBefore, guardWritesBefore := guard.head, guard.writes
	snapshotsBefore, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	current := []Record{
		{Path: "same", Mode: 0600, Data: []byte("same bytes")},
		{Path: "changed", Mode: 0600, Data: []byte("new bytes")},
		{Path: "content-only", Mode: 0644, Data: []byte("new content")},
		{Path: "mode-only", Mode: 0600, Data: []byte("same content")},
		{Path: "m-added", Mode: 0600, Data: []byte("new")},
		{Path: "a-added", Mode: 0600, Data: []byte("new")},
	}

	result, err := vault.AuditCurrent(func() ([]Record, error) { return current, nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != AuditDiffers || result.Snapshot != snapshot.Manifest.Snapshot {
		t.Fatalf("audit result identity = %#v", result)
	}
	if !reflect.DeepEqual(result.Added, []string{"a-added", "m-added"}) ||
		!reflect.DeepEqual(result.Missing, []string{"b-missing", "z-missing"}) ||
		!reflect.DeepEqual(result.ContentChanged, []string{"changed", "content-only"}) ||
		!reflect.DeepEqual(result.ModeChanged, []string{"changed", "mode-only"}) {
		t.Fatalf("audit differences = %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"old bytes", "new bytes", vault.Root, "snapshot-"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit output exposed %q: %s", forbidden, encoded)
		}
	}
	headAfter, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil || !bytes.Equal(headBefore, headAfter) {
		t.Fatalf("audit changed head: %v", err)
	}
	snapshotsAfter, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(snapshotsAfter) != len(snapshotsBefore) {
		t.Fatalf("audit changed snapshots: before=%d after=%d err=%v", len(snapshotsBefore), len(snapshotsAfter), err)
	}
	if guard.head != guardBefore || guard.writes != guardWritesBefore {
		t.Fatalf("audit changed keyring guard: before=(%q,%d) after=(%q,%d)", guardBefore, guardWritesBefore, guard.head, guard.writes)
	}
}

func TestAuditCurrentReportsMatchesWithAnExistingSharedLock(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("unchanged")}}
	snapshot, err := vault.SaveIfChanged(records)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := vault.AuditCurrent(func() ([]Record, error) { return records, nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != AuditMatches || result.Snapshot != snapshot.Manifest.Snapshot {
		t.Fatalf("matching audit = %#v", result)
	}
	if result.Added == nil || result.Missing == nil || result.ContentChanged == nil || result.ModeChanged == nil {
		t.Fatalf("matching audit did not return empty lists: %#v", result)
	}
	headAfter, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil || !bytes.Equal(headBefore, headAfter) {
		t.Fatalf("matching audit changed head: %v", err)
	}
}

func TestAuditCurrentWaitsForExistingExclusiveRecoveryLock(t *testing.T) {
	root := t.TempDir()
	vault := newAuditVault(t, root, &auditGuard{})
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("unchanged")}}
	if _, err := vault.SaveIfChanged(records); err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- withVaultLock(root, func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	captured := make(chan struct{})
	auditDone := make(chan error, 1)
	go func() {
		_, err := vault.AuditCurrent(func() ([]Record, error) {
			close(captured)
			return records, nil
		})
		auditDone <- err
	}()
	select {
	case <-captured:
		close(release)
		t.Fatal("audit read adapter records while an exclusive recovery lock was held")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	if err := <-auditDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-captured:
	default:
		t.Fatal("audit did not resume after releasing exclusive lock")
	}
}

func TestAuditCurrentRejectsLockThatAppearsDuringUnlockedRead(t *testing.T) {
	root := t.TempDir()
	vault := newAuditVault(t, root, &auditGuard{})
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("unchanged")}}
	if _, err := vault.SaveIfChanged(records); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".recovery.lock")); err != nil {
		t.Fatal(err)
	}
	result, err := vault.AuditCurrent(func() ([]Record, error) {
		if err := os.WriteFile(filepath.Join(root, ".recovery.lock"), nil, 0600); err != nil {
			return nil, err
		}
		return records, nil
	})
	if err == nil || result.Status != "" {
		t.Fatalf("audit accepted lock appearing mid-read: result=%#v err=%v", result, err)
	}
}

func TestAuditCurrentDoesNotCreateLockWhenBaselineExistsWithoutOne(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("unchanged")}}
	if _, err := vault.SaveIfChanged(records); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".recovery.lock")); err != nil {
		t.Fatal(err)
	}
	result, err := vault.AuditCurrent(func() ([]Record, error) { return records, nil })
	if err != nil || result.Status != AuditMatches {
		t.Fatalf("audit result=%#v err=%v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".recovery.lock")); !os.IsNotExist(err) {
		t.Fatalf("audit created recovery lock: %v", err)
	}
}

func TestAuditCurrentRejectsHeadChangeDuringCapture(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	if _, err := vault.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("baseline")}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".recovery.lock")); err != nil {
		t.Fatal(err)
	}
	concurrent := NewWithGuard(root, vault.Operational, vault.Signing, guard)
	result, err := vault.AuditCurrent(func() ([]Record, error) {
		if _, saveErr := concurrent.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("concurrent")}}); saveErr != nil {
			return nil, saveErr
		}
		return []Record{{Path: "config", Mode: 0600, Data: []byte("captured")}}, nil
	})
	if err == nil || result.Status != "" || result.Snapshot != "" || len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) != 0 {
		t.Fatalf("concurrent head change returned partial success: result=%#v err=%v", result, err)
	}
}

func TestAuditCurrentRejectsGuardChangeDuringCapture(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	if _, err := vault.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("baseline")}}); err != nil {
		t.Fatal(err)
	}
	guard.writes = 0
	result, err := vault.AuditCurrent(func() ([]Record, error) {
		guard.head = "changed-guard"
		return []Record{{Path: "config", Mode: 0600, Data: []byte("baseline")}}, nil
	})
	if err == nil || result.Status != "" || result.Snapshot != "" || len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) != 0 {
		t.Fatalf("concurrent guard change returned partial success: result=%#v err=%v", result, err)
	}
}

func TestAuditCurrentRejectsInvalidHeadWithoutPartialResult(t *testing.T) {
	root := t.TempDir()
	guard := &auditGuard{}
	vault := newAuditVault(t, root, guard)
	if _, err := vault.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("baseline")}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "head.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := vault.AuditCurrent(func() ([]Record, error) {
		return []Record{{Path: "config", Mode: 0600, Data: []byte("changed")}}, nil
	})
	if err == nil || result.Status != "" || result.Snapshot != "" || len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) != 0 {
		t.Fatalf("invalid head returned partial result: result=%#v err=%v", result, err)
	}
}

func TestAuditCurrentRejectsInvalidCatalogManifestWithoutPartialResult(t *testing.T) {
	root := t.TempDir()
	vault := newAuditVault(t, root, &auditGuard{})
	snapshot, err := vault.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("baseline")}})
	if err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(root, "catalog", snapshot.Manifest.Snapshot+".json")
	if err := os.WriteFile(catalog, []byte("invalid manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := vault.AuditCurrent(func() ([]Record, error) {
		return []Record{{Path: "config", Mode: 0600, Data: []byte("changed")}}, nil
	})
	if err == nil || result.Status != "" || result.Snapshot != "" || len(result.Added)+len(result.Missing)+len(result.ContentChanged)+len(result.ModeChanged) != 0 {
		t.Fatalf("invalid catalog manifest returned partial result: result=%#v err=%v", result, err)
	}
}
