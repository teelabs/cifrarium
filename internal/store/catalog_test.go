package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
	"github.com/teelabs/cifrarium/internal/limits"
)

func TestCatalogChainSurvivesRestartAndDetectsTamper(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, op, sign)
	m1, err := v.Save([]Record{{Path: "one", Data: []byte("1"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := v.Save([]Record{{Path: "two", Data: []byte("2"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(root, op, sign)
	if err != nil || restarted.Head != m2.Snapshot {
		t.Fatalf("restart: %v %s", err, restarted.Head)
	}
	rawHead, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawHead, []byte(`"snapshot"`)) || bytes.Contains(rawHead, []byte(m2.Snapshot)) {
		t.Fatal("catalog metadata is stored in plaintext")
	}
	if err := restarted.VerifyCurrentHead(m1.Snapshot); err == nil {
		t.Fatal("rollback accepted")
	}
	path := filepath.Join(root, "catalog", m1.Snapshot+".json")
	raw, _ := os.ReadFile(path)
	raw[len(raw)-2] ^= 1
	os.WriteFile(path, raw, 0600)
	if err := restarted.VerifyChain(m2.Snapshot, sign.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("tampered catalog accepted")
	}
}

func TestSaveRejectsOversizedSnapshotRecord(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, op, sign)
	if _, err := v.Save([]Record{{Path: "large", Data: bytes.Repeat([]byte("x"), int(limits.MaxCapturedFileBytes)+1)}}); err == nil {
		t.Fatal("oversized snapshot record accepted")
	}
}

func TestRecordsFromCiphertextRejectsOversizedRecord(t *testing.T) {
	op := make([]byte, 32)
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(t.TempDir(), op, sign)
	raw, err := json.Marshal([]Record{{Path: "large", Data: bytes.Repeat([]byte("x"), int(limits.MaxCapturedFileBytes)+1)}})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := crypt.Seal(raw, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RecordsFromCiphertext(ciphertext); err == nil {
		t.Fatal("oversized record from ciphertext accepted")
	}
}

func TestSnapshotCiphertextRejectsOversizedFileBeforeReading(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshots", "snapshot"), bytes.Repeat([]byte("x"), int(limits.MaxSnapshotCipherBytes)+1), 0600); err != nil {
		t.Fatal(err)
	}
	v := New(root, make([]byte, 32), nil)
	if _, err := v.SnapshotCiphertext("snapshot"); err == nil {
		t.Fatal("oversized snapshot ciphertext accepted")
	}
}

type testHeadGuard struct{ head string }

func (g *testHeadGuard) CatalogHead() (string, error)     { return g.head, nil }
func (g *testHeadGuard) SetCatalogHead(head string) error { g.head = head; return nil }

type failingHeadGuard struct {
	head     string
	attempts int
}

func (g *failingHeadGuard) CatalogHead() (string, error) { return g.head, nil }
func (g *failingHeadGuard) SetCatalogHead(head string) error {
	g.attempts++
	if g.attempts == 1 {
		return errors.New("injected keyring head failure")
	}
	g.head = head
	return nil
}

func TestSaveRollsBackFilesWhenHeadGuardUpdateFails(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	guard := &failingHeadGuard{}
	v := NewWithGuard(root, op, sign, guard)
	_, err := v.Save([]Record{{Path: "one", Data: []byte("1")}})
	if err == nil {
		t.Fatal("head guard failure was ignored")
	}
	for _, dir := range []string{filepath.Join(root, "snapshots"), filepath.Join(root, "catalog")} {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("partial snapshot files survived in %s: entries=%d err=%v", dir, len(entries), readErr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(statErr) {
		t.Fatalf("partial head survived: %v", statErr)
	}
	if guard.head != "" || guard.attempts != 2 {
		t.Fatalf("guard was not restored: head=%q attempts=%d", guard.head, guard.attempts)
	}
}

func TestCatalogGuardRejectsReplayedHead(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	guard := &testHeadGuard{}
	v := NewWithGuard(root, op, sign, guard)
	m1, _ := v.Save([]Record{{Path: "one", Data: []byte("1"), Mode: 0600}})
	m2, _ := v.Save([]Record{{Path: "two", Data: []byte("2"), Mode: 0600}})
	old, _ := os.ReadFile(filepath.Join(root, "catalog", m1.Snapshot+".json"))
	_ = os.WriteFile(filepath.Join(root, "head.json"), old, 0600)
	if _, err := OpenWithGuard(root, op, sign, guard); err == nil {
		t.Fatalf("replayed head accepted; current=%s old=%s", m2.Snapshot, m1.Snapshot)
	}
}

func TestCatalogGuardRejectsMissingHead(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	guard := &testHeadGuard{head: "known-head"}
	if _, err := OpenWithGuard(root, op, sign, guard); err == nil {
		t.Fatal("missing head accepted with keyring guard")
	}
}

func TestVerifyHistoricalHeadRequiresActiveChain(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	v := New(root, op, sign)
	m1, _ := v.Save([]Record{{Path: "one", Data: []byte("1")}})
	m2, _ := v.Save([]Record{{Path: "two", Data: []byte("2")}})
	if err := v.VerifyHistoricalHead(m1.Snapshot, sign.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("historical snapshot rejected: %v", err)
	}
	if err := v.VerifyHistoricalHead("not-in-chain", sign.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("unanchored historical snapshot accepted")
	}
	if v.Head != m2.Snapshot {
		t.Fatalf("historical verification changed head: %s", v.Head)
	}
}

func TestMigrateCatalogEncryptsVerifiedLegacyMetadata(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	v := New(root, op, sign)
	m, err := v.Save([]Record{{Path: "one", Data: []byte("1")}})
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(root, "head.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "catalog", m.Snapshot+".json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := MigrateCatalog(root, op, sign.Public().(ed25519.PublicKey))
	if err != nil || !changed {
		t.Fatalf("migration: changed=%v err=%v", changed, err)
	}
	if _, err := Open(root, op, sign); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "head.json"))
	if bytes.Contains(raw, []byte(`"snapshot"`)) {
		t.Fatal("legacy metadata remains plaintext")
	}
}

func TestMigrateCatalogRollsBackWriteFailure(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	v := New(root, op, sign)
	m, err := v.Save([]Record{{Path: "one", Data: []byte("1")}})
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(m)
	headPath := filepath.Join(root, "head.json")
	catalogPath := filepath.Join(root, "catalog", m.Snapshot+".json")
	if err := os.WriteFile(headPath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	write := func(path string, data []byte, mode os.FileMode) error {
		calls++
		if calls == 2 {
			return errors.New("injected migration write failure")
		}
		return writeAtomic(path, data, mode)
	}
	if _, err := migrateCatalog(root, op, sign.Public().(ed25519.PublicKey), write); err == nil {
		t.Fatal("write failure accepted")
	}
	gotHead, _ := os.ReadFile(headPath)
	gotCatalog, _ := os.ReadFile(catalogPath)
	if !bytes.Equal(gotHead, legacy) || !bytes.Equal(gotCatalog, legacy) {
		t.Fatal("migration did not restore original plaintext metadata")
	}
}
