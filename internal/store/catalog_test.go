package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
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

type testHeadGuard struct{ head string }

func (g *testHeadGuard) CatalogHead() (string, error)     { return g.head, nil }
func (g *testHeadGuard) SetCatalogHead(head string) error { g.head = head; return nil }
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
