package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestSaveIfChangedReusesCurrentSnapshotAndDetectsRecordChanges(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, op, sign)
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("same")}}

	first, err := v.SaveIfChanged(records)
	if err != nil {
		t.Fatal(err)
	}
	if first.Unchanged {
		t.Fatal("first save was marked unchanged")
	}
	headBefore, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	countBefore, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}

	second, err := v.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("same")}})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Unchanged || second.Manifest.Snapshot != first.Manifest.Snapshot {
		t.Fatalf("second result = (unchanged=%t, snapshot=%q), want reuse of %q", second.Unchanged, second.Manifest.Snapshot, first.Manifest.Snapshot)
	}
	if !bytes.Equal(first.Ciphertext, second.Ciphertext) || !bytes.Equal(first.ManifestBytes, second.ManifestBytes) {
		t.Fatal("unchanged result did not reuse exact stored snapshot and manifest bytes")
	}
	headAfter, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil || !bytes.Equal(headBefore, headAfter) {
		t.Fatalf("unchanged capture changed head: %v", err)
	}
	countAfter, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(countAfter) != len(countBefore) {
		t.Fatalf("unchanged capture changed snapshot count: before=%d after=%d err=%v", len(countBefore), len(countAfter), err)
	}

	for _, changed := range [][]Record{
		{{Path: "other", Mode: 0600, Data: []byte("same")}},
		{{Path: "config", Mode: 0640, Data: []byte("same")}},
		{{Path: "config", Mode: 0600, Data: []byte("changed")}},
	} {
		result, err := v.SaveIfChanged(changed)
		if err != nil {
			t.Fatal(err)
		}
		if result.Unchanged {
			t.Fatalf("changed records were treated as unchanged: %#v", changed)
		}
		if result.Manifest.Metadata == nil || result.Manifest.Metadata.ContentFingerprint == "" {
			t.Fatal("new snapshot is missing signed content metadata")
		}
		if err := v.Verify(result.Manifest, sign.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("new snapshot metadata did not verify: %v", err)
		}
	}
}

func TestSaveIfChangedComparesLegacyHeadWithoutCreatingSnapshot(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, op, sign)
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("legacy")}}
	legacy := writeLegacySnapshot(t, v, records)
	headBefore, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	countBefore, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := v.SaveIfChanged(records)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged || result.Manifest.Snapshot != legacy.Snapshot || result.Manifest.Metadata != nil {
		t.Fatalf("legacy comparison result = %#v, want unchanged legacy head", result)
	}
	headAfter, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil || !bytes.Equal(headBefore, headAfter) {
		t.Fatalf("legacy no-op changed head: %v", err)
	}
	countAfter, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(countAfter) != len(countBefore) {
		t.Fatalf("legacy no-op changed snapshot count: before=%d after=%d err=%v", len(countBefore), len(countAfter), err)
	}
}

func TestSnapshotMetadataKeepsLegacySignatureAndAuthenticatesMetadata(t *testing.T) {
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := New(t.TempDir(), op, sign)
	result, err := v.SaveIfChanged([]Record{{Path: "config", Mode: 0600, Data: []byte("content")}})
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(result.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestJSON, []byte(`"metadata"`)) {
		t.Fatal("new manifest JSON is missing the optional metadata field")
	}
	legacy := struct {
		Version   int       `json:"version"`
		CreatedAt time.Time `json:"created_at"`
		Previous  string    `json:"previous"`
		Snapshot  string    `json:"snapshot"`
		Signer    string    `json:"signer"`
		Signature string    `json:"signature"`
	}{}
	if err := json.Unmarshal(manifestJSON, &legacy); err != nil {
		t.Fatalf("legacy manifest reader rejected unknown metadata field: %v", err)
	}
	legacySignature, err := hex.DecodeString(legacy.Signature)
	if err != nil {
		t.Fatalf("decode legacy manifest signature: %v", err)
	}
	legacy.Signature = ""
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(sign.Public().(ed25519.PublicKey), legacyBytes, legacySignature) {
		t.Fatal("new manifest legacy signature does not verify with legacy JSON reader")
	}

	tampered := result.Manifest
	metadata := *result.Manifest.Metadata
	metadata.Signature = strings.Repeat("0", ed25519.SignatureSize*2)
	tampered.Metadata = &metadata
	if err := v.Verify(tampered, sign.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("tampered metadata signature was accepted")
	}
	unsupported := result.Manifest
	metadata = *result.Manifest.Metadata
	metadata.Version++
	unsupported.Metadata = &metadata
	if err := v.Verify(unsupported, sign.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("unsupported metadata version was accepted")
	}
}

func TestConcurrentSaveIfChangedCreatesOneSnapshot(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstVault := New(root, op, sign)
	secondVault := New(root, op, sign)
	records := []Record{{Path: "config", Mode: 0600, Data: []byte("same")}}
	start := make(chan struct{})
	results := make(chan SnapshotResult, 2)
	errs := make(chan error, 2)
	for _, vault := range []*Vault{firstVault, secondVault} {
		go func(vault *Vault) {
			<-start
			input := append([]Record(nil), records...)
			result, err := vault.SaveIfChanged(input)
			results <- result
			errs <- err
		}(vault)
	}
	close(start)
	first, second := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if first.Manifest.Snapshot != second.Manifest.Snapshot || first.Unchanged == second.Unchanged {
		t.Fatalf("concurrent results = (%q, unchanged=%t), (%q, unchanged=%t)", first.Manifest.Snapshot, first.Unchanged, second.Manifest.Snapshot, second.Unchanged)
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("concurrent snapshot count=%d err=%v, want 1", len(entries), err)
	}
}

func writeLegacySnapshot(t *testing.T, v *Vault, records []Record) Manifest {
	t.Helper()
	canonical := append([]Record(nil), records...)
	sortRecords(canonical)
	plain, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := crypt.Seal(plain, v.Operational)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(ciphertext)
	id := hex.EncodeToString(hash[:])
	manifest := Manifest{
		Version: 1, CreatedAt: time.Now().UTC(), Snapshot: id,
		Signer: crypt.Fingerprint(v.Signing.Public().(ed25519.PublicKey)),
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(v.Signing, manifestBytes(manifest)))
	sealed, err := SealManifest(manifest, v.Operational)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		filepath.Join(v.Root, "snapshots", id):       ciphertext,
		filepath.Join(v.Root, "catalog", id+".json"): sealed,
		filepath.Join(v.Root, "head.json"):           sealed,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	v.Head = id
	return manifest
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
