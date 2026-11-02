package sync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
	"os"
	"path/filepath"
	"testing"
)

type fakeProvider struct {
	uploads, catalogs int
	download, catalog []byte
}

func (f *fakeProvider) Upload(context.Context, string, []byte) error        { f.uploads++; return nil }
func (f *fakeProvider) UploadCatalog(context.Context, string, []byte) error { f.catalogs++; return nil }
func (f *fakeProvider) Download(context.Context, string) ([]byte, error)    { return f.download, nil }
func (f *fakeProvider) DownloadCatalog(context.Context, string) ([]byte, error) {
	return f.catalog, nil
}
func (f *fakeProvider) List(context.Context) ([]string, error) { return nil, nil }
func (f *fakeProvider) Health(context.Context) error           { return nil }
func TestUploadRequiresRecovery(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	shares, err := recovery.Split(key)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{}
	g := UploadGate{OperationalKey: key}
	if err = g.Upload(context.Background(), p, "id", []byte("cipher"), []recovery.Share{shares[0]}); err == nil || p.uploads != 0 {
		t.Fatal("uploaded without recovery")
	}
	if err = g.Upload(context.Background(), p, "id", []byte("cipher"), []recovery.Share{shares[0], shares[1]}); err != nil || p.uploads != 1 {
		t.Fatalf("verified upload: %v %d", err, p.uploads)
	}
}

func TestRestoreRemoteVerifiesAndRestoresAtomically(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	v := store.New(root, op, sign)
	m, err := v.Save([]store.Record{{Path: "config", Data: []byte("new"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _ := os.ReadFile(filepath.Join(root, "snapshots", m.Snapshot))
	manifest, _ := json.Marshal(m)
	p := &fakeProvider{download: ciphertext, catalog: manifest}
	target := filepath.Join(t.TempDir(), "home")
	os.MkdirAll(target, 0700)
	os.WriteFile(filepath.Join(target, "config"), []byte("old"), 0600)
	if err := RestoreRemote(context.Background(), p, v, m.Snapshot, sign.Public().(ed25519.PublicKey), target, filepath.Join(t.TempDir(), "backups")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "config"))
	if string(got) != "new" {
		t.Fatalf("got %q", got)
	}
}

func TestRestoreRemoteAtAllowsVerifiedHistoricalSelection(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	v := store.New(root, op, sign)
	m1, err := v.Save([]store.Record{{Path: "config", Data: []byte("old"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := v.Save([]store.Record{{Path: "config", Data: []byte("new"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	oldCiphertext, _ := os.ReadFile(filepath.Join(root, "snapshots", m1.Snapshot))
	oldManifest, _ := os.ReadFile(filepath.Join(root, "catalog", m1.Snapshot+".json"))
	p := &fakeProvider{download: oldCiphertext, catalog: oldManifest}
	target := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreRemoteAt(context.Background(), p, v, m1.Snapshot, sign.Public().(ed25519.PublicKey), target, filepath.Join(t.TempDir(), "backups")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "config"))
	if string(got) != "old" || v.Head != m2.Snapshot {
		t.Fatalf("historical restore got %q and changed head to %s", got, v.Head)
	}
}

func TestUploadSnapshotRequiresValidManifestAndUploadsCatalog(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	shares, _ := recovery.Split(key)
	p := &fakeProvider{}
	g := UploadGate{OperationalKey: key}
	manifest := []byte(`{"snapshot":"id"}`)
	if err := g.UploadSnapshot(context.Background(), p, "id", []byte("cipher"), manifest, []recovery.Share{shares[0], shares[1]}); err != nil || p.uploads != 1 || p.catalogs != 1 {
		t.Fatalf("snapshot upload: %v uploads=%d catalogs=%d", err, p.uploads, p.catalogs)
	}
	if err := g.UploadSnapshot(context.Background(), p, "other", []byte("cipher"), manifest, []recovery.Share{shares[0], shares[1]}); err == nil {
		t.Fatal("manifest mismatch accepted")
	}
}
