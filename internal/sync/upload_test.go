package sync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
)

type fakeProvider struct {
	uploads, catalogs int
	download, catalog []byte
	privateCalls      int
	privateErr        error
}

func testUploadGate(t *testing.T, operational []byte) (UploadGate, []recovery.Share) {
	t.Helper()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(operational, signing)
	if err != nil {
		t.Fatal(err)
	}
	return UploadGate{OperationalKey: operational, SigningKey: signing}, shares
}

func (f *fakeProvider) Upload(context.Context, string, []byte) error        { f.uploads++; return nil }
func (f *fakeProvider) UploadCatalog(context.Context, string, []byte) error { f.catalogs++; return nil }
func (f *fakeProvider) Download(context.Context, string) ([]byte, error)    { return f.download, nil }
func (f *fakeProvider) DownloadCatalog(context.Context, string) ([]byte, error) {
	return f.catalog, nil
}
func (f *fakeProvider) List(context.Context) ([]string, error) { return nil, nil }
func (f *fakeProvider) Health(context.Context) error           { return nil }
func (f *fakeProvider) VerifyPrivate(context.Context) error {
	f.privateCalls++
	return f.privateErr
}

func TestUploadRequiresPrivateProviderBeforeCiphertext(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	gate, shares := testUploadGate(t, key)
	var err error
	manifest, err := store.SealManifest(store.Manifest{Snapshot: "id"}, key)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{privateErr: errors.New("repository is public")}
	if err := gate.UploadSnapshot(context.Background(), p, "id", []byte("cipher"), manifest, shares[:2]); err == nil {
		t.Fatal("public provider accepted")
	}
	if p.privateCalls != 1 || p.uploads != 0 || p.catalogs != 0 {
		t.Fatalf("privacy gate calls=%d uploads=%d catalogs=%d", p.privateCalls, p.uploads, p.catalogs)
	}
	p.privateErr = nil
	if err := gate.UploadSnapshot(context.Background(), p, "id", []byte("cipher"), manifest, shares[:2]); err != nil {
		t.Fatal(err)
	}
}

func TestUploadRequiresRecovery(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	gate, shares := testUploadGate(t, key)
	var err error
	p := &fakeProvider{}
	if err = gate.Upload(context.Background(), p, "id", []byte("cipher"), shares[:1]); err == nil || p.uploads != 0 {
		t.Fatal("uploaded without recovery")
	}
	if err = gate.Upload(context.Background(), p, "id", []byte("cipher"), shares[:2]); err != nil || p.uploads != 1 {
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
	manifest, err := store.SealManifest(m, op)
	if err != nil {
		t.Fatal(err)
	}
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
	gate, shares := testUploadGate(t, key)
	p := &fakeProvider{}
	manifest, err := store.SealManifest(store.Manifest{Snapshot: "id"}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.UploadSnapshot(context.Background(), p, "id", []byte("cipher"), manifest, shares[:2]); err != nil || p.uploads != 1 || p.catalogs != 1 {
		t.Fatalf("snapshot upload: %v uploads=%d catalogs=%d", err, p.uploads, p.catalogs)
	}
	if err := gate.UploadSnapshot(context.Background(), p, "other", []byte("cipher"), manifest, shares[:2]); err == nil {
		t.Fatal("manifest mismatch accepted")
	}
}

func TestUploadSnapshotValidatesV1RecoveryBundleBeforeProvider(t *testing.T) {
	operational, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(operational, signing)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.SealManifest(store.Manifest{Snapshot: "id"}, operational)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	gate := UploadGate{OperationalKey: operational, SigningKey: signing}
	if err := gate.UploadSnapshot(context.Background(), provider, "id", []byte("cipher"), manifest, shares[:2]); err != nil {
		t.Fatalf("normal v1 recovery shares rejected: %v", err)
	}
	if provider.uploads != 1 || provider.catalogs != 1 || provider.privateCalls != 1 {
		t.Fatalf("provider calls after valid shares: private=%d uploads=%d catalogs=%d", provider.privateCalls, provider.uploads, provider.catalogs)
	}

	otherOperational, otherSigning, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	otherShares, err := store.RecoveryShares(otherOperational, otherSigning)
	if err != nil {
		t.Fatal(err)
	}
	provider = &fakeProvider{}
	gate = UploadGate{OperationalKey: operational, SigningKey: signing}
	if err := gate.UploadSnapshot(context.Background(), provider, "id", []byte("cipher"), manifest, otherShares[:2]); err == nil {
		t.Fatal("shares from another vault accepted")
	}
	if provider.privateCalls != 0 || provider.uploads != 0 || provider.catalogs != 0 {
		t.Fatalf("provider reached before rejecting other-vault shares: private=%d uploads=%d catalogs=%d", provider.privateCalls, provider.uploads, provider.catalogs)
	}

	_, wrongSigning, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sameVaultOperationalShares, err := store.RecoveryShares(operational, wrongSigning)
	if err != nil {
		t.Fatal(err)
	}
	provider = &fakeProvider{}
	if err := gate.UploadSnapshot(context.Background(), provider, "id", []byte("cipher"), manifest, sameVaultOperationalShares[:2]); err == nil {
		t.Fatal("shares with the active operational key but another signing key accepted")
	}
	if provider.privateCalls != 0 || provider.uploads != 0 || provider.catalogs != 0 {
		t.Fatalf("provider reached before rejecting wrong signing key: private=%d uploads=%d catalogs=%d", provider.privateCalls, provider.uploads, provider.catalogs)
	}
}
