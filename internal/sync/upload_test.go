package sync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
)

func TestUploadSnapshotAcceptsEquivalentLegacyRemoteManifestOnUpgrade(t *testing.T) {
	root := t.TempDir()
	operational := make([]byte, 32)
	if _, err := rand.Read(operational); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records := []store.Record{{Path: "config", Mode: 0600, Data: []byte("same")}}
	vault := store.New(filepath.Join(root, "vault"), operational, signing)
	legacyManifest, err := vault.Save(records)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(vault.Root, "snapshots", legacyManifest.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	legacyUploadedManifest, err := store.SealManifest(legacyManifest, operational)
	if err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(root, "remote.git")
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", bare).CombinedOutput(); err != nil {
		t.Fatalf("initialize bare remote: %v (%s)", err, out)
	}
	gitBinary, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	remoteURL := "https://github.com/teelabs/cifrarium-test.git"
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrapper := fmt.Sprintf("#!/bin/bash\nargs=()\nrewrite=1\nif [[ \" $* \" == *' remote add origin '* ]]; then rewrite=0; fi\nfor arg in \"$@\"; do\n  if [[ $rewrite == 1 && \"$arg\" == %s ]]; then arg=%s; fi\n  args+=(\"$arg\")\ndone\nexec %s \"${args[@]}\"\n", strconv.Quote(remoteURL), strconv.Quote(bare), strconv.Quote(gitBinary))
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "gh"), []byte("#!/bin/sh\nprintf 'true\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	git := provider.Git{Dir: filepath.Join(root, "provider"), Remote: remoteURL}
	if err := git.UploadSnapshot(context.Background(), legacyManifest.Snapshot, ciphertext, legacyUploadedManifest); err != nil {
		t.Fatalf("seed provider using legacy upload bytes: %v", err)
	}
	remoteCommitsBefore, err := exec.Command(gitBinary, "--git-dir", bare, "rev-list", "--count", "refs/heads/main").Output()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := store.RecoveryShares(operational, signing)
	if err != nil {
		t.Fatal(err)
	}
	gate := UploadGate{OperationalKey: operational, SigningKey: signing}
	current, err := vault.SaveIfChanged(records)
	if err != nil || !current.Unchanged {
		t.Fatalf("upgrade capture unchanged=%t err=%v", current.Unchanged, err)
	}
	if bytes.Equal(legacyUploadedManifest, current.ManifestBytes) {
		t.Fatal("fixture did not reproduce legacy double-sealing difference")
	}
	if err := gate.UploadSnapshot(context.Background(), git, current.Manifest.Snapshot, current.Ciphertext, current.ManifestBytes, shares[:2]); err != nil {
		t.Fatalf("upgrade upload rejected equivalent current manifest: %v", err)
	}
	remoteManifest, err := exec.Command(gitBinary, "--git-dir", bare, "show", "refs/heads/main:catalog/"+legacyManifest.Snapshot+".json").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remoteManifest, legacyUploadedManifest) {
		t.Fatal("upgrade rewrote the existing remote manifest instead of accepting its verified equivalent")
	}
	remoteCommitsAfter, err := exec.Command(gitBinary, "--git-dir", bare, "rev-list", "--count", "refs/heads/main").Output()
	if err != nil || !bytes.Equal(remoteCommitsBefore, remoteCommitsAfter) {
		t.Fatalf("equivalent upload created a remote commit: before=%q after=%q err=%v", remoteCommitsBefore, remoteCommitsAfter, err)
	}
	clone := filepath.Join(root, "clone")
	if out, err := exec.Command(gitBinary, "clone", bare, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone test remote: %v (%s)", err, out)
	}
	if err := os.Remove(filepath.Join(clone, "objects", legacyManifest.Snapshot)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-C", clone, "add", "-u"},
		{"-C", clone, "-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-m", "remove snapshot object"},
		{"-C", clone, "push", "origin", "main"},
	} {
		if out, err := exec.Command(gitBinary, args...).CombinedOutput(); err != nil {
			t.Fatalf("make partial remote snapshot: git %v: %v (%s)", args, err, out)
		}
	}
	if err := gate.UploadSnapshot(context.Background(), git, current.Manifest.Snapshot, current.Ciphertext, current.ManifestBytes, shares[:2]); err != nil {
		t.Fatalf("upload missing object beside equivalent remote manifest: %v", err)
	}
	remoteCiphertext, err := exec.Command(gitBinary, "--git-dir", bare, "show", "refs/heads/main:objects/"+legacyManifest.Snapshot).Output()
	if err != nil || !bytes.Equal(remoteCiphertext, ciphertext) {
		t.Fatalf("partial remote object was not repaired with exact ciphertext: err=%v", err)
	}
	remoteManifest, err = exec.Command(gitBinary, "--git-dir", bare, "show", "refs/heads/main:catalog/"+legacyManifest.Snapshot+".json").Output()
	if err != nil || !bytes.Equal(remoteManifest, legacyUploadedManifest) {
		t.Fatalf("partial repair changed the verified legacy catalog bytes: err=%v", err)
	}
	if out, err := exec.Command(gitBinary, "-C", clone, "pull", "--ff-only", "origin", "main").CombinedOutput(); err != nil {
		t.Fatalf("synchronize test clone before catalog repair: %v (%s)", err, out)
	}
	if err := os.Remove(filepath.Join(clone, "catalog", legacyManifest.Snapshot+".json")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-C", clone, "add", "-u"},
		{"-C", clone, "-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-m", "remove catalog object"},
		{"-C", clone, "push", "origin", "main"},
	} {
		if out, err := exec.Command(gitBinary, args...).CombinedOutput(); err != nil {
			t.Fatalf("make partial remote catalog: git %v: %v (%s)", args, err, out)
		}
	}
	if err := gate.UploadSnapshot(context.Background(), git, current.Manifest.Snapshot, current.Ciphertext, current.ManifestBytes, shares[:2]); err != nil {
		t.Fatalf("upload missing catalog beside existing snapshot: %v", err)
	}
	remoteManifest, err = exec.Command(gitBinary, "--git-dir", bare, "show", "refs/heads/main:catalog/"+legacyManifest.Snapshot+".json").Output()
	if err != nil || !bytes.Equal(remoteManifest, current.ManifestBytes) {
		t.Fatalf("catalog repair did not upload current stored manifest bytes: err=%v", err)
	}

	// A matching snapshot path is not enough: a catalog with an invalid
	// metadata signature must still be rejected as a conflicting object.
	if out, err := exec.Command(gitBinary, "-C", clone, "pull", "--ff-only", "origin", "main").CombinedOutput(); err != nil {
		t.Fatalf("synchronize test clone before tampering: %v (%s)", err, out)
	}
	forged := legacyManifest
	forged.Metadata = &store.SnapshotMetadata{
		Version: 1, ContentFingerprint: strings.Repeat("0", 64),
		Signature: strings.Repeat("0", ed25519.SignatureSize*2),
	}
	forgedBytes, err := store.SealManifest(forged, operational)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clone, "catalog", legacyManifest.Snapshot+".json"), forgedBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-C", clone, "add", "catalog/" + legacyManifest.Snapshot + ".json"},
		{"-C", clone, "-c", "user.name=test", "-c", "user.email=test@localhost", "commit", "-m", "replace with invalid metadata"},
		{"-C", clone, "push", "origin", "main"},
	} {
		if out, err := exec.Command(gitBinary, args...).CombinedOutput(); err != nil {
			t.Fatalf("update test remote with invalid manifest: git %v: %v (%s)", args, err, out)
		}
	}
	if err := gate.UploadSnapshot(context.Background(), git, current.Manifest.Snapshot, current.Ciphertext, current.ManifestBytes, shares[:2]); err == nil {
		t.Fatal("invalid remote metadata was accepted based on its snapshot ID")
	}
}

type canonicalSnapshotFake struct {
	fakeProvider
	marker    []byte
	revision  string
	gotMarker []byte
	gotID     string
}

func (f *canonicalSnapshotFake) ReadRemoteHistorySelection(context.Context) ([]byte, string, error) {
	return f.marker, f.revision, nil
}
func (f *canonicalSnapshotFake) UploadSnapshotWithHistorySelection(_ context.Context, id string, _, _, marker []byte, revision string) error {
	f.gotID, f.gotMarker, f.revision = id, append([]byte(nil), marker...), revision
	return nil
}

func TestUploadSnapshotAtomicallyAdvancesSelectedHistory(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	base, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("base")}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("next")}})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := store.SealHistorySelection(base.Manifest.Snapshot, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(op, signing)
	if err != nil {
		t.Fatal(err)
	}
	p := &canonicalSnapshotFake{marker: marker, revision: "0123456789012345678901234567890123456789"}
	gate := UploadGate{OperationalKey: op, SigningKey: signing}
	if err := gate.UploadSnapshot(context.Background(), p, next.Manifest.Snapshot, next.Ciphertext, next.ManifestBytes, shares[:2]); err != nil {
		t.Fatal(err)
	}
	selection, err := store.OpenHistorySelection(p.gotMarker, op, signing.Public().(ed25519.PublicKey))
	if err != nil || p.gotID != next.Manifest.Snapshot || selection.Head != next.Manifest.Snapshot {
		t.Fatalf("id=%q selection=%+v err=%v", p.gotID, selection, err)
	}
	updatedMarker := append([]byte(nil), p.gotMarker...)
	p.marker = updatedMarker
	p.gotMarker = nil
	if err := gate.UploadSnapshot(context.Background(), p, next.Manifest.Snapshot, next.Ciphertext, next.ManifestBytes, shares[:2]); err != nil {
		t.Fatal(err)
	}
	if p.gotID != next.Manifest.Snapshot || !bytes.Equal(p.gotMarker, updatedMarker) {
		t.Fatal("canonical retry did not reuse the exact marker for local cache repair")
	}
}

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
