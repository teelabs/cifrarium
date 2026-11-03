package provider

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

type memoryProvider struct {
	objects    map[string][]byte
	catalogs   map[string][]byte
	atomic     bool
	privateErr error
}

func newMemoryProvider() *memoryProvider {
	return &memoryProvider{objects: map[string][]byte{}, catalogs: map[string][]byte{}}
}
func (m *memoryProvider) Upload(_ context.Context, id string, ciphertext []byte) error {
	m.objects[id] = append([]byte(nil), ciphertext...)
	return nil
}
func (m *memoryProvider) UploadCatalog(_ context.Context, id string, manifest []byte) error {
	m.catalogs[id] = append([]byte(nil), manifest...)
	return nil
}
func (m *memoryProvider) UploadSnapshot(_ context.Context, id string, ciphertext, manifest []byte) error {
	if !m.atomic {
		return errors.New("atomic upload unsupported")
	}
	if err := m.Upload(context.Background(), id, ciphertext); err != nil {
		return err
	}
	return m.UploadCatalog(context.Background(), id, manifest)
}
func (m *memoryProvider) Download(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), m.objects[id]...), nil
}
func (m *memoryProvider) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), m.catalogs[id]...), nil
}
func (m *memoryProvider) List(context.Context) ([]string, error) { return nil, nil }
func (m *memoryProvider) Health(context.Context) error           { return nil }
func (m *memoryProvider) VerifyPrivate(context.Context) error    { return m.privateErr }

type bareMigrationProvider struct {
	objects  map[string][]byte
	catalogs map[string][]byte
}

func (b *bareMigrationProvider) Upload(_ context.Context, id string, data []byte) error {
	if b.objects == nil {
		b.objects = map[string][]byte{}
	}
	b.objects[id] = append([]byte(nil), data...)
	return nil
}
func (b *bareMigrationProvider) UploadCatalog(_ context.Context, id string, data []byte) error {
	if b.catalogs == nil {
		b.catalogs = map[string][]byte{}
	}
	b.catalogs[id] = append([]byte(nil), data...)
	return nil
}
func (b *bareMigrationProvider) Download(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (b *bareMigrationProvider) DownloadCatalog(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (b *bareMigrationProvider) List(context.Context) ([]string, error) { return nil, nil }
func (b *bareMigrationProvider) Health(context.Context) error           { return nil }

func TestMigrateCopiesOpaqueSnapshotAndCatalogAtomically(t *testing.T) {
	source := newMemoryProvider()
	source.objects["snapshot"] = []byte("ciphertext")
	source.catalogs["snapshot"] = []byte(`{"snapshot":"snapshot"}`)
	destination := newMemoryProvider()
	destination.atomic = true
	if err := Migrate(context.Background(), source, destination, []string{"snapshot"}); err != nil {
		t.Fatal(err)
	}
	if string(destination.objects["snapshot"]) != "ciphertext" || string(destination.catalogs["snapshot"]) != `{"snapshot":"snapshot"}` {
		t.Fatal("opaque snapshot was not migrated")
	}
}

func TestMigrateRejectsDestinationWithoutPrivacyVerifierBeforeWriting(t *testing.T) {
	source := newMemoryProvider()
	source.objects["snapshot"] = []byte("ciphertext")
	source.catalogs["snapshot"] = []byte(`{"snapshot":"snapshot"}`)
	destination := &bareMigrationProvider{}
	if err := Migrate(context.Background(), source, destination, []string{"snapshot"}); err == nil {
		t.Fatal("migration accepted destination without privacy verification")
	}
	if len(destination.objects) != 0 || len(destination.catalogs) != 0 {
		t.Fatal("migration wrote before privacy verification")
	}
}

func TestGitCheckRemoteAccessReportsRevokedIdentityStyleFailure(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")
	if out, err := exec.Command("git", "init", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v (%s)", err, out)
	}
	local := filepath.Join(root, "local")
	g := Git{Dir: local}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.run(context.Background(), "remote", "add", "origin", bare); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckRemoteAccess(context.Background()); err != nil {
		t.Fatalf("healthy remote: %v", err)
	}
	if err := g.run(context.Background(), "remote", "set-url", "origin", filepath.Join(root, "revoked.git")); err != nil {
		t.Fatal(err)
	}
	err := g.CheckRemoteAccess(context.Background())
	var accessErr *RemoteAccessError
	if !errors.As(err, &accessErr) {
		t.Fatalf("expected remote access error, got %v", err)
	}
}

func TestGitHubRepoSlugValidation(t *testing.T) {
	for _, tc := range []struct {
		remote string
		want   string
		valid  bool
	}{
		{remote: "https://github.com/teelabs/cifrarium.git", want: "teelabs/cifrarium", valid: true},
		{remote: "https://github.com/teelabs/cifrarium", want: "teelabs/cifrarium", valid: true},
		{remote: "https://github.com/teelabs", valid: false},
		{remote: "https://github.com/teelabs/cifrarium/extra", valid: false},
	} {
		got, err := githubRepoSlug(tc.remote)
		if tc.valid && (err != nil || got != tc.want) {
			t.Fatalf("%s: got=%q err=%v", tc.remote, got, err)
		}
		if !tc.valid && err == nil {
			t.Fatalf("accepted invalid remote %s", tc.remote)
		}
	}
}
