package provider

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

type memoryProvider struct {
	objects  map[string][]byte
	catalogs map[string][]byte
	atomic   bool
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
