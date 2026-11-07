package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/restore"
	"github.com/teelabs/cifrarium/internal/store"
)

type restoreFixtureProvider struct {
	ids      []string
	objects  map[string][]byte
	catalogs map[string][]byte
}

func (p *restoreFixtureProvider) Upload(context.Context, string, []byte) error        { return nil }
func (p *restoreFixtureProvider) UploadCatalog(context.Context, string, []byte) error { return nil }
func (p *restoreFixtureProvider) Download(_ context.Context, id string) ([]byte, error) {
	return p.objects[id], nil
}
func (p *restoreFixtureProvider) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	return p.catalogs[id], nil
}
func (p *restoreFixtureProvider) List(context.Context) ([]string, error) { return p.ids, nil }
func (p *restoreFixtureProvider) Health(context.Context) error           { return nil }

var _ provider.Provider = (*restoreFixtureProvider)(nil)

func TestBackendRestoreFilesAppliesVerifiedSelection(t *testing.T) {
	home, root := t.TempDir(), filepath.Join(t.TempDir(), "vault")
	op := bytes.Repeat([]byte{7}, 32)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remoteVault := store.New(filepath.Join(t.TempDir(), "remote"), op, signing)
	manifest, err := remoteVault.Save([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("restored")}})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(remoteVault.Root, "snapshots", manifest.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := os.ReadFile(filepath.Join(remoteVault.Root, "catalog", manifest.Snapshot+".json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &Backend{Home: home, Vault: store.New(root, op, signing), Operational: op, Signing: signing, Guard: &auditTestGuard{}, Provider: &restoreFixtureProvider{
		ids: []string{manifest.Snapshot}, objects: map[string][]byte{manifest.Snapshot: ciphertext}, catalogs: map[string][]byte{manifest.Snapshot: catalog},
	}}
	history, err := restore.VerifyRemoteHistory(context.Background(), backend.Provider, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.BuildFilePlan(home, history, manifest.Snapshot, history.Entries[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := restore.Fingerprint(plan)
	if err != nil {
		t.Fatal(err)
	}
	err = backend.RestoreFiles(context.Background(), FileRestoreRequest{Snapshot: manifest.Snapshot, Paths: []string{".zshrc"}, Fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil || !bytes.Equal(got, []byte("restored")) {
		t.Fatalf("restored file = %q, err = %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); err != nil {
		t.Fatalf("verified vault history not installed: %v", err)
	}
	if _, err := backend.CaptureSnapshot(context.Background()); err == nil {
		t.Fatal("daemon accepted a new snapshot after restore completion")
	}
}

type auditTestGuard struct {
	head   string
	writes int
}

func (g *auditTestGuard) CatalogHead() (string, error) { return g.head, nil }
func (g *auditTestGuard) SetCatalogHead(head string) error {
	g.writes++
	g.head = head
	return nil
}

type auditTestProvider struct{ calls int }

func (p *auditTestProvider) Upload(context.Context, string, []byte) error {
	p.calls++
	return nil
}
func (p *auditTestProvider) UploadCatalog(context.Context, string, []byte) error {
	p.calls++
	return nil
}
func (p *auditTestProvider) Download(context.Context, string) ([]byte, error) {
	p.calls++
	return nil, nil
}
func (p *auditTestProvider) DownloadCatalog(context.Context, string) ([]byte, error) {
	p.calls++
	return nil, nil
}
func (p *auditTestProvider) List(context.Context) ([]string, error) {
	p.calls++
	return nil, nil
}
func (p *auditTestProvider) Health(context.Context) error {
	p.calls++
	return nil
}

func TestBackendPlansAreReadOnlyAndUseTheSharedAdapterContract(t *testing.T) {
	backend := Backend{}
	snapshot := backend.SnapshotPlan()
	if snapshot["action"] != "capture" || snapshot["readOnly"] != true {
		t.Fatalf("snapshot plan = %#v", snapshot)
	}
	if _, err := backend.RestorePlan(""); err == nil {
		t.Fatal("empty restore plan was accepted")
	}
	restore, err := backend.RestorePlan("snapshot-id")
	if err != nil {
		t.Fatal(err)
	}
	if restore["action"] != "restore" || restore["snapshot"] != "snapshot-id" || restore["requiresCliConfirmation"] != true {
		t.Fatalf("restore plan = %#v", restore)
	}
}

func TestBackendStatusIsTheSharedOperationalView(t *testing.T) {
	root := t.TempDir()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := Backend{
		Vault:       store.New(root, []byte("operational-key"), signing),
		Pending:     &Queue{},
		Operational: []byte("operational-key"),
		Signing:     signing,
	}
	status, err := backend.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Vault != root || !status.Configured || status.VaultState != "ready" || status.KeyringState != "available" {
		t.Fatalf("unexpected backend status: %#v", status)
	}
	if status.Pending != 0 || status.Snapshots != 0 || status.Signer == "" {
		t.Fatalf("unexpected backend counters: %#v", status)
	}
}

func TestBackendCaptureClassifiesVaultWriteFailure(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := Backend{Home: home, Vault: store.New(root, make([]byte, 32), signing)}
	_, err = backend.CaptureSnapshot(context.Background())
	var captureErr *CaptureError
	if !errors.As(err, &captureErr) || captureErr.Stage != CaptureStageVaultWrite {
		t.Fatalf("capture error = %#v (%v), want typed vault-write failure", captureErr, err)
	}
	var marker interface{ CaptureFailure() }
	if !errors.As(err, &marker) {
		t.Fatal("vault write failure was not classified as a local capture failure")
	}
}

func TestBackendCaptureReusesIdenticalSnapshotAndStoredManifestBytes(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"same\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	backend := &Backend{Home: home, Vault: store.New(root, make([]byte, 32), signing)}

	first, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Unchanged {
		t.Fatal("initial capture was reported unchanged")
	}
	storedManifest, err := os.ReadFile(filepath.Join(root, "catalog", first.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedManifest, first.Manifest) {
		t.Fatal("capture returned manifest bytes different from the stored catalog")
	}

	second, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.Unchanged || second.ID != first.ID {
		t.Fatalf("second capture = (unchanged=%t, id=%q), want same head %q", second.Unchanged, second.ID, first.ID)
	}
	if !bytes.Equal(first.Ciphertext, second.Ciphertext) || !bytes.Equal(first.Manifest, second.Manifest) {
		t.Fatal("unchanged capture did not return exact stored encrypted bytes")
	}
	if _, err := os.Stat(filepath.Join(root, "snapshots", second.ID)); err != nil {
		t.Fatalf("current snapshot missing: %v", err)
	}
	status, err := backend.Status()
	if err != nil || status.Snapshots != 1 {
		t.Fatalf("snapshot count=%d err=%v, want exactly one", status.Snapshots, err)
	}

	if err := os.WriteFile(configPath, []byte("model = \"changed\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	third, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.Unchanged || third.ID == second.ID {
		t.Fatalf("changed capture = (unchanged=%t, id=%q), want a new snapshot", third.Unchanged, third.ID)
	}
}

func TestBackendAuditSnapshotUsesAdaptersAndDoesNotMutateVaultQueueGuardOrProvider(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"before\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guard := &auditTestGuard{}
	provider := &auditTestProvider{}
	queue := &Queue{}
	if err := queue.Push(Item{ID: "pending-id", Ciphertext: []byte("opaque pending bytes")}); err != nil {
		t.Fatal(err)
	}
	queuePath := filepath.Join(root, "pending.queue")
	if err := queue.Save(queuePath, key); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{
		Home:               home,
		Vault:              store.NewWithGuard(root, key, signing, guard),
		Operational:        key,
		Signing:            signing,
		Pending:            queue,
		QueuePath:          queuePath,
		Provider:           provider,
		ProviderConfigured: true,
	}
	snapshot, err := backend.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	queueBefore, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	guardHeadBefore, guardWritesBefore := guard.head, guard.writes
	if err := os.WriteFile(configPath, []byte("model = \"after\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := backend.AuditSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != store.AuditDiffers || result.Snapshot != snapshot.ID || !reflect.DeepEqual(result.ContentChanged, []string{".codex/config.toml"}) {
		t.Fatalf("audit result = %#v", result)
	}
	if provider.calls != 0 {
		t.Fatalf("audit called provider %d times", provider.calls)
	}
	if queue.Len() != 1 {
		t.Fatalf("audit changed in-memory pending queue length to %d", queue.Len())
	}
	queueAfter, err := os.ReadFile(queuePath)
	if err != nil || !bytes.Equal(queueBefore, queueAfter) {
		t.Fatalf("audit changed pending queue file: %v", err)
	}
	headAfter, err := os.ReadFile(filepath.Join(root, "head.json"))
	if err != nil || !bytes.Equal(headBefore, headAfter) {
		t.Fatalf("audit changed head: %v", err)
	}
	entriesAfter, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil || len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("audit changed snapshot count: before=%d after=%d err=%v", len(entriesBefore), len(entriesAfter), err)
	}
	if guard.head != guardHeadBefore || guard.writes != guardWritesBefore {
		t.Fatalf("audit changed guard: before=(%q,%d) after=(%q,%d)", guardHeadBefore, guardWritesBefore, guard.head, guard.writes)
	}
}

func TestBackendOwnsQueuePersistenceAndProviderGate(t *testing.T) {
	root := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	queue := &Queue{}
	if err := queue.Push(Item{ID: "snapshot-id", Ciphertext: []byte("ciphertext")}); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{
		Vault:       store.New(root, key, signing),
		Operational: key,
		Pending:     queue,
		QueuePath:   filepath.Join(root, "pending.queue"),
	}
	if err := backend.PersistQueue(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(backend.QueuePath, key)
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("persisted queue = %#v, %v", loaded, err)
	}
	if err := backend.UploadSnapshot(context.Background(), Item{ID: "snapshot-id", Ciphertext: []byte("ciphertext")}); err == nil {
		t.Fatal("backend uploaded without a configured provider")
	}
}
