package restore

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
)

type historyProvider struct {
	objects    map[string][]byte
	catalogs   map[string][]byte
	selection  []byte
	ancestors  map[string]store.RemoteSnapshot
	stageCalls int
}

func TestSortSnapshotRecoveryCandidatesByRecordedDateNewestFirst(t *testing.T) {
	newer := time.Date(2026, 11, 11, 15, 0, 0, 0, time.UTC)
	older := newer.Add(-24 * time.Hour)
	candidates := []VerifiedSnapshot{
		{ID: "z-tie", Manifest: store.Manifest{CreatedAt: newer}},
		{ID: "older", Manifest: store.Manifest{CreatedAt: older}},
		{ID: "a-tie", Manifest: store.Manifest{CreatedAt: newer}},
	}

	sortSnapshotRecoveryCandidates(candidates)

	if got := []string{candidates[0].ID, candidates[1].ID, candidates[2].ID}; got[0] != "a-tie" || got[1] != "z-tie" || got[2] != "older" {
		t.Fatalf("candidate order = %v; want newest date first, then ID ascending for ties", got)
	}
}

// readOnlyHistoryProvider deliberately has no upload methods: remote history
// verification must depend only on a read-only provider capability.
type readOnlyHistoryProvider struct {
	objects  map[string][]byte
	catalogs map[string][]byte
}

func (p *readOnlyHistoryProvider) Download(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), p.objects[id]...), nil
}
func (p *readOnlyHistoryProvider) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), p.catalogs[id]...), nil
}
func (p *readOnlyHistoryProvider) List(context.Context) ([]string, error) {
	ids := make([]string, 0, len(p.objects))
	for id := range p.objects {
		ids = append(ids, id)
	}
	return ids, nil
}

func (p *historyProvider) Upload(context.Context, string, []byte) error        { return nil }
func (p *historyProvider) UploadCatalog(context.Context, string, []byte) error { return nil }
func (p *historyProvider) Download(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), p.objects[id]...), nil
}
func (p *historyProvider) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	return append([]byte(nil), p.catalogs[id]...), nil
}
func (p *historyProvider) List(context.Context) ([]string, error) {
	ids := make([]string, 0, len(p.objects))
	for id := range p.objects {
		ids = append(ids, id)
	}
	return ids, nil
}
func (p *historyProvider) Health(context.Context) error { return nil }
func (p *historyProvider) StageHistoricalSnapshots(_ context.Context, ids []string) (bool, error) {
	p.stageCalls++
	staged := false
	for _, id := range ids {
		item, ok := p.ancestors[id]
		if !ok {
			return false, nil
		}
		p.objects[id] = append([]byte(nil), item.Ciphertext...)
		p.catalogs[id] = append([]byte(nil), item.Catalog...)
		staged = true
	}
	return staged, nil
}
func (p *historyProvider) DownloadHistorySelection(context.Context) ([]byte, error) {
	return append([]byte(nil), p.selection...), nil
}
func (p *historyProvider) UploadHistorySelection(context.Context, []byte) error { return nil }

func TestVerifyRemoteHistoryReturnsNewestVerifiedChain(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	first, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("one\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("two\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	remote := &historyProvider{
		objects:  map[string][]byte{first.Manifest.Snapshot: first.Ciphertext, second.Manifest.Snapshot: second.Ciphertext},
		catalogs: map[string][]byte{first.Manifest.Snapshot: first.ManifestBytes, second.Manifest.Snapshot: second.ManifestBytes},
	}
	history, err := VerifyRemoteHistory(context.Background(), remote, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if history.Head != second.Manifest.Snapshot || len(history.Entries) != 2 || history.Entries[0].ID != history.Head {
		t.Fatalf("history=%+v", history)
	}
	if string(history.Entries[0].Records[0].Data) != "two\n" {
		t.Fatalf("latest data=%q", history.Entries[0].Records[0].Data)
	}
}

func TestVerifyRemoteHistoryUsesReadOnlyProviderCapability(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	snapshot, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("verified\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &readOnlyHistoryProvider{
		objects:  map[string][]byte{snapshot.Manifest.Snapshot: snapshot.Ciphertext},
		catalogs: map[string][]byte{snapshot.Manifest.Snapshot: snapshot.ManifestBytes},
	}
	history, err := VerifyRemoteHistory(context.Background(), reader, op, signing)
	if err != nil {
		t.Fatalf("verify with read-only source: %v", err)
	}
	if len(history.Entries) != 1 || history.Head != snapshot.Manifest.Snapshot {
		t.Fatalf("verified history = %#v", history)
	}
}

func TestVerifyRemoteHistoryResolvesMissingAncestorThroughStager(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	first, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("base\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("tip\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	remote := &historyProvider{
		objects:   map[string][]byte{second.Manifest.Snapshot: second.Ciphertext},
		catalogs:  map[string][]byte{second.Manifest.Snapshot: second.ManifestBytes},
		ancestors: map[string]store.RemoteSnapshot{first.Manifest.Snapshot: {ID: first.Manifest.Snapshot, Ciphertext: first.Ciphertext, Catalog: first.ManifestBytes}},
	}
	history, err := VerifyRemoteHistory(context.Background(), remote, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if history.Head != second.Manifest.Snapshot || len(history.Entries) != 2 || history.Entries[1].ID != first.Manifest.Snapshot {
		t.Fatalf("history=%+v; want tip and recovered base", history)
	}
	if remote.stageCalls != 1 {
		t.Fatalf("historical stage calls=%d; want exactly one", remote.stageCalls)
	}
}

func TestVerifyRemoteHistoryForSnapshotRecoveryUsesVerifiedCurrentViewWhenAncestorIsMissing(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	_, err = vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("older\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	tip, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("recoverable\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	remote := &historyProvider{
		objects:  map[string][]byte{tip.Manifest.Snapshot: tip.Ciphertext},
		catalogs: map[string][]byte{tip.Manifest.Snapshot: tip.ManifestBytes},
	}
	if _, err := VerifyRemoteHistory(context.Background(), remote, op, signing); err == nil {
		t.Fatal("strict history verification accepted a snapshot with a missing ancestor")
	}

	got, err := VerifyRemoteHistoryForSnapshotRecovery(context.Background(), remote, op, signing)
	if err != nil {
		t.Fatalf("snapshot recovery rejected an independently verified current snapshot: %v", err)
	}
	if got.Complete {
		t.Fatal("history without its referenced ancestor was reported complete")
	}
	if len(got.Snapshots) != 1 || got.Snapshots[0].ID != tip.Manifest.Snapshot || string(got.Snapshots[0].Records[0].Data) != "recoverable\n" {
		t.Fatalf("verified snapshot candidates = %#v; want the signed current-view snapshot", got.Snapshots)
	}
}

func TestVerifyRemoteHistoryForSnapshotRecoveryReturnsIncompleteCandidatesNewestDateFirst(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	makeCandidate := func(data string) store.SnapshotResult {
		t.Helper()
		vault := store.New(t.TempDir(), op, signing)
		result, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte(data), Mode: 0600}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first, second := makeCandidate("first candidate"), makeCandidate("second candidate")
	older, newer := first, second
	if older.Manifest.Snapshot > newer.Manifest.Snapshot {
		older, newer = newer, older
	}
	older.Manifest.CreatedAt = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	newer.Manifest.CreatedAt = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	newer.Manifest.Previous = strings.Repeat("f", 64)
	older.ManifestBytes = sealTestManifest(t, older.Manifest, op, signing)
	newer.ManifestBytes = sealTestManifest(t, newer.Manifest, op, signing)
	remote := &historyProvider{
		objects: map[string][]byte{
			older.Manifest.Snapshot: older.Ciphertext,
			newer.Manifest.Snapshot: newer.Ciphertext,
		},
		catalogs: map[string][]byte{
			older.Manifest.Snapshot: older.ManifestBytes,
			newer.Manifest.Snapshot: newer.ManifestBytes,
		},
	}

	got, err := VerifyRemoteHistoryForSnapshotRecovery(context.Background(), remote, op, signing)
	if err != nil {
		t.Fatalf("VerifyRemoteHistoryForSnapshotRecovery() error = %v", err)
	}
	if got.Complete || len(got.Snapshots) != 2 {
		t.Fatalf("recovery history = complete:%v candidates:%d; want two incomplete-history candidates", got.Complete, len(got.Snapshots))
	}
	if got.Snapshots[0].ID != newer.Manifest.Snapshot || got.Snapshots[1].ID != older.Manifest.Snapshot {
		t.Fatalf("candidate order = [%s, %s]; want newest recorded date first, regardless of ID order", got.Snapshots[0].ID, got.Snapshots[1].ID)
	}
}

func sealTestManifest(t *testing.T, manifest store.Manifest, operational []byte, signing ed25519.PrivateKey) []byte {
	t.Helper()
	manifest.Metadata = nil
	manifest.Signature = ""
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(signing, payload))
	sealed, err := store.SealManifest(manifest, operational)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestVerifyRemoteHistoryForSnapshotRecoveryDoesNotSalvageInvalidCurrentSnapshot(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	snapshot, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("recoverable\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	remote := &historyProvider{
		objects:  map[string][]byte{snapshot.Manifest.Snapshot: snapshot.Ciphertext},
		catalogs: map[string][]byte{snapshot.Manifest.Snapshot: []byte("not an authenticated catalog")},
	}

	got, err := VerifyRemoteHistoryForSnapshotRecovery(context.Background(), remote, op, signing)
	if err == nil || len(got.Snapshots) != 0 {
		t.Fatalf("invalid current snapshot returned candidates %#v and error %v", got.Snapshots, err)
	}
}

func TestVerifyRemoteHistoryForSnapshotRecoveryRejectsBadSignatureAndCiphertextHash(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(t.TempDir(), op, signing)
	_, err = vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("older\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	tip, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("recoverable\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	badSignature, err := store.OpenManifest(tip.ManifestBytes, op)
	if err != nil {
		t.Fatal(err)
	}
	badSignature.Signature = "00"
	badSignatureCatalog, err := store.SealManifest(badSignature, op)
	if err != nil {
		t.Fatal(err)
	}
	badCiphertext := append([]byte(nil), tip.Ciphertext...)
	badCiphertext[0] ^= 0xff

	for _, tc := range []struct {
		name    string
		cipher  []byte
		catalog []byte
	}{
		{name: "signature", cipher: tip.Ciphertext, catalog: badSignatureCatalog},
		{name: "ciphertext hash", cipher: badCiphertext, catalog: tip.ManifestBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := &historyProvider{
				objects:  map[string][]byte{tip.Manifest.Snapshot: tc.cipher},
				catalogs: map[string][]byte{tip.Manifest.Snapshot: tc.catalog},
			}
			got, err := VerifyRemoteHistoryForSnapshotRecovery(context.Background(), remote, op, signing)
			if err == nil || len(got.Snapshots) != 0 {
				t.Fatalf("invalid snapshot returned candidates %#v and error %v", got.Snapshots, err)
			}
		})
	}
}

func TestVerifyRemoteHistoryRejectsForksAndTamperedObjects(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	makeRoot := func(content string) store.SnapshotResult {
		vault := store.New(t.TempDir(), op, signing)
		result, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte(content), Mode: 0600}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	left, right := makeRoot("left\n"), makeRoot("right\n")
	fork := &historyProvider{
		objects:  map[string][]byte{left.Manifest.Snapshot: left.Ciphertext, right.Manifest.Snapshot: right.Ciphertext},
		catalogs: map[string][]byte{left.Manifest.Snapshot: left.ManifestBytes, right.Manifest.Snapshot: right.ManifestBytes},
	}
	if _, err := VerifyRemoteHistory(context.Background(), fork, op, signing); err == nil {
		t.Fatal("forked history accepted")
	}

	tampered := &historyProvider{
		objects:  map[string][]byte{left.Manifest.Snapshot: []byte("tampered")},
		catalogs: map[string][]byte{left.Manifest.Snapshot: left.ManifestBytes},
	}
	if _, err := VerifyRemoteHistory(context.Background(), tampered, op, signing); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
}

func TestInspectRemoteHistoryHonorsAuthenticatedSelection(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	makeRoot := func(text string) store.SnapshotResult {
		v := store.New(t.TempDir(), op, signing)
		snap, e := v.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte(text), Mode: 0600}})
		if e != nil {
			t.Fatal(e)
		}
		return snap
	}
	left, right := makeRoot("left"), makeRoot("right")
	p := &historyProvider{objects: map[string][]byte{left.Manifest.Snapshot: left.Ciphertext, right.Manifest.Snapshot: right.Ciphertext}, catalogs: map[string][]byte{left.Manifest.Snapshot: left.ManifestBytes, right.Manifest.Snapshot: right.ManifestBytes}}
	if _, err := VerifyRemoteHistory(context.Background(), p, op, signing); err == nil {
		t.Fatal("unmarked fork accepted")
	}
	marker, err := store.SealHistorySelection(right.Manifest.Snapshot, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	p.selection = marker
	history, err := VerifyRemoteHistory(context.Background(), p, op, signing)
	if err != nil || history.Head != right.Manifest.Snapshot {
		t.Fatalf("selected history=%+v err=%v", history, err)
	}
	inspection, gotMarker, err := InspectRemoteHistory(context.Background(), p, op, signing)
	if err != nil || len(inspection.Branches) != 2 || string(gotMarker) != string(marker) {
		t.Fatalf("inspection=%+v marker=%d err=%v", inspection, len(gotMarker), err)
	}
}

var _ provider.Provider = (*historyProvider)(nil)
