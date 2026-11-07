package restore

import (
	"context"
	"testing"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
)

type historyProvider struct {
	objects  map[string][]byte
	catalogs map[string][]byte
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

var _ provider.Provider = (*historyProvider)(nil)
