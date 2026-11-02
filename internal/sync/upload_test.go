package sync

import (
	"context"
	"github.com/teelabs/cifrarium/internal/recovery"
	"testing"
)

type fakeProvider struct{ uploads int }

func (f *fakeProvider) Upload(context.Context, string, []byte) error     { f.uploads++; return nil }
func (f *fakeProvider) Download(context.Context, string) ([]byte, error) { return nil, nil }
func (f *fakeProvider) List(context.Context) ([]string, error)           { return nil, nil }
func (f *fakeProvider) Health(context.Context) error                     { return nil }
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
