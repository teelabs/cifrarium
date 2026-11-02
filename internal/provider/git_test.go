package provider

import (
	"context"
	"testing"
)

func TestGitProviderRejectsObjectTraversal(t *testing.T) {
	g := Git{Dir: t.TempDir()}
	if _, err := g.Download(context.Background(), "../escape"); err == nil {
		t.Fatal("download traversal accepted")
	}
	if err := g.Upload(context.Background(), "../escape", []byte("x")); err == nil {
		t.Fatal("upload traversal accepted")
	}
}
