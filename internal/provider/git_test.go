package provider

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

func TestGitEnsureInitializesAndValidatesRemote(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir, Remote: "https://github.com/teelabs/cifrarium.git"}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := (Git{Dir: dir, Remote: "https://user:pass@github.com/teelabs/cifrarium.git"}).Ensure(context.Background()); err == nil {
		t.Fatal("credential-bearing remote accepted")
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := (Git{Dir: link}).Ensure(context.Background()); err == nil {
		t.Fatal("provider directory symlink accepted")
	}
	dir2 := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, ".git"), filepath.Join(dir2, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := (Git{Dir: dir2}).Ensure(context.Background()); err == nil {
		t.Fatal(".git symlink accepted")
	}
}

func TestGitUploadSnapshotCommitsCiphertextAndCatalogTogether(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "objects", "id")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "catalog", "id.json")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "rev-list", "--count", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil || string(out) != "1\n" {
		t.Fatalf("commits=%q err=%v", out, err)
	}
}

func TestGitRejectsObjectAndCatalogDirectorySymlinks(t *testing.T) {
	for _, name := range []string{"objects", "catalog"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			g := Git{Dir: dir}
			if err := g.Ensure(context.Background()); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			var err error
			if name == "objects" {
				err = g.Upload(context.Background(), "id", []byte("cipher"))
			} else {
				err = g.UploadCatalog(context.Background(), "id", []byte("manifest"))
			}
			if err == nil {
				t.Fatal("provider directory symlink accepted")
			}
			expected := filepath.Join(outside, "id")
			if name == "catalog" {
				expected += ".json"
			}
			if _, statErr := os.Stat(expected); statErr == nil {
				t.Fatal("provider wrote through symlink")
			}
		})
	}
}

func TestGitRejectsSymlinkedProviderObjectsOnRead(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "objects", "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "objects", "id")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Download(context.Background(), "id"); err == nil {
		t.Fatal("download followed symlink")
	}
}
