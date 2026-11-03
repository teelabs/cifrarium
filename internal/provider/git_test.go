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

func TestGitUploadSnapshotDoesNotExecuteRepositoryHooksOrExposeRecoveryShares(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	script := "#!/bin/sh\nprintf '%s' \"$CIFRARIUM_RECOVERY_SHARE_1\" > " + marker + "\n"
	if err := os.WriteFile(hook, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CIFRARIUM_RECOVERY_SHARE_1", "cifrarium-1:secret")
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("repository hook executed during provider upload")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestGitRejectsExecutableLocalConfiguration(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "config", "--local", "filter.evil.clean", "printf injected")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure malicious filter: %v (%s)", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("objects/* filter=evil\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err == nil {
		t.Fatal("unsafe local Git configuration accepted")
	}
}

func TestGitRejectsTransportLocalConfiguration(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "config", "--local", "http.proxy", "http://attacker.invalid")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure transport setting: %v (%s)", err, out)
	}
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err == nil {
		t.Fatal("unsafe local transport configuration accepted")
	}
}

func TestGitCommandStaysAnchoredWhenProviderPathIsReplaced(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "provider")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	g := Git{Dir: dir}
	cmd, cleanup, err := g.commandAtDir(context.Background(), "cat", "marker")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	moved := filepath.Join(parent, "provider-old")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "old" {
		t.Fatalf("command followed replaced provider path: %q", out)
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

func TestGitRejectsProviderRootSymlinkOnRead(t *testing.T) {
	dir := t.TempDir()
	if err := (Git{Dir: dir}).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked-checkout")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (Git{Dir: link}).Download(context.Background(), "id"); err == nil {
		t.Fatal("provider root symlink accepted on read")
	}
}
