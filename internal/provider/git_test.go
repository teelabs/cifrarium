package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/limits"
)

func runProviderGitTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@localhost", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@localhost")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

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

func TestCanonicalSelectionUploadPreservesSnapshotTreeAndRejectsStaleRevision(t *testing.T) {
	bare, seed, local := t.TempDir(), t.TempDir(), t.TempDir()
	runProviderGitTest(t, bare, "init", "--bare", "--initial-branch=main")
	runProviderGitTest(t, seed, "init", "--initial-branch=main")
	for path, value := range map[string]string{"objects/old": "cipher", "catalog/old.json": "catalog"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(seed, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(seed, path), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runProviderGitTest(t, seed, "add", "objects/old", "catalog/old.json")
	runProviderGitTest(t, seed, "commit", "-m", "seed snapshots")
	runProviderGitTest(t, seed, "push", bare, "HEAD:refs/heads/main")
	gitBinary, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	remoteURL := "https://github.com/teelabs/cifrarium-history-test.git"
	binDir := t.TempDir()
	wrapper := fmt.Sprintf("#!/bin/bash\nargs=()\nrewrite=1\nif [[ \" $* \" == *' remote add origin '* ]]; then rewrite=0; fi\nfor arg in \"$@\"; do if [[ $rewrite == 1 && \"$arg\" == %s ]]; then arg=%s; fi; args+=(\"$arg\"); done\nexec %s \"${args[@]}\"\n", strconv.Quote(remoteURL), strconv.Quote(bare), strconv.Quote(gitBinary))
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "gh"), []byte("#!/bin/sh\nprintf 'true\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	g := Git{Dir: local, Remote: remoteURL}
	if err := g.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, revision, err := g.remoteHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeObjects, err := exec.Command("git", "-C", local, "count-objects", "-v").Output()
	if err != nil {
		t.Fatal(err)
	}
	beforeCount, err := exec.Command("git", "--git-dir", bare, "rev-list", "--count", "refs/heads/main").Output()
	if err != nil || strings.TrimSpace(string(beforeCount)) != "1" {
		t.Fatalf("initial remote commit count=%q err=%v", beforeCount, err)
	}
	if err := g.UploadSnapshotWithHistorySelection(context.Background(), idA, []byte("ciphertext"), []byte("signed catalog"), []byte("encrypted marker"), strings.Repeat("a", 40)); err == nil {
		t.Fatal("stale revision accepted")
	}
	afterStaleObjects, err := exec.Command("git", "-C", local, "count-objects", "-v").Output()
	if err != nil || !bytes.Equal(beforeObjects, afterStaleObjects) {
		t.Fatalf("stale upload left local Git objects: before=%q after=%q err=%v", beforeObjects, afterStaleObjects, err)
	}
	if _, err := os.Stat(filepath.Join(local, "objects", idA)); !os.IsNotExist(err) {
		t.Fatalf("stale upload modified the local cache: %v", err)
	}
	if err := g.UploadSnapshotWithHistorySelection(context.Background(), idA, []byte("ciphertext"), []byte("signed catalog"), []byte("encrypted marker"), revision); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"objects/" + idA: "ciphertext", "catalog/" + idA + ".json": "signed catalog", historySelectionPath: "encrypted marker"} {
		got, err := readProviderFileLimited(local, path, limits.MaxSnapshotCipherBytes)
		if err != nil || string(got) != want {
			t.Fatalf("local cache %s=%q err=%v", path, got, err)
		}
	}
	got := strings.Fields(runProviderGitTest(t, bare, "ls-tree", "-r", "--name-only", "refs/heads/main"))
	want := []string{"catalog/" + idA + ".json", "catalog/old.json", "history/selection.json", "objects/" + idA, "objects/old"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("remote paths=%v want=%v", got, want)
	}
	afterCount, err := exec.Command("git", "--git-dir", bare, "rev-list", "--count", "refs/heads/main").Output()
	if err != nil || strings.TrimSpace(string(afterCount)) != "2" {
		t.Fatalf("remote commit count=%q, want exactly one atomic update after %q; err=%v", afterCount, beforeCount, err)
	}
}

func TestGitUploadSnapshotUsesServiceIdentityWithoutCommittingUnrelatedStagedFiles(t *testing.T) {
	dir := t.TempDir()
	runProviderGitTest(t, dir, "init", "--initial-branch=main")

	// A Cifrarium upload must not commit unrelated content already staged in
	// the existing checkout's shared index.
	if err := os.WriteFile(filepath.Join(dir, "private.txt"), []byte("plaintext sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	runProviderGitTest(t, dir, "add", "private.txt")

	if err := (Git{Dir: dir}).UploadSnapshot(context.Background(), "current", []byte("ciphertext"), []byte(`{"snapshot":"current"}`)); err != nil {
		t.Fatalf("upload through existing checkout without local identity: %v", err)
	}
	if got, want := runProviderGitTest(t, dir, "show", "-s", "--format=%an <%ae>", "HEAD"), "cifrarium <cifrarium@localhost>\n"; got != want {
		t.Fatalf("commit identity = %q, want %q", got, want)
	}
	if got, want := runProviderGitTest(t, dir, "ls-tree", "-r", "--name-only", "HEAD"), "catalog/current.json\nobjects/current\n"; got != want {
		t.Fatalf("committed paths = %q, want %q", got, want)
	}
	if got, want := runProviderGitTest(t, dir, "diff", "--cached", "--name-only"), "private.txt\n"; got != want {
		t.Fatalf("staged paths = %q, want %q", got, want)
	}
	for _, key := range []string{"user.name", "user.email"} {
		if err := exec.Command("git", "-C", dir, "config", "--local", "--get", key).Run(); err == nil {
			t.Errorf("provider local %s was modified", key)
		}
	}
}

func TestGitRemoteUploadExcludesLocalCommitHistory(t *testing.T) {
	bare, seed, local := t.TempDir(), t.TempDir(), t.TempDir()
	runProviderGitTest(t, bare, "init", "--bare", "--initial-branch=main")
	runProviderGitTest(t, seed, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(seed, "remote.txt"), []byte("remote base"), 0600); err != nil {
		t.Fatal(err)
	}
	runProviderGitTest(t, seed, "add", "remote.txt")
	runProviderGitTest(t, seed, "commit", "-m", "remote base")
	runProviderGitTest(t, seed, "push", bare, "HEAD:refs/heads/main")
	runProviderGitTest(t, local, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(local, "plaintext.txt"), []byte("must not publish"), 0600); err != nil {
		t.Fatal(err)
	}
	runProviderGitTest(t, local, "add", "plaintext.txt")
	runProviderGitTest(t, local, "commit", "-m", "unpublished local history")
	if err := os.WriteFile(filepath.Join(local, "staged.txt"), []byte("also private"), 0600); err != nil {
		t.Fatal(err)
	}
	runProviderGitTest(t, local, "add", "staged.txt")
	g := Git{Dir: local, Remote: bare}
	for _, id := range []string{"first", "second", "second"} {
		objects := []gitObject{{"objects/" + id, []byte("ciphertext")}, {"catalog/" + id + ".json", []byte(`{"snapshot":"` + id + `"}`)}}
		hashes := make([]string, len(objects))
		for i, object := range objects {
			path := filepath.Join(local, "hash-input")
			if err := os.WriteFile(path, object.data, 0600); err != nil {
				t.Fatal(err)
			}
			hashes[i] = strings.TrimSpace(runProviderGitTest(t, local, "hash-object", "-w", path))
		}
		index, cleanup, err := g.newUploadIndex(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		err = g.commitAndPushRemote(context.Background(), index, "snapshot "+id, objects, hashes)
		cleanup()
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := runProviderGitTest(t, bare, "--git-dir", bare, "ls-tree", "-r", "--name-only", "refs/heads/main"); got != "catalog/first.json\ncatalog/second.json\nobjects/first\nobjects/second\nremote.txt\n" {
		t.Fatalf("remote paths = %q", got)
	}
	if got := runProviderGitTest(t, bare, "--git-dir", bare, "rev-list", "--count", "refs/heads/main"); got != "3\n" {
		t.Fatalf("remote history length = %q", got)
	}
	if got := runProviderGitTest(t, local, "diff", "--cached", "--name-only"); got != "staged.txt\n" {
		t.Fatalf("local staged files = %q", got)
	}
	if got := runProviderGitTest(t, local, "show", "HEAD:plaintext.txt"); got != "must not publish" {
		t.Fatalf("local-only history changed: %q", got)
	}
}

func TestRemoteSnapshotEquivalenceRejectsSymlinkTreeEntries(t *testing.T) {
	bare, local := t.TempDir(), t.TempDir()
	runProviderGitTest(t, bare, "init", "--bare", "--initial-branch=main")
	runProviderGitTest(t, local, "init", "--initial-branch=main")
	ciphertext, manifest := []byte("encrypted snapshot"), []byte("encrypted manifest")
	if err := os.MkdirAll(filepath.Join(local, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(local, "catalog"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "objects", "id"), ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "catalog", "id.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	runProviderGitTest(t, local, "add", "objects/id", "catalog/id.json")
	runProviderGitTest(t, local, "commit", "-m", "seed regular snapshot")
	runProviderGitTest(t, local, "push", bare, "HEAD:refs/heads/main")
	g := Git{Dir: local, Remote: bare}
	validate := func(candidate []byte) bool { return bytes.Equal(candidate, manifest) }
	if raw, equivalent, exists, matches, err := g.remoteSnapshotEquivalent(context.Background(), "id", ciphertext, validate); err != nil || !equivalent || !exists || !matches || !bytes.Equal(raw, manifest) {
		t.Fatalf("regular remote entries were not recognized: equivalent=%t exists=%t matches=%t err=%v", equivalent, exists, matches, err)
	}

	for _, path := range []string{"objects/id", "catalog/id.json"} {
		parent := strings.TrimSpace(runProviderGitTest(t, bare, "rev-parse", "refs/heads/main"))
		blob := strings.TrimSpace(runProviderGitTest(t, local, "rev-parse", parent+":"+path))
		runProviderGitTest(t, local, "read-tree", parent)
		runProviderGitTest(t, local, "update-index", "--cacheinfo", "120000,"+blob+","+path)
		tree := strings.TrimSpace(runProviderGitTest(t, local, "write-tree"))
		commit := strings.TrimSpace(runProviderGitTest(t, local, "commit-tree", tree, "-p", parent, "-m", "symlink fixture"))
		runProviderGitTest(t, local, "push", bare, commit+":refs/heads/main")
		_, equivalent, exists, matches, err := g.remoteSnapshotEquivalent(context.Background(), "id", ciphertext, validate)
		if err != nil {
			t.Fatal(err)
		}
		if equivalent && exists && matches {
			t.Fatalf("remote symlink tree entry %q was accepted as a complete snapshot", path)
		}
	}
}

func TestGitRemoteUploadStartsAnUnbornRemote(t *testing.T) {
	bare, local := t.TempDir(), t.TempDir()
	runProviderGitTest(t, bare, "init", "--bare", "--initial-branch=main")
	runProviderGitTest(t, local, "init", "--initial-branch=main")
	g := Git{Dir: local, Remote: bare}
	objects := []gitObject{{"objects/first", []byte("ciphertext")}, {"catalog/first.json", []byte(`{"snapshot":"first"}`)}}
	hashes := make([]string, len(objects))
	for i, object := range objects {
		path := filepath.Join(local, "hash-input")
		if err := os.WriteFile(path, object.data, 0600); err != nil {
			t.Fatal(err)
		}
		hashes[i] = strings.TrimSpace(runProviderGitTest(t, local, "hash-object", "-w", path))
	}
	index, cleanup, err := g.newUploadIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := g.commitAndPushRemote(context.Background(), index, "snapshot first", objects, hashes); err != nil {
		t.Fatal(err)
	}
	if got := runProviderGitTest(t, bare, "--git-dir", bare, "ls-tree", "-r", "--name-only", "refs/heads/main"); got != "catalog/first.json\nobjects/first\n" {
		t.Fatalf("remote paths = %q", got)
	}
}

func TestGitUploadSnapshotIsIdempotentAfterCommittedRetry(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err != nil {
		t.Fatal(err)
	}
	if err := g.UploadSnapshot(context.Background(), "id", []byte("cipher"), []byte(`{"snapshot":"id"}`)); err != nil {
		t.Fatalf("retry after committed upload failed: %v", err)
	}
	cmd := exec.Command("git", "rev-list", "--count", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil || string(out) != "1\n" {
		t.Fatalf("retry created unexpected history: %q err=%v", out, err)
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
