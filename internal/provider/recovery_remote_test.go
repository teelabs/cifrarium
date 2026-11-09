package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/limits"
)

var idA = strings.Repeat("a", 64)

func TestFilteredFetchUnsupportedRecognizesServerFallbackWarnings(t *testing.T) {
	for _, warning := range []string{
		"warning: filtering not recognized by server, ignoring",
		"warning: filtering not supported by server",
		"warning: requested filter was ignored",
	} {
		if !filteredFetchUnsupported(warning) {
			t.Errorf("filteredFetchUnsupported(%q)=false", warning)
		}
	}
	for _, output := range []string{"", "From https://github.com/example/repo", "warning: filter blob:none accepted"} {
		if filteredFetchUnsupported(output) {
			t.Errorf("filteredFetchUnsupported(%q)=true", output)
		}
	}
}

func TestFilteredHistoryFetchFailsClosedWhenServerIgnoresFilter(t *testing.T) {
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote.git")
	workDir := filepath.Join(root, "work")
	stageDir := filepath.Join(root, "stage")
	for _, dir := range []string{remoteDir, workDir, stageDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}
	run(root, "init", "--bare", "--initial-branch=main", remoteDir)
	run(remoteDir, "config", "uploadpack.allowFilter", "false")
	run(workDir, "init", "--initial-branch=main")
	run(workDir, "config", "user.name", "test")
	run(workDir, "config", "user.email", "test@example.invalid")
	if err := os.WriteFile(filepath.Join(workDir, "snapshot"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	run(workDir, "add", "snapshot")
	run(workDir, "commit", "-m", "snapshot")
	run(workDir, "remote", "add", "origin", remoteDir)
	run(workDir, "push", "origin", "main")
	run(stageDir, "init", "--initial-branch=main")
	run(stageDir, "remote", "add", "origin", remoteDir)
	run(stageDir, "fetch", "--depth=1", "origin", "main")
	g := Git{Dir: stageDir}
	if err := g.run(context.Background(), "config", "--local", "extensions.partialClone", "origin"); err != nil {
		t.Fatal(err)
	}
	err := g.runFilteredHistoryFetch(context.Background(), 1, "refs/heads/main")
	if err == nil || !strings.Contains(err.Error(), "does not support bounded") {
		t.Fatalf("filtered fetch error=%v; want fail-closed unsupported-filter error", err)
	}
}

func TestFilteredInitialFetchCanReadPromisedBlobAfterConfiguration(t *testing.T) {
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote.git")
	workDir := filepath.Join(root, "work")
	stageDir := filepath.Join(root, "stage")
	for _, dir := range []string{remoteDir, workDir, stageDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(dir string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
		return output
	}
	run(root, "init", "--bare", "--initial-branch=main", remoteDir)
	run(remoteDir, "config", "uploadpack.allowFilter", "true")
	run(workDir, "init", "--initial-branch=main")
	run(workDir, "config", "user.name", "test")
	run(workDir, "config", "user.email", "test@example.invalid")
	content := []byte("promised snapshot blob")
	if err := os.WriteFile(filepath.Join(workDir, "snapshot"), content, 0600); err != nil {
		t.Fatal(err)
	}
	run(workDir, "add", "snapshot")
	run(workDir, "commit", "-m", "snapshot")
	run(workDir, "remote", "add", "origin", remoteDir)
	run(workDir, "push", "origin", "main")
	run(stageDir, "init", "--initial-branch=main")
	run(stageDir, "remote", "add", "origin", remoteDir)
	g := Git{Dir: stageDir}
	if err := g.configurePartialClone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.runFilteredFetch(context.Background(), "--filter=blob:none", "--depth=1", "--no-tags", "origin", "main"); err != nil {
		t.Fatal(err)
	}
	oid := strings.TrimSpace(string(run(workDir, "rev-parse", "HEAD:snapshot")))
	got, err := g.readBlobKnownSizeLimited(context.Background(), oid, int64(len(content)), limits.MaxSnapshotCipherBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("read promised blob=%q, want %q", got, content)
	}
}

func TestStageHistoricalSnapshotsFetchesOnlyRequestedPairWithoutRemoteWrite(t *testing.T) {
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote.git")
	workDir := filepath.Join(root, "work")
	stageDir := filepath.Join(root, "stage")
	fakeBin := filepath.Join(root, "bin")
	for _, dir := range []string{remoteDir, workDir, stageDir, fakeBin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(dir string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
		return output
	}
	run(root, "init", "--bare", "--initial-branch=main", remoteDir)
	run(remoteDir, "config", "uploadpack.allowFilter", "true")
	run(workDir, "init", "--initial-branch=main")
	run(workDir, "config", "user.name", "test")
	run(workDir, "config", "user.email", "test@example.invalid")
	oldID, unrequestedID, currentID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	oldObject, oldCatalog := []byte("wanted encrypted object"), []byte("wanted encrypted catalog")
	unrequestedObject, unrequestedCatalog := []byte("do not stage"), []byte("do not stage catalog")
	currentObject, currentCatalog := []byte("current object"), []byte("current catalog")
	writePair := func(dir, id string, object, catalog []byte) {
		t.Helper()
		for path, data := range map[string][]byte{"objects/" + id: object, "catalog/" + id + ".json": catalog} {
			fullPath := filepath.Join(dir, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fullPath, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writePair(workDir, oldID, oldObject, oldCatalog)
	writePair(workDir, unrequestedID, unrequestedObject, unrequestedCatalog)
	run(workDir, "add", "objects", "catalog")
	run(workDir, "commit", "-m", "old snapshots")
	oldCommit := strings.TrimSpace(string(run(workDir, "rev-parse", "HEAD")))
	writePair(workDir, currentID, currentObject, currentCatalog)
	for _, path := range []string{"objects/" + oldID, "catalog/" + oldID + ".json", "objects/" + unrequestedID, "catalog/" + unrequestedID + ".json"} {
		if err := os.Remove(filepath.Join(workDir, filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
	}
	run(workDir, "add", "-A")
	run(workDir, "commit", "-m", "current snapshot")
	run(workDir, "remote", "add", "origin", remoteDir)
	run(workDir, "push", "origin", "main")
	remoteHead := strings.TrimSpace(string(run(remoteDir, "rev-parse", "refs/heads/main")))
	run(stageDir, "init", "--initial-branch=main")
	run(stageDir, "remote", "add", "origin", remoteDir)
	g := Git{Dir: stageDir, Remote: "https://github.com/example/private.git"}
	if err := g.configurePartialClone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.runFilteredFetch(context.Background(), "--filter=blob:none", "--depth=1", "--no-tags", "origin", "main"); err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(run(stageDir, "rev-parse", "FETCH_HEAD^{commit}")))
	writePair(stageDir, currentID, currentObject, currentCatalog)
	if err := writeProviderFileLimited(stageDir, stagedRemoteHeadPath, []byte(head), 128); err != nil {
		t.Fatal(err)
	}
	if err := writeProviderFileLimited(stageDir, stagedRemoteBytesPath, []byte(fmt.Sprint(len(currentObject)+len(currentCatalog))), 32); err != nil {
		t.Fatal(err)
	}
	objectsTree := strings.TrimSpace(string(run(workDir, "rev-parse", oldCommit+":objects")))
	catalogTree := strings.TrimSpace(string(run(workDir, "rev-parse", oldCommit+":catalog")))
	oldObjectOID := strings.TrimSpace(string(run(workDir, "rev-parse", oldCommit+":objects/"+oldID)))
	oldCatalogOID := strings.TrimSpace(string(run(workDir, "rev-parse", oldCommit+":catalog/"+oldID+".json")))
	mapPath := filepath.Join(root, "tree-map")
	rootTree := strings.TrimSpace(string(run(workDir, "rev-parse", oldCommit+"^{tree}")))
	mapData := fmt.Sprintf("%s\tobjects\ttree\t%s\t-1\n%s\t%s\tblob\t%s\t%d\n%s\tcatalog\ttree\t%s\t-1\n%s\t%s.json\tblob\t%s\t%d\n", rootTree, objectsTree, objectsTree, oldID, oldObjectOID, len(oldObject), rootTree, catalogTree, catalogTree, oldID, oldCatalogOID, len(oldCatalog))
	if err := os.WriteFile(mapPath, []byte(mapData), 0600); err != nil {
		t.Fatal(err)
	}
	ghScript := "#!/bin/sh\nendpoint=\"$2\"\nquery=\"$4\"\ntree=\"${endpoint##*/}\"\npath=$(printf '%s' \"$query\" | sed -n 's/.*select(\\.path == \\\"\\([^\\\"]*\\)\\\").*/\\1/p')\nawk -F '\\t' -v tree=\"$tree\" -v path=\"$path\" '$1 == tree && $2 == path { print $3 \"\\t\" $4 \"\\t\" $5 }' \"$CIFRARIUM_TREE_MAP\"\n"
	ghPath := filepath.Join(fakeBin, "gh")
	if err := os.WriteFile(ghPath, []byte(ghScript), 0700); err != nil {
		t.Fatal(err)
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitShim := fmt.Sprintf("#!/bin/sh\ncase \" $* \" in *\" ls-remote --symref https://github.com/example/private.git HEAD \"*) printf 'ref: refs/heads/main\\tHEAD\\n%s\\tHEAD\\n'; exit 0;; esac\nexec %q \"$@\"\n", remoteHead, gitPath)
	if err := os.WriteFile(filepath.Join(fakeBin, "git"), []byte(gitShim), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CIFRARIUM_TREE_MAP", mapPath)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	staged, err := g.StageHistoricalSnapshots(context.Background(), []string{oldID})
	if err != nil || !staged {
		t.Fatalf("StageHistoricalSnapshots()=(%v,%v), want (true,nil)", staged, err)
	}
	for path, want := range map[string][]byte{"objects/" + oldID: oldObject, "catalog/" + oldID + ".json": oldCatalog} {
		got, err := os.ReadFile(filepath.Join(stageDir, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("staged %s=%q, err=%v; want %q", path, got, err, want)
		}
	}
	for _, path := range []string{"objects/" + unrequestedID, "catalog/" + unrequestedID + ".json"} {
		if _, err := os.Lstat(filepath.Join(stageDir, filepath.FromSlash(path))); !os.IsNotExist(err) {
			t.Fatalf("unrequested historical path %s was staged; err=%v", path, err)
		}
	}
	if got := strings.TrimSpace(string(run(remoteDir, "rev-parse", "refs/heads/main"))); got != remoteHead {
		t.Fatalf("remote ref changed from %s to %s", remoteHead, got)
	}
}

func TestParseRecoveryTreeAcceptsOnlyRegularSnapshotObjectsAndCatalogs(t *testing.T) {
	raw := []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00100644 blob 1123456789012345678901234567890123456789\tcatalog/" + idA + ".json\x00")
	entries, err := parseRecoveryTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].id != idA || entries[0].objectOID == "" || entries[0].catalogOID == "" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestParseRecoveryTreeRejectsUnexpectedModesPathsAndIncompletePairs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "symlink", raw: []byte("120000 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00")},
		{name: "unowned path", raw: []byte("100644 blob 0123456789012345678901234567890123456789\t.ssh/authorized_keys\x00")},
		{name: "object without catalog", raw: []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRecoveryTree(tc.raw); err == nil {
				t.Fatal("untrusted provider tree accepted")
			}
		})
	}
}

func TestRecoveryOutputBufferEnforcesBound(t *testing.T) {
	buffer := &recoveryOutputBuffer{max: 3}
	if _, err := buffer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("d")); err != errRecoveryOutputLimit {
		t.Fatalf("overflow error=%v", err)
	}
	if buffer.String() != "abc" {
		t.Fatalf("buffer=%q", buffer.String())
	}
}

func TestParseRecoveryTreeWithSelectionAcceptsOnlyExactRegularMarker(t *testing.T) {
	raw := []byte("100644 blob 0123456789012345678901234567890123456789\tobjects/" + idA + "\x00100644 blob 1123456789012345678901234567890123456789\tcatalog/" + idA + ".json\x00100644 blob 2123456789012345678901234567890123456789\thistory/selection.json\x00")
	entries, marker, err := parseRecoveryTreeWithSelection(raw)
	if err != nil || len(entries) != 1 || marker != "2123456789012345678901234567890123456789" {
		t.Fatalf("entries=%+v marker=%q err=%v", entries, marker, err)
	}
	unsafe := []byte("120000 blob 2123456789012345678901234567890123456789\thistory/selection.json\x00")
	if _, _, err := parseRecoveryTreeWithSelection(unsafe); err == nil {
		t.Fatal("symlink history marker accepted")
	}
	unknown := []byte("100644 blob 2123456789012345678901234567890123456789\thistory/other.json\x00")
	if _, _, err := parseRecoveryTreeWithSelection(unknown); err == nil {
		t.Fatal("unknown history metadata accepted")
	}
}

func TestDownloadStagedHistorySelectionUsesBoundedNoFollowRead(t *testing.T) {
	dir := t.TempDir()
	g := Git{Dir: dir}
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("opaque encrypted marker")
	if err := os.WriteFile(filepath.Join(dir, "history", "selection.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := g.DownloadHistorySelection(t.Context())
	if err != nil || !bytes.Equal(got, marker) {
		t.Fatalf("marker=%q err=%v", got, err)
	}
	if err := os.Remove(filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.DownloadHistorySelection(t.Context()); err == nil {
		t.Fatal("history marker symlink was read")
	}
	if err := os.Remove(filepath.Join(dir, "history", "selection.json")); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, int(limits.MaxManifestBytes)+1)
	if err := os.WriteFile(filepath.Join(dir, "history", "selection.json"), oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.DownloadHistorySelection(t.Context()); err == nil {
		t.Fatal("oversized staged marker was read")
	}
}
