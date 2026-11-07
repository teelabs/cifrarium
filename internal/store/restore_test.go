package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/limits"
)

func TestRestoreRejectsTraversalAndSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Restore([]Record{{Path: "../escape", Data: []byte("x"), Mode: 0600}}, target, backup); err == nil {
		t.Fatal("traversal accepted")
	}
	os.WriteFile(filepath.Join(target, "safe"), []byte("old"), 0600)
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(target, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Restore([]Record{{Path: "link", Data: []byte("x"), Mode: 0600}}, target, backup); err == nil {
		t.Fatal("symlink target accepted")
	}
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := Restore([]Record{{Path: "linked/file", Data: []byte("x"), Mode: 0600}}, target, backup); err == nil {
		t.Fatal("intermediate symlink accepted")
	}
	rootLink := filepath.Join(root, "target-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := Restore([]Record{{Path: "file", Data: []byte("x"), Mode: 0600}}, rootLink, backup); err == nil {
		t.Fatal("symlink restore root accepted")
	}
	backupLink := filepath.Join(root, "backup-link")
	if err := os.Symlink(backup, backupLink); err != nil {
		t.Fatal(err)
	}
	if err := Restore([]Record{{Path: "file", Data: []byte("x"), Mode: 0600}}, target, backupLink); err == nil {
		t.Fatal("symlink backup root accepted")
	}
}

func TestRestoreWithVaultLockWaitsForConcurrentVaultOperation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	home := t.TempDir()
	locked, release := make(chan struct{}), make(chan struct{})
	go func() { _ = withVaultLock(root, func() error { close(locked); <-release; return nil }) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("failed to acquire test vault lock")
	}
	committed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RestoreWithVaultLock([]Record{{Path: ".zshrc", Mode: 0600, Data: []byte("restored")}}, []RestoreDestination{{Path: ".zshrc"}}, home, filepath.Join(root, "backups"), root, func() error { close(committed); return nil })
	}()
	select {
	case <-committed:
		t.Fatal("restore committed while another vault operation held the lock")
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore did not finish")
	}
	if _, err := os.Stat(filepath.Join(home, ".zshrc")); err != nil {
		t.Fatalf("restore did not activate file: %v", err)
	}
}

func TestSnapshotSaveWaitsUntilRestoreCommitReleasesVaultLock(t *testing.T) {
	root, home := filepath.Join(t.TempDir(), "vault"), t.TempDir()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vault := New(root, bytes.Repeat([]byte{3}, 32), signing)
	if _, err := vault.Save([]Record{{Path: ".seed", Mode: 0600, Data: []byte("seed")}}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(file, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	commitEntered, releaseCommit := make(chan struct{}), make(chan struct{})
	restoreDone := make(chan error, 1)
	go func() {
		restoreDone <- RestoreWithVaultLock([]Record{{Path: ".zshrc", Mode: 0600, Data: []byte("restored")}}, []RestoreDestination{{Path: ".zshrc", Exists: true, Data: []byte("before"), Mode: 0600}}, home, filepath.Join(root, "backups"), root, func() error {
			close(commitEntered)
			<-releaseCommit
			return nil
		})
	}()
	select {
	case <-commitEntered:
	case <-time.After(time.Second):
		t.Fatal("restore never entered its commit phase")
	}
	saveDone := make(chan error, 1)
	go func() {
		_, err := vault.Save([]Record{{Path: ".seed", Mode: 0600, Data: []byte("concurrent save")}})
		saveDone <- err
	}()
	select {
	case err := <-saveDone:
		t.Fatalf("snapshot save interleaved with restore commit: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(releaseCommit)
	select {
	case err := <-restoreDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore did not finish")
	}
	select {
	case err := <-saveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot save remained blocked after restore")
	}
}

func TestInspectRestorePreflightsAllDestinationsWithoutWriting(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	records := []Record{
		{Path: ".zshrc", Data: []byte("replacement"), Mode: 0600},
		{Path: ".config/starship.toml", Data: []byte("new"), Mode: 0600},
	}
	states, err := InspectRestore(home, records)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || !states[0].Exists || string(states[0].Data) != "existing" || states[1].Exists {
		t.Fatalf("states=%+v", states)
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); !os.IsNotExist(err) {
		t.Fatalf("preflight created a destination parent: %v", err)
	}
}

func TestInspectRestoreRejectsSymlinkParents(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	_, err := InspectRestore(home, []Record{{Path: ".config/starship.toml", Data: []byte("x")}})
	if err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestRestoreRejectsDuplicatePaths(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	if err := Restore([]Record{
		{Path: "config", Data: []byte("one"), Mode: 0600},
		{Path: "config", Data: []byte("two"), Mode: 0600},
	}, target, backup); err == nil {
		t.Fatal("duplicate restore path accepted")
	}
}

func TestRestoreRejectsOversizedRecord(t *testing.T) {
	root := t.TempDir()
	if err := RestoreWithRename([]Record{{Path: "large", Data: bytes.Repeat([]byte("x"), int(limits.MaxCapturedFileBytes)+1)}}, filepath.Join(root, "home"), filepath.Join(root, "backups"), os.Rename); err == nil {
		t.Fatal("oversized restore record accepted")
	}
}

func TestRestoreCreatesBackup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	os.MkdirAll(target, 0700)
	os.WriteFile(filepath.Join(target, "config"), []byte("old"), 0600)
	if err := Restore([]Record{{Path: "config", Data: []byte("new"), Mode: 0600}}, target, backup); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "config"))
	if string(got) != "new" {
		t.Fatalf("got %q", got)
	}
	entries, _ := os.ReadDir(backup)
	if len(entries) != 1 {
		t.Fatalf("backup count %d", len(entries))
	}
}

func TestRestoreRollsBackAfterMidActivationFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(target, name), []byte("old-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	activations := 0
	rename := func(oldPath, newPath string) error {
		if strings.Contains(oldPath, string(filepath.Separator)+".cifrarium-restore-") {
			activations++
			if activations == 2 {
				return errors.New("injected activation failure")
			}
		}
		return os.Rename(oldPath, newPath)
	}
	err := RestoreWithRename([]Record{
		{Path: "a", Data: []byte("new-a"), Mode: 0600},
		{Path: "b", Data: []byte("new-b"), Mode: 0600},
	}, target, backup, rename)
	if err == nil {
		t.Fatal("mid-activation failure accepted")
	}
	for _, tc := range []struct{ name, want string }{{"a", "old-a"}, {"b", "old-b"}} {
		got, readErr := os.ReadFile(filepath.Join(target, tc.name))
		if readErr != nil || string(got) != tc.want {
			t.Fatalf("rollback %s: %q, %v", tc.name, got, readErr)
		}
	}
}

func TestRestoreRollsBackNewFilesAfterMidActivationFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	activations := 0
	rename := func(oldPath, newPath string) error {
		if strings.Contains(oldPath, string(filepath.Separator)+".cifrarium-restore-") {
			activations++
			if activations == 2 {
				return errors.New("injected activation failure")
			}
		}
		return os.Rename(oldPath, newPath)
	}
	err := RestoreWithRename([]Record{
		{Path: "a", Data: []byte("new-a"), Mode: 0600},
		{Path: "b", Data: []byte("new-b"), Mode: 0600},
	}, target, backup, rename)
	if err == nil {
		t.Fatal("mid-activation failure accepted")
	}
	for _, name := range []string{"a", "b"} {
		if _, statErr := os.Lstat(filepath.Join(target, name)); !os.IsNotExist(statErr) {
			t.Fatalf("new file %s survived rollback: %v", name, statErr)
		}
	}
}

func TestRestoreWithCommitRollsBackFilesWhenLocalStateCommitFails(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home")
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, ".zshrc"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := RestoreWithCommit([]Record{
		{Path: ".zshrc", Data: []byte("new"), Mode: 0600},
		{Path: ".config/starship.toml", Data: []byte("created"), Mode: 0600},
	}, target, backup, func() error { return errors.New("state commit failed") })
	if err == nil {
		t.Fatal("commit failure was ignored")
	}
	got, readErr := os.ReadFile(filepath.Join(target, ".zshrc"))
	if readErr != nil || string(got) != "old" {
		t.Fatalf("overwritten file after rollback=%q err=%v", got, readErr)
	}
	if _, err := os.Stat(filepath.Join(target, ".config", "starship.toml")); !os.IsNotExist(err) {
		t.Fatalf("new file remained after rollback: %v", err)
	}
}

func TestRestoreWithExpectedStateRejectsStaleAppliedAndSkippedDestinations(t *testing.T) {
	for _, applied := range []bool{true, false} {
		root := t.TempDir()
		target := filepath.Join(root, "home")
		backup := filepath.Join(root, "backups")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, ".zshrc"), []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		records := []Record{}
		if applied {
			records = append(records, Record{Path: ".zshrc", Data: []byte("restore"), Mode: 0600})
		}
		err := RestoreWithExpectedState(records, []RestoreDestination{{Path: ".zshrc", Exists: true, Data: []byte("preflight"), Mode: 0600}}, target, backup, nil)
		if err == nil {
			t.Fatal("stale preflight state accepted")
		}
		got, readErr := os.ReadFile(filepath.Join(target, ".zshrc"))
		if readErr != nil || string(got) != "changed" {
			t.Fatalf("destination changed: %q %v", got, readErr)
		}
	}
}
