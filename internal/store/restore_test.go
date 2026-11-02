package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
