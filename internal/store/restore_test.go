package store

import (
	"os"
	"path/filepath"
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
