//go:build linux

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultLockRejectsSymlinkedRootAndLock(t *testing.T) {
	root := t.TempDir()
	if err := withVaultLock(root, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".recovery.lock")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-lock")
	if err := os.WriteFile(outside, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".recovery.lock")); err != nil {
		t.Fatal(err)
	}
	if err := withVaultLock(root, func() error { return nil }); err == nil {
		t.Fatal("symlinked lock accepted")
	}

	alias := filepath.Join(t.TempDir(), "vault-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := withVaultLock(alias, func() error { return nil }); err == nil {
		t.Fatal("symlinked vault root accepted")
	}
}
