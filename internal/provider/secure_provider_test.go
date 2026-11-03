//go:build linux

package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureProviderWriteAndReadRejectSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "objects")); err != nil {
		t.Fatal(err)
	}
	if err := writeProviderFile(root, "objects/id", []byte("cipher")); err == nil {
		t.Fatal("secure provider write followed symlinked parent")
	}
	if _, err := readProviderFile(root, "objects/id"); err == nil {
		t.Fatal("secure provider read followed symlinked parent")
	}
}

func TestSecureProviderWriteAndReadUsesRelativeDescriptors(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeProviderFile(root, "objects/id", []byte("cipher")); err != nil {
		t.Fatal(err)
	}
	got, err := readProviderFile(root, "objects/id")
	if err != nil || string(got) != "cipher" {
		t.Fatalf("read secure provider file: %q %v", got, err)
	}
}
