//go:build linux

package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGitListCanEnumerateSecureProviderDirectory(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	if err := os.Mkdir(filepath.Join(root, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "objects", id), []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := (Git{Dir: root}).List(context.Background())
	if err != nil {
		t.Fatalf("list secure provider objects: %v", err)
	}
	if len(got) != 1 || got[0] != id {
		t.Fatalf("listed object IDs = %v, want [%s]", got, id)
	}
}

func TestGitListRejectsNonRegularProviderObjects(t *testing.T) {
	tests := []struct {
		name string
		make func(string) error
	}{
		{name: "symlink", make: func(path string) error {
			outside := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
				return err
			}
			return os.Symlink(outside, path)
		}},
		{name: "directory", make: func(path string) error {
			return os.Mkdir(path, 0700)
		}},
		{name: "fifo", make: func(path string) error {
			return unix.Mkfifo(path, 0600)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			objects := filepath.Join(root, "objects")
			if err := os.Mkdir(objects, 0700); err != nil {
				t.Fatal(err)
			}
			if err := tt.make(filepath.Join(objects, strings.Repeat("a", 64))); err != nil {
				t.Fatal(err)
			}

			if _, err := (Git{Dir: root}).List(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("list %s error = %v; want non-regular object rejection", tt.name, err)
			}
		})
	}
}
