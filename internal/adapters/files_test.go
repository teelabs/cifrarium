package adapters

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigAllowlist(t *testing.T) {
	h := t.TempDir()
	if err := os.MkdirAll(filepath.Join(h, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(h, ".codex", "config.toml"), []byte("x"), 0600)
	os.WriteFile(filepath.Join(h, ".codex", "auth.json"), []byte("secret"), 0600)
	files, err := (Config{}).Collect(h)
	if err != nil || len(files) != 1 || files[0].Relative != ".codex/config.toml" {
		t.Fatalf("%v %#v", err, files)
	}
}
