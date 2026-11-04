package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndLoadCanonicalRootWithRestrictivePermissions(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config", "cifrarium", "config.json")
	root := filepath.Join(base, "vault")
	cfg, err := SaveTo(path, root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Root != root {
		t.Fatalf("root=%q want %q", cfg.Root, root)
	}
	loaded, err := LoadFrom(path)
	if err != nil || loaded != cfg {
		t.Fatalf("loaded=%+v err=%v want %+v", loaded, err, cfg)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("config dir mode=%v err=%v", dirInfo.Mode().Perm(), err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil || fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("config file mode=%v err=%v", fileInfo.Mode().Perm(), err)
	}
}

func TestSaveRefusesDifferentConfiguredRoot(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config.json")
	if _, err := SaveTo(path, filepath.Join(base, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveTo(path, filepath.Join(base, "two")); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err=%v", err)
	}
}

func TestCanonicalRootRejectsSymlinkedComponent(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalRoot(filepath.Join(link, "vault")); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadRejectsNonCanonicalConfig(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "vault")
	path := filepath.Join(base, "config.json")
	if err := os.WriteFile(path, []byte(`{"schema":1,"root":"`+root+`/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(path); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("err=%v", err)
	}
}

func TestSaveRejectsSymlinkedConfigParent(t *testing.T) {
	base := t.TempDir()
	actual := filepath.Join(base, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveTo(filepath.Join(alias, "config.json"), filepath.Join(base, "vault")); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("err=%v", err)
	}
}
