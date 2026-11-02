package adapters

import (
	"errors"
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
	os.WriteFile(filepath.Join(h, ".codex", "AGENTS.md"), []byte("instructions"), 0600)
	os.WriteFile(filepath.Join(h, ".codex", "auth.json"), []byte("secret"), 0600)
	files, err := (Config{}).Collect(h)
	if err != nil || len(files) != 2 || files[0].Relative != ".codex/AGENTS.md" || files[1].Relative != ".codex/config.toml" {
		t.Fatalf("%v %#v", err, files)
	}
}

func TestReadStableRetriesWhenContentChanges(t *testing.T) {
	reads := 0
	data, err := readStableWith(func() ([]byte, error) {
		reads++
		if reads%2 == 1 {
			return []byte("before"), nil
		}
		return []byte("after"), nil
	})
	if err == nil || data != nil {
		t.Fatalf("unstable read accepted: data=%q err=%v", data, err)
	}
	if reads != stableReadAttempts*2 {
		t.Fatalf("reads=%d, want %d", reads, stableReadAttempts*2)
	}
}

func TestReadStableReturnsAConsistentPair(t *testing.T) {
	reads := 0
	data, err := readStableWith(func() ([]byte, error) {
		reads++
		return []byte("same"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "same" || reads != 2 {
		t.Fatalf("data=%q reads=%d", data, reads)
	}
}

func TestReadStablePropagatesReadErrors(t *testing.T) {
	want := errors.New("read failed")
	_, err := readStableWith(func() ([]byte, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
}

func TestZshCollectsNestedCustomFilesAndSkipsHiddenEntries(t *testing.T) {
	h := t.TempDir()
	custom := filepath.Join(h, ".oh-my-zsh", "custom")
	if err := os.MkdirAll(filepath.Join(custom, "theme"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(custom, ".hidden"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		filepath.Join(custom, "theme", "prompt.zsh-theme"): "nested",
		filepath.Join(custom, "plain.zsh"):                 "plain",
		filepath.Join(custom, ".hidden", "secret.zsh"):     "hidden",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}

	files, err := (Zsh{}).Collect(h)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Relative != ".oh-my-zsh/custom/plain.zsh" || files[1].Relative != ".oh-my-zsh/custom/theme/prompt.zsh-theme" {
		t.Fatalf("files=%#v", files)
	}
}

func TestZshRejectsCustomSymlinks(t *testing.T) {
	h := t.TempDir()
	custom := filepath.Join(h, ".oh-my-zsh", "custom")
	if err := os.MkdirAll(custom, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h, "outside"), filepath.Join(custom, "linked.zsh")); err != nil {
		t.Fatal(err)
	}
	if _, err := (Zsh{}).Collect(h); err == nil {
		t.Fatal("custom symlink accepted")
	}
}
