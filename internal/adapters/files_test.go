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
	os.WriteFile(filepath.Join(h, ".codex", "auth.json"), []byte("secret"), 0600)
	files, err := (Config{}).Collect(h)
	if err != nil || len(files) != 1 || files[0].Relative != ".codex/config.toml" {
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
