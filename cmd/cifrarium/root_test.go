package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/config"
)

func TestResolveVaultRootFailsWithoutConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if _, err := resolveVaultRoot("status", "", home); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "cifrarium")); !os.IsNotExist(err) {
		t.Fatalf("status created vault root: %v", err)
	}
}

func TestSetupEstablishesAndReusesConfiguredRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	want := filepath.Join(home, "vault")
	got, err := resolveVaultRoot("setup", want, home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensureConfiguredRoot(home, got); err != nil {
		t.Fatal(err)
	}
	got, err = resolveVaultRoot("status", "", home)
	if err != nil || got != want {
		t.Fatalf("got=%q err=%v want=%q", got, err, want)
	}
}

func TestDifferentExplicitRootFailsSecurityCheck(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	configured := filepath.Join(home, "vault")
	if _, err := ensureConfiguredRoot(home, configured); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveVaultRoot("status", filepath.Join(home, "other"), home); err == nil || !strings.Contains(err.Error(), "SECURITY CHECK FAILED") {
		t.Fatalf("err=%v", err)
	}
}

func TestConfiguredRootCannotBeReplaced(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if _, err := ensureConfiguredRoot(home, filepath.Join(home, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureConfiguredRoot(home, filepath.Join(home, "two")); err == nil {
		t.Fatal("different root replaced configured root")
	}
	if _, err := config.Load(); err != nil {
		t.Fatal(err)
	}
}
