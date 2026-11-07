package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/store"
)

type failingRestoreStateKeyring struct {
	setCalls int
	saved    bool
}

func (k *failingRestoreStateKeyring) CatalogHead() (string, error) { return "", nil }
func (k *failingRestoreStateKeyring) SetCatalogHead(head string) error {
	k.setCalls++
	if k.setCalls == 1 {
		return errors.New("simulated catalog guard write failure")
	}
	return nil
}
func (k *failingRestoreStateKeyring) SaveForRoot(string, []byte, ed25519.PrivateKey) error {
	k.saved = true
	return nil
}
func (k *failingRestoreStateKeyring) DeleteForRoot(string) error { k.saved = false; return nil }

func TestRestoreDaemonStateFailsClosedForRemainingSocket(t *testing.T) {
	oldSystemctl, oldMCP, oldBackend := runDaemonRefreshSystemctl, daemonRefreshProbe, daemonRefreshBackendProbe
	defer func() {
		runDaemonRefreshSystemctl, daemonRefreshProbe, daemonRefreshBackendProbe = oldSystemctl, oldMCP, oldBackend
	}()
	runDaemonRefreshSystemctl = func(...string) error { return errors.New("systemd unavailable") }
	daemonRefreshProbe = func(string) error { return errors.New("not serving") }
	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{}, errors.New("not serving")
	}
	root := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(root, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := disableUserDaemonForRestore(root); err == nil || !strings.Contains(err.Error(), "socket remains") {
		t.Fatalf("err=%v", err)
	}
}

func TestRestoreDaemonStateAcceptsInactiveServiceWithoutSockets(t *testing.T) {
	old := runDaemonRefreshSystemctl
	defer func() { runDaemonRefreshSystemctl = old }()
	runDaemonRefreshSystemctl = func(...string) error { return errors.New("inactive or unavailable") }
	if err := disableUserDaemonForRestore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreDaemonStateDisablesActiveService(t *testing.T) {
	old := runDaemonRefreshSystemctl
	defer func() { runDaemonRefreshSystemctl = old }()
	active := true
	disabled := false
	runDaemonRefreshSystemctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "is-active" {
			if active {
				return nil
			}
			return errors.New("inactive")
		}
		if len(args) > 0 && args[0] == "disable" {
			active = false
			disabled = true
			return nil
		}
		return errors.New("disabled")
	}
	if err := disableUserDaemonForRestore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("active service was not disabled")
	}
}

func TestPrepareRestoreConfigurationPersistsProtectedStateAndRollsBack(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	configPath := providerConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("OTHER_SETTING=preserve\n")
	if err := os.WriteFile(configPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	rollback, err := prepareRestoreConfiguration(home, filepath.Join(home, "vault"), filepath.Join(home, "provider"), "https://github.com/owner/repo.git", []string{"share-one", "share-two"})
	if err != nil {
		t.Fatal(err)
	}
	configured, err := loadProviderConfig(home)
	if err != nil || configured.Remote != "https://github.com/owner/repo.git" {
		t.Fatalf("provider configuration = %#v, err=%v", configured, err)
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("protected config mode = %v, err=%v", info, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(data), "CIFRARIUM_RECOVERY_SHARE_1=share-one") {
		t.Fatalf("recovery shares were not persisted: %v", err)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(configPath)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("rollback config = %q, err=%v", data, err)
	}
}

func TestRestoreTransactionRollsBackFilesAndProtectedConfigOnCommitFailure(t *testing.T) {
	home, root := t.TempDir(), filepath.Join(t.TempDir(), "vault")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	configPath := providerConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("OTHER_SETTING=keep\n")
	if err := os.WriteFile(configPath, originalConfig, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".zshrc")
	originalFile := []byte("user content")
	if err := os.WriteFile(target, originalFile, 0600); err != nil {
		t.Fatal(err)
	}
	rollbackConfig, err := prepareRestoreConfiguration(home, root, filepath.Join(home, "provider"), "https://github.com/owner/repo.git", []string{"share-one", "share-two"})
	if err != nil {
		t.Fatal(err)
	}
	wantFailure := errors.New("simulated verified-history commit failure")
	err = store.RestoreWithVaultLock([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("backup content")}}, []store.RestoreDestination{{Path: ".zshrc", Exists: true, Data: originalFile, Mode: 0600}}, home, filepath.Join(root, "backups"), root, func() error {
		if err := rollbackConfig(); err != nil {
			return err
		}
		return wantFailure
	})
	if !errors.Is(err, wantFailure) {
		t.Fatalf("restore error = %v; want commit failure", err)
	}
	gotFile, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(gotFile, originalFile) {
		t.Fatalf("target rollback = %q err=%v", gotFile, err)
	}
	gotConfig, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(gotConfig, originalConfig) {
		t.Fatalf("config rollback = %q err=%v", gotConfig, err)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("failed restore left a vault head: %v", err)
	}
}

func TestFreshRestoreCommitRollsBackNewKeyringAndConfigAfterGuardFailure(t *testing.T) {
	home, root := t.TempDir(), filepath.Join(t.TempDir(), "vault")
	configHome := filepath.Join(home, ".config")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configPath, envPath := config.ConfigPathForHome(home), providerConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	originalConfig, originalEnv := []byte("{\"vault_root\":\"old\"}\n"), []byte("OTHER_SETTING=preserve\n")
	if err := os.WriteFile(configPath, originalConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, originalEnv, 0600); err != nil {
		t.Fatal(err)
	}
	op := bytes.Repeat([]byte{5}, 32)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remote := store.New(filepath.Join(t.TempDir(), "remote"), op, signing)
	manifest, err := remote.Save([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("recovered")}})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(remote.Root, "snapshots", manifest.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := os.ReadFile(filepath.Join(remote.Root, "catalog", manifest.Snapshot+".json"))
	if err != nil {
		t.Fatal(err)
	}
	history, err := store.VerifyRemoteHistory([]store.RemoteSnapshot{{ID: manifest.Snapshot, Ciphertext: ciphertext, Catalog: catalog}}, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(file, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	keys := &failingRestoreStateKeyring{}
	err = store.RestoreWithVaultLock([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("recovered")}}, []store.RestoreDestination{{Path: ".zshrc", Exists: true, Data: []byte("before"), Mode: 0600}}, home, filepath.Join(root, "backups"), root, func() error {
		return commitVerifiedRestore(home, root, filepath.Join(home, "provider"), "https://github.com/owner/repo.git", []string{"share-one", "share-two"}, true, keys, op, signing, history)
	})
	if err == nil {
		t.Fatal("guard write failure was accepted")
	}
	if keys.saved {
		t.Fatal("new keyring material was not deleted during rollback")
	}
	gotFile, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(gotFile, []byte("before")) {
		t.Fatalf("file rollback = %q err=%v", gotFile, err)
	}
	gotConfig, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(gotConfig, originalConfig) {
		t.Fatalf("config rollback = %q err=%v", gotConfig, err)
	}
	gotEnv, err := os.ReadFile(envPath)
	if err != nil || !bytes.Equal(gotEnv, originalEnv) {
		t.Fatalf("environment rollback = %q err=%v", gotEnv, err)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("failed restore left a vault head: %v", err)
	}
}

func TestSafeDiffLineRendersTerminalControlCharactersVisibly(t *testing.T) {
	got := safeDiffLine([]byte("first\r\tsecond\x1b[2J bidi\u202eoverlay"))
	if got != "first\\r\\tsecond�[2J bidi�overlay" {
		t.Fatalf("safe diff line = %q", got)
	}
}
