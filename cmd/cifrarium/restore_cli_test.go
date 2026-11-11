package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
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

func TestValidateRestoreRecoverySharesReportsProgressWithoutPrintingShares(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(op, signing)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{shares[0].Label + ":" + shares[0].Value, shares[1].Label + ":" + shares[1].Value}
	var output bytes.Buffer
	if err := validateRestoreRecoveryShares(&output, op, signing, values); err != nil {
		t.Fatalf("valid recovery shares rejected: %v", err)
	}
	if !strings.Contains(output.String(), "Validating recovery shares") {
		t.Fatalf("validation progress missing: %q", output.String())
	}
	for _, share := range shares {
		if strings.Contains(output.String(), share.Value) {
			t.Fatal("recovery share appeared in progress output")
		}
	}
}

func TestRestoreKeyModeOffersSnapshotOnlyRecoveryWithoutChangingTheDefault(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		wantSnapshot bool
	}{
		{name: "default keeps using the local vault", input: "\n", wantSnapshot: false},
		{name: "explicit snapshot-only recovery", input: "snapshot\n", wantSnapshot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			got, err := promptRestoreSnapshotOnly(bufio.NewReader(strings.NewReader(tc.input)), &output)
			if err != nil {
				t.Fatalf("promptRestoreSnapshotOnly() error = %v", err)
			}
			if got != tc.wantSnapshot {
				t.Fatalf("snapshot-only = %v, want %v", got, tc.wantSnapshot)
			}
			if !strings.Contains(output.String(), "snapshot-only") {
				t.Fatalf("prompt does not explain snapshot-only option: %q", output.String())
			}
		})
	}
}

func TestRestoreKeyModeRejectsUnknownChoice(t *testing.T) {
	_, err := promptRestoreSnapshotOnly(bufio.NewReader(strings.NewReader("replace\n")), &bytes.Buffer{})
	if err == nil || err.Error() != "recovery mode must be normal or snapshot-only" {
		t.Fatalf("promptRestoreSnapshotOnly() error = %v", err)
	}
}

func TestRecoverSnapshotOnlyKeysUsesSharesWithoutComparingOrPersistingLocalKeys(t *testing.T) {
	localOp, localSigning, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	backupOp, backupSigning, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(backupOp, backupSigning)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{shares[0].Label + ":" + shares[0].Value, shares[1].Label + ":" + shares[1].Value}
	gotOp, gotSigning, err := recoverSnapshotOnlyKeys(values)
	if err != nil {
		t.Fatalf("recoverSnapshotOnlyKeys() error = %v", err)
	}
	if !bytes.Equal(gotOp, backupOp) || !bytes.Equal(gotSigning, backupSigning) {
		t.Fatal("snapshot-only recovery did not decode the backup keys")
	}
	if bytes.Equal(gotOp, localOp) || bytes.Equal(gotSigning, localSigning) {
		t.Fatal("fixture backup keys unexpectedly match the existing local vault")
	}
	for i := range shares {
		shares[i].Value = ""
	}
}

func TestApplySnapshotOnlyRestoreLeavesCifrariumStateUntouched(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "vault")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	configPath, envPath := config.ConfigPathForHome(home), providerConfigPath(home)
	state := map[string][]byte{
		configPath:                             []byte("existing vault config"),
		envPath:                                []byte("existing provider config"),
		filepath.Join(root, "head.json"):       []byte("existing head"),
		filepath.Join(root, "pending.queue"):   []byte("existing queue"),
		filepath.Join(root, "keyring.fixture"): []byte("existing keyring"),
	}
	for path, contents := range state {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(file, []byte("old user file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applySnapshotOnlyRestore(home, root, []store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("recovered user file")}}, []store.RestoreDestination{{Path: ".zshrc", Exists: true, Data: []byte("old user file"), Mode: 0600}}); err != nil {
		t.Fatalf("applySnapshotOnlyRestore() error = %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(got, []byte("recovered user file")) {
		t.Fatalf("restored file = %q, err = %v", got, err)
	}
	for path, want := range state {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("Cifrarium state %s = %q, err = %v; want unchanged %q", path, got, err, want)
		}
	}
}

func TestApplySnapshotOnlyRestoreRollsBackIfDestinationChanged(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "vault")
	file := filepath.Join(home, ".zshrc")
	before := []byte("changed after preflight")
	if err := os.WriteFile(file, before, 0600); err != nil {
		t.Fatal(err)
	}
	err := applySnapshotOnlyRestore(home, root, []store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("backup")}}, []store.RestoreDestination{{Path: ".zshrc", Exists: true, Data: []byte("stale preflight"), Mode: 0600}})
	if err == nil || !strings.Contains(err.Error(), "restore destination changed after preflight") {
		t.Fatalf("applySnapshotOnlyRestore() error = %v; want changed-destination failure", err)
	}
	got, readErr := os.ReadFile(file)
	if readErr != nil || !bytes.Equal(got, before) {
		t.Fatalf("failed snapshot-only restore left file = %q, err = %v", got, readErr)
	}
}

func TestRestoreFailureDiagnosticsHideUnderlyingPathsAndErrors(t *testing.T) {
	unsafe := errors.New("open /home/user/.config/cifrarium/keyring: permission denied")
	for _, tc := range []struct {
		name string
		got  error
		want string
	}{
		{"preflight", restorePreflightFailure(unsafe), "restore preflight failed; no files or vault state were changed"},
		{"application", restoreApplicationFailure(unsafe), "Cifrarium could not complete the restore. Inspect selected files and local vault state before retrying."},
		{"staging", restoreStagingFailure(unsafe), "could not create temporary backup staging area; restore stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Error() != tc.want || strings.Contains(tc.got.Error(), unsafe.Error()) || strings.Contains(tc.got.Error(), "/home/user") {
				t.Fatalf("diagnostic = %q, want safe message %q", tc.got, tc.want)
			}
		})
	}
}

type restoreProgressErrorWriter struct{}

func (restoreProgressErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("terminal failure with private detail")
}

func TestRestoreProgressWriteFailureIsSafeAndStopsProgress(t *testing.T) {
	err := writeRestoreProgress(restoreProgressErrorWriter{}, "Applying selected files...")
	if err == nil || err.Error() != "could not write restore progress to the controlling terminal" || strings.Contains(err.Error(), "private detail") {
		t.Fatalf("progress write error = %v; want safe terminal error", err)
	}
}

func TestRestoreCompletionAndSharePromptWriteFailuresAreSanitized(t *testing.T) {
	if err := writeRestoreCompletion(restoreProgressErrorWriter{}, "Recovery completed."); err == nil || err.Error() != "restore completed, but confirmation could not be written to the controlling terminal" {
		t.Fatalf("completion write error = %v", err)
	}
	if err := writeRecoverySharePrompt(restoreProgressErrorWriter{}, 1); err == nil || err.Error() != "could not display the hidden recovery-share prompt" || strings.Contains(err.Error(), "private detail") {
		t.Fatalf("share prompt write error = %v", err)
	}
}

func TestRestoreStageCleanupFailureReportsOutcomeWithoutPaths(t *testing.T) {
	cleanupErr := errors.New("remove /tmp/cifrarium-private-stage: permission denied")
	if got := restoreStageCleanupFailure(nil, cleanupErr).Error(); got != "restore completed, but encrypted backup staging cleanup failed; inspect temporary storage" || strings.Contains(got, "/tmp/") {
		t.Fatalf("successful restore cleanup diagnostic = %q", got)
	}
	if got := restoreStageCleanupFailure(errors.New("restore failed"), cleanupErr).Error(); got != "restore failed, and encrypted backup staging cleanup failed; inspect temporary storage before retrying" || strings.Contains(got, "/tmp/") {
		t.Fatalf("failed restore cleanup diagnostic = %q", got)
	}
}

func TestRestoreVerifyStageCleanupFailureDoesNotClaimRestore(t *testing.T) {
	cleanupErr := errors.New("remove /tmp/private-stage: permission denied")
	if got := restoreVerifyStageCleanupFailure(nil, cleanupErr).Error(); got != "backup verification completed, but temporary encrypted staging cleanup failed; inspect temporary storage" || strings.Contains(got, "/tmp/") {
		t.Fatalf("successful verification cleanup diagnostic = %q", got)
	}
	if got := restoreVerifyStageCleanupFailure(errors.New("verification failed"), cleanupErr).Error(); got != "backup verification failed, and temporary encrypted staging cleanup failed; inspect temporary storage before retrying" || strings.Contains(got, "/tmp/") {
		t.Fatalf("failed verification cleanup diagnostic = %q", got)
	}
}

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

func TestRestoreHistoryVerificationErrorExplainsForkWithoutDetailLeak(t *testing.T) {
	if got, want := restoreHistoryVerificationError(store.ErrRemoteHistoryForked).Error(), "backup history has multiple branches or no unique head; no local recovery state was written"; got != want {
		t.Fatalf("fork diagnostic = %q, want %q", got, want)
	}
	if got, want := restoreHistoryVerificationError(errors.New("private object id and path detail")).Error(), "backup history verification failed; no local recovery state was written"; got != want {
		t.Fatalf("generic diagnostic = %q, want %q", got, want)
	}
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{fmt.Errorf("remote snapshot catalog is invalid: %w", store.ErrRemoteSnapshotCatalog), "backup contains a catalog that failed validation; no local recovery state was written"},
		{fmt.Errorf("remote snapshot catalog is malformed: %w", errors.Join(store.ErrRemoteSnapshotCatalog, store.ErrRemoteSnapshotCatalogMalformed)), "backup contains a malformed catalog envelope; no local recovery state was written"},
		{fmt.Errorf("remote snapshot catalog could not be opened: %w", errors.Join(store.ErrRemoteSnapshotCatalog, store.ErrRemoteSnapshotCatalogUnreadable)), "backup catalog could not be opened with these recovery keys. The shares may belong to a different backup, or the catalog may be damaged. Verify the share pair and backup source; no local recovery state was written."},
		{fmt.Errorf("remote snapshot catalog identifier does not match object: %w", errors.Join(store.ErrRemoteSnapshotCatalog, store.ErrRemoteSnapshotCatalogMismatch)), "backup catalog identifier does not match its remote object; backup metadata is inconsistent and no local recovery state was written"},
		{fmt.Errorf("remote snapshot signature or hash verification failed: %w", store.ErrRemoteSnapshotIntegrity), "backup contains a snapshot that failed integrity verification; no local recovery state was written"},
		{fmt.Errorf("remote snapshot decryption failed: %w", store.ErrRemoteSnapshotDecryption), "backup contains a snapshot that could not be decrypted; no local recovery state was written"},
	} {
		got := restoreHistoryVerificationError(tc.cause).Error()
		if got != tc.want || strings.Contains(got, tc.cause.Error()) {
			t.Fatalf("diagnostic for %q = %q, want sanitized %q", tc.cause, got, tc.want)
		}
	}
}

func TestRestoreVerifyCommandParsingAndSecretClassification(t *testing.T) {
	command, args, err := canonicalCommand([]string{"restore", "verify", "-provider-remote", "https://github.com/owner/repo.git"})
	if err != nil || command != "restore-verify" || len(args) != 2 || args[0] != "-provider-remote" {
		t.Fatalf("canonicalCommand = %q, %v, %v", command, args, err)
	}
	if !commandMutatesOrHandlesSecrets(command) {
		t.Fatal("restore verify must not accept non-interactive secret handling")
	}
}

type readOnlyRestoreVerifyKeyring struct {
	operational []byte
	signing     ed25519.PrivateKey
	err         error
	reads       int
}

func (k *readOnlyRestoreVerifyKeyring) LoadExistingForRoot(string) ([]byte, ed25519.PrivateKey, error) {
	k.reads++
	return append([]byte(nil), k.operational...), append(ed25519.PrivateKey(nil), k.signing...), k.err
}

type readOnlyRestoreVerifySource struct {
	id         string
	ciphertext []byte
	catalog    []byte
	verified   bool
	staged     bool
}

func (s *readOnlyRestoreVerifySource) VerifyPrivate(context.Context) error {
	s.verified = true
	return nil
}
func (s *readOnlyRestoreVerifySource) StageRemoteSnapshots(context.Context) error {
	s.staged = true
	return nil
}
func (s *readOnlyRestoreVerifySource) Download(_ context.Context, id string) ([]byte, error) {
	if id != s.id {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), s.ciphertext...), nil
}
func (s *readOnlyRestoreVerifySource) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	if id != s.id {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), s.catalog...), nil
}
func (s *readOnlyRestoreVerifySource) List(context.Context) ([]string, error) {
	return []string{s.id}, nil
}

func TestRunRestoreVerificationLeavesLocalStateUnchangedOnSuccessAndFailure(t *testing.T) {
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := store.RecoveryShares(op, signing)
	if err != nil {
		t.Fatal(err)
	}
	shareValues := []string{shares[0].Label + ":" + shares[0].Value, shares[1].Label + ":" + shares[1].Value}
	vault := store.New(t.TempDir(), op, signing)
	snapshot, err := vault.SaveIfChanged([]store.Record{{Path: ".zshrc", Data: []byte("verified\n"), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		catalog []byte
		wantErr bool
	}{
		{name: "verified backup", catalog: snapshot.ManifestBytes},
		{name: "invalid catalog", catalog: []byte("not-json"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			state := map[string][]byte{
				"head.json":       []byte("existing-head"),
				"pending.queue":   []byte("existing-queue"),
				"keyring.fixture": []byte("existing-keyring"),
			}
			for path, data := range state {
				fullPath := filepath.Join(root, path)
				if err := os.WriteFile(fullPath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			keyring := &readOnlyRestoreVerifyKeyring{err: keyring.ErrNotFound}
			source := &readOnlyRestoreVerifySource{id: snapshot.Manifest.Snapshot, ciphertext: snapshot.Ciphertext, catalog: tc.catalog}
			prompts, cleaned := 0, false
			var output bytes.Buffer
			err := runRestoreVerification(context.Background(), root, "https://github.com/owner/repo.git", keyring, func(_ *os.File, _ int) (string, error) {
				value := shareValues[prompts]
				prompts++
				return value, nil
			}, func(string) (restoreVerifySource, func() error, error) {
				return source, func() error { cleaned = true; return nil }, nil
			}, &output, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("runRestoreVerification error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "malformed catalog envelope") {
				t.Fatalf("verification failure = %v; want actionable catalog diagnosis", err)
			}
			if !tc.wantErr && !strings.Contains(output.String(), "No local recovery state was written") {
				t.Fatalf("success output lacks read-only confirmation: %q", output.String())
			}
			if prompts != 2 || keyring.reads != 1 || !source.verified || !source.staged || !cleaned {
				t.Fatalf("verification calls: prompts=%d keyringReads=%d verified=%v staged=%v cleaned=%v", prompts, keyring.reads, source.verified, source.staged, cleaned)
			}
			for path, want := range state {
				got, err := os.ReadFile(filepath.Join(root, path))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("local state %s changed: got %q err=%v", path, got, err)
				}
			}
			for _, share := range shares {
				if strings.Contains(output.String(), share.Value) {
					t.Fatal("recovery share appeared in verification output")
				}
			}
		})
	}
}

func TestNewRestoreVerifySourceUsesAndRemovesTemporaryCheckout(t *testing.T) {
	configuredProviderDir := filepath.Join(t.TempDir(), "configured-provider")
	if err := os.MkdirAll(configuredProviderDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(configuredProviderDir, "marker")
	if err := os.WriteFile(marker, []byte("configured-provider-state"), 0600); err != nil {
		t.Fatal(err)
	}
	source, cleanup, err := newRestoreVerifySource("https://github.com/owner/repo.git")
	if err != nil {
		t.Fatal(err)
	}
	gitSource, ok := source.(provider.Git)
	if !ok {
		t.Fatalf("source type = %T; want provider.Git", source)
	}
	if filepath.Clean(gitSource.Dir) == filepath.Clean(configuredProviderDir) || !strings.HasPrefix(filepath.Clean(gitSource.Dir), filepath.Clean(os.TempDir())+string(os.PathSeparator)) {
		t.Fatalf("verification checkout %q is not isolated under temporary storage", gitSource.Dir)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gitSource.Dir); !os.IsNotExist(err) {
		t.Fatalf("temporary verification checkout still exists: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "configured-provider-state" {
		t.Fatalf("configured provider state changed: data=%q err=%v", got, err)
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
