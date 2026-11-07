package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/limits"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/restore"
	"github.com/teelabs/cifrarium/internal/rpc"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
)

func runFileRestore(home, rootOverride, providerDir, remote string, output io.Writer) error {
	if !isTerminalFile(os.Stdin) || !isTerminalFile(os.Stdout) {
		return fmt.Errorf("cifrarium restore requires an interactive terminal")
	}
	tty, err := openSetupTTY()
	if err != nil {
		return err
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	root, err := resolveVaultRoot("restore", rootOverride, home)
	if err != nil {
		return err
	}
	currentProvider, savedValues, err := readDaemonEnv(home)
	if err != nil {
		return fmt.Errorf("protected provider configuration is unsafe or unreadable")
	}
	if providerDir == "" {
		providerDir = currentProvider.Dir
	}
	if remote == "" {
		remote = currentProvider.Remote
	}
	if remote == "" {
		remote, err = promptLine(reader, tty, "Private GitHub remote (OWNER/REPO or HTTPS URL)", "")
		if err != nil {
			return err
		}
		if strings.Count(remote, "/") == 1 && !strings.Contains(remote, "://") {
			remote = "https://github.com/" + remote + ".git"
		}
	}
	if !strings.HasPrefix(remote, "https://github.com/") || strings.ContainsAny(remote, "\r\n\t ") {
		return fmt.Errorf("restore requires an HTTPS GitHub remote")
	}
	if providerDir == "" {
		providerDir = filepath.Join(home, ".local", "share", "cifrarium-provider")
	}

	keys := store.NewKeyring()
	op, signing, keyErr := keys.LoadExistingForRoot(root)
	shareValues := make([]string, 0, 2)
	freshKeys := false
	if keyErr != nil {
		if !errors.Is(keyErr, keyring.ErrNotFound) {
			return fmt.Errorf("existing keyring is unavailable; restore stopped")
		}
		freshKeys = true
		first, err := readRecoveryShare(tty, 1)
		if err != nil {
			return err
		}
		second, err := readRecoveryShare(tty, 2)
		if err != nil {
			return err
		}
		shares, err := parseRecoveryShares([]string{first, second})
		shareValues = []string{first, second}
		first = ""
		second = ""
		if err != nil {
			return fmt.Errorf("recovery shares are invalid")
		}
		op, signing, err = store.RecoverKeys(shares)
		for i := range shares {
			shares[i].Value = ""
		}
		if err != nil {
			return fmt.Errorf("recovery shares could not unlock this backup")
		}
	} else {
		if savedValues["CIFRARIUM_RECOVERY_SHARE_1"] != "" && savedValues["CIFRARIUM_RECOVERY_SHARE_2"] != "" {
			shareValues = []string{savedValues["CIFRARIUM_RECOVERY_SHARE_1"], savedValues["CIFRARIUM_RECOVERY_SHARE_2"]}
			shares, parseErr := parseRecoveryShares(shareValues)
			if parseErr != nil || !matchesKeyMaterial(op, signing, shares) {
				return fmt.Errorf("saved recovery shares do not match this vault")
			}
		} else {
			for i := 1; i <= 2; i++ {
				value, readErr := readRecoveryShare(tty, i)
				if readErr != nil {
					return readErr
				}
				shareValues = append(shareValues, value)
			}
			shares, parseErr := parseRecoveryShares(shareValues)
			if parseErr != nil || !matchesKeyMaterial(op, signing, shares) {
				return fmt.Errorf("recovery shares do not match this vault")
			}
		}
	}

	stage, err := os.MkdirTemp("", "cifrarium-restore-provider-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	gitProvider := provider.Git{Dir: stage, Remote: remote}
	if err := gitProvider.VerifyPrivate(context.Background()); err != nil {
		return fmt.Errorf("private GitHub provider could not be verified; restore stopped")
	}
	if err := gitProvider.StageRemoteSnapshots(context.Background()); err != nil {
		return fmt.Errorf("private backup could not be staged or verified")
	}
	history, err := restore.VerifyRemoteHistory(context.Background(), gitProvider, op, signing)
	if err != nil {
		return fmt.Errorf("backup history verification failed; no local recovery state was written")
	}
	if len(history.Entries) == 0 {
		return fmt.Errorf("verified backup history is empty")
	}
	fmt.Fprintln(tty, "Verified snapshot chain. On a new machine the provider branch is the freshness anchor; a valid older signed history after remote rollback cannot be detected.")
	fmt.Fprintln(tty, "Snapshots (newest first):")
	for i, entry := range history.Entries {
		fmt.Fprintf(tty, "  %d) %s (%d files)\n", i+1, entry.ID, len(entry.Records))
	}
	choice, err := promptLine(reader, tty, "Snapshot number", "1")
	if err != nil {
		return err
	}
	var index int
	if _, err := fmt.Sscan(choice, &index); err != nil || index < 1 || index > len(history.Entries) {
		return fmt.Errorf("invalid snapshot selection")
	}
	selectedSnapshot := history.Entries[index-1]
	availableAdapters := map[string][]string{}
	for _, record := range selectedSnapshot.Records {
		name, ok := restoreAdapter(record.Path)
		if !ok {
			return fmt.Errorf("verified snapshot contains a path outside the restore allowlist")
		}
		availableAdapters[name] = append(availableAdapters[name], record.Path)
	}
	for name, paths := range availableAdapters {
		sort.Strings(paths)
		fmt.Fprintf(tty, "  %s: %d files\n", name, len(paths))
	}
	selectedNames, err := promptLine(reader, tty, "Adapters (all or comma-separated names; empty selects files only)", "all")
	if err != nil {
		return err
	}
	selectedAdapters := map[string]bool{}
	if strings.TrimSpace(selectedNames) == "all" {
		for name := range availableAdapters {
			selectedAdapters[name] = true
		}
	} else {
		for _, name := range strings.Split(selectedNames, ",") {
			if name = strings.TrimSpace(name); name != "" {
				selectedAdapters[name] = true
			}
		}
	}
	selectedPaths := map[string]bool{}
	if len(selectedAdapters) == 0 {
		for i, record := range selectedSnapshot.Records {
			fmt.Fprintf(tty, "  %d) %s\n", i+1, record.Path)
		}
		list, err := promptLine(reader, tty, "File numbers (comma-separated)", "")
		if err != nil {
			return err
		}
		for _, value := range strings.Split(list, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			var n int
			if _, err := fmt.Sscan(value, &n); err != nil || n < 1 || n > len(selectedSnapshot.Records) {
				return fmt.Errorf("invalid file selection")
			}
			selectedPaths[selectedSnapshot.Records[n-1].Path] = true
		}
	}
	selected, err := restore.SelectRecords(selectedSnapshot.Records, selectedAdapters, selectedPaths)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return fmt.Errorf("no files selected")
	}
	plan, err := restore.BuildFilePlan(home, history, selectedSnapshot.ID, selected)
	if err != nil {
		return fmt.Errorf("restore preflight failed: %w", err)
	}
	choices := map[string]restore.ConflictChoice{}
	for _, item := range plan {
		switch item.Status {
		case restore.PlanIdentical:
			fmt.Fprintf(tty, "  %s: identical, skip\n", item.Record.Path)
		case restore.PlanNew:
			fmt.Fprintf(tty, "  %s: new\n", item.Record.Path)
		case restore.PlanMerge:
			fmt.Fprintf(tty, "  %s: clean merge from verified common base\n", item.Record.Path)
		case restore.PlanConflict:
			fmt.Fprintf(tty, "  %s: %s\n", item.Record.Path, item.Reason)
			answer, err := promptLine(reader, tty, "Choose overwrite, keep, or cancel (diff is available with d)", "cancel")
			if err != nil {
				return err
			}
			if answer == "d" {
				renderRestoreDiff(tty, item.Current, item.Record.Data)
				answer, err = promptLine(reader, tty, "Choose overwrite, keep, or cancel", "cancel")
				if err != nil {
					return err
				}
			}
			switch strings.ToLower(answer) {
			case "overwrite":
				choices[item.Record.Path] = restore.ChoiceOverwrite
			case "keep":
				choices[item.Record.Path] = restore.ChoiceKeep
			default:
				choices[item.Record.Path] = restore.ChoiceCancel
			}
		}
	}
	apply, err := restore.ResolveFilePlan(plan, choices)
	if err != nil {
		return err
	}
	fingerprint, err := restore.Fingerprint(plan)
	if err != nil {
		return err
	}
	request := daemon.FileRestoreRequest{Snapshot: selectedSnapshot.ID, Remote: remote, Choices: choices, Fingerprint: fingerprint}
	for _, record := range selected {
		request.Paths = append(request.Paths, record.Path)
	}
	daemonMayBeActive := false
	if _, err := os.Lstat(filepath.Join(root, "control.sock")); err == nil {
		daemonMayBeActive = true
		if err := validateDaemonRestoreRequestSize(request); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("daemon state is unknown; restore stopped")
	}
	if !promptConfirmation(reader, tty, "Apply selected restore? Replaced files will receive private backups and vault/keyring configuration will be installed.") {
		return fmt.Errorf("restore cancelled; no local state was changed")
	}
	if daemonMayBeActive {
		rollbackConfig, err := prepareRestoreConfiguration(home, root, providerDir, remote, shareValues)
		if err != nil {
			return fmt.Errorf("could not prepare protected recovery configuration")
		}
		active, callErr := callDaemonRestore(root, request)
		if callErr != nil {
			if rollbackErr := rollbackConfig(); rollbackErr != nil {
				return fmt.Errorf("active daemon restore failed; configuration rollback also failed")
			}
			return callErr
		}
		if active {
			if err := finishDaemonRestore(root); err != nil {
				return err
			}
			fmt.Fprintf(tty, "Recovery completed through the daemon. %d selected files applied; the user daemon is disabled.\n", len(apply))
			return nil
		}
		if err := rollbackConfig(); err != nil {
			return fmt.Errorf("daemon stopped before restore; protected configuration rollback failed")
		}
	}
	if err := disableUserDaemonForRestore(root); err != nil {
		return err
	}
	commit := func() error {
		if err := gitProvider.Ensure(context.Background()); err != nil {
			return err
		}
		return commitVerifiedRestore(home, root, providerDir, remote, shareValues, freshKeys, keys, op, signing, history)
	}
	expected := make([]store.RestoreDestination, 0, len(plan))
	for _, item := range plan {
		expected = append(expected, store.RestoreDestination{Path: item.Record.Path, Exists: item.Status != restore.PlanNew, Data: item.Current, Mode: item.CurrentMode})
	}
	if err := store.RestoreWithVaultLock(apply, expected, home, filepath.Join(root, "backups"), root, commit); err != nil {
		return fmt.Errorf("restore application failed and was rolled back where possible: %w", err)
	}
	fmt.Fprintf(tty, "Recovery completed. %d selected files applied; the user daemon remains disabled.\n", len(apply))
	return nil
}

func validateDaemonRestoreRequestSize(request daemon.FileRestoreRequest) error {
	params, err := json.Marshal(request)
	if err != nil {
		return err
	}
	line, err := json.Marshal(rpc.Request{JSONRPC: "2.0", ID: "1844674407370955161", Protocol: rpc.ProtocolVersion, Method: "restore.apply", Params: params})
	if err != nil {
		return err
	}
	if len(line)+1 > limits.MaxMCPLineBytes {
		return fmt.Errorf("selected files exceed the active daemon's %d-byte restore request limit; reduce the selection, or stop the daemon and rerun restore", limits.MaxMCPLineBytes)
	}
	return nil
}

type restoreStateKeyring interface {
	store.HeadGuard
	SaveForRoot(string, []byte, ed25519.PrivateKey) error
	DeleteForRoot(string) error
}

func commitVerifiedRestore(home, root, providerDir, remote string, shares []string, freshKeys bool, keys restoreStateKeyring, op []byte, signing ed25519.PrivateKey, history store.VerifiedHistory) error {
	configPath, envPath := config.ConfigPathForHome(home), providerConfigPath(home)
	configBefore, err := captureRestoreConfig(configPath)
	if err != nil {
		return err
	}
	envBefore, err := captureRestoreConfig(envPath)
	if err != nil {
		return err
	}
	configChanged, envChanged, keySaved := false, false, false
	rollback := func(cause error) error {
		var rollbackErr error
		if envChanged {
			rollbackErr = restoreRestoreConfig(envBefore)
		}
		if configChanged {
			if err := restoreRestoreConfig(configBefore); rollbackErr == nil {
				rollbackErr = err
			}
		}
		if freshKeys && keySaved {
			if err := keys.DeleteForRoot(root); rollbackErr == nil {
				rollbackErr = err
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w; local recovery-state rollback failed: %v", cause, rollbackErr)
		}
		return cause
	}
	if _, err := config.SaveTo(configPath, root); err != nil {
		return rollback(err)
	}
	configChanged = true
	if len(shares) != 2 {
		return rollback(fmt.Errorf("exactly two validated recovery shares are required"))
	}
	if err := writeDaemonEnv(home, providerDir, remote, map[string]string{"CIFRARIUM_RECOVERY_SHARE_1": shares[0], "CIFRARIUM_RECOVERY_SHARE_2": shares[1]}); err != nil {
		return rollback(err)
	}
	envChanged = true
	if freshKeys {
		if err := keys.SaveForRoot(root, op, signing); err != nil {
			return rollback(err)
		}
		keySaved = true
	}
	if err := store.InstallVerifiedHistoryWithCommit(root, history, op, signing, keys, func() error { _, err := store.OpenWithGuard(root, op, signing, keys); return err }); err != nil {
		return rollback(err)
	}
	return nil
}

func prepareRestoreConfiguration(home, root, providerDir, remote string, shares []string) (func() error, error) {
	if len(shares) != 2 {
		return nil, fmt.Errorf("exactly two validated recovery shares are required")
	}
	configPath, envPath := config.ConfigPathForHome(home), providerConfigPath(home)
	configBefore, err := captureRestoreConfig(configPath)
	if err != nil {
		return nil, err
	}
	envBefore, err := captureRestoreConfig(envPath)
	if err != nil {
		return nil, err
	}
	if _, err := config.SaveTo(configPath, root); err != nil {
		return nil, err
	}
	rollback := func() error {
		if err := restoreRestoreConfig(envBefore); err != nil {
			return err
		}
		return restoreRestoreConfig(configBefore)
	}
	if err := writeDaemonEnv(home, providerDir, remote, map[string]string{"CIFRARIUM_RECOVERY_SHARE_1": shares[0], "CIFRARIUM_RECOVERY_SHARE_2": shares[1]}); err != nil {
		if rollbackErr := restoreRestoreConfig(configBefore); rollbackErr != nil {
			return nil, fmt.Errorf("%w; configuration rollback failed", err)
		}
		return nil, err
	}
	return rollback, nil
}

func callDaemonRestore(root string, request daemon.FileRestoreRequest) (bool, error) {
	socket := filepath.Join(root, "control.sock")
	if _, err := os.Lstat(socket); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("daemon state is unknown; restore stopped")
	}
	if err := validateDaemonRestoreRequestSize(request); err != nil {
		return true, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var result struct {
		Restored bool `json:"restored"`
	}
	if err := rpc.Call(ctx, socket, "restore.apply", request, &result); err != nil {
		return true, fmt.Errorf("active daemon could not complete restore; no local fallback was attempted")
	}
	if !result.Restored {
		return true, fmt.Errorf("active daemon returned an incomplete restore result")
	}
	return true, nil
}

func finishDaemonRestore(root string) error {
	if err := runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service"); err == nil {
		if err := runDaemonRefreshSystemctl("disable", "--now", "cifrarium.service"); err != nil {
			return fmt.Errorf("restore completed, but the active daemon could not be disabled; inspect daemon state")
		}
	} else if err := runDaemonRefreshSystemctl("is-enabled", "--quiet", "cifrarium.service"); err == nil {
		if err := runDaemonRefreshSystemctl("disable", "cifrarium.service"); err != nil {
			return fmt.Errorf("restore completed, but the daemon could not be disabled; inspect daemon state")
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		present := false
		for _, socket := range []string{filepath.Join(root, "control.sock"), filepath.Join(root, "cifrarium.sock")} {
			if _, err := os.Lstat(socket); err == nil {
				present = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("restore completed, but daemon socket state is unreadable")
			}
		}
		if !present {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("restore completed, but the daemon socket remains active; stop and inspect it")
}

func restoreAdapter(path string) (string, bool) { return adapters.RestoreAdapterForPath(path) }
func renderRestoreDiff(w io.Writer, before, after []byte) {
	fmt.Fprintln(w, "--- current / +++ backup (terminal only)")
	writeDiffSide(w, '-', before)
	writeDiffSide(w, '+', after)
}
func writeDiffSide(w io.Writer, prefix byte, data []byte) {
	const maxDiffBytes = 8192
	if len(data) > maxDiffBytes {
		data = data[:maxDiffBytes]
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fmt.Fprintf(w, "%c %s\n", prefix, safeDiffLine([]byte(line)))
	}
	if len(data) == maxDiffBytes {
		fmt.Fprintln(w, "  … diff truncated …")
	}
}
func safeDiffLine(data []byte) string {
	const limit = 300
	s := strings.ToValidUTF8(string(data), "�")
	var visible strings.Builder
	for _, r := range s {
		switch r {
		case '\n':
			visible.WriteString(`\n`)
		case '\r':
			visible.WriteString(`\r`)
		case '\t':
			visible.WriteString(`\t`)
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				visible.WriteRune('�')
			} else {
				visible.WriteRune(r)
			}
		}
	}
	s = visible.String()
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return s
}

type restoreConfigSnapshot struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

func captureRestoreConfig(path string) (restoreConfigSnapshot, error) {
	s := restoreConfigSnapshot{path: path}
	if err := rejectPathSymlink(path); err != nil {
		return s, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return s, fmt.Errorf("protected recovery configuration is unsafe")
	}
	s.data, err = os.ReadFile(path)
	if err != nil {
		return s, err
	}
	s.exists = true
	s.mode = info.Mode().Perm()
	return s, nil
}
func restoreRestoreConfig(s restoreConfigSnapshot) error {
	if err := rejectPathSymlink(filepath.Dir(s.path)); err != nil {
		return err
	}
	if err := rejectPathSymlink(s.path); err != nil {
		return err
	}
	if !s.exists {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".cifrarium-restore-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(s.mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(s.data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func disableUserDaemonForRestore(root string) error {
	if err := runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service"); err == nil {
		if err := runDaemonRefreshSystemctl("disable", "--now", "cifrarium.service"); err != nil {
			return fmt.Errorf("could not disable the active daemon; recovery stopped")
		}
	} else if err := runDaemonRefreshSystemctl("is-enabled", "--quiet", "cifrarium.service"); err == nil {
		if err := runDaemonRefreshSystemctl("disable", "cifrarium.service"); err != nil {
			return fmt.Errorf("could not disable the daemon; recovery stopped")
		}
	}
	for _, socket := range []string{filepath.Join(root, "control.sock"), filepath.Join(root, "cifrarium.sock")} {
		info, err := os.Lstat(socket)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("daemon state is unknown at the configured vault; stop and inspect it before restore")
		}
		probe := daemonRefreshProbe
		if strings.HasSuffix(socket, "control.sock") {
			probe = func(path string) error { _, err := daemonRefreshBackendProbe(path); return err }
		}
		if probe(socket) == nil {
			return fmt.Errorf("a foreground Cifrarium daemon is still active; stop it before restore")
		}
		return fmt.Errorf("a daemon socket remains at the configured vault; inspect or stop the daemon before restore")
	}
	if err := runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service"); err == nil {
		return fmt.Errorf("the Cifrarium service remains active; recovery stopped")
	}
	return nil
}
