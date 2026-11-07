package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
)

// runProviderSetup is deliberately interactive. Provider setup can write
// recovery material to a protected local file and may create a remote
// repository, so a non-interactive invocation must stop with a repair path.
func runProviderSetup(home, rootOverride string, nonInteractive bool, output io.Writer) error {
	return runProviderSetupWithInitialShares(home, rootOverride, nonInteractive, output, nil)
}

func runProviderSetupWithInitialShares(home, rootOverride string, nonInteractive bool, output io.Writer, initialShares map[string]string) error {
	if nonInteractive {
		return fmt.Errorf("provider setup requires a terminal; run cifrarium provider setup, review each confirmation, then run cifrarium provider health")
	}
	root, err := resolveVaultRoot("provider-setup", rootOverride, home)
	if err != nil {
		return err
	}
	keys := store.NewKeyring()
	op, signing, err := keys.LoadExistingForRoot(root)
	if err != nil {
		return fmt.Errorf("provider setup requires an existing vault; run cifrarium setup first: %w", err)
	}
	if _, err := store.Open(root, op, signing); err != nil {
		return fmt.Errorf("provider setup cannot use the vault: %w", err)
	}

	tty, err := openSetupTTY()
	if err != nil {
		return err
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	current, values, err := readDaemonEnv(home)
	if err != nil {
		return err
	}
	for key, value := range initialShares {
		if values[key] == "" {
			values[key] = value
		}
	}

	defaultDir := current.Dir
	if defaultDir == "" {
		defaultDir = filepath.Join(home, ".local", "share", "cifrarium-provider")
	}
	dir, err := promptLine(reader, tty, "Local provider directory", defaultDir)
	if err != nil {
		return err
	}
	remote, err := promptLine(reader, tty, "Private GitHub remote (leave empty for local-only)", current.Remote)
	if err != nil {
		return err
	}
	if remote != "" && !strings.HasPrefix(remote, "https://github.com/") {
		return fmt.Errorf("remote must be an HTTPS GitHub URL without embedded credentials; rerun cifrarium provider setup")
	}

	createRemote := false
	remoteSlug := ""
	if remote == "" {
		create, err := promptYesNo(reader, tty, "Create a new private GitHub repository with gh now?", false)
		if err != nil {
			return err
		}
		if create {
			remoteSlug, err = promptLine(reader, tty, "GitHub repository (OWNER/REPO)", "cifrarium-backup")
			if err != nil {
				return err
			}
			if strings.Count(remoteSlug, "/") != 1 || strings.ContainsAny(remoteSlug, " \t\r\n") {
				return fmt.Errorf("repository must be OWNER/REPO; rerun cifrarium provider setup")
			}
			remote = "https://github.com/" + remoteSlug + ".git"
			createRemote = true
		}
	}
	if dir == "" {
		return fmt.Errorf("provider directory cannot be empty")
	}

	gitProvider := provider.Git{Dir: dir, Remote: remote}
	fmt.Fprintln(tty, "\nReview provider changes:")
	fmt.Fprintf(tty, "  local checkout: %s\n", dir)
	if remote == "" {
		fmt.Fprintln(tty, "  remote: local-only")
	} else {
		fmt.Fprintf(tty, "  remote: %s\n", remote)
	}
	if !promptConfirmation(reader, tty, "Apply this provider configuration?") {
		return fmt.Errorf("provider setup cancelled; no provider configuration was changed")
	}
	localProvider := gitProvider
	if createRemote {
		// Let gh create and attach origin; adding the placeholder remote first
		// would make `gh repo create --remote origin` fail.
		localProvider.Remote = ""
	}
	if err := localProvider.Ensure(context.Background()); err != nil {
		return fmt.Errorf("provider local checkout: %w", err)
	}
	if createRemote {
		if err := createPrivateGitHubRepository(dir, remoteSlug); err != nil {
			return err
		}
		// gh configured origin, but Ensure also enforces that it matches the
		// URL which will be stored in daemon.env.
		if err := gitProvider.Ensure(context.Background()); err != nil {
			return fmt.Errorf("provider remote configuration: %w", err)
		}
	} else if remote != "" {
		if err := gitProvider.CheckRemoteAccess(context.Background()); err != nil {
			return fmt.Errorf("provider remote check failed; no daemon.env was written: %w", err)
		}
		if err := gitProvider.VerifyPrivate(context.Background()); err != nil {
			return fmt.Errorf("provider privacy check failed; no daemon.env was written: %w", err)
		}
	}

	shareValues, err := reconcileRecoveryShares(reader, tty, values, op, signing)
	if err != nil {
		return err
	}
	if err := writeDaemonEnv(home, dir, remote, shareValues); err != nil {
		return err
	}
	fmt.Fprintln(tty, "Provider configuration saved with mode 0600. No snapshot was captured and no upload was performed.")
	enable, err := promptYesNo(reader, tty, "Enable the user daemon now?", false)
	if err != nil {
		return err
	}
	if enable {
		if err := enableUserDaemon(); err != nil {
			return err
		}
		fmt.Fprintln(tty, "Daemon enabled.")
	} else {
		fmt.Fprintln(tty, "Daemon remains disabled. Run systemctl --user enable --now cifrarium.service when ready.")
	}
	return nil
}

func promptLine(reader *bufio.Reader, tty io.Writer, label, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(tty, "%s [%s]: ", label, defaultValue)
	} else {
		fmt.Fprintf(tty, "%s: ", label)
	}
	value, err := reader.ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptYesNo(reader *bufio.Reader, tty io.Writer, question string, defaultValue bool) (bool, error) {
	answerDefault := "y/N"
	if defaultValue {
		answerDefault = "Y/n"
	}
	fmt.Fprintf(tty, "%s [%s]: ", question, answerDefault)
	answer, err := reader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" {
		return defaultValue, nil
	}
	return answer == "y" || answer == "yes" || answer == "s" || answer == "sim", nil
}

func promptConfirmation(reader *bufio.Reader, tty io.Writer, question string) bool {
	ok, err := promptYesNo(reader, tty, question+" Type yes to continue", false)
	return err == nil && ok
}

func createPrivateGitHubRepository(dir, slug string) error {
	cmd := exec.Command("gh", "repo", "create", slug, "--private", "--source", dir, "--remote", "origin")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("private GitHub repository creation failed; authenticate gh and retry: %w", err)
	}
	return nil
}

func enableUserDaemon() error {
	if err := runDaemonRefreshSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("daemon activation reload: %w", err)
	}
	if err := runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service"); err == nil {
		if err := runDaemonRefreshSystemctl("restart", "cifrarium.service"); err != nil {
			return fmt.Errorf("daemon activation restart: %w", err)
		}
		return nil
	}
	if err := runDaemonRefreshSystemctl("enable", "--now", "cifrarium.service"); err != nil {
		return fmt.Errorf("daemon activation: %w", err)
	}
	return nil
}

func readDaemonEnv(home string) (providerConfig, map[string]string, error) {
	path := providerConfigPath(home)
	if err := rejectPathSymlink(path); err != nil {
		return providerConfig{}, nil, err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return providerConfig{}, map[string]string{}, nil
	}
	if err != nil {
		return providerConfig{}, nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil {
		return providerConfig{}, nil, err
	} else if info.Mode().Perm()&0077 != 0 {
		return providerConfig{}, nil, fmt.Errorf("%s must be private (mode 0600); run chmod 600 %s", path, path)
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return providerConfig{}, nil, fmt.Errorf("%s line %d is invalid; fix it or remove it before retrying", path, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return providerConfig{}, nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return providerConfig{Dir: values["CIFRARIUM_PROVIDER_DIR"], Remote: values["CIFRARIUM_PROVIDER_REMOTE"]}, values, nil
}

func reconcileRecoveryShares(reader *bufio.Reader, tty io.Writer, values map[string]string, op []byte, signing ed25519.PrivateKey) (map[string]string, error) {
	result := map[string]string{}
	first, second := values["CIFRARIUM_RECOVERY_SHARE_1"], values["CIFRARIUM_RECOVERY_SHARE_2"]
	if first != "" && second != "" {
		shares, err := parseRecoveryShares([]string{first, second})
		if err != nil || !matchesKeyMaterial(op, signing, shares) {
			return nil, fmt.Errorf("existing recovery shares are invalid; import a protected pair or explicitly generate a replacement")
		}
		result["CIFRARIUM_RECOVERY_SHARE_1"], result["CIFRARIUM_RECOVERY_SHARE_2"] = first, second
		fmt.Fprintln(tty, "Existing recovery shares were validated and will be preserved.")
		return result, nil
	}

	choice, err := promptLine(reader, tty, "Recovery shares: import PATH, generate, or skip", "skip")
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(choice) {
	case "generate":
		shares, err := store.RecoveryShares(op, signing)
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(tty, "The three shares are shown only on this terminal. Store two independently and keep the third offline:")
		for _, share := range shares {
			fmt.Fprintf(tty, "%s:%s\n", share.Label, share.Value)
		}
		if !promptConfirmation(reader, tty, "I have stored two shares securely and will keep the third offline.") {
			return nil, fmt.Errorf("recovery share setup cancelled; no recovery shares were written")
		}
		result["CIFRARIUM_RECOVERY_SHARE_1"] = shares[0].Label + ":" + shares[0].Value
		result["CIFRARIUM_RECOVERY_SHARE_2"] = shares[1].Label + ":" + shares[1].Value
	case "skip", "":
		fmt.Fprintln(tty, "Recovery shares were not written; remote uploads will remain unavailable until configured.")
	default:
		contents, err := os.ReadFile(choice)
		if err != nil {
			return nil, fmt.Errorf("cannot import recovery shares from protected file: %w", err)
		}
		lines := strings.Fields(string(contents))
		shares, err := parseRecoveryShares(lines)
		if err != nil || !matchesKeyMaterial(op, signing, shares) {
			return nil, fmt.Errorf("protected recovery-share file did not contain two valid shares for this keyring")
		}
		result["CIFRARIUM_RECOVERY_SHARE_1"] = lines[0]
		result["CIFRARIUM_RECOVERY_SHARE_2"] = lines[1]
	}
	return result, nil
}

func matchesKeyMaterial(op []byte, signing ed25519.PrivateKey, shares []recovery.Share) bool {
	recoveredOp, recoveredSigning, err := store.RecoverKeys(shares)
	return err == nil && string(recoveredOp) == string(op) && string(recoveredSigning) == string(signing)
}

// writeDaemonEnv updates only Cifrarium-owned keys and preserves unrelated
// operator variables. The temporary file is created in the same directory so
// rename is atomic on the filesystem containing daemon.env.
func writeDaemonEnv(home, dir, remote string, shares map[string]string) error {
	path := providerConfigPath(home)
	parent := filepath.Dir(path)
	if err := rejectPathSymlink(parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	if info, err := os.Stat(parent); err == nil && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("configuration directory %s must be private (mode 0700)", parent)
	}
	if err := rejectPathSymlink(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("configuration file must be a regular file")
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	updates := map[string]string{
		"CIFRARIUM_PROVIDER_DIR":    dir,
		"CIFRARIUM_PROVIDER_REMOTE": remote,
	}
	for key, value := range shares {
		updates[key] = value
	}
	owned := map[string]bool{}
	var lines []string
	for _, raw := range strings.Split(strings.TrimSuffix(string(old), "\n"), "\n") {
		if strings.TrimSpace(raw) == "" {
			lines = append(lines, raw)
			continue
		}
		key, _, ok := strings.Cut(strings.TrimSpace(raw), "=")
		key = strings.TrimSpace(key)
		if ok && updates[key] != "" {
			lines = append(lines, key+"="+envValue(updates[key]))
			owned[key] = true
			continue
		}
		if ok && updates[key] == "" && (key == "CIFRARIUM_PROVIDER_REMOTE" || strings.HasPrefix(key, "CIFRARIUM_RECOVERY_SHARE_")) {
			// Remove stale owned values when the operator explicitly selected
			// local-only mode or skipped recovery shares.
			owned[key] = true
			continue
		}
		lines = append(lines, raw)
	}
	for _, key := range []string{"CIFRARIUM_PROVIDER_DIR", "CIFRARIUM_PROVIDER_REMOTE", "CIFRARIUM_RECOVERY_SHARE_1", "CIFRARIUM_RECOVERY_SHARE_2"} {
		if value, ok := updates[key]; ok && value != "" && !owned[key] {
			lines = append(lines, key+"="+envValue(value))
		}
	}
	data := []byte(strings.TrimLeft(strings.Join(lines, "\n"), "\n") + "\n")
	tmp, err := os.CreateTemp(parent, ".daemon.env-*")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("activate configuration: %w", err)
	}
	return nil
}

func rejectPathSymlink(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(absolute), current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect protected configuration path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("protected configuration path contains a symlink")
		}
	}
	return nil
}

func envValue(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n#\"'\\") {
		return value
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
