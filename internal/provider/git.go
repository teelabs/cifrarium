package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
)

type Git struct {
	Dir    string
	Remote string
}

type gitObject struct {
	path string
	data []byte
}

type RemoteAccessError struct{ Err error }

func (e *RemoteAccessError) Error() string {
	return fmt.Sprintf("GitHub remote access failed; verify repository visibility and token permissions (tokens are never stored by Cifrarium): %v", e.Err)
}
func (e *RemoteAccessError) Unwrap() error { return e.Err }

func (g Git) run(ctx context.Context, args ...string) error {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return err
	}
	c, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return err
	}
	defer cleanup()
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("git %v: %w (%s)", args, err, out)
	}
	return nil
}

func (g Git) output(ctx context.Context, args ...string) ([]byte, error) {
	if err := g.validateRepositoryConfig(ctx); err != nil {
		return nil, err
	}
	c, cleanup, err := g.commandAtDir(ctx, "git", args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return c.Output()
}

func (g Git) command(ctx context.Context, executable string, args ...string) *exec.Cmd {
	if executable == "git" {
		args = hardenedGitArgs(args)
	}
	c := exec.CommandContext(ctx, executable, args...)
	c.Env = hardenedCommandEnv(executable)
	return c
}

func (g Git) commandAtDir(ctx context.Context, executable string, args ...string) (*exec.Cmd, func(), error) {
	if executable == "git" {
		args = hardenedGitArgs(args)
	}
	f, err := openGitDir(g.Dir)
	if err != nil {
		return nil, func() {}, err
	}
	c := anchoredGitCommand(ctx, executable, args, hardenedCommandEnv(executable), g.Dir, f)
	return c, func() { _ = f.Close() }, nil
}

func hardenedGitArgs(args []string) []string {
	return append([]string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.sshCommand=",
		"-c", "credential.helper=!/usr/bin/gh auth git-credential",
		"-c", "commit.gpgSign=false",
	}, args...)
}

func hardenedCommandEnv(executable string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(name, "GIT_") || strings.HasPrefix(name, "SSH_") ||
			strings.HasPrefix(name, "GH_") || name == "GITHUB_TOKEN" ||
			strings.HasPrefix(name, "CIFRARIUM_RECOVERY_SHARE_") {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	if executable == "gh" {
		env = append(env, "GH_PROMPT_DISABLED=1")
	}
	return env
}
func (g Git) Upload(ctx context.Context, id string, ciphertext []byte) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	if err := g.writeObject(ctx, filepath.Join("objects", id), ciphertext); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "snapshot "+id, gitObject{filepath.Join("objects", id), ciphertext})
}
func (g Git) UploadCatalog(ctx context.Context, id string, manifest []byte) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	path := filepath.Join("catalog", id+".json")
	if err := g.writeObject(ctx, path, manifest); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "catalog "+id, gitObject{path, manifest})
}
func (g Git) UploadSnapshot(ctx context.Context, id string, ciphertext, manifest []byte) error {
	if err := g.Ensure(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	objectPath := filepath.Join("objects", id)
	catalogPath := filepath.Join("catalog", id+".json")
	if err := g.writeObject(ctx, objectPath, ciphertext); err != nil {
		return err
	}
	if err := g.writeObject(ctx, catalogPath, manifest); err != nil {
		return err
	}
	return g.commitAndPush(ctx, "snapshot "+id,
		gitObject{objectPath, ciphertext}, gitObject{catalogPath, manifest})
}
func (g Git) Download(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return readProviderFileLimited(g.Dir, filepath.Join("objects", id), limits.MaxSnapshotCipherBytes)
}
func (g Git) DownloadCatalog(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return readProviderFileLimited(g.Dir, filepath.Join("catalog", id+".json"), limits.MaxManifestBytes)
}
func (g Git) List(ctx context.Context) ([]string, error) {
	return listProviderFiles(g.Dir, "objects")
}
func (g Git) Health(ctx context.Context) error {
	if err := g.run(ctx, "status", "--porcelain"); err != nil {
		return err
	}
	if g.Remote != "" {
		return g.CheckRemoteAccess(ctx)
	}
	return nil
}

// CheckRemoteAccess performs a read-only remote probe. Git remains the
// credential boundary, so revoked tokens and insufficient repository access
// are diagnosed without receiving or persisting credentials in Cifrarium.
func (g Git) CheckRemoteAccess(ctx context.Context) error {
	if g.Dir == "" {
		return fmt.Errorf("provider directory is required")
	}
	if _, err := g.remoteURL(ctx); err != nil {
		return &RemoteAccessError{Err: err}
	}
	remote := "origin"
	if g.Remote != "" {
		remote = g.Remote
	}
	if err := g.run(ctx, "ls-remote", remote, "HEAD"); err != nil {
		return &RemoteAccessError{Err: err}
	}
	return nil
}

// VerifyPrivate optionally checks the GitHub repository privacy flag through
// the operator's gh authentication. The token is owned by gh and is never
// passed as an argument or persisted by Cifrarium.
func (g Git) VerifyPrivate(ctx context.Context) error {
	if g.Remote == "" {
		return fmt.Errorf("GitHub privacy cannot be verified for a local-only provider")
	}
	remote := g.Remote
	if remote == "" {
		var err error
		remote, err = g.remoteURL(ctx)
		if err != nil {
			return &RemoteAccessError{Err: err}
		}
	}
	slug, err := githubRepoSlug(remote)
	if err != nil {
		return err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "gh", "api", "repos/"+slug, "--jq", ".private")
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		return &RemoteAccessError{Err: fmt.Errorf("GitHub privacy check unavailable: %w", err)}
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("GitHub repository %s is not private", slug)
	}
	return nil
}

func (g Git) validateRepositoryConfig(ctx context.Context) error {
	if g.Dir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(g.Dir, ".git")); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cmd, cleanup, err := g.commandAtDir(ctx, "git", "config", "--local", "--name-only", "--get-regexp", `^(filter\.|credential\.helper$|core\.(sshCommand|attributesFile|hooksPath|fsmonitor)|include\.|url\..*\.(insteadOf|pushInsteadOf)|remote\..*\.(uploadpack|receivepack)|http\.)`)
	if err != nil {
		return err
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return fmt.Errorf("cannot inspect local Git configuration: %w", err)
	}
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("unsafe local Git configuration rejected")
	}
	return nil
}

func (g Git) writeObject(ctx context.Context, relative string, data []byte) error {
	max := limits.MaxSnapshotCipherBytes
	if strings.HasPrefix(relative, "catalog"+string(filepath.Separator)) {
		max = limits.MaxManifestBytes
	}
	return writeProviderFileLimited(g.Dir, relative, data, max)
}

func (g Git) commitAndPush(ctx context.Context, message string, objects ...gitObject) error {
	for _, object := range objects {
		cmd, cleanup, err := g.commandAtDir(ctx, "git", "hash-object", "-w", "--stdin")
		if err != nil {
			return err
		}
		cmd.Stdin = bytes.NewReader(object.data)
		hash, err := cmd.Output()
		cleanup()
		if err != nil {
			return fmt.Errorf("hash provider object %s: %w", object.path, err)
		}
		hashText := strings.TrimSpace(string(hash))
		if len(hashText) != 40 {
			return fmt.Errorf("invalid Git object hash for %s", object.path)
		}
		if err := g.run(ctx, "update-index", "--add", "--cacheinfo", "100644,"+hashText+","+object.path); err != nil {
			return err
		}
	}
	if err := g.run(ctx, "commit", "-m", message); err != nil {
		// A retry after a successful remote upload may have nothing new to
		// commit. Continue to the push so a prior local-only commit is still
		// delivered, and let the remote remain the idempotency boundary.
		if !strings.Contains(err.Error(), "nothing to commit") {
			return err
		}
	}
	if g.Remote != "" {
		if err := g.VerifyPrivate(ctx); err != nil {
			return fmt.Errorf("privacy verification before push failed: %w", err)
		}
		return g.run(ctx, "push", g.Remote, "HEAD")
	}
	return nil
}

// Ensure initializes only the local repository and verifies an existing
// origin. It never creates a GitHub repository and never accepts credentials
// embedded in a remote URL.
func (g Git) Ensure(ctx context.Context) error {
	if g.Dir == "" {
		return fmt.Errorf("provider directory is required")
	}
	if info, err := os.Lstat(g.Dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("provider directory symlink rejected")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(g.Dir, 0700); err != nil {
		return err
	}
	gitDir := filepath.Join(g.Dir, ".git")
	if info, err := os.Lstat(gitDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("provider .git symlink rejected")
	} else if os.IsNotExist(err) {
		if err := g.run(ctx, "init", "--initial-branch=main"); err != nil {
			return err
		}
		if err := g.run(ctx, "config", "user.name", "cifrarium"); err != nil {
			return err
		}
		if err := g.run(ctx, "config", "user.email", "cifrarium@localhost"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if g.Remote == "" {
		return nil
	}
	if err := validateRemote(g.Remote); err != nil {
		return err
	}
	current, err := g.remoteURL(ctx)
	if err != nil {
		return g.run(ctx, "remote", "add", "origin", g.Remote)
	}
	if current != g.Remote {
		return fmt.Errorf("configured origin does not match requested GitHub remote")
	}
	return nil
}

func (g Git) remoteURL(ctx context.Context) (string, error) {
	out, err := g.output(ctx, "remote", "get-url", "origin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func validateRemote(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("remote must be an HTTPS GitHub URL without embedded credentials")
	}
	return nil
}

func githubRepoSlug(raw string) (string, error) {
	if err := validateRemote(raw); err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(uPath(raw), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("remote must identify one GitHub repository")
	}
	return strings.TrimSuffix(parts[0]+"/"+parts[1], ".git"), nil
}

func uPath(raw string) string {
	u, _ := url.Parse(raw)
	return u.Path
}

func validateID(id string) error {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return fmt.Errorf("invalid provider object id")
	}
	return nil
}
