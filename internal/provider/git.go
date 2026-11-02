package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Git struct {
	Dir    string
	Remote string
}

type RemoteAccessError struct{ Err error }

func (e *RemoteAccessError) Error() string {
	return fmt.Sprintf("GitHub remote access failed; verify repository visibility and token permissions (tokens are never stored by Cifrarium): %v", e.Err)
}
func (e *RemoteAccessError) Unwrap() error { return e.Err }

func (g Git) run(ctx context.Context, args ...string) error {
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = g.Dir
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("git %v: %w (%s)", args, err, out)
	}
	return nil
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
	return g.commitAndPush(ctx, "snapshot "+id, filepath.Join("objects", id))
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
	return g.commitAndPush(ctx, "catalog "+id, path)
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
	return g.commitAndPush(ctx, "snapshot "+id, objectPath, catalogPath)
}
func (g Git) Download(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	path, err := g.safePath(filepath.Join("objects", id))
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
func (g Git) DownloadCatalog(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	path, err := g.safePath(filepath.Join("catalog", id+".json"))
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
func (g Git) List(ctx context.Context) ([]string, error) {
	objects, err := g.safePath("objects")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(objects)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
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
	if err := g.run(ctx, "ls-remote", "origin", "HEAD"); err != nil {
		return &RemoteAccessError{Err: err}
	}
	return nil
}

// VerifyPrivate optionally checks the GitHub repository privacy flag through
// the operator's gh authentication. The token is owned by gh and is never
// passed as an argument or persisted by Cifrarium.
func (g Git) VerifyPrivate(ctx context.Context) error {
	remote, err := g.remoteURL(ctx)
	if err != nil {
		return &RemoteAccessError{Err: err}
	}
	slug, err := githubRepoSlug(remote)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "gh", "api", "repos/"+slug, "--jq", ".private")
	cmd.Dir = g.Dir
	out, err := cmd.Output()
	if err != nil {
		return &RemoteAccessError{Err: fmt.Errorf("GitHub privacy check unavailable: %w", err)}
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("GitHub repository %s is not private", slug)
	}
	return nil
}

func (g Git) writeObject(ctx context.Context, relative string, data []byte) error {
	path, err := g.safePath(relative)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (g Git) safePath(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", fmt.Errorf("unsafe provider path")
	}
	path := filepath.Join(g.Dir, relative)
	current := g.Dir
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("provider symlink path rejected: %s", relative)
		}
	}
	return path, nil
}
func (g Git) commitAndPush(ctx context.Context, message string, paths ...string) error {
	args := append([]string{"add", "--"}, paths...)
	if err := g.run(ctx, args...); err != nil {
		return err
	}
	if err := g.run(ctx, "commit", "-m", message); err != nil {
		return err
	}
	if g.Remote != "" {
		return g.run(ctx, "push", "origin", "HEAD")
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
	c := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	c.Dir = g.Dir
	out, err := c.Output()
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
