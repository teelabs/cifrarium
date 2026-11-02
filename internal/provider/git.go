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
	if err := os.MkdirAll(filepath.Join(g.Dir, "objects"), 0700); err != nil {
		return err
	}
	p := filepath.Join(g.Dir, "objects", id)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if err := g.run(ctx, "add", "--", filepath.Join("objects", id)); err != nil {
		return err
	}
	if err := g.run(ctx, "commit", "-m", "snapshot "+id); err != nil {
		return err
	}
	if g.Remote != "" {
		return g.run(ctx, "push", "origin", "HEAD")
	}
	return nil
}
func (g Git) Download(ctx context.Context, id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(g.Dir, "objects", id))
}
func (g Git) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(g.Dir, "objects"))
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
func (g Git) Health(ctx context.Context) error { return g.run(ctx, "status", "--porcelain") }

// Ensure initializes only the local repository and verifies an existing
// origin. It never creates a GitHub repository and never accepts credentials
// embedded in a remote URL.
func (g Git) Ensure(ctx context.Context) error {
	if g.Dir == "" {
		return fmt.Errorf("provider directory is required")
	}
	if err := os.MkdirAll(g.Dir, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(g.Dir, ".git")); os.IsNotExist(err) {
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

func validateID(id string) error {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return fmt.Errorf("invalid provider object id")
	}
	return nil
}
