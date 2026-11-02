package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		return g.run(ctx, "push", g.Remote, "HEAD")
	}
	return nil
}
func (g Git) Download(ctx context.Context, id string) ([]byte, error) {
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
