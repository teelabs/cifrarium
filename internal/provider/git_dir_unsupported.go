//go:build !linux

package provider

import (
	"context"
	"os"
	"os/exec"
)

func openGitDir(path string) (*os.File, error) { return os.Open(path) }

func anchoredGitCommand(ctx context.Context, executable string, args []string, env []string, path string, _ *os.File) *exec.Cmd {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = env
	cmd.Dir = path
	return cmd
}
