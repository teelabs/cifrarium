//go:build linux

package provider

import (
	"context"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func openGitDir(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func anchoredGitCommand(ctx context.Context, executable string, args []string, env []string, _ string, dir *os.File) *exec.Cmd {
	const script = "cd -- /proc/self/fd/3 || exit 126; exec \"$@\""
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "cifrarium-git", executable)
	cmd.Args = append(cmd.Args, args...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{dir}
	return cmd
}
