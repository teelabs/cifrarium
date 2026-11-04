//go:build linux

package store

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openReadNoSymlinks(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if err == unix.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("open without symlinks: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, os.ErrInvalid
	}
	return f, nil
}
