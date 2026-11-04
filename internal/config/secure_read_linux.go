//go:build linux

package config

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readConfigNoSymlinks(path string) ([]byte, os.FileInfo, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if err == unix.ENOENT {
			return nil, nil, os.ErrNotExist
		}
		return nil, nil, fmt.Errorf("open root configuration without symlinks: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, nil, os.ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}
