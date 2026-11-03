//go:build linux

package store

import (
	"os"

	"golang.org/x/sys/unix"
)

func withVaultLock(root string, fn func() error) error {
	rootFD, err := openVaultRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat(rootFD, ".recovery.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), ".recovery.lock")
	if f == nil {
		_ = unix.Close(fd)
		return os.ErrInvalid
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}

func openVaultRoot(root string) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err == nil {
		return fd, nil
	}
	if !os.IsNotExist(err) {
		return -1, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return -1, err
	}
	return unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}
