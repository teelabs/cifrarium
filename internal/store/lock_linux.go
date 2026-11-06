//go:build linux

package store

import (
	"fmt"
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

// withVaultAuditLock shares an existing lock without creating one. When no
// lock exists, the caller performs its own head/guard consistency check and
// this helper rejects a lock that appears before the read completes.
func withVaultAuditLock(root string, fn func() error) error {
	rootFD, err := openVaultRootExisting(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)

	fd, err := openAuditLock(rootFD)
	if os.IsNotExist(err) {
		if err := fn(); err != nil {
			return err
		}
		appearedFD, appearedErr := openAuditLock(rootFD)
		if os.IsNotExist(appearedErr) {
			return nil
		}
		if appearedErr != nil {
			return appearedErr
		}
		_ = unix.Close(appearedFD)
		return fmt.Errorf("vault lock appeared during snapshot audit")
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), ".recovery.lock")
	if f == nil {
		_ = unix.Close(fd)
		return os.ErrInvalid
	}
	defer f.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("vault recovery lock is not a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_SH); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}

func openAuditLock(rootFD int) (int, error) {
	return unix.Openat(rootFD, ".recovery.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

// ValidateRoot opens the vault root with descriptor-relative no-symlink
// resolution. Callers use it immediately before opening vault state.
func ValidateRoot(root string) error {
	fd, err := openVaultRoot(root)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func openVaultRoot(root string) (int, error) {
	fd, err := openVaultRootExisting(root)
	if err == nil || !os.IsNotExist(err) {
		return fd, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return -1, err
	}
	return openVaultRootExisting(root)
}

func openVaultRootExisting(root string) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	return fd, err
}
