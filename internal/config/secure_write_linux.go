//go:build linux

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func writeConfigNoSymlinks(path string, raw []byte) error {
	dirPath := filepath.Dir(path)
	base := filepath.Base(path)
	dirFD, err := unix.Openat2(unix.AT_FDCWD, dirPath, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("open configuration directory without symlinks: %w", err)
	}
	defer unix.Close(dirFD)

	name, err := temporaryConfigName()
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("create root configuration without symlinks: %w", err)
	}
	tmp := os.NewFile(uintptr(fd), name)
	if tmp == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(dirFD, name, 0)
		return os.ErrInvalid
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
	}()

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := unix.Linkat(dirFD, name, dirFD, base, 0); err != nil {
		return err
	}
	removeTemp = false
	_ = unix.Unlinkat(dirFD, name, 0)
	return nil
}

func temporaryConfigName() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate temporary configuration name: %w", err)
	}
	return ".config.json-" + hex.EncodeToString(random[:]), nil
}
