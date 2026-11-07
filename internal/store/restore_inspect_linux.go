//go:build linux

package store

import (
	"fmt"
	"os"

	"github.com/teelabs/cifrarium/internal/limits"
	"golang.org/x/sys/unix"
)

func inspectRestoreDestinations(target string, records []Record) ([]RestoreDestination, error) {
	if err := rejectSymlinkPath(target); err != nil {
		return nil, err
	}
	rootFD, err := openRestoreRoot(target)
	if err != nil {
		return nil, fmt.Errorf("open restore target: %w", err)
	}
	defer unix.Close(rootFD)
	out := make([]RestoreDestination, 0, len(records))
	for _, record := range records {
		parent, base := restoreParentAndBase(record.Path)
		parentFD, err := openRestoreRelativeDir(rootFD, parent, false)
		if err == unix.ENOENT {
			out = append(out, RestoreDestination{Path: record.Path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("unsafe restore destination %q", record.Path)
		}
		state, err := inspectRestoreFile(parentFD, base, record.Path)
		_ = unix.Close(parentFD)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, nil
}

func inspectRestoreFile(parentFD int, base, path string) (RestoreDestination, error) {
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return RestoreDestination{Path: path}, nil
	}
	if err != nil {
		return RestoreDestination{}, fmt.Errorf("unsafe restore destination %q", path)
	}
	file := os.NewFile(uintptr(fd), "cifrarium-restore-preflight")
	if file == nil {
		_ = unix.Close(fd)
		return RestoreDestination{}, fmt.Errorf("could not inspect restore destination")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return RestoreDestination{}, fmt.Errorf("restore destination %q is not a regular file", path)
	}
	if info.Size() < 0 || info.Size() > limits.MaxCapturedFileBytes {
		return RestoreDestination{}, fmt.Errorf("restore destination %q exceeds the supported size", path)
	}
	data, err := limits.ReadAll(file, limits.MaxCapturedFileBytes)
	if err != nil {
		return RestoreDestination{}, fmt.Errorf("cannot inspect restore destination %q", path)
	}
	return RestoreDestination{Path: path, Exists: true, Data: data, Mode: info.Mode().Perm()}, nil
}
