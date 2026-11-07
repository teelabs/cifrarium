//go:build linux

package provider

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
	"golang.org/x/sys/unix"
)

const providerResolveFlags = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

func writeProviderFile(root, relative string, data []byte) error {
	return writeProviderFileLimited(root, relative, data, limits.MaxQueueItemBytes)
}

func writeProviderFileLimited(root, relative string, data []byte, max int64) error {
	if err := validateProviderRelative(relative); err != nil {
		return err
	}
	if err := limits.CheckBytes(len(data), max); err != nil {
		return err
	}
	rootFD, err := openProviderRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	parentPath, base := filepath.Split(relative)
	parentFD, err := openProviderRelativeDir(rootFD, strings.TrimSuffix(parentPath, string(filepath.Separator)), true)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	for attempt := 0; attempt < 32; attempt++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		temporary := ".cifrarium-write-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return err
		}
		ok := false
		defer func() {
			if !ok {
				_ = unix.Unlinkat(parentFD, temporary, 0)
			}
		}()
		for len(data) > 0 {
			n, writeErr := unix.Write(fd, data)
			if writeErr != nil {
				_ = unix.Close(fd)
				return writeErr
			}
			data = data[n:]
		}
		if err := unix.Fsync(fd); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
		if err := unix.Renameat2(parentFD, temporary, parentFD, base, 0); err != nil {
			return err
		}
		ok = true
		return nil
	}
	return fmt.Errorf("could not allocate secure provider temporary file")
}

func readProviderFile(root, relative string) ([]byte, error) {
	return readProviderFileLimited(root, relative, limits.MaxQueueItemBytes)
}

func readProviderFileLimited(root, relative string, max int64) ([]byte, error) {
	if err := validateProviderRelative(relative); err != nil {
		return nil, err
	}
	rootFD, err := openProviderRoot(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	parentPath, base := filepath.Split(relative)
	parentFD, err := openProviderRelativeDir(rootFD, strings.TrimSuffix(parentPath, string(filepath.Separator)), false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "cifrarium-provider-read")
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("could not open provider file")
	}
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("provider object is not a regular file")
	}
	return limits.ReadAll(f, max)
}

func listProviderFiles(root, relative string) ([]string, error) {
	if err := validateProviderRelative(relative); err != nil {
		return nil, err
	}
	rootFD, err := openProviderRoot(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	dirFD, err := openProviderReadableRelativeDir(rootFD, relative)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(dirFD), "cifrarium-provider-list")
	if directory == nil {
		_ = unix.Close(dirFD)
		return nil, fmt.Errorf("could not open provider directory")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(limits.MaxCapturedFiles + 1)
	if err != nil {
		return nil, err
	}
	if len(entries) > limits.MaxCapturedFiles {
		return nil, fmt.Errorf("provider directory exceeds file limit")
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if err := validateProviderRelative(filepath.Join(relative, name)); err != nil {
			return nil, err
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf("provider object is not a regular file: %s", name)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func openProviderRoot(root string) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: providerResolveFlags,
	})
}

func openProviderRelativeDir(rootFD int, relative string, create bool) (int, error) {
	if relative == "" || relative == "." {
		return unix.Dup(rootFD)
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(current)
			return -1, fmt.Errorf("unsafe provider directory")
		}
		if create {
			if err := unix.Mkdirat(current, component, 0700); err != nil && err != unix.EEXIST {
				_ = unix.Close(current)
				return -1, err
			}
		}
		next, err := unix.Openat2(current, component, &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
			Resolve: providerResolveFlags,
		})
		_ = unix.Close(current)
		if err != nil {
			return -1, err
		}
		current = next
	}
	return current, nil
}

// openProviderReadableRelativeDir keeps the path traversal anchored through
// the existing O_PATH descriptors, then reopens the final directory itself
// for reading so callers can enumerate it with ReadDir.
func openProviderReadableRelativeDir(rootFD int, relative string) (int, error) {
	pathFD, err := openProviderRelativeDir(rootFD, relative, false)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pathFD)
	return unix.Openat2(pathFD, ".", &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: providerResolveFlags,
	})
}

func validateProviderRelative(relative string) error {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe provider path")
	}
	if len(relative) > limits.MaxPathBytes || len(strings.Split(relative, string(filepath.Separator))) > limits.MaxPathDepth {
		return fmt.Errorf("provider path exceeds limits")
	}
	return nil
}
