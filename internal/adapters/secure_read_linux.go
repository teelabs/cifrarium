//go:build linux

package adapters

import (
	"fmt"
	"os"

	"github.com/teelabs/cifrarium/internal/limits"
	"golang.org/x/sys/unix"
)

func readNoFollow(path string) ([]byte, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("cannot open %s", path)
	}
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("capture target is not a regular file")
	}
	return limits.ReadAll(f, limits.MaxCapturedFileBytes)
}
