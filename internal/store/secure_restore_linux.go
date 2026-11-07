//go:build linux

package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const restoreResolveFlags = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

type restoreMove struct {
	fromFD int
	from   string
	toFD   int
	to     string
}

type restoreActivation struct {
	stageFD  int
	stage    string
	targetFD int
	target   string
}

// restoreSecure keeps directory descriptors open for the complete activation
// transaction. Every rename is relative to an already-open directory;
// replacing a path component after validation cannot redirect the operation.
func restoreSecure(records []Record, target, backupRoot string) error {
	return restoreSecureWithCommit(records, target, backupRoot, nil)
}

func restoreSecureWithCommit(records []Record, target, backupRoot string, commit func() error) error {
	return restoreSecureWithExpected(records, nil, target, backupRoot, commit)
}

func restoreSecureWithExpected(records []Record, expected []RestoreDestination, target, backupRoot string, commit func() error) error {
	if len(records) == 0 {
		current, err := inspectRestoreDestinations(target, expectedRecords(expected))
		if err != nil {
			return err
		}
		for i, state := range expected {
			got := current[i]
			if got.Exists != state.Exists || (state.Exists && (!bytes.Equal(got.Data, state.Data) || got.Mode.Perm() != state.Mode.Perm())) {
				return fmt.Errorf("restore destination changed after preflight: %s", state.Path)
			}
		}
		if commit != nil {
			return commit()
		}
		return nil
	}
	if err := validateRestoreRoots(target, backupRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(backupRoot, 0700); err != nil {
		return err
	}

	targetFD, err := openRestoreRoot(target)
	if err != nil {
		return fmt.Errorf("open restore target: %w", err)
	}
	defer unix.Close(targetFD)
	backupRootFD, err := openRestoreRoot(backupRoot)
	if err != nil {
		return fmt.Errorf("open restore backup root: %w", err)
	}
	defer unix.Close(backupRootFD)
	expectedByPath := make(map[string]RestoreDestination, len(expected))
	for _, state := range expected {
		if err := validateRestoreRecordPath(state.Path); err != nil {
			return err
		}
		if _, exists := expectedByPath[state.Path]; exists {
			return fmt.Errorf("duplicate expected restore path")
		}
		expectedByPath[state.Path] = state
	}

	stageName, stageFD, err := createRestoreDirectory(targetFD, ".cifrarium-restore-")
	if err != nil {
		return err
	}
	defer unix.Close(stageFD)
	defer func() { _ = removeRestoreTree(targetFD, stageName) }()

	openFDs := []int{targetFD, backupRootFD, stageFD}
	defer func() {
		for _, fd := range openFDs[3:] {
			_ = unix.Close(fd)
		}
	}()

	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := validateRestoreRecordPath(record.Path); err != nil {
			return err
		}
		if _, ok := seen[record.Path]; ok {
			return fmt.Errorf("duplicate restore path %q", record.Path)
		}
		seen[record.Path] = struct{}{}
		parent, base := restoreParentAndBase(record.Path)
		stageParent, err := openRestoreRelativeDir(stageFD, parent, true)
		if err != nil {
			return fmt.Errorf("open staged parent for %q: %w", record.Path, err)
		}
		openFDs = append(openFDs, stageParent)
		if err := writeRestoreFile(stageParent, base, record.Data, os.FileMode(record.Mode)&0777); err != nil {
			return fmt.Errorf("stage %q: %w", record.Path, err)
		}
	}

	backupName, backupFD, err := createRestoreDirectory(backupRootFD, "restore-")
	if err != nil {
		return err
	}
	openFDs = append(openFDs, backupFD)
	backupCommitted := false
	rollbackFailed := false
	defer func() {
		if !backupCommitted && !rollbackFailed {
			_ = removeRestoreTree(backupRootFD, backupName)
		}
	}()

	var moved []restoreMove
	var activated []restoreActivation
	rollback := func() error {
		var rollbackErr error
		for i := len(activated) - 1; i >= 0; i-- {
			move := activated[i]
			if err := unix.Renameat2(move.targetFD, move.target, move.stageFD, move.stage, unix.RENAME_NOREPLACE); err != nil && rollbackErr == nil {
				rollbackErr = fmt.Errorf("restore activated file %s: %w", move.target, err)
			}
		}
		for i := len(moved) - 1; i >= 0; i-- {
			move := moved[i]
			if err := unix.Renameat2(move.toFD, move.to, move.fromFD, move.from, unix.RENAME_NOREPLACE); err != nil && rollbackErr == nil {
				rollbackErr = fmt.Errorf("restore backup %s: %w", move.to, err)
			}
		}
		if rollbackErr != nil {
			rollbackFailed = true
		}
		return rollbackErr
	}

	for _, record := range records {
		parent, base := restoreParentAndBase(record.Path)
		targetParent, err := openRestoreRelativeDir(targetFD, parent, true)
		if err != nil {
			return restoreFailure(err, rollback)
		}
		openFDs = append(openFDs, targetParent)
		stageParent, err := openRestoreRelativeDir(stageFD, parent, false)
		if err != nil {
			return restoreFailure(err, rollback)
		}
		openFDs = append(openFDs, stageParent)

		existing, err := openRestoreExisting(targetParent, base)
		if err != nil {
			return restoreFailure(err, rollback)
		}
		if existing {
			backupParent, err := openRestoreRelativeDir(backupFD, parent, true)
			if err != nil {
				return restoreFailure(err, rollback)
			}
			openFDs = append(openFDs, backupParent)
			if err := unix.Renameat2(targetParent, base, backupParent, base, unix.RENAME_NOREPLACE); err != nil {
				return restoreFailure(err, rollback)
			}
			moved = append(moved, restoreMove{fromFD: targetParent, from: base, toFD: backupParent, to: base})
			if state, ok := expectedByPath[record.Path]; ok {
				backupState, err := inspectRestoreFile(backupParent, base, record.Path)
				if err != nil || !state.Exists || !backupState.Exists || !bytes.Equal(state.Data, backupState.Data) || state.Mode.Perm() != backupState.Mode.Perm() {
					if err == nil {
						err = fmt.Errorf("restore destination changed after preflight: %s", record.Path)
					}
					return restoreFailure(err, rollback)
				}
			}
		} else if state, ok := expectedByPath[record.Path]; ok && state.Exists {
			return restoreFailure(fmt.Errorf("restore destination changed after preflight: %s", record.Path), rollback)
		}
		if err := unix.Renameat2(stageParent, base, targetParent, base, unix.RENAME_NOREPLACE); err != nil {
			return restoreFailure(err, rollback)
		}
		activated = append(activated, restoreActivation{stageFD: stageParent, stage: base, targetFD: targetParent, target: base})
	}
	// Recheck selected files that are kept or identical and therefore were not
	// renamed. Applied files were compared after moving into the private backup.
	for path, state := range expectedByPath {
		if _, applied := seen[path]; applied {
			continue
		}
		parent, base := restoreParentAndBase(path)
		parentFD, err := openRestoreRelativeDir(targetFD, parent, false)
		if err == unix.ENOENT {
			if state.Exists {
				return restoreFailure(fmt.Errorf("restore destination changed after preflight: %s", path), rollback)
			}
			continue
		}
		if err != nil {
			return restoreFailure(fmt.Errorf("unsafe restore destination %q", path), rollback)
		}
		current, err := inspectRestoreFile(parentFD, base, path)
		_ = unix.Close(parentFD)
		if err != nil || current.Exists != state.Exists || (state.Exists && (!bytes.Equal(current.Data, state.Data) || current.Mode.Perm() != state.Mode.Perm())) {
			if err == nil {
				err = fmt.Errorf("restore destination changed after preflight: %s", path)
			}
			return restoreFailure(err, rollback)
		}
	}
	if commit != nil {
		if err := commit(); err != nil {
			return restoreFailure(err, rollback)
		}
	}
	backupCommitted = true
	return nil
}

func expectedRecords(states []RestoreDestination) []Record {
	records := make([]Record, len(states))
	for i, state := range states {
		records[i] = Record{Path: state.Path}
	}
	return records
}

func restoreFailure(cause error, rollback func() error) error {
	if rollbackErr := rollback(); rollbackErr != nil {
		return fmt.Errorf("%w; rollback failed: %v", cause, rollbackErr)
	}
	return cause
}

func validateRestoreRoots(target, backupRoot string) error {
	if filepath.Clean(target) == "." || filepath.Clean(target) == "/" {
		return fmt.Errorf("unsafe restore target")
	}
	if filepath.Clean(backupRoot) == "." || filepath.Clean(backupRoot) == "/" {
		return fmt.Errorf("unsafe restore backup root")
	}
	if err := rejectSymlinkPath(target); err != nil {
		return err
	}
	return rejectSymlinkPath(backupRoot)
}

func restoreParentAndBase(path string) (string, string) {
	parent, base := filepath.Split(path)
	return strings.TrimSuffix(parent, string(filepath.Separator)), base
}

func openRestoreRoot(path string) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: restoreResolveFlags,
	})
}

func createRestoreDirectory(parentFD int, prefix string) (string, int, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, err
		}
		name := prefix + hex.EncodeToString(random[:])
		if err := unix.Mkdirat(parentFD, name, 0700); err != nil {
			if err == unix.EEXIST {
				continue
			}
			return "", -1, err
		}
		fd, err := openRestoreRelativeDir(parentFD, name, false)
		if err != nil {
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			return "", -1, err
		}
		return name, fd, nil
	}
	return "", -1, fmt.Errorf("could not allocate secure temporary directory")
}

func removeRestoreTree(parentFD int, name string) error {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: restoreResolveFlags,
	})
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "cifrarium-restore-cleanup")
	if directory == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("could not open restore cleanup directory")
	}
	entries, readErr := directory.Readdirnames(-1)
	if readErr != nil {
		_ = directory.Close()
		return readErr
	}
	for _, entry := range entries {
		childFD, childErr := unix.Openat2(fd, entry, &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: restoreResolveFlags,
		})
		if childErr != nil {
			continue
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(childFD, &stat)
		_ = unix.Close(childFD)
		if statErr != nil {
			continue
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			_ = removeRestoreTree(fd, entry)
			continue
		}
		_ = unix.Unlinkat(fd, entry, 0)
	}
	if err := directory.Close(); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func openRestoreRelativeDir(rootFD int, path string, create bool) (int, error) {
	if path == "" || path == "." {
		return unix.Dup(rootFD)
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(current)
			return -1, fmt.Errorf("unsafe relative directory %q", path)
		}
		if create {
			if err := unix.Mkdirat(current, component, 0700); err != nil && err != unix.EEXIST {
				_ = unix.Close(current)
				return -1, err
			}
		}
		next, err := unix.Openat2(current, component, &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
			Resolve: restoreResolveFlags,
		})
		_ = unix.Close(current)
		if err != nil {
			return -1, err
		}
		current = next
	}
	return current, nil
}

func openRestoreExisting(parentFD int, name string) (bool, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, fmt.Errorf("restore target is not a regular file: %s", name)
	}
	return true, nil
}

func writeRestoreFile(parentFD int, name string, data []byte, mode os.FileMode) error {
	fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return unix.Fsync(fd)
}
