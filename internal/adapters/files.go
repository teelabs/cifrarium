package adapters

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type File struct {
	Relative string
	Data     []byte
	Mode     os.FileMode
}
type Adapter interface {
	Name() string
	Collect(home string) ([]File, error)
}

type Config struct{}

func (Config) Name() string { return "codex" }
func (Config) Collect(home string) ([]File, error) {
	return collect(home, []string{".codex/AGENTS.md", ".codex/config.toml"}, []string{".codex/auth.json", ".codex/logs", ".codex/history", ".codex/cache"})
}

type Zsh struct{}

func (Zsh) Name() string { return "oh-my-zsh" }
func (Zsh) Collect(home string) ([]File, error) {
	var paths = []string{".zshrc"}
	if exists(filepath.Join(home, ".zprofile")) {
		paths = append(paths, ".zprofile")
	}
	custom := filepath.Join(home, ".oh-my-zsh", "custom")
	customPaths, err := collectCustomPaths(custom)
	if err != nil {
		return nil, err
	}
	paths = append(paths, customPaths...)
	return collect(home, paths, []string{".oh-my-zsh/oh-my-zsh.sh", ".oh-my-zsh/plugins", ".oh-my-zsh/cache"})
}

type Starship struct{}

func (Starship) Name() string { return "starship" }
func (Starship) Collect(home string) ([]File, error) {
	return collect(home, []string{".config/starship.toml"}, nil)
}
func collect(home string, paths, excluded []string) ([]File, error) {
	for _, p := range paths {
		for _, x := range excluded {
			if p == x || strings.HasPrefix(p, x+"/") {
				return nil, fmt.Errorf("allowlist includes excluded path %s", p)
			}
		}
	}
	sort.Strings(paths)
	out := []File{}
	for _, p := range paths {
		full := filepath.Join(home, p)
		info, err := os.Lstat(full)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink rejected: %s", p)
		}
		data, err := readStable(full)
		if err != nil {
			return nil, err
		}
		out = append(out, File{Relative: p, Data: data, Mode: info.Mode().Perm()})
	}
	return out, nil
}
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func collectCustomPaths(root string) ([]string, error) {
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink rejected: %s", root)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("custom path is not a directory: %s", root)
	}

	var paths []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, component := range strings.Split(rel, string(filepath.Separator)) {
			if strings.HasPrefix(component, ".") {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink rejected: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported custom entry: %s", path)
		}
		paths = append(paths, filepath.Join(".oh-my-zsh", "custom", rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

const stableReadAttempts = 3

func readStable(path string) ([]byte, error) {
	return readStableWith(func() ([]byte, error) {
		return readNoFollow(path)
	})
}

func readStableWith(read func() ([]byte, error)) ([]byte, error) {
	for attempt := 0; attempt < stableReadAttempts; attempt++ {
		first, err := read()
		if err != nil {
			return nil, err
		}
		second, err := read()
		if err != nil {
			return nil, err
		}
		if bytes.Equal(first, second) {
			return first, nil
		}
	}
	return nil, fmt.Errorf("file changed while reading")
}

func readNoFollow(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("cannot open %s", path)
	}
	defer f.Close()
	return io.ReadAll(f)
}
