package adapters

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/teelabs/cifrarium/internal/limits"
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

// RestoreAdapterForPath returns the capture adapter that owns path. Snapshot
// signatures authenticate the bytes, but they do not grant authority to write
// arbitrary files under a user's home directory.
func RestoreAdapterForPath(path string) (string, bool) {
	if validateCapturePath(path) != nil {
		return "", false
	}
	switch path {
	case ".codex/AGENTS.md", ".codex/config.toml":
		return "codex", true
	case ".zshrc", ".zprofile":
		return "oh-my-zsh", true
	case ".config/starship.toml":
		return "starship", true
	}
	const customPrefix = ".oh-my-zsh/custom/"
	if !strings.HasPrefix(path, customPrefix) {
		return "", false
	}
	relative := strings.TrimPrefix(path, customPrefix)
	if relative == "" {
		return "", false
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || strings.HasPrefix(component, ".") {
			return "", false
		}
	}
	return "oh-my-zsh", true
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
	if len(paths) > limits.MaxCapturedFiles {
		return nil, fmt.Errorf("capture contains too many files")
	}
	for _, p := range paths {
		if err := validateCapturePath(p); err != nil {
			return nil, err
		}
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
			return nil, &os.PathError{Op: "capture", Path: p, Err: err}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, &os.PathError{Op: "capture", Path: p, Err: fmt.Errorf("symlink rejected")}
		}
		data, err := readStable(full)
		if err != nil {
			return nil, &os.PathError{Op: "capture", Path: p, Err: err}
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
		return nil, &os.PathError{Op: "capture", Path: ".oh-my-zsh/custom", Err: err}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "capture", Path: ".oh-my-zsh/custom", Err: fmt.Errorf("symlink rejected")}
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "capture", Path: ".oh-my-zsh/custom", Err: fmt.Errorf("custom path is not a directory")}
	}

	var paths []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil || rel == "." {
				return &os.PathError{Op: "capture", Path: ".oh-my-zsh/custom", Err: walkErr}
			}
			return &os.PathError{Op: "capture", Path: filepath.Join(".oh-my-zsh", "custom", rel), Err: walkErr}
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
			return &os.PathError{Op: "capture", Path: filepath.Join(".oh-my-zsh", "custom", rel), Err: fmt.Errorf("symlink rejected")}
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return &os.PathError{Op: "capture", Path: filepath.Join(".oh-my-zsh", "custom", rel), Err: fmt.Errorf("unsupported custom entry")}
		}
		if len(paths) >= limits.MaxCapturedFiles {
			return fmt.Errorf("capture contains too many files")
		}
		candidate := filepath.Join(".oh-my-zsh", "custom", rel)
		if err := validateCapturePath(candidate); err != nil {
			return err
		}
		paths = append(paths, candidate)
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

func validateCapturePath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("unsafe capture path %q", path)
	}
	if len(path) > limits.MaxPathBytes || len(strings.Split(path, string(filepath.Separator))) > limits.MaxPathDepth {
		return fmt.Errorf("capture path exceeds limits")
	}
	return nil
}
