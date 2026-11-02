package adapters

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	return collect(home, []string{".codex/config.toml"}, []string{".codex/auth.json", ".codex/logs", ".codex/history", ".codex/cache"})
}

type Zsh struct{}

func (Zsh) Name() string { return "oh-my-zsh" }
func (Zsh) Collect(home string) ([]File, error) {
	var paths = []string{".zshrc"}
	if exists(filepath.Join(home, ".zprofile")) {
		paths = append(paths, ".zprofile")
	}
	custom := filepath.Join(home, ".oh-my-zsh", "custom")
	entries, _ := os.ReadDir(custom)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			paths = append(paths, filepath.Join(".oh-my-zsh", "custom", e.Name()))
		}
	}
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
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		out = append(out, File{Relative: p, Data: data, Mode: info.Mode().Perm()})
	}
	return out, nil
}
func exists(p string) bool { _, err := os.Stat(p); return err == nil }
