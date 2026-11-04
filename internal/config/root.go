package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const schemaVersion = 1

type RootConfig struct {
	Schema int    `json:"schema"`
	Root   string `json:"root"`
}

func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return ConfigPathForHome(home), nil
}

func ConfigPathForHome(home string) string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "cifrarium", "config.json")
}

func CanonicalRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("vault root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("make vault root absolute: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if err := rejectSymlinkComponents(absolute); err != nil {
		return "", err
	}
	parent := filepath.Dir(absolute)
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("canonicalize vault root parent: %w", err)
	}
	if err == nil {
		absolute = filepath.Join(canonicalParent, filepath.Base(absolute))
	}
	return filepath.Clean(absolute), nil
}

func rejectSymlinkComponents(path string) error {
	volume := filepath.VolumeName(path)
	rest := filepath.Clean(path[len(volume):])
	current := volume + string(filepath.Separator)
	if filepath.IsAbs(rest) {
		rest = rest[1:]
	}
	for _, component := range splitPath(rest) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return fmt.Errorf("inspect vault root component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("vault root contains symlinked component: %s", current)
		}
	}
	return nil
}

func splitPath(path string) []string {
	parts := make([]string, 0)
	for path != "" {
		part := filepath.Base(path)
		parts = append([]string{part}, parts...)
		next := filepath.Dir(path)
		if next == path {
			break
		}
		path = next
	}
	return parts
}

func Load() (RootConfig, error) {
	path, err := ConfigPath()
	if err != nil {
		return RootConfig{}, err
	}
	return LoadFrom(path)
}

func LoadFrom(path string) (RootConfig, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return RootConfig{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return RootConfig{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return RootConfig{}, errors.New("root configuration symlink is not allowed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return RootConfig{}, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return RootConfig{}, fmt.Errorf("root configuration has unsafe permissions: %04o", info.Mode().Perm())
	}
	var cfg RootConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return RootConfig{}, fmt.Errorf("invalid root configuration: %w", err)
	}
	if cfg.Schema != schemaVersion || cfg.Root == "" {
		return RootConfig{}, errors.New("invalid root configuration schema")
	}
	canonical, err := CanonicalRoot(cfg.Root)
	if err != nil {
		return RootConfig{}, err
	}
	if canonical != cfg.Root {
		return RootConfig{}, errors.New("root configuration is not canonical")
	}
	cfg.Root = canonical
	return cfg, nil
}

func Save(root string) (RootConfig, error) {
	path, err := ConfigPath()
	if err != nil {
		return RootConfig{}, err
	}
	return SaveTo(path, root)
}

func SaveTo(path, root string) (RootConfig, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return RootConfig{}, err
	}
	canonical, err := CanonicalRoot(root)
	if err != nil {
		return RootConfig{}, err
	}
	if existing, err := LoadFrom(path); err == nil {
		if existing.Root != canonical {
			return RootConfig{}, fmt.Errorf("configured vault root is %q; refusing to replace it with %q", existing.Root, canonical)
		}
		return existing, nil
	} else if !os.IsNotExist(err) {
		return RootConfig{}, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return RootConfig{}, fmt.Errorf("create configuration directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return RootConfig{}, fmt.Errorf("secure configuration directory: %w", err)
	}
	cfg := RootConfig{Schema: schemaVersion, Root: canonical}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return RootConfig{}, err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".config.json-*")
	if err != nil {
		return RootConfig{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return RootConfig{}, err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return RootConfig{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return RootConfig{}, err
	}
	if err := tmp.Close(); err != nil {
		return RootConfig{}, err
	}
	if err := os.Link(tmpName, path); err != nil {
		return RootConfig{}, err
	}
	return cfg, nil
}
