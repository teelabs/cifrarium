package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/teelabs/cifrarium/internal/config"
)

var errRootNotConfigured = errors.New("Cifrarium is not configured on this computer.\n\nConfigure the vault location first:\n\ncifrarium setup")

func resolveVaultRoot(command, explicit, home string) (string, error) {
	path := config.ConfigPathForHome(home)
	cfg, err := config.LoadFrom(path)
	if errors.Is(err, os.ErrNotExist) {
		if command == "setup" {
			if explicit == "" {
				explicit = filepath.Join(home, ".local", "share", "cifrarium")
			}
			return config.CanonicalRoot(explicit)
		}
		return "", errRootNotConfigured
	}
	if err != nil {
		return "", fmt.Errorf("cannot load Cifrarium root configuration: %w", err)
	}
	if explicit == "" {
		return cfg.Root, nil
	}
	requested, err := config.CanonicalRoot(explicit)
	if err != nil {
		return "", err
	}
	if requested != cfg.Root {
		return "", fmt.Errorf("SECURITY CHECK FAILED\n\nThe requested vault:\n  %s\n\ndoes not match the configured vault:\n  %s\n\nCifrarium stopped to prevent using the wrong vault.\nDo not override this check.", requested, cfg.Root)
	}
	return cfg.Root, nil
}

func ensureConfiguredRoot(home, root string) (string, error) {
	cfg, err := config.SaveTo(config.ConfigPathForHome(home), root)
	if err != nil {
		return "", err
	}
	return cfg.Root, nil
}
