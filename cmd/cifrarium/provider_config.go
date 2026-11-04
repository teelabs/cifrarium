package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type providerConfig struct {
	Dir    string
	Remote string
}

func providerConfigPath(home string) string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "cifrarium", "daemon.env")
}

// loadProviderConfig reads only the two non-secret provider settings. It never
// sources daemon.env and deliberately ignores recovery-share variables.
func loadProviderConfig(home string) (providerConfig, error) {
	file, err := os.Open(providerConfigPath(home))
	if os.IsNotExist(err) {
		return providerConfig{}, nil
	}
	if err != nil {
		return providerConfig{}, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil {
		return providerConfig{}, err
	} else if info.Mode().Perm()&0077 != 0 {
		return providerConfig{}, fmt.Errorf("%s must be private (mode 0600)", providerConfigPath(home))
	}

	var result providerConfig
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return providerConfig{}, fmt.Errorf("%s line %d is invalid; expected KEY=value", providerConfigPath(home), lineNumber)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		switch key {
		case "CIFRARIUM_PROVIDER_DIR":
			result.Dir = value
		case "CIFRARIUM_PROVIDER_REMOTE":
			result.Remote = value
		}
	}
	if err := scanner.Err(); err != nil {
		return providerConfig{}, err
	}
	return result, nil
}
