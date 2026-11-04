//go:build !linux

package config

import (
	"fmt"
	"os"
)

func readConfigNoSymlinks(string) ([]byte, os.FileInfo, error) {
	return nil, nil, fmt.Errorf("secure root configuration reads require Linux descriptor-relative filesystem operations")
}
