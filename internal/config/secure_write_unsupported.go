//go:build !linux

package config

import "fmt"

func writeConfigNoSymlinks(string, []byte) error {
	return fmt.Errorf("secure root configuration writes require Linux descriptor-relative filesystem operations")
}
