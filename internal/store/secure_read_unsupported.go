//go:build !linux

package store

import (
	"fmt"
	"os"
)

func openReadNoSymlinks(string) (*os.File, error) {
	return nil, fmt.Errorf("secure vault reads require Linux descriptor-relative filesystem operations")
}
