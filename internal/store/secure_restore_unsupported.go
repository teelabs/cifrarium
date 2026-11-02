//go:build !linux

package store

import "fmt"

func restoreSecure([]Record, string, string) error {
	return fmt.Errorf("secure restore requires Linux descriptor-relative filesystem operations")
}
