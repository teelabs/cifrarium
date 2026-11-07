//go:build !linux

package store

import "fmt"

func restoreSecure([]Record, string, string) error {
	return fmt.Errorf("secure restore requires Linux descriptor-relative filesystem operations")
}

func restoreSecureWithCommit([]Record, string, string, func() error) error {
	return fmt.Errorf("secure restore requires Linux descriptor-relative filesystem operations")
}

func restoreSecureWithExpected([]Record, []RestoreDestination, string, string, func() error) error {
	return fmt.Errorf("secure restore requires Linux descriptor-relative filesystem operations")
}
