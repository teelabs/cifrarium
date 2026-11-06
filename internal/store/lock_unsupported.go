//go:build !linux

package store

import "fmt"

func ValidateRoot(string) error {
	return fmt.Errorf("secure vault root validation requires Linux descriptor-relative filesystem operations")
}

func withVaultLock(string, func() error) error {
	return fmt.Errorf("vault locking requires Linux")
}

func withVaultAuditLock(string, func() error) error {
	return fmt.Errorf("read-only vault locking requires Linux")
}
