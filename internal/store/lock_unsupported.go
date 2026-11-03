//go:build !linux

package store

import "fmt"

func withVaultLock(string, func() error) error {
	return fmt.Errorf("vault locking requires Linux")
}
