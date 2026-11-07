//go:build !linux

package store

import "fmt"

func inspectRestoreDestinations(string, []Record) ([]RestoreDestination, error) {
	return nil, fmt.Errorf("secure restore preflight requires Linux descriptor-relative filesystem operations")
}
