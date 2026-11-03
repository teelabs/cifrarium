//go:build !linux

package adapters

import "fmt"

func readNoFollow(string) ([]byte, error) {
	return nil, fmt.Errorf("secure adapter capture requires Linux")
}
