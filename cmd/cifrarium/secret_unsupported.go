//go:build !linux

package main

import (
	"fmt"
	"os"
)

func isTerminalFile(*os.File) bool { return false }

func readRecoveryShare(*os.File, int) (string, error) {
	return "", fmt.Errorf("secure recovery input requires a supported terminal")
}
