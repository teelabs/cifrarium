//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func isTerminalFile(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

func readRecoveryShare(tty *os.File, number int) (string, error) {
	fd := int(tty.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("recovery shares require a terminal")
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); err != nil {
		return "", fmt.Errorf("cannot disable terminal echo for recovery input")
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, original) }()
	if _, err := fmt.Fprintf(tty, "Recovery share %d (hidden): ", number); err != nil {
		return "", err
	}
	value := make([]byte, 0, 512)
	for len(value) < 4096 {
		var one [1]byte
		n, err := unix.Read(fd, one[:])
		if err != nil || n != 1 {
			clear(value)
			return "", fmt.Errorf("recovery input interrupted")
		}
		switch one[0] {
		case '\n', '\r':
			_ = unix.IoctlSetTermios(fd, unix.TCSETS, original)
			_, _ = fmt.Fprintln(tty)
			return string(value), nil
		case 3:
			clear(value)
			return "", fmt.Errorf("recovery input interrupted")
		case 8, 127:
			if len(value) > 0 {
				value = value[:len(value)-1]
			}
		default:
			value = append(value, one[0])
		}
	}
	clear(value)
	return "", fmt.Errorf("recovery share input is too long")
}
