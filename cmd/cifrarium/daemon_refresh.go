package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/teelabs/cifrarium/internal/rpc"
)

const daemonRefreshTimeout = 10 * time.Second

var runDaemonRefreshSystemctl = func(args ...string) error {
	return exec.Command("systemctl", append([]string{"--user"}, args...)...).Run()
}

var daemonRefreshProbe = func(socket string) error { return probeMCP(socket) }

var daemonRefreshBackendProbe = func(socket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var result struct {
		Backend string `json:"backend"`
		MCP     struct {
			State string `json:"state"`
		} `json:"mcp"`
	}
	if err := rpc.Call(ctx, socket, "mcp.status", nil, &result); err != nil {
		return err
	}
	if !daemonRefreshReady(result.Backend, result.MCP.State) {
		return fmt.Errorf("backend=%s mcp=%s", result.Backend, result.MCP.State)
	}
	return nil
}

func daemonRefreshReady(backend, mcp string) bool {
	return mcp == "ready"
}

func daemonManagedServiceActive() bool {
	return runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service") == nil
}

func daemonAlreadyRunning(root string) bool {
	if daemonManagedServiceActive() {
		return true
	}
	if root == "" {
		return false
	}
	return daemonRefreshProbe(filepath.Join(root, "cifrarium.sock")) == nil &&
		daemonRefreshBackendProbe(filepath.Join(root, "control.sock")) == nil
}

func runDaemonRefresh(root string) error {
	if root == "" {
		return fmt.Errorf("configured vault root is required")
	}
	if err := runDaemonRefreshSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("could not reload the user service manager: %w", err)
	}
	if err := runDaemonRefreshSystemctl("restart", "cifrarium.service"); err != nil {
		return fmt.Errorf("could not restart cifrarium.service: %w", err)
	}
	socket := filepath.Join(root, "cifrarium.sock")
	controlSocket := filepath.Join(root, "control.sock")
	deadline := time.Now().Add(daemonRefreshTimeout)
	for time.Now().Before(deadline) {
		if err := daemonRefreshProbe(socket); err == nil {
			if err := daemonRefreshBackendProbe(controlSocket); err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("daemon service is active but MCP did not become ready")
}
