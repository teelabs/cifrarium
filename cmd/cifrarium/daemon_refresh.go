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

type daemonRefreshReadiness struct {
	Backend string
	MCP     string
}

var daemonRefreshBackendProbe = func(socket string) (daemonRefreshReadiness, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var status struct {
		Backend string `json:"backend"`
		MCP     struct {
			State string `json:"state"`
		} `json:"mcp"`
	}
	if err := rpc.Call(ctx, socket, "mcp.status", nil, &status); err != nil {
		return daemonRefreshReadiness{}, err
	}
	return daemonRefreshReadiness{Backend: safeReadinessState(status.Backend), MCP: safeReadinessState(status.MCP.State)}, nil
}

func daemonRefreshReady(backend, mcp string) bool {
	return backend == "ready" && mcp == "ready"
}

func safeReadinessState(state string) string {
	switch state {
	case "ready", "starting":
		return state
	default:
		return "unknown"
	}
}

func daemonRefreshMessage(readiness daemonRefreshReadiness) string {
	if daemonRefreshReady(readiness.Backend, readiness.MCP) {
		return "daemon refreshed; backend and MCP are ready"
	}
	return fmt.Sprintf("daemon refreshed; MCP is ready; backend is %s.\nNext: complete recovery/provider setup, then run `cifrarium daemon refresh` again.", safeReadinessState(readiness.Backend))
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
	if daemonRefreshProbe(filepath.Join(root, "cifrarium.sock")) != nil {
		return false
	}
	readiness, err := daemonRefreshBackendProbe(filepath.Join(root, "control.sock"))
	return err == nil && daemonRefreshReady(readiness.Backend, readiness.MCP)
}

func runDaemonRefresh(root string) (daemonRefreshReadiness, error) {
	if root == "" {
		return daemonRefreshReadiness{}, fmt.Errorf("configured vault root is required")
	}
	if err := runDaemonRefreshSystemctl("daemon-reload"); err != nil {
		return daemonRefreshReadiness{}, fmt.Errorf("could not reload the user service manager: %w", err)
	}
	if err := runDaemonRefreshSystemctl("restart", "cifrarium.service"); err != nil {
		return daemonRefreshReadiness{}, fmt.Errorf("could not restart cifrarium.service: %w", err)
	}
	socket := filepath.Join(root, "cifrarium.sock")
	controlSocket := filepath.Join(root, "control.sock")
	deadline := time.Now().Add(daemonRefreshTimeout)
	for time.Now().Before(deadline) {
		if err := daemonRefreshProbe(socket); err == nil {
			readiness, err := daemonRefreshBackendProbe(controlSocket)
			if err == nil && readiness.MCP == "ready" {
				return readiness, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return daemonRefreshReadiness{}, fmt.Errorf("daemon service did not become ready")
}
