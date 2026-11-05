package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

type daemonRefreshServiceState struct {
	ActiveState string
	SubState    string
	Result      string
	ExitStatus  string
	MainPID     string
}

var daemonRefreshSystemdStateProbe = func() (daemonRefreshServiceState, error) {
	output, err := exec.Command("systemctl", "--user", "show", "--property=ActiveState,SubState,Result,ExecMainStatus,MainPID", "cifrarium.service").Output()
	if err != nil {
		return daemonRefreshServiceState{}, err
	}
	return parseDaemonRefreshServiceState(string(output))
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

func parseDaemonRefreshServiceState(output string) (daemonRefreshServiceState, error) {
	properties := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (name != "ActiveState" && name != "SubState" && name != "Result" && name != "ExecMainStatus" && name != "MainPID") {
			return daemonRefreshServiceState{}, fmt.Errorf("unexpected systemd state output")
		}
		if _, exists := properties[name]; exists {
			return daemonRefreshServiceState{}, fmt.Errorf("unexpected systemd state output")
		}
		properties[name] = strings.TrimSpace(value)
	}
	for _, name := range []string{"ActiveState", "SubState", "Result", "ExecMainStatus", "MainPID"} {
		if _, ok := properties[name]; !ok {
			return daemonRefreshServiceState{}, fmt.Errorf("unexpected systemd state output")
		}
	}
	status := "unknown"
	if parsed, err := strconv.Atoi(properties["ExecMainStatus"]); err == nil && parsed >= 0 && parsed <= 255 {
		status = strconv.Itoa(parsed)
	}
	mainPID := "unknown"
	if parsed, err := strconv.ParseUint(properties["MainPID"], 10, 32); err == nil {
		mainPID = strconv.FormatUint(parsed, 10)
	}
	return daemonRefreshServiceState{
		ActiveState: safeSystemdValue(properties["ActiveState"], "active", "activating", "deactivating", "failed", "inactive", "reloading", "maintenance", "refreshing"),
		SubState:    safeSystemdValue(properties["SubState"], "running", "start", "start-pre", "start-post", "dead", "failed", "exited", "auto-restart", "stop", "stop-sigterm", "stop-post", "condition", "assert", "reload", "maintenance"),
		Result:      safeSystemdValue(properties["Result"], "success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "oom-kill", "protocol", "condition", "assert", "clean"),
		ExitStatus:  status,
		MainPID:     mainPID,
	}, nil
}

func safeSystemdValue(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

func daemonRefreshServiceExitedError(state daemonRefreshServiceState) error {
	active := safeSystemdValue(state.ActiveState, "active", "activating", "deactivating", "failed", "inactive", "reloading", "maintenance", "refreshing")
	sub := safeSystemdValue(state.SubState, "running", "start", "start-pre", "start-post", "dead", "failed", "exited", "auto-restart", "stop", "stop-sigterm", "stop-post", "condition", "assert", "reload", "maintenance")
	result := safeSystemdValue(state.Result, "success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "oom-kill", "protocol", "condition", "assert", "clean")
	exitStatus := "unknown"
	if status, err := strconv.Atoi(state.ExitStatus); err == nil && status >= 0 && status <= 255 {
		exitStatus = strconv.Itoa(status)
	}
	return fmt.Errorf("cifrarium.service exited before readiness (systemd state=%s/%s, result=%s, exit-status=%s). Check `systemctl --user status cifrarium.service`, resolve the reported startup issue, then run `cifrarium daemon refresh` again.", active, sub, result, exitStatus)
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
		if state, err := daemonRefreshSystemdStateProbe(); err == nil {
			if mainPID, parseErr := strconv.Atoi(state.MainPID); parseErr == nil && mainPID > 0 {
				return mainPID != os.Getpid()
			}
		}
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
	systemdStateUnconfirmed := false
	for time.Now().Before(deadline) {
		if err := runDaemonRefreshSystemctl("is-active", "--quiet", "cifrarium.service"); err != nil {
			state, stateErr := daemonRefreshSystemdStateProbe()
			if stateErr != nil {
				systemdStateUnconfirmed = true
			} else {
				switch state.ActiveState {
				case "failed", "inactive":
					return daemonRefreshReadiness{}, daemonRefreshServiceExitedError(state)
				case "active", "activating", "reloading":
					systemdStateUnconfirmed = false
				default:
					systemdStateUnconfirmed = true
				}
			}
		} else {
			systemdStateUnconfirmed = false
		}
		if err := daemonRefreshProbe(socket); err == nil {
			readiness, err := daemonRefreshBackendProbe(controlSocket)
			if err == nil && readiness.MCP == "ready" {
				return readiness, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if systemdStateUnconfirmed {
		return daemonRefreshReadiness{}, fmt.Errorf("daemon did not become ready and systemd could not confirm cifrarium.service state. Check `systemctl --user status cifrarium.service`, resolve any reported manager or startup issue, then run `cifrarium daemon refresh` again.")
	}
	return daemonRefreshReadiness{}, fmt.Errorf("daemon service is active but MCP did not become ready")
}
