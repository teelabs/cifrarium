package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunDaemonRefreshReloadsRestartsAndWaitsForMCP(t *testing.T) {
	var calls [][]string
	runDaemonRefreshSystemctl = func(args ...string) error {
		calls = append(calls, append([]string{}, args...))
		return nil
	}
	defer func() { runDaemonRefreshSystemctl = func(args ...string) error { return nil } }()
	var probes []string
	daemonRefreshProbe = func(socket string) error {
		probes = append(probes, socket)
		return nil
	}
	defer func() { daemonRefreshProbe = func(socket string) error { return probeMCP(socket) } }()
	var backendProbes []string
	daemonRefreshBackendProbe = func(socket string) (daemonRefreshReadiness, error) {
		backendProbes = append(backendProbes, socket)
		return daemonRefreshReadiness{Backend: "ready", MCP: "ready"}, nil
	}
	defer func() {
		daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
			return daemonRefreshReadiness{Backend: "ready", MCP: "ready"}, nil
		}
	}()

	root := filepath.Join(t.TempDir(), "vault")
	readiness, err := runDaemonRefresh(root)
	if err != nil {
		t.Fatal(err)
	}
	if !daemonRefreshReady(readiness.Backend, readiness.MCP) {
		t.Fatalf("readiness = %#v", readiness)
	}
	if want := [][]string{{"daemon-reload"}, {"restart", "cifrarium.service"}, {"is-active", "--quiet", "cifrarium.service"}}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("systemctl calls = %#v; want %#v", calls, want)
	}
	if want := []string{filepath.Join(root, "cifrarium.sock")}; !reflect.DeepEqual(probes, want) {
		t.Fatalf("probes = %#v; want %#v", probes, want)
	}
	if want := []string{filepath.Join(root, "control.sock")}; !reflect.DeepEqual(backendProbes, want) {
		t.Fatalf("backend probes = %#v; want %#v", backendProbes, want)
	}
}

func TestRunDaemonRefreshReportsRestartFailure(t *testing.T) {
	runDaemonRefreshSystemctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "restart" {
			return errors.New("service unavailable")
		}
		return nil
	}
	defer func() { runDaemonRefreshSystemctl = func(args ...string) error { return nil } }()

	_, err := runDaemonRefresh(t.TempDir())
	if err == nil || err.Error() != "could not restart cifrarium.service: service unavailable" {
		t.Fatalf("runDaemonRefresh() error = %v", err)
	}
}

func TestRunDaemonRefreshReportsMCPReadyWhileBackendIsStarting(t *testing.T) {
	runDaemonRefreshSystemctl = func(...string) error { return nil }
	defer func() { runDaemonRefreshSystemctl = func(...string) error { return nil } }()
	daemonRefreshProbe = func(string) error { return nil }
	defer func() { daemonRefreshProbe = func(socket string) error { return probeMCP(socket) } }()
	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{Backend: "starting", MCP: "ready"}, nil
	}
	defer func() {
		daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
			return daemonRefreshReadiness{}, fmt.Errorf("not configured")
		}
	}()

	readiness, err := runDaemonRefresh(t.TempDir())
	if err != nil {
		t.Fatalf("refresh failed despite ready MCP transport: %v", err)
	}
	if readiness.Backend != "starting" || readiness.MCP != "ready" {
		t.Fatalf("readiness = %#v", readiness)
	}
	if got, want := daemonRefreshMessage(readiness), "daemon refreshed; MCP is ready; backend is starting.\nNext: complete recovery/provider setup, then run `cifrarium daemon refresh` again."; got != want {
		t.Fatalf("refresh message = %q, want %q", got, want)
	}
}

func TestDaemonRefreshReadinessRequiresBothEndpointsReady(t *testing.T) {
	if daemonRefreshReady("starting", "ready") {
		t.Fatal("combined readiness reported ready while backend was waiting for recovery action")
	}
	if !daemonRefreshReady("ready", "ready") {
		t.Fatal("combined readiness rejected ready MCP and backend endpoints")
	}
	if daemonRefreshReady("ready", "starting") {
		t.Fatal("combined readiness accepted an MCP endpoint that was not ready")
	}
}

func TestDaemonRefreshServiceStateSanitizesSystemdOutput(t *testing.T) {
	state, err := parseDaemonRefreshServiceState("failed\n/home/secret\nprivate-remote\n17\n")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveState != "failed" || state.SubState != "unknown" || state.Result != "unknown" || state.ExitStatus != "17" {
		t.Fatalf("parsed service state = %#v", state)
	}
	message := daemonRefreshServiceExitedError(state).Error()
	if strings.Contains(message, "/home/secret") || strings.Contains(message, "private-remote") {
		t.Fatalf("service diagnostic leaked raw systemd output: %q", message)
	}
}

func TestDaemonAlreadyRunningUsesManagedEndpoints(t *testing.T) {
	runDaemonRefreshSystemctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "is-active" {
			return nil
		}
		return errors.New("unexpected systemctl call")
	}
	defer func() { runDaemonRefreshSystemctl = func(args ...string) error { return nil } }()

	if !daemonManagedServiceActive() {
		t.Fatal("daemonManagedServiceActive() = false; want active managed service")
	}
}
