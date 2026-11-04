package main

import (
	"errors"
	"path/filepath"
	"reflect"
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
	daemonRefreshBackendProbe = func(socket string) error {
		backendProbes = append(backendProbes, socket)
		return nil
	}
	defer func() { daemonRefreshBackendProbe = func(socket string) error { return nil } }()

	root := filepath.Join(t.TempDir(), "vault")
	if err := runDaemonRefresh(root); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"daemon-reload"}, {"restart", "cifrarium.service"}}; !reflect.DeepEqual(calls, want) {
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

	err := runDaemonRefresh(t.TempDir())
	if err == nil || err.Error() != "could not restart cifrarium.service: service unavailable" {
		t.Fatalf("runDaemonRefresh() error = %v", err)
	}
}

func TestDaemonRefreshAcceptsMCPWhileBackendIsWaiting(t *testing.T) {
	if !daemonRefreshReady("starting", "ready") {
		t.Fatal("daemon refresh rejected a ready MCP endpoint while backend was waiting for recovery action")
	}
	if daemonRefreshReady("starting", "starting") {
		t.Fatal("daemon refresh accepted an MCP endpoint that was not ready")
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
