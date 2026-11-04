package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestEnableUserDaemonRefreshesAnActiveService(t *testing.T) {
	var calls [][]string
	runDaemonRefreshSystemctl = func(args ...string) error {
		calls = append(calls, append([]string{}, args...))
		if len(args) > 0 && args[0] == "is-active" {
			return nil
		}
		return nil
	}
	defer func() { runDaemonRefreshSystemctl = func(args ...string) error { return nil } }()

	if err := enableUserDaemon(); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"daemon-reload"}, {"is-active", "--quiet", "cifrarium.service"}, {"restart", "cifrarium.service"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("systemctl calls = %#v; want %#v", calls, want)
	}
}

func TestEnableUserDaemonEnablesAnInactiveService(t *testing.T) {
	var calls [][]string
	runDaemonRefreshSystemctl = func(args ...string) error {
		calls = append(calls, append([]string{}, args...))
		if len(args) > 0 && args[0] == "is-active" {
			return errors.New("inactive")
		}
		return nil
	}
	defer func() { runDaemonRefreshSystemctl = func(args ...string) error { return nil } }()

	if err := enableUserDaemon(); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"daemon-reload"}, {"is-active", "--quiet", "cifrarium.service"}, {"enable", "--now", "cifrarium.service"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("systemctl calls = %#v; want %#v", calls, want)
	}
}
