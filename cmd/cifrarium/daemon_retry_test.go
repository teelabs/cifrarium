package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/daemon"
)

func TestDaemonRetryControllerDefaultsToRetryAndWaitsForEnter(t *testing.T) {
	var out bytes.Buffer
	waited := false
	controller := &daemonRetryController{
		interactive: true,
		reader:      bufio.NewReader(strings.NewReader("\n")),
		output:      &out,
		timeout:     time.Second,
		wait: func(context.Context, *daemonRetryController) error {
			waited = true
			return nil
		},
	}

	if got := controller.Handle(context.Background(), errors.New("recovery verification required before upload")); got != daemon.RetryNow {
		t.Fatalf("retry decision=%v, want RetryNow", got)
	}
	text := strings.ToLower(out.String())
	if !waited || !strings.Contains(text, "another console") || !strings.Contains(text, "press enter") {
		t.Fatalf("retry guidance=%q, want waiting guidance", out.String())
	}
}

func TestDaemonRetryControllerDeclineStopsWithoutWaiting(t *testing.T) {
	var out bytes.Buffer
	waited := false
	controller := &daemonRetryController{
		interactive: true,
		reader:      bufio.NewReader(strings.NewReader("n\n")),
		output:      &out,
		timeout:     time.Second,
		wait: func(context.Context, *daemonRetryController) error {
			waited = true
			return nil
		},
	}

	if got := controller.Handle(context.Background(), errors.New("provider offline")); got != daemon.StopRetry {
		t.Fatalf("retry decision=%v, want StopRetry", got)
	}
	if waited {
		t.Fatal("declined retry entered countdown")
	}
}

func TestDaemonRetryControllerNeverPrintsRawRecoveryError(t *testing.T) {
	var out bytes.Buffer
	controller := &daemonRetryController{
		interactive: false,
		output:      &out,
		timeout:     time.Second,
		wait:        func(context.Context, *daemonRetryController) error { return nil },
	}

	controller.Handle(context.Background(), errors.New("recovery verification required before upload"))
	text := strings.ToLower(out.String())
	for _, forbidden := range []string{"recovery verification required before upload", "share", "token"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("retry output leaked %q: %q", forbidden, out.String())
		}
	}
}

func TestWaitForDaemonRetryAcceptsEnterBeforeTimeout(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	var out bytes.Buffer
	controller := &daemonRetryController{
		interactive: true,
		tty:         reader,
		reader:      bufio.NewReader(reader),
		output:      &out,
		timeout:     time.Second,
	}
	go func() { _, _ = writer.WriteString("\n") }()

	if err := waitForDaemonRetry(context.Background(), controller); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Retrying now") {
		t.Fatalf("countdown output=%q, want immediate retry confirmation", out.String())
	}
}

func TestWaitForDaemonRetryNonTTYUsesStableLines(t *testing.T) {
	var out bytes.Buffer
	controller := &daemonRetryController{output: &out, timeout: time.Millisecond}
	if err := waitForDaemonRetry(context.Background(), controller); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Count(text, "Next retry") != 1 || strings.Count(text, "Retrying now") != 1 {
		t.Fatalf("non-TTY progress=%q, want one waiting and one completion line", text)
	}
	if strings.ContainsAny(text, "\r\x1b") {
		t.Fatalf("non-TTY progress contains terminal controls: %q", text)
	}
}
