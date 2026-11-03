package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/store"
)

func TestRenderStatusHumanUsesUsefulLabels(t *testing.T) {
	report := statusReport{
		Vault:        "/home/test/.local/share/cifrarium",
		VaultState:   "ready",
		KeyringState: "available",
		Snapshots:    3,
		Head:         "snapshot-123",
		Pending:      2,
	}
	var out bytes.Buffer
	if err := renderStatus(&out, report, outputHuman); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"Vault: ready",
		"Path: /home/test/.local/share/cifrarium",
		"Keyring: available",
		"Snapshots: 3",
		"Pending uploads: 2",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("human status missing %q in %q", want, text)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(text), "{") || strings.Contains(text, "signer") {
		t.Fatalf("human status leaked machine-oriented output: %q", text)
	}
}

func TestRenderStatusJSONIsStructured(t *testing.T) {
	report := statusReport{Vault: "/vault", VaultState: "ready", KeyringState: "available", Snapshots: 1, Head: "head", Pending: 0}
	var out bytes.Buffer
	if err := renderStatus(&out, report, outputJSON); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json output: %v", err)
	}
	if decoded["vault"] != "/vault" || decoded["vaultState"] != "ready" {
		t.Fatalf("unexpected status JSON: %#v", decoded)
	}
}

func TestDoctorExitCodeTreatsOptionalProviderAsWarning(t *testing.T) {
	report := doctorReport{Provider: componentReport{State: "not-configured", Severity: severityWarning}}
	if got := report.exitCode(); got != 0 {
		t.Fatalf("exit code = %d, want 0 for optional provider warning", got)
	}
	report.Provider = componentReport{State: "unreachable", Severity: severityProblem}
	if got := report.exitCode(); got != 1 {
		t.Fatalf("exit code = %d, want 1 for provider problem", got)
	}
}

func TestRenderDoctorHumanIncludesOperationalSections(t *testing.T) {
	report := doctorReport{
		Vault:    componentReport{Name: "Vault", State: "ready", Detail: "/vault"},
		Daemon:   componentReport{Name: "Daemon", State: "disabled", Detail: "systemd user service"},
		MCP:      componentReport{Name: "MCP", State: "not-running", Detail: "/vault/cifrarium.sock"},
		Adapters: []adapterReport{{Name: "codex", State: "configured", Paths: []string{"~/.codex/config.toml"}}},
		Provider: componentReport{Name: "Provider", State: "not-configured", Detail: "optional"},
	}
	var out bytes.Buffer
	if err := renderDoctor(&out, report, outputHuman); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Vault", "Daemon", "MCP", "Adapters", "Provider", "codex", "disabled", "not-running"} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor output missing %q in %q", want, text)
		}
	}
}

func TestInspectAdaptersDoesNotReadConfigurationContents(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("secret-looking config"), 0600); err != nil {
		t.Fatal(err)
	}
	reports := inspectAdapters(home)
	var codex adapterReport
	for _, report := range reports {
		if report.Name == "codex" {
			codex = report
		}
	}
	if codex.State != "partial" {
		t.Fatalf("codex state = %q, want partial: %#v", codex.State, codex)
	}
	for _, path := range codex.Paths {
		if strings.Contains(path, "secret-looking") {
			t.Fatalf("adapter diagnostic leaked file contents: %#v", codex)
		}
	}
}

func TestRunDoctorDoesNotCreateVaultOrKeyringState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	var output bytes.Buffer
	report, err := runDoctor(root, t.TempDir(), "", "", &output)
	if err != nil {
		t.Fatal(err)
	}
	if report.exitCode() != 0 {
		t.Fatalf("doctor exit code = %d, report=%#v", report.exitCode(), report)
	}
	if report.Vault.State != "not-initialized" {
		t.Fatalf("vault state = %q, want not-initialized", report.Vault.State)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("doctor created vault root: %v", err)
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatalf("doctor output contains sensitive-looking material: %q", output.String())
	}
}

func TestVersionFlag(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "dev\n" {
		t.Fatalf("version output = %q", out)
	}
}

func TestDaemonWiresRecoverySnapshotAndQueuesIt(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"test\""), 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(root, op, signing)
	snapshot := func(context.Context) (daemon.Item, error) {
		return captureSnapshot(home, vault)
	}
	scheduler := newDaemonScheduler(snapshot, func(context.Context, daemon.Item) error {
		return errors.New("offline")
	}, &daemon.Queue{})
	scheduler.Retry.MaxAttempts = 1

	if err := scheduler.Cycle(context.Background()); err == nil {
		t.Fatal("offline cycle succeeded")
	}
	if scheduler.Pending.Len() != 2 {
		t.Fatalf("pending=%d, want normal and recovery snapshots", scheduler.Pending.Len())
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("snapshots=%d, want 2", len(entries))
	}
}

func TestMCPHandlerReturnsReadOnlyRestorePlan(t *testing.T) {
	handler := newMCPHandler("/vault", "/provider")
	result, err := handler.Handle(context.Background(), mcp.Request{
		Method: "restore.plan",
		Params: json.RawMessage(`{"snapshot":"snapshot-id"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result=%#v", result)
	}
	if plan["readOnly"] != true || plan["requiresCliConfirmation"] != true || plan["snapshot"] != "snapshot-id" {
		t.Fatalf("unexpected plan=%#v", plan)
	}
}

func TestSetupNonInteractiveDoesNotLeakSharesOrCapture(t *testing.T) {
	root := t.TempDir()
	var output strings.Builder
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSetupWithKeys(root, t.TempDir(), true, &output, op, signing, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Modo não interativo") {
		t.Fatalf("output=%q", output.String())
	}
	if strings.Contains(output.String(), "cifrarium-1:") {
		t.Fatalf("recovery share leaked: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("non-interactive setup captured data: %v", err)
	}
}
