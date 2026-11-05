package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/rpc"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
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
	if !strings.Contains(text, "Cifrarium status") || !strings.Contains(text, "\n\n") {
		t.Fatalf("human status is not structured: %q", text)
	}
}

func TestRenderSetupDiagnosticsUsesStructuredSections(t *testing.T) {
	var out bytes.Buffer
	renderSetupDiagnostics(&out, "/home/test/.local/share/cifrarium", t.TempDir(), true)
	text := out.String()
	for _, want := range []string{"Cifrarium setup", "System", "Configured vault", "GitHub CLI"} {
		if !strings.Contains(text, want) {
			t.Fatalf("setup diagnostics missing %q: %q", want, text)
		}
	}
	if !strings.Contains(text, "\n\n") {
		t.Fatalf("setup diagnostics has no section spacing: %q", text)
	}
}

func TestRenderStatusJSONIsStructured(t *testing.T) {
	report := statusReport{Vault: "/vault", Configured: true, VaultState: "ready", KeyringState: "available", Snapshots: 1, Head: "head", Pending: 0}
	var out bytes.Buffer
	if err := renderStatus(&out, report, outputJSON); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json output: %v", err)
	}
	if decoded["vault"] != "/vault" || decoded["vaultState"] != "ready" || decoded["configured"] != true {
		t.Fatalf("unexpected status JSON: %#v", decoded)
	}
}

func TestRenderStatusJSONHasNoANSIOrHumanFormatting(t *testing.T) {
	report := statusReport{Vault: "/vault", Configured: true, VaultState: "ready", KeyringState: "available", Snapshots: 1, Head: "head", Pending: 0}
	var out bytes.Buffer
	if err := renderStatus(&out, report, outputJSON); err != nil {
		t.Fatal(err)
	}
	want := `{"vault":"/vault","configured":true,"vaultState":"ready","keyring":"available","snapshots":1,"head":"head","pending":0}` + "\n"
	if out.String() != want {
		t.Fatalf("JSON output changed: got %q, want %q", out.String(), want)
	}
}

func TestProviderSetupCommandsUseDetectedHomeAndNoSecrets(t *testing.T) {
	home := filepath.Join("/tmp", "cifrarium-test-home")
	commands := providerSetupCommands(home)
	for _, want := range []string{"cifrarium-provider", "git -C", "gh repo create", "--private"} {
		if !strings.Contains(commands, want) {
			t.Fatalf("commands missing %q: %s", want, commands)
		}
	}
	for _, forbidden := range []string{"recovery", "token", "CIFRARIUM_RECOVERY"} {
		if strings.Contains(strings.ToLower(commands), strings.ToLower(forbidden)) {
			t.Fatalf("commands leaked %q: %s", forbidden, commands)
		}
	}
}

func TestShellQuoteProtectsProviderPaths(t *testing.T) {
	value := "/tmp/$HOME/it's a path/`echo bad`"
	quoted := shellQuote(value)
	if quoted != "'/tmp/$HOME/it'\\''s a path/`echo bad`'" {
		t.Fatalf("quoted=%q", quoted)
	}
}

func TestCanonicalCommandUsesNestedSubcommands(t *testing.T) {
	cases := []struct {
		args []string
		want string
		rest []string
	}{
		{[]string{"doctor", "--format=json"}, "doctor", []string{"--format=json"}},
		{[]string{"provider", "health", "--verify-private"}, "provider-health", []string{"--verify-private"}},
		{[]string{"provider", "setup"}, "provider-setup", nil},
		{[]string{"recovery", "shares"}, "recovery-shares", nil},
		{[]string{"recovery", "import", "--recovery-share", "one"}, "recover", []string{"--recovery-share", "one"}},
	}
	for _, tc := range cases {
		got, rest, err := canonicalCommand(tc.args)
		if err != nil || got != tc.want || strings.Join(rest, "\x00") != strings.Join(tc.rest, "\x00") {
			t.Fatalf("canonicalCommand(%v) = %q, %v, %v; want %q, %v", tc.args, got, rest, err, tc.want, tc.rest)
		}
	}
}

func TestCanonicalCommandAcceptsDaemonRefresh(t *testing.T) {
	command, args, err := canonicalCommand([]string{"daemon", "refresh"})
	if err != nil {
		t.Fatal(err)
	}
	if command != "daemon-refresh" || len(args) != 0 {
		t.Fatalf("canonicalCommand() = %q, %#v; want daemon-refresh, no args", command, args)
	}
}

func TestCanonicalCommandRejectsLegacyFlag(t *testing.T) {
	if _, _, err := canonicalCommand([]string{"-command=doctor"}); err == nil {
		t.Fatal("legacy -command syntax was accepted")
	}
}

func TestCanonicalCommandAcceptsHelp(t *testing.T) {
	command, rest, err := canonicalCommand([]string{"help"})
	if err != nil || command != "help" || len(rest) != 0 {
		t.Fatalf("canonicalCommand(help) = %q, %v, %v; want help, no args, nil", command, rest, err)
	}
}

func TestHelpSubcommandWritesCommandsAndOptionsToOneStream(t *testing.T) {
	var out bytes.Buffer
	fs := flag.NewFlagSet("cifrarium", flag.ContinueOnError)
	fs.SetOutput(&out)
	fs.String("example", "", "example option")
	writeCifrariumUsage(&out, fs, "cifrarium")
	text := out.String()
	if !strings.Contains(text, "Commands:") || !strings.Contains(text, "-example") {
		t.Fatalf("usage output incomplete: %q", text)
	}
}

func TestCifrariumHelpListsCommandsWithoutConfiguredValues(t *testing.T) {
	configHome := t.TempDir()
	home := t.TempDir()
	binary := filepath.Join(t.TempDir(), "cifrarium")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building help probe: %v\n%s", err, out)
	}
	cmd := exec.Command(binary, "--help")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+configHome,
		"CIFRARIUM_PROVIDER_DIR=/private/example-provider",
		"CIFRARIUM_PROVIDER_REMOTE=https://github.example/private/example.git",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"Usage: cifrarium <command> [flags]", "Commands:", "status", "doctor", "provider setup", "provider health", "recovery shares", "recovery import", "daemon", "daemon refresh"} {
		if !strings.Contains(text, want) {
			t.Fatalf("help missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"/private/example-provider", "github.example/private/example.git", "CIFRARIUM_RECOVERY_SHARE", home} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("help leaked %q: %s", forbidden, text)
		}
	}
}

func TestLoadProviderConfigIgnoresRecoveryShares(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	path := filepath.Join(configHome, "cifrarium")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "daemon.env"), []byte("CIFRARIUM_PROVIDER_DIR=/provider\nCIFRARIUM_PROVIDER_REMOTE='https://github.com/o/r.git'\nCIFRARIUM_RECOVERY_SHARE_1='secret-looking-share'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadProviderConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != "/provider" || got.Remote != "https://github.com/o/r.git" {
		t.Fatalf("provider config = %#v", got)
	}
}

func TestWriteDaemonEnvPreservesUnrelatedValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	path := filepath.Join(home, ".config", "cifrarium")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(path, "daemon.env")
	if err := os.WriteFile(envPath, []byte("OTHER_SETTING=preserve\nCIFRARIUM_PROVIDER_DIR=/old\nCIFRARIUM_RECOVERY_SHARE_1=old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeDaemonEnv(home, "/new/provider", "https://github.com/o/r.git", map[string]string{
		"CIFRARIUM_RECOVERY_SHARE_1": "cifrarium-1:new",
		"CIFRARIUM_RECOVERY_SHARE_2": "cifrarium-2:new",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"OTHER_SETTING=preserve", "CIFRARIUM_PROVIDER_DIR=/new/provider", "CIFRARIUM_PROVIDER_REMOTE=https://github.com/o/r.git", "CIFRARIUM_RECOVERY_SHARE_1=cifrarium-1:new", "CIFRARIUM_RECOVERY_SHARE_2=cifrarium-2:new"} {
		if !strings.Contains(text, want) {
			t.Fatalf("daemon.env missing %q: %s", want, text)
		}
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("daemon.env mode = %v; want 0600", info.Mode().Perm())
	}
}

func TestSetupCancellationHappensBeforeCommitChoices(t *testing.T) {
	called := 0
	_, err := collectSetupChoices(func(prompt string) (bool, error) {
		if strings.Contains(prompt, "saved") {
			return false, nil
		}
		called++
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err=%v", err)
	}
	if called != 0 {
		t.Fatalf("later setup prompts ran after cancellation: %d", called)
	}
}

func TestInteractiveSetupDoesNotWriteRecoverySharesToRedirectedOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	op := make([]byte, 32)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	err = runSetupWithKeys(root, t.TempDir(), false, &output, op, signing, nil)
	if err == nil {
		t.Fatal("interactive setup unexpectedly succeeded without a controlling terminal")
	}
	if strings.Contains(output.String(), "cifrarium-1:") || strings.Contains(output.String(), "cifrarium-2:") {
		t.Fatalf("recovery share leaked to redirected output: %q", output.String())
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("setup created vault before terminal confirmation: %v", statErr)
	}
}

func TestSystemdUsesConfiguredRootResolver(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "systemd", "cifrarium.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "-root=") {
		t.Fatalf("systemd unit hardcodes a root: %s", text)
	}
	if !strings.Contains(text, "ExecStart=%h/.local/bin/cifrarium daemon") {
		t.Fatalf("systemd unit does not use the configured-root daemon command: %s", text)
	}
	if !strings.Contains(text, "Environment=XDG_CONFIG_HOME=%E") || !strings.Contains(text, "EnvironmentFile=-%E/cifrarium/daemon.env") {
		t.Fatalf("systemd unit does not resolve XDG config and provider files from the same user config root: %s", text)
	}
}

func TestNonInteractiveRejectsStatefulCommands(t *testing.T) {
	for _, command := range []string{"provider-setup", "provider-health", "snapshot", "recovery-shares", "recover", "migrate-catalog", "daemon"} {
		if !commandMutatesOrHandlesSecrets(command) {
			t.Fatalf("%s was not classified as stateful", command)
		}
	}
	for _, command := range []string{"status", "doctor", "setup"} {
		if commandMutatesOrHandlesSecrets(command) {
			t.Fatalf("%s was classified as stateful", command)
		}
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
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	systemctl := filepath.Join(bin, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	originalLoadDoctorKeys := loadDoctorKeys
	originalLoadDoctorKeysForRoot := loadDoctorKeysForRoot
	loadDoctorKeys = func() ([]byte, ed25519.PrivateKey, error) {
		return nil, nil, keyring.ErrNotFound
	}
	loadDoctorKeysForRoot = func(string) ([]byte, ed25519.PrivateKey, error) {
		return nil, nil, keyring.ErrNotFound
	}
	t.Cleanup(func() {
		loadDoctorKeys = originalLoadDoctorKeys
		loadDoctorKeysForRoot = originalLoadDoctorKeysForRoot
	})
	report, err := runDoctor(root, t.TempDir(), "", "", &output)
	if err != nil {
		t.Fatal(err)
	}
	if report.exitCode() != 0 {
		t.Fatalf("doctor exit code = %d, report=%#v", report.exitCode(), report)
	}
	if report.Vault.State != "not-configured" {
		t.Fatalf("vault state = %q, want not-configured", report.Vault.State)
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
	backend := &daemon.Backend{Home: home, Vault: vault}
	snapshot := func(context.Context) (daemon.Item, error) {
		return backend.CaptureSnapshot(context.Background())
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

func TestWriteDaemonServiceErrorSuppressesAlreadyRenderedCaptureDetails(t *testing.T) {
	var out bytes.Buffer
	err := fmt.Errorf("initial capture failed: %w", &daemon.CaptureError{Err: errors.New("symlink rejected: .zshrc; recovery snapshot failed: symlink rejected: /secret/target")})

	writeDaemonServiceError(&out, err)

	if out.Len() != 0 {
		t.Fatalf("raw capture error was printed after sanitized renderer: %q", out.String())
	}
}

func TestWriteDaemonServiceErrorSuppressesAlreadyRenderedRetryDetails(t *testing.T) {
	var out bytes.Buffer
	err := &daemon.ReportedFailure{Err: errors.New("initial pending drain failed: recovery verification required before upload")}

	writeDaemonServiceError(&out, err)

	if out.Len() != 0 {
		t.Fatalf("raw retry error was printed after sanitized renderer: %q", out.String())
	}
}

func TestDaemonRecoverySharesReloadsProtectedConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if err := os.MkdirAll(filepath.Join(home, "config", "cifrarium"), 0700); err != nil {
		t.Fatal(err)
	}
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	shares, err := recovery.Split(op)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(home, "config", "cifrarium", "daemon.env")
	contents := fmt.Sprintf("CIFRARIUM_RECOVERY_SHARE_1=%s\nCIFRARIUM_RECOVERY_SHARE_2=%s\n", shares[0].Label+":"+shares[0].Value, shares[1].Label+":"+shares[1].Value)
	if err := os.WriteFile(envPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := daemonRecoveryShares(home, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("daemonRecoveryShares() = %#v, %v; want two shares", got, err)
	}
}

func TestDaemonRecoverySharesRejectsIncompleteProtectedConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if err := os.MkdirAll(filepath.Join(home, "config", "cifrarium"), 0700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(home, "config", "cifrarium", "daemon.env")
	if err := os.WriteFile(envPath, []byte("CIFRARIUM_RECOVERY_SHARE_1=protected-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := daemonRecoveryShares(home, nil); err == nil {
		t.Fatal("incomplete recovery configuration unexpectedly accepted")
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

func TestMCPStatusUsesDaemonBackendView(t *testing.T) {
	root := t.TempDir()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := &daemon.Backend{Vault: store.New(root, []byte("operational-key"), signing), Pending: &daemon.Queue{}}
	ready := &atomic.Bool{}
	ready.Store(true)
	handler := newMCPHandlerWithReadiness(root, "", backend, ready)
	result, err := handler.Handle(context.Background(), mcp.Request{Method: "status"})
	if err != nil {
		t.Fatal(err)
	}
	status, ok := result.(map[string]any)
	if !ok || status["vault"] != root || status["vaultState"] != "ready" || status["backend"] != "ready" {
		t.Fatalf("MCP status = %#v; want daemon backend view", result)
	}
}

func TestDaemonControlHandlerRequiresBackendReadiness(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vault := store.New(root, op, signing)
	backendReady := &atomic.Bool{}
	mcpReady := &atomic.Bool{}
	backend := &daemon.Backend{Vault: vault, Operational: op, Signing: signing}
	handler := newDaemonControlHandler(backend, func(context.Context) (daemon.Item, error) {
		return daemon.Item{ID: "snapshot"}, nil
	}, backendReady, mcpReady)
	_, rpcErr := handler(context.Background(), rpc.Request{JSONRPC: "2.0", ID: "1", Method: "daemon.status"})
	if rpcErr == nil || rpcErr.Code != -32002 {
		t.Fatalf("status error = %#v; want backend-not-ready", rpcErr)
	}
	backendReady.Store(true)
	result, rpcErr := handler(context.Background(), rpc.Request{JSONRPC: "2.0", ID: "2", Method: "daemon.status"})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if result.(daemon.Status).Vault != root {
		t.Fatalf("status vault = %q; want test root", result.(daemon.Status).Vault)
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
	if !strings.Contains(output.String(), "Non-interactive mode") {
		t.Fatalf("output=%q", output.String())
	}
	if strings.Contains(output.String(), "cifrarium-1:") {
		t.Fatalf("recovery share leaked: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("non-interactive setup captured data: %v", err)
	}
}
