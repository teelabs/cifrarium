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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/mcp"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/restore"
	"github.com/teelabs/cifrarium/internal/rpc"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
)

type controlRestoreTestProvider struct {
	id         string
	ciphertext []byte
	catalog    []byte
}

func (p controlRestoreTestProvider) Upload(context.Context, string, []byte) error        { return nil }
func (p controlRestoreTestProvider) UploadCatalog(context.Context, string, []byte) error { return nil }
func (p controlRestoreTestProvider) Download(_ context.Context, id string) ([]byte, error) {
	if id != p.id {
		return nil, os.ErrNotExist
	}
	return p.ciphertext, nil
}
func (p controlRestoreTestProvider) DownloadCatalog(_ context.Context, id string) ([]byte, error) {
	if id != p.id {
		return nil, os.ErrNotExist
	}
	return p.catalog, nil
}
func (p controlRestoreTestProvider) List(context.Context) ([]string, error) {
	return []string{p.id}, nil
}
func (p controlRestoreTestProvider) Health(context.Context) error { return nil }

var _ provider.Provider = controlRestoreTestProvider{}

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

func TestRenderSnapshotResultDistinguishesUnchangedHead(t *testing.T) {
	var out bytes.Buffer
	writeSnapshotResult(&out, "head-id", true)
	if got, want := out.String(), "snapshot head-id (unchanged; reused current)\n"; got != want {
		t.Fatalf("unchanged snapshot output = %q, want %q", got, want)
	}
	out.Reset()
	writeSnapshotResult(&out, "new-id", false)
	if got, want := out.String(), "snapshot new-id\n"; got != want {
		t.Fatalf("new snapshot output = %q, want %q", got, want)
	}
}

func TestDaemonSnapshotRPCReportsUnchangedHead(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	handler := newDaemonControlHandler(nil, func(context.Context) (daemon.Item, error) {
		return daemon.Item{ID: "head-id", Unchanged: true}, nil
	}, ready, &atomic.Bool{})
	result, rpcErr := handler(context.Background(), rpc.Request{Method: "snapshot.create"})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Snapshot  string `json:"snapshot"`
		Unchanged bool   `json:"unchanged"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Snapshot != "head-id" || !got.Unchanged {
		t.Fatalf("snapshot RPC result = %#v, want unchanged head-id", got)
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
		{[]string{"restore"}, "restore", nil},
		{[]string{"provider", "health", "--verify-private"}, "provider-health", []string{"--verify-private"}},
		{[]string{"provider", "setup"}, "provider-setup", nil},
		{[]string{"recovery", "shares"}, "recovery-shares", nil},
		{[]string{"recovery", "import", "--recovery-share", "one"}, "recover", []string{"--recovery-share", "one"}},
		{[]string{"snapshot", "audit", "--format=json"}, "snapshot-audit", []string{"--format=json"}},
	}
	for _, tc := range cases {
		got, rest, err := canonicalCommand(tc.args)
		if err != nil || got != tc.want || strings.Join(rest, "\x00") != strings.Join(tc.rest, "\x00") {
			t.Fatalf("canonicalCommand(%v) = %q, %v, %v; want %q, %v", tc.args, got, rest, err, tc.want, tc.rest)
		}
	}
}

func TestRenderSnapshotAuditHumanAndJSON(t *testing.T) {
	result := store.AuditResult{
		Status:         store.AuditDiffers,
		Snapshot:       "snapshot-id",
		Added:          []string{".config/new.toml"},
		Missing:        []string{".zshrc"},
		ContentChanged: []string{".codex/config.toml"},
		ModeChanged:    []string{".codex/config.toml"},
	}
	var human bytes.Buffer
	if err := renderSnapshotAudit(&human, result, outputHuman); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Cifrarium snapshot audit", "Status: differs", "Snapshot: snapshot-id", "Added", ".config/new.toml", "Missing", ".zshrc", "Content changed", "Mode changed"} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human audit output missing %q: %q", want, human.String())
		}
	}
	if strings.Contains(human.String(), string([]byte{0x1b})) || strings.Contains(human.String(), "/home/") {
		t.Fatalf("human audit output contains terminal controls or absolute paths: %q", human.String())
	}

	var machine bytes.Buffer
	if err := renderSnapshotAudit(&machine, result, outputJSON); err != nil {
		t.Fatal(err)
	}
	var decoded store.AuditResult
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON audit output: %v", err)
	}
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("JSON audit output = %#v, want %#v", decoded, result)
	}
}

func TestRenderSnapshotAuditEscapesTerminalControlsInPaths(t *testing.T) {
	result := store.AuditResult{Status: store.AuditDiffers, Added: []string{".oh-my-zsh/custom/\x1b[2J\nforged"}}
	var output bytes.Buffer
	if err := renderSnapshotAudit(&output, result, outputHuman); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(output.String(), '\x1b') || strings.Contains(output.String(), "forged\n") {
		t.Fatalf("audit output contains an unescaped control or forged line: %q", output.String())
	}
	if !strings.Contains(output.String(), `\x1b[2J\nforged`) {
		t.Fatalf("audit output does not visibly escape path controls: %q", output.String())
	}
}

func TestRunSnapshotAuditUsesDaemonAndDoesNotFallBackWhenBackendIsStarting(t *testing.T) {
	root := t.TempDir()
	controlSocket := filepath.Join(root, "control.sock")
	server, err := rpc.ListenUnix(controlSocket, func(_ context.Context, request rpc.Request) (any, *rpc.Error) {
		if request.Method != "snapshot.audit" {
			return nil, &rpc.Error{Code: -32601, Message: "method not found"}
		}
		return nil, &rpc.Error{Code: -32002, Message: "daemon backend is not ready"}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	defer server.Close()

	result, err := runSnapshotAudit(root, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "daemon backend is still starting") {
		t.Fatalf("runSnapshotAudit result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "head.json")); !os.IsNotExist(err) {
		t.Fatalf("CLI bypassed the starting daemon and created a local snapshot: %v", err)
	}
}

func TestRunSnapshotAuditReturnsDaemonResult(t *testing.T) {
	root := t.TempDir()
	want := store.AuditResult{Status: store.AuditDiffers, Snapshot: "snapshot-id", Added: []string{".zshrc"}}
	server, err := rpc.ListenUnix(filepath.Join(root, "control.sock"), func(_ context.Context, request rpc.Request) (any, *rpc.Error) {
		if request.Method != "snapshot.audit" {
			return nil, &rpc.Error{Code: -32601, Message: "method not found"}
		}
		return want, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	defer server.Close()

	got, err := runSnapshotAudit(root, t.TempDir())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("runSnapshotAudit() = %#v, %v; want %#v", got, err, want)
	}
}

func TestCallDaemonAuditRejectsAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	server, err := rpc.ListenUnix(filepath.Join(root, "control.sock"), func(_ context.Context, request rpc.Request) (any, *rpc.Error) {
		if request.Method != "snapshot.audit" {
			return nil, &rpc.Error{Code: -32601, Message: "method not found"}
		}
		return store.AuditResult{Status: store.AuditDiffers, Snapshot: "snapshot-id", Added: []string{"/home/user/.config"}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	defer server.Close()
	if result, ok, err := callDaemonAudit(root); err == nil || !ok || result.Status != "" {
		t.Fatalf("absolute path accepted: result=%#v ok=%v err=%v", result, ok, err)
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
	for _, command := range []string{"provider-setup", "provider-health", "snapshot", "recovery-shares", "recover", "restore", "migrate-catalog", "daemon"} {
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
	report = doctorReport{Backend: componentReport{State: "starting", Severity: severityProblem}}
	if got := report.exitCode(); got != 1 {
		t.Fatalf("exit code = %d, want 1 for a starting daemon backend", got)
	}
}

func TestDoctorBackendReadinessDistinguishesBackendFromMCP(t *testing.T) {
	oldProbe := daemonRefreshBackendProbe
	t.Cleanup(func() { daemonRefreshBackendProbe = oldProbe })

	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{Backend: "starting", MCP: "ready"}, nil
	}
	starting := inspectDoctorBackend(true, filepath.Join(t.TempDir(), "control.sock"))
	if starting.State != "starting" || starting.Severity != severityProblem || !strings.Contains(starting.Detail, "MCP ready") {
		t.Fatalf("backend diagnostic = %#v; want starting/problem with MCP ready detail", starting)
	}

	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{Backend: "ready", MCP: "ready"}, nil
	}
	ready := inspectDoctorBackend(true, filepath.Join(t.TempDir(), "control.sock"))
	if ready.State != "ready" || ready.Severity != severityHealthy {
		t.Fatalf("backend diagnostic = %#v; want ready/healthy", ready)
	}

	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{}, errors.New("raw /private/provider/token error")
	}
	unknown := inspectDoctorBackend(true, filepath.Join(t.TempDir(), "control.sock"))
	if unknown.State != "unknown" || unknown.Severity != severityProblem || strings.Contains(unknown.Detail, "/private") || strings.Contains(unknown.Detail, "token") {
		t.Fatalf("backend diagnostic = %#v; want sanitized unknown/problem", unknown)
	}

	inactive := inspectDoctorBackend(false, filepath.Join(t.TempDir(), "control.sock"))
	if inactive.State != "not-running" || inactive.Severity != severityWarning {
		t.Fatalf("backend diagnostic = %#v; want not-running/warning", inactive)
	}
	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{Backend: "ready", MCP: "ready"}, nil
	}
	manual := inspectDoctorBackend(false, filepath.Join(t.TempDir(), "control.sock"))
	if manual.State != "ready" || manual.Severity != severityHealthy {
		t.Fatalf("responsive manual daemon backend = %#v; want ready/healthy", manual)
	}
}

func TestRunDoctorReportsActiveMCPButStartingBackendAsProblem(t *testing.T) {
	oldKeys := loadDoctorKeysForRoot
	oldMCPProbe := doctorMCPProbe
	oldBackendProbe := daemonRefreshBackendProbe
	t.Cleanup(func() {
		loadDoctorKeysForRoot = oldKeys
		doctorMCPProbe = oldMCPProbe
		daemonRefreshBackendProbe = oldBackendProbe
	})

	root := t.TempDir()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	loadDoctorKeysForRoot = func(string) ([]byte, ed25519.PrivateKey, error) {
		return make([]byte, 32), signing, nil
	}
	if err := os.WriteFile(filepath.Join(root, "cifrarium.sock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\ncase \"$2\" in is-active) echo active;; is-enabled) echo enabled;; *) exit 1;; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	doctorMCPProbe = func(string) error { return nil }
	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{Backend: "starting", MCP: "ready"}, nil
	}

	report, err := runDoctor(root, t.TempDir(), "", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if report.Daemon.State != "active" || report.MCP.State != "ready" || report.Backend.State != "starting" || report.Overall != severityProblem || report.exitCode() != 1 {
		t.Fatalf("doctor report failed to distinguish readiness states: %#v", report)
	}
	var output bytes.Buffer
	if err := renderDoctor(&output, report, outputJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"backend":{"name":"Backend","state":"starting","severity":"problem","detail":"MCP ready"}`) {
		t.Fatalf("doctor JSON omitted backend readiness: %s", output.String())
	}
}

func TestDaemonBackendNotReadyAdviceIsSafeAndActionable(t *testing.T) {
	got := daemonBackendNotReadyAdvice(&rpc.Error{Code: -32002, Message: "daemon backend is not ready", Data: "/private/token"})
	for _, want := range []string{"MCP and backend readiness", "foreground `cifrarium daemon`", "systemctl --user stop cifrarium.service", "local snapshot"} {
		if !strings.Contains(got.Error(), want) {
			t.Fatalf("readiness advice %q does not include %q", got, want)
		}
	}
	if strings.Contains(got.Error(), "/private") || strings.Contains(got.Error(), "token") || strings.Contains(got.Error(), "backend is not ready") {
		t.Fatalf("readiness advice leaked raw RPC details: %q", got)
	}

	original := errors.New("other RPC failure")
	if got := daemonBackendNotReadyAdvice(original); got != original {
		t.Fatalf("unrelated RPC error changed: %v", got)
	}
}

func TestRenderDoctorHumanIncludesOperationalSections(t *testing.T) {
	report := doctorReport{
		Vault:    componentReport{Name: "Vault", State: "ready", Detail: "/vault"},
		Daemon:   componentReport{Name: "Daemon", State: "disabled", Detail: "systemd user service"},
		MCP:      componentReport{Name: "MCP", State: "not-running", Detail: "/vault/cifrarium.sock"},
		Backend:  componentReport{Name: "Backend", State: "not-running", Detail: "daemon is not active"},
		Adapters: []adapterReport{{Name: "codex", State: "configured", Paths: []string{"~/.codex/config.toml"}}},
		Provider: componentReport{Name: "Provider", State: "not-configured", Detail: "optional"},
	}
	var out bytes.Buffer
	if err := renderDoctor(&out, report, outputHuman); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Vault", "Daemon", "MCP", "Backend", "Adapters", "Provider", "codex", "disabled", "not-running"} {
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
	if scheduler.Pending.Len() != 1 {
		t.Fatalf("pending=%d, want one reused normal/recovery snapshot", scheduler.Pending.Len())
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("snapshots=%d, want 1 reused snapshot", len(entries))
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

func TestWriteDaemonServiceErrorSuppressesCompoundRecoveryDetails(t *testing.T) {
	var out bytes.Buffer
	err := &daemon.RecoverySnapshotError{
		Primary:  errors.New("provider URL contains private-token"),
		Recovery: errors.New("write failed at /private/home"),
	}
	writeDaemonServiceError(&out, err)
	if out.Len() != 0 {
		t.Fatalf("raw compound recovery error was printed after sanitized diagnostics: %q", out.String())
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

func TestWriteDaemonServiceErrorSanitizesInitialQueuePersistenceFailure(t *testing.T) {
	queue := &daemon.Queue{}
	scheduler := daemon.NewScheduler(
		func(context.Context) (daemon.Item, error) {
			return daemon.Item{ID: "fresh", Ciphertext: []byte("cipher")}, nil
		},
		func(context.Context, daemon.Item) error { return errors.New("remote failed token=private") },
		queue,
	)
	scheduler.Retry.MaxAttempts = 1
	scheduler.Persist = func() error { return errors.New("permission denied: /private/home") }
	err := (daemon.Service{Scheduler: scheduler}).Run(context.Background())
	var out bytes.Buffer
	writeDaemonServiceError(&out, err)
	text := out.String()
	for _, want := range []string{"pending queue", "could not be persisted"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Fatalf("queue-persistence diagnostic missing %q: %q", want, text)
		}
	}
	for _, forbidden := range []string{"remote failed", "/private/home", "permission denied", "token=private"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("queue-persistence diagnostic leaked %q: %q", forbidden, text)
		}
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

func TestSnapshotAuditMCPAndControlRequireReadyBackend(t *testing.T) {
	root := t.TempDir()
	backend := &daemon.Backend{Vault: store.New(root, make([]byte, 32), nil)}
	ready := &atomic.Bool{}
	mcpHandler := newMCPHandlerWithReadiness(root, "", backend, ready)
	if _, err := mcpHandler.Handle(context.Background(), mcp.Request{Method: "snapshot.audit"}); err == nil || err.Error() != "daemon backend is not ready" {
		t.Fatalf("MCP audit before readiness error = %v", err)
	}
	controlHandler := newDaemonControlHandler(backend, nil, ready, &atomic.Bool{})
	if _, rpcErr := controlHandler(context.Background(), rpc.Request{Method: "snapshot.audit"}); rpcErr == nil || rpcErr.Code != -32002 {
		t.Fatalf("control audit before readiness error = %#v", rpcErr)
	}
	ready.Store(true)
	result, err := mcpHandler.Handle(context.Background(), mcp.Request{Method: "snapshot.audit"})
	if err != nil || result.(store.AuditResult).Status != store.AuditNoSnapshot {
		t.Fatalf("MCP audit result=%#v err=%v", result, err)
	}
	result, rpcErr := controlHandler(context.Background(), rpc.Request{Method: "snapshot.audit"})
	if rpcErr != nil || result.(store.AuditResult).Status != store.AuditNoSnapshot {
		t.Fatalf("control audit result=%#v err=%v", result, rpcErr)
	}
	if _, err := os.Lstat(filepath.Join(root, ".recovery.lock")); !os.IsNotExist(err) {
		t.Fatalf("audit created recovery lock: %v", err)
	}
	if _, err := mcpHandler.Handle(context.Background(), mcp.Request{Method: "restore.apply"}); err == nil {
		t.Fatal("MCP exposed the mutating restore operation")
	}
	controlResult, controlErr := controlHandler(context.Background(), rpc.Request{Method: "restore.apply", Params: json.RawMessage(`{}`)})
	if controlErr == nil || controlErr.Code != -32012 || controlResult != nil {
		t.Fatalf("control restore route = (%#v, %#v), want backend restore failure", controlResult, controlErr)
	}
}

func TestDaemonRestoreRequestSizeRespectsControlLineLimit(t *testing.T) {
	if err := validateDaemonRestoreRequestSize(daemon.FileRestoreRequest{Snapshot: "snapshot", Remote: "https://github.com/owner/repo.git", Paths: []string{".zshrc"}, Fingerprint: strings.Repeat("a", 64)}); err != nil {
		t.Fatalf("small restore request rejected: %v", err)
	}
	large := daemon.FileRestoreRequest{Snapshot: "snapshot", Remote: "https://github.com/owner/repo.git", Fingerprint: strings.Repeat("a", 64)}
	for i := 0; i < 40; i++ {
		large.Paths = append(large.Paths, strings.Repeat("x", 2000))
	}
	if err := validateDaemonRestoreRequestSize(large); err == nil || !strings.Contains(err.Error(), "reduce the selection") {
		t.Fatalf("oversized restore request error = %v; want actionable size limit", err)
	}
}

func TestDaemonControlRPCAppliesRestoreAndStopsService(t *testing.T) {
	home, root := t.TempDir(), filepath.Join(t.TempDir(), "vault")
	op := bytes.Repeat([]byte{9}, 32)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remoteVault := store.New(filepath.Join(t.TempDir(), "remote"), op, signing)
	manifest, err := remoteVault.Save([]store.Record{{Path: ".zshrc", Mode: 0600, Data: []byte("restored through rpc")}})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(remoteVault.Root, "snapshots", manifest.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := os.ReadFile(filepath.Join(remoteVault.Root, "catalog", manifest.Snapshot+".json"))
	if err != nil {
		t.Fatal(err)
	}
	source := controlRestoreTestProvider{id: manifest.Snapshot, ciphertext: ciphertext, catalog: catalog}
	history, err := restore.VerifyRemoteHistory(context.Background(), source, op, signing)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.BuildFilePlan(home, history, manifest.Snapshot, history.Entries[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := restore.Fingerprint(plan)
	if err != nil {
		t.Fatal(err)
	}
	request := daemon.FileRestoreRequest{Snapshot: manifest.Snapshot, Paths: []string{".zshrc"}, Fingerprint: fingerprint}
	backend := &daemon.Backend{Home: home, Vault: store.New(root, op, signing), Operational: op, Signing: signing, Provider: source}
	ready, mcpReady := &atomic.Bool{}, &atomic.Bool{}
	ready.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(root, "control.sock")
	server, err := rpc.ListenUnix(socket, newDaemonControlHandler(backend, nil, ready, mcpReady, cancel), nil)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx); _ = server.Close() }()
	oldSystemctl := runDaemonRefreshSystemctl
	disabled := false
	runDaemonRefreshSystemctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "is-active" {
			return nil
		}
		if len(args) > 0 && args[0] == "disable" {
			disabled = true
			return nil
		}
		return errors.New("inactive")
	}
	defer func() { runDaemonRefreshSystemctl = oldSystemctl; _ = server.Close() }()
	active, err := callDaemonRestore(root, request)
	if err != nil || !active {
		t.Fatalf("daemon restore route active=%v err=%v", active, err)
	}
	if err := finishDaemonRestore(root); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("systemd service was not disabled after successful restore")
	}
	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil || !bytes.Equal(data, []byte("restored through rpc")) {
		t.Fatalf("restored file = %q err=%v", data, err)
	}
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop after successful restore")
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
