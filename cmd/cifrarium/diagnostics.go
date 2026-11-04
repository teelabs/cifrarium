package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
)

type outputFormat string

const (
	outputHuman outputFormat = "human"
	outputJSON  outputFormat = "json"
)

type statusReport struct {
	Vault        string `json:"vault"`
	Configured   bool   `json:"configured"`
	VaultState   string `json:"vaultState"`
	KeyringState string `json:"keyring"`
	Snapshots    int    `json:"snapshots"`
	Head         string `json:"head,omitempty"`
	Pending      int    `json:"pending"`
	Signer       string `json:"signer,omitempty"`
}

type severity string

const (
	severityHealthy severity = "healthy"
	severityWarning severity = "warning"
	severityProblem severity = "problem"
)

type componentReport struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Severity severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
}

type adapterReport struct {
	Name  string   `json:"name"`
	State string   `json:"state"`
	Paths []string `json:"paths,omitempty"`
}

type doctorReport struct {
	Configuration componentReport `json:"configuration"`
	Overall       severity        `json:"overall"`
	Vault         componentReport `json:"vault"`
	Daemon        componentReport `json:"daemon"`
	MCP           componentReport `json:"mcp"`
	Adapters      []adapterReport `json:"adapters"`
	Provider      componentReport `json:"provider"`
}

var loadDoctorKeys = func() ([]byte, ed25519.PrivateKey, error) {
	return store.NewKeyring().LoadExisting()
}

var loadDoctorKeysForRoot = func(root string) ([]byte, ed25519.PrivateKey, error) {
	return store.NewKeyring().LoadExistingForRoot(root)
}

func (r doctorReport) exitCode() int {
	if r.Overall == severityProblem || r.Vault.Severity == severityProblem || r.Daemon.Severity == severityProblem || r.MCP.Severity == severityProblem || r.Provider.Severity == severityProblem {
		return 1
	}
	for _, adapter := range r.Adapters {
		if adapter.State == "error" {
			return 1
		}
	}
	return 0
}

func renderStatus(w io.Writer, report statusReport, format outputFormat) error {
	if format == outputJSON {
		return json.NewEncoder(w).Encode(report)
	}
	if format != outputHuman {
		return fmt.Errorf("unsupported output format %q", format)
	}
	fmt.Fprintf(w, "Vault: %s\n", report.VaultState)
	fmt.Fprintf(w, "Path: %s\n", report.Vault)
	fmt.Fprintf(w, "Configured: %t\n", report.Configured)
	fmt.Fprintf(w, "Keyring: %s\n", report.KeyringState)
	fmt.Fprintf(w, "Snapshots: %d\n", report.Snapshots)
	if report.Head != "" {
		fmt.Fprintf(w, "Current snapshot: %s\n", report.Head)
	}
	fmt.Fprintf(w, "Pending uploads: %d\n", report.Pending)
	return nil
}

func renderDoctor(w io.Writer, report doctorReport, format outputFormat) error {
	if format == outputJSON {
		return json.NewEncoder(w).Encode(report)
	}
	if format != outputHuman {
		return fmt.Errorf("unsupported output format %q", format)
	}
	fmt.Fprintf(w, "Overall: %s\n\n", report.Overall)
	writeComponent(w, report.Configuration)
	writeComponent(w, report.Vault)
	writeComponent(w, report.Daemon)
	writeComponent(w, report.MCP)
	fmt.Fprintln(w, "Adapters:")
	for _, adapter := range report.Adapters {
		fmt.Fprintf(w, "  - %s: %s", adapter.Name, adapter.State)
		if len(adapter.Paths) > 0 {
			fmt.Fprintf(w, " (%s)", strings.Join(adapter.Paths, ", "))
		}
		fmt.Fprintln(w)
	}
	writeComponent(w, report.Provider)
	return nil
}

func writeComponent(w io.Writer, component componentReport) {
	fmt.Fprintf(w, "%s: %s", component.Name, component.State)
	if component.Detail != "" {
		fmt.Fprintf(w, " (%s)", component.Detail)
	}
	fmt.Fprintln(w)
}

func inspectAdapters(home string) []adapterReport {
	return []adapterReport{
		inspectAdapter("codex", home, []string{".codex/AGENTS.md", ".codex/config.toml"}, nil),
		inspectAdapter("oh-my-zsh", home, []string{".zshrc"}, []string{".zprofile", ".oh-my-zsh/custom"}),
		inspectAdapter("starship", home, []string{".config/starship.toml"}, nil),
	}
}

func inspectAdapter(name, home string, required, optional []string) adapterReport {
	found := make([]string, 0, len(required)+len(optional))
	missingRequired := 0
	for _, path := range required {
		if _, err := os.Lstat(filepath.Join(home, path)); err == nil {
			found = append(found, path)
		} else {
			missingRequired++
		}
	}
	for _, path := range optional {
		if _, err := os.Lstat(filepath.Join(home, path)); err == nil {
			found = append(found, path)
		}
	}
	state := "not-configured"
	if len(required) > 0 && missingRequired == 0 {
		state = "configured"
	} else if len(found) > 0 {
		state = "partial"
	}
	return adapterReport{Name: name, State: state, Paths: found}
}

func runDoctor(root, home, providerDir, providerRemote string, _ io.Writer) (doctorReport, error) {
	report := doctorReport{
		Configuration: componentReport{Name: "Configuration", State: "not-configured", Severity: severityWarning, Detail: "run cifrarium setup"},
		Vault:         componentReport{Name: "Vault", State: "not-configured", Severity: severityWarning, Detail: root},
		Daemon:        componentReport{Name: "Daemon", State: "unknown", Severity: severityWarning, Detail: "systemd user service"},
		MCP:           componentReport{Name: "MCP", State: "not-running", Severity: severityWarning, Detail: filepath.Join(root, "cifrarium.sock")},
		Adapters:      inspectAdapters(home),
		Provider:      componentReport{Name: "Provider", State: "not-configured", Severity: severityWarning, Detail: "optional"},
	}
	if root == "" {
		report.Overall = severityWarning
		return report, nil
	}
	report.Configuration = componentReport{Name: "Configuration", State: "configured", Severity: severityHealthy, Detail: root}

	var op []byte
	var signing ed25519.PrivateKey
	var keyErr error
	if root == "" {
		op, signing, keyErr = loadDoctorKeys()
	} else {
		op, signing, keyErr = loadDoctorKeysForRoot(root)
	}
	if keyErr == nil {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			report.Vault.State = "not-initialized"
			report.Vault.Severity = severityWarning
			report.Vault.Detail = root
		} else if err != nil {
			report.Vault.State = "problem"
			report.Vault.Severity = severityProblem
			report.Vault.Detail = err.Error()
		} else {
			report.Vault.State = "ready"
			report.Vault.Severity = severityHealthy
			if vault, err := store.Open(root, op, signing); err != nil {
				report.Vault.State = "problem"
				report.Vault.Severity = severityProblem
				report.Vault.Detail = err.Error()
			} else {
				report.Vault.Detail = fmt.Sprintf("%s; current snapshot %s", root, emptyAs(vault.Head, "none"))
			}
		}
	} else if !errors.Is(keyErr, keyring.ErrNotFound) {
		report.Vault.State = "keyring-unavailable"
		report.Vault.Severity = severityProblem
		report.Vault.Detail = "keyring could not be read"
	}

	daemonActive, daemonEnabled, daemonAvailable, daemonDetail := systemdStatus("cifrarium.service")
	if daemonDetail != "" {
		report.Daemon.Detail = daemonDetail
		if !daemonAvailable {
			report.Daemon.State = "unavailable"
		} else if daemonEnabled && !daemonActive {
			report.Daemon.State = "enabled-but-inactive"
			report.Daemon.Severity = severityProblem
		} else if daemonActive {
			report.Daemon.State = "active"
			report.Daemon.Severity = severityHealthy
		} else {
			report.Daemon.State = "disabled"
		}
	}

	socket := filepath.Join(root, "cifrarium.sock")
	if info, err := os.Stat(socket); err == nil {
		if info.Mode().Perm()&0077 != 0 {
			report.MCP.State = "unsafe-permissions"
			report.MCP.Severity = severityProblem
		} else if err := probeMCP(socket); err != nil {
			report.MCP.State = "unreachable"
			if daemonActive {
				report.MCP.Severity = severityProblem
			}
			report.MCP.Detail = err.Error()
		} else {
			report.MCP.State = "ready"
			report.MCP.Severity = severityHealthy
		}
	}

	if providerDir != "" || providerRemote != "" {
		report.Provider = componentReport{Name: "Provider", State: "configured", Severity: severityHealthy, Detail: providerDir}
		gitProvider := provider.Git{Dir: providerDir, Remote: providerRemote}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := gitProvider.Health(ctx); err != nil {
			report.Provider.State = "unreachable"
			report.Provider.Severity = severityProblem
			report.Provider.Detail = err.Error()
		} else if err := gitProvider.VerifyPrivate(ctx); err != nil {
			report.Provider.State = "not-private"
			report.Provider.Severity = severityProblem
			report.Provider.Detail = err.Error()
		} else {
			report.Provider.Detail = fmt.Sprintf("%s; %s", providerDir, providerRemote)
		}
	}

	report.Overall = severityHealthy
	for _, component := range []componentReport{report.Vault, report.Daemon, report.MCP, report.Provider} {
		if component.Severity == severityProblem {
			report.Overall = severityProblem
			break
		}
		if component.Severity == severityWarning {
			report.Overall = severityWarning
		}
	}
	return report, nil
}

func emptyAs(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func countSnapshots(root string) int {
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			count++
		}
	}
	return count
}

func countPending(root string, operational []byte) int {
	path := filepath.Join(root, "pending.queue")
	if _, err := os.Stat(path); err != nil {
		return 0
	}
	queue, err := daemon.Load(path, operational)
	if err != nil {
		return -1
	}
	return queue.Len()
}

func systemdStatus(unit string) (active, enabled, available bool, detail string) {
	activeOut, activeErr := exec.Command("systemctl", "--user", "is-active", unit).Output()
	enabledOut, enabledErr := exec.Command("systemctl", "--user", "is-enabled", unit).Output()
	if activeErr != nil && enabledErr != nil {
		return false, false, false, "systemd user service unavailable"
	}
	active = strings.TrimSpace(string(activeOut)) == "active"
	enabled = strings.TrimSpace(string(enabledOut)) == "enabled"
	return active, enabled, true, fmt.Sprintf("enabled=%t active=%t", enabled, active)
}

func probeMCP(socket string) error {
	conn, err := net.DialTimeout("unix", socket, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := fmt.Fprintln(conn, `{"jsonrpc":"2.0","id":1,"method":"status"}`); err != nil {
		return err
	}
	var response struct {
		Result any `json:"result"`
		Error  any `json:"error"`
	}
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("MCP returned an error")
	}
	return nil
}
