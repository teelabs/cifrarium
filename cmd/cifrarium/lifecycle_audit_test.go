package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/config"
	"github.com/teelabs/cifrarium/internal/daemon"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
	"github.com/zalando/go-keyring"
)

type lifecycleAuditProvider struct {
	mu        sync.Mutex
	attempted []daemon.Item
	uploaded  []daemon.Item
	err       error
}

func (p *lifecycleAuditProvider) Upload(context.Context, string, []byte) error { return nil }
func (p *lifecycleAuditProvider) UploadCatalog(context.Context, string, []byte) error {
	return nil
}
func (p *lifecycleAuditProvider) Download(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("not used by lifecycle audit")
}
func (p *lifecycleAuditProvider) DownloadCatalog(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("not used by lifecycle audit")
}
func (p *lifecycleAuditProvider) List(context.Context) ([]string, error) { return nil, nil }
func (p *lifecycleAuditProvider) Health(context.Context) error           { return nil }
func (p *lifecycleAuditProvider) VerifyPrivate(context.Context) error    { return nil }
func (p *lifecycleAuditProvider) UploadSnapshot(_ context.Context, id string, ciphertext, manifest []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	item := daemon.Item{ID: id, Ciphertext: append([]byte(nil), ciphertext...), Manifest: append([]byte(nil), manifest...)}
	p.attempted = append(p.attempted, item)
	if p.err != nil {
		return p.err
	}
	p.uploaded = append(p.uploaded, item)
	return nil
}

func TestLifecycleAuditFreshInstallQueueResume(t *testing.T) {
	work := t.TempDir()
	home := filepath.Join(work, "home")
	xdg := filepath.Join(work, "xdg")
	root := filepath.Join(work, "vault")
	for _, dir := range []string{home, xdg, filepath.Join(home, ".codex")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	configPath := config.ConfigPathForHome(home)
	if _, err := config.SaveTo(configPath, root); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveVaultRoot("setup", "", home)
	if err != nil || resolved != root {
		t.Fatalf("configured root resolution = %q, %v", resolved, err)
	}
	keyring.MockInit()
	keys := &store.Keyring{User: "anonymous-test-user"}
	op, signing, err := store.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveForRoot(root, op, signing); err != nil {
		t.Fatal(err)
	}
	vault, err := store.OpenWithGuard(root, op, signing, keys)
	if err != nil {
		t.Fatal(err)
	}

	// New-install local-only path: a snapshot exists before any provider is set.
	localOnly := daemon.Backend{Home: home, Vault: vault}
	first, err := localOnly.CaptureSnapshot(context.Background())
	if err != nil {
		t.Fatalf("first local snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "snapshots", first.ID)); err != nil {
		t.Fatalf("local snapshot missing: %v", err)
	}

	shares, err := store.RecoveryShares(op, signing)
	if err != nil || len(shares) != 3 {
		t.Fatalf("in-memory test recovery setup failed: count=%d err=%v", len(shares), err)
	}
	if _, _, err := store.RecoverKeys([]recovery.Share{shares[0], shares[1]}); err != nil {
		t.Fatalf("generated shares do not recover keyring material: %v", err)
	}
	provider := &lifecycleAuditProvider{}
	queuePath := filepath.Join(root, "pending.queue")
	queue := &daemon.Queue{}
	backend := &daemon.Backend{
		Home: home, Vault: vault, Operational: op, Signing: signing,
		Pending: queue, QueuePath: queuePath, Provider: provider,
		ProviderConfigured: true,
		// Simulate a missing recovery configuration after an upgrade. The first
		// upload must stay queued until the protected recovery material is restored.
	}
	backend.RecoveryShares = []recovery.Share{shares[0], shares[1]}
	provider.err = errors.New("temporary provider failure")
	if err := backend.UploadSnapshot(context.Background(), first); err == nil || err.Error() != "temporary provider failure" {
		t.Fatalf("generated setup shares did not reach the provider gate: %v", err)
	}
	var captures int
	capture := func(ctx context.Context) (daemon.Item, error) {
		captures++
		return backend.CaptureSnapshot(ctx)
	}
	scheduler := daemon.NewScheduler(capture, backend.UploadSnapshot, queue)
	scheduler.RecoverySnapshot = capture
	scheduler.Retry.MaxAttempts = 1
	scheduler.Interval = time.Hour
	scheduler.Persist = backend.PersistQueue
	scheduler.Report = func(error) {}
	ready := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (daemon.Service{Scheduler: scheduler, Ready: func() { ready <- struct{}{} }}).Run(ctx) }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("daemon did not expose MCP/backend process readiness after preserving pending work")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("daemon stopped without context cancellation")
	}
	if queue.Len() != 2 {
		t.Fatalf("pending items=%d, want original and recovery snapshot", queue.Len())
	}
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("encrypted pending queue was not persisted: %v", err)
	}
	beforeRestart, err := daemon.Load(queuePath, op)
	if err != nil {
		t.Fatal(err)
	}
	var queuedBeforeRestart []daemon.Item
	for {
		item, ok := beforeRestart.Pop()
		if !ok {
			break
		}
		queuedBeforeRestart = append(queuedBeforeRestart, item)
	}
	if len(queuedBeforeRestart) != 2 {
		t.Fatalf("persisted queue items=%d, want 2", len(queuedBeforeRestart))
	}

	// Restart with valid recovery verification and the provider restored. Draining
	// must upload the old queue before the normal immediate post-restart capture.
	restartedQueue, err := daemon.Load(queuePath, op)
	if err != nil {
		t.Fatal(err)
	}
	backend.Pending = restartedQueue
	provider.err = nil
	backend.RecoveryShares = []recovery.Share{shares[0], shares[1]}
	restarted := daemon.NewScheduler(capture, backend.UploadSnapshot, restartedQueue)
	restarted.Retry.MaxAttempts = 1
	restarted.Interval = time.Hour
	restarted.Persist = backend.PersistQueue
	restarted.Report = func(error) {}
	restartedReady := make(chan struct{}, 1)
	restartedCtx, stopRestarted := context.WithCancel(context.Background())
	restartedDone := make(chan error, 1)
	go func() {
		restartedDone <- (daemon.Service{Scheduler: restarted, Ready: func() { restartedReady <- struct{}{} }}).Run(restartedCtx)
	}()
	select {
	case <-restartedReady:
	case <-time.After(3 * time.Second):
		stopRestarted()
		t.Fatalf("restarted daemon did not reach readiness; service result: %v", <-restartedDone)
	}
	stopRestarted()
	if err := <-restartedDone; err == nil {
		t.Fatal("restarted daemon stopped without context cancellation")
	}
	if got := restartedQueue.Len(); got != 0 {
		t.Fatalf("pending items after retry=%d, want 0", got)
	}
	if captures != 3 {
		t.Fatalf("capture calls=%d, want failed cycle + recovery + post-restart cycle", captures)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.uploaded) != 3 {
		t.Fatalf("provider uploads=%d, want two queued snapshots and one restart snapshot", len(provider.uploaded))
	}
	for i, queued := range queuedBeforeRestart {
		got := provider.uploaded[i]
		if got.ID != queued.ID || !bytes.Equal(got.Ciphertext, queued.Ciphertext) {
			t.Fatalf("restart upload %d = (%q, %d ciphertext bytes), want original queued item (%q, %d ciphertext bytes)", i, got.ID, len(got.Ciphertext), queued.ID, len(queued.Ciphertext))
		}
	}
}

func TestLifecycleAuditCustomXDGSystemdPathsMatchCLIAndInstaller(t *testing.T) {
	work := t.TempDir()
	home := filepath.Join(work, "home")
	xdg := filepath.Join(work, "config-home")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if err := os.MkdirAll(filepath.Join(xdg, "cifrarium"), 0700); err != nil {
		t.Fatal(err)
	}
	unitBytes, err := os.ReadFile(filepath.Join("..", "..", "systemd", "cifrarium.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitBytes)
	cliConfig := config.ConfigPathForHome(home)
	customDaemonEnv := providerConfigPath(home)
	if cliConfig != filepath.Join(xdg, "cifrarium", "config.json") {
		t.Fatalf("CLI config path = %q; want custom XDG path", cliConfig)
	}
	if customDaemonEnv != filepath.Join(xdg, "cifrarium", "daemon.env") {
		t.Fatalf("installer daemon.env path = %q; want custom XDG path", customDaemonEnv)
	}
	if !strings.Contains(unit, "Environment=XDG_CONFIG_HOME=%E") || !strings.Contains(unit, "EnvironmentFile=-%E/cifrarium/daemon.env") {
		t.Fatalf("systemd unit does not resolve its config paths from the XDG config root:\n%s", unit)
	}
}

func TestLifecycleAuditDefaultXDGSystemdPathsMatchCLIAndInstaller(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	if got, want := config.ConfigPathForHome(home), filepath.Join(home, ".config", "cifrarium", "config.json"); got != want {
		t.Fatalf("default CLI config path = %q; want %q", got, want)
	}
	if got, want := providerConfigPath(home), filepath.Join(home, ".config", "cifrarium", "daemon.env"); got != want {
		t.Fatalf("default installer daemon.env path = %q; want %q", got, want)
	}
}

func TestLifecycleAuditRefreshMasksExitedService(t *testing.T) {
	serviceActive := true
	var calls [][]string
	runDaemonRefreshSystemctl = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 0 && args[0] == "restart" {
			serviceActive = false
		}
		if len(args) > 0 && args[0] == "is-active" && !serviceActive {
			return fmt.Errorf("inactive")
		}
		return nil
	}
	oldMCPProbe, oldBackendProbe := daemonRefreshProbe, daemonRefreshBackendProbe
	daemonRefreshProbe = func(string) error { return fmt.Errorf("socket unavailable") }
	daemonRefreshBackendProbe = func(string) (daemonRefreshReadiness, error) {
		return daemonRefreshReadiness{}, fmt.Errorf("backend unavailable")
	}
	t.Cleanup(func() {
		runDaemonRefreshSystemctl = func(...string) error { return nil }
		daemonRefreshProbe = oldMCPProbe
		daemonRefreshBackendProbe = oldBackendProbe
	})

	_, err := runDaemonRefresh(filepath.Join(t.TempDir(), "vault"))
	if err == nil || err.Error() != "daemon service did not become ready" {
		t.Fatalf("refresh error = %v; want generic readiness timeout while the service exit remains unchecked", err)
	}
	for _, call := range calls {
		if len(call) > 0 && call[0] == "is-active" {
			t.Fatal("refresh unexpectedly checked whether the service exited")
		}
	}
	t.Log("reproduced: exited service is reported as active after a generic MCP readiness timeout")
}

var _ provider.Provider = (*lifecycleAuditProvider)(nil)
var _ provider.AtomicSnapshotProvider = (*lifecycleAuditProvider)(nil)
var _ provider.PrivateVerifier = (*lifecycleAuditProvider)(nil)
