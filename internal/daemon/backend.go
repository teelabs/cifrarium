package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/restore"
	"github.com/teelabs/cifrarium/internal/store"
	syncvault "github.com/teelabs/cifrarium/internal/sync"
)

// Backend owns vault operations shared by the daemon and its local interfaces.
// Transport and terminal concerns stay outside this package.
type Backend struct {
	Home               string
	Vault              *store.Vault
	Operational        []byte
	Signing            ed25519.PrivateKey
	Pending            *Queue
	QueuePath          string
	Provider           provider.Provider
	Guard              store.HeadGuard
	RecoveryShares     []recovery.Share
	ProviderConfigured bool
	operationMu        sync.Mutex
	restorePending     atomic.Bool
}

// FileRestoreRequest contains only the user's selection and the digest of the
// terminal preflight. File contents and recovery shares stay out of RPC.
type FileRestoreRequest struct {
	Snapshot    string                            `json:"snapshot"`
	Remote      string                            `json:"remote"`
	Paths       []string                          `json:"paths"`
	Choices     map[string]restore.ConflictChoice `json:"choices,omitempty"`
	Fingerprint string                            `json:"fingerprint"`
}

// RestoreFiles re-verifies the remote chain and destination state inside the
// daemon before applying a terminal-confirmed file selection.
func (b *Backend) RestoreFiles(ctx context.Context, request FileRestoreRequest) error {
	if !b.restorePending.CompareAndSwap(false, true) {
		return fmt.Errorf("a restore is already in progress")
	}
	completed := false
	defer func() {
		if !completed {
			b.restorePending.Store(false)
		}
	}()
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.Vault == nil || len(b.Operational) == 0 || len(b.Signing) == 0 {
		return fmt.Errorf("daemon restore backend is not ready")
	}
	if request.Snapshot == "" || len(request.Paths) == 0 || len(request.Paths) > 4096 || request.Fingerprint == "" {
		return fmt.Errorf("invalid daemon restore request")
	}
	source := b.Provider
	if request.Remote != "" {
		if !strings.HasPrefix(request.Remote, "https://github.com/") || strings.ContainsAny(request.Remote, "\r\n\t ") {
			return fmt.Errorf("invalid GitHub restore remote")
		}
		stage, err := os.MkdirTemp("", "cifrarium-daemon-restore-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		staged := provider.Git{Dir: stage, Remote: request.Remote}
		if err := staged.VerifyPrivate(ctx); err != nil {
			return fmt.Errorf("private GitHub provider verification failed")
		}
		if err := staged.StageRemoteSnapshots(ctx); err != nil {
			return fmt.Errorf("stage remote restore history: %w", err)
		}
		source = staged
	} else if source == nil {
		return fmt.Errorf("daemon restore requires a configured GitHub remote")
	}
	history, err := restore.VerifyRemoteHistory(ctx, source, b.Operational, b.Signing)
	if err != nil {
		return fmt.Errorf("verify remote restore history: %w", err)
	}
	var target *restore.VerifiedSnapshot
	for i := range history.Entries {
		if history.Entries[i].ID == request.Snapshot {
			target = &history.Entries[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("selected snapshot is not in verified remote history")
	}
	selected := make([]store.Record, 0, len(request.Paths))
	seen := make(map[string]bool, len(request.Paths))
	for _, path := range request.Paths {
		if path == "" || seen[path] {
			return fmt.Errorf("invalid or duplicate restore path")
		}
		seen[path] = true
		found := false
		for _, record := range target.Records {
			if record.Path == path {
				selected = append(selected, record)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("selected restore path is absent from the snapshot")
		}
	}
	plan, err := restore.BuildFilePlan(b.Home, history, request.Snapshot, selected)
	if err != nil {
		return fmt.Errorf("daemon restore preflight failed: %w", err)
	}
	fingerprint, err := restore.Fingerprint(plan)
	if err != nil {
		return err
	}
	if len(fingerprint) != len(request.Fingerprint) || subtle.ConstantTimeCompare([]byte(fingerprint), []byte(request.Fingerprint)) != 1 {
		return fmt.Errorf("restore destinations changed after terminal preflight; review and confirm again")
	}
	apply, err := restore.ResolveFilePlan(plan, request.Choices)
	if err != nil {
		return err
	}
	expected := make([]store.RestoreDestination, 0, len(plan))
	for _, item := range plan {
		expected = append(expected, store.RestoreDestination{Path: item.Record.Path, Exists: item.Status != restore.PlanNew, Data: item.Current, Mode: item.CurrentMode})
	}
	guard := b.Guard
	if guard == nil {
		guard = b.Vault.Guard
	}
	commit := func() error {
		return store.InstallVerifiedHistoryWithCommitUnderLock(b.Vault.Root, history, b.Operational, b.Signing, guard, func() error {
			_, err := store.OpenWithGuard(b.Vault.Root, b.Operational, b.Signing, guard)
			return err
		})
	}
	if err := store.RestoreWithVaultLock(apply, expected, b.Home, filepath.Join(b.Vault.Root, "backups"), b.Vault.Root, commit); err != nil {
		return err
	}
	completed = true
	return nil
}

// Status is the daemon-owned operational status contract. Interface adapters
// may select a subset of these fields, but they must not rebuild vault state
// independently.
type Status struct {
	Vault        string `json:"vault"`
	Configured   bool   `json:"configured"`
	VaultState   string `json:"vaultState"`
	KeyringState string `json:"keyring"`
	Snapshots    int    `json:"snapshots"`
	Head         string `json:"head,omitempty"`
	Pending      int    `json:"pending"`
	Signer       string `json:"signer,omitempty"`
}

func (b *Backend) Status() (Status, error) {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if b.Vault == nil {
		return Status{}, fmt.Errorf("daemon backend vault is unavailable")
	}
	pending := 0
	if b.Pending != nil {
		pending = b.Pending.Len()
	} else if b.Operational != nil {
		if queue, err := Load(filepath.Join(b.Vault.Root, "pending.queue"), b.Operational); err == nil {
			pending = queue.Len()
		} else if !os.IsNotExist(err) {
			pending = -1
		}
	}
	status := Status{
		Vault:        b.Vault.Root,
		Configured:   true,
		VaultState:   "ready",
		KeyringState: "available",
		Snapshots:    countSnapshots(b.Vault.Root),
		Head:         b.Vault.Head,
		Pending:      pending,
	}
	if len(b.Signing) > 0 {
		status.Signer = fmt.Sprintf("%x", b.Signing.Public())
	}
	return status, nil
}

func (b *Backend) SnapshotPlan() map[string]any {
	return map[string]any{
		"action":                  "capture",
		"adapters":                []string{"codex", "oh-my-zsh", "starship"},
		"readOnly":                true,
		"requiresCliConfirmation": true,
	}
}

func (b *Backend) RestorePlan(snapshot string) (map[string]any, error) {
	if snapshot == "" {
		return nil, fmt.Errorf("restore plan requires a snapshot")
	}
	return map[string]any{
		"action":                  "restore",
		"snapshot":                snapshot,
		"readOnly":                true,
		"requiresCliConfirmation": true,
	}, nil
}

func (b *Backend) CaptureSnapshot(ctx context.Context) (Item, error) {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if b.restorePending.Load() {
		return Item{}, fmt.Errorf("daemon is stopping after file restore")
	}
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	if b.Vault == nil {
		return Item{}, &CaptureError{Stage: CaptureStageVaultWrite, Err: context.Canceled}
	}
	records, err := b.collectAdapterRecords(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return Item{}, err
		}
		return Item{}, &CaptureError{Stage: CaptureStageAdapters, Err: err}
	}
	snapshot, err := b.Vault.SaveIfChanged(records)
	if err != nil {
		return Item{}, &CaptureError{Stage: CaptureStageVaultWrite, Err: err}
	}
	return Item{
		ID:         snapshot.Manifest.Snapshot,
		Ciphertext: snapshot.Ciphertext,
		Manifest:   snapshot.ManifestBytes,
		Unchanged:  snapshot.Unchanged,
	}, nil
}

// AuditSnapshot compares the current adapter files with the verified active
// snapshot without creating or persisting any vault state.
func (b *Backend) AuditSnapshot(ctx context.Context) (store.AuditResult, error) {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return store.AuditResult{}, err
	}
	if b.Vault == nil {
		return store.AuditResult{}, fmt.Errorf("daemon backend vault is unavailable")
	}
	return b.Vault.AuditCurrent(func() ([]store.Record, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return b.collectAdapterRecords(ctx)
	})
}

func (b *Backend) collectAdapterRecords(ctx context.Context) ([]store.Record, error) {
	var records []store.Record
	for _, adapter := range []adapters.Adapter{adapters.Config{}, adapters.Zsh{}, adapters.Starship{}} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		files, err := adapter.Collect(b.Home)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			records = append(records, store.Record{Path: file.Relative, Mode: uint32(file.Mode), Data: file.Data})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// UploadSnapshot applies the daemon-owned recovery and provider gates before
// handing opaque ciphertext and its sealed manifest to the configured
// provider. Interfaces do not get to bypass these checks.
func (b *Backend) UploadSnapshot(ctx context.Context, item Item) error {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if b.restorePending.Load() {
		return fmt.Errorf("daemon is stopping after file restore")
	}
	if b.Vault == nil {
		return fmt.Errorf("daemon backend vault is unavailable")
	}
	if b.Provider == nil {
		return fmt.Errorf("provider is not configured")
	}
	if len(b.RecoveryShares) == 0 {
		return fmt.Errorf("recovery verification required before upload")
	}
	return (syncvault.UploadGate{OperationalKey: b.Vault.Operational, SigningKey: b.Vault.Signing}).UploadSnapshot(
		ctx, b.Provider, item.ID, item.Ciphertext, item.Manifest, b.RecoveryShares,
	)
}

func (b *Backend) PersistQueue() error {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
	if b.restorePending.Load() {
		return fmt.Errorf("daemon is stopping after file restore")
	}
	if b.Vault == nil {
		return fmt.Errorf("daemon backend vault is unavailable")
	}
	if b.Pending == nil || b.QueuePath == "" {
		return fmt.Errorf("daemon queue persistence is not configured")
	}
	return b.Pending.Save(b.QueuePath, b.Vault.Operational)
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
