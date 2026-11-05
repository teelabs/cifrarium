package daemon

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/teelabs/cifrarium/internal/adapters"
	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
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
	RecoveryShares     []recovery.Share
	ProviderConfigured bool
	operationMu        sync.Mutex
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
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	if b.Vault == nil {
		return Item{}, &CaptureError{Stage: CaptureStageVaultWrite, Err: context.Canceled}
	}
	var records []store.Record
	for _, adapter := range []adapters.Adapter{adapters.Config{}, adapters.Zsh{}, adapters.Starship{}} {
		if err := ctx.Err(); err != nil {
			return Item{}, err
		}
		files, err := adapter.Collect(b.Home)
		if err != nil {
			return Item{}, &CaptureError{Stage: CaptureStageAdapters, Err: err}
		}
		for _, file := range files {
			records = append(records, store.Record{Path: file.Relative, Mode: uint32(file.Mode), Data: file.Data})
		}
	}
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	manifest, err := b.Vault.Save(records)
	if err != nil {
		return Item{}, &CaptureError{Stage: CaptureStageVaultWrite, Err: err}
	}
	ciphertext, err := b.Vault.SnapshotCiphertext(manifest.Snapshot)
	if err != nil {
		return Item{}, &CaptureError{Stage: CaptureStageSnapshotRead, Err: err}
	}
	sealed, err := store.SealManifest(manifest, b.Vault.Operational)
	if err != nil {
		return Item{}, &CaptureError{Stage: CaptureStageManifestPreparation, Err: err}
	}
	return Item{ID: manifest.Snapshot, Ciphertext: ciphertext, Manifest: sealed}, nil
}

// UploadSnapshot applies the daemon-owned recovery and provider gates before
// handing opaque ciphertext and its sealed manifest to the configured
// provider. Interfaces do not get to bypass these checks.
func (b *Backend) UploadSnapshot(ctx context.Context, item Item) error {
	b.operationMu.Lock()
	defer b.operationMu.Unlock()
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
