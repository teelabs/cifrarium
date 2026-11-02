package sync

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
)

type UploadGate struct{ OperationalKey []byte }

// Upload refuses to call a provider until two distinct recovery shares
// reconstruct the exact operational key currently used by the vault.
func (g UploadGate) Upload(ctx context.Context, p provider.Provider, id string, ciphertext []byte, shares []recovery.Share) error {
	if err := g.verify(ctx, shares); err != nil {
		return err
	}
	return p.Upload(ctx, id, ciphertext)
}

func (g UploadGate) UploadSnapshot(ctx context.Context, p provider.Provider, id string, ciphertext, manifestBytes []byte, shares []recovery.Share) error {
	manifest, err := store.OpenManifest(manifestBytes, g.OperationalKey)
	if err != nil {
		return fmt.Errorf("invalid catalog manifest: %w", err)
	}
	if manifest.Snapshot != id {
		return fmt.Errorf("manifest snapshot mismatch")
	}
	if err := g.verify(ctx, shares); err != nil {
		return err
	}
	if atomic, ok := p.(provider.AtomicSnapshotProvider); ok {
		return atomic.UploadSnapshot(ctx, id, ciphertext, manifestBytes)
	}
	if err := p.Upload(ctx, id, ciphertext); err != nil {
		return err
	}
	return p.UploadCatalog(ctx, id, manifestBytes)
}
func (g UploadGate) verify(_ context.Context, shares []recovery.Share) error {
	key, err := recovery.Combine(shares)
	if err != nil || string(key) != string(g.OperationalKey) {
		return fmt.Errorf("recovery verification required before upload")
	}
	return nil
}

func DownloadSnapshot(ctx context.Context, p provider.Provider, vault *store.Vault, id string, pub ed25519.PublicKey) ([]byte, store.Manifest, error) {
	return downloadSnapshot(ctx, p, vault, id, pub, false)
}

// DownloadSnapshotAt permits an explicit historical selection while keeping
// the default DownloadSnapshot current-head-only contract.
func DownloadSnapshotAt(ctx context.Context, p provider.Provider, vault *store.Vault, id string, pub ed25519.PublicKey) ([]byte, store.Manifest, error) {
	return downloadSnapshot(ctx, p, vault, id, pub, true)
}

func downloadSnapshot(ctx context.Context, p provider.Provider, vault *store.Vault, id string, pub ed25519.PublicKey, historical bool) ([]byte, store.Manifest, error) {
	if historical {
		if err := vault.VerifyHistoricalHead(id, pub); err != nil {
			return nil, store.Manifest{}, err
		}
	} else if err := vault.VerifyCurrentHead(id); err != nil {
		return nil, store.Manifest{}, err
	}
	ciphertext, err := p.Download(ctx, id)
	if err != nil {
		return nil, store.Manifest{}, err
	}
	raw, err := p.DownloadCatalog(ctx, id)
	if err != nil {
		return nil, store.Manifest{}, err
	}
	m, err := store.OpenManifest(raw, vault.Operational)
	if err != nil {
		return nil, store.Manifest{}, err
	}
	if err := vault.VerifySnapshot(m, ciphertext, pub); err != nil {
		return nil, store.Manifest{}, err
	}
	return ciphertext, m, nil
}

func RestoreRemote(ctx context.Context, p provider.Provider, vault *store.Vault, id string, pub ed25519.PublicKey, target, backupRoot string) error {
	ciphertext, _, err := DownloadSnapshot(ctx, p, vault, id, pub)
	if err != nil {
		return err
	}
	records, err := vault.RecordsFromCiphertext(ciphertext)
	if err != nil {
		return err
	}
	return store.Restore(records, target, backupRoot)
}

func RestoreRemoteAt(ctx context.Context, p provider.Provider, vault *store.Vault, id string, pub ed25519.PublicKey, target, backupRoot string) error {
	ciphertext, _, err := DownloadSnapshotAt(ctx, p, vault, id, pub)
	if err != nil {
		return err
	}
	records, err := vault.RecordsFromCiphertext(ciphertext)
	if err != nil {
		return err
	}
	return store.Restore(records, target, backupRoot)
}
