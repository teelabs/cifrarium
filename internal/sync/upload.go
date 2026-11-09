package sync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"fmt"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/teelabs/cifrarium/internal/store"
)

type UploadGate struct {
	OperationalKey []byte
	SigningKey     ed25519.PrivateKey
}

// Upload refuses to call a provider until recovery shares reconstruct the v1
// keyring bundle currently used by the vault.
func (g UploadGate) Upload(ctx context.Context, p provider.Provider, id string, ciphertext []byte, shares []recovery.Share) error {
	if err := g.verify(ctx, shares); err != nil {
		return err
	}
	if err := verifyPrivate(ctx, p); err != nil {
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
	if err := verifyPrivate(ctx, p); err != nil {
		return err
	}
	if canonical, ok := p.(provider.CanonicalSnapshotProvider); ok {
		marker, revision, err := canonical.ReadRemoteHistorySelection(ctx)
		if err != nil {
			return fmt.Errorf("read canonical backup history: %w", err)
		}
		if len(marker) != 0 {
			selection, err := store.OpenHistorySelection(marker, g.OperationalKey, g.SigningKey.Public().(ed25519.PublicKey))
			if err != nil {
				return fmt.Errorf("canonical backup history marker is invalid; snapshot upload stopped")
			}
			if selection.Head != id {
				if manifest.Previous != selection.Head {
					return fmt.Errorf("snapshot does not extend the selected canonical backup history")
				}
				vault := store.New("", g.OperationalKey, g.SigningKey)
				if err := vault.VerifySnapshot(manifest, ciphertext, g.SigningKey.Public().(ed25519.PublicKey)); err != nil {
					return fmt.Errorf("snapshot verification failed before canonical history advance")
				}
				updated, err := store.SealHistorySelection(id, g.OperationalKey, g.SigningKey)
				if err != nil {
					return err
				}
				return canonical.UploadSnapshotWithHistorySelection(ctx, id, ciphertext, manifestBytes, updated, revision)
			}
			vault := store.New("", g.OperationalKey, g.SigningKey)
			if err := vault.VerifySnapshot(manifest, ciphertext, g.SigningKey.Public().(ed25519.PublicKey)); err != nil {
				return fmt.Errorf("snapshot verification failed before canonical upload retry")
			}
			// An earlier push may have succeeded even if its response was lost.
			// Re-submit the exact artifacts so the provider can repair its local
			// checkout without advancing or re-encrypting the marker.
			return canonical.UploadSnapshotWithHistorySelection(ctx, id, ciphertext, manifestBytes, marker, revision)
		}
	}
	if equivalent, ok := p.(provider.EquivalentManifestSnapshotProvider); ok {
		return equivalent.UploadSnapshotWithEquivalentManifest(ctx, id, ciphertext, manifestBytes, func(existingBytes []byte) bool {
			existing, err := store.OpenManifest(existingBytes, g.OperationalKey)
			if err != nil {
				return false
			}
			vault := store.New("", g.OperationalKey, g.SigningKey)
			pub := g.SigningKey.Public().(ed25519.PublicKey)
			if vault.VerifySnapshot(manifest, ciphertext, pub) != nil || vault.VerifySnapshot(existing, ciphertext, pub) != nil {
				return false
			}
			candidatePlain, err := json.Marshal(manifest)
			if err != nil {
				return false
			}
			existingPlain, err := json.Marshal(existing)
			return err == nil && bytes.Equal(candidatePlain, existingPlain)
		})
	}
	if atomic, ok := p.(provider.AtomicSnapshotProvider); ok {
		return atomic.UploadSnapshot(ctx, id, ciphertext, manifestBytes)
	}
	if err := p.Upload(ctx, id, ciphertext); err != nil {
		return err
	}
	return p.UploadCatalog(ctx, id, manifestBytes)
}

func verifyPrivate(ctx context.Context, p provider.Provider) error {
	verifier, ok := p.(provider.PrivateVerifier)
	if !ok {
		return nil
	}
	if err := verifier.VerifyPrivate(ctx); err != nil {
		return fmt.Errorf("private repository verification required before upload: %w", err)
	}
	return nil
}

func (g UploadGate) verify(_ context.Context, shares []recovery.Share) error {
	operational, signing, err := store.RecoverKeys(shares)
	if err != nil || subtle.ConstantTimeCompare(operational, g.OperationalKey) != 1 || subtle.ConstantTimeCompare(signing, g.SigningKey) != 1 {
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
