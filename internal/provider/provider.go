package provider

import (
	"context"
	"fmt"
)

// Provider stores opaque encrypted objects. Providers never receive plaintext.
type Provider interface {
	Upload(ctx context.Context, id string, ciphertext []byte) error
	UploadCatalog(ctx context.Context, id string, manifest []byte) error
	Download(ctx context.Context, id string) ([]byte, error)
	DownloadCatalog(ctx context.Context, id string) ([]byte, error)
	List(ctx context.Context) ([]string, error)
	Health(ctx context.Context) error
}

// CanonicalHistoryProvider exposes an encrypted operator selection marker.
// Implementations must not interpret or log its contents.
type CanonicalHistoryProvider interface {
	DownloadHistorySelection(ctx context.Context) ([]byte, error)
	UploadHistorySelection(ctx context.Context, marker []byte) error
}

// HistoricalSnapshotStager can recover exact snapshot IDs referenced by a
// verified catalog from commits reachable from the provider's configured
// default branch. Implementations stage data locally and never write remotely.
type HistoricalSnapshotStager interface {
	StageHistoricalSnapshots(ctx context.Context, ids []string) (bool, error)
}

// CanonicalSnapshotProvider atomically advances a selected history marker with
// the new encrypted snapshot, guarded by the remote revision that was read.
type CanonicalSnapshotProvider interface {
	ReadRemoteHistorySelection(ctx context.Context) (marker []byte, revision string, err error)
	UploadSnapshotWithHistorySelection(ctx context.Context, id string, ciphertext, manifest, marker []byte, expectedRevision string) error
}
type AtomicSnapshotProvider interface {
	UploadSnapshot(ctx context.Context, id string, ciphertext, manifest []byte) error
}

// EquivalentManifestSnapshotProvider may treat an existing encrypted catalog
// object as the same upload only after the caller verifies its plaintext
// manifest. Providers must also prove that the existing snapshot object is
// byte-identical before accepting this equivalence.
type EquivalentManifestSnapshotProvider interface {
	UploadSnapshotWithEquivalentManifest(ctx context.Context, id string, ciphertext, manifest []byte, equivalent func([]byte) bool) error
}

// PrivateVerifier is implemented by providers whose remote visibility is a
// confidentiality boundary. Upload orchestration must verify it before any
// ciphertext is written remotely.
type PrivateVerifier interface {
	VerifyPrivate(ctx context.Context) error
}

// Migrate copies opaque provider objects without decrypting or interpreting
// their contents. The destination's atomic capability is used when present.
func Migrate(ctx context.Context, source, destination Provider, ids []string) error {
	if err := verifyDestinationPrivacy(ctx, destination); err != nil {
		return err
	}
	for _, id := range ids {
		if err := validateID(id); err != nil {
			return err
		}
		ciphertext, err := source.Download(ctx, id)
		if err != nil {
			return fmt.Errorf("download snapshot %s: %w", id, err)
		}
		manifest, err := source.DownloadCatalog(ctx, id)
		if err != nil {
			return fmt.Errorf("download catalog %s: %w", id, err)
		}
		if atomic, ok := destination.(AtomicSnapshotProvider); ok {
			if err := atomic.UploadSnapshot(ctx, id, ciphertext, manifest); err != nil {
				return fmt.Errorf("upload snapshot %s: %w", id, err)
			}
			continue
		}
		if err := destination.Upload(ctx, id, ciphertext); err != nil {
			return fmt.Errorf("upload snapshot %s: %w", id, err)
		}
		if err := destination.UploadCatalog(ctx, id, manifest); err != nil {
			return fmt.Errorf("upload catalog %s: %w", id, err)
		}
	}
	return nil
}

func verifyDestinationPrivacy(ctx context.Context, destination Provider) error {
	verifier, ok := destination.(PrivateVerifier)
	if !ok {
		return fmt.Errorf("provider migration requires an explicit destination privacy verifier")
	}
	if err := verifier.VerifyPrivate(ctx); err != nil {
		return fmt.Errorf("destination privacy verification failed: %w", err)
	}
	return nil
}
