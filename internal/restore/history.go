package restore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
)

type VerifiedSnapshot = store.VerifiedSnapshot
type VerifiedHistory = store.VerifiedHistory
type HistoryInspection = store.RemoteHistoryInspection

// SnapshotRecoveryHistory is safe for snapshot-only file recovery. Complete
// histories are ordered newest first; incomplete histories contain the
// individually verified objects from the provider's initially staged view,
// sorted by recorded catalog date without implying freshness.
type SnapshotRecoveryHistory struct {
	Snapshots []VerifiedSnapshot
	Complete  bool
}

// HistoryReader exposes only the remote reads needed to verify backup
// history. Verification cannot upload through this interface.
type HistoryReader interface {
	Download(context.Context, string) ([]byte, error)
	DownloadCatalog(context.Context, string) ([]byte, error)
	List(context.Context) ([]string, error)
}

// InspectRemoteHistory downloads and verifies every branch without selecting
// one. It returns the encrypted selection marker for the caller to validate.
func InspectRemoteHistory(ctx context.Context, source HistoryReader, operational []byte, signing ed25519.PrivateKey) (HistoryInspection, []byte, error) {
	remote, err := downloadHistory(ctx, source)
	if err != nil {
		return HistoryInspection{}, nil, err
	}
	resolver := historicalSnapshotResolver(ctx, source)
	inspection, err := store.InspectRemoteHistoryWithResolver(remote, operational, signing, resolver)
	if err != nil {
		return HistoryInspection{}, nil, err
	}
	marker, err := downloadHistorySelection(ctx, source)
	if err != nil {
		return HistoryInspection{}, nil, err
	}
	return inspection, marker, nil
}

// VerifyRemoteHistory downloads provider objects and delegates full chain,
// signature, hash, and decryption verification to the store boundary.
func VerifyRemoteHistory(ctx context.Context, source HistoryReader, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	remote, err := downloadHistory(ctx, source)
	if err != nil {
		return VerifiedHistory{}, err
	}
	marker, err := downloadHistorySelection(ctx, source)
	if err != nil {
		return VerifiedHistory{}, err
	}
	return store.VerifyRemoteHistoryWithSelectionResolver(remote, marker, operational, signing, historicalSnapshotResolver(ctx, source))
}

// VerifyRemoteHistoryForSnapshotRecovery retains normal full-history checks,
// but permits explicit snapshot-only recovery when the only verification
// failure is a missing ancestor. Fallback candidates come only from the
// initially staged provider view, and every candidate must independently
// pass catalog, signature, hash, and decryption verification.
func VerifyRemoteHistoryForSnapshotRecovery(ctx context.Context, source HistoryReader, operational []byte, signing ed25519.PrivateKey) (SnapshotRecoveryHistory, error) {
	remote, err := downloadHistory(ctx, source)
	if err != nil {
		return SnapshotRecoveryHistory{}, err
	}
	marker, err := downloadHistorySelection(ctx, source)
	if err != nil {
		return SnapshotRecoveryHistory{}, err
	}
	history, err := store.VerifyRemoteHistoryWithSelectionResolver(remote, marker, operational, signing, historicalSnapshotResolver(ctx, source))
	if err == nil {
		return SnapshotRecoveryHistory{Snapshots: append([]VerifiedSnapshot(nil), history.Entries...), Complete: true}, nil
	}
	var missing *store.MissingHistorySnapshotsError
	if !errors.As(err, &missing) {
		return SnapshotRecoveryHistory{}, err
	}
	snapshots, verifyErr := store.VerifyRemoteSnapshots(remote, operational, signing)
	if verifyErr != nil {
		return SnapshotRecoveryHistory{}, verifyErr
	}
	sortSnapshotRecoveryCandidates(snapshots)
	return SnapshotRecoveryHistory{Snapshots: snapshots, Complete: false}, nil
}

func sortSnapshotRecoveryCandidates(snapshots []VerifiedSnapshot) {
	sort.Slice(snapshots, func(i, j int) bool {
		left, right := snapshots[i], snapshots[j]
		if !left.Manifest.CreatedAt.Equal(right.Manifest.CreatedAt) {
			return left.Manifest.CreatedAt.After(right.Manifest.CreatedAt)
		}
		return left.ID < right.ID
	})
}

func historicalSnapshotResolver(ctx context.Context, source HistoryReader) store.RemoteSnapshotResolver {
	stager, ok := source.(provider.HistoricalSnapshotStager)
	if !ok {
		return nil
	}
	return func(id string) (store.RemoteSnapshot, bool, error) {
		staged, err := stager.StageHistoricalSnapshots(ctx, []string{id})
		if err != nil {
			return store.RemoteSnapshot{}, false, fmt.Errorf("recover missing remote snapshot history: %w", err)
		}
		if !staged {
			return store.RemoteSnapshot{}, false, nil
		}
		ciphertext, err := source.Download(ctx, id)
		if err != nil {
			return store.RemoteSnapshot{}, false, fmt.Errorf("download recovered remote snapshot: %w", err)
		}
		catalog, err := source.DownloadCatalog(ctx, id)
		if err != nil {
			return store.RemoteSnapshot{}, false, fmt.Errorf("download recovered remote catalog: %w", err)
		}
		return store.RemoteSnapshot{ID: id, Ciphertext: ciphertext, Catalog: catalog}, true, nil
	}
}

func downloadHistorySelection(ctx context.Context, source HistoryReader) ([]byte, error) {
	if marked, ok := source.(interface {
		DownloadHistorySelection(context.Context) ([]byte, error)
	}); ok {
		marker, err := marked.DownloadHistorySelection(ctx)
		if err != nil {
			return nil, fmt.Errorf("read remote history selection: %w", err)
		}
		return marker, nil
	}
	return nil, nil
}

func downloadHistory(ctx context.Context, source HistoryReader) ([]store.RemoteSnapshot, error) {
	ids, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list remote snapshots: %w", err)
	}
	remote := make([]store.RemoteSnapshot, 0, len(ids))
	for _, id := range ids {
		ciphertext, err := source.Download(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("download remote snapshot: %w", err)
		}
		catalog, err := source.DownloadCatalog(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("download remote catalog: %w", err)
		}
		remote = append(remote, store.RemoteSnapshot{ID: id, Ciphertext: ciphertext, Catalog: catalog})
	}
	return remote, nil
}
