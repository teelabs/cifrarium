package restore

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/store"
)

type VerifiedSnapshot = store.VerifiedSnapshot
type VerifiedHistory = store.VerifiedHistory
type HistoryInspection = store.RemoteHistoryInspection

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
