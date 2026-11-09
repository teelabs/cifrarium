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

// InspectRemoteHistory downloads and verifies every branch without selecting
// one. It returns the encrypted selection marker for the caller to validate.
func InspectRemoteHistory(ctx context.Context, source provider.Provider, operational []byte, signing ed25519.PrivateKey) (HistoryInspection, []byte, error) {
	remote, err := downloadHistory(ctx, source)
	if err != nil {
		return HistoryInspection{}, nil, err
	}
	inspection, err := store.InspectRemoteHistory(remote, operational, signing)
	if err != nil {
		return HistoryInspection{}, nil, err
	}
	var marker []byte
	if marked, ok := source.(interface {
		DownloadHistorySelection(context.Context) ([]byte, error)
	}); ok {
		marker, err = marked.DownloadHistorySelection(ctx)
		if err != nil {
			return HistoryInspection{}, nil, fmt.Errorf("read remote history selection: %w", err)
		}
	}
	return inspection, marker, nil
}

// VerifyRemoteHistory downloads provider objects and delegates full chain,
// signature, hash, and decryption verification to the store boundary.
func VerifyRemoteHistory(ctx context.Context, source provider.Provider, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	remote, err := downloadHistory(ctx, source)
	if err != nil {
		return VerifiedHistory{}, err
	}
	var marker []byte
	if marked, ok := source.(interface {
		DownloadHistorySelection(context.Context) ([]byte, error)
	}); ok {
		marker, err = marked.DownloadHistorySelection(ctx)
		if err != nil {
			return VerifiedHistory{}, fmt.Errorf("read remote history selection: %w", err)
		}
	}
	return store.VerifyRemoteHistoryWithSelection(remote, marker, operational, signing)
}

func downloadHistory(ctx context.Context, source provider.Provider) ([]store.RemoteSnapshot, error) {
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
