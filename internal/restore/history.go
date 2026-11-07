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

// VerifyRemoteHistory downloads provider objects and delegates full chain,
// signature, hash, and decryption verification to the store boundary.
func VerifyRemoteHistory(ctx context.Context, source provider.Provider, operational []byte, signing ed25519.PrivateKey) (VerifiedHistory, error) {
	ids, err := source.List(ctx)
	if err != nil {
		return VerifiedHistory{}, fmt.Errorf("list remote snapshots: %w", err)
	}
	remote := make([]store.RemoteSnapshot, 0, len(ids))
	for _, id := range ids {
		ciphertext, err := source.Download(ctx, id)
		if err != nil {
			return VerifiedHistory{}, fmt.Errorf("download remote snapshot: %w", err)
		}
		catalog, err := source.DownloadCatalog(ctx, id)
		if err != nil {
			return VerifiedHistory{}, fmt.Errorf("download remote catalog: %w", err)
		}
		remote = append(remote, store.RemoteSnapshot{ID: id, Ciphertext: ciphertext, Catalog: catalog})
	}
	history, err := store.VerifyRemoteHistory(remote, operational, signing)
	if err != nil {
		return VerifiedHistory{}, err
	}
	return history, nil
}
