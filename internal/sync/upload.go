package sync

import (
	"context"
	"fmt"

	"github.com/teelabs/cifrarium/internal/provider"
	"github.com/teelabs/cifrarium/internal/recovery"
)

type UploadGate struct{ OperationalKey []byte }

// Upload refuses to call a provider until two distinct recovery shares
// reconstruct the exact operational key currently used by the vault.
func (g UploadGate) Upload(ctx context.Context, p provider.Provider, id string, ciphertext []byte, shares []recovery.Share) error {
	key, err := recovery.Combine(shares)
	if err != nil || string(key) != string(g.OperationalKey) {
		return fmt.Errorf("recovery verification required before upload")
	}
	return p.Upload(ctx, id, ciphertext)
}
