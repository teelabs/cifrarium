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
type AtomicSnapshotProvider interface {
	UploadSnapshot(ctx context.Context, id string, ciphertext, manifest []byte) error
}

// Migrate copies opaque provider objects without decrypting or interpreting
// their contents. The destination's atomic capability is used when present.
func Migrate(ctx context.Context, source, destination Provider, ids []string) error {
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
