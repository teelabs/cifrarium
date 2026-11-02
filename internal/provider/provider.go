package provider

import "context"

// Provider stores opaque encrypted objects. Providers never receive plaintext.
type Provider interface {
	Upload(ctx context.Context, id string, ciphertext []byte) error
	UploadCatalog(ctx context.Context, id string, manifest []byte) error
	Download(ctx context.Context, id string) ([]byte, error)
	DownloadCatalog(ctx context.Context, id string) ([]byte, error)
	List(ctx context.Context) ([]string, error)
	Health(ctx context.Context) error
}
