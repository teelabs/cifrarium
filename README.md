# cifrarium
Local, portable encrypted configuration vault with CLI, daemon, and local MCP integration.

## Current baseline

The repository contains the MVP security design and a testable Go core:

- AES-256-GCM envelopes with a fresh data key per snapshot.
- Linux keyring-backed operational and Ed25519 signing keys.
- Shamir 2-of-3 recovery primitives with pair coverage tests.
- Explicit Codex, Oh My Zsh, and Starship adapters that reject symlinks and sensitive paths.
- Opaque Git provider contract and local Git implementation.
- Mode-0600 local MCP socket exposing status and plan-only methods.
- Signed catalog manifests persist across restarts and verify the snapshot hash chain before activation.

Remote upload is guarded by explicit two-share recovery verification. Restore stages a complete tree, rejects traversal and symlink targets, and preserves a local backup. The daemon command now loads/saves the encrypted queue, runs an initial cycle and pending drain, starts the six-hour scheduler and local MCP socket, and accepts an explicitly configured Git provider. `-provider-remote` accepts only an HTTPS GitHub URL without embedded credentials; repository creation and token provisioning remain operator actions. Do not store `auth.json`, logs, caches, databases, or shell history in the vault.

```sh
go test ./...
go run ./cmd/cifrarium -command=status
go run ./cmd/cifrarium -command=snapshot
```
