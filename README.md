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
- Catalog manifests are encrypted at rest and in the provider; signatures are verified only after local decryption.
- Git provider snapshots include their signed catalog manifest; downloads can reject stale heads and hash/signature tampering.
- Verified remote snapshots can be restored through the staged local restore path with backup creation.

Remote upload is guarded by explicit two-share recovery verification. Restore stages a complete tree, rejects traversal and symlink targets, and preserves a local backup. The daemon command now loads/saves the encrypted queue, runs an initial cycle and pending drain, starts the six-hour scheduler and local MCP socket, and accepts an explicitly configured Git provider. `-provider-remote` accepts only an HTTPS GitHub URL without embedded credentials; repository creation and token provisioning remain operator actions. Do not store `auth.json`, logs, caches, databases, or shell history in the vault.

Use `-command=recovery-shares` to print three recovery shares for the current keyring. On a fresh environment, import exactly two with `-command=recover -recovery-share label:value` repeated twice, then run `status` to verify the signed vault chain. Treat these shares as secrets; Cifrarium never stores them in the vault or remote provider.

If upgrading a pre-encryption development vault, run `-command=migrate-catalog` once and then `status`. The migration verifies the complete signed chain and snapshot hashes before replacing plaintext catalog metadata with encrypted envelopes.

Provider health performs a read-only `git ls-remote` probe when a GitHub remote is configured. Authentication remains Git's responsibility; failures identify repository or token access problems without embedding or storing credentials. Provider migration transfers only encrypted objects and signed manifests.

Run `-command=provider-health -provider-dir PATH -provider-remote https://github.com/OWNER/REPO.git` to validate the configured remote. The command delegates authentication to Git and prints only the provider, remote URL, and status.

Install the user service with `scripts/install-systemd-user.sh`; this installs the unit without starting it. Before `--enable`, create `~/.config/cifrarium/daemon.env` with mode `0600`, containing `CIFRARIUM_PROVIDER_DIR`, `CIFRARIUM_PROVIDER_REMOTE`, and exactly two `CIFRARIUM_RECOVERY_SHARE_1/2` values. Treat that file as secret material; the installer never creates it or copies shares.

```sh
go test ./...
go run ./cmd/cifrarium -command=status
go run ./cmd/cifrarium -command=snapshot
```
