# Cifrarium MVP design

Status: implementation baseline, subject to security review.

## Goals and boundaries

Cifrarium is a Linux-first, single-user, local vault for portable configuration. It captures only explicit allowlists for Codex, Oh My Zsh, and Starship, stores encrypted snapshots, and uses GitHub through native Git as the first remote provider. The daemon is the only component allowed to perform sync. The MVP does not install dependencies, inspect application state, expose remote MCP, support multiple users, or implement non-GitHub providers.

## Threat model

The design protects configuration contents, filenames, catalog metadata, recovery shares, and remote Git history from a stolen disk, remote-provider reader, or untrusted local process without the Unix socket credentials. It does not protect a compromised user account, a running process with access to the keyring, or a user who intentionally grants the daemon access. Plaintext is kept in memory only during capture/restore and temporary files are created with mode 0600.

## Cryptographic envelope

Each snapshot is serialized as a deterministic sequence of records and encrypted with a fresh 32-byte random data key using AES-256-GCM. The data key is wrapped by the operational key using AES-256-GCM with a distinct random nonce. The operational key is stored in the Linux Secret Service/keyring under service `cifrarium`, account derived from the current UID. A separate Ed25519 signing key is stored in the same keyring entry namespace. The external fingerprint is SHA-256 of the public signing key; private keys and keyring payloads are never placed in the catalog.

The catalog is encrypted as a regular snapshot and each entry contains the previous entry hash, snapshot hash, creation time, schema version, and signer fingerprint. Verification rejects an invalid signature, broken chain, duplicate sequence, or rollback to a catalog entry older than the active head.

## Recovery

The operational key is split with Shamir secret sharing into three text shares with threshold two. Before a remote upload, the user must successfully reconstruct the key with two distinct shares and an explicit verification step. Shares contain only an encoded index and share bytes; labels and SHA-256 fingerprints are safe to record in local metadata. One share never recovers the key. Recovery imports shares into a new keyring entry and never requires the old machine.

## Storage and provider contract

The provider interface is capability-oriented: upload, catalog upload, list, download, catalog download, and health. Snapshot IDs, ciphertext, and signed manifests are opaque to providers. The Git provider uses a private repository, a local temporary Git checkout, atomic file writes, and commits that contain only encrypted objects and signed manifests. Provider reads verify the local signature and catalog chain before activation. Future providers must implement the same opaque-object contract and must not receive plaintext.

## Adapters and consistency

Adapters return canonical paths and bytes from explicit allowlists. Codex includes `config.toml` and allowlisted instruction files, never `auth.json`, logs, history, databases, or caches. Oh My Zsh includes `.zshrc`, optional `.zprofile`, and `~/.oh-my-zsh/custom`, excluding the framework and installed plugins. Starship includes only `~/.config/starship.toml`. Files are opened with `O_NOFOLLOW`; symlinked files are rejected. A capture reads each file twice and retries when content changes.

## Restore and daemon

Restore writes a same-filesystem temporary tree, rejects traversal and symlink targets, renames existing files into a local backup, then activates staged files. On an activation failure it restores files already moved. The user daemon has a systemd user unit, a six-hour scheduler contract, retry/backoff, an encrypted bounded queue of at most 16 pending objects, recovery-snapshot triggering after a missed cycle, and incident notification deduplication. Wiring the scheduler into the installed service remains rollout work.

## MCP boundary

MCP binds to a mode-0600 Unix socket owned by the user. Requests are JSON-RPC-like messages mediated by the daemon. `status`, `snapshot.plan`, and `restore.plan` are read/plan operations. No MCP method mutates the vault or starts an upload; CLI confirmation is required.

## Verification and rollout

Unit tests cover all recovery pairs, one-share rejection, tampering, catalog rollback, unstable reads, path traversal, symlink rejection, atomic restore failure, queue limits, revoked Git identity, and provider rollback. `go test -race ./...`, `go vet ./...`, `go build ./...`, `git diff --check`, a secret scan, and an MCP handshake are release gates. Rollout is local-only first, then an opt-in GitHub provider after recovery verification. Public release requires separate domain/brand clearance and human approval.

## Decisions left explicit

Key rotation and historical re-encryption, the exact systemd install UX, and provider migration UX remain implementation decisions behind the interfaces. They must not weaken the rule that all provider data is ciphertext and that recovery is verified before first upload.
