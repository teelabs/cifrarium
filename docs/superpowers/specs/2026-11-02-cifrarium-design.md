# Cifrarium MVP design

Status: implementation baseline, subject to security review.

## Goals and boundaries

Cifrarium is a Linux-first, single-user, local vault for portable configuration. It captures only explicit allowlists for Codex, Oh My Zsh, and Starship, stores encrypted snapshots, and uses GitHub through native Git as the first remote provider. The daemon is the only component allowed to perform sync. The MVP does not install dependencies, inspect application state, expose remote MCP, support multiple users, or implement non-GitHub providers.

## Threat model

The design protects configuration contents, filenames, catalog metadata, recovery shares, and remote Git history from a stolen disk, remote-provider reader, or untrusted local process without the Unix socket credentials. It does not protect a compromised user account, a running process with access to the keyring, or a user who intentionally grants the daemon access. Plaintext is kept in memory only during capture/restore and temporary files are created with mode 0600.

## Cryptographic envelope

Each snapshot is serialized as a deterministic sequence of records and encrypted with a fresh 32-byte random data key using AES-256-GCM. The data key is wrapped by the operational key using AES-256-GCM with a distinct random nonce. The operational key is stored in the Linux Secret Service/keyring under service `cifrarium`, account derived from the current UID. A separate Ed25519 signing key is stored in the same keyring entry namespace. The external fingerprint is SHA-256 of the public signing key; private keys and keyring payloads are never placed in the catalog.

The catalog is encrypted with the same AES-256-GCM operational-key envelope as snapshot payloads. Each decrypted entry contains the previous entry hash, snapshot hash, creation time, schema version, and signer fingerprint; its Ed25519 signature is verified after decryption. Verification rejects an invalid envelope/signature, broken chain, duplicate sequence, or rollback to a catalog entry older than the active head. The explicit `migrate-catalog` command verifies a pre-encryption plaintext chain and all snapshot hashes before sealing it; normal vault opening has no plaintext fallback. Normal remote restore accepts only the active head; an explicit historical restore must identify an entry already anchored in the verified local chain and never changes the write head.

## Recovery

The operational key and the Ed25519 signing private key are encoded in a versioned recovery bundle, then split with Shamir secret sharing into three text shares with threshold two. The `recovery-shares` CLI command emits the three opaque `label:value` shares; the `recover` command accepts exactly two and replaces the local keyring entry. Before a remote upload, the user must successfully reconstruct the operational key with two distinct shares and an explicit verification step. Shares contain only encoded indexes and share bytes; labels and SHA-256 fingerprints are safe to record in local metadata. One share never recovers the bundle. Recovery never requires the old machine and resets the keyring catalog-head guard, which is re-established only after the signed local chain is verified.

## Storage and provider contract

The provider interface is capability-oriented: upload, catalog upload, list, download, catalog download, and health. Snapshot IDs, ciphertext, and signed manifests are opaque to providers. The Git provider uses a private repository, a local temporary Git checkout, atomic file writes, and commits that contain only encrypted objects and signed manifests. Its read-only remote probe reports actionable repository/token access failures while leaving credentials to Git; an opt-in `gh api` check verifies the repository privacy flag without passing tokens through Cifrarium. Migration copies ciphertext and manifests through the same contract, using atomic upload when available, and never decrypts data. Provider reads verify the local signature and catalog chain before activation. Future providers must implement the same opaque-object contract and must not receive plaintext.

## Adapters and consistency

Adapters return canonical paths and bytes from explicit allowlists. Codex includes `config.toml` and allowlisted instruction files, never `auth.json`, logs, history, databases, or caches. Oh My Zsh includes `.zshrc`, optional `.zprofile`, and `~/.oh-my-zsh/custom`, excluding the framework and installed plugins. Starship includes only `~/.config/starship.toml`. Files are opened with `O_NOFOLLOW`; symlinked files are rejected. A capture reads each file twice and retries when content changes.

## Restore and daemon

Restore writes a same-filesystem temporary tree, rejects traversal and symlink targets, renames existing files into a local backup, then activates staged files. On an activation failure it restores files already moved; a deterministic rename seam proves this partial-activation rollback. The user daemon has a systemd user unit, a six-hour scheduler contract, retry/backoff, an encrypted bounded queue of at most 16 pending objects, recovery-snapshot triggering after a missed cycle, and incident notification deduplication. Wiring the scheduler into the installed service remains rollout work.

## MCP boundary

MCP binds to a mode-0600 Unix socket owned by the user. Requests are JSON-RPC-like messages mediated by the daemon. `status`, `snapshot.plan`, and `restore.plan` are read/plan operations. No MCP method mutates the vault or starts an upload; CLI confirmation is required.

## Verification and rollout

Unit tests cover all recovery pairs, one-share rejection, tampering, catalog rollback, unstable reads, path traversal, symlink rejection, atomic restore failure, queue limits, revoked Git identity, and provider rollback. `go test -race ./...`, `go vet ./...`, `go build ./...`, `git diff --check`, a secret scan, and an MCP handshake are release gates. Rollout is local-only first, then an opt-in GitHub provider after recovery verification. Public release requires separate domain/brand clearance and human approval.

## Decisions left explicit

Key rotation and historical re-encryption, the exact systemd install UX, and provider migration UX remain implementation decisions behind the interfaces. They must not weaken the rule that all provider data is ciphertext and that recovery is verified before first upload.
