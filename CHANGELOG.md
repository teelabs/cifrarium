# Changelog

All notable changes to Cifrarium will be documented here.

## [Unreleased]

### Added

- Synchronized the canonical design with the implemented systemd daemon wiring; documentation-only change, `VERSION` remains `0.3.0`.
- Added versioned recovery shares that restore both the operational and signing keys on a fresh environment, with explicit `recovery-shares` and `recover` CLI commands.
- Added explicit historical restore APIs anchored to the verified local catalog chain and a deterministic mid-activation rollback test seam.
- Added read-only GitHub remote access diagnostics and opaque provider migration through the atomic snapshot capability.
- Encrypted local and provider catalog manifests with the operational-key envelope while retaining Ed25519 verification after decryption.
- Added explicit `migrate-catalog` conversion for verified pre-encryption catalog metadata before normal vault opening.
- Added MCP boundary regression coverage for private socket permissions and mutation rejection; version remains 0.3.0 because this is test-only hardening.
- Added a provider-health CLI command that validates the configured GitHub remote without loading or printing credentials.
- Added an opt-in systemd user installer and CI syntax gate; installation does not activate the daemon unless `--enable` is supplied.
- Added systemd environment-file wiring for provider configuration and explicitly supplied recovery shares, with restrictive service umask and no-new-privileges.
- Added opt-in GitHub privacy verification through the operator's `gh` authentication without passing tokens to Cifrarium.
- Hardened restore against symlinked intermediate directories and symlinked restore roots, with adversarial regression coverage.
- Recorded a primary-source brand and namespace preflight; no legal clearance is claimed. Documentation-only change; `VERSION` remains `0.3.0`.
- Recorded the red-team evidence matrix and explicit security/release residuals; documentation-only change, `VERSION` remains `0.3.0`.
- Hardened adapter capture with two-pass stable reads, bounded retries, and `O_NOFOLLOW`; `VERSION` remains `0.3.0` pending release classification.
- Added the allowlisted Codex `~/.codex/AGENTS.md` instructions file alongside `config.toml`; sensitive Codex state remains excluded. `VERSION` remains `0.3.0`.
- Wired missed-cycle recovery snapshots into the real daemon and queued them for encrypted provider delivery, preserving catalog continuity; `VERSION` remains `0.3.0` pending release classification.
- Hardened keyring startup so only `ErrNotFound` initializes new keys; backend failures now stop with an actionable error. `VERSION` remains `0.3.0` pending release classification.
- Fixed Oh My Zsh custom capture to recurse through regular files while skipping hidden entries and rejecting symlinks. `VERSION` remains `0.3.0` pending release classification.
- Hardened Git provider reads and writes against symlinked `objects` and `catalog` paths. `VERSION` remains `0.3.0` pending release classification.
- Hardened Git provider reads against a symlinked checkout root. `VERSION` remains `0.3.0` pending release classification.
- Added the operator GitHub provisioning runbook with repository-scoped token permissions and pre-upload privacy/recovery gates. Documentation-only; `VERSION` remains `0.3.0`.
- Hardened recovery import to verify reconstructed keys against the existing signed vault chain before changing the keyring; `VERSION` remains `0.3.0` pending release classification.

### Fixed

- Restore rollback now removes newly activated files before restoring pre-existing files when a later activation fails; `VERSION` remains `0.3.0` pending release classification.
- `Vault.Save` now rolls back snapshot, catalog, and head files when a write or keyring-head update fails; `VERSION` remains `0.3.0` pending release classification.
- Git uploads now require a successful private-repository verifier before writing remote ciphertext; `VERSION` remains `0.3.0` pending release classification.

### Changed

- Routed allowed MCP status and plan methods through a daemon-supplied handler with structured read-only results; `VERSION` remains `0.3.0` pending release classification.
- Refreshed the red-team report to the reconciled `main` commit and current CI evidence, including the latest restore, save, and MCP security slices; documentation-only, `VERSION` remains `0.3.0`.
- Refreshed the red-team report with the mandatory provider privacy gate and current `main`/CI evidence; documentation-only, `VERSION` remains `0.3.0`.

## [0.3.0] - 2026-11-02

### Added

- Six-hour daemon scheduler contract with retry/backoff, encrypted pending queue integration, recovery snapshot trigger, and incident deduplication.
- Incident deduplication is bounded to prevent unbounded memory growth.
- Wired the daemon command to encrypted queue persistence, initial snapshot/drain cycles, configured Git uploads, recovery-share gating, signal shutdown, and the local MCP socket.
- Added safe Git provider initialization and HTTPS GitHub remote validation without embedded credentials.
- Added signed catalog persistence, restart verification, snapshot hash checks, and explicit current-head rollback rejection.
- Added a keyring-backed catalog head guard to reject replay of an older valid local head.
- Providers now transport signed catalog manifests alongside encrypted snapshot objects, with verified download helpers.
- Git provider uploads ciphertext and its manifest in one commit/push when the atomic capability is available.
- Verified remote restore now decrypts and applies records through the existing atomic local restore path.

## [0.2.1] - 2026-11-02

### Security

- Replaced the broad HashiCorp Vault dependency used for recovery shares with a dedicated pure-Go secret-sharing module.
- Reject duplicate recovery share indexes before interpolation.

## [0.2.0] - 2026-11-02

### Added

- Initial encrypted local vault core, 2-of-3 recovery, configuration adapters, and CLI scaffold.
- Transactional restore staging with traversal/symlink defenses, bounded daemon queue, and recovery-gated provider uploads.
- MCP initialize handshake regression coverage.
- Canonical security design document for the MVP.
