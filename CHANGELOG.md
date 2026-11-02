# Changelog

All notable changes to Cifrarium will be documented here.

## [Unreleased]

### Added

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
