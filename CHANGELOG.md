# Changelog

All notable changes to Cifrarium will be documented here.

## [Unreleased]

## [0.3.0] - 2026-11-02

### Added

- Six-hour daemon scheduler contract with retry/backoff, encrypted pending queue integration, recovery snapshot trigger, and incident deduplication.
- Incident deduplication is bounded to prevent unbounded memory growth.
- Wired the daemon command to encrypted queue persistence, initial snapshot/drain cycles, configured Git uploads, recovery-share gating, signal shutdown, and the local MCP socket.
- Added safe Git provider initialization and HTTPS GitHub remote validation without embedded credentials.
- Added signed catalog persistence, restart verification, snapshot hash checks, and explicit current-head rollback rejection.

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
