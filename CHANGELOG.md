# Changelog

All notable changes to Cifrarium will be documented here.

## [Unreleased]

### Changed

- Improved the Linux installer preflight to audit all operation-specific
  dependencies together, print package-manager guidance, and show progress for
  each verification and installation stage.

## [0.5.1] - 2026-11-03

### Fixed

- Made the guided setup regression test independent of the host Secret Service
  keyring, so release CI validates the non-interactive contract consistently.

## [0.5.0] - 2026-11-03

### Added

- Added the guided `cifrarium setup` wizard with TTY-based prompts for recovery
  shares, private backup preparation, first capture, and daemon activation.
- Added explicit `--non-interactive` behavior that does not display recovery
  shares, capture data, upload remotely, or enable the daemon.

### Changed

- Expanded the README into the operational entry point for signed Linux
  installation, prerequisites, first snapshot ingestion, recovery-share
  handling, GitHub provider setup, daemon activation, troubleshooting, and
  human/agent safety guidance.

### Fixed

- The standalone installer now resolves the published manifest version when no
  version is supplied and starts the guided setup only when a terminal exists.

## [0.4.0] - 2026-11-03

### Added

- Added the Cloudflare Pages installer-channel bootstrap for project
  `usecifrarium`. The first bundle is status-only and intentionally does not
  publish an executable installer.
- Added a versioned Linux installer contract and release builder for signed
  `amd64` and `arm64` artifacts, with explicit verification, atomic activation,
  rollback, uninstall, and opt-in daemon enablement.

## [0.3.1] - 2026-11-02

### Security

- Hardened Git/provider execution against repository hooks, unsafe inherited
  configuration, unsafe local transport settings,
  credential/recovery-share leakage, path-component symlink races, and
  unverified migration destinations.
- Made already-committed Git snapshot retries idempotent and documented the
  remaining crash-consistency boundary for multi-file restore.
- Added guarded, serialized recovery import and bounded validation for captured
  files, snapshots, manifests, queue items, restore records, and MCP request
  lines.
- Surfaced daemon initialization, persistence, retry, and MCP listener failures
  instead of silently treating failed work as healthy.

### Added

- Added the [human user guide](docs/USER-GUIDE.md), the detailed
  [agent operating contract](docs/AGENT-USAGE.md), and root [agent routing
  instructions](AGENTS.md) with setup, provider, daemon, recovery, failure,
  and scenario examples.
- Documented the accepted threat-model boundary: restored plaintext and
  user-owned recovery material are not protected from a compromised same-user
  process, and GitHub visibility checks are operational rather than atomic.

- Added the initial versioned Cifrarium visual identity proposal with four SVG directions and usage guidance; legal clearance remains tracked separately in [issue #49](https://github.com/teelabs/cifrarium/issues/49) and [`VERSION`](VERSION) remains `0.3.0`.
- Refreshed the [red-team report](docs/security/2026-11-02-red-team-review.md) to the reconciled `main` commit and post-merge CI evidence after the visual identity slice; documentation-only change, [`VERSION`](VERSION) remains `0.3.0`.
- Refreshed the [red-team report](docs/security/2026-11-02-red-team-review.md) to the restore-hardening `main` commit and post-merge CI evidence; documentation-only change, [`VERSION`](VERSION) remains `0.3.0`.
- Synchronized the [canonical design](docs/superpowers/specs/2026-11-02-cifrarium-design.md) with the implemented systemd daemon wiring; documentation-only change, [`VERSION`](VERSION) remains `0.3.0`.
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
- Recorded the [primary-source brand and namespace preflight](docs/research/2026-11-02-cifrarium-brand-clearance.md); no legal clearance is claimed. Documentation-only change; [`VERSION`](VERSION) remains `0.3.0`.
- Recorded the [red-team evidence matrix](docs/security/2026-11-02-red-team-review.md) and explicit security/release residuals; documentation-only change, [`VERSION`](VERSION) remains `0.3.0`.
- Hardened adapter capture with two-pass stable reads, bounded retries, and `O_NOFOLLOW`; [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Added the allowlisted Codex `~/.codex/AGENTS.md` instructions file alongside `config.toml`; sensitive Codex state remains excluded. [`VERSION`](VERSION) remains `0.3.0`.
- Wired missed-cycle recovery snapshots into the real daemon and queued them for encrypted provider delivery, preserving catalog continuity; [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Hardened keyring startup so only `ErrNotFound` initializes new keys; backend failures now stop with an actionable error. [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Fixed Oh My Zsh custom capture to recurse through regular files while skipping hidden entries and rejecting symlinks. [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Hardened Git provider reads and writes against symlinked `objects` and `catalog` paths. [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Hardened Git provider reads against a symlinked checkout root. [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Added the operator [GitHub provisioning runbook](docs/runbooks/github-provider-provisioning.md) with repository-scoped token permissions and pre-upload privacy/recovery gates. Documentation-only; [`VERSION`](VERSION) remains `0.3.0`.
- Hardened recovery import to verify reconstructed keys against the existing signed vault chain before changing the keyring; [`VERSION`](VERSION) remains `0.3.0` pending release classification.

### Fixed

- Hardened Linux production restore with descriptor-relative `openat2`/`renameat2` operations and fail-closed unsupported-platform behavior; [`VERSION`](VERSION) remains `0.3.0` pending release classification.

- Restore rollback now removes newly activated files before restoring pre-existing files when a later activation fails; [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- `Vault.Save` now rolls back snapshot, catalog, and head files when a write or keyring-head update fails; [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Git uploads now require a successful private-repository verifier before writing remote ciphertext; [`VERSION`](VERSION) remains `0.3.0` pending release classification.

### Changed

- Clarified that Cifrarium is a general application-configuration vault and that Codex, Oh My Zsh, and Starship are initial adapters; documentation-only, [`VERSION`](VERSION) remains `0.3.0`.
- Streamlined the [README](README.md) around project usage and interaction, and clarified the separate recovery-share environment variables in the [GitHub provider provisioning runbook](docs/runbooks/github-provider-provisioning.md); documentation-only, [`VERSION`](VERSION) remains `0.3.0`.
- Routed allowed MCP status and plan methods through a daemon-supplied handler with structured read-only results; [`VERSION`](VERSION) remains `0.3.0` pending release classification.
- Refreshed the [red-team report](docs/security/2026-11-02-red-team-review.md) to the reconciled `main` commit and current CI evidence, including the latest restore, save, and MCP security slices; documentation-only, [`VERSION`](VERSION) remains `0.3.0`.
- Refreshed the [red-team report](docs/security/2026-11-02-red-team-review.md) with the mandatory provider privacy gate and current `main`/CI evidence; documentation-only, [`VERSION`](VERSION) remains `0.3.0`.

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
