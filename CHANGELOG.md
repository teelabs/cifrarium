# Changelog

All notable changes to Cifrarium will be documented here.

## [Unreleased]

## [0.14.2] - 2026-11-10

### Fixed

- Show safe progress during recovery-share validation, remote backup staging
  and verification, restore preflight, and file application; classify invalid
  catalogs and snapshot integrity or decryption failures without exposing raw
  verification details.

## [0.14.1] - 2026-11-09

### Fixed

- Restore required ancestor snapshots from commits reachable on the configured
  private provider branch when they are absent from its current tree, without
  writing recovered objects back to the provider.

## [0.14.0] - 2026-11-09

### Added

- Inspect every verified private backup branch and interactively select a
  canonical branch anchored to the current local vault head. The encrypted,
  signed selection preserves all snapshots and branches; future snapshots
  advance the selection atomically with their encrypted object and catalog.

## [0.13.1] - 2026-11-06

### Fixed

- Enumerate staged provider directories through readable, descriptor-anchored
  handles and verify entries without following symlinks, allowing restore to
  validate remote snapshot history on Linux.
- Explain when remote backup history has multiple branches or no unique head;
  stop without writing local recovery state instead of choosing a history.

## [0.13.0] - 2026-11-06

### Added

- Restore selected adapter files interactively from a verified private GitHub
  snapshot history on a new machine using two recovery shares, with safe
  destination preflight, private backups, conflict choices, and the daemon left
  disabled.

### Changed

- Document the new-machine restore flow, its freshness limit, and the read-only
  MCP boundary.

## [0.12.0] - 2026-11-06

### Added

- Add a read-only snapshot audit command and MCP method that compare current
  allowlisted adapter files with the latest verified snapshot without
  persisting vault or provider state.

### Fixed

- Escape terminal control characters in audited paths.
- Bound read-only installer doctor preflight by the release version embedded in
  its signed installer instead of a manually growing version list.

## [0.11.0] - 2026-11-06

### Added

- Skip writing a new encrypted snapshot when canonical captured records match
  the current head, using authenticated private metadata inside the encrypted
  manifest; reuse exact stored artifacts for provider repair, preserve verified
  legacy manifest bytes on Git remotes, and identify the no-op result in CLI
  output.
- Make retries for identical queued snapshot artifacts idempotent while
  rejecting conflicting content for an existing snapshot ID.

### Fixed

- Recognize the 0.11 release line as using the safe JSON doctor interface so
  subsequent upgrades retain their root and keyring preflight.

## [0.10.8] - 2026-11-05

### Fixed

- Use a stable Cifrarium commit identity for provider uploads when an existing
  local Git checkout has no configured author, without changing local Git
  configuration; isolate upload commits from staged files and unpublished local
  history while preserving retry idempotency.

## [0.10.7] - 2026-11-05

### Fixed

- Distinguish failures while draining pending uploads, uploading a new snapshot,
  retaining a failed upload in a full pending queue, and persisting queue
  changes, without exposing raw provider or filesystem errors.

## [0.10.6] - 2026-11-05

### Fixed

- Report daemon backend readiness separately from systemd and MCP transport
  health, and return an actionable message when CLI status or snapshot requests
  are rejected while the backend is starting.
- Preserve safe capture failure stages through recovery-snapshot errors and
  avoid suggesting that an adapter path was reported when no validated path is
  available.

## [0.10.5] - 2026-11-05

### Fixed

- Allow the daemon process started by its own systemd unit to initialize while
  continuing to detect other managed instances. Parse named systemd properties
  to report service exits accurately during readiness checks.
- Show the relative allowlisted adapter path and a safe failure category when
  local capture cannot read a configuration file, without printing absolute
  paths or underlying errors.

## [0.10.4] - 2026-11-05

### Fixed

- Allow upgrades when the active doctor confirms a healthy configured vault,
  even if an unrelated system health problem makes its overall exit status
  non-zero. Select the doctor invocation only for known release families,
  reject non-canonical versions and symlinked binaries, and stop if the active
  target changes during preflight; malformed reports and unhealthy
  configuration or vault state still block the upgrade.

## [0.10.3] - 2026-11-05

### Added

- Added an isolated lifecycle audit harness that runs the real installer
  against the same temporary vault, recovery configuration, encrypted queue,
  and in-memory keyring used by the real daemon service/backend. It checks
  byte-for-byte state preservation across preflight, migration, and rollback
  failures, then verifies queued items drain before the post-upgrade capture.

### Fixed

- Validate generated v1 recovery shares against both active keyring keys before
  allowing provider uploads.
- Report MCP and backend readiness separately after daemon refresh, including
  a safe next step while the backend is waiting for recovery/provider setup.
- Resolve systemd's Cifrarium configuration and provider paths from the same
  XDG configuration root used by the CLI and installer.
- Detect a Cifrarium systemd service exit during readiness polling and report
  sanitized state, result, exit status, and a safe recovery step.
- Retry readiness when systemd state cannot be observed, and report an
  unconfirmed state separately from a confirmed service exit.

## [0.10.2] - 2026-11-04

### Fixed

- Managed daemon launches now detect an already active service and return an
  actionable status instead of attempting duplicate listeners.
- `cifrarium daemon refresh` now accepts a ready MCP endpoint while the daemon
  backend is waiting for protected recovery action.

## [0.10.1] - 2026-11-04

### Fixed

- Installer upgrades now accept and preserve the two protected recovery-share
  variables written to `daemon.env` without printing or exposing their values.

## [0.10.0] - 2026-11-04

### Added

- Added a Linux local JSON-RPC control endpoint owned by the daemon, with
  structured errors and a `cifrarium daemon refresh` command that reloads the
  managed service and verifies MCP readiness.

### Changed

- Running CLI status and snapshot operations use the daemon backend when its
  control endpoint is available; bootstrap-compatible direct operation remains
  available when no daemon endpoint exists.
- MCP errors now use structured JSON-RPC error objects while keeping MCP tools
  separate from CLI subcommands.

## [0.9.5] - 2026-11-04

### Fixed

- `cifrarium --help` now lists canonical commands and nested provider/recovery
  forms without exposing configured filesystem paths or provider remotes.
- Daemon pending-upload diagnostics now distinguish recovery verification,
  provider setup, privacy, and access failures with safe next actions.

## [0.9.4] - 2026-11-04

### Fixed

- Initial daemon pending-drain failures now use the safe retry flow instead of
  printing a raw error or appearing stuck.
- Interactive retry asks before waiting, accepts Enter for an immediate retry,
  and returns to the console when declined; non-TTY output remains plain.
- Installer progress updates in place on TTY while redirected output remains
  free of carriage returns and ANSI control sequences.

## [0.9.3] - 2026-11-04

### Fixed

- Daemon capture failures caused by rejected local symlinks now return control
  to the shell after showing one sanitized recovery diagnostic; transient
  provider and upload failures retain queue and retry behavior.
- Human command blocks now have explicit separators and use the approved muted
  Codex-style foreground palette while redirected output, systemd logs, and
  JSON remain free of ANSI color codes.

## [0.9.2] - 2026-11-04

### Fixed

- Corrected daemon symlink diagnostics so compound recovery-snapshot errors do
  not contaminate the validated path or expose raw error details.
- Centralized Codex semantic terminal colors for human output while preserving
  uncolored redirected output and unchanged JSON.

## [0.9.1] - 2026-11-04

### Changed

- Clarified the safe operator procedure for rejected symlinked configuration
  files and added the current v0.9.0 provider-wizard/CLI specification. This
  documentation and daemon diagnostics update.

### Fixed

- Daemon recovery-snapshot failures caused by an allowlisted symlink now print
  the same safe stop-inspect-copy-verify-restart instructions as setup without
  exposing target contents or recovery material.

## [0.9.0] - 2026-11-04

### Added

- Added canonical nested CLI commands (`provider setup`, `provider health`,
  `recovery shares`, and `recovery import`) and removed the legacy
  `-command=` interface.
- Added an interactive provider wizard that validates GitHub access and
  privacy, preserves existing provider settings, and atomically writes the
  protected daemon configuration.

### Changed

- Provider setup now requires explicit confirmation for local configuration,
  recovery-share import or generation, and daemon activation. It never uploads
  a snapshot automatically and never stores credentials.

## [0.8.2] - 2026-11-03

### Changed

- Upgrades preserve the configured vault, keyring, snapshot history, provider
  checkout, and existing recovery shares; setup is idempotent and does not
  rotate or print shares during retries.
- Release metadata declares provider compatibility. Provider migrations are
  staged only and require an explicit operator command before retrying an
  upgrade.

### Added

- Added installer acceptance coverage for valid and failed provider preflights,
  invalid `daemon.env`, explicit migration gating, upgrade retries, and
  preservation of local vault-state sentinels.

### Fixed

- The installer now validates provider configuration and privacy, runs the
  candidate binary preflight before activation, and leaves the previous active
  version in place when a required check fails.

## [0.8.1] - 2026-11-03

### Changed

- Structured human setup, status, and doctor output with separated sections,
  copyable command blocks, TTY-only colors, and immediate contextual feedback
  after each setup decision.

### Fixed

- Made setup capture failures actionable by identifying rejected symlink paths
  and showing a safe local correction command before retrying setup.

## [0.8.0] - 2026-11-03

### Added

- Added a persistent per-user vault-root configuration with restrictive
  permissions, canonical-path and symlink checks, keyring binding, safe
  explicit-root compatibility, and fail-closed alternate-root detection.

### Changed

- Changed setup and the systemd user service to use the configured root, and
  made normal commands root-free after setup while keeping `-format=json` for
  agents.
- Made setup copy English-only and kept non-interactive execution from
  configuring root, capturing data, showing recovery shares, changing a
  provider, or enabling the daemon.

### Fixed

- Fixed setup cancellation and redirected-output handling so configuration,
  keyring, vault capture, and recovery shares are not persisted or leaked
  before interactive confirmation.
- Made `provider-health` read-only and rejected `--non-interactive` for
  stateful, secret-handling, and remote-capable commands.
- Added shell-safe quoting to generated provider commands and aligned the
  systemd XDG configuration default with the CLI.
- Hardened vault and configuration reads with Linux descriptor-relative
  no-symlink resolution immediately at file open.

## [0.7.0] - 2026-11-03

### Added

- Added a read-only `doctor` command that reports vault, keyring, daemon, MCP,
  adapter, and optional GitHub provider health for humans and agents.

### Changed

- Made `status` human-readable by default and added explicit `-format=json`
  output for scripts and automation.

## [0.6.1] - 2026-11-03

### Fixed

- Removed the repeated installer message prefix and drained piped input after
  dependency-preflight failures so `curl | bash` does not report a misleading
  broken-pipe error.

- Fixed the installer deploy workflow so workflow-run deployments preserve the
  resolved release tag through signed-artifact verification.

## [0.6.0] - 2026-11-03

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
