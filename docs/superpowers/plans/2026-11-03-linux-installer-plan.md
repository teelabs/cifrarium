# Linux Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate a signed, versioned Linux installer for Cifrarium served by `usecifrarium`.

**Architecture:** A strict Bash installer consumes a signed JSON manifest and architecture-specific release bundle from the Pages origin. A release builder creates deterministic archives and checksums; GitHub Actions signs with keyless Cosign and publishes the complete bundle only after tests. The installer stages all content before atomically switching user-owned symlinks.

**Tech Stack:** POSIX shell, Go cross-compilation, `tar`, `sha256sum`, `curl`, Cosign keyless bundles, GitHub Actions, Cloudflare Pages Wrangler.

**Spec:** `docs/superpowers/specs/2026-11-03-linux-installer-design.md`

## Global Constraints

- Linux `amd64` and `arm64` only.
- Explicit SemVer is required for install.
- Default prefix is `$HOME/.local`; no root and no daemon start by default.
- HTTPS and checksum plus Cosign verification are mandatory.
- No real credentials or signing keys enter the repository or tests.
- Existing user state and active version remain untouched on failed activation.

## Review Focus

- Shell quoting, option injection, URL validation, and temporary-directory cleanup.
- Archive path traversal, symlink, hardlink, device-node, and permission abuse.
- Checksum/signature confusion or verification of a different file than the one extracted.
- Atomicity when the active binary/service already exists or a concurrent installer runs.
- Rollback/uninstall deleting the wrong prefix or starting the daemon unexpectedly.

---

### Task 1: Installer implementation

**Files:**
- Create: `scripts/install.sh`
- Create: `scripts/install-test.sh`
- Test: temporary HOME/prefix fixtures and a local release bundle

- [x] Write harness cases for install, traversal,
  signature failure, rollback, uninstall confirmation, and `--enable`.
- [x] Implement strict argument/platform/version/base-URL validation.
- [x] Implement HTTPS downloads, manifest binding, SHA-256 verification, and
  Cosign bundle verification.
- [x] Implement archive validation, staged extraction, atomic symlink activation,
  service installation, rollback, uninstall, and explicit enable.
- [x] Run the harness outside the source checkout and confirm no default start.

### Task 2: Release builder and manifest

**Files:**
- Create: `scripts/build-release.sh`
- Create: `scripts/verify-release.sh`
- Create: `distribution/installer/manifest.schema.json`
- Modify: `CHANGELOG.md` under `[Unreleased]`

- [x] Cross-build amd64 and arm64 binaries with embedded version metadata.
- [x] Package binary, service unit, README, and release metadata with stable names.
- [x] Generate checksums and manifest entries without signing credentials.
- [x] Verify all archive members, checksums, versions, and supported platforms.

### Task 3: Release and Pages automation

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `.github/workflows/deploy-installer.yml`
- Modify: `distribution/installer/index.html` and `bootstrap.json` only when
  the release contract is implemented

- [x] Run build/test verification on tags and create release artifacts.
- [x] Use keyless Cosign signing with GitHub OIDC and upload bundles.
- [x] Deploy the complete installer bundle to `usecifrarium` only from main or
  a release workflow after artifact verification.
- [x] Smoke-test exact public files and fail if `install.sh` is absent or
  unsigned after a release deployment. Verified against the canonical
  `usecifrarium.pages.dev` deployment for `v0.4.0` on 2026-11-03.

### Task 4: Documentation and adversarial review

**Files:**
- Modify: `README.md`, `docs/USER-GUIDE.md`, `docs/AGENT-USAGE.md`
- Modify: `docs/security/2026-11-02-red-team-review.md`
- Modify: issue #65 and Project #5

- [x] Document install, upgrade, rollback, uninstall, verification, runtime
  requirements, troubleshooting, and optional daemon activation.
- [x] Run independent red-team review focused on shell and release boundaries.
- [x] Resolve Critical/Important findings before merge or deploy; repository
  tag protection and release-environment reviewer configuration remain
  operational prerequisites documented in the installer guide.
