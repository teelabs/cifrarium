# Cifrarium red-team review

Status: implementation review evidence; not a release approval.

Review date: 2026-11-02.

## Scope

The review covered the local encrypted store, recovery shares, catalog chain, remote snapshot verification, restore activation, provider boundary, daemon queue, systemd user boundary, adapters, and local MCP server. The source of truth is the current `main` branch at `4008d24`.

## Evidence matrix

| Threat or invariant | Direct evidence |
| --- | --- |
| One recovery share cannot recover the bundle; every pair works | `internal/recovery/recovery_test.go`, `internal/store/keyring_test.go` |
| Duplicate share indexes, malformed bundles, and key lengths are rejected | `internal/recovery/recovery.go`, `internal/store/keyring.go` |
| Snapshot and catalog tampering is detected | `internal/store/catalog_test.go`, `internal/crypto/envelope_test.go` |
| Catalog rollback and missing guarded head are rejected | `internal/store/catalog_test.go`, `internal/store/snapshot.go` |
| Historical restore cannot change the active write head | `internal/store/catalog_test.go`, `internal/sync/upload_test.go` |
| Restore traversal, final symlink, root symlink, and intermediate symlink attacks are rejected | `internal/store/restore_test.go`, `internal/store/snapshot.go` |
| Partial activation failure restores moved files | `internal/store/restore_test.go` |
| Provider receives opaque ciphertext and encrypted catalog bytes | `internal/provider/provider_test.go`, `internal/provider/git_test.go`, `internal/sync/upload_test.go` |
| Remote access and privacy failures are actionable without token arguments | `internal/provider/git.go`, `internal/provider/provider_test.go`, `cmd/cifrarium/main.go` |
| Provider migration preserves opaque objects and atomic capability | `internal/provider/provider.go`, `internal/provider/provider_test.go` |
| Pending queue is encrypted and bounded to 16 items | `internal/daemon/queue.go`, `internal/daemon/queue_test.go` |
| Retry, missed-cycle recovery snapshot, persistence failure, and alert deduplication are covered | `internal/daemon/scheduler_test.go`, `internal/daemon/service_test.go` |
| MCP is local, mode 0600, plan-only, and rejects mutation methods | `internal/mcp/server.go`, `internal/mcp/server_test.go` |
| Adapter allowlists exclude sensitive application state and reject symlinks | `internal/adapters/files_test.go` |

## Verification run

The following gates passed on the review branch before publication:

```text
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check
./scripts/verify-version-changelog.sh
./scripts/verify-secrets.sh
```

The GitHub Actions `verify` job also passed these gates on `main`, including the MCP handshake and systemd installer checks.

## Findings and residuals

### Fixed

Restore previously checked only the final destination for symlinks. A symlinked intermediate directory or restore root could redirect activation outside the requested target. Component-by-component `Lstat` checks and regression tests were added in PR #25.

### Accepted within the current threat model

1. A same-user hostile process can attempt a TOCTOU race between path validation and `os.Rename`. The SDD excludes a compromised running user account. A future Linux-hardening slice may replace this with descriptor-relative `openat`/`renameat2` operations.
2. Recovery shares supplied to systemd live in the operator-created `daemon.env` and are plaintext to the same user with file access. The file is required to be mode `0600`; the installer never creates or copies it. Shares are never stored in the vault or provider.

### Open before public release

1. GitHub repository creation and fine-grained token issuance remain explicit operator actions and require a documented provisioning runbook.
2. Domain/trademark clearance requires a registrar check and qualified legal review; the brand preflight is only technical evidence.
3. Human security and release approval has not been granted by this report.

## Decision

No blocking implementation finding remains in the reviewed code paths. The open residuals above must remain visible in the release checklist; this document does not authorize publication, deployment, or public branding.
