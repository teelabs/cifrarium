# Cifrarium red-team review

Status: implementation review evidence; not a release approval.

Review date: 2026-11-02.

## Scope

The review covered the local encrypted store, recovery shares, catalog chain, remote snapshot verification, restore activation, provider boundary, daemon queue, systemd user boundary, adapters, local MCP server, and the current repository release evidence. The source of truth is the reconciled `main` branch at `555dceffbea704424064d44c4aab8c0d04370298`.

## Evidence matrix

| Threat or invariant | Direct evidence |
| --- | --- |
| One recovery share cannot recover the bundle; every pair works | `internal/recovery/recovery_test.go`, `internal/store/keyring_test.go` |
| Duplicate share indexes, malformed bundles, and key lengths are rejected | `internal/recovery/recovery.go`, `internal/store/keyring.go` |
| Snapshot and catalog tampering is detected | `internal/store/catalog_test.go`, `internal/crypto/envelope_test.go` |
| Catalog rollback and missing guarded head are rejected | `internal/store/catalog_test.go`, `internal/store/snapshot.go` |
| Historical restore cannot change the active write head | `internal/store/catalog_test.go`, `internal/sync/upload_test.go` |
| Restore traversal, final symlink, root symlink, backup-root symlink, and intermediate symlink attacks are rejected | `internal/store/restore_test.go`, `internal/store/snapshot.go`, `internal/store/secure_restore_linux.go` |
| Production restore uses descriptor-relative directory handles and no-replace renames to prevent path-component TOCTOU redirection | `internal/store/secure_restore_linux.go`, `internal/store/restore_test.go`, issue #56 |
| Partial activation failure restores moved files and removes newly activated files | `internal/store/restore_test.go`, PR #40 |
| Snapshot, catalog, and head files roll back when a write or keyring-head update fails | `internal/store/catalog_test.go`, PR #44 |
| Provider receives opaque ciphertext and encrypted catalog bytes | `internal/provider/provider_test.go`, `internal/provider/git_test.go`, `internal/sync/upload_test.go` |
| Git uploads require private-provider verification before remote writes | `internal/provider/provider.go`, `internal/sync/upload.go`, `internal/sync/upload_test.go`, PR #48 |
| Remote access and privacy failures are actionable without token arguments | `internal/provider/git.go`, `internal/provider/provider_test.go`, `cmd/cifrarium/main.go` |
| Provider migration preserves opaque objects and atomic capability | `internal/provider/provider.go`, `internal/provider/provider_test.go` |
| Pending queue is encrypted and bounded to 16 items | `internal/daemon/queue.go`, `internal/daemon/queue_test.go` |
| Retry, missed-cycle recovery snapshot, persistence failure, and alert deduplication are covered | `internal/daemon/scheduler_test.go`, `internal/daemon/service_test.go` |
| MCP is local, mode 0600, daemon-mediated, structured plan-only, and rejects mutation methods | `internal/mcp/server.go`, `internal/mcp/server_test.go`, `cmd/cifrarium/main.go`, PR #42 |
| Adapter allowlists exclude sensitive application state and reject symlinks | `internal/adapters/files_test.go` |

## Verification run

The following gates passed locally against the reconciled `main` before publication:

```text
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check
./scripts/verify-version-changelog.sh
./scripts/verify-secrets.sh
```

The GitHub Actions `verify` job passed these gates on `main` in run `41511270630`, including the MCP handshake and systemd installer checks. The visual identity proposal is versioned under `docs/brand/`; it makes no legal-clearance claim, and qualified review remains tracked in issue #49.

## Findings and residuals

### Fixed

Restore previously checked only the final destination for symlinks. A symlinked intermediate directory or restore root could redirect activation outside the requested target. Component-by-component `Lstat` checks and regression tests were added in PR #25.

### Accepted within the current threat model

1. Recovery shares supplied to systemd live in the operator-created `daemon.env` and are plaintext to the same user with file access. The file is required to be mode `0600`; the installer never creates or copies it. Shares are never stored in the vault or provider.

The previous restore path TOCTOU residual is remediated for the Linux MVP by
descriptor-relative production operations. A compromised same-user process can
still interfere with the operation and cause a fail-closed error or rollback
failure; it cannot redirect a validated rename through a replaced symlink
component. Unsupported platforms fail closed.

### Open before public release

1. GitHub repository creation and fine-grained token issuance remain explicit operator actions; the provisioning runbook is now present at `docs/runbooks/github-provider-provisioning.md`.
2. Domain/trademark clearance requires a registrar check and qualified legal review; the brand preflight is only technical evidence.
3. Human security and release approval has not been granted by this report.

## Decision

No blocking implementation finding remains in the reviewed code paths. The open residuals above must remain visible in the release checklist; this document does not authorize publication, deployment, or public branding.
