# Cifrarium red-team review

Status: implementation review evidence with accepted threat-model residuals; not
a release approval.

Review date: 2026-11-02.

## Scope

The review covered the local encrypted store, recovery shares, catalog chain, remote snapshot verification, restore activation, provider boundary, daemon queue, systemd user boundary, adapters, local MCP server, and the current repository release evidence. The baseline is `main` at `ee0c907`. This report also covers the uncommitted security-hardening worktree for issue #66; it is evidence of implementation and verification, not a merge or release approval.

TRAG was unavailable during this review, so no repository-history citation is claimed. The independent adversarial pass returned `CHANGES REQUESTED` before the follow-up fixes below.

## Accepted threat-model boundary

Cifrarium protects configuration while it is encrypted in the local vault or
provider. Restored files are plaintext by design so applications can use them.
A process running as the same Unix user is therefore outside the vault's
confidentiality boundary: it may read user files, observe user processes,
alter user-owned paths, or interfere with a vault operation. The hardening
rejects unsafe paths and preserves integrity for ordinary failures, but it
does not promise sandboxing against that process. A same-user interference may
produce a fail-closed error, require recovery, or require rotating affected
credentials.

## Evidence matrix

| Threat or invariant | Direct evidence |
| --- | --- |
| One recovery share cannot recover the bundle; every pair works | [`internal/recovery/recovery_test.go`](../../internal/recovery/recovery_test.go), [`internal/store/keyring_test.go`](../../internal/store/keyring_test.go) |
| Duplicate share indexes, malformed bundles, and key lengths are rejected | [`internal/recovery/recovery.go`](../../internal/recovery/recovery.go), [`internal/store/keyring.go`](../../internal/store/keyring.go) |
| Snapshot and catalog tampering is detected | [`internal/store/catalog_test.go`](../../internal/store/catalog_test.go), [`internal/crypto/envelope_test.go`](../../internal/crypto/envelope_test.go) |
| Catalog rollback and missing guarded head are rejected | [`internal/store/catalog_test.go`](../../internal/store/catalog_test.go), [`internal/store/snapshot.go`](../../internal/store/snapshot.go) |
| Historical restore cannot change the active write head | [`internal/store/catalog_test.go`](../../internal/store/catalog_test.go), [`internal/sync/upload_test.go`](../../internal/sync/upload_test.go) |
| Restore traversal, final symlink, root symlink, backup-root symlink, and intermediate symlink attacks are rejected | [`internal/store/restore_test.go`](../../internal/store/restore_test.go), [`internal/store/snapshot.go`](../../internal/store/snapshot.go), [`internal/store/secure_restore_linux.go`](../../internal/store/secure_restore_linux.go) |
| Production restore uses descriptor-relative directory handles and no-replace renames to prevent path-component TOCTOU redirection | [`internal/store/secure_restore_linux.go`](../../internal/store/secure_restore_linux.go), [`internal/store/restore_test.go`](../../internal/store/restore_test.go), [issue #56](https://github.com/teelabs/cifrarium/issues/56) |
| Partial activation failure restores moved files and removes newly activated files | [`internal/store/restore_test.go`](../../internal/store/restore_test.go), [PR #40](https://github.com/teelabs/cifrarium/pull/40) |
| Snapshot, catalog, and head files roll back when a write or keyring-head update fails | [`internal/store/catalog_test.go`](../../internal/store/catalog_test.go), [PR #44](https://github.com/teelabs/cifrarium/pull/44) |
| Provider receives opaque ciphertext and encrypted catalog bytes | [`internal/provider/provider_test.go`](../../internal/provider/provider_test.go), [`internal/provider/git_test.go`](../../internal/provider/git_test.go), [`internal/sync/upload_test.go`](../../internal/sync/upload_test.go) |
| Git uploads require private-provider verification before remote writes | [`internal/provider/provider.go`](../../internal/provider/provider.go), [`internal/sync/upload.go`](../../internal/sync/upload.go), [`internal/sync/upload_test.go`](../../internal/sync/upload_test.go), [PR #48](https://github.com/teelabs/cifrarium/pull/48) |
| Remote access and privacy failures are actionable without token arguments | [`internal/provider/git.go`](../../internal/provider/git.go), [`internal/provider/provider_test.go`](../../internal/provider/provider_test.go), [`cmd/cifrarium/main.go`](../../cmd/cifrarium/main.go) |
| Provider migration preserves opaque objects and atomic capability | [`internal/provider/provider.go`](../../internal/provider/provider.go), [`internal/provider/provider_test.go`](../../internal/provider/provider_test.go) |
| Pending queue is encrypted and bounded to 16 items | [`internal/daemon/queue.go`](../../internal/daemon/queue.go), [`internal/daemon/queue_test.go`](../../internal/daemon/queue_test.go) |
| Retry, missed-cycle recovery snapshot, persistence failure, and alert deduplication are covered | [`internal/daemon/scheduler_test.go`](../../internal/daemon/scheduler_test.go), [`internal/daemon/service_test.go`](../../internal/daemon/service_test.go) |
| MCP is local, mode 0600, daemon-mediated, structured plan-only, and rejects mutation methods | [`internal/mcp/server.go`](../../internal/mcp/server.go), [`internal/mcp/server_test.go`](../../internal/mcp/server_test.go), [`cmd/cifrarium/main.go`](../../cmd/cifrarium/main.go), [PR #42](https://github.com/teelabs/cifrarium/pull/42) |
| Adapter allowlists exclude sensitive application state and reject symlinks | [`internal/adapters/files_test.go`](../../internal/adapters/files_test.go) |

## Verification run

The following gates passed locally in the issue #66 worktree after the follow-up implementation (not a release artifact):

```text
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check
```

The version/changelog and secret scans also passed after the follow-up work.
A Darwin/amd64 test compilation passed; runtime execution on Darwin was not
attempted. The prior GitHub Actions result on `main` does not validate this
uncommitted hardening worktree. The visual identity proposal is versioned
under [`docs/brand/`](../brand/); it makes no legal-clearance claim, and
qualified review remains tracked in [issue #49](https://github.com/teelabs/cifrarium/issues/49).

## Findings and residuals

### Issue #66 follow-up disposition

| Finding | Disposition and evidence |
| --- | --- |
| Git hooks, inherited credential/recovery-share environment, and unsafe local Git filters/helpers | **Resisted for covered cases.** Git commands disable hooks/fsmonitor, strip sensitive environment variables, inspect local config, and reject executable filter/helper/include/transport settings. Regression coverage includes hooks and a malicious local filter. |
| Provider/adapters/Git path redirection | **Resisted for covered cases.** Linux provider writes/listing, adapter reads, and Git/`gh` subprocess working directories use descriptor-relative `openat2`/`O_NOFOLLOW`; a replacement-path regression test confirms the child remains on the opened directory. Unsupported provider platforms fail closed. |
| Recovery rollback and concurrent Save/import | **Resisted.** Recovery and Save share an exclusive descriptor-relative lock; recovery validates the signed chain twice, preserves an existing guard, and anchors a previously unguarded existing head. Regression tests cover valid historical rollback, missing-guard anchoring, and lock symlink/alias rejection. |
| Migration to a destination without a privacy boundary | **Resisted.** Migration requires `PrivateVerifier`; GitHub privacy verification rejects local-only Git destinations. |
| Oversized files, records, manifests, queue items, provider listings, daemon snapshot reads, and MCP lines | **Resisted for covered cases.** Central limits are enforced before retention/decryption where applicable, including the CLI snapshot handoff, with focused rejection tests. |
| Queue loss after upload/removal persistence failure | **Resisted for covered cases.** Pending items remain durable until upload succeeds; only then are they removed and persisted. If removal persistence fails, the item is restored in memory and remains in the previous durable queue. Git retries tolerate an already-committed snapshot and continue to push the current head. Regression coverage reloads the queue after the failure. Scheduled persistence failures terminate the scheduler; if the storage device cannot persist a newly queued item, delivery of that item is not claimed durable and the local encrypted vault remains the source of truth for the next cycle. |
| Daemon startup/listener/persistence observability | **Resisted.** Initial drain and initial-cycle persistence failures are fatal; MCP readiness is announced only after bind/chmod; malformed MCP input receives a parse error response. |
| Privacy check versus push race | **Accepted residual.** Privacy is checked immediately before push, but an external GitHub visibility change can still occur between verification and remote acceptance. Organization/repository policy is required when that guarantee matters. |

### Remaining residuals

1. A same-user process with permission to alter the vault root, lock parent, or
   restored files remains outside the confidentiality boundary and can disrupt
   operations. The lock itself rejects a symlink and is opened with `O_NOFOLLOW`
   on Linux; this is integrity/availability hardening, not a same-user sandbox.
2. This report is evidence, not approval by itself. Commit, push, and merge
   require the explicit delivery authorization and gates recorded on PR #67;
   publication and deployment remain outside this delivery.
3. Abrupt process termination during multi-file restore can occur between
   descriptor-relative renames. Handled activation errors roll back and leave
   a backup, but the MVP has no durable restore journal for crash recovery;
   operators must preserve the backup and retry after an interrupted restore.
   The follow-up is tracked in [issue #68](https://github.com/teelabs/cifrarium/issues/68).

### Fixed

Restore previously checked only the final destination for symlinks. A symlinked intermediate directory or restore root could redirect activation outside the requested target. Component-by-component `Lstat` checks and regression tests were added in [PR #25](https://github.com/teelabs/cifrarium/pull/25).

### Accepted within the current threat model

1. Recovery shares supplied to systemd live in the operator-created `daemon.env` and are plaintext to the same user with file access. The file is required to be mode `0600`; the installer never creates or copies it. Shares are never stored in the vault or provider.

The previous restore path TOCTOU residual is remediated for the Linux MVP by
descriptor-relative production operations. A compromised same-user process can
still interfere with the operation and cause a fail-closed error or rollback
failure; it cannot redirect a validated rename through a replaced symlink
component. Unsupported platforms fail closed. This is accepted because
restored plaintext is necessarily readable by the same user.

### Open before public release

1. GitHub repository creation and fine-grained token issuance remain explicit operator actions; the provisioning runbook is now present at [`docs/runbooks/github-provider-provisioning.md`](../runbooks/github-provider-provisioning.md).
2. Domain/trademark clearance requires a registrar check and qualified legal review; the brand preflight is only technical evidence in [`docs/research/2026-11-02-cifrarium-brand-clearance.md`](../research/2026-11-02-cifrarium-brand-clearance.md).
3. Human security and release approval has not been granted by this report.

## Decision

Implementation findings from issue #66 are resisted by current evidence. The
release state is still pending explicit human security/release approval and
the residual threat-model decision above. This document does not authorize
publication, deployment, or public branding.
