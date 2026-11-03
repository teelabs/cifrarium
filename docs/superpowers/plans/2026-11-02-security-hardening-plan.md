# Cifrarium Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Close the adversarial security and reliability findings tracked by issue #66 without merging, pushing, releasing, or deploying.

**Architecture:** Preserve the current package boundaries while adding a small shared limit/secure-I/O seam. Provider and adapter writes/reads become descriptor-relative on Linux and fail closed elsewhere. Recovery, migration, and daemon orchestration expose explicit gates and errors rather than relying on caller discipline.

**Tech Stack:** Go 1.24.4, Linux `openat2`/`openat`/`renameat2`, Unix file locks, native Git subprocesses, Go table tests, race detector.

**Spec:** `docs/superpowers/specs/2026-11-02-security-hardening-design.md`

## Global Constraints

- Preserve unrelated work and the original checkout's untracked `.worktrees/`.
- No public distribution, release, deployment, publication, merge, or push.
- Unsupported platforms must fail closed for secure filesystem operations.
- Recovery must never clear a non-empty catalog-head guard.
- Remote/provider payloads must be bounded before unbounded allocation.
- Every security behavior needs an adversarial regression test.

## Review Focus

- A repository hook or Git configuration must not execute with recovery-share environment; owned by Task 1.
- A raced provider or adapter path component must not redirect file access; owned by Task 2.
- A valid historical vault must not downgrade a guarded recovery; owned by Task 3.
- A provider migration must not write before destination privacy verification; owned by Task 1.
- Oversized remote/local payloads and silent daemon failures must be rejected or surfaced; owned by Tasks 4 and 5.

### Task 1: Harden Git execution and migration privacy

**Files:**
- Modify: `internal/provider/git.go`
- Modify: `internal/provider/provider.go`
- Modify: `internal/sync/upload.go`
- Test: `internal/provider/git_test.go`, `internal/provider/provider_test.go`, `internal/sync/upload_test.go`

**Interfaces:**
- Produces a single Git runner that sanitizes inherited configuration/secret variables and disables hooks for every command.
- Produces a migration preflight requiring destination `PrivateVerifier` before any destination write.

- [ ] Write a failing test that installs a local pre-commit hook and asserts `UploadSnapshot` neither executes it nor exposes recovery-share variables.
- [ ] Run the focused provider test and observe the expected failure.
- [ ] Implement the hardened runner with explicit environment filtering, noninteractive Git settings, disabled hooks, and no repository-provided helper execution.
- [ ] Write a failing migration test using a destination with a failing `PrivateVerifier` and assert zero object writes.
- [ ] Implement the migration privacy preflight; local-only providers must expose an explicit successful verifier.
- [ ] Add a regression proving privacy verification runs immediately before a Git push and that a failed check leaves only local state.
- [ ] Run provider and sync tests, then the full Go suite.

### Task 2: Replace provider and adapter path races

**Files:**
- Modify: `internal/provider/git.go`
- Modify: `internal/adapters/files.go`
- Create/modify: Linux secure-I/O helper files under `internal/provider/` and `internal/adapters/`
- Test: `internal/provider/git_test.go`, `internal/adapters/files_test.go`

**Interfaces:**
- Produces descriptor-relative provider object read/write helpers anchored to a trusted root.
- Produces descriptor-relative adapter traversal/read helpers anchored to the supplied home directory.

- [ ] Write failing tests for raced/replaced provider directory components, intermediate adapter symlinks, and unsupported-platform fail-closed behavior.
- [ ] Run focused tests and confirm they fail for the current path-based implementation.
- [ ] Implement Linux helpers using opened directory descriptors, `openat2` resolution flags, `O_NOFOLLOW`, exclusive temporary files, fsync, and relative no-replace/atomic rename.
- [ ] Route provider and adapter operations through those helpers; remove check-then-use security claims that are not backed by the descriptors.
- [ ] Preserve existing allowlists, modes, rollback, and traversal validation.
- [ ] Run focused tests, Linux race tests, and full package tests.

### Task 3: Make recovery guard-preserving and serialized

**Files:**
- Modify: `internal/store/keyring.go`
- Modify: `internal/store/snapshot.go`
- Test: `internal/store/keyring_test.go`, `internal/store/catalog_test.go`

**Interfaces:**
- Produces a recovery-import operation that validates and imports under one vault lock while preserving an existing non-empty guard.

- [ ] Write failing tests for recovery against a replayed but valid historical chain, guard preservation, and mutation between validation and import.
- [ ] Run the focused tests and confirm current recovery accepts or permits the downgrade.
- [ ] Implement a 0600 vault lock and a single recovery transaction that validates the active chain and guard, writes the recovered keyring payload atomically, and rechecks the validated head.
- [ ] Keep fresh-vault recovery supported with an empty guard and ensure failed imports leave the original keyring unchanged.
- [ ] Run store tests with `-race` and full verification.

### Task 4: Add bounded payload handling

**Files:**
- Create: `internal/limits/limits.go` or an equivalent focused package
- Modify: `internal/adapters/files.go`, `internal/crypto/envelope.go`, `internal/provider/git.go`, `internal/store/snapshot.go`, `internal/daemon/queue.go`, `internal/mcp/server.go`
- Test: corresponding package tests

**Interfaces:**
- Produces named limits: 16 MiB file, 64 MiB snapshot plaintext/ciphertext, 1 MiB manifest, 64 MiB queue item/file, and 64 KiB MCP line.
- Produces bounded readers that reject limit-plus-one input before retaining it.

- [ ] Write failing exact-limit and limit-plus-one tests for capture, envelope/manifest, queue load, remote object download, and MCP lines.
- [ ] Implement bounded reads and validation before JSON decode or decryption allocation.
- [ ] Reject malformed queue items and oversized individual records even when the encrypted container itself is within its limit.
- [ ] Run focused tests, fuzz-adjacent malformed-input cases, and full suite.

### Task 5: Surface daemon failure states

**Files:**
- Modify: `internal/daemon/service.go`, `internal/daemon/scheduler.go`
- Modify: `cmd/cifrarium/main.go`, `internal/mcp/server.go`
- Test: `internal/daemon/service_test.go`, `cmd/cifrarium/main_test.go`, `internal/mcp/server_test.go`

**Interfaces:**
- Produces explicit service error/event propagation for initial drain, initial cycle, queue persistence, and MCP listener startup.

- [ ] Write failing tests proving initial drain/persistence and listener failures are observable and do not report a healthy daemon.
- [ ] Implement fatal-vs-retryable error classification, retaining retryable work in the encrypted queue.
- [ ] Connect MCP listener failure to daemon shutdown and make main return a non-zero error path.
- [ ] Run daemon, command, and MCP tests with race detection.

### Task 6: Evidence, changelog, and independent review

**Files:**
- Modify: `docs/superpowers/specs/2026-11-02-security-hardening-design.md`
- Modify: `docs/security/2026-11-02-red-team-review.md`, `README.md`, `CHANGELOG.md` as evidence requires

- [ ] Re-run the original attack matrix against the final worktree and classify every case `RESISTED`, `EXPLOITABLE`, `UNPROVEN`, or `BLOCKED`.
- [ ] Record the unavoidable GitHub visibility race and any unsupported-platform limitation without calling them fixed.
- [ ] Run `gofmt`, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `git diff --check`, secret scan, and version/changelog verification.
- [ ] Invoke `version-changelog` before any local commit or integration decision; classify this as security/bugfix and determine the SemVer transition.
- [ ] Obtain an independent red-team and contract/test review. Critical or important open findings block readiness.
