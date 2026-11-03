# Cifrarium Security Hardening Design

Status: approved for local implementation under issue #66; no integration or
release approval.

## Intent and scope

Close the adversarial findings from the review of `ee0c907` before release:
unsafe Git execution, provider and adapter path races, recovery rollback,
migration privacy bypass, unbounded payloads, and silent daemon failures.

Non-goals are public distribution, release, deployment, cryptographic-envelope
redesign, multi-user trust, or protection from a compromised user account.

The accepted threat model is explicit: restored application files are plaintext
at user-owned paths, so a process running as that same user can read them and
interfere with the vault or daemon. The hardening targets accidental exposure,
untrusted path inputs, rollback, corruption, and ordinary concurrent use. It
uses fail-closed behavior and descriptor-relative operations as integrity and
availability protections, not as a same-user sandbox.

## Selected approach

The requester selected deep hardening over minimal patches or a deferred
two-phase fix. The implementation will use a hardened Git runner, Linux
descriptor-relative filesystem access with fail-closed unsupported paths,
serialized guarded recovery, explicit destination privacy verification,
bounded payloads, and observable daemon failure propagation.

## Decisions

- Git subprocesses strip inherited `GIT_*`, `SSH_*`, `GH_*`, and recovery-share
  variables; disable system/global config, interactive prompts, aliases, hooks,
  filters, and repository-provided helpers. A malicious hook regression test
  must prove recovery material is not observed.
- Linux provider and adapter operations are anchored to opened non-symlinked
  directories using `openat2`/`openat`, `O_NOFOLLOW`, and relative temporary
  creation/rename. Unsupported platforms fail closed.
- Recovery holds a vault lock, validates the active signed chain against the
  existing keyring guard, preserves a non-empty guard during import, and
  rechecks identity before releasing the lock. Fresh vaults may initialize an
  empty guard.
- Migration requires a destination `PrivateVerifier`; local-only providers
  must explicitly implement a safe verifier. Git verifies privacy immediately
  before final push and documents the unavoidable visibility race; repository
  or organization policy is the enforcement layer when visibility must not
  change after the check.
- Initial limits: 16 MiB per captured file, 64 MiB snapshot plaintext, 64 MiB
  snapshot ciphertext, 1 MiB encrypted manifest, 64 MiB per queue item, 64 MiB
  queue file, and 64 KiB per MCP line.
- Daemon startup, queue persistence, upload, and MCP listener failures are
  surfaced; retryable uploads remain queued and observable.

## PO/SM decisions from builder check — 2026-11-02

- A `recover`/`Save` race is serialized. If the validated head changes before
  import, recovery fails without replacing keyring material.
- A valid historical chain without the current guarded head is not sufficient
  for recovery import.
- The hardened runner owns every `git` and `gh` invocation. It preserves only
  the explicit credential boundary plus `PATH`/`HOME`; `GIT_*`, `GH_*`, `SSH_*`,
  and recovery-share variables are removed.
- Existing ordinary Git checkouts remain supported; worktrees and alternates
  are outside the trusted provider layout and are rejected.
- Missing `openat2`/required Linux primitives fail the affected operation
  closed.
- Limits include raw captured bytes, serialized plaintext, encrypted payload,
  queue storage, file count, path length, and traversal depth.
- A full queue is a visible failure that stops the cycle; it never silently
  drops or coalesces snapshots.
- Initial setup, persistence, and MCP startup failures are fatal and visible;
  upload failures remain retryable only when the failed item stays queued and
  the failure is observable.

## Acceptance evidence

Each finding gets a red test, minimal fix, and green focused test. Final proof
requires full tests, race tests, vet, build, formatting, secret scan,
version/changelog checks, and a red-team review. Same-user interference and the
GitHub visibility race remain documented accepted residuals, never claimed as
atomically closed guarantees.
