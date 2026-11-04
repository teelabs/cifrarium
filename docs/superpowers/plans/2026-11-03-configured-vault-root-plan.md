# Configured Vault Root and Contextual Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bind normal Cifrarium commands and the daemon to one persistent, canonical per-user vault root and make setup explain safe next actions.

**Architecture:** `internal/config` owns restrictive root configuration and canonicalization. The CLI resolves it before keyring/vault access; `internal/store` binds the keyring payload to that root. Setup is the only initial mutating path, while doctor remains read-only.

**Tech Stack:** Go, Linux user keyring, systemd user service, Markdown operational contracts.

**Spec:** `docs/superpowers/specs/2026-11-03-configured-vault-root-design.md`

## Global Constraints

- The configuration contains no recovery share, token, or vault content.
- A different explicit root is a security failure, never an override prompt.
- Normal commands must not create keyring or vault state when unconfigured.
- `--non-interactive` must not configure root, capture, upload, or enable daemon.
- Recovery shares remain human-only output and are never persisted by the wizard.

## Review Focus

- Config replacement or root symlink must not redirect the keyring: covered by `internal/config` and root-resolution tests.
- A legacy unbound keyring must not be silently used: covered by `internal/store/keyring_test.go`.
- Doctor/setup must not initialize state while diagnosing: covered by CLI tests and existing doctor tests.
- Systemd must not select an alternate vault: covered by unit-text check and documentation.
- User-facing commands must remain actionable without leaking secret values: covered by wizard output tests and secret scan.

### Task 1: Root configuration and keyring binding

Create `internal/config/root.go`, bind `internal/store/keyring.go`, and add focused tests for canonical paths, restrictive permissions, mismatch, symlink rejection, legacy state, and recovery binding.

### Task 2: CLI resolver and wizard

Resolve root before keyring access in `cmd/cifrarium`, allow setup to establish it once, keep doctor read-only, and keep normal setup copy in simple English.

### Task 3: Operations and contracts

Remove the hardcoded systemd root, update the technical specification, README, user/agent guides, provider runbook, installer guidance, and changelog. Verify all normal examples use the configured root.

### Task 4: Full verification and adversarial review

Run the complete Go, race, vet, build, installer, changelog, secret, and diff gates; review explicit-root mismatch, config tampering, legacy migration, recovery, and non-interactive paths.
