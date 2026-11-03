# Cifrarium Usage Documentation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document how humans and agents use Cifrarium safely across setup, capture, daemon operation, recovery, provider failures, and the accepted same-user threat model.

**Architecture:** Keep the README as a short entry point, place the complete human workflow in a dedicated guide, and place machine-readable operational rules in an agent-facing contract. Root `AGENTS.md` points agents to the contract without duplicating it. The red-team report remains the source of truth for residual-risk disposition.

**Tech Stack:** Markdown, Go CLI examples, systemd user service, GitHub provider, local MCP.

**Spec:** `docs/superpowers/specs/2026-11-02-security-hardening-design.md` and the accepted threat-model decision in the current task.

## Global Constraints

- Documentation-only change; retain `VERSION` at `0.3.0` and record the decision under `CHANGELOG.md` `[Unreleased]`.
- Do not document real secrets, tokens, recovery shares, or user-specific absolute paths as usable credentials.
- Keep remote publication, deployment, merge, and push outside this task.
- State clearly that same-user active compromise is outside the confidentiality boundary.
- Every operational example must have a verification or failure criterion.

## Review Focus

- A new operator must be able to distinguish local vault, encrypted provider, and restored plaintext locations; verify with the human guide's data-flow section.
- An agent must know which commands are read-only, mutating, retryable, or fatal; verify with the agent contract's command matrix.
- Recovery must not be attempted with one share or an unverified provider; verify the recovery scenario and abort criteria.
- Provider and daemon failures must lead to observable next actions rather than silent retry assumptions; verify the failure playbooks.
- Documentation must not promise protection from a compromised same-user process; verify the threat-model section and red-team disposition.

---

### Task 1: Record the accepted threat model

**Files:**
- Modify: `docs/security/2026-11-02-red-team-review.md`
- Modify: `docs/superpowers/specs/2026-11-02-security-hardening-design.md`

- [x] Add an explicit trust-boundary section distinguishing data at rest, provider ciphertext, restored plaintext, and same-user processes.
- [x] Reclassify the same-user interference and GitHub visibility race as accepted residuals with operational mitigations, not hidden blockers.
- [x] State that the report is not release approval.

### Task 2: Write the human guide

**Files:**
- Create: `docs/USER-GUIDE.md`

- [x] Cover installation prerequisites, first snapshot, recovery shares, daemon setup, provider setup, restore/recovery, and removal/incident response.
- [x] Include examples for local-only use, private GitHub backup, laptop migration, scheduled daemon use, offline queueing, and provider failure.
- [x] Add expected outputs/verification criteria and explicit unsafe actions to avoid.

### Task 3: Write the agent contract

**Files:**
- Create: `docs/AGENT-USAGE.md`
- Create: `AGENTS.md`

- [x] Define preflight checks, command classification, required confirmations, invariants, failure handling, and handoff format.
- [x] Make `AGENTS.md` a concise pointer to the detailed contract and repository checks.
- [x] Include examples for status, snapshot, provider health, recovery, and daemon diagnosis without embedding secrets.

### Task 4: Connect entry points and changelog

**Files:**
- Modify: `README.md`
- Modify: `docs/runbooks/github-provider-provisioning.md`
- Modify: `CHANGELOG.md`

- [x] Add links and a short “choose your path” section to the README.
- [x] Add the accepted threat-model boundary and agent contract to the provider runbook.
- [x] Record the documentation-only change under `[Unreleased]`; keep version `0.3.0`.

### Task 5: Documentation QA

**Files:**
- Test: all changed Markdown and shell/Go command examples.

- [x] Search for accidental real secrets, stale claims, contradictory security language, and broken local links.
- [x] Run version/changelog validation, secret scan, `git diff --check`, and the existing Go gates because examples and docs describe executable behavior.
- [x] Review the final diff for scope, readability, and agent completion criteria.
