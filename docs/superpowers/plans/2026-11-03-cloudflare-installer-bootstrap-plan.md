# Cloudflare Installer Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the `usecifrarium` Cloudflare Pages origin with a safe static status bundle for the future signed installer.

**Architecture:** A static Pages direct-upload directory contains only a human-readable status page and a machine-readable bootstrap manifest. Wrangler creates or targets the Pages project; no Worker, R2 bucket, custom domain, or installer executable is introduced in this slice.

**Tech Stack:** Cloudflare Pages, Wrangler 4.x, static HTML, JSON, shell verification.

**Spec:** `docs/superpowers/specs/2026-11-03-cloudflare-installer-bootstrap-design.md`

## Global Constraints

- Project name is exactly `usecifrarium`.
- The first bundle must not contain secrets or an executable installer.
- `/install.sh` must remain absent until the installer release exists.
- Deployment requires explicit Cloudflare authentication and must be verified by fetching the public URL.
- This bootstrap is not a release and does not authorize publication of a Cifrarium binary.

## Review Focus

- Accidental inclusion of the repository, secrets, `.git`, or recovery material in the upload; verify the exact file list.
- A bootstrap status being mistaken for a successful installer; test status fields and the absent `/install.sh` path.
- Wrong Cloudflare project or account; verify project name before upload and URL after upload.
- Deployment drift from local content; record the exact directory and deployment output.
- Future automation accidentally turning the endpoint executable without signed artifacts; document the release gate.

---

### Task 1: Static bootstrap bundle

**Files:**
- Create: `distribution/installer/index.html`
- Create: `distribution/installer/bootstrap.json`
- Test: shell file-list and JSON validation checks

- [x] Write the bootstrap manifest and page with explicit `bootstrap-only`
  status and no install command.
- [x] Verify the bundle contains only the intended static files and valid JSON.
- [x] Verify no `.git`, secret, recovery-share, or executable installer path is
  present.

### Task 2: Documentation and changelog

**Files:**
- Create: this design and plan
- Modify: `CHANGELOG.md` under `[Unreleased]`
- Modify: `README.md` only if the public bootstrap URL is verified and worth
  linking

- [x] Record the project name, public contract, and future release boundary.
- [x] Classify as deployment/bootstrap infrastructure; retain the current
  application version unless the release workflow changes it.

### Task 3: Cloudflare Pages deployment

**External target:** Cloudflare Pages project `usecifrarium`

- [x] Authenticate Wrangler with the operator's Cloudflare account.
- [x] Confirm or create exactly the `usecifrarium` Pages project.
- [x] Deploy only `distribution/installer` with the explicit project name.
- [x] Fetch the returned public URL, `bootstrap.json`, and `/install.sh` to
  verify the contract.
- [x] Record the deployment URL and deployment identifier in the issue tracker.
