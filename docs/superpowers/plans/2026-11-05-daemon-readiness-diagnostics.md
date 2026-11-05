# Daemon backend readiness and capture diagnostics

## Goal

Report MCP and backend readiness separately, and make startup capture failures actionable without exposing raw filesystem/provider errors. The reported v0.10.5 incident's underlying capture cause remains unknown; this work must not claim to fix that cause.

## Tasks

1. **Doctor readiness** — add a `Backend` component to JSON and human doctor reports. Probe existing `mcp.status` over `control.sock` with a bounded timeout. `ready` is healthy; `starting` or an unavailable readiness probe while systemd is active is a problem. Include Backend in doctor exit-code and Overall aggregation. Add deterministic probe-seam tests for starting, ready, unknown, and inactive.
2. **Safe capture diagnostics** — define bounded capture stages at `Backend.CaptureSnapshot` (adapter collection, vault write, encrypted snapshot read, manifest preparation). Preserve typed errors when `Scheduler.missed` joins the original and recovery-snapshot failures. Render a path only from a typed adapter failure whose path is relative and allowlisted; render stage-specific safe guidance otherwise. Remove string parsing that can infer symlink identity from arbitrary error text. Add redaction and stage tests.
3. **CLI readiness message** — map the known backend-not-ready RPC error to a safe explanation and next step for both status and snapshot. Keep daemon mediation and do not fall back to a second local capture while its control socket exists.
4. **Documentation and gates** — document the distinction between process/MCP/backend readiness and that a local snapshot taken with the service stopped does not prove daemon readiness. Update `[Unreleased]`; run the repository's full local gates and adversarial review. No real systemd activation, real shares, or provider upload.

## Verification

First prove each regression test fails against the baseline, then pass focused tests, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `./scripts/install-test.sh`, version/changelog, secrets, and diff checks. A reviewer must confirm no raw paths, symlink targets, recovery values, or arbitrary errors reach human/JSON/systemd output.
