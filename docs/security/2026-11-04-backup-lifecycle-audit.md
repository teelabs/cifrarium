# Backup lifecycle adversarial audit — 2026-11-04

## Scope and boundary

This audit traced the verified installer, configured root, keyring, provider
configuration, encrypted pending queue, systemd unit, daemon service/backend,
MCP, CLI refresh, and recovery verification. It compared upgrade with a new
local-only setup and provider resume. All test state lived under temporary
folders; the keyring was mocked in memory. Test-only recovery material was
created from an ephemeral key, used only in process memory, and never printed.
No real vault, keyring, queue, provider checkout, daemon, or remote repository
was used.

Tracker gate: audit issue #106 is High priority and In Progress on Project #5.
Five pre-existing open issues were Todo; no existing item was In Progress.
Follow-up findings #107–#110 are separate Bug issues in Todo. TRAG was not
available, so this report uses current source and local harness evidence only.

## Findings

### High — generated recovery shares prevent every configured upload (#107)

`store.RecoveryShares` creates shares for a JSON bundle containing both the
operational and signing keys. `internal/sync/upload.go` recombines the pair and
compares the entire bundle bytes directly to the operational key. Therefore,
the exact pair generated for setup can recover both keys but fails the upload
gate with `recovery verification required before upload`. The queue remains
encrypted and retained, while remote backup never resumes with the configured
shares.

Reproduced by:

```sh
go test ./cmd/cifrarium -run '^TestLifecycleAuditFreshInstallQueueResume$' -count=1 -v
```

The harness validates that the generated pair recovers the keyring material,
then verifies that upload rejects it. It then uses a separate ephemeral
operational-key pair solely to exercise the queue-drain mechanics expected by
the current gate; this is not representative of setup output.

### Medium — installed unit splits custom XDG state from CLI state (#109)

The CLI root and provider config paths honor `XDG_CONFIG_HOME`. The unit
hardcodes `XDG_CONFIG_HOME=%h/.config` and reads
`%h/.config/cifrarium/daemon.env`. The installer, however, chooses the unit and
provider-config locations from the caller's `XDG_CONFIG_HOME`. A custom-XDG
installation can consequently leave the CLI and managed daemon reading
separate root/provider configuration.

Reproduced by:

```sh
go test ./cmd/cifrarium -run '^TestLifecycleAuditCustomXDGSystemdUnitMismatch$' -count=1 -v
```

The test compares only temporary paths and the unit template; it does not start
systemd.

### Medium — refresh reports backend ready while it is still starting (#108)

`daemonRefreshReady(backend, mcp)` ignores `backend`. It accepts
`backend=starting, mcp=ready`, after which the CLI prints that both backend and
MCP are ready. This state is expected while recovery action is pending; the
user should see MCP transport readiness and backend wait state separately.

Reproduced by:

```sh
go test ./cmd/cifrarium -run '^TestDaemonRefreshAcceptsMCPWhileBackendIsWaiting$' -count=1 -v
```

### Medium — readiness timeout misreports a service that exited (#110)

After `systemctl --user restart` succeeds, refresh polls socket readiness for
10 seconds but never checks systemd state during the wait. If the service exits,
the function still reports `daemon service is active but MCP did not become
ready`, with no safe cause or next step.

Reproduced with a fake systemctl state and unavailable temporary socket probes:

```sh
go test ./cmd/cifrarium -run '^TestLifecycleAuditRefreshMasksExitedService$' -count=1 -v
```

### Risks not established as findings

- A process crash during handled multi-file restore remains the separately
  tracked residual in issue #68; this audit did not attempt power-loss testing.
- The installer harness uses sentinel files for the existing history, keyring,
  pending queue, and provider/recovery configuration. It does not substitute
  for an on-disk Secret Service integration or a power-loss durability test.
- Cancellation and interactive retry key handling are covered by focused unit
  tests; this harness does not automate a real controlling terminal or
  SIGTERM against an installed systemd user service.
- Provider verification and upload are mocked. No remote upload or privacy
  boundary was exercised.
- No separate rollback fault was reproduced; the harness verifies version
  selection and pending-queue preservation during successful rollback.

## Harness and evidence

Run the complete isolated audit with:

```sh
./scripts/lifecycle-audit-test.sh
```

It composes the installer control-flow harness with a Go lifecycle test that
uses temporary home/XDG/vault/provider state, a temporary encrypted queue, and
in-memory keyring/recovery values. It verifies a local-only snapshot, pending
queue persistence when normal setup recovery shares fail upload verification,
restart behavior, and drain mechanics when the upload gate receives its
expected ephemeral fixture. It also reproduces XDG and daemon-readiness issues.

The installer phase simulates successful upgrade, provider-missing,
provider-offline, public-provider, invalid configuration, migration-required,
signature-failure, and rollback paths. Sentinel history, keyring, pending queue,
and `daemon.env` contents are compared byte-for-byte on the relevant paths.

## Delivery boundary

This round contains an audit report and test harness only. No product fix,
commit, push, PR, merge, release, deployment, daemon activation, or remote
provider mutation was performed. The issues #107–#110 hold the proposed fixes
as separate Todo work.

## Verification

- `./scripts/lifecycle-audit-test.sh` — PASS; installer scenarios and all four
  reproduction/lifecycle probes passed.
- `go test ./...` — PASS.
- `go test -race ./...` — PASS.
- `go vet ./...` — PASS.
- `go build ./...` — PASS.
- `./scripts/verify-version-changelog.sh` — PASS; version-tracking files found:
  `VERSION` and `CHANGELOG.md`.
- `./scripts/verify-secrets.sh` — PASS.
- `git diff --check` — PASS.
- `npm run audit:github-text` — unavailable because this Go repository has no
  `package.json`; the required remote fallback
  `node /home/thiago/.agents/bin/validate-github-text.mjs --remote
  teelabs/cifrarium` passed.

Version-changelog classification: documentation and test-only audit work;
current version remains 0.10.2. No product behavior or release metadata
changed.
