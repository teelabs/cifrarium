# Cifrarium daemon backend and local interfaces

## Decision

The daemon is the operational backend and single source of truth for normal
Cifrarium operations. The human CLI and MCP are separate interfaces over the
same backend; neither interface owns a second copy of vault, queue, provider,
or recovery rules.

```text
CLI ─────> daemon backend <──── MCP
```

The current MVP implements Linux transport only. The transport contract uses
logical endpoint names so future macOS and Windows implementations do not
require domain changes.

## Local control contract

The CLI-to-daemon control interface uses versioned JSON-RPC 2.0 over a private
Linux Unix socket. Requests use named parameters, IDs, timeouts, cancellation,
bounded payloads, protocol negotiation, and structured errors. The current
protocol identifier is `cifrarium.control.v1`.

The daemon control endpoint is separate from the MCP endpoint. Both endpoints
delegate to daemon-owned services, but MCP receives an explicit allowlist and
does not receive the internal control API wholesale. Status, capture, and
planning are computed by the same backend object; adapters only render or
frame those results.

## Responsibilities

The daemon backend owns vault access, keyring gates, adapters, snapshot
creation, recovery verification, queue persistence, provider uploads, restore
planning/activation, scheduler state, readiness, and concurrency.

The CLI owns argument parsing, prompts, confirmations, human/JSON rendering,
and exit codes. The MCP adapter owns MCP protocol framing, tool/resource
exposure, and protocol errors. Neither interface bypasses backend validation.

Bootstrap and emergency paths may operate locally when no healthy daemon exists
for setup, initial recovery, installation, and minimum diagnostics.

## Lifecycle and readiness

`cifrarium daemon refresh` reloads the managed user service, restarts it, and
waits until the MCP socket accepts connections and the control endpoint reports
the independent MCP and backend states. A socket existing alone is not
sufficient evidence. When MCP is ready but the backend is still starting while
recovery/provider setup is pending, refresh exits successfully and reports both
states with a safe next step. It claims full readiness only when both are ready.
If systemd reports that the service exited before readiness, refresh returns a
sanitized systemd state/result/exit-status diagnostic and a safe next step.

The Linux service uses systemd user lifecycle. macOS launchd, Windows service
or user-process lifecycle, Unix sockets on macOS, and Windows Named Pipes are
post-MVP implementations tracked in issue #98.

## MCP boundary

MCP tools remain protocol operations such as status, snapshot planning, and
restore planning. They are not `cifrarium mcp ...` shell commands. Mutation
tools, if added later, require explicit authorization and remain subject to the
same daemon safety gates.

## Future adapter plugins

Builtin adapters remain in the MVP. Issue #99 defines the future versioned
out-of-process plugin protocol; issue #100 tracks builtin deprecation and
removal after compatibility, comparison, fallback, and rollback evidence.
Plugins will return structured records only. The daemon will retain path,
symlink, traversal, size, encryption, queue, and provider validation.
