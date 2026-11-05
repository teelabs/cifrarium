#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

printf '%s\n' 'Lifecycle audit: installer upgrade preservation'
"$ROOT_DIR/scripts/install-test.sh"

printf '%s\n' 'Lifecycle audit: fresh local snapshot, encrypted queue, restart, and upload resume'
go test ./cmd/cifrarium -run '^TestLifecycleAuditFreshInstallQueueResume$' -count=1 -v

printf '%s\n' 'Lifecycle audit: custom XDG/systemd path comparison'
go test ./cmd/cifrarium -run '^TestLifecycleAuditCustomXDGSystemdUnitMismatch$' -count=1 -v

printf '%s\n' 'Lifecycle audit: MCP/backend readiness mismatch reproduction'
go test ./cmd/cifrarium -run '^TestDaemonRefreshAcceptsMCPWhileBackendIsWaiting$' -count=1 -v

printf '%s\n' 'Lifecycle audit: exited service diagnostic reproduction (10 second bound)'
go test ./cmd/cifrarium -run '^TestLifecycleAuditRefreshMasksExitedService$' -count=1 -v

printf '%s\n' 'Lifecycle audit harness completed'
