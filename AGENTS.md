# Cifrarium agent operating contract

This repository contains a local encrypted configuration vault. Agents may
inspect and document the system, run read-only diagnostics, and execute
explicitly requested local operations. They must preserve the user's
credentials, recovery material, worktrees, and pending queue.

Read [docs/AGENT-USAGE.md](docs/AGENT-USAGE.md) before using the CLI, daemon,
provider, recovery flow, or MCP. It is the detailed operational contract; this
file is only the routing pointer and the repository gate summary.

## Required behavior

- Establish the current root, provider, branch, and worktree before acting.
- Classify an operation as read-only, local mutation, remote mutation, or
  destructive before running it.
- Ask for explicit confirmation before remote push, recovery import, daemon
  activation, restore activation, deletion, merge, publication, or deployment.
- Never request, print, copy, synthesize, or commit real recovery shares or
  tokens.
- Treat `status`, `provider-health`, and `migrate-catalog` output as evidence,
  not as permission to change external state.
- Preserve `pending.queue`, `head.json`, keyring state, and unrelated dirty
  work.
- Report same-user compromise as outside the confidentiality boundary: restored
  plaintext and user-owned secrets are readable by that user.

## Local verification

Run the relevant checks from the worktree:

~~~sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check
./scripts/verify-version-changelog.sh
./scripts/verify-secrets.sh
~~~

Before claiming completion, cite the exact command, result, changed paths, and
remaining residuals.
