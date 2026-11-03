# cifrarium

Cifrarium is a local, portable encrypted vault for application configuration
that needs secure storage, reuse, version management, and backup. It provides
a CLI, an optional Linux user daemon, and a local read-only MCP interface.

## What it does

- Captures application configuration into encrypted, versioned snapshots.
- Keeps keys in the Linux keyring and uses two of three recovery shares for
  recovery and before remote upload.
- Uses a private Git repository as the first remote provider; remote setup is
  operator-managed.
- Restores snapshots atomically with a local backup and rejects unsafe paths.
- Exposes local status and change-plan MCP methods through the daemon; it does
  not accept autonomous mutations.

The first adapters support Codex, Oh My Zsh, and Starship. They are the
initial integrations, not a limit on the types of application configuration
that Cifrarium is intended to manage.

## Requirements

- Linux with a user keyring and `systemd --user` for daemon installation.
- Go version declared in [`go.mod`](go.mod).
- Git for the local provider and optional GitHub remote.
- An authenticated `gh` CLI only when running the optional private-repository
  diagnostic.

## Quick start

Run these commands from a checkout:

```sh
go run ./cmd/cifrarium -command=status
go run ./cmd/cifrarium -command=snapshot
go run ./cmd/cifrarium -command=recovery-shares
```

The `recovery-shares` command prints three lines such as
`cifrarium-1:BASE64_VALUE`. Store two different lines in separate protected
locations. Cifrarium never stores recovery shares in the vault or provider.

## Configure the daemon

Create `~/.config/cifrarium/daemon.env` yourself with mode `0600`:

```dotenv
CIFRARIUM_PROVIDER_DIR=/home/you/.local/share/cifrarium-provider
CIFRARIUM_PROVIDER_REMOTE=https://github.com/OWNER/REPO.git
CIFRARIUM_RECOVERY_SHARE_1='cifrarium-1:BASE64_VALUE_1'
CIFRARIUM_RECOVERY_SHARE_2='cifrarium-2:BASE64_VALUE_2'
```

`CIFRARIUM_RECOVERY_SHARE_1` and `CIFRARIUM_RECOVERY_SHARE_2` are two separate
variable names. The `/` in the shorthand `CIFRARIUM_RECOVERY_SHARE_1/2` is not
part of a variable name. A `/` or `+` that appears inside the Base64 value is
normal encoded data; keep the complete `label:value` line and quote it as
shown. Never put real shares in shell history or commit them.

Install the user service without starting it:

```sh
./scripts/install-systemd-user.sh
```

Enable it only after checking the provider and recovery setup:

```sh
systemctl --user enable --now cifrarium.service
systemctl --user status cifrarium.service
```

The complete provider setup and first-upload procedure is in the
[GitHub provider provisioning runbook](docs/runbooks/github-provider-provisioning.md).

## Check the provider

The health command performs a read-only Git access check. Add
`-verify-private` to check the GitHub repository privacy setting through the
operator's `gh` authentication:

```sh
go run ./cmd/cifrarium -command=provider-health \
  -provider-dir "$HOME/.local/share/cifrarium-provider" \
  -provider-remote "https://github.com/OWNER/REPO.git" \
  -verify-private
```

## Recover a fresh environment

Set two trusted recovery shares in the environment, then run:

```sh
go run ./cmd/cifrarium -command=recover
go run ./cmd/cifrarium -command=status
```

Recovery verifies the existing vault before importing the reconstructed keys.
Treat shares as secret material and do not place them in a remote repository.

## Local MCP

The daemon creates a mode-`0600` local socket with read-only `status`,
`snapshot.plan`, and `restore.plan` methods. Restore plans still require CLI
confirmation. Remote MCP and autonomous mutation methods are not supported.

## Documentation

- [Human user guide](docs/USER-GUIDE.md)
- [Contrato operacional para agentes](docs/AGENT-USAGE.md)
- [Instruções locais para agentes](AGENTS.md)
- [Canonical design](docs/superpowers/specs/2026-11-02-cifrarium-design.md)
- [Security and red-team review](docs/security/2026-11-02-red-team-review.md)
- [Brand guidance](docs/brand/README.md)
- [Changelog](CHANGELOG.md)

## Choose a path

- For local-only testing, start with the [human user guide](docs/USER-GUIDE.md#3-first-local-use-without-a-provider).
- For recurring private backup, read the [GitHub provider runbook](docs/runbooks/github-provider-provisioning.md) and then the daemon workflow in the guide.
- For an agent or automation, read the [agent contract](docs/AGENT-USAGE.md) before running any command.

The vault protects configuration while it is encrypted at rest. Restored files
are plaintext by design so applications can use them; a process running as the
same user is outside Cifrarium's confidentiality boundary. The security review
records this residual and the separate GitHub visibility race explicitly.

For development checks, run `go test ./...`, `go test -race ./...`, `go vet
./...`, and `go build ./...`. The full CI workflow also checks formatting,
secrets, changelog/version consistency, MCP handshake, and the systemd
installer.
