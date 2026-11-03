# Cifrarium User Guide

This guide explains how to use Cifrarium as a local encrypted configuration
vault with encrypted snapshots, recovery shares, and optional private Git
backup.

## 1. Mental model

Cifrarium has four distinct storage areas:

| Area | Contents | Intended reader |
| --- | --- | --- |
| Local vault | Keyring-backed keys, signed catalog, encrypted snapshots | The local user and Cifrarium |
| Git provider | Ciphertext and encrypted manifests; never plaintext | The operator/GitHub under the operating policy |
| Daemon queue | Encrypted upload work | The user and daemon |
| Restored files | Plaintext configuration at normal application paths | The user and the applications that need it |

The vault protects data while it is stored in the vault or provider. When
configuration is restored for an application to use, it exists as plaintext in
the filesystem again. A malicious process running as the same user can also
read or alter those files; Cifrarium does not promise a confidentiality
boundary against that process.

Cifrarium still rejects traversal, dangerous symlinks, rollback, oversized
inputs, providers without privacy verification, and persistence failures that
could silently lose snapshots.

## 2. Prerequisites

- Linux with a user keyring for normal operation.
- The Go version declared in go.mod when running from source.
- Git for the local provider.
- An authenticated gh CLI when checking GitHub repository privacy.
- systemd --user only when the scheduled daemon is needed.

Check the current interface before copying examples:

~~~sh
go run ./cmd/cifrarium -h
~~~

The main commands are status, doctor, snapshot, recovery-shares, recover,
migrate-catalog, provider-health, and daemon.

## 3. First local use without a provider

Use this path to test the vault or keep snapshots only on the current machine.

~~~sh
ROOT="$HOME/.local/share/cifrarium"

go run ./cmd/cifrarium -root "$ROOT" -command=status
go run ./cmd/cifrarium -root "$ROOT" -command=snapshot
go run ./cmd/cifrarium -root "$ROOT" -command=status
~~~

Success criteria:

- snapshot prints a hexadecimal snapshot identifier;
- status exits with code zero;
- the vault does not contain plaintext application configuration;
- the user's keyring remains available.

This path is not a backup. Losing the machine or keyring may require recovery.

## 4. Create and store recovery shares

Generate shares after the first vault is working:

~~~sh
go run ./cmd/cifrarium -command=recovery-shares
~~~

The output has three lines like:

~~~text
cifrarium-1:BASE64_VALUE
cifrarium-2:BASE64_VALUE
cifrarium-3:BASE64_VALUE
~~~

Good practice:

1. store two different shares in protected, independent locations;
2. keep shares out of Git, tickets, logs, screenshots, and agent prompts;
3. never treat one share as sufficient;
4. keep CIFRARIUM_RECOVERY_SHARE_1 and CIFRARIUM_RECOVERY_SHARE_2 as separate variables;
5. treat each share as secret material while it can recover the vault.

The command does not print the operational or signing private keys.

## 5. Private GitHub provider

The provider has two layers: a local checkout and a remote repository. The
local checkout contains encrypted objects only. The complete procedure is in
the GitHub provider provisioning runbook.

Short setup:

~~~sh
umask 077
mkdir -p "$HOME/.local/share/cifrarium-provider"
git -C "$HOME/.local/share/cifrarium-provider" init --initial-branch=main
gh auth status
~~~

Create an operator-managed environment file:

~~~sh
mkdir -p "$HOME/.config/cifrarium"
chmod 700 "$HOME/.config/cifrarium"
touch "$HOME/.config/cifrarium/daemon.env"
chmod 600 "$HOME/.config/cifrarium/daemon.env"
~~~

Example contents, with no real values:

~~~dotenv
CIFRARIUM_PROVIDER_DIR=/home/you/.local/share/cifrarium-provider
CIFRARIUM_PROVIDER_REMOTE=https://github.com/OWNER/REPO.git
CIFRARIUM_RECOVERY_SHARE_1='cifrarium-1:BASE64_VALUE_1'
CIFRARIUM_RECOVERY_SHARE_2='cifrarium-2:BASE64_VALUE_2'
~~~

Check access and privacy before enabling uploads:

~~~sh
PROVIDER_DIR="$HOME/.local/share/cifrarium-provider"
PROVIDER_REMOTE="https://github.com/OWNER/REPO.git"

go run ./cmd/cifrarium -command=provider-health \
  -provider-dir "$PROVIDER_DIR" \
  -provider-remote "$PROVIDER_REMOTE" \
  -verify-private
~~~

Expected result: JSON containing status=ok. An access failure, mismatched
remote, or public repository stops preparation.

The privacy check is an operational check, not an atomic GitHub transaction: an
external administrator can change visibility after the check. Snapshots remain
encrypted, but organization or repository policy must enforce privacy when that
guarantee matters.

## 6. Scheduled daemon

Install without enabling:

~~~sh
./scripts/install-systemd-user.sh
~~~

After validating the provider and recovery setup:

~~~sh
systemctl --user enable --now cifrarium.service
systemctl --user status cifrarium.service
journalctl --user -u cifrarium.service -n 100 --no-pager
~~~

The daemon:

- captures snapshots at the interval defined by the code;
- retries uploads;
- keeps encrypted items queued when the provider is unavailable;
- persists the queue before continuing;
- stops when it cannot guarantee persistence;
- exposes a local MCP socket with mode 0600.

A running process is not proof that an upload succeeded. Check logs, queue
state, and provider-health.

## 7. Common failures and response

### Read-only health check

To see the state of the local vault, keyring, daemon, MCP socket, adapters, and
provider in one report, run:

~~~sh
ROOT="$HOME/.local/share/cifrarium"
cifrarium -root "$ROOT" -command=doctor
~~~

The command is read-only. It does not initialize missing keyring material,
create a vault, enable the daemon, or send data. If the provider is configured,
it performs the remote access and private-repository checks as part of the
report. Use `-format=json` for scripts and agents.

### Provider unavailable

Symptoms include GitHub access errors, timeouts, or pending items.

~~~sh
PROVIDER_DIR="$HOME/.local/share/cifrarium-provider"
PROVIDER_REMOTE="https://github.com/OWNER/REPO.git"

go run ./cmd/cifrarium -command=provider-health \
  -provider-dir "$PROVIDER_DIR" \
  -provider-remote "$PROVIDER_REMOTE" \
  -verify-private
journalctl --user -u cifrarium.service -n 100 --no-pager
~~~

Do not delete pending.queue, generate new shares, or embed a token in a URL.
Fix access or privacy, then let the daemon retry or restart it after confirming
that the queue is still present.

### Keyring unavailable

Stop and preserve the vault. Do not remove files to start over. Check the user
keyring/session and run status again. Use recover only when local keys were
actually lost or on a new machine.

### Recovery on a new machine

Copy the encrypted vault if it is available and provide two distinct shares:

~~~sh
go run ./cmd/cifrarium -root "$ROOT" -command=recover \
  -recovery-share 'cifrarium-1:VALUE_1' \
  -recovery-share 'cifrarium-2:VALUE_2'
go run ./cmd/cifrarium -root "$ROOT" -command=status
~~~

Recovery verifies the head and signed chain before replacing the keyring. A
historical or inconsistent head must be rejected. If recovery fails, preserve
the files and investigate; do not force the import.

### Legacy catalog

Run migration only when the vault came from a version that used the legacy
catalog format:

~~~sh
go run ./cmd/cifrarium -root "$ROOT" -command=migrate-catalog
go run ./cmd/cifrarium -root "$ROOT" -command=status
~~~

Back up the directory before migration. “Already uses encrypted metadata”
means that no conversion was needed.

### Input too large

Cifrarium rejects file, snapshot, manifest, queue, path, and MCP-line limits.
That is expected protection against unbounded memory or disk use. Reduce the
input scope; do not raise production limits without reviewing the threat model.

## 8. Local MCP

The MCP is local-only and offers status, snapshot.plan, and restore.plan. Plans
are not mutations: they require explicit confirmation and a separate flow. Do
not expose the socket over a network, copy it to another host, or treat a plan
response as proof that a restore was applied.

The current CLI does not expose a public restore-activation command;
restore.plan is planning only. Agents must state this clearly.

## 9. Usage scenarios

| Scenario | Recommended path | Success evidence |
| --- | --- | --- |
| Local evaluation | status -> snapshot | Snapshot created and status remains healthy |
| Recurring private backup | provider-health -> daemon | Clean logs and provider updated |
| New laptop | Copy vault -> two shares -> recover -> status | Chain verified and keyring imported |
| Offline period | Keep daemon running | Encrypted queue persists and later uploads |
| Repository became public | Stop uploads, check GitHub, fix policy | Provider is private before resuming |
| Same-user process compromised | Assume read/alter capability | External isolation, rotation, and recovery; do not treat the vault as a sandbox |
| Legacy catalog migration | Backup -> migrate-catalog -> status | Encrypted metadata and guard verified |

## 10. Do not

- put tokens or shares in remote URLs;
- enable the daemon before checking provider and recovery setup;
- delete the queue or head to bypass an error;
- treat provider ciphertext as editable configuration;
- promise that restored plaintext is protected from the same user;
- publish, merge, or deploy merely because local tests pass.

For development, use the checks described in the README and the root AGENTS.md.
