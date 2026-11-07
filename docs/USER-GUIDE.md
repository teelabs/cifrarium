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

The systemd unit uses `$HOME/.config` as its default configuration directory.
If `XDG_CONFIG_HOME` is customized, set the same value in the operator-managed
`daemon.env` so the CLI and daemon resolve the same root configuration.

Check the current interface before copying examples:

~~~sh
go run ./cmd/cifrarium -h
~~~

The main commands are `status`, `doctor`, `setup`, `restore`, `snapshot`,
`snapshot audit`, `daemon`, `daemon refresh`, `migrate-catalog`, `provider setup`,
`provider health`, `recovery shares`, and `recovery import`. Options follow the subcommand, for example
`cifrarium provider health --verify-private`.

`cifrarium snapshot audit` compares current allowlisted adapter files with the
latest verified local snapshot. `-format=json` returns `matches`, `differs`, or
`noSnapshot`, with sorted relative-path difference lists when a baseline exists.
Differences and no baseline are successful audit results; read or integrity
errors fail without returning partial results. The audit does not create a
snapshot or update vault, keyring, queue, or provider state.

Run `cifrarium --help` to see this command list and the global options. Help
uses blank provider defaults intentionally: configured paths, remotes,
usernames, and recovery material are resolved only after parsing and are never
printed as help defaults.

Upgrading Cifrarium preserves the configured vault root, keyring, snapshot
history, provider checkout, and existing recovery shares. Setup is idempotent:
an upgrade or retry reuses existing key material and does not print new shares.
Use `recovery shares` only when you explicitly need a new set. Provider setup
can preserve existing shares, import a protected pair, or generate a new set
only after explicit confirmation.

The root configuration is non-secret and per-user:
`${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/config.json`. It contains only
schema `1` and the canonical vault path, with directory mode `0700` and file
mode `0600`. Configure it once; normal commands do not need `-root`.

The interactive setup is staged. Each answer is confirmed immediately with
its effect and the next step. Human output uses headings, spacing, and colors
on a terminal, while redirected output omits ANSI colors. Use JSON output when
another program needs stable fields.

## 3. First local use without a provider

Use this path to test the vault or keep snapshots only on the current machine.

~~~sh
go run ./cmd/cifrarium setup --root "$HOME/.local/share/cifrarium"
go run ./cmd/cifrarium status
go run ./cmd/cifrarium snapshot
go run ./cmd/cifrarium status
~~~

Success criteria:

- snapshot prints a hexadecimal snapshot identifier;
- repeated captures with identical paths, modes, and bytes report
  `(unchanged; reused current)` and do not add another local snapshot;
- status exits with code zero;
- the vault does not contain plaintext application configuration;
- the user's keyring remains available.

This path is not a backup. Losing the machine or keyring may require recovery.

Symlinked allowlisted files are rejected rather than followed. If the daemon
reports one, stop it before changing the path and inspect only the link:

~~~sh
systemctl --user stop cifrarium.service
test -L "$HOME/.zshrc" && readlink "$HOME/.zshrc"
~~~

If the symlink is intentional, materialize a regular file through the dotfile
manager or leave capture disabled. Otherwise, create and atomically install a
regular copy:

~~~sh
cp --dereference --preserve=mode \
  "$HOME/.zshrc" "$HOME/.zshrc.cifrarium-regular"
test ! -L "$HOME/.zshrc.cifrarium-regular"
mv "$HOME/.zshrc.cifrarium-regular" "$HOME/.zshrc"
cifrarium snapshot
systemctl --user start cifrarium.service
~~~

This can break future updates from the dotfile manager. Do not use `rm`,
`source`, `sudo`, or disable the symlink safety check. No remote upload occurs
until the local snapshot succeeds.

The daemon diagnostic is organized as `Daemon needs attention`, followed by
`What happened`, `Why it matters`, `How to fix it`, and `What to do next`. Its
correction block is a copyable instruction rather than diagnostic output, with
explicit separators before and after the commands. A local capture failure
ends the foreground daemon and returns control to the shell. Pending recovery
verification and provider/upload failures use `Retry? [Y/n]` with yes as the
default; after confirmation the daemon explains that another console can be
used, shows a countdown, and accepts Enter for an immediate retry. A negative
answer returns to the shell. Systemd and other non-TTY runs retry without a
prompt. The encrypted pending queue is preserved. It extracts only the validated local path
from a compound error such as
`symlink rejected: .zshrc; recovery snapshot failed: symlink rejected: .zshrc`;
it never prints the symlink target, file contents, tokens, or recovery shares.
TTY output uses the muted Codex semantic palette: headers `#58A6FF`, commands
`#3FB950`, paths `#79C0FF`, warnings `#D29922`, failures `#F85149`, identity
`#D2A8FF`, and secondary text `#8B949E`. Redirected output, systemd logs, and
JSON have no ANSI control codes.
The retry countdown defaults to 30 seconds and accepts a Go duration from
`CIFRARIUM_DAEMON_RETRY_TIMEOUT`, such as `45s`, in the protected daemon
environment.

Pending-upload diagnostics explain whether recovery verification, provider
setup, repository privacy, or provider access needs attention. They suggest
safe commands without printing configured values. Use another console for the
correction, preserve `pending.queue`, then return to the daemon console and
press Enter or wait for retry.

## 4. Create and store recovery shares

Generate shares after the first vault is working:

~~~sh
go run ./cmd/cifrarium recovery shares
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
local checkout contains encrypted objects only. The guided path is:

~~~sh
cifrarium provider setup
~~~

The wizard can keep the provider local-only, validate an existing private
GitHub repository, or create a new private repository through the operator's
authenticated `gh` CLI. It writes `daemon.env` atomically with mode `0600`,
preserves unrelated variables, and never stores or asks for a GitHub token.
It also preserves existing shares, or offers a protected-file import or
explicit share generation. No snapshot or upload occurs during setup.

For environments where the wizard cannot be used, the complete manual
procedure is in the GitHub provider provisioning runbook.

Short setup:

~~~sh
umask 077
mkdir -p "$HOME/.local/share/cifrarium-provider"
git -C "$HOME/.local/share/cifrarium-provider" init --initial-branch=main
gh auth status
~~~

The wizard creates the operator-managed environment file. Its shape is shown
below only to explain what it manages; do not paste real shares into tickets,
logs, or prompts:

~~~sh
mkdir -p "$HOME/.config/cifrarium"
chmod 700 "$HOME/.config/cifrarium"
touch "$HOME/.config/cifrarium/daemon.env"
chmod 600 "$HOME/.config/cifrarium/daemon.env"
~~~

Example contents, with no real values:

~~~dotenv
CIFRARIUM_PROVIDER_DIR=$HOME/.local/share/cifrarium-provider
CIFRARIUM_PROVIDER_REMOTE=https://github.com/OWNER/REPO.git
CIFRARIUM_RECOVERY_SHARE_1='cifrarium-1:BASE64_VALUE_1'
CIFRARIUM_RECOVERY_SHARE_2='cifrarium-2:BASE64_VALUE_2'
~~~

Check access and privacy before enabling uploads:

~~~sh
PROVIDER_DIR="$HOME/.local/share/cifrarium-provider"
PROVIDER_REMOTE="https://github.com/OWNER/REPO.git"

go run ./cmd/cifrarium provider health \
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

The daemon is the backend for coordinated CLI and MCP operations. After
changing protected daemon configuration, use:

~~~sh
cifrarium daemon refresh
~~~

This reloads and restarts the managed user service, then reports MCP and
backend readiness separately. If MCP is ready while the backend is waiting for
recovery/provider setup, the command exits successfully with both states and a
safe next step. Full readiness requires both endpoints; an early service exit
includes a sanitized systemd cause. MCP tools remain protocol operations; they
are not exposed as `cifrarium mcp ...` shell commands.

`cifrarium doctor` reports daemon process, MCP transport, and backend
readiness separately. If the daemon is active but the backend is still
starting, `status` and `snapshot` remain daemon-mediated and report that state;
`status` and `snapshot` return a safe explanation and do not create a second
local snapshot. To test local capture independently, exit a foreground daemon
by answering `n` at `Retry?`, or stop a systemd-managed daemon with
`systemctl --user stop cifrarium.service` before running `cifrarium snapshot`.
A successful local snapshot does not prove that the daemon backend is ready.

When initial daemon work fails, diagnostics identify whether Cifrarium was
draining pending uploads, uploading a new capture, or unable to retain a failed
upload because the queue is full. A full-queue message means the new local
snapshot was captured but was not queued and its provider upload was not
confirmed. Keep the daemon stopped, do not edit or delete `pending.queue`, and
check `cifrarium status -format=json` plus `cifrarium provider health
--verify-private` before retrying.

A running process is not proof that an upload succeeded. Check logs, queue
state, and provider health.

## 7. Common failures and response

### Read-only health check

To see the state of the local vault, keyring, daemon, MCP socket, adapters, and
provider in one report, run:

~~~sh
cifrarium doctor
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

go run ./cmd/cifrarium provider health \
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

For a new installation, install Cifrarium, authenticate `gh` for the private
GitHub repository, then run the interactive restore command:

~~~sh
cifrarium restore
~~~

The command asks for the private GitHub remote when it is not configured and
reads two distinct recovery shares without echo when the keyring is missing.
It stages the remote history locally, verifies its signatures and hashes, then
lets you choose the newest snapshot (default) or another verified snapshot,
and select adapters or individual files. Destination conflicts offer
overwrite, keep, cancel, and an optional terminal-only diff. Existing files
that are replaced receive private backups under `backups/` in the configured
vault. If the daemon is already active, the CLI asks it to independently
reverify the history and destination preflight, then apply the selected files.
It exits after a successful restore, and the CLI disables its systemd service.
The daemon remains disabled after recovery.

The flow requires a TTY and does not accept shares through command arguments or
JSON output. It does not upload to GitHub. On a new machine, the provider branch
is the freshness anchor: Cifrarium cannot detect a valid older signed history
if the remote branch itself was rolled back. A valid signed chain is still
required. If recovery fails, preserve local files and investigate; do not force
an import. If the remote history has multiple branches or no unique head,
restore stops before writing local recovery state; do not choose or edit
catalog entries manually.

During initial interactive setup, answer yes to the recovery question to run
the same flow before any new keys or recovery shares are created. Non-interactive
setup never offers recovery. For an existing vault whose keys alone were lost,
use `recovery import` with two protected shares instead.

### Legacy catalog

Run migration only when the vault came from a version that used the legacy
catalog format:

~~~sh
go run ./cmd/cifrarium migrate-catalog
go run ./cmd/cifrarium status
~~~

Back up the directory before migration. “Already uses encrypted metadata”
means that no conversion was needed.

### Input too large

Cifrarium rejects file, snapshot, manifest, queue, path, and MCP-line limits.
That is expected protection against unbounded memory or disk use. Reduce the
input scope; do not raise production limits without reviewing the threat model.

## 8. Local MCP

The MCP is local-only and offers status, snapshot.plan, restore.plan, and
snapshot.audit as protocol tools. `snapshot.audit` is read-only and compares
the current allowlisted adapter files with the latest verified local snapshot.
Plans are not mutations: they require explicit confirmation and a separate
flow. Do not expose the socket over a network, copy it to another host, or
treat a plan response as proof that a restore was applied.

`restore.plan` remains a read-only MCP plan. File restoration is available only
through the interactive `cifrarium restore` CLI and requires final human
confirmation.

## 9. Usage scenarios

| Scenario | Recommended path | Success evidence |
| --- | --- | --- |
| Local evaluation | status -> snapshot | Snapshot created and status remains healthy |
| Recurring private backup | provider health -> daemon | Clean logs and provider updated |
| New laptop and selected files | `cifrarium restore` -> choose snapshot/files | Verified chain installed, selected files restored, daemon disabled |
| Lost keyring with existing vault | Two shares -> `recovery import` -> status | Chain verified and keyring imported |
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
