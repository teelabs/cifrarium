# cifrarium

Cifrarium is a local, portable encrypted vault for application configuration
that needs secure storage, reuse, version management, and backup. It provides
a Linux CLI, an optional Linux user daemon, encrypted snapshots, 2-of-3
recovery shares, a Git-backed storage provider, and a local read-only MCP
interface.

The current release channel is Linux-first and supports `amd64` and `arm64`.
The installer resolves the published version from the signed manifest.

## Security model in one minute

- The local vault stores encrypted snapshots, encrypted catalog metadata, and
  keyring-backed keys.
- The Git provider receives ciphertext and encrypted manifests, never the
  captured plaintext.
- Recovery uses any two of three shares to reconstruct the operational and
  signing keys. Cifrarium never stores the shares in the vault or provider.
- Restored application files are plaintext again because applications need to
  read them. A malicious process running as the same operating-system user can
  read or alter those files and can interfere with the vault; Cifrarium is not
  a same-user sandbox.
- A failed verification, keyring check, provider privacy check, or persistence
  operation is a stop condition. Preserve the vault, queue, head, and logs
  while investigating.

For the detailed security boundary and residuals, read the [security and
red-team review](docs/security/2026-11-02-red-team-review.md).

## Install the signed Linux release

### Prerequisites

The host must be Linux `amd64` or `arm64` and provide:

- `curl` with HTTPS support;
- `tar`;
- `sha256sum`;
- `python3`;
- `cosign` for keyless signature verification.

`systemctl --user` is required only when enabling the daemon or removing an
installed user service. Normal CLI use also requires an available Linux user
keyring. Git is required for the optional storage provider; `gh` is required
only for the GitHub privacy diagnostic.

### Recommended installation command

The normal human flow is one command. It streams the release installer from the
canonical public origin, resolves the current published version, verifies the
archive, manifest, checksum, and Cosign bundle, then starts the guided setup:

~~~sh
curl -fsSL https://usecifrarium.pages.dev/install.sh | bash
~~~

For a reproducible agent install, pin the version and disable all prompts and
side effects:

~~~sh
curl -fsSL https://usecifrarium.pages.dev/install.sh \
  | bash -s -- --version 0.8.1 --non-interactive
~~~

The daemon is never enabled by non-interactive installation.

The installer audits all dependencies before starting the download. If several
tools are missing, it lists them together and prints a package-manager command
or Cosign installation guidance. It never runs those commands or invokes
`sudo` automatically; install the listed dependencies and run the same command
again.

Equivalent `wget` form:

~~~sh
bash -o pipefail -c \
  'wget -qO- https://usecifrarium.pages.dev/install.sh | bash -s -- --version "$1"' \
  bash 0.8.1
~~~

The stream form is convenient, but it does not let you inspect the installer
bundle before execution. For a higher-assurance installation, download
`install.sh` and `install.sh.bundle`, verify the script with the fixed GitHub
Actions identity and OIDC issuer, then execute the local script:

~~~sh
curl --fail --silent --show-error --location \
  https://usecifrarium.pages.dev/install.sh -o /tmp/cifrarium-install.sh
curl --fail --silent --show-error --location \
  https://usecifrarium.pages.dev/install.sh.bundle -o /tmp/cifrarium-install.sh.bundle
cosign verify-blob --bundle /tmp/cifrarium-install.sh.bundle \
  --certificate-identity-regexp \
  '^https://github.com/teelabs/cifrarium/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  /tmp/cifrarium-install.sh
chmod 0755 /tmp/cifrarium-install.sh
/tmp/cifrarium-install.sh --version 0.8.1 --non-interactive
~~~

Both forms refuse invalid metadata, signatures, checksums, architectures, or
paths. Neither form starts or enables the daemon unless `--enable` is supplied.

The default prefix is `$HOME/.local`; the active executable is
`$HOME/.local/bin/cifrarium`. Add it to `PATH` if needed:

~~~sh
export PATH="$HOME/.local/bin:$PATH"
cifrarium --version
~~~

Use a different absolute, user-owned prefix in the stream form when required:

~~~sh
bash -o pipefail -c \
  'curl --fail --silent --show-error --location https://usecifrarium.pages.dev/install.sh | bash -s -- --version "$1" --prefix "$2"' \
  bash 0.8.1 "$HOME/opt/cifrarium"
"$HOME/opt/cifrarium/bin/cifrarium" --version
~~~

### Upgrade, rollback, and uninstall

Install another explicit version to stage it and keep the previous version
available for rollback:

~~~sh
bash -o pipefail -c \
  'curl --fail --silent --show-error --location https://usecifrarium.pages.dev/install.sh | bash -s -- --version "$1"' \
  bash 0.4.1
bash -o pipefail -c \
  'curl --fail --silent --show-error --location https://usecifrarium.pages.dev/install.sh | bash -s -- --rollback "$1"' \
  bash 0.8.1
~~~

Rollback selects a version already staged under the prefix; it does not fetch
or execute a new artifact. Uninstall is destructive to the selected installed
versions, links, and Cifrarium user service, so it requires an explicit flag:

~~~sh
bash -o pipefail -c \
  'curl --fail --silent --show-error --location https://usecifrarium.pages.dev/install.sh | bash -s -- --uninstall --prefix "$1" --yes' \
  bash "$HOME/.local"
~~~

Uninstall does not remove the vault, provider checkout, recovery shares, or
files outside the selected installation prefix and Cifrarium service path.
Back up or export anything needed before uninstalling.

## First local use: initialize and ingest a snapshot

Configure the vault root once. Normal commands then resolve it automatically:

~~~sh
ROOT="$HOME/.local/share/cifrarium"
cifrarium setup --root "$ROOT"
cifrarium -command=status
cifrarium -command=status -format=json
cifrarium -command=snapshot
cifrarium -command=status
~~~

The normal `status` output is written for humans. Use `-format=json` when a
script or agent needs stable fields. `status` never initializes an unconfigured
computer or keyring. The first `snapshot` is the initial ingestion. Success means
that it prints a snapshot identifier and the following `status` exits zero.
The snapshot is encrypted before it is written to the vault; do not inspect
or print its plaintext.

The setup wizard presents one decision at a time. After each answer it shows
a separate confirmation block with the decision's effect and the next step.
Human output uses spacing, headings, and terminal colors when connected to a
TTY; redirected output keeps the same layout without ANSI control codes. Use
`-format=json` for machine-readable status and doctor output.

The built-in ingestion adapters currently collect only these allowlisted
paths when present:

- Codex: `~/.codex/config.toml` and `~/.codex/AGENTS.md`;
- Oh My Zsh: `~/.zshrc`, optional `~/.zprofile`, and regular non-hidden files
  below `~/.oh-my-zsh/custom`;
- Starship: `~/.config/starship.toml`.

They exclude sensitive or operational state such as Codex authentication,
logs, history, and cache, plus the Oh My Zsh framework, installed plugins, and
cache. Symlinks, unsafe paths, unsupported file types, changing files, and
oversized captures are rejected. There is currently no user-editable adapter
configuration file: adding a new adapter or changing an allowlist is a code
change requiring review.

If an allowlisted file such as `~/.zshrc` is a symlink, the first capture stops
with an actionable error. Cifrarium never follows it automatically. Copy the
target to a regular file using the command shown by the wizard, then run
`cifrarium setup` again.

## Diagnose the local installation

Use `doctor` for one read-only report of the vault, keyring, daemon, local MCP
socket, adapters, and optional GitHub provider:

~~~sh
cifrarium -command=doctor
~~~

The report does not create keys, a vault, a provider checkout, a socket, or a
service. When a GitHub provider is configured, the doctor also checks remote
access and repository privacy. An unconfigured provider and a disabled
optional daemon are warnings; a configured provider that cannot be reached,
an invalid vault, or a running daemon without a working MCP socket is a
problem and returns exit code 1.

For scripts and agents, request structured output and preserve the exit code:

~~~sh
cifrarium -command=doctor -format=json
~~~

The remote path belongs to the provider. Adapters report only their local
allowlisted paths; they do not have independent remote configuration.

## Generate and protect recovery shares

Generate shares only after the vault has opened successfully, and capture the
output directly into a protected local workflow rather than an agent log,
ticket, screenshot, shell history, or chat transcript:

~~~sh
umask 077
cifrarium -command=recovery-shares
~~~

The command prints three complete `label:value` lines, for example:

~~~text
cifrarium-1:BASE64_VALUE
cifrarium-2:BASE64_VALUE
cifrarium-3:BASE64_VALUE
~~~

Store at least two different shares in independent protected locations. A
single share is insufficient. Keep the exact label and value together; `/` or
`+` inside the Base64 value is ordinary encoded data. The shares reconstruct
both the operational and signing keys, so treat them as secret material.

Do not generate replacement shares casually: replacing the keyring without a
matching existing vault can make old snapshots unusable. If the output may
have been exposed, stop remote operations, assess compromise, and rotate or
rebuild through a deliberate recovery plan.

## Configure the storage provider

“Storage adapter” means the provider boundary in the current implementation.
The first provider is a private GitHub repository accessed by native Git. It
has two separate locations:

1. `CIFRARIUM_PROVIDER_DIR`: a dedicated local Git checkout containing only
   encrypted Cifrarium objects;
2. `CIFRARIUM_PROVIDER_REMOTE`: an HTTPS GitHub URL without embedded
   credentials.

Prepare the local checkout with restrictive permissions:

~~~sh
umask 077
mkdir -p "$HOME/.local/share/cifrarium-provider"
git -C "$HOME/.local/share/cifrarium-provider" init --initial-branch=main
~~~

Create or select a **private** GitHub repository. For a new repository, the
operator can use:

~~~sh
gh auth status
gh repo create OWNER/REPO --private \
  --source="$HOME/.local/share/cifrarium-provider" \
  --remote=origin
~~~

Use a repository-scoped credential with only metadata read and contents
read/write access, preferably with an expiry. Keep credentials in Git's
credential manager or the `gh` authentication boundary. Never place a token
in the remote URL, `daemon.env`, a Cifrarium argument, a snapshot, or a log.

Create the daemon environment file without putting real values in source
control:

~~~sh
umask 077
mkdir -p "$HOME/.config/cifrarium"
chmod 0700 "$HOME/.config/cifrarium"
touch "$HOME/.config/cifrarium/daemon.env"
chmod 0600 "$HOME/.config/cifrarium/daemon.env"
~~~

Its shape is:

~~~dotenv
CIFRARIUM_PROVIDER_DIR=/home/you/.local/share/cifrarium-provider
CIFRARIUM_PROVIDER_REMOTE=https://github.com/OWNER/REPO.git
CIFRARIUM_RECOVERY_SHARE_1='cifrarium-1:BASE64_VALUE_1'
CIFRARIUM_RECOVERY_SHARE_2='cifrarium-2:BASE64_VALUE_2'
~~~

The two recovery variables are separate names. The slash in the shorthand
`CIFRARIUM_RECOVERY_SHARE_1/2` is not part of a variable name. Keep the file
at mode `0600`; do not source it into an untrusted process or print it.

Check access and privacy before any upload:

~~~sh
PROVIDER_DIR="$HOME/.local/share/cifrarium-provider"
PROVIDER_REMOTE="https://github.com/OWNER/REPO.git"

cifrarium -command=provider-health \
  -provider-dir "$PROVIDER_DIR" \
  -provider-remote "$PROVIDER_REMOTE" \
  -verify-private
~~~

Expected evidence is JSON with `"status":"ok"`. This is a diagnostic, but
the upload boundary repeats the private-repository check. Privacy can still
change between a check and a remote GitHub operation, so enforce repository
and organization policy when that race matters.

The complete operator procedure, including token scope and incident response,
is in the [GitHub provider provisioning runbook](docs/runbooks/github-provider-provisioning.md).

## Enable the daemon only after preflight

Before activation, confirm all of the following:

- `cifrarium -command=status` succeeds;
- two distinct recovery shares are available in the protected environment
  file;
- `provider-health -verify-private` reports success;
- the provider checkout and remote URL are the intended ones;
- no concurrent migration, restore, or snapshot operation is running.

Then explicitly enable it:

~~~sh
systemctl --user daemon-reload
systemctl --user enable --now cifrarium.service
systemctl --user status cifrarium.service
journalctl --user -u cifrarium.service -n 100 --no-pager
~~~

The release installer writes the user unit during installation even when it
does not start it. This release flow does not require a source checkout or a
Go toolchain on the operator's machine.

The daemon captures snapshots, queues encrypted upload work, retries provider
failures, and persists the queue. A running process is not proof that an
upload completed: inspect logs, queue state, and provider health. The local
MCP socket is mode `0600` and exposes only read-only `status`,
`snapshot.plan`, and `restore.plan` methods. Plans do not apply mutations.

## Recover a fresh environment

When moving to a new machine, preserve or copy the encrypted vault directory,
install the same or a compatible Cifrarium release, make the user keyring
available, and provide two trusted distinct shares through a protected local
input path:

~~~sh
cifrarium -command=recover \
  -recovery-share "$SHARE_1_FROM_PROTECTED_INPUT" \
  -recovery-share "$SHARE_2_FROM_PROTECTED_INPUT"
cifrarium -command=status
~~~

Recovery verifies the existing signed catalog and head before replacing the
keyring. If it fails, preserve the vault and current keyring; do not delete
`head.json`, catalog files, snapshots, or the provider checkout and do not
force an import. A historical or inconsistent head must be rejected.

## Troubleshooting and data-loss prevention

| Symptom | Safe response |
| --- | --- |
| Installer checksum, signature, manifest, archive, or platform failure | Stop. Do not disable TLS or Cosign, substitute a different script, or retry with an unreviewed version. |
| `keyring unavailable` | Preserve the vault. Repair the user keyring/session and rerun `status`; use `recover` only when keys were actually lost. |
| Provider access timeout or authentication failure | Run `provider-health`, inspect Git credentials, and preserve `pending.queue`; never embed a token in a URL. |
| Repository reported public | Stop uploads, fix GitHub visibility/policy, rerun the privacy check, and retain existing encrypted history. |
| Pending queue exists | Treat it as durable encrypted work. Do not delete it to make the daemon appear healthy. |
| Queue or catalog persistence failure | Stop or leave the daemon stopped and preserve the vault, queue, and head for investigation. |
| Snapshot capture rejects a path or file | Reduce the allowlisted input; do not bypass size, symlink, or stability checks. |
| Migration is needed | Back up the vault first, stop concurrent operations, run `migrate-catalog`, then verify with `status`. |
| Interrupted multi-file restore | Preserve the generated backup and retry only after inspection; the MVP has no durable restore journal. |

The minimum preservation rule is: never delete the local vault, `head.json`,
catalog, snapshots, `pending.queue`, provider history, keyring entry, or
recovery material while diagnosing an error. Make a recoverable copy first and
record exact commands and exit codes without recording secrets.

## Human and agent operating rules

Humans should read the [user guide](docs/USER-GUIDE.md) for scenarios and the
[GitHub provider runbook](docs/runbooks/github-provider-provisioning.md) for
remote setup. Agents must read the [agent operating contract](docs/AGENT-USAGE.md)
before using the CLI, daemon, recovery flow, provider, or MCP.

For every operation, distinguish:

- read-only diagnostics: `status`, `provider-health`, and MCP plans;
- local mutations: `snapshot`, `migrate-catalog`, and recovery import;
- persistent/remote effects: daemon activation and provider upload;
- destructive effects: uninstalling, deleting queue/history, or replacing
  keyring state.

An agent may report a plan as a plan, never as a completed mutation. It must
preserve secret material, use an explicit version and prefix, report the
architecture and exact command, and stop on verification or integrity errors.

## Documentation and development

- [Human user guide](docs/USER-GUIDE.md)
- [Linux installer guide](docs/INSTALLER.md)
- [Agent operating contract](docs/AGENT-USAGE.md)
- [Canonical design](docs/superpowers/specs/2026-11-02-cifrarium-design.md)
- [Security and red-team review](docs/security/2026-11-02-red-team-review.md)
- [Changelog](CHANGELOG.md)

For development checks:

~~~sh
gofmt -l .
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check
./scripts/verify-version-changelog.sh
./scripts/verify-secrets.sh
~~~

Documentation is maintained in English so humans and agents share one
operational contract. This README is an entry point; implementation details
and security claims belong in the linked source documents and tests.
