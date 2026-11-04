# Linux Installer

The release installer supports Linux `amd64` and `arm64`. It downloads a
versioned archive from the `usecifrarium` Pages origin and verifies both its
SHA-256 checksum and its keyless Cosign bundle before extracting anything.
The installer host must provide `curl`, `tar`, `sha256sum`, `python3`, and
`cosign`; `systemctl` is needed only with `--enable` or when removing an
installed user service.

## Install a release

For the normal human flow, the installer resolves the current published
version from the manifest and starts the guided setup:

```sh
curl -fsSL https://usecifrarium.pages.dev/install.sh | bash
```

For agents and reproducible installs, pin the version and disable prompts and
side effects:

```sh
curl -fsSL https://usecifrarium.pages.dev/install.sh \
  | bash -s -- --version 0.9.2 --non-interactive
```

For the highest-assurance path, inspect and verify the installer first:

```sh
curl --fail --silent --show-error --location \
  https://usecifrarium.pages.dev/install.sh \
  -o /tmp/cifrarium-install.sh
curl --fail --silent --show-error --location \
  https://usecifrarium.pages.dev/install.sh.bundle \
  -o /tmp/cifrarium-install.sh.bundle
cosign verify-blob --bundle /tmp/cifrarium-install.sh.bundle \
  --certificate-identity-regexp \
  '^https://github.com/teelabs/cifrarium/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  /tmp/cifrarium-install.sh
chmod 0755 /tmp/cifrarium-install.sh
/tmp/cifrarium-install.sh --version 0.9.2 --non-interactive
```

The default prefix is `$HOME/.local`. The active executable is
`$HOME/.local/bin/cifrarium`; add `$HOME/.local/bin` to `PATH` if necessary.
The command installs files and starts the assistant only when a TTY is
available. It does not start or enable the daemon implicitly.

After installation, configure the vault location once:

```sh
cifrarium setup --root "$HOME/.local/share/cifrarium"
```

Normal commands resolve that configured root automatically. The installer does
not configure a root in `--non-interactive` mode.

The systemd user unit defaults `XDG_CONFIG_HOME` to `$HOME/.config`. If a
custom XDG directory is required, set `XDG_CONFIG_HOME` in the mode-`0600`
`daemon.env` used by the unit and configure the root there before activation.

## Missing dependencies and progress output

The installer audits every dependency needed for the selected operation before
creating its state directory or downloading a release. A normal installation
needs `curl`, `tar`, `sha256sum`, `python3`, `cosign`, `mktemp`, `mv`, `ln`,
`install`, `mkdir`, `rm`, `rmdir`, `dirname`, `sed`, and `grep`. `systemctl` is
added only for `--enable`, and is required when uninstalling an installed user
service.

If more than one tool is missing, the installer reports all of them in one
message, detects a supported package manager when possible, and prints a
copyable suggestion. It never runs the suggestion or invokes `sudo` itself.
For Cosign, follow the official installation and verification instructions:

<https://docs.sigstore.dev/cosign/system_config/installation/>

After installing the dependencies, run the original command again. During a
successful run, the installer reports platform checks, manifest and artifact
downloads, checksum and signature verification, archive validation, and atomic
installation before starting the assistant.

## Custom prefix and daemon activation

Use a user-owned absolute prefix when the default is unsuitable:

```sh
/tmp/cifrarium-install.sh \
  --version 0.9.2 \
  --prefix "$HOME/opt/cifrarium"
```

After configuring `~/.config/cifrarium/daemon.env` and checking provider and
recovery-share prerequisites, opt in to activation:

```sh
/tmp/cifrarium-install.sh --version 0.9.2 --enable
systemctl --user status cifrarium.service
```

`--enable` runs `systemctl --user enable --now`. Without that flag no service
manager command is invoked.

## Upgrade and rollback

Install another explicit version to retain the previous active target:

```sh
/tmp/cifrarium-install.sh --version 0.4.1
/tmp/cifrarium-install.sh --rollback 0.6.1
```

An existing installation is an upgrade, not a new setup. The installer keeps
the configured root, keyring, snapshots, provider checkout, and recovery
shares intact; it does not run `setup` or generate shares again. It stages and
preflights the candidate before changing the active link. A configured
provider must pass local access, remote access, and GitHub privacy checks.

If release metadata reports an incompatible provider format or
`migrationRequired`, the installer prints an actionable `Upgrade blocked`
report and leaves the previous version active. It never runs the migration
automatically. Run the displayed approved command explicitly, then retry.
With no configured provider, installation remains local-only and emits a
warning.

Rollback only selects a version already staged under the prefix. It does not
download or execute a new artifact.

## Uninstall

Uninstall is deliberately explicit because it removes the active links,
version directory, and the Cifrarium user service:

```sh
/tmp/cifrarium-install.sh --uninstall --yes
```

The installer refuses this operation without `--yes` and does not remove
files outside the selected prefix or the Cifrarium service path.

## Agent operating contract

Agents may install only an explicit version supplied by the operator or
approved release policy, or use `--non-interactive` with the published manifest.
They must preserve the command output and report the
selected prefix, architecture, and version. They must not pass `--enable`
unless the operator has separately approved daemon activation and the daemon
environment has been reviewed.

Agents should treat any checksum, signature, archive-member, metadata, or
platform failure as a hard stop. They must not replace the installer with a
downloaded shell pipeline, disable TLS verification, use `--yes` implicitly,
or retry a failed release with a different version.

## Local release validation

Maintainers can build and inspect both supported archives without signing
credentials:

```sh
scripts/build-release.sh --out-dir /tmp/cifrarium-release
scripts/verify-release.sh --dir /tmp/cifrarium-release
scripts/install-test.sh
```

The lifecycle harness uses a temporary HTTPS server and a fake Cosign verifier
only for installer control-flow tests. Production installation still requires
the real `cosign` binary and a valid release bundle.

## Release controls

Before enabling the release workflows, repository administrators must configure
the `release` and `installer-production` environments with required reviewers,
protect or make immutable the `v*.*.*` tag pattern, and provide the deploy
workflow with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets. The
release and deploy jobs reject tags whose commit is not an ancestor of `main`,
and deploy rejects a tag whose version differs from the manifest. These
controls are repository policy and cannot be proven by a checkout-only test.
