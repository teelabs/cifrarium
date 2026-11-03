# Linux Installer Design

## Intent

Provide a real, reproducible Linux installer for Cifrarium releases served
from the `usecifrarium` Pages origin. The installer must be safe to invoke on a
user-owned machine, must not start the daemon by default, and must fail closed
when release metadata or signatures are invalid.

## Goals

- Support Linux `amd64` and `arm64` only.
- Require an explicit SemVer release; no implicit mutable `latest` install.
- Download only over HTTPS from the configured Pages origin.
- Verify SHA-256 and a Cosign keyless signature before extraction.
- Reject unsafe archive entries and install into a user-writable prefix.
- Atomically switch the active binary and preserve a rollback target.
- Support explicit `--enable`, `--rollback VERSION`, and `--uninstall --yes`.
- Exercise installation in a temporary home/prefix outside the checkout.

## Non-goals

- Installing Go, Git, Cosign, Python, systemd, or a keyring backend.
- Running as root or modifying `/usr/bin` by default.
- Starting or enabling the daemon unless `--enable` is supplied.
- Downloading or executing an unsigned script from the network.
- Supporting macOS, Windows, or package-manager formats in this slice.

## Release contract

Each release publishes these files under the same origin:

- `install.sh`
- `install.sh.bundle`
- `manifest.json`
- `cifrarium-VERSION-linux-amd64.tar.gz`
- `cifrarium-VERSION-linux-amd64.tar.gz.sha256`
- `cifrarium-VERSION-linux-amd64.tar.gz.bundle`
- equivalent `arm64` files

The archive contains `cifrarium`, `cifrarium.service`, `README.md`, and
`release.json` at its root. The manifest binds version, architecture, archive name,
SHA-256, and Cosign bundle name. The installer verifies all of these before
writing the prefix. The entry-point script is also Cosign-signed; users verify
it before execution.

## Installer contract

```text
install.sh --version VERSION [--prefix DIR] [--base-url URL]
           [--enable]
install.sh --rollback VERSION [--prefix DIR] [--enable]
install.sh --uninstall --prefix DIR --yes
```

The default prefix is `$HOME/.local`. Binaries live in
`$prefix/lib/cifrarium/versions/VERSION/cifrarium`, the active symlink is
`$prefix/bin/cifrarium`, and the previous active symlink is retained as
`$prefix/bin/cifrarium.previous`. The service is installed under
`$HOME/.config/systemd/user` and is never started unless `--enable` is passed.

The Cosign identity policy is fixed to the repository's GitHub Actions release
workflow and the GitHub Actions OIDC issuer. It is not user-overridable at
install time.

## Failure and rollback behavior

- Invalid arguments, platform, URL, manifest, checksum, signature, archive,
  or existing path state stop before activation.
- Downloads and extraction use a temporary directory with restrictive modes.
- The active symlink is changed only after all files are verified and staged.
- A failed activation leaves the old active symlink unchanged.
- Rollback selects only an already-installed version directory and performs the
  same atomic symlink swap.
- Uninstall requires `--yes`, removes the active links and user service, and
  leaves versioned archives/logs outside the install prefix untouched.

## Acceptance evidence

- Static shell checks cover argument validation, platform/architecture,
  checksum/signature failure, archive traversal, atomic replacement, enable,
  rollback, uninstall confirmation, and no-start default behavior.
- A local test harness serves a generated release bundle over HTTPS-compatible
  local transport or a controlled file fixture and uses a fake Cosign verifier
  only to test installer control flow; production mode still requires the real
  `cosign` binary.
- Release build checks produce both Linux architectures and manifest entries.
- GitHub Actions validates the build, signs release artifacts with keyless
  Cosign, and deploys the installer bundle to Pages only after release checks.
