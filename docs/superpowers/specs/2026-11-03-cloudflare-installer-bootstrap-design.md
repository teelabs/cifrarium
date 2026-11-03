# Cloudflare Installer Bootstrap Design

## Intent

Provision the public Cloudflare Pages project `usecifrarium` as the delivery
origin for the future Cifrarium Linux installer. The first deployment proves
the Pages project and public route without publishing an installer that does
not exist yet.

## Goals

- Publish a static, non-executable bootstrap page and machine-readable status.
- Keep the public bundle free of credentials, release claims, and install
  commands that could be mistaken for a usable installer.
- Make the future installer path explicit so a later release workflow can
  publish `install.sh`, checksums, signatures, and a manifest atomically at the
  same origin.
- Record the Cloudflare project name and deployment verification steps.

## Non-goals

- Implement the Linux installer itself.
- Create release archives, signing keys, Cloudflare API tokens, DNS records, or
  custom domains.
- Add a Worker, R2 bucket, or application runtime.
- Treat the bootstrap page as a release or as evidence that installation is
  available.

## Approach

Cloudflare Pages direct upload is the smallest fit for a public static
installer channel. R2 would be useful for immutable artifact storage later,
and a Worker could add routing or policy logic, but neither is required to
prove the first public origin. Wrangler is installed locally in the operator
environment and the first upload is performed with the explicit Pages project
name `usecifrarium`.

## Public contract

- `/` serves the bootstrap status page.
- `/bootstrap.json` serves the same status for automation.
- `/install.sh` is intentionally absent until a signed installer release is
  implemented and approved.
- A future release must deploy the installer, checksums, signatures, and
  manifest as one verified bundle; it must not silently turn the bootstrap
  status into an executable installer.

## Acceptance

- `wrangler pages project list` shows `usecifrarium` after authentication.
- `wrangler pages deploy` succeeds for the bootstrap directory.
- The returned Pages URL serves the expected page and `bootstrap.json`.
- `/install.sh` returns a non-success response because no installer is
  published yet.
- No secret or unrelated repository content is included in the upload.
