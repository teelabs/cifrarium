# GitHub provider provisioning runbook

This runbook provisions the operator-owned GitHub boundary for Cifrarium. It
does not give Cifrarium a GitHub API token, create repositories automatically,
or upload plaintext. The daemon continues to use native Git and receives only
the configured local checkout, remote URL, and recovery shares.

This runbook protects data at rest and the remote provider boundary. It does
not make restored plaintext safe from a process running as the same Unix user;
that process can read user files and interfere with the user daemon. The
provider privacy check is also a pre-push operational check, not an atomic
GitHub policy lock. Use organization/repository controls when the privacy
policy must be enforced against other administrators.

For agent-operated work, read [`AGENTS.md`](../../AGENTS.md) and the
[agent usage contract](../AGENT-USAGE.md). Agents must not activate the
daemon, import recovery shares, or push without explicit human confirmation.

## 0. Configure the vault root first

The root is configured once per user and is not selected independently by the
provider flow:

```sh
cifrarium setup --root "$HOME/.local/share/cifrarium"
cifrarium -command=doctor
```

After this, normal Cifrarium commands omit `-root`. Supplying a different
explicit root is a security failure and must not be overridden.

## 1. Prepare the local provider checkout

Use a dedicated directory with mode `0700`. It must not contain application
state or credentials outside Cifrarium's encrypted objects.

```sh
umask 077
mkdir -p "$HOME/.local/share/cifrarium-provider"
git -C "$HOME/.local/share/cifrarium-provider" init --initial-branch=main
```

If the directory is already a Git checkout, do not reinitialize it. A
configured remote must be an HTTPS GitHub URL without embedded credentials.

## 2. Create or select a private repository

For a new repository, authenticate `gh` as the operator and create the remote
without pushing yet:

```sh
gh auth status
gh repo create OWNER/REPO --private \
  --source="$HOME/.local/share/cifrarium-provider" \
  --remote=origin
```

The `gh repo create` command supports `--private`, `--source`, `--remote`, and
an explicit `--push`; omitting `--push` keeps repository creation separate from
the first Cifrarium upload. See the [GitHub CLI repository creation
reference](https://cli.github.com/manual/gh_repo_create).

For an existing repository, clone it into the dedicated directory or point
`CIFRARIUM_PROVIDER_DIR` at an existing checkout whose `origin` exactly matches
`CIFRARIUM_PROVIDER_REMOTE`.

## 3. Use the minimum GitHub credential

Create a fine-grained personal access token owned by the operator, restricted
to the single Cifrarium repository. Grant only:

- Repository permissions: `Metadata: read`.
- Repository permissions: `Contents: read and write` for Git fetch/push.

Do not grant Administration, Actions, Secrets, Workflows, Issues, Pull
requests, or organization-wide repository access. Set an expiration and record
the expiry in the operator's credential inventory, never in the vault or Git
history. GitHub documents repository-scoped fine-grained access and the
permission mapping in its [token management
guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
and [fine-grained token permission
reference](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).

Keep the token in the operator's Git credential manager or `gh` authentication
boundary. Never put it in a remote URL, `daemon.env`, a Cifrarium argument, a
snapshot, or a log. Cifrarium must see only Git's success or actionable access
failure.

## 4. Verify before the first upload

Set the remote values in the operator-managed environment file with mode
`0600`. Do not put recovery shares in shell history; use a protected file or
the interactive environment setup approved by the operator.

```sh
chmod 600 "$HOME/.config/cifrarium/daemon.env"
export CIFRARIUM_PROVIDER_DIR="$HOME/.local/share/cifrarium-provider"
export CIFRARIUM_PROVIDER_REMOTE="https://github.com/OWNER/REPO.git"
go run ./cmd/cifrarium -command=provider-health \
  -provider-dir "$CIFRARIUM_PROVIDER_DIR" \
  -provider-remote "$CIFRARIUM_PROVIDER_REMOTE" \
  -verify-private
```

Before enabling the daemon, generate three recovery shares and place two
complete `label:value` lines in the operator-created environment file:

```dotenv
CIFRARIUM_RECOVERY_SHARE_1='cifrarium-1:BASE64_VALUE_1'
CIFRARIUM_RECOVERY_SHARE_2='cifrarium-2:BASE64_VALUE_2'
```

These are two separate variable names; the slash in the shorthand
`CIFRARIUM_RECOVERY_SHARE_1/2` is not part of a variable name. The share value
is unpadded Base64, so `/` and `+` may appear inside it. Keep the file at mode
`0600`, quote the complete values, and never put real shares in shell history.

The daemon refuses remote upload without exactly two valid, distinct shares
matching the active operational key and a successful private-repository
verification. The first upload is therefore an explicit operator action after
privacy, remote-access, and recovery checks are green; the daemon repeats the
privacy check at the upload boundary.

`provider-health` is read-only and expects this checkout to already exist. It
does not run `git init`, create directories, add a remote, or repair provider
state. Run the local setup commands above separately before probing health.

## 5. Revocation and incident response

If the token, checkout, host, or account is suspected compromised:

1. Revoke the fine-grained token in GitHub.
2. Stop the user service and preserve the encrypted local queue.
3. Verify the repository privacy and Git access with a newly issued token.
4. Run Cifrarium recovery with two trusted shares on a trusted environment.
5. Inspect the encrypted provider history and local catalog before resuming.

Never solve an access failure by embedding a new token in a remote URL or by
disabling the recovery gate.

## Release boundary

This runbook proves the operator procedure, not ownership of a domain or legal
brand clearance. Public release still requires the separate [brand/legal and
security release gate](https://github.com/teelabs/cifrarium/issues/49), human
security approval, and a fresh audit of token scope and repository privacy.
