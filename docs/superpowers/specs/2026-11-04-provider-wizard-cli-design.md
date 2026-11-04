# Provider Wizard and Canonical CLI

Status: implemented in v0.9.0; this document is the current contract for the
provider setup and recovery command surface.

## Intent

Cifrarium must make provider configuration understandable and recoverable
without asking users to paste credentials or hand-edit secret values. Existing
vault, keyring, snapshot history, provider checkout, and recovery material are
preserved unless the operator explicitly chooses a replacement operation.

## CLI contract

The public command form is a subcommand followed by its options:

```text
cifrarium status
cifrarium doctor
cifrarium provider setup
cifrarium provider health
cifrarium recovery shares
cifrarium recovery import
cifrarium snapshot
cifrarium daemon
cifrarium migrate-catalog
```

The legacy `-command=` option is rejected. Internal command names such as
`provider-health` remain implementation details only.

## Provider setup

`cifrarium provider setup` is interactive and requires an existing configured
vault. It may configure a local-only provider, validate an existing private
GitHub repository, or create a private repository through the operator's
authenticated `gh` CLI. Cifrarium never receives, stores, or prints a GitHub
token and never performs an automatic snapshot upload.

The wizard validates the local checkout, configured remote, Git access, and
GitHub privacy before writing configuration. It writes only Cifrarium-owned
keys to `${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/daemon.env`, preserves
unrelated lines, uses an atomic same-directory replacement, and requires mode
`0600` for the file and `0700` for its directory.

Daemon activation is a separate final confirmation and is disabled by default.
`--non-interactive` never runs the wizard, generates or displays shares,
creates a repository, writes provider configuration, or enables the daemon.

## Recovery shares

Existing valid shares are preserved. If shares are absent, the wizard offers:

- import of exactly two shares from a protected local file;
- explicit generation and terminal-only display of a new three-share set;
- skip, leaving remote uploads unavailable until shares are configured.

The first two shares may be written to the protected daemon environment only
after confirmation. The third share is given offline-storage guidance and is
not written by the wizard. Shares are never included in logs, repository files,
provider objects, or agent output.

## Symlink capture policy

Allowlisted application files, including `~/.zshrc`, must be regular files.
Cifrarium rejects symlinks rather than following them because following a link
could capture an unallowlisted path or allow a path replacement to redirect a
capture. The failure occurs before a new snapshot is saved or uploaded.

The safe operator procedure is:

1. stop the user daemon;
2. inspect only the link type and target with `test -L` and `readlink`;
3. if the link is managed intentionally, keep the daemon stopped and
   materialize a regular file through the dotfile manager or defer capture;
4. otherwise copy through the link with `cp --dereference --preserve=mode` to
   a temporary regular file in the same directory and atomically replace the
   symlink with `mv`;
5. verify the path is no longer a symlink, run a local `cifrarium snapshot`,
   then restart the daemon.

The procedure must not use `rm`, `source`, `sudo`, symlink-following overrides,
or any recovery-share/token output.

When this failure reaches the daemon, the human output is ordered as `Daemon
needs attention`, `What happened`, `Why it matters`, `How to fix it`, and `What
to do next`. The correction block is a copyable instruction, not diagnostic
output. It parses only the first path segment before `; recovery snapshot
failed`; the compound error `symlink rejected: .zshrc; recovery snapshot
failed: symlink rejected: .zshrc` therefore displays only the validated
`~/.zshrc` path. It does not display the complete symlink error, target,
contents, tokens, or recovery shares. TTY output uses the named Codex semantic
foreground palette: headers `#58A6FF`, commands `#3FB950`, paths `#79C0FF`,
warnings `#D29922`, failures `#F85149`, identity `#D2A8FF`, and secondary text
`#8B949E`. Copyable command blocks are separated from surrounding prose. A
local capture failure ends the foreground daemon after the sanitized
diagnostic. Pending recovery-verification and provider/upload failures use an
interactive `Retry? [Y/n]` flow with yes as the default, instructions to use
another console, an in-place countdown, and Enter for immediate retry. A
negative answer returns control to the shell. Systemd and other non-TTY runs
retry without prompting. The encrypted queue is preserved; redirected output
and JSON remain unchanged and contain no ANSI sequences.

## Acceptance evidence

- CLI tests reject `-command=` and cover nested provider/recovery commands.
- Provider configuration tests prove recovery-share variables are not exposed
  by safe provider discovery and that unrelated daemon environment lines are
  preserved.
- Adapter tests reject symlinked capture paths.
- Daemon error output gives a safe, copyable symlink recovery procedure and
  does not expose the compound error, target contents, tokens, or recovery
  shares; parsing rejects traversal and external absolute paths.
- Installer tests prove upgrade, rollback, provider preflight, and local-state
  preservation.
- The release gate for v0.9.0 passed Go tests, race, vet, build, installer,
  changelog, secret, and diff checks.
