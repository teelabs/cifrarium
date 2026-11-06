# Agent usage contract for Cifrarium

This document is the operational contract for an AI agent, automation worker, or
developer tool that interacts with Cifrarium. It describes what an agent may
observe, what it may propose, and which operations require a human decision.

This file is the detailed operational contract for using the CLI, daemon,
provider, recovery flow, and MCP. The root `AGENTS.md` is only the routing
pointer and repository gate summary.

## 1. Scope and trust boundaries

Cifrarium stores application configuration locally as encrypted snapshots. The
agent must keep these boundaries distinct:

1. The local vault contains encrypted snapshots, signed catalog metadata, and
   keyring-backed keys.
2. The Git provider receives opaque encrypted objects and encrypted manifests.
3. The daemon queue contains encrypted upload work.
4. Restored application files are plaintext at their normal user paths.
5. A process running as the same operating-system user can generally inspect
   user-readable files, observe the user's processes, and interfere with the
   user's vault. Cifrarium is not a sandbox against that process.

The agent should therefore protect secrets from accidental disclosure and
untrusted paths, while reporting same-user compromise as a threat-model
limitation rather than promising impossible isolation.

The vault root is configured once per user at
`${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/config.json`. Normal commands
resolve it automatically. A different explicit `-root` is a security failure;
it is not an alternate-vault option. On a new machine, configure the intended
location first with `cifrarium setup --root PATH`. The config contains only the
schema and canonical root, never shares, tokens, or vault content.

## 2. Preflight

Before using a command, collect only non-secret context:

~~~sh
pwd
git status --short
git branch --show-current
go run ./cmd/cifrarium -h
~~~

Record:

- the absolute worktree path;
- the selected vault root, without reading secret contents;
- whether a provider is configured;
- whether a daemon is already running;
- whether the request is local-only or includes a remote side effect;
- whether another worktree or task owns the same files.

Do not inspect environment values whose names contain recovery shares, tokens, or
credentials. It is sufficient to check whether required variables are present.

## 3. Operation classification

| Operation | Classification | Agent default |
| --- | --- | --- |
| `status` | Read-only, human output by default | May run after root setup and report; use `-format=json` for parsing |
| `doctor` | Read-only local and configured-provider diagnostic | May run and report; it never initializes state |
| `provider health` | Read-only local/remote diagnostic | Requires an existing provider checkout; it never initializes Git or writes provider state |
| `provider setup` | Local configuration and optional remote provisioning | Human-only; requires explicit confirmations and never runs in `--non-interactive` mode |
| `snapshot` | Local mutation | Run only when explicitly requested |
| `recovery shares` | Secret creation/display | Human-only by default; never capture output |
| `recovery import` | Keyring mutation and integrity-sensitive | Require explicit human confirmation and two supplied shares |
| `migrate-catalog` | Local data migration | Require explicit confirmation and backup/rollback plan |
| `daemon` | Persistent process and remote-capable | Require explicit confirmation before activation |
| `snapshot.plan` | Read-only MCP plan | May inspect; does not perform upload |
| `restore.plan` | Read-only MCP plan | May inspect; never describe it as an applied restore |
| provider upload/push | Remote mutation | Require explicit confirmation and successful privacy/access checks |
| deleting queue, vault, keyring, or history | Destructive | Never infer permission; require a separate explicit request |

A request to “check”, “review”, or “diagnose” authorizes read-only inspection,
not snapshot creation, recovery import, daemon activation, push, deletion, or
restore activation. If the root is not configured, `status` and other normal
commands stop before creating keyring or vault state; use `doctor` to see the
safe setup prompt.

## 4. Human confirmation gates

Ask for confirmation immediately before the side effect, after showing:

- exact command and selected root/provider;
- whether the effect is local or remote;
- data classes involved;
- expected rollback/recovery path;
- validation already completed;
- any known residual risk.

Do not ask the human to paste a recovery share into a chat if a protected local
input path is available. Do not echo a supplied share in logs or final output.

Example confirmation summary:

~~~text
Planned effect: create one encrypted local snapshot and leave it in the vault.
Remote effect: none.
Root: /path/known-to-user
Validation: status passed; no provider configured.
Proceed?
~~~

For a remote upload:

~~~text
Planned effect: enable the user daemon, which may push ciphertext to the
configured GitHub repository.
Preconditions: provider health passed; repository reported private; two shares
are available through the protected environment.
Residual: GitHub visibility can change externally after the check.
Proceed?
~~~

## 5. Standard workflows

### 5.1 Configure and inspect a vault

~~~sh
cifrarium setup --root "$HOME/.local/share/cifrarium"
cifrarium status
~~~

Success means exit code zero and a readable status response. Use
`-format=json` for a structured response. It does not prove that the provider
is reachable or that a backup exists.

Installer upgrades are read-only with respect to existing vault state until
candidate preflight succeeds. They preserve the root, keyring, history,
provider checkout, and recovery shares. Provider migrations are never automatic;
an agent must report the approved command and wait for an explicit operator
action before retrying.

### 5.1.1 Run the complete doctor

~~~sh
cifrarium doctor -format=json
~~~

`doctor` does not create keyring material, a vault, a provider checkout, a
socket, or a daemon. It reports vault/keyring integrity, systemd user service
state, MCP socket reachability, daemon backend readiness, local adapter paths,
and provider state. Backend readiness is probed separately from the MCP
transport: an active service and ready MCP do not mean the backend can accept
status or snapshot requests. When a provider is configured, doctor performs
remote access and GitHub privacy checks.

Human setup, status, and doctor output is organized into headings, separated
sections, and copyable command blocks. Interactive setup confirms each answer
before asking the next question. ANSI colors are used only for TTY output;
redirected output keeps the same structure without terminal control codes.

Exit codes are stable: `0` means healthy or only optional warnings, `1` means a
required or configured component has a problem, and `2` means invalid CLI use.
Do not treat an `overall` report as proof that a remote upload completed.

### 5.2 Create a local snapshot

~~~sh
go run ./cmd/cifrarium snapshot
~~~

Check that a snapshot identifier was returned. If the captured configuration
matches the current vault head, output says `(unchanged; reused current)`; no
new encrypted snapshot is written. The vault keeps a keyed fingerprint in the
encrypted manifest, so it does not expose configuration paths or content to the
provider. Do not read or print the snapshot plaintext. With an active daemon,
the CLI sends this request through the daemon control socket and does not
bypass a backend that is still starting.
To test local capture without daemon mediation, exit a foreground daemon by
answering `n` at `Retry?`, or stop a systemd-managed daemon with
`systemctl --user stop cifrarium.service`. If a failure has no validated
allowlisted adapter path, do not guess which path to change; use doctor and the
failure stage instead.

Symlinked allowlisted paths are a deliberate stop condition. Do not bypass the
check or follow the link. The safe human procedure is to stop the daemon,
inspect only `test -L`/`readlink`, then either materialize a regular file
through the dotfile manager or use the following local copy procedure:

~~~sh
systemctl --user stop cifrarium.service
cp --dereference --preserve=mode \
  "$HOME/.zshrc" "$HOME/.zshrc.cifrarium-regular"
test ! -L "$HOME/.zshrc.cifrarium-regular"
mv "$HOME/.zshrc.cifrarium-regular" "$HOME/.zshrc"
cifrarium snapshot
systemctl --user start cifrarium.service
~~~

Do not use `rm`, `source`, `sudo`, or a symlink-following override. If the link
is intentionally managed, leave capture disabled until the manager provides a
regular file. An adapter-path failure stops the foreground daemon and does not
upload. Other local snapshot stages report whether persistence or upload
preparation failed; messages do not expose raw errors or paths.

Daemon human diagnostics use the sections `Daemon needs attention`, `What
happened`, `Why it matters`, `How to fix it`, and `What to do next`. A correction
block is a copyable instruction, not diagnostic output. Adapter paths are shown
only when they come from a typed adapter failure and pass the relative allowlist.
Other stages use safe categories; raw errors, unvalidated paths, symlink
targets, file contents, recovery shares, and tokens are not printed.
TTY output uses the muted semantic foreground palette: headers `#58A6FF`,
commands `#3FB950`, paths `#79C0FF`, warnings `#D29922`, failures `#F85149`,
identity `#D2A8FF`, and secondary text `#8B949E`. Copyable command blocks are
bounded by visible separators and blank lines. A local capture failure ends the
foreground daemon after this diagnostic. Pending recovery-verification and
provider/upload failures use the retry flow: an interactive daemon asks
`Retry? [Y/n]`, defaults to yes, explains that the operator should use another
console, accepts Enter before the countdown ends, and returns to the shell
when declined. Systemd and other non-TTY runs retry without prompting. The
encrypted queue is preserved. Redirected output, systemd logs, and JSON remain
free of ANSI sequences.

Pending-upload diagnostics are specific but sanitized: recovery verification
suggests `cifrarium provider setup`, provider privacy suggests
`cifrarium provider health --verify-private`, and missing or inaccessible
providers receive distinct next steps. Agents must not add paths, remotes,
usernames, shares, tokens, or file contents to those messages.

Initial daemon work distinguishes draining an existing pending upload from
uploading a new capture. If a failed new upload cannot be added because the
queue is full, the message says that the local capture completed, the upload
was not confirmed, and the new item was not queued. Keep the service stopped,
preserve `pending.queue`, and inspect `cifrarium status -format=json` and
`cifrarium provider health --verify-private` before retrying.

### 5.3 Check a GitHub provider

~~~sh
go run ./cmd/cifrarium provider health \
  -provider-dir "$PROVIDER_DIR" \
  -provider-remote "$PROVIDER_REMOTE" \
  -verify-private
~~~

Treat a failure as a stop condition for uploads. Do not repair it by adding a
token to a remote URL, disabling privacy checks, or editing encrypted objects.

### 5.4 Generate recovery shares

Run only when the human explicitly asks for new shares:

~~~sh
go run ./cmd/cifrarium recovery shares
~~~

The command's stdout is secret material. Keep it out of agent transcripts,
terminal captures, issue comments, test fixtures, and telemetry. The agent may
confirm that the command completed without recording the lines.

### 5.5 Recover a keyring

Recovery requires two distinct valid shares. The agent must first explain that
the operation changes keyring state and may reject a rollback. After explicit
confirmation, use a protected input mechanism:

~~~sh
cifrarium recovery import \
  -recovery-share "$SHARE_1_FROM_PROTECTED_INPUT" \
  -recovery-share "$SHARE_2_FROM_PROTECTED_INPUT"
~~~

Then run `status`. If recovery fails, preserve the vault and existing keyring;
do not retry with guessed, reordered, or copied shares.

### 5.6 Migrate a legacy catalog

Preconditions:

- the human has confirmed that the vault is legacy;
- a recoverable backup exists;
- no concurrent daemon or snapshot operation is running.

~~~sh
go run ./cmd/cifrarium migrate-catalog
go run ./cmd/cifrarium status
~~~

The agent must report whether migration changed anything. A failure is not a
reason to delete `head.json`, catalog files, or the keyring.

### 5.7 Diagnose a daemon

Use read-only observation first:

~~~sh
systemctl --user status cifrarium.service
journalctl --user -u cifrarium.service -n 100 --no-pager
cifrarium doctor -format=json
~~~

The agent may recommend restarting a service only after the human requests an
operational intervention. A persistent queue is valuable evidence; preserve it
during diagnosis.

The daemon is the backend for normal coordinated CLI and MCP operations. After
the human approves a service refresh, use the copyable command:

~~~sh
cifrarium daemon refresh
~~~

This reloads the managed service configuration, restarts the daemon, and checks
backend and MCP readiness separately. It does not start a second foreground
daemon. MCP tools remain protocol-level operations and are not CLI subcommands.

## 6. Failure handling

| Observation | Safe interpretation | Next action |
| --- | --- | --- |
| Provider access failure | Remote operation is not proven | Run provider health; preserve queue |
| Repository is public | Privacy policy failed | Stop uploads; fix external policy; re-check |
| Queue exists after offline period | Work may be pending | Inspect logs and provider; do not delete |
| Queue persistence failure | Durability is not proven | Stop/leave daemon stopped; preserve vault |
| Keyring backend error | Key state is unavailable | Preserve files; repair keyring/session |
| Catalog rollback error | History integrity failed | Stop; do not replace head manually |
| Oversized input | Resource bound worked | Reduce scope; do not bypass limit casually |
| MCP parse/connection error | Local request was not accepted | Inspect socket/service; do not assume mutation |
| Same-user interference | Local trust boundary is compromised | Stop sensitive work, preserve evidence, rotate/recover |

Never convert an error into success because a later retry happened to work.
Report the first failure and the final verified state.

## 7. MCP rules

The local MCP server supports:

- `status`;
- `snapshot.plan`;
- `restore.plan`.

Plans are observations and proposals. They are not proof that a snapshot was
created, uploaded, or restored. The agent must not expose the socket remotely or
invent mutation methods that are not in the current server.

## 8. Agent handoff format

Every completed agent operation should report:

~~~text
Result: PASS | FAIL | BLOCKED | NOT RUN
Scope: local vault / provider diagnostic / daemon / recovery / docs
Commands: exact commands run, excluding secret values
Evidence: exit codes, relevant non-secret output, and changed paths
State: what changed and what did not change
Risks: residuals, same-user boundary, privacy race, or missing evidence
Next action: one safe, concrete recommendation
~~~

Example:

~~~text
Result: PASS
Scope: provider diagnostic
Commands: provider health with configured non-secret paths
Evidence: exit 0; status=ok; repository reported private
State: no local or remote mutation performed
Risks: external GitHub visibility can change after the check
Next action: human may separately approve daemon activation
~~~

## 9. Completion criteria

An agent may claim a Cifrarium task complete only when:

- the requested scope is explicit;
- no secret was copied into output or files;
- every requested command has an observed result;
- local and remote mutations are distinguished;
- queue/keyring/vault state was preserved on failure;
- documentation and changelog impact were handled;
- residual same-user and provider-privacy limits are stated;
- the exact verification commands and worktree are reported.

Passing tests is evidence for code changes, not permission to push, merge,
publish, deploy, activate the daemon, or import recovery keys.
