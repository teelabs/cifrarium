#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(tr -d '[:space:]' <"$ROOT_DIR/VERSION")
GO_CACHE=$(go env GOCACHE)
GO_MOD_CACHE=$(go env GOMODCACHE)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-installer-test.XXXXXX")
PUBLIC_DIR="$TEST_ROOT/public"
HOME_DIR="$TEST_ROOT/home"
PREFIX="$HOME_DIR/.local"
FAKE_BIN="$TEST_ROOT/bin"
SYSTEMCTL_LOG="$TEST_ROOT/systemctl.log"
LIFECYCLE_BRIDGE=""
LIFECYCLE_PID=""
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
CERT="$TEST_ROOT/cert.pem"
KEY="$TEST_ROOT/key.pem"

cleanup() {
  if [[ -n "$LIFECYCLE_PID" ]]; then
    : >"$LIFECYCLE_BRIDGE/continue" 2>/dev/null || true
    wait "$LIFECYCLE_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$PUBLIC_DIR" "$HOME_DIR" "$FAKE_BIN"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=127.0.0.1 -keyout "$KEY" -out "$CERT" >/dev/null 2>&1

MISSING_BIN="$TEST_ROOT/missing-bin"
mkdir -p "$MISSING_BIN"
cat >"$MISSING_BIN/uname" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == -s ]]; then
  printf 'Linux\n'
else
  printf 'x86_64\n'
fi
EOF
chmod 0755 "$MISSING_BIN/uname"
cat >"$MISSING_BIN/apt-get" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod 0755 "$MISSING_BIN/apt-get"
missing_output="$TEST_ROOT/missing-dependencies.txt"
if PATH="$MISSING_BIN" HOME="$HOME_DIR" /bin/bash "$ROOT_DIR/scripts/install.sh" \
  --version "$VERSION" --prefix "$PREFIX" --base-url "https://127.0.0.1:$PORT" \
  >"$missing_output" 2>&1; then
  echo 'missing dependencies unexpectedly passed preflight' >&2
  exit 1
fi
for dependency in mktemp mv ln install curl tar sha256sum cosign python3; do
  grep -Fq "$dependency" "$missing_output" || {
    echo "missing dependency was not reported: $dependency" >&2
    cat "$missing_output" >&2
    exit 1
  }
done
grep -Fq 'Install the missing dependencies' "$missing_output" || {
  echo 'missing dependency guidance was not reported' >&2
  cat "$missing_output" >&2
  exit 1
}
grep -Fq 'sudo apt-get update && sudo apt-get install' "$missing_output" || {
  echo 'package manager guidance was not reported' >&2
  cat "$missing_output" >&2
  exit 1
}
grep -Fq 'https://docs.sigstore.dev/cosign/system_config/installation/' "$missing_output" || {
  echo 'Cosign installation guidance was not reported' >&2
  cat "$missing_output" >&2
  exit 1
}
if /usr/bin/curl --fail --silent --show-error --location "file://$ROOT_DIR/scripts/install.sh" \
  | PATH="$MISSING_BIN" HOME="$HOME_DIR" /bin/bash >"$TEST_ROOT/pipeline-missing-dependencies.txt" 2>&1; then
  echo 'missing dependencies unexpectedly passed through curl pipe' >&2
  exit 1
fi
if grep -Fq 'curl: (23)' "$TEST_ROOT/pipeline-missing-dependencies.txt"; then
  echo 'curl broken-pipe noise was not suppressed' >&2
  cat "$TEST_ROOT/pipeline-missing-dependencies.txt" >&2
  exit 1
fi
if grep -Fq 'cifrarium installer:' "$missing_output"; then
  echo 'installer prefix was not removed' >&2
  cat "$missing_output" >&2
  exit 1
fi
[[ ! -e "$PREFIX" ]] || {
  echo 'missing dependency preflight mutated the prefix' >&2
  exit 1
}

cat >"$FAKE_BIN/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == verify-blob && "${2:-}" == --bundle ]] || exit 2
[[ "${CIFRARIUM_TEST_COSIGN_FAIL:-0}" != 1 ]] || exit 4
exit 0
EOF
cat >"$FAKE_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --user && "${2:-}" == is-active ]]; then
  [[ "${CIFRARIUM_TEST_SYSTEMCTL_ACTIVE:-0}" == 1 ]] && exit 0
  exit 3
fi
if [[ "${CIFRARIUM_TEST_SYSTEMCTL_ACTIVE:-0}" == 1 && "${2:-}" == disable && "${3:-}" == --now ]]; then
  exit 1
fi
printf '%s\n' "$*" >>"${CIFRARIUM_SYSTEMCTL_LOG:?}"
exit 0
EOF
chmod 0755 "$FAKE_BIN/cosign" "$FAKE_BIN/systemctl"
cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == -C ]] || exit 2
case "${2:-}" in
  *)
    case "${3:-}" in
      status) exit 0 ;;
      ls-remote) [[ "${CIFRARIUM_TEST_REMOTE_FAIL:-0}" != 1 ]] ;;
      *) exit 2 ;;
    esac
    ;;
esac
EOF
cat >"$FAKE_BIN/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${CIFRARIUM_TEST_PUBLIC_REPO:-0}" != 1 ]] && printf 'true\n' || printf 'false\n'
EOF
chmod 0755 "$FAKE_BIN/git" "$FAKE_BIN/gh"

export PATH="$FAKE_BIN:$PATH"
export HOME="$HOME_DIR"
export XDG_CONFIG_HOME="$TEST_ROOT/custom-xdg-config"
export GOCACHE="$GO_CACHE"
export GOMODCACHE="$GO_MOD_CACHE"
export CURL_CA_BUNDLE="$CERT"
export CIFRARIUM_SYSTEMCTL_LOG="$SYSTEMCTL_LOG"

"$ROOT_DIR/scripts/build-release.sh" --version "$VERSION" --out-dir "$PUBLIC_DIR"
cp "$ROOT_DIR/scripts/install.sh" "$PUBLIC_DIR/install.sh"
printf 'test bundle\n' >"$PUBLIC_DIR/install.sh.bundle"
for archive in "$PUBLIC_DIR"/*.tar.gz; do
  printf 'test bundle\n' >"$archive.bundle"
done
python3 - "$PORT" "$PUBLIC_DIR" "$CERT" "$KEY" <<'PY' &
import http.server
import os
import ssl
import sys

port, directory, cert, key = sys.argv[1:]
os.chdir(directory)
server = http.server.ThreadingHTTPServer(("127.0.0.1", int(port)), http.server.SimpleHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
SERVER_PID=$!
for _ in {1..50}; do
  curl --silent --output /dev/null --cacert "$CERT" "https://127.0.0.1:$PORT/" && break
  sleep 0.1
done
"$ROOT_DIR/scripts/verify-release.sh" --dir "$PUBLIC_DIR" --require-signatures

cp "$PUBLIC_DIR/manifest.json" "$TEST_ROOT/manifest.valid.json"
python3 - "$PUBLIC_DIR/manifest.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest['version'] = '9.9.9'
path.write_text(json.dumps(manifest, indent=2) + '\n')
PY
if "$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT"; then
  echo 'invalid metadata unexpectedly installed a release' >&2
  exit 1
fi
cp "$TEST_ROOT/manifest.valid.json" "$PUBLIC_DIR/manifest.json"

ln -s "$TEST_ROOT/symlink-target" "$TEST_ROOT/symlink-prefix"
if "$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$TEST_ROOT/symlink-prefix" \
  --base-url "https://127.0.0.1:$PORT"; then
  echo 'symlinked prefix unexpectedly accepted' >&2
  exit 1
fi

mkdir -p "$TEST_ROOT/derived-prefix"
ln -s "$TEST_ROOT/escaped-lib" "$TEST_ROOT/derived-prefix/lib"
if "$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$TEST_ROOT/derived-prefix" \
  --base-url "https://127.0.0.1:$PORT"; then
  echo 'symlinked derived prefix component unexpectedly accepted' >&2
  exit 1
fi

install_output="$TEST_ROOT/install-output.txt"
"$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$install_output" 2>&1
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]
[[ -L "$PREFIX/bin/cifrarium" ]]
[[ -f "$XDG_CONFIG_HOME/systemd/user/cifrarium.service" ]]
grep -Fq 'Environment=XDG_CONFIG_HOME=%E' "$XDG_CONFIG_HOME/systemd/user/cifrarium.service"
grep -Fq 'EnvironmentFile=-%E/cifrarium/daemon.env' "$XDG_CONFIG_HOME/systemd/user/cifrarium.service"
if command -v systemd-analyze >/dev/null 2>&1; then
  XDG_CONFIG_HOME="$XDG_CONFIG_HOME" systemd-analyze verify "$XDG_CONFIG_HOME/systemd/user/cifrarium.service"
fi
for step in 'Checking platform' 'Checking dependencies' 'Downloading manifest' 'Verifying archive signature'; do
  grep -Fq "$step" "$install_output" || {
    echo "progress step was not reported: $step" >&2
    cat "$install_output" >&2
    exit 1
  }
done
if grep -Fq $'\033' "$install_output" || grep -Fq $'\r' "$install_output"; then
  echo 'redirected installer output contains terminal control sequences' >&2
  cat -v "$install_output" >&2
  exit 1
fi
if command -v script >/dev/null 2>&1; then
  tty_progress=$(script -qec "bash -c 'source <(sed -n \"32,46p\" \"$ROOT_DIR/scripts/install.sh\"); step test; step_done test'" /dev/null 2>/dev/null)
  [[ "$tty_progress" == *$'\033[2K'* && "$tty_progress" == *$'\r'* ]] || {
    echo 'TTY installer progress did not use in-place terminal updates' >&2
    printf '%s\n' "$tty_progress" | cat -v >&2
    exit 1
  }
fi
if [[ -s "$SYSTEMCTL_LOG" ]]; then
  echo 'installer started systemd without --enable' >&2
  cat "$SYSTEMCTL_LOG" >&2
  exit 1
fi

# Dedicated upgrade/provider/state-preservation cases.
PROVIDER_DIR="$TEST_ROOT/provider"
mkdir -p "$PROVIDER_DIR/.git" "$HOME_DIR/.local/share/cifrarium/snapshots"
printf 'history sentinel\n' >"$HOME_DIR/.local/share/cifrarium/snapshots/history"
printf 'keyring sentinel\n' >"$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
printf 'encrypted queue sentinel\n' >"$HOME_DIR/.local/share/cifrarium/pending.queue"
DAEMON_ENV="$XDG_CONFIG_HOME/cifrarium/daemon.env"
mkdir -p "$(dirname "$DAEMON_ENV")"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\nCIFRARIUM_RECOVERY_SHARE_1=placeholder-one\nCIFRARIUM_RECOVERY_SHARE_2=placeholder-two\n' "$PROVIDER_DIR" >"$DAEMON_ENV"
chmod 0600 "$DAEMON_ENV"
cp "$HOME_DIR/.local/share/cifrarium/snapshots/history" "$TEST_ROOT/history.before"
cp "$HOME_DIR/.local/share/cifrarium/keyring-sentinel" "$TEST_ROOT/keyring.before"
cp "$HOME_DIR/.local/share/cifrarium/pending.queue" "$TEST_ROOT/pending.before"

"$ROOT_DIR/scripts/build-release.sh" --version 0.8.3 --out-dir "$TEST_ROOT/release-0.8.3"
cp "$TEST_ROOT/release-0.8.3"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.3-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
upgrade_output="$TEST_ROOT/upgrade-output.txt"
"$ROOT_DIR/scripts/install.sh" --version 0.8.3 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$upgrade_output" 2>&1
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
grep -Fq 'installation mode: upgrade' "$upgrade_output"
! grep -Fq 'Recovery shares' "$upgrade_output"
! grep -Fq 'placeholder-one' "$upgrade_output"
! grep -Fq 'placeholder-two' "$upgrade_output"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
cmp -s "$DAEMON_ENV" <(printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\nCIFRARIUM_RECOVERY_SHARE_1=placeholder-one\nCIFRARIUM_RECOVERY_SHARE_2=placeholder-two\n' "$PROVIDER_DIR")

# A non-zero doctor exit caused by an unrelated daemon problem must not block
# an upgrade when its JSON proves that configuration and the vault are ready.
CONFIGURED_ROOT="$HOME_DIR/.local/share/cifrarium"
mkdir -p "$CONFIGURED_ROOT"
CONFIG_FILE="$XDG_CONFIG_HOME/cifrarium/config.json"
mkdir -p "$(dirname "$CONFIG_FILE")"
printf '{"schema":1,"root":"%s"}\n' "$CONFIGURED_ROOT" >"$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"
cp "$CONFIG_FILE" "$TEST_ROOT/config.before"
cp "$DAEMON_ENV" "$TEST_ROOT/daemon-env.before"
ACTIVE_BINARY="$PREFIX/lib/cifrarium/versions/0.8.3/cifrarium"
mv "$ACTIVE_BINARY" "$ACTIVE_BINARY.test-real"
DOCTOR_REPORT="$TEST_ROOT/doctor-report.json"
cat >"$ACTIVE_BINARY" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == doctor ]]; then
  cat "${CIFRARIUM_TEST_DOCTOR_REPORT:?}"
  exit "${CIFRARIUM_TEST_DOCTOR_EXIT:?}"
fi
exec "$(readlink -f "$0").test-real" "$@"
EOF
chmod 0755 "$ACTIVE_BINARY"
export CIFRARIUM_TEST_DOCTOR_REPORT="$DOCTOR_REPORT"
export CIFRARIUM_TEST_DOCTOR_EXIT=1
cat >"$DOCTOR_REPORT" <<'EOF'
{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"ready","severity":"healthy"},"daemon":{"state":"enabled-but-inactive","severity":"problem"}}
EOF

for scenario in vault-problem vault-not-ready configuration-problem malformed-json missing-json incomplete-json top-level-array wrong-field-types; do
  case "$scenario" in
    vault-problem)
      printf '%s\n' '{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"keyring-unavailable","severity":"problem"}}' >"$DOCTOR_REPORT"
      ;;
    vault-not-ready)
      printf '%s\n' '{"configuration":{"state":"configured","severity":"healthy"},"overall":"healthy","vault":{"state":"not-initialized","severity":"healthy"}}' >"$DOCTOR_REPORT"
      ;;
    configuration-problem)
      printf '%s\n' '{"configuration":{"state":"problem","severity":"problem"},"overall":"problem","vault":{"state":"ready","severity":"healthy"}}' >"$DOCTOR_REPORT"
      ;;
    malformed-json)
      printf '%s\n' '{not-json' >"$DOCTOR_REPORT"
      ;;
    missing-json)
      : >"$DOCTOR_REPORT"
      ;;
    incomplete-json)
      printf '%s\n' '{"overall":"healthy"}' >"$DOCTOR_REPORT"
      ;;
    top-level-array)
      printf '%s\n' '[]' >"$DOCTOR_REPORT"
      ;;
    wrong-field-types)
      printf '%s\n' '{"configuration":[],"vault":{"state":[],"severity":"healthy"}}' >"$DOCTOR_REPORT"
      ;;
  esac
  if "$ROOT_DIR/scripts/install.sh" --version 0.8.36 --prefix "$PREFIX" \
    --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/doctor-$scenario.txt" 2>&1; then
    echo "doctor preflight unexpectedly accepted $scenario" >&2
    exit 1
  fi
  grep -Fq 'The active version could not confirm that the configured root and keyring are healthy.' \
    "$TEST_ROOT/doctor-$scenario.txt" || {
    echo "doctor preflight did not reject $scenario using its report" >&2
    cat "$TEST_ROOT/doctor-$scenario.txt" >&2
    exit 1
  }
  [[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
  cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
  cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
  cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
  cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
  cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
done

cat >"$DOCTOR_REPORT" <<'EOF'
{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"ready","severity":"healthy"},"daemon":{"state":"enabled-but-inactive","severity":"problem"}}
EOF
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.35 --out-dir "$TEST_ROOT/release-0.8.35"
cp "$TEST_ROOT/release-0.8.35"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.35-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
upgrade_output="$TEST_ROOT/doctor-daemon-problem-upgrade.txt"
if ! "$ROOT_DIR/scripts/install.sh" --version 0.8.35 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$upgrade_output" 2>&1; then
  cat "$upgrade_output" >&2
  exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.35 ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"

unset CIFRARIUM_TEST_DOCTOR_REPORT CIFRARIUM_TEST_DOCTOR_EXIT
rm -f "$CONFIG_FILE"
"$ROOT_DIR/scripts/install.sh" --rollback 0.8.3 --prefix "$PREFIX"
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]

mv "$PROVIDER_DIR" "$PROVIDER_DIR.missing"
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.4 --out-dir "$TEST_ROOT/release-0.8.4"
cp "$TEST_ROOT/release-0.8.4"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.4-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if "$ROOT_DIR/scripts/install.sh" --version 0.8.4 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/provider-missing.txt" 2>&1; then
  echo 'missing provider checkout unexpectedly upgraded' >&2; exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
mv "$PROVIDER_DIR.missing" "$PROVIDER_DIR"

export CIFRARIUM_TEST_REMOTE_FAIL=1
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.5 --out-dir "$TEST_ROOT/release-0.8.5"
cp "$TEST_ROOT/release-0.8.5"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.5-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if "$ROOT_DIR/scripts/install.sh" --version 0.8.5 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/provider-remote-fail.txt" 2>&1; then
  echo 'inaccessible provider remote unexpectedly upgraded' >&2; exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_REMOTE_FAIL

export CIFRARIUM_TEST_PUBLIC_REPO=1
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.6 --out-dir "$TEST_ROOT/release-0.8.6"
cp "$TEST_ROOT/release-0.8.6"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.6-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if "$ROOT_DIR/scripts/install.sh" --version 0.8.6 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/provider-public.txt" 2>&1; then
  echo 'public provider repository unexpectedly upgraded' >&2; exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_PUBLIC_REPO

cp "$DAEMON_ENV" "$TEST_ROOT/daemon.env.valid"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_SECRET_MARKER=must-not-leak\n' "$PROVIDER_DIR" >"$DAEMON_ENV"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.6 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/daemon-env-invalid.txt" 2>&1; then
  echo 'invalid daemon.env unexpectedly upgraded' >&2; exit 1
fi
! grep -Fq 'must-not-leak' "$TEST_ROOT/daemon-env-invalid.txt"
cp "$TEST_ROOT/daemon.env.valid" "$DAEMON_ENV"

MIGRATION_MARKER="$TEST_ROOT/migration-ran"
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.7 --out-dir "$TEST_ROOT/release-0.8.7"
python3 - "$TEST_ROOT/release-0.8.7/cifrarium-0.8.7-linux-amd64.tar.gz" "$MIGRATION_MARKER" <<'PY'
import io, json, pathlib, sys, tarfile
archive, marker = map(pathlib.Path, sys.argv[1:])
rewritten = archive.with_suffix('.migration.tar.gz')
with tarfile.open(archive, 'r:gz') as source, tarfile.open(rewritten, 'w:gz') as target:
    for member in source.getmembers():
        data = source.extractfile(member).read() if member.isfile() else None
        if member.name == 'release.json':
            metadata = json.loads(data)
            metadata['provider']['migrationRequired'] = True
            metadata['provider']['migrationCommand'] = f'touch {marker}'
            data = (json.dumps(metadata, indent=2) + '\n').encode()
            member.size = len(data)
        target.addfile(member, io.BytesIO(data) if data is not None else None)
rewritten.replace(archive)
PY
sha256sum "$TEST_ROOT/release-0.8.7/cifrarium-0.8.7-linux-amd64.tar.gz" | awk '{print $1 "  " $2}' >"$TEST_ROOT/release-0.8.7/cifrarium-0.8.7-linux-amd64.tar.gz.sha256"
cp "$TEST_ROOT/release-0.8.7"/* "$PUBLIC_DIR/"
python3 - "$PUBLIC_DIR/manifest.json" "$TEST_ROOT/release-0.8.7/cifrarium-0.8.7-linux-amd64.tar.gz" <<'PY'
import hashlib, json, pathlib, sys
manifest_path, archive = map(pathlib.Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())
for release in manifest['releases']:
    if release['architecture'] == 'linux-amd64':
        release['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY
for archive in "$PUBLIC_DIR"/cifrarium-0.8.7-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if "$ROOT_DIR/scripts/install.sh" --version 0.8.7 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/migration-pending.txt" 2>&1; then
  echo 'migration-required release unexpectedly upgraded' >&2; exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
[[ ! -e "$MIGRATION_MARKER" ]]
grep -Fqi 'migration' "$TEST_ROOT/migration-pending.txt"

NO_SYSTEMCTL_BIN="$TEST_ROOT/no-systemctl-bin"
mkdir -p "$NO_SYSTEMCTL_BIN"
for dependency in bash env uname mkdir rm rmdir grep mktemp mv ln install dirname sed curl tar sha256sum python3 readlink; do
  ln -s "$(command -v "$dependency")" "$NO_SYSTEMCTL_BIN/$dependency"
done
ln -s "$FAKE_BIN/cosign" "$NO_SYSTEMCTL_BIN/cosign"
if PATH="$NO_SYSTEMCTL_BIN" HOME="$HOME_DIR" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
  "$ROOT_DIR/scripts/install.sh" --uninstall --prefix "$PREFIX" --yes \
  >"$TEST_ROOT/no-systemctl-output.txt" 2>&1; then
  echo 'uninstall unexpectedly passed without systemctl' >&2
  exit 1
fi
grep -Fq 'systemctl' "$TEST_ROOT/no-systemctl-output.txt"
[[ -f "$XDG_CONFIG_HOME/systemd/user/cifrarium.service" ]]
[[ -L "$PREFIX/bin/cifrarium" ]]

"$ROOT_DIR/scripts/build-release.sh" --version 0.4.1 --out-dir "$TEST_ROOT/release-0.4.1"
cp "$TEST_ROOT/release-0.4.1"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/*.tar.gz; do
  printf 'test bundle\n' >"$archive.bundle"
done
export CIFRARIUM_TEST_COSIGN_FAIL=1
if "$ROOT_DIR/scripts/install.sh" --version 0.4.1 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT"; then
  echo 'signature failure unexpectedly installed a release' >&2
  exit 1
fi
unset CIFRARIUM_TEST_COSIGN_FAIL

"$ROOT_DIR/scripts/install.sh" --version 0.4.1 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" --enable
[[ "$("$PREFIX/bin/cifrarium" -version)" == "0.4.1" ]]
grep -Fq 'enable --now cifrarium.service' "$SYSTEMCTL_LOG"

"$ROOT_DIR/scripts/install.sh" --rollback "$VERSION" --prefix "$PREFIX"
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"

"$ROOT_DIR/scripts/build-release.sh" --version 0.4.2 --out-dir "$TEST_ROOT/release-0.4.2"
cp "$TEST_ROOT/release-0.4.2"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.4.2-*.tar.gz; do
  printf 'test bundle\n' >"$archive.bundle"
done
python3 - "$PUBLIC_DIR" <<'PY'
import hashlib
import json
import pathlib
import tarfile

root = pathlib.Path(__import__('sys').argv[1])
archive = root / 'cifrarium-0.4.2-linux-amd64.tar.gz'
rewritten = archive.with_suffix('.malicious.tar.gz')
with tarfile.open(archive, 'r:gz') as source, tarfile.open(rewritten, 'w:gz') as target:
    for member in source.getmembers():
        target.addfile(member, source.extractfile(member) if member.isfile() else None)
    payload = b'escape\n'
    entry = tarfile.TarInfo('../escape')
    entry.size = len(payload)
    target.addfile(entry, __import__('io').BytesIO(payload))
rewritten.replace(archive)
(root / (archive.name + '.sha256')).write_text(
    hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n'
)
manifest_path = root / 'manifest.json'
manifest = json.loads(manifest_path.read_text())
for release in manifest['releases']:
    if release['architecture'] == 'linux-amd64':
        release['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY
if "$ROOT_DIR/scripts/install.sh" --version 0.4.2 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT"; then
  echo 'archive traversal unexpectedly installed a release' >&2
  exit 1
fi
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]

if "$ROOT_DIR/scripts/install.sh" --uninstall --prefix "$PREFIX" >/dev/null 2>&1; then
  echo 'uninstall unexpectedly succeeded without --yes' >&2
  exit 1
fi
export CIFRARIUM_TEST_SYSTEMCTL_ACTIVE=1
if "$ROOT_DIR/scripts/install.sh" --uninstall --prefix "$PREFIX" --yes >/dev/null 2>&1; then
  echo 'uninstall unexpectedly removed an active service' >&2
  exit 1
fi
[[ -f "$XDG_CONFIG_HOME/systemd/user/cifrarium.service" ]]
[[ -L "$PREFIX/bin/cifrarium" ]]
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]
unset CIFRARIUM_TEST_SYSTEMCTL_ACTIVE
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.8 --out-dir "$TEST_ROOT/release-0.8.8"
cp "$TEST_ROOT/release-0.8.8"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.8-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
cp "$TEST_ROOT/release-0.8.8/manifest.json" "$PUBLIC_DIR/manifest.json"
XDG_CONFIG_HOME="$HOME_DIR/.config" "$ROOT_DIR/scripts/install.sh" --version 0.8.8 \
  --prefix "$PREFIX" --base-url "https://127.0.0.1:$PORT" >/dev/null
[[ -f "$HOME_DIR/.config/systemd/user/cifrarium.service" ]]
grep -Fq 'Environment=XDG_CONFIG_HOME=%E' "$HOME_DIR/.config/systemd/user/cifrarium.service"
grep -Fq 'EnvironmentFile=-%E/cifrarium/daemon.env' "$HOME_DIR/.config/systemd/user/cifrarium.service"
if command -v systemd-analyze >/dev/null 2>&1; then
  XDG_CONFIG_HOME="$HOME_DIR/.config" systemd-analyze verify "$HOME_DIR/.config/systemd/user/cifrarium.service"
fi
"$ROOT_DIR/scripts/install.sh" --uninstall --prefix "$PREFIX" --yes
[[ ! -e "$PREFIX/bin/cifrarium" ]]

# Run the real installer against the same home/XDG/vault/queue fixture that a
# real Service/Backend process holds open across an upgrade.
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.9 --out-dir "$TEST_ROOT/release-0.8.9"
cp "$TEST_ROOT/release-0.8.9"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.9-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
"$ROOT_DIR/scripts/install.sh" --version 0.8.9 --prefix "$PREFIX" --base-url "https://127.0.0.1:$PORT" >/dev/null
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.8.9 ]]
# The real keyring is intentionally in the Go test process' in-memory keyring.
# The active binary is a separate process, so stub only its read-only doctor
# preflight; keep its version command and all candidate binaries real.
ACTIVE_BINARY="$PREFIX/lib/cifrarium/versions/0.8.9/cifrarium"
mv "$ACTIVE_BINARY" "$ACTIVE_BINARY.test-real"
cat >"$ACTIVE_BINARY" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == doctor ]]; then
  printf '{"configuration":{"state":"configured","severity":"healthy"},"overall":"healthy","vault":{"state":"ready","severity":"healthy"}}\n'
  exit 0
fi
exec "$(readlink -f "$0").test-real" "$@"
EOF
chmod 0755 "$ACTIVE_BINARY"

LIFECYCLE_BRIDGE="$TEST_ROOT/lifecycle-bridge"
mkdir -m 0700 "$LIFECYCLE_BRIDGE"
CIFRARIUM_LIFECYCLE_INSTALL_BRIDGE="$LIFECYCLE_BRIDGE" \
  go test ./cmd/cifrarium -run '^TestLifecycleAuditFreshInstallQueueResume$' -count=1 -v \
  >"$LIFECYCLE_BRIDGE/go-test.log" 2>&1 &
LIFECYCLE_PID=$!
for _ in {1..1200}; do
  [[ -f "$LIFECYCLE_BRIDGE/ready" ]] && break
  if ! kill -0 "$LIFECYCLE_PID" 2>/dev/null; then
    cat "$LIFECYCLE_BRIDGE/go-test.log" >&2
    echo 'shared installer lifecycle test exited before preparing its fixture' >&2
    exit 1
  fi
  sleep 0.1
done
[[ -f "$LIFECYCLE_BRIDGE/ready" ]] || {
  cat "$LIFECYCLE_BRIDGE/go-test.log" >&2
  echo 'shared installer lifecycle fixture did not become ready' >&2
  exit 1
}

lifecycle_state_digest() {
  python3 - "$HOME_DIR" "$XDG_CONFIG_HOME" <<'PY'
import hashlib, json, os, pathlib, stat, sys
home, xdg = map(pathlib.Path, sys.argv[1:])
records = []
for label, root in (("home", home / ".local/share/cifrarium-lifecycle"), ("xdg", xdg / "cifrarium")):
    if not root.exists():
        continue
    for directory, _, files in os.walk(root):
        for name in files:
            path = pathlib.Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise SystemExit("unexpected non-regular lifecycle state")
            relative = f"{label}/{path.relative_to(root).as_posix()}"
            records.append((relative, stat.S_IMODE(path.stat().st_mode), hashlib.sha256(path.read_bytes()).hexdigest()))
records.sort()
payload = json.dumps(records, separators=(",", ":")).encode()
print(hashlib.sha256(payload).hexdigest())
PY
}

state_before=$(lifecycle_state_digest)
assert_lifecycle_state_preserved() {
  local label=$1 state_after
  state_after=$(lifecycle_state_digest)
  [[ "$state_after" == "$state_before" ]] || {
    echo "installer $label changed vault, keyring sentinel, recovery config, or queue state" >&2
    exit 1
  }
}

# A rejected manifest is a failed preflight against the real queued vault.
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.10 --out-dir "$TEST_ROOT/release-0.8.10"
cp "$TEST_ROOT/release-0.8.10"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.10-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
cp "$PUBLIC_DIR/manifest.json" "$TEST_ROOT/lifecycle-manifest.valid.json"
python3 - "$PUBLIC_DIR/manifest.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["version"] = "9.9.9"
path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
if "$ROOT_DIR/scripts/install.sh" --version 0.8.10 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/lifecycle-preflight-failure.txt" 2>&1; then
  echo 'invalid lifecycle manifest unexpectedly installed' >&2
  exit 1
fi
cp "$TEST_ROOT/lifecycle-manifest.valid.json" "$PUBLIC_DIR/manifest.json"
assert_lifecycle_state_preserved 'preflight failure'
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.8.9 ]]

# A migration-required candidate must leave the same real vault and queue intact.
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.11 --out-dir "$TEST_ROOT/release-0.8.11"
python3 - "$TEST_ROOT/release-0.8.11/cifrarium-0.8.11-linux-amd64.tar.gz" "$TEST_ROOT/lifecycle-migration-ran" <<'PY'
import io, json, pathlib, sys, tarfile
archive, marker = map(pathlib.Path, sys.argv[1:])
rewritten = archive.with_suffix('.migration.tar.gz')
with tarfile.open(archive, 'r:gz') as source, tarfile.open(rewritten, 'w:gz') as target:
    for member in source.getmembers():
        data = source.extractfile(member).read() if member.isfile() else None
        if member.name == 'release.json':
            metadata = json.loads(data)
            metadata['provider']['migrationRequired'] = True
            metadata['provider']['migrationCommand'] = f'touch {marker}'
            data = (json.dumps(metadata, indent=2) + '\n').encode()
            member.size = len(data)
        target.addfile(member, io.BytesIO(data) if data is not None else None)
rewritten.replace(archive)
PY
sha256sum "$TEST_ROOT/release-0.8.11/cifrarium-0.8.11-linux-amd64.tar.gz" \
  | awk '{print $1 "  " $2}' >"$TEST_ROOT/release-0.8.11/cifrarium-0.8.11-linux-amd64.tar.gz.sha256"
cp "$TEST_ROOT/release-0.8.11"/* "$PUBLIC_DIR/"
python3 - "$PUBLIC_DIR/manifest.json" "$TEST_ROOT/release-0.8.11/cifrarium-0.8.11-linux-amd64.tar.gz" <<'PY'
import hashlib, json, pathlib, sys
manifest_path, archive = map(pathlib.Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())
for release in manifest['releases']:
    if release['architecture'] == 'linux-amd64':
        release['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY
for archive in "$PUBLIC_DIR"/cifrarium-0.8.11-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if "$ROOT_DIR/scripts/install.sh" --version 0.8.11 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/lifecycle-migration-failure.txt" 2>&1; then
  echo 'migration-required lifecycle candidate unexpectedly installed' >&2
  exit 1
fi
[[ ! -e "$TEST_ROOT/lifecycle-migration-ran" ]]
assert_lifecycle_state_preserved 'migration failure'
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.8.9 ]]

# A failed rollback to a nonexistent version must leave user state untouched.
if "$ROOT_DIR/scripts/install.sh" --rollback 0.8.99 --prefix "$PREFIX" \
  >"$TEST_ROOT/lifecycle-rollback-failure.txt" 2>&1; then
  echo 'rollback to a missing lifecycle version unexpectedly succeeded' >&2
  exit 1
fi
assert_lifecycle_state_preserved 'rollback failure'
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.8.9 ]]

# Now execute a successful real installer upgrade while the service test
# process keeps the in-memory keyring and old encrypted queue alive.
cp "$TEST_ROOT/release-0.8.10"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.10-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
if ! "$ROOT_DIR/scripts/install.sh" --version 0.8.10 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/lifecycle-upgrade.txt" 2>&1; then
  cat "$TEST_ROOT/lifecycle-upgrade.txt" >&2
  exit 1
fi
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.8.10 ]]
assert_lifecycle_state_preserved 'successful upgrade'
: >"$LIFECYCLE_BRIDGE/continue"
if ! wait "$LIFECYCLE_PID"; then
  cat "$LIFECYCLE_BRIDGE/go-test.log" >&2
  echo 'real Service/Backend queue resume failed after installer upgrade' >&2
  exit 1
fi
LIFECYCLE_PID=""
cat "$LIFECYCLE_BRIDGE/go-test.log"
unset CIFRARIUM_LIFECYCLE_INSTALL_BRIDGE

printf 'installer integration tests passed\n'
