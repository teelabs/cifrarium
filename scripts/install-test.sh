#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(tr -d '[:space:]' <"$ROOT_DIR/VERSION")
GO_CACHE=$(go env GOCACHE)
GO_MOD_CACHE=$(go env GOMODCACHE)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-installer-test.XXXXXX")
UNSAFE_TEST_ROOT=""
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
SERVER_CERT="$TEST_ROOT/server-cert.pem"
SERVER_KEY="$TEST_ROOT/server-key.pem"
REAL_INSTALL=$(command -v install)
REAL_MV=$(command -v mv)
REAL_MKDIR=$(command -v mkdir)

cleanup() {
  if [[ -n "$LIFECYCLE_PID" ]]; then
    : >"$LIFECYCLE_BRIDGE/continue" 2>/dev/null || true
    wait "$LIFECYCLE_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$UNSAFE_TEST_ROOT" ]]; then
    rm -rf "$UNSAFE_TEST_ROOT"
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$PUBLIC_DIR" "$HOME_DIR" "$FAKE_BIN"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=Cifrarium-Test-CA -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj /CN=127.0.0.1 \
  -addext 'subjectAltName=IP:127.0.0.1' -keyout "$SERVER_KEY" \
  -out "$TEST_ROOT/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$TEST_ROOT/server.csr" -CA "$CERT" -CAkey "$KEY" \
  -CAcreateserial -copy_extensions copy -out "$SERVER_CERT" >/dev/null 2>&1

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
cat >"$FAKE_BIN/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${@: -1}"
if [[ "${CIFRARIUM_TEST_INSTALL_SERVICE_FAIL:-0}" == 1 && "$target" == */systemd/user/cifrarium.service ]]; then
  printf 'partial test unit write\n' >"$target"
  exit 1
fi
exec "${CIFRARIUM_TEST_REAL_INSTALL:?}" "$@"
EOF
chmod 0755 "$FAKE_BIN/install"
export CIFRARIUM_TEST_REAL_INSTALL="$REAL_INSTALL"
cat >"$FAKE_BIN/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${@: -1}"
if [[ "${CIFRARIUM_TEST_INSTALL_SERVICE_FAIL:-0}" == 1 && "$target" == */systemd/user/cifrarium.service && ! -e "${CIFRARIUM_TEST_ROOT:?}/service-mv-failed" ]]; then
  : >"$CIFRARIUM_TEST_ROOT/service-mv-failed"
  exit 1
fi
if [[ "${CIFRARIUM_TEST_ACTIVE_LINK_FAIL:-0}" == 1 && "$target" == */bin/cifrarium ]]; then
  exit 1
fi
source="${@: -2:1}"
if [[ "${CIFRARIUM_TEST_CANDIDATE_SWAP:-0}" == 1 && "$target" == */versions/0.8.12 ]]; then
  "${CIFRARIUM_TEST_REAL_MV:?}" -T "$source" "${CIFRARIUM_TEST_ROOT:?}/stolen-candidate"
  mkdir -p "$target"
  printf 'attacker-controlled version\n' >"$target/marker"
  exit 0
fi
if [[ "${CIFRARIUM_TEST_ACTIVE_LINK_SIGNAL:-0}" == 1 && "$target" == */bin/cifrarium ]]; then
  "${CIFRARIUM_TEST_REAL_MV:?}" "$@"
  kill -TERM "$PPID"
  exit 0
fi
exec "${CIFRARIUM_TEST_REAL_MV:?}" "$@"
EOF
cat >"$FAKE_BIN/mkdir" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${@: -1}"
if [[ "${CIFRARIUM_TEST_LOCK_SIGNAL:-0}" == 1 && "$target" == */.install.lock ]]; then
  "${CIFRARIUM_TEST_REAL_MKDIR:?}" "$@"
  kill -HUP "$PPID"
  exit 0
fi
exec "${CIFRARIUM_TEST_REAL_MKDIR:?}" "$@"
EOF
chmod 0755 "$FAKE_BIN/mv" "$FAKE_BIN/mkdir"
export CIFRARIUM_TEST_REAL_MV="$REAL_MV"
export CIFRARIUM_TEST_REAL_MKDIR="$REAL_MKDIR"
export CIFRARIUM_TEST_ROOT="$TEST_ROOT"
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
INSTALLER_SCRIPT="$TEST_ROOT/install-$VERSION.sh"
cp "$PUBLIC_DIR/install.sh" "$INSTALLER_SCRIPT"
printf 'test bundle\n' >"$PUBLIC_DIR/install.sh.bundle"
for archive in "$PUBLIC_DIR"/*.tar.gz; do
  printf 'test bundle\n' >"$archive.bundle"
done
python3 - "$PORT" "$PUBLIC_DIR" "$SERVER_CERT" "$SERVER_KEY" <<'PY' &
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

UNSAFE_TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-unsafe-install.XXXXXX")
chmod 0755 "$UNSAFE_TEST_ROOT"
UNSAFE_PREFIX="$UNSAFE_TEST_ROOT/prefix"
mkdir -m 0755 "$UNSAFE_PREFIX"
mkdir -m 0755 "$UNSAFE_PREFIX/lib"
mkdir -m 0755 "$UNSAFE_PREFIX/lib/cifrarium"
mkdir -m 0777 "$UNSAFE_PREFIX/lib/cifrarium/versions"
mkdir -m 0755 "$UNSAFE_PREFIX/bin"
if "$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$UNSAFE_PREFIX" \
  --base-url "https://127.0.0.1:$PORT" --non-interactive >"$TEST_ROOT/unsafe-prefix.txt" 2>&1; then
  echo 'world-writable installation prefix unexpectedly accepted' >&2
  exit 1
fi
grep -Fq 'unsafe writable installation directory' "$TEST_ROOT/unsafe-prefix.txt"
[[ ! -e "$UNSAFE_PREFIX/bin/cifrarium" && ! -L "$UNSAFE_PREFIX/bin/cifrarium" ]]

SHARED_PREFIX="$UNSAFE_TEST_ROOT/shared-prefix"
mkdir -m 1777 "$SHARED_PREFIX"
if "$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$SHARED_PREFIX" \
  --base-url "https://127.0.0.1:$PORT" --non-interactive >"$TEST_ROOT/shared-prefix.txt" 2>&1; then
  echo 'world-writable sticky installation prefix unexpectedly accepted' >&2
  exit 1
fi
grep -Fq 'unsafe writable installation directory' "$TEST_ROOT/shared-prefix.txt"
[[ ! -e "$SHARED_PREFIX/lib" && ! -e "$SHARED_PREFIX/bin" ]]

SHARED_CONFIG="$UNSAFE_TEST_ROOT/shared-config"
mkdir -m 1777 "$SHARED_CONFIG"
if XDG_CONFIG_HOME="$SHARED_CONFIG" "$ROOT_DIR/scripts/install.sh" --version "$VERSION" \
  --prefix "$TEST_ROOT/shared-config-prefix" --base-url "https://127.0.0.1:$PORT" \
  --non-interactive >"$TEST_ROOT/shared-config.txt" 2>&1; then
  echo 'world-writable sticky XDG config root unexpectedly accepted' >&2
  exit 1
fi
grep -Fq 'unsafe writable installation directory' "$TEST_ROOT/shared-config.txt"
[[ ! -e "$SHARED_CONFIG/systemd" ]]

if XDG_CONFIG_HOME="relative-config-root" "$ROOT_DIR/scripts/install.sh" --version "$VERSION" \
  --prefix "$TEST_ROOT/relative-config-prefix" --base-url "https://127.0.0.1:$PORT" \
  --non-interactive >"$TEST_ROOT/relative-config.txt" 2>&1; then
  echo 'relative XDG config root unexpectedly accepted' >&2
  exit 1
fi
grep -Fq 'XDG_CONFIG_HOME must be an absolute path' "$TEST_ROOT/relative-config.txt"
[[ ! -e "$TEST_ROOT/relative-config-root" ]]

MISSING_ROLLBACK_PREFIX="$TEST_ROOT/missing-rollback-prefix"
if "$ROOT_DIR/scripts/install.sh" --rollback 0.8.99 --prefix "$MISSING_ROLLBACK_PREFIX" \
  >"$TEST_ROOT/missing-rollback.txt" 2>&1; then
  echo 'rollback to a missing version unexpectedly succeeded' >&2
  exit 1
fi
grep -Fq 'version is not installed: 0.8.99' "$TEST_ROOT/missing-rollback.txt"
[[ ! -e "$MISSING_ROLLBACK_PREFIX" ]]

EMPTY_UNINSTALL_PREFIX="$TEST_ROOT/empty-uninstall-prefix"
if ! XDG_CONFIG_HOME="$TEST_ROOT/empty-uninstall-xdg" "$ROOT_DIR/scripts/install.sh" \
  --uninstall --prefix "$EMPTY_UNINSTALL_PREFIX" --yes >"$TEST_ROOT/empty-uninstall.txt" 2>&1; then
  cat "$TEST_ROOT/empty-uninstall.txt" >&2
  exit 1
fi
[[ ! -e "$EMPTY_UNINSTALL_PREFIX" ]]

install_output="$TEST_ROOT/install-output.txt"
if ! "$INSTALLER_SCRIPT" --version "$VERSION" --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$install_output" 2>&1; then
  cat "$install_output" >&2
  exit 1
fi
if ! installed_version=$("$PREFIX/bin/cifrarium" -version 2>&1); then
  cat "$install_output" >&2
  printf 'active binary version probe failed: %s\n' "$installed_version" >&2
  exit 1
fi
[[ "$installed_version" == "$VERSION" ]]
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
ACTIVE_BINARY="$PREFIX/lib/cifrarium/versions/0.11.0/cifrarium"
mkdir -p "$(dirname "$ACTIVE_BINARY")"
DOCTOR_REPORT="$TEST_ROOT/doctor-report.json"
cat >"$ACTIVE_BINARY" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  doctor)
    cat "${CIFRARIUM_TEST_DOCTOR_REPORT:?}"
    exit "${CIFRARIUM_TEST_DOCTOR_EXIT:?}"
    ;;
  -version)
    printf '0.11.0\n'
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod 0755 "$ACTIVE_BINARY"
ln -sfn ../lib/cifrarium/versions/0.11.0/cifrarium "$PREFIX/bin/cifrarium"
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
  grep -Fq "$PREFIX/lib/cifrarium/versions/0.11.0/cifrarium doctor -format=json and resolve" "$TEST_ROOT/doctor-$scenario.txt"
  [[ "$($PREFIX/bin/cifrarium -version)" == 0.11.0 ]]
  cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
  cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
  cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
  cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
  cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
done

# The release installer may inspect a configured 0.12.0 binary using the
# positional, read-only doctor interface because 0.12.0 is its embedded cap.
SUPPORTED_012_BINARY="$PREFIX/lib/cifrarium/versions/0.12.0/cifrarium"
SUPPORTED_012_DOCTOR="$TEST_ROOT/0.12-doctor-invoked"
mkdir -p "$(dirname "$SUPPORTED_012_BINARY")"
cat >"$SUPPORTED_012_BINARY" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  doctor)
    [[ "${2:-}" == -format=json ]] || exit 64
    printf 'positional-json\n' >"${CIFRARIUM_TEST_012_DOCTOR:?}"
    cat "${CIFRARIUM_TEST_DOCTOR_REPORT:?}"
    exit "${CIFRARIUM_TEST_DOCTOR_EXIT:?}"
    ;;
  -version)
    printf '0.12.0\n'
    ;;
  *)
    exit 64
    ;;
esac
EOF
chmod 0755 "$SUPPORTED_012_BINARY"
ln -sfn ../lib/cifrarium/versions/0.12.0/cifrarium "$PREFIX/bin/cifrarium"
export CIFRARIUM_TEST_012_DOCTOR="$SUPPORTED_012_DOCTOR"
cat >"$DOCTOR_REPORT" <<'EOF'
{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"ready","severity":"healthy"},"daemon":{"state":"enabled-but-inactive","severity":"problem"}}
EOF
export CIFRARIUM_TEST_DOCTOR_EXIT=1
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.39 --out-dir "$TEST_ROOT/release-0.8.39"
cp "$TEST_ROOT/release-0.8.39"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.39-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
supported_012_output="$TEST_ROOT/supported-0.12.0-upgrade.txt"
if ! "$INSTALLER_SCRIPT" --version 0.8.39 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$supported_012_output" 2>&1; then
  cat "$supported_012_output" >&2
  exit 1
fi
[[ "$(cat "$SUPPORTED_012_DOCTOR")" == positional-json ]]
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.39 ]]
grep -Fq 'installation mode: upgrade' "$supported_012_output"
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_012_DOCTOR
ln -sfn ../lib/cifrarium/versions/0.11.0/cifrarium "$PREFIX/bin/cifrarium"

# Simulate rollback swapping the active link immediately after preflight reads
# it. The validated executable path must be invoked, and activation must
# abort once the changed link is observed under the installer lock.
cat >"$DOCTOR_REPORT" <<'EOF'
{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"ready","severity":"healthy"},"daemon":{"state":"enabled-but-inactive","severity":"problem"}}
EOF
export CIFRARIUM_TEST_DOCTOR_EXIT=1
RACE_BINARY="$PREFIX/lib/cifrarium/versions/0.7.1/cifrarium"
RACE_SIDE_EFFECT="$TEST_ROOT/raced-legacy-status-executed"
mkdir -p "$(dirname "$RACE_BINARY")" "$TEST_ROOT/race-bin"
cat >"$RACE_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_RACE_SIDE_EFFECT:?}"
printf 'legacy status\n'
EOF
chmod 0755 "$RACE_BINARY"
RACE_REAL_READLINK=$(command -v readlink)
cat >"$TEST_ROOT/race-bin/readlink" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
real=${CIFRARIUM_TEST_REAL_READLINK:?}
if [[ "$#" == 1 && "$1" == "${CIFRARIUM_TEST_ACTIVE_LINK:?}" && ! -e "${CIFRARIUM_TEST_RACE_MARKER:?}" ]]; then
  target=$("$real" "$1")
  ln -sfn "${CIFRARIUM_TEST_RACE_TARGET:?}" "$1"
  : >"$CIFRARIUM_TEST_RACE_MARKER"
  printf '%s\n' "$target"
else
  exec "$real" "$@"
fi
EOF
chmod 0755 "$TEST_ROOT/race-bin/readlink"
export CIFRARIUM_TEST_REAL_READLINK="$RACE_REAL_READLINK"
export CIFRARIUM_TEST_ACTIVE_LINK="$PREFIX/bin/cifrarium"
export CIFRARIUM_TEST_RACE_MARKER="$TEST_ROOT/race-swap-done"
export CIFRARIUM_TEST_RACE_TARGET=../lib/cifrarium/versions/0.7.1/cifrarium
export CIFRARIUM_TEST_RACE_SIDE_EFFECT="$RACE_SIDE_EFFECT"
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.34 --out-dir "$TEST_ROOT/release-0.8.34"
cp "$TEST_ROOT/release-0.8.34"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.34-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
race_output="$TEST_ROOT/active-version-race.txt"
if PATH="$TEST_ROOT/race-bin:$PATH" "$ROOT_DIR/scripts/install.sh" --version 0.8.34 \
  --prefix "$PREFIX" --base-url "https://127.0.0.1:$PORT" >"$race_output" 2>&1; then
  echo 'upgrade proceeded after the active link changed during preflight' >&2
  exit 1
fi
grep -Fq 'active version changed during upgrade preflight' "$race_output" || {
  cat "$race_output" >&2
  exit 1
}
[[ -f "$CIFRARIUM_TEST_RACE_MARKER" ]]
[[ ! -e "$RACE_SIDE_EFFECT" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium")" == "$CIFRARIUM_TEST_RACE_TARGET" ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
ln -sfn ../lib/cifrarium/versions/0.11.0/cifrarium "$PREFIX/bin/cifrarium"
unset CIFRARIUM_TEST_REAL_READLINK CIFRARIUM_TEST_ACTIVE_LINK CIFRARIUM_TEST_RACE_MARKER
unset CIFRARIUM_TEST_RACE_TARGET CIFRARIUM_TEST_RACE_SIDE_EFFECT

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

# v0.8.0-v0.8.2 require the legacy -command syntax. A positional "doctor"
# invokes status in those binaries and may mutate the keyring catalog guard.
LEGACY_BINARY="$PREFIX/lib/cifrarium/versions/0.8.2/cifrarium"
LEGACY_STATUS_SIDE_EFFECT="$TEST_ROOT/legacy-status-mutated-keyring"
mkdir -p "$(dirname "$LEGACY_BINARY")"
cat >"$LEGACY_BINARY" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -command=doctor)
    [[ "${2:-}" == -format=json ]] || exit 64
    cat "${CIFRARIUM_TEST_DOCTOR_REPORT:?}"
    exit "${CIFRARIUM_TEST_DOCTOR_EXIT:?}"
    ;;
  doctor)
    printf 'catalog guard changed\n' >"${CIFRARIUM_TEST_LEGACY_SIDE_EFFECT:?}"
    printf 'Cifrarium status\n'
    exit 0
    ;;
  -version)
    printf '0.8.2\n'
    ;;
  *)
    printf 'Cifrarium status\n'
    ;;
esac
EOF
chmod 0755 "$LEGACY_BINARY"
export CIFRARIUM_TEST_LEGACY_SIDE_EFFECT="$LEGACY_STATUS_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.8.2/cifrarium "$PREFIX/bin/cifrarium"
printf '%s\n' '{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"keyring-unavailable","severity":"problem"}}' >"$DOCTOR_REPORT"
legacy_blocked_output="$TEST_ROOT/legacy-doctor-blocked.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.37 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$legacy_blocked_output" 2>&1; then
  echo 'legacy doctor unhealthy vault unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq -- "$PREFIX/lib/cifrarium/versions/0.8.2/cifrarium -command=doctor -format=json and resolve" "$legacy_blocked_output"
[[ ! -e "$LEGACY_STATUS_SIDE_EFFECT" ]]
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.2 ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"

cat >"$DOCTOR_REPORT" <<'EOF'
{"configuration":{"state":"configured","severity":"healthy"},"overall":"problem","vault":{"state":"ready","severity":"healthy"},"daemon":{"state":"enabled-but-inactive","severity":"problem"}}
EOF
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.37 --out-dir "$TEST_ROOT/release-0.8.37"
cp "$TEST_ROOT/release-0.8.37"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.37-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
legacy_upgrade_output="$TEST_ROOT/legacy-doctor-upgrade.txt"
if ! "$ROOT_DIR/scripts/install.sh" --version 0.8.37 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$legacy_upgrade_output" 2>&1; then
  cat "$legacy_upgrade_output" >&2
  exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.37 ]]
[[ ! -e "$LEGACY_STATUS_SIDE_EFFECT" ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_LEGACY_SIDE_EFFECT

# An expected-looking managed symlink must not redirect execution through a
# symlinked version binary into an external program.
INTERNAL_LINKED_BINARY="$PREFIX/lib/cifrarium/versions/0.10.99/cifrarium"
INTERNAL_LINK_SIDE_EFFECT="$TEST_ROOT/internal-linked-binary-executed"
mkdir -p "$(dirname "$INTERNAL_LINKED_BINARY")" "$TEST_ROOT/internal-linked"
cat >"$TEST_ROOT/internal-linked/cifrarium" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_EXTERNAL_SIDE_EFFECT:?}"
printf '{"configuration":{"state":"configured","severity":"healthy"},"vault":{"state":"ready","severity":"healthy"}}\n'
EOF
chmod 0755 "$TEST_ROOT/internal-linked/cifrarium"
ln -s "$TEST_ROOT/internal-linked/cifrarium" "$INTERNAL_LINKED_BINARY"
export CIFRARIUM_TEST_EXTERNAL_SIDE_EFFECT="$INTERNAL_LINK_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.10.99/cifrarium "$PREFIX/bin/cifrarium"
internal_link_output="$TEST_ROOT/internal-linked-target.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$internal_link_output" 2>&1; then
  echo 'symlinked managed binary unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'symlinked path component' "$internal_link_output"
[[ ! -e "$INTERNAL_LINK_SIDE_EFFECT" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium")" == ../lib/cifrarium/versions/0.10.99/cifrarium ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"

# A not-yet-released 0.8.x version has no proven doctor interface and must
# fail closed before its legacy status path can run.
UNKNOWN_08_BINARY="$PREFIX/lib/cifrarium/versions/0.8.3/cifrarium"
UNKNOWN_08_SIDE_EFFECT="$TEST_ROOT/unknown-08-binary-executed"
mkdir -p "$(dirname "$UNKNOWN_08_BINARY")"
mv "$UNKNOWN_08_BINARY" "$UNKNOWN_08_BINARY.test-real"
cat >"$UNKNOWN_08_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT:?}"
printf 'status\n'
EOF
chmod 0755 "$UNKNOWN_08_BINARY"
export CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT="$UNKNOWN_08_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.8.3/cifrarium "$PREFIX/bin/cifrarium"
unknown_08_output="$TEST_ROOT/unknown-08-version.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$unknown_08_output" 2>&1; then
  echo 'unsupported v0.8.3 active version unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'The installer cannot safely inspect this active version.' "$unknown_08_output"
[[ ! -e "$UNKNOWN_08_SIDE_EFFECT" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium")" == ../lib/cifrarium/versions/0.8.3/cifrarium ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT
mv "$UNKNOWN_08_BINARY.test-real" "$UNKNOWN_08_BINARY"

# Leading-zero aliases are not canonical SemVer and cannot select a known
# doctor interface family.
NONCANONICAL_BINARY="$PREFIX/lib/cifrarium/versions/0.09.0/cifrarium"
NONCANONICAL_SIDE_EFFECT="$TEST_ROOT/noncanonical-binary-executed"
mkdir -p "$(dirname "$NONCANONICAL_BINARY")"
cat >"$NONCANONICAL_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_NONCANONICAL_SIDE_EFFECT:?}"
printf '{"configuration":{"state":"configured","severity":"healthy"},"vault":{"state":"ready","severity":"healthy"}}\n'
EOF
chmod 0755 "$NONCANONICAL_BINARY"
export CIFRARIUM_TEST_NONCANONICAL_SIDE_EFFECT="$NONCANONICAL_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.09.0/cifrarium "$PREFIX/bin/cifrarium"
noncanonical_output="$TEST_ROOT/noncanonical-version.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$noncanonical_output" 2>&1; then
  echo 'leading-zero active version unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'The installer cannot safely inspect this active version.' "$noncanonical_output"
[[ ! -e "$NONCANONICAL_SIDE_EFFECT" ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_NONCANONICAL_SIDE_EFFECT

# Canonical but unbounded numeric components must not overflow a shell
# arithmetic comparison into a supported doctor family.
for unsupported_version in \
  18446744073709551616.9.0 \
  0.8.18446744073709551618; do
  overflow_binary="$PREFIX/lib/cifrarium/versions/$unsupported_version/cifrarium"
  overflow_side_effect="$TEST_ROOT/overflow-binary-executed"
  mkdir -p "$(dirname "$overflow_binary")"
  cat >"$overflow_binary" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_OVERFLOW_SIDE_EFFECT:?}"
printf 'status\n'
EOF
  chmod 0755 "$overflow_binary"
  export CIFRARIUM_TEST_OVERFLOW_SIDE_EFFECT="$overflow_side_effect"
  ln -sfn "../lib/cifrarium/versions/$unsupported_version/cifrarium" "$PREFIX/bin/cifrarium"
  overflow_output="$TEST_ROOT/overflow-${unsupported_version}.txt"
  if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
    --base-url "https://127.0.0.1:$PORT" >"$overflow_output" 2>&1; then
    echo "overflow-sized active version $unsupported_version unexpectedly upgraded" >&2
    exit 1
  fi
  grep -Fq 'The installer cannot safely inspect this active version.' "$overflow_output"
  [[ ! -e "$overflow_side_effect" ]]
  cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
  cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
  cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
  cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
  cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
done
unset CIFRARIUM_TEST_OVERFLOW_SIDE_EFFECT

# Future releases outside the known doctor interface families also fail
# before execution.
FUTURE_BINARY="$PREFIX/lib/cifrarium/versions/0.15.0/cifrarium"
FUTURE_SIDE_EFFECT="$TEST_ROOT/future-binary-executed"
mkdir -p "$(dirname "$FUTURE_BINARY")"
cat >"$FUTURE_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT:?}"
printf 'status\n'
EOF
chmod 0755 "$FUTURE_BINARY"
export CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT="$FUTURE_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.15.0/cifrarium "$PREFIX/bin/cifrarium"
future_output="$TEST_ROOT/future-version.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$future_output" 2>&1; then
  echo 'unknown future active version unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'The installer cannot safely inspect this active version.' "$future_output"
[[ ! -e "$FUTURE_SIDE_EFFECT" ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT

# Unsupported pre-v0.8 and external symlink targets must not be executed.
UNSUPPORTED_BINARY="$PREFIX/lib/cifrarium/versions/0.7.0/cifrarium"
UNSUPPORTED_SIDE_EFFECT="$TEST_ROOT/unsupported-binary-executed"
mkdir -p "$(dirname "$UNSUPPORTED_BINARY")"
cat >"$UNSUPPORTED_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT:?}"
printf '{"configuration":{"state":"configured","severity":"healthy"},"vault":{"state":"ready","severity":"healthy"}}\n'
EOF
chmod 0755 "$UNSUPPORTED_BINARY"
export CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT="$UNSUPPORTED_SIDE_EFFECT"
ln -sfn ../lib/cifrarium/versions/0.7.0/cifrarium "$PREFIX/bin/cifrarium"
unsupported_output="$TEST_ROOT/unsupported-version.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$unsupported_output" 2>&1; then
  echo 'unsupported v0.7 active version unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'The installer cannot safely inspect this active version.' "$unsupported_output"
[[ ! -e "$UNSUPPORTED_SIDE_EFFECT" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium")" == ../lib/cifrarium/versions/0.7.0/cifrarium ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"

EXTERNAL_BINARY="$TEST_ROOT/external/versions/0.10.2/cifrarium"
EXTERNAL_SIDE_EFFECT="$TEST_ROOT/external-binary-executed"
mkdir -p "$(dirname "$EXTERNAL_BINARY")"
cat >"$EXTERNAL_BINARY" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >"${CIFRARIUM_TEST_EXTERNAL_SIDE_EFFECT:?}"
printf '{"configuration":{"state":"configured","severity":"healthy"},"vault":{"state":"ready","severity":"healthy"}}\n'
EOF
chmod 0755 "$EXTERNAL_BINARY"
export CIFRARIUM_TEST_EXTERNAL_SIDE_EFFECT="$EXTERNAL_SIDE_EFFECT"
ln -sfn "$EXTERNAL_BINARY" "$PREFIX/bin/cifrarium"
external_output="$TEST_ROOT/external-active-target.txt"
if "$ROOT_DIR/scripts/install.sh" --version 0.8.38 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$external_output" 2>&1; then
  echo 'external active binary unexpectedly upgraded' >&2
  exit 1
fi
grep -Fq 'The installer cannot safely inspect this active version.' "$external_output"
[[ ! -e "$EXTERNAL_SIDE_EFFECT" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium")" == "$EXTERNAL_BINARY" ]]
cmp -s "$TEST_ROOT/config.before" "$CONFIG_FILE"
cmp -s "$TEST_ROOT/daemon-env.before" "$DAEMON_ENV"
cmp -s "$TEST_ROOT/history.before" "$HOME_DIR/.local/share/cifrarium/snapshots/history"
cmp -s "$TEST_ROOT/keyring.before" "$HOME_DIR/.local/share/cifrarium/keyring-sentinel"
cmp -s "$TEST_ROOT/pending.before" "$HOME_DIR/.local/share/cifrarium/pending.queue"
unset CIFRARIUM_TEST_UNSUPPORTED_SIDE_EFFECT CIFRARIUM_TEST_EXTERNAL_SIDE_EFFECT
ln -sfn ../lib/cifrarium/versions/0.8.37/cifrarium "$PREFIX/bin/cifrarium"

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
previous_target_before=$(readlink "$PREFIX/bin/cifrarium.previous" 2>/dev/null || true)
if "$ROOT_DIR/scripts/install.sh" --version 0.8.5 --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/provider-remote-fail.txt" 2>&1; then
  echo 'inaccessible provider remote unexpectedly upgraded' >&2; exit 1
fi
[[ "$($PREFIX/bin/cifrarium -version)" == 0.8.3 ]]
[[ ! -e "$PREFIX/lib/cifrarium/versions/0.8.5" ]]
[[ -z "$(find "$PREFIX/lib/cifrarium/versions" -maxdepth 1 -name '.staging-0.8.5-*' -print -quit)" ]]
[[ "$(readlink "$PREFIX/bin/cifrarium.previous" 2>/dev/null || true)" == "$previous_target_before" ]]
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
"$ROOT_DIR/scripts/build-release.sh" --version 0.9.0 --out-dir "$TEST_ROOT/release-0.9.0"
cp "$TEST_ROOT/release-0.9.0"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.9.0-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
"$ROOT_DIR/scripts/install.sh" --version 0.9.0 --prefix "$PREFIX" --base-url "https://127.0.0.1:$PORT" >/dev/null
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.9.0 ]]
# The real keyring is intentionally in the Go test process' in-memory keyring.
# The active binary is a separate process, so stub only its read-only doctor
# preflight; keep its version command and all candidate binaries real.
ACTIVE_BINARY="$PREFIX/lib/cifrarium/versions/0.9.0/cifrarium"
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
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.9.0 ]]

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
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.9.0 ]]

# A failed rollback to a nonexistent version must leave user state untouched.
if "$ROOT_DIR/scripts/install.sh" --rollback 0.8.99 --prefix "$PREFIX" \
  >"$TEST_ROOT/lifecycle-rollback-failure.txt" 2>&1; then
  echo 'rollback to a missing lifecycle version unexpectedly succeeded' >&2
  exit 1
fi
assert_lifecycle_state_preserved 'rollback failure'
[[ "$("$PREFIX/bin/cifrarium" -version)" == 0.9.0 ]]

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

# A failed new-install preflight must leave the same version retryable.
RETRY_PREFIX="$TEST_ROOT/retry-prefix"
RETRY_XDG="$TEST_ROOT/retry-xdg"
mkdir -p "$RETRY_XDG/cifrarium"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\n' "$PROVIDER_DIR" >"$RETRY_XDG/cifrarium/daemon.env"
chmod 0600 "$RETRY_XDG/cifrarium/daemon.env"
"$ROOT_DIR/scripts/build-release.sh" --version 0.8.12 --out-dir "$TEST_ROOT/release-0.8.12"
cp "$TEST_ROOT/release-0.8.12"/* "$PUBLIC_DIR/"
for archive in "$PUBLIC_DIR"/cifrarium-0.8.12-*.tar.gz; do printf 'test bundle\n' >"$archive.bundle"; done
export CIFRARIUM_TEST_REMOTE_FAIL=1
if XDG_CONFIG_HOME="$RETRY_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 --prefix "$RETRY_PREFIX" --non-interactive \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/retry-preflight-failure.txt" 2>&1; then
  echo 'inaccessible provider remote unexpectedly installed a new version' >&2
  cat "$TEST_ROOT/retry-preflight-failure.txt" >&2
  exit 1
fi
[[ ! -e "$RETRY_PREFIX/lib/cifrarium/versions/0.8.12" ]]
[[ ! -e "$RETRY_PREFIX/bin/cifrarium" && ! -L "$RETRY_PREFIX/bin/cifrarium" ]]
[[ -z "$(find "$RETRY_PREFIX/lib/cifrarium/versions" -maxdepth 1 -name '.staging-0.8.12.*' -print -quit)" ]]
unset CIFRARIUM_TEST_REMOTE_FAIL
if ! XDG_CONFIG_HOME="$RETRY_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 --prefix "$RETRY_PREFIX" --non-interactive \
  --base-url "https://127.0.0.1:$PORT" >"$TEST_ROOT/retry-after-preflight.txt" 2>&1; then
  cat "$TEST_ROOT/retry-after-preflight.txt" >&2
  exit 1
fi
[[ "$("$RETRY_PREFIX/bin/cifrarium" -version)" == 0.8.12 ]]
[[ -d "$RETRY_PREFIX/lib/cifrarium/versions/0.8.12" ]]
[[ -z "$(find "$RETRY_PREFIX/lib/cifrarium/versions" -maxdepth 1 -name '.staging-0.8.12.*' -print -quit)" ]]

# A hangup during lock acquisition must not strand an installer lock.
LOCKSIGNAL_PREFIX="$TEST_ROOT/locksignal-prefix"
LOCKSIGNAL_XDG="$TEST_ROOT/locksignal-xdg"
mkdir -p "$LOCKSIGNAL_XDG/cifrarium"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\n' "$PROVIDER_DIR" >"$LOCKSIGNAL_XDG/cifrarium/daemon.env"
chmod 0600 "$LOCKSIGNAL_XDG/cifrarium/daemon.env"
export CIFRARIUM_TEST_LOCK_SIGNAL=1
if XDG_CONFIG_HOME="$LOCKSIGNAL_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$LOCKSIGNAL_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/lock-signal.txt" 2>&1; then
  echo 'lock-acquisition hangup unexpectedly returned success' >&2
  exit 1
else
  lock_signal_status=$?
fi
unset CIFRARIUM_TEST_LOCK_SIGNAL
if [[ "$lock_signal_status" != 129 ]]; then
  cat "$TEST_ROOT/lock-signal.txt" >&2
  echo "expected HUP exit 129, got $lock_signal_status" >&2
  exit 1
fi
[[ ! -e "$LOCKSIGNAL_PREFIX/lib/cifrarium/.install.lock" ]]

# A first install must create bin privately even when invoked with umask 000.
UMASK_PREFIX="$TEST_ROOT/umask-prefix"
if ! (umask 000; XDG_CONFIG_HOME="$RETRY_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$UMASK_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT") \
  >"$TEST_ROOT/umask-install.txt" 2>&1; then
  cat "$TEST_ROOT/umask-install.txt" >&2
  exit 1
fi
bin_mode=$(stat -c '%a' "$UMASK_PREFIX/bin")
(( (8#$bin_mode & 0022) == 0 ))
[[ "$($UMASK_PREFIX/bin/cifrarium -version)" == 0.8.12 ]]

# A dangling collision must be preserved and reported without activating a version.
COLLISION_PREFIX="$TEST_ROOT/collision-prefix"
COLLISION_DIR="$COLLISION_PREFIX/lib/cifrarium/versions/0.8.12"
mkdir -p "$(dirname "$COLLISION_DIR")"
ln -s "$TEST_ROOT/missing-candidate-target" "$COLLISION_DIR"
if XDG_CONFIG_HOME="$RETRY_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$COLLISION_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/version-collision.txt" 2>&1; then
  echo 'dangling version collision unexpectedly installed' >&2
  exit 1
fi
grep -Fq "version directory already exists: $COLLISION_DIR" "$TEST_ROOT/version-collision.txt"
[[ -L "$COLLISION_DIR" ]]
[[ "$(readlink "$COLLISION_DIR")" == "$TEST_ROOT/missing-candidate-target" ]]
[[ ! -e "$COLLISION_PREFIX/bin/cifrarium" && ! -L "$COLLISION_PREFIX/bin/cifrarium" ]]

# A source-to-destination swap during promotion must not activate or delete the replacement.
ATTACK_PREFIX="$TEST_ROOT/attack-prefix"
export CIFRARIUM_TEST_CANDIDATE_SWAP=1
if XDG_CONFIG_HOME="$RETRY_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$ATTACK_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/candidate-swap.txt" 2>&1; then
  echo 'substituted candidate directory unexpectedly installed' >&2
  exit 1
fi
unset CIFRARIUM_TEST_CANDIDATE_SWAP
grep -Fq 'staged candidate identity changed during promotion' "$TEST_ROOT/candidate-swap.txt"
[[ -f "$ATTACK_PREFIX/lib/cifrarium/versions/0.8.12/marker" ]]
grep -Fq 'attacker-controlled version' "$ATTACK_PREFIX/lib/cifrarium/versions/0.8.12/marker"
[[ ! -e "$ATTACK_PREFIX/bin/cifrarium" && ! -L "$ATTACK_PREFIX/bin/cifrarium" ]]

# A unit-file failure after candidate preflight must leave the candidate retryable.
POSTFAIL_PREFIX="$TEST_ROOT/postfail-prefix"
POSTFAIL_XDG="$TEST_ROOT/postfail-xdg"
mkdir -p "$POSTFAIL_XDG/cifrarium" "$POSTFAIL_XDG/systemd/user"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\n' "$PROVIDER_DIR" >"$POSTFAIL_XDG/cifrarium/daemon.env"
chmod 0600 "$POSTFAIL_XDG/cifrarium/daemon.env"
printf 'prior service unit sentinel\n' >"$POSTFAIL_XDG/systemd/user/cifrarium.service"
chmod 0644 "$POSTFAIL_XDG/systemd/user/cifrarium.service"
cp "$POSTFAIL_XDG/systemd/user/cifrarium.service" "$TEST_ROOT/prior-service-unit"
export CIFRARIUM_TEST_INSTALL_SERVICE_FAIL=1
if XDG_CONFIG_HOME="$POSTFAIL_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$POSTFAIL_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/post-preflight-failure.txt" 2>&1; then
  echo 'systemd unit write failure unexpectedly installed a version' >&2
  exit 1
fi
[[ ! -e "$POSTFAIL_PREFIX/lib/cifrarium/versions/0.8.12" ]]
[[ ! -e "$POSTFAIL_PREFIX/bin/cifrarium" && ! -L "$POSTFAIL_PREFIX/bin/cifrarium" ]]
[[ ! -e "$POSTFAIL_PREFIX/bin/cifrarium.previous" && ! -L "$POSTFAIL_PREFIX/bin/cifrarium.previous" ]]
[[ -z "$(find "$POSTFAIL_PREFIX/lib/cifrarium/versions" -maxdepth 1 -name '.staging-0.8.12.*' -print -quit)" ]]
[[ -z "$(find "$POSTFAIL_XDG/systemd/user" -maxdepth 1 -name '.cifrarium.service.*' -print -quit)" ]]
cmp -s "$TEST_ROOT/prior-service-unit" "$POSTFAIL_XDG/systemd/user/cifrarium.service"
unset CIFRARIUM_TEST_INSTALL_SERVICE_FAIL
if ! XDG_CONFIG_HOME="$POSTFAIL_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$POSTFAIL_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/post-preflight-retry.txt" 2>&1; then
  cat "$TEST_ROOT/post-preflight-retry.txt" >&2
  exit 1
fi
[[ "$("$POSTFAIL_PREFIX/bin/cifrarium" -version)" == 0.8.12 ]]

# If active-link replacement fails after the unit write, restore the old unit.
ACTIVEFAIL_PREFIX="$TEST_ROOT/activefail-prefix"
ACTIVEFAIL_XDG="$TEST_ROOT/activefail-xdg"
mkdir -p "$ACTIVEFAIL_XDG/cifrarium" "$ACTIVEFAIL_XDG/systemd/user"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\n' "$PROVIDER_DIR" >"$ACTIVEFAIL_XDG/cifrarium/daemon.env"
chmod 0600 "$ACTIVEFAIL_XDG/cifrarium/daemon.env"
printf 'prior unit before activation failure\n' >"$ACTIVEFAIL_XDG/systemd/user/cifrarium.service"
cp "$ACTIVEFAIL_XDG/systemd/user/cifrarium.service" "$TEST_ROOT/activefail-prior-unit"
export CIFRARIUM_TEST_ACTIVE_LINK_FAIL=1
if XDG_CONFIG_HOME="$ACTIVEFAIL_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$ACTIVEFAIL_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/active-link-failure.txt" 2>&1; then
  echo 'active-link failure injection unexpectedly succeeded' >&2
  exit 1
fi
unset CIFRARIUM_TEST_ACTIVE_LINK_FAIL
cmp -s "$TEST_ROOT/activefail-prior-unit" "$ACTIVEFAIL_XDG/systemd/user/cifrarium.service"
[[ ! -e "$ACTIVEFAIL_PREFIX/lib/cifrarium/versions/0.8.12" ]]
[[ ! -e "$ACTIVEFAIL_PREFIX/bin/cifrarium" && ! -L "$ACTIVEFAIL_PREFIX/bin/cifrarium" ]]
[[ -z "$(find "$ACTIVEFAIL_XDG/systemd/user" -maxdepth 1 -name '.cifrarium.service.*' -print -quit)" ]]

# An interruption after the active-link swap must report that activation committed.
SIGNAL_PREFIX="$TEST_ROOT/signal-prefix"
SIGNAL_XDG="$TEST_ROOT/signal-xdg"
mkdir -p "$SIGNAL_XDG/cifrarium"
printf 'CIFRARIUM_PROVIDER_DIR=%s\nCIFRARIUM_PROVIDER_REMOTE=https://github.com/teelabs/private-provider.git\n' "$PROVIDER_DIR" >"$SIGNAL_XDG/cifrarium/daemon.env"
chmod 0600 "$SIGNAL_XDG/cifrarium/daemon.env"
export CIFRARIUM_TEST_ACTIVE_LINK_SIGNAL=1
if XDG_CONFIG_HOME="$SIGNAL_XDG" "$ROOT_DIR/scripts/install.sh" --version 0.8.12 \
  --prefix "$SIGNAL_PREFIX" --non-interactive --base-url "https://127.0.0.1:$PORT" \
  >"$TEST_ROOT/activation-signal.txt" 2>&1; then
  echo 'post-activation signal unexpectedly returned success' >&2
  exit 1
else
  signal_status=$?
fi
unset CIFRARIUM_TEST_ACTIVE_LINK_SIGNAL
[[ "$signal_status" == 143 ]]
grep -Fq 'activation completed before interruption' "$TEST_ROOT/activation-signal.txt"
[[ -L "$SIGNAL_PREFIX/bin/cifrarium" ]]
[[ "$("$SIGNAL_PREFIX/bin/cifrarium" -version)" == 0.8.12 ]]
[[ -d "$SIGNAL_PREFIX/lib/cifrarium/versions/0.8.12" ]]

printf 'installer integration tests passed\n'
