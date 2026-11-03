#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=0.4.0
GO_CACHE=$(go env GOCACHE)
GO_MOD_CACHE=$(go env GOMODCACHE)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-installer-test.XXXXXX")
PUBLIC_DIR="$TEST_ROOT/public"
HOME_DIR="$TEST_ROOT/home"
PREFIX="$HOME_DIR/.local"
FAKE_BIN="$TEST_ROOT/bin"
SYSTEMCTL_LOG="$TEST_ROOT/systemctl.log"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
CERT="$TEST_ROOT/cert.pem"
KEY="$TEST_ROOT/key.pem"

cleanup() {
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

export PATH="$FAKE_BIN:$PATH"
export HOME="$HOME_DIR"
export XDG_CONFIG_HOME="$HOME_DIR/.config"
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

"$ROOT_DIR/scripts/install.sh" --version "$VERSION" --prefix "$PREFIX" \
  --base-url "https://127.0.0.1:$PORT"
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]
[[ -L "$PREFIX/bin/cifrarium" ]]
[[ -f "$HOME_DIR/.config/systemd/user/cifrarium.service" ]]
if [[ -s "$SYSTEMCTL_LOG" ]]; then
  echo 'installer started systemd without --enable' >&2
  cat "$SYSTEMCTL_LOG" >&2
  exit 1
fi

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
[[ -f "$HOME_DIR/.config/systemd/user/cifrarium.service" ]]
[[ -L "$PREFIX/bin/cifrarium" ]]
[[ "$("$PREFIX/bin/cifrarium" -version)" == "$VERSION" ]]
unset CIFRARIUM_TEST_SYSTEMCTL_ACTIVE
"$ROOT_DIR/scripts/install.sh" --uninstall --prefix "$PREFIX" --yes
[[ ! -e "$PREFIX/bin/cifrarium" ]]

printf 'installer integration tests passed\n'
