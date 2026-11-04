#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION_FILE="$ROOT_DIR/VERSION"
VERSION=$(tr -d '[:space:]' <"$VERSION_FILE")
OUT_DIR="$ROOT_DIR/dist/release"

usage() {
  cat <<'EOF'
Usage: scripts/build-release.sh [--version VERSION] [--out-dir DIR]
EOF
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || { echo "--version requires a value" >&2; exit 2; }
      VERSION=$2
      shift 2
      ;;
    --out-dir)
      (($# >= 2)) || { echo "--out-dir requires a value" >&2; exit 2; }
      OUT_DIR=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version: $VERSION" >&2; exit 1; }
command -v go >/dev/null || { echo "go is required" >&2; exit 1; }
command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }
command -v realpath >/dev/null || { echo "realpath is required" >&2; exit 1; }

resolved_out_dir=$(realpath -m "$OUT_DIR")
safe_default_out_dir=$(realpath -m "$ROOT_DIR/dist/release")
case "$resolved_out_dir" in
  /|"$ROOT_DIR")
    echo "refusing unsafe output directory: $OUT_DIR" >&2
    exit 1
    ;;
  "$ROOT_DIR"/*)
    [[ "$resolved_out_dir" == "$safe_default_out_dir" ]] || {
      echo "refusing output directory inside the checkout: $OUT_DIR" >&2
      exit 1
    }
    ;;
esac
if [[ "$resolved_out_dir" != "$safe_default_out_dir" && -e "$resolved_out_dir" ]]; then
  [[ -d "$resolved_out_dir" ]] || {
    echo "refusing non-directory output path: $OUT_DIR" >&2
    exit 1
  }
  if [[ -n "$(find "$resolved_out_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "refusing non-empty output directory: $OUT_DIR" >&2
    exit 1
  fi
fi
OUT_DIR=$resolved_out_dir

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-release.XXXXXX")
trap 'rm -rf "$tmp_root"' EXIT

for arch in amd64 arm64; do
  stage="$tmp_root/linux-$arch"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$VERSION" \
    -o "$stage/cifrarium" "$ROOT_DIR/cmd/cifrarium"
  install -m 0644 "$ROOT_DIR/systemd/cifrarium.service" "$stage/cifrarium.service"
  install -m 0644 "$ROOT_DIR/README.md" "$stage/README.md"
  cat >"$stage/release.json" <<EOF
{
  "product": "cifrarium",
  "version": "$VERSION",
  "architecture": "linux-$arch",
  "provider": {
    "format": 1,
    "compatible": true,
    "migrationRequired": false,
    "migrationCommand": ""
  }
}
EOF
  archive="$OUT_DIR/cifrarium-$VERSION-linux-$arch.tar.gz"
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "$archive" -C "$stage" cifrarium cifrarium.service README.md release.json
  (cd "$OUT_DIR" && sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256")
done

amd64_archive="cifrarium-$VERSION-linux-amd64.tar.gz"
arm64_archive="cifrarium-$VERSION-linux-arm64.tar.gz"
amd64_hash=$(awk '{print $1}' "$OUT_DIR/$amd64_archive.sha256")
arm64_hash=$(awk '{print $1}' "$OUT_DIR/$arm64_archive.sha256")
cat >"$OUT_DIR/manifest.json" <<EOF
{
  "schema": 1,
  "product": "cifrarium",
  "version": "$VERSION",
  "releases": [
    {
      "architecture": "linux-amd64",
      "archive": "$amd64_archive",
      "sha256": "$amd64_hash",
      "bundle": "$amd64_archive.bundle"
    },
    {
      "architecture": "linux-arm64",
      "archive": "$arm64_archive",
      "sha256": "$arm64_hash",
      "bundle": "$arm64_archive.bundle"
    }
  ]
}
EOF

printf 'built Cifrarium %s release artifacts in %s\n' "$VERSION" "$OUT_DIR"
