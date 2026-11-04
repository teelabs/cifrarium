#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RELEASE_DIR="$ROOT_DIR/dist/release"
require_signatures=0

while (($#)); do
  case "$1" in
    --dir)
      (($# >= 2)) || { echo "--dir requires a value" >&2; exit 2; }
      RELEASE_DIR=$2
      shift 2
      ;;
    --require-signatures)
      require_signatures=1
      shift
      ;;
    --help|-h)
      echo "Usage: scripts/verify-release.sh [--dir DIR] [--require-signatures]"
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

VERSION=$(tr -d '[:space:]' <"$ROOT_DIR/VERSION")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid VERSION" >&2; exit 1; }
[[ -f "$RELEASE_DIR/manifest.json" ]] || { echo "manifest missing" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 - "$RELEASE_DIR/manifest.json" "$RELEASE_DIR" "$VERSION" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path, release_dir, version = sys.argv[1:]
manifest = json.loads(pathlib.Path(manifest_path).read_text())
if manifest != {"schema": 1, "product": "cifrarium", "version": version, "releases": manifest["releases"]}:
    raise SystemExit("manifest has unexpected top-level fields")
release_list = manifest.get("releases", [])
if len(release_list) != 2:
    raise SystemExit("manifest must contain exactly two releases")
if len({entry.get("architecture") for entry in release_list}) != len(release_list):
    raise SystemExit("manifest contains duplicate architectures")
releases = {entry.get("architecture"): entry for entry in release_list}
if set(releases) != {"linux-amd64", "linux-arm64"}:
    raise SystemExit("manifest must contain exactly amd64 and arm64 releases")
root = pathlib.Path(release_dir)
for architecture, entry in releases.items():
    expected_archive = f"cifrarium-{version}-{architecture}.tar.gz"
    expected_bundle = expected_archive + ".bundle"
    if entry.get("archive") != expected_archive or entry.get("bundle") != expected_bundle:
        raise SystemExit(f"manifest filename mismatch for {architecture}")
    archive = root / expected_archive
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if entry.get("sha256") != digest:
        raise SystemExit(f"manifest checksum mismatch for {architecture}")
PY

for arch in amd64 arm64; do
  archive="$RELEASE_DIR/cifrarium-$VERSION-linux-$arch.tar.gz"
  checksum="$archive.sha256"
  bundle="$archive.bundle"
  [[ -f "$archive" && -f "$checksum" ]] || { echo "missing $arch artifact" >&2; exit 1; }
  (cd "$RELEASE_DIR" && sha256sum --check "$(basename "$checksum")")
  while IFS= read -r member; do
    case "$member" in
      cifrarium|cifrarium.service|README.md|release.json) ;;
      *) echo "unexpected archive member: $member" >&2; exit 1 ;;
    esac
  done < <(tar -tzf "$archive")
  while IFS= read -r listing; do
    read -r file_type _ <<<"$listing"
    [[ "$file_type" == -* ]] || { echo "archive contains a non-regular member: $listing" >&2; exit 1; }
  done < <(tar -tvzf "$archive")
  tar -xOf "$archive" release.json | grep -Fq "\"architecture\": \"linux-$arch\"" || {
    echo "archive architecture mismatch: $arch" >&2
    exit 1
  }
  tar -xOf "$archive" release.json | grep -Fq "\"version\": \"$VERSION\"" || {
    echo "archive version mismatch: $arch" >&2
    exit 1
  }
  tar -xOf "$archive" release.json | python3 -c 'import json,sys; p=json.load(sys.stdin).get("provider"); assert isinstance(p,dict) and isinstance(p.get("format"),int) and isinstance(p.get("compatible"),bool) and isinstance(p.get("migrationRequired"),bool) and isinstance(p.get("migrationCommand"),str) and (not p["migrationRequired"] or p["migrationCommand"])' || {
    echo "archive provider compatibility metadata mismatch: $arch" >&2
    exit 1
  }
  if ((require_signatures)); then
    [[ -s "$bundle" ]] || { echo "signature bundle missing: $bundle" >&2; exit 1; }
    command -v cosign >/dev/null || { echo "cosign is required for signature verification" >&2; exit 1; }
    cosign verify-blob --bundle "$bundle" \
      --certificate-identity-regexp '^https://github.com/teelabs/cifrarium/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "$archive" >/dev/null
  fi
done
if ((require_signatures)); then
  installer="$RELEASE_DIR/install.sh"
  installer_bundle="$RELEASE_DIR/install.sh.bundle"
  [[ -s "$installer" && -s "$installer_bundle" ]] || {
    echo "signed installer entry point is missing" >&2
    exit 1
  }
  cosign verify-blob --bundle "$installer_bundle" \
    --certificate-identity-regexp '^https://github.com/teelabs/cifrarium/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$installer" >/dev/null
fi
printf 'release verification passed for %s\n' "$VERSION"
