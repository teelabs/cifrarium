#!/usr/bin/env bash
set -Eeuo pipefail

PRODUCT="cifrarium"
DEFAULT_BASE_URL="https://usecifrarium.pages.dev"
DEFAULT_PREFIX="${HOME:-}/.local"
DEFAULT_COSIGN_IDENTITY='^https://github.com/teelabs/cifrarium/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
DEFAULT_COSIGN_ISSUER="https://token.actions.githubusercontent.com"

action=install
version=""
prefix="$DEFAULT_PREFIX"
base_url="${CIFRARIUM_INSTALL_BASE_URL:-$DEFAULT_BASE_URL}"
cosign_identity="$DEFAULT_COSIGN_IDENTITY"
cosign_issuer="$DEFAULT_COSIGN_ISSUER"
enable=0
confirmed=0
non_interactive=0

die() {
  printf 'cifrarium installer: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  install.sh [--version VERSION] [--prefix DIR] [--base-url URL]
             [--non-interactive] [--enable]
  install.sh --rollback VERSION [--prefix DIR] [--enable]
  install.sh --uninstall --prefix DIR --yes
EOF
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die "--version requires a value"
      action=install
      version=$2
      shift 2
      ;;
    --rollback)
      (($# >= 2)) || die "--rollback requires a value"
      action=rollback
      version=$2
      shift 2
      ;;
    --uninstall)
      action=uninstall
      shift
      ;;
    --prefix)
      (($# >= 2)) || die "--prefix requires a value"
      prefix=$2
      shift 2
      ;;
    --base-url)
      (($# >= 2)) || die "--base-url requires a value"
      base_url=$2
      shift 2
      ;;
    --enable)
      enable=1
      shift
      ;;
    --non-interactive)
      non_interactive=1
      shift
      ;;
    --yes)
      confirmed=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$prefix" && "$prefix" = /* && "$prefix" != "/" ]] || die "prefix must be an absolute non-root path"
[[ "$prefix" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "prefix contains unsupported characters"
[[ "$base_url" =~ ^https://[^[:space:]]+$ ]] || die "base URL must use HTTPS without whitespace"
base_url=${base_url%/}
((enable && non_interactive)) && die "--non-interactive cannot activate the daemon"

reject_symlinked_path_components() {
  local path=$1
  local current="" part
  local -a components
  IFS=/ read -r -a components <<<"$path"
  for part in "${components[@]}"; do
    [[ -n "$part" ]] || continue
    current="$current/$part"
    [[ ! -L "$current" ]] || die "prefix contains a symlinked path component: $current"
  done
}

for protected_path in \
  "$prefix" \
  "$prefix/bin" \
  "$prefix/lib" \
  "$prefix/lib/$PRODUCT" \
  "$prefix/lib/$PRODUCT/versions"; do
  reject_symlinked_path_components "$protected_path"
done

valid_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

if [[ "$action" == rollback ]]; then
  valid_version "$version" || die "rollback requires an explicit SemVer such as 0.4.0"
fi

case "$(uname -s)" in
  Linux) ;;
  *) die "only Linux is supported" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

command -v mktemp >/dev/null || die "mktemp is required"
command -v mv >/dev/null || die "mv is required"
command -v ln >/dev/null || die "ln is required"
command -v install >/dev/null || die "install is required"

state_dir="$prefix/lib/$PRODUCT"
versions_dir="$state_dir/versions"
active_link="$prefix/bin/$PRODUCT"
previous_link="$prefix/bin/$PRODUCT.previous"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_dir/$PRODUCT.service"
lock_dir="$state_dir/.install.lock"

acquire_lock() {
  mkdir -p "$state_dir"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    die "another installer operation is active at $lock_dir"
  fi
  trap 'rm -rf "${work_dir:-}"; rmdir "$lock_dir" 2>/dev/null || true' EXIT
}

atomic_symlink() {
  local target=$1 link=$2 tmp
  mkdir -p "$(dirname "$link")"
  tmp="${link}.tmp.$$"
  rm -f "$tmp"
  ln -s "$target" "$tmp"
  mv -Tf "$tmp" "$link"
}

write_unit() {
  local target=$1 tmp extract_dir=${EXTRACT_DIR:?}
  mkdir -p "$unit_dir"
  tmp="$unit_path.tmp.$$"
  sed "s|%h/.local/bin/cifrarium|$target|g" "$extract_dir/cifrarium.service" >"$tmp"
  install -m 0644 "$tmp" "$unit_path"
  rm -f "$tmp"
}

enable_service() {
  command -v systemctl >/dev/null || die "--enable requires systemctl"
  systemctl --user daemon-reload
  systemctl --user enable --now "$PRODUCT.service"
}

rollback() {
  acquire_lock
  local target="$versions_dir/$version/cifrarium"
  [[ -f "$target" && -x "$target" ]] || die "version is not installed: $version"
  if [[ -L "$active_link" ]]; then
    atomic_symlink "$(readlink "$active_link")" "$previous_link"
  fi
  atomic_symlink "../lib/$PRODUCT/versions/$version/cifrarium" "$active_link"
  if ((enable)); then
    enable_service
  fi
  printf 'rolled back to %s\n' "$version"
}

uninstall() {
  ((confirmed)) || die "uninstall is destructive; pass --yes explicitly"
  acquire_lock
  if [[ -f "$unit_path" ]]; then
    if grep -Fq "Description=Cifrarium" "$unit_path"; then
      if command -v systemctl >/dev/null; then
        set +e
        systemctl --user is-active --quiet "$PRODUCT.service" >/dev/null 2>&1
        active_status=$?
        set -e
        case "$active_status" in
          0)
            systemctl --user disable --now "$PRODUCT.service" >/dev/null 2>&1 || die "could not stop $PRODUCT.service"
            if systemctl --user is-active --quiet "$PRODUCT.service" >/dev/null 2>&1; then
              die "$PRODUCT.service is still active after uninstall request"
            fi
            ;;
          3|4)
            systemctl --user disable "$PRODUCT.service" >/dev/null 2>&1 || true
            ;;
          *)
            die "could not determine $PRODUCT.service state"
            ;;
        esac
        systemctl --user daemon-reload >/dev/null 2>&1 || die "could not reload the user service manager"
      fi
      rm -f "$unit_path"
    else
      printf 'preserved unrelated service file: %s\n' "$unit_path" >&2
    fi
  fi
  if [[ -e "$active_link" || -L "$active_link" ]]; then
    rm -f "$active_link"
  fi
  if [[ -e "$previous_link" || -L "$previous_link" ]]; then
    rm -f "$previous_link"
  fi
  rm -rf "$state_dir"
  printf 'uninstalled from %s\n' "$prefix"
}

if [[ "$action" == rollback ]]; then
  rollback
  exit 0
fi
if [[ "$action" == uninstall ]]; then
  uninstall
  exit 0
fi

for command_name in curl tar sha256sum cosign python3; do
  command -v "$command_name" >/dev/null || die "$command_name is required for verified installation"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-install.XXXXXX")
manifest="$work_dir/manifest.json"

download() {
  local url=$1 output=$2
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 --output "$output" "$url"
}

download "$base_url/manifest.json" "$manifest"
if [[ -z "$version" ]]; then
  version=$(python3 - "$manifest" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
  ) || die "could not resolve the published manifest version"
fi
manifest_info=$(python3 - "$manifest" "$version" "linux-$arch" <<'PY'
import json
import re
import sys

path, version, architecture = sys.argv[1:]
try:
    manifest = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit(f"invalid manifest JSON: {exc}")
if not version:
    version = manifest.get("version", "")
if set(manifest) != {"schema", "product", "version", "releases"}:
    raise SystemExit("manifest has unexpected top-level fields")
if manifest["schema"] != 1 or manifest["product"] != "cifrarium" or manifest["version"] != version:
    raise SystemExit("manifest product, schema, or version mismatch")
releases = manifest["releases"]
if not isinstance(releases, list) or len(releases) != 2:
    raise SystemExit("manifest must contain exactly two releases")
if len({entry.get("architecture") for entry in releases}) != len(releases):
    raise SystemExit("manifest contains duplicate architectures")
selected = None
for entry in releases:
    if set(entry) != {"architecture", "archive", "sha256", "bundle"}:
        raise SystemExit("manifest release entry has unexpected fields")
    if entry["architecture"] not in {"linux-amd64", "linux-arm64"}:
        raise SystemExit("manifest contains an unsupported architecture")
    expected_archive = f"cifrarium-{version}-{entry['architecture']}.tar.gz"
    expected_bundle = expected_archive + ".bundle"
    if entry["archive"] != expected_archive or entry["bundle"] != expected_bundle:
        raise SystemExit("manifest release filenames do not match version and architecture")
    if not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
        raise SystemExit("manifest contains an invalid SHA-256 digest")
    if entry["architecture"] == architecture:
        selected = entry
if selected is None:
    raise SystemExit("manifest does not contain the current architecture")
print(selected["archive"], selected["bundle"], selected["sha256"], sep="\t")
PY
) || die "manifest validation failed"
IFS=$'\t' read -r manifest_archive manifest_bundle manifest_sha <<<"$manifest_info"
valid_version "$version" || die "manifest did not provide a valid SemVer version"
archive_name="$PRODUCT-$version-linux-$arch.tar.gz"
archive="$work_dir/$archive_name"
checksum="$work_dir/$archive_name.sha256"
bundle="$work_dir/$archive_name.bundle"
[[ "$manifest_archive" == "$archive_name" ]] || die "manifest archive mismatch"
[[ "$manifest_bundle" == "$archive_name.bundle" ]] || die "manifest bundle mismatch"

download "$base_url/$archive_name" "$archive"
download "$base_url/$archive_name.sha256" "$checksum"
download "$base_url/$archive_name.bundle" "$bundle"

(cd "$work_dir" && sha256sum --check "$checksum") || die "archive checksum verification failed"
read -r actual_sha _ < <(sha256sum "$archive")
[[ "$actual_sha" == "$manifest_sha" ]] || die "manifest checksum verification failed"
cosign verify-blob --bundle "$bundle" --certificate-identity-regexp "$cosign_identity" --certificate-oidc-issuer "$cosign_issuer" "$archive" >/dev/null || die "Cosign signature verification failed"

extract_dir="$work_dir/extract"
mkdir -m 0700 "$extract_dir"
while IFS= read -r member; do
  case "$member" in
    cifrarium|cifrarium.service|README.md|release.json) ;;
    *) die "unsafe or unexpected archive member: $member" ;;
  esac
done < <(tar -tzf "$archive")
while IFS= read -r listing; do
  read -r file_type _ <<<"$listing"
  [[ "$file_type" == -* ]] || die "archive contains a non-regular member: $listing"
done < <(tar -tvzf "$archive")
tar -xzf "$archive" --no-same-owner --no-same-permissions --directory "$extract_dir"
for required in cifrarium cifrarium.service README.md release.json; do
  [[ -f "$extract_dir/$required" ]] || die "archive is missing $required"
done
[[ -x "$extract_dir/cifrarium" ]] || die "archive binary is not executable"
grep -Fq "\"version\": \"$version\"" "$extract_dir/release.json" || die "archive version metadata mismatch"
grep -Fq "\"architecture\": \"linux-$arch\"" "$extract_dir/release.json" || die "archive architecture metadata mismatch"

acquire_lock
mkdir -p "$versions_dir"
version_dir="$versions_dir/$version"
[[ ! -e "$version_dir" ]] || die "version is already installed: $version"
stage_dir="$versions_dir/.staging-$version-$$"
mkdir -m 0700 "$stage_dir"
install -m 0755 "$extract_dir/cifrarium" "$stage_dir/cifrarium"
install -m 0644 "$extract_dir/cifrarium.service" "$stage_dir/cifrarium.service"
install -m 0644 "$extract_dir/README.md" "$stage_dir/README.md"
install -m 0644 "$extract_dir/release.json" "$stage_dir/release.json"
mv "$stage_dir" "$version_dir"

EXTRACT_DIR="$extract_dir" write_unit "$active_link"

old_target=""
if [[ -L "$active_link" ]]; then
  old_target=$(readlink "$active_link")
elif [[ -e "$active_link" ]]; then
  die "refusing to replace non-symlink active binary: $active_link"
fi
if [[ -n "$old_target" ]]; then
  atomic_symlink "$old_target" "$previous_link"
fi
atomic_symlink "../lib/$PRODUCT/versions/$version/cifrarium" "$active_link"

if ((non_interactive == 0)); then
  if [[ -r /dev/tty && -w /dev/tty && ( -t 0 || -t 1 ) ]]; then
    "$active_link" setup
  else
    printf 'installation completed; no terminal is available for the assistant, run cifrarium setup in a terminal\n' >&2
  fi
fi
if ((enable)); then
  enable_service
fi
printf 'installed %s for linux-%s at %s\n' "$version" "$arch" "$prefix"
