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

drain_piped_input() {
  if [[ ! -t 0 ]]; then
    while IFS= read -r; do :; done || true
  fi
}

die() {
  printf '%b\n' "$*" >&2
  drain_piped_input
  exit 1
}

step() {
	if [[ -t 2 ]]; then
		printf '\r\033[2K%s...' "$*" >&2
	else
		printf '%s...\n' "$*" >&2
	fi
}

step_done() {
	if [[ -t 2 ]]; then
		printf '\r\033[2K%s OK\n' "$*" >&2
	else
		printf '%s OK\n' "$*" >&2
	fi
}

INSTALLER_RELEASE_VERSION="__CIFRARIUM_INSTALLER_RELEASE_VERSION__"

dependency_suggestions() {
  local manager=""
  if command -v apt-get >/dev/null 2>&1; then
    manager=apt
  elif command -v dnf >/dev/null 2>&1; then
    manager=dnf
  elif command -v pacman >/dev/null 2>&1; then
    manager=pacman
  elif command -v apk >/dev/null 2>&1; then
    manager=apk
  elif command -v brew >/dev/null 2>&1; then
    manager=brew
  elif command -v nix >/dev/null 2>&1; then
    manager=nix
  fi

  printf '\n' >&2
  printf 'Install the missing dependencies, then run the command again.\n' >&2
  case "$manager" in
    apt)
      printf '  sudo apt-get update && sudo apt-get install -y curl tar coreutils python3\n' >&2
      ;;
    dnf)
      printf '  sudo dnf install -y curl tar coreutils python3\n' >&2
      ;;
    pacman)
      printf '  sudo pacman -S --needed curl tar coreutils python\n' >&2
      ;;
    apk)
      printf '  sudo apk add curl tar coreutils python3\n' >&2
      ;;
    brew)
      printf '  brew install curl gnu-tar coreutils python3\n' >&2
      ;;
    nix)
      printf '  nix profile install nixpkgs#curl nixpkgs#gnutar nixpkgs#coreutils nixpkgs#python3\n' >&2
      ;;
    *)
      printf '  Install the listed tools with your Linux distribution package manager.\n' >&2
      ;;
  esac
  if [[ " ${missing_dependencies[*]} " == *' cosign '* ]]; then
    printf '  Cosign installation options: https://docs.sigstore.dev/cosign/system_config/installation/\n' >&2
    case "$manager" in
      pacman) printf '  sudo pacman -S --needed cosign\n' >&2 ;;
      apk) printf '  sudo apk add cosign\n' >&2 ;;
      brew) printf '  brew install cosign\n' >&2 ;;
      nix) printf '  nix profile install nixpkgs#cosign\n' >&2 ;;
      *) printf '  Follow the official Cosign installation and verification instructions above.\n' >&2 ;;
    esac
  fi
  printf '\n'
}

audit_dependencies() {
  local command_name
  missing_dependencies=()
  for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing_dependencies+=("$command_name")
    fi
  done
  if ((${#missing_dependencies[@]} > 0)); then
    printf 'missing dependencies:\n' >&2
    for command_name in "${missing_dependencies[@]}"; do
      printf '  - %s\n' "$command_name" >&2
    done
    dependency_suggestions
    drain_piped_input
    exit 1
  fi
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

modern_doctor_interface_supported() {
  local installer_version="$INSTALLER_RELEASE_VERSION"
  if [[ ! "$installer_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local script_dir="${BASH_SOURCE[0]%/*}"
    local source_version_file="$script_dir/../VERSION"
    if [[ -f "$source_version_file" ]]; then
      IFS= read -r installer_version <"$source_version_file"
    else
      installer_version=""
    fi
  fi
  python3 - "$1" "$installer_version" <<'PY'
import re
import sys

def semver(value):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("invalid semantic version")
    return tuple(int(part) for part in value.split("."))

try:
    active = semver(sys.argv[1])
    installer = semver(sys.argv[2])
except ValueError:
    raise SystemExit(1)

raise SystemExit(0 if (0, 9, 0) <= active <= installer else 1)
PY
}

if [[ "$action" == rollback ]]; then
  valid_version "$version" || die "rollback requires an explicit SemVer such as 0.4.0"
fi

required_commands=(uname mkdir rm rmdir)
case "$action" in
  install)
    required_commands+=(mktemp mv ln install dirname sed grep curl tar sha256sum cosign python3 stat readlink)
    ;;
  rollback)
    required_commands+=(mv ln readlink)
    ;;
  uninstall)
    required_commands+=(grep)
    ;;
esac
if ((enable)); then
  required_commands+=(systemctl)
fi
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_dir/$PRODUCT.service"
if [[ "$action" == uninstall && -f "$unit_path" ]]; then
  required_commands+=(systemctl)
fi

step 'Checking dependencies'
audit_dependencies
step_done 'Checking dependencies'

step 'Checking platform'
case "$(uname -s)" in
  Linux) ;;
  *) die "only Linux is supported" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
step_done "Checking platform (Linux $arch)"

state_dir="$prefix/lib/$PRODUCT"
versions_dir="$state_dir/versions"
active_link="$prefix/bin/$PRODUCT"
previous_link="$prefix/bin/$PRODUCT.previous"
lock_dir="$state_dir/.install.lock"
upgrade=0
validated_active_target=""
validated_active_binary=""
provider_dir_configured=""
provider_remote_configured=""
provider_configured=0

if [[ -L "$active_link" ]]; then
  upgrade=1
fi

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

read_provider_config() {
  local env_file="${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/daemon.env"
  [[ -e "$env_file" ]] || return 0
  [[ -f "$env_file" ]] || die "daemon.env is not a regular file: $env_file"
  local mode
  mode=$(stat -c '%a' "$env_file" 2>/dev/null) || die "cannot inspect daemon.env permissions"
  [[ "$mode" == 600 ]] || die "daemon.env must have mode 0600: $env_file"
  local values
  values=$(python3 - "$env_file" <<'PY'
import pathlib, sys
allowed = {
    "CIFRARIUM_PROVIDER_DIR",
    "CIFRARIUM_PROVIDER_REMOTE",
    "CIFRARIUM_RECOVERY_SHARE_1",
    "CIFRARIUM_RECOVERY_SHARE_2",
}
values = {}
for number, raw in enumerate(pathlib.Path(sys.argv[1]).read_text().splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit(f"daemon.env line {number} is invalid; use KEY=value")
    key, value = line.split("=", 1)
    if key not in allowed or not value or any(c in value for c in "\t\r\n"):
        raise SystemExit(f"daemon.env line {number} is invalid; only recognized provider and recovery keys are accepted")
    values[key] = value
if bool(values.get("CIFRARIUM_PROVIDER_DIR")) != bool(values.get("CIFRARIUM_PROVIDER_REMOTE")):
    raise SystemExit("daemon.env must configure provider directory and remote together")
print(values.get("CIFRARIUM_PROVIDER_DIR", ""), values.get("CIFRARIUM_PROVIDER_REMOTE", ""), sep="\t")
PY
  ) || die "invalid daemon.env; fix it and retry the upgrade"
  IFS=$'\t' read -r provider_dir_configured provider_remote_configured <<<"$values"
  if [[ -n "$provider_dir_configured" ]]; then
    provider_configured=1
  fi
}

provider_preflight() {
  if ((provider_configured == 0)); then
    printf 'Provider: not configured (local installation permitted)\n' >&2
    return 0
  fi
  [[ "$provider_dir_configured" = /* ]] || die "configured provider directory must be absolute"
  [[ -d "$provider_dir_configured/.git" ]] || die "Upgrade blocked\n\nWhat happened\nThe configured provider checkout is missing.\n\nWhy it matters\nActivating this version could strand encrypted history.\n\nHow to fix it\nRestore the checkout, then retry.\n\nCOMMAND\ngit -C <provider-directory> status\n\nWhat to do next\nKeep the current version active until provider health passes."
  git -C "$provider_dir_configured" status --porcelain >/dev/null 2>&1 || die "configured provider checkout is inaccessible"
  git -C "$provider_dir_configured" ls-remote "$provider_remote_configured" HEAD >/dev/null 2>&1 || die "Upgrade blocked\n\nWhat happened\nThe configured provider remote is inaccessible.\n\nWhy it matters\nThe upgrade cannot verify the remote backup boundary.\n\nHow to fix it\nRestore GitHub access without putting tokens in daemon.env.\n\nCOMMAND\ncifrarium provider health -provider-dir <provider-directory> -provider-remote <github-remote>\n\nWhat to do next\nKeep the current version active and retry after provider health passes."
  command -v gh >/dev/null 2>&1 || die "configured GitHub provider requires gh for privacy verification"
  local slug
  slug=$(python3 - "$provider_remote_configured" <<'PY'
import re, sys
m = re.fullmatch(r"https://github\.com/([^/]+)/([^/#]+?)(?:\.git)?", sys.argv[1])
if not m: raise SystemExit(1)
print(f"{m.group(1)}/{m.group(2)}")
PY
  ) || die "configured provider remote must be an HTTPS GitHub repository URL"
  [[ "$(gh api "repos/$slug" --jq .private 2>/dev/null)" == true ]] || die "Upgrade blocked\n\nWhat happened\nThe configured GitHub repository is not confirmed private.\n\nWhy it matters\nCifrarium requires a private provider for encrypted backup metadata.\n\nHow to fix it\nMake the repository private and verify access.\n\nCOMMAND\ngh api repos/<owner>/<repository> --jq .private\n\nWhat to do next\nKeep the current version active and retry."
}

validate_existing_state() {
  ((upgrade)) || return 0
  local active_target active_version active_major active_minor active_patch active_binary
  active_target=$(readlink "$active_link") || die "The installer cannot safely inspect this active version.\n\nNo diagnostic command was run because the active executable is not a recognized managed release. Keep it in place and consult its documented upgrade guidance."
  if [[ ! "$active_target" =~ ^\.\./lib/cifrarium/versions/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)/cifrarium$ ]]; then
    die "The installer cannot safely inspect this active version.\n\nNo diagnostic command was run because the active executable is not a recognized managed release. Keep it in place and consult its documented upgrade guidance."
  fi
  active_major=${BASH_REMATCH[1]}
  active_minor=${BASH_REMATCH[2]}
  active_patch=${BASH_REMATCH[3]}
  active_version="$active_major.$active_minor.$active_patch"
  active_binary="$prefix/lib/$PRODUCT/versions/$active_version/$PRODUCT"
  reject_symlinked_path_components "$active_binary"
  [[ -f "$active_binary" && -x "$active_binary" ]] || die "The installer cannot safely inspect this active version.\n\nThe managed executable is missing or is not a regular executable file. Keep it in place and consult its documented upgrade guidance."
  validated_active_target="$active_target"
  validated_active_binary="$active_binary"

  local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/config.json"
  if [[ ! -e "$config_file" ]]; then
    printf 'Vault: not configured (upgrade will preserve the local installation)\n' >&2
    return 0
  fi
  [[ -f "$config_file" ]] || die "config.json is not a regular file"
  [[ "$(stat -c '%a' "$config_file" 2>/dev/null)" == 600 ]] || die "config.json must have mode 0600 before an upgrade"
  python3 - "$config_file" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
root = data.get("root")
if data.get("schema") != 1 or not isinstance(root, str) or not root.startswith("/"):
    raise SystemExit("config.json has invalid schema or root")
if os.path.realpath(root) != root or not os.path.isdir(root):
    raise SystemExit("configured vault root is missing or not canonical")
PY
  local doctor_report doctor_command
  local -a doctor_args
  if [[ "$active_version" == 0.8.0 || "$active_version" == 0.8.1 || "$active_version" == 0.8.2 ]]; then
    # v0.8.0-v0.8.2 parse doctor through the legacy flag. A modern positional
    # argument is treated as the default status command and can update keyring
    # catalog metadata before returning non-JSON output.
    doctor_args=(-command=doctor -format=json)
    doctor_command="$active_binary -command=doctor -format=json"
  elif modern_doctor_interface_supported "$active_version"; then
    # Cifrarium releases from 0.9.0 onward keep the positional, read-only doctor
    # contract. Bound this range to the release version embedded in this
    # installer so future, unrecognized interfaces still fail closed.
    doctor_args=(doctor -format=json)
    doctor_command="$active_binary doctor -format=json"
  else
    die "The installer cannot safely inspect this active version.\n\nNo diagnostic command was run because its doctor interface is not known to be safe for upgrade preflight. Keep it in place and consult its documented upgrade guidance."
  fi
  doctor_report=$("$active_binary" "${doctor_args[@]}" 2>/dev/null) || true
  if ! printf '%s' "$doctor_report" | python3 -c '
import json
import sys

try:
    report = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(1)

configuration = report.get("configuration")
vault = report.get("vault")
if not isinstance(configuration, dict) or not isinstance(vault, dict):
    raise SystemExit(1)
if configuration.get("state") != "configured" or configuration.get("severity") != "healthy":
    raise SystemExit(1)
if vault.get("state") != "ready" or vault.get("severity") != "healthy":
    raise SystemExit(1)
' >/dev/null 2>&1; then
    die "Upgrade blocked\n\nWhat happened\nThe active version could not confirm that the configured root and keyring are healthy.\n\nWhy it matters\nChanging versions without that proof risks losing access to the vault.\n\nHow to fix it\nRun $doctor_command and resolve any Configuration or Vault problem.\n\nWhat to do next\nKeep the active version in place and retry."
  fi
  # A non-zero doctor status can reflect an unrelated daemon, MCP, provider, or
  # adapter problem. The Configuration and Vault JSON fields above are the
  # upgrade safety proof; the full doctor status remains available to users.
}

if [[ "$action" == install ]]; then
  read_provider_config
fi

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

validate_existing_state

for command_name in curl tar sha256sum cosign python3; do
  command -v "$command_name" >/dev/null || die "$command_name is required for verified installation"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/cifrarium-install.XXXXXX")
manifest="$work_dir/manifest.json"

download() {
  local label=$1 url=$2 output=$3
  step "Downloading $label"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 --output "$output" "$url"
  step_done "Downloading $label"
}

download 'manifest' "$base_url/manifest.json" "$manifest"
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
step_done "Selecting version $version for linux-$arch"
IFS=$'\t' read -r manifest_archive manifest_bundle manifest_sha <<<"$manifest_info"
valid_version "$version" || die "manifest did not provide a valid SemVer version"
archive_name="$PRODUCT-$version-linux-$arch.tar.gz"
archive="$work_dir/$archive_name"
checksum="$work_dir/$archive_name.sha256"
bundle="$work_dir/$archive_name.bundle"
[[ "$manifest_archive" == "$archive_name" ]] || die "manifest archive mismatch"
[[ "$manifest_bundle" == "$archive_name.bundle" ]] || die "manifest bundle mismatch"

download 'archive' "$base_url/$archive_name" "$archive"
download 'checksum' "$base_url/$archive_name.sha256" "$checksum"
download 'signature bundle' "$base_url/$archive_name.bundle" "$bundle"

step 'Verifying archive checksum'
(cd "$work_dir" && sha256sum --check "$checksum") || die "archive checksum verification failed"
read -r actual_sha _ < <(sha256sum "$archive")
[[ "$actual_sha" == "$manifest_sha" ]] || die "manifest checksum verification failed"
step_done 'Verifying archive checksum'
step 'Verifying archive signature'
cosign verify-blob --bundle "$bundle" --certificate-identity-regexp "$cosign_identity" --certificate-oidc-issuer "$cosign_issuer" "$archive" >/dev/null || die "Cosign signature verification failed"
step_done 'Verifying archive signature'

step 'Validating archive contents'
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
release_info=$(python3 - "$extract_dir/release.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
p = m.get("provider")
if not isinstance(p, dict) or not isinstance(p.get("format"), int) or not isinstance(p.get("compatible"), bool) or not isinstance(p.get("migrationRequired"), bool) or not isinstance(p.get("migrationCommand"), str):
    raise SystemExit("invalid provider compatibility metadata")
if p["migrationRequired"] and not p["migrationCommand"]:
    raise SystemExit("migrationRequired metadata must include migrationCommand")
print(p["format"], str(p["compatible"]).lower(), str(p["migrationRequired"]).lower(), p["migrationCommand"], sep="\t")
PY
) || die "archive provider compatibility metadata is invalid"
IFS=$'\t' read -r candidate_provider_format candidate_compatible candidate_migration_required candidate_migration_command <<<"$release_info"
if ((upgrade)); then
  active_release="$(dirname "$validated_active_binary")/release.json"
  if [[ -f "$active_release" ]]; then
    active_provider_format=$(python3 - "$active_release" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("provider", {}).get("format", 1))
PY
    ) || die "active release metadata is invalid"
    [[ "$candidate_compatible" == true && "$candidate_provider_format" == "$active_provider_format" ]] || die "Upgrade blocked\n\nWhat happened\nThe candidate provider format is incompatible with the active version.\n\nHow to fix it\nReview and run the approved provider migration command.\n\nCOMMAND\n$candidate_migration_command\n\nWhat to do next\nThe previous version remains active; retry after migration."
    if [[ "$candidate_migration_required" == true ]]; then
      die "Upgrade blocked\n\nWhat happened\nThis release requires a provider migration.\n\nWhy it matters\nMigrations can change durable provider state and are never automatic.\n\nCOMMAND\n$candidate_migration_command\n\nWhat to do next\nThe previous version remains active; retry after migration."
    fi
  fi
fi
step_done 'Validating archive contents'

step 'Installing verified files'
acquire_lock
current_active_target=$(readlink "$active_link" 2>/dev/null || true)
if ((upgrade)); then
  [[ "$current_active_target" == "$validated_active_target" ]] || die "The active version changed during upgrade preflight. Keep the current version in place and retry the upgrade."
else
  [[ ! -e "$active_link" && ! -L "$active_link" ]] || die "An active version appeared during installation. Keep it in place and retry."
fi
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

old_target=""
if [[ -L "$active_link" ]]; then
  old_target=$(readlink "$active_link")
elif [[ -e "$active_link" ]]; then
  die "refusing to replace non-symlink active binary: $active_link"
fi
if [[ -n "$old_target" ]]; then
  atomic_symlink "$old_target" "$previous_link"
fi
step 'Running staged preflight'
[[ "$($version_dir/cifrarium -version 2>/dev/null)" == "$version" ]] || die "candidate binary preflight failed"
set +e
"$version_dir/cifrarium" doctor -format=json >/dev/null 2>&1
candidate_diagnostic_status=$?
set -e
((candidate_diagnostic_status <= 1)) || die "candidate diagnostic preflight failed"
provider_preflight
step_done 'Running staged preflight'
EXTRACT_DIR="$extract_dir" write_unit "$active_link"
atomic_symlink "../lib/$PRODUCT/versions/$version/cifrarium" "$active_link"

step 'Running final read-only diagnostic'
set +e
"$active_link" doctor -format=json >/dev/null 2>&1
diagnostic_status=$?
set -e
((diagnostic_status <= 1)) || die "final diagnostic failed"
if ((upgrade)); then
  installation_mode=upgrade
else
  installation_mode='new install'
fi
printf 'installation mode: %s\nactive version: %s\ncandidate version: %s\nprovider: %s\nprovider format: %s\nmigration required: %s\ndaemon compatibility: %s\n' \
  "$installation_mode" "$([[ -n "$old_target" ]] && basename "$(dirname "$old_target")" || printf 'none')" "$version" \
  "$([[ $provider_configured == 1 ]] && printf configured || printf 'not configured')" "$candidate_provider_format" "$candidate_migration_required" "$candidate_compatible" >&2
step_done 'Running final read-only diagnostic'

if ((non_interactive == 0 && upgrade == 0)); then
  if [[ -r /dev/tty && -w /dev/tty && ( -t 0 || -t 1 ) ]]; then
    "$active_link" setup
  else
    printf 'installation completed; no terminal is available for the assistant, run cifrarium setup in a terminal\n' >&2
  fi
fi
if ((enable)); then
  enable_service
fi
step_done 'Installing verified files'
printf 'installed %s for linux-%s at %s\n' "$version" "$arch" "$prefix"
