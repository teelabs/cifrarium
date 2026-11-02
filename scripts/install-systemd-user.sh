#!/usr/bin/env bash
set -euo pipefail

enable_service=false
if [[ "${1:-}" == "--enable" ]]; then
  enable_service=true
elif [[ "${1:-}" != "" ]]; then
  echo "usage: $0 [--enable]" >&2
  exit 2
fi

home_dir=${HOME:?HOME must be set}
config_home=${XDG_CONFIG_HOME:-"$home_dir/.config"}
unit_dir="$config_home/systemd/user"
source_dir=$(cd "$(dirname "$0")/.." && pwd)
unit_source="$source_dir/systemd/cifrarium.service"
unit_target="$unit_dir/cifrarium.service"

[[ -f "$unit_source" ]] || { echo "unit not found: $unit_source" >&2; exit 1; }
mkdir -p "$unit_dir"
install -m 0644 "$unit_source" "$unit_target"

if [[ "$enable_service" == true ]]; then
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl is required for --enable" >&2; exit 1; }
  systemctl --user daemon-reload
  systemctl --user enable --now cifrarium.service
else
  echo "installed $unit_target; run $0 --enable to reload, enable, and start it"
fi
