#!/usr/bin/env bash
set -euo pipefail

version=$(tr -d '[:space:]' < VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid VERSION: $version" >&2; exit 1; }
grep -q '^## \[Unreleased\]' CHANGELOG.md || { echo 'CHANGELOG.md lacks Unreleased section' >&2; exit 1; }
grep -q "^## \[$version\] - " CHANGELOG.md || { echo "CHANGELOG.md lacks released version $version" >&2; exit 1; }
if grep -R -n --exclude-dir=.git --exclude=go.sum --exclude=CHANGELOG.md --exclude=VERSION '0\.1\.0' .; then
  echo 'stale version reference found' >&2
  exit 1
fi
