#!/usr/bin/env bash
set -euo pipefail

if git grep -n -I -E -e '-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}' -- ':!go.sum' ':!scripts/verify-secrets.sh'; then
  echo 'high-confidence secret pattern found in tracked source' >&2
  exit 1
fi
