#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unit_file="$repo_root/deploy/cloudflared/cloudflared.service"

systemd-analyze verify "$unit_file"

if grep -q -- "--token " "$unit_file"; then
  echo "cloudflared unit must not embed a tunnel token inline" >&2
  exit 1
fi

if ! grep -q -- "--token-file" "$unit_file"; then
  echo "cloudflared unit must load the tunnel token from a token file" >&2
  exit 1
fi
