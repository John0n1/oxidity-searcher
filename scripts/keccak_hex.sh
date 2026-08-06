#!/usr/bin/env bash
set -euo pipefail

cast_bin="${CAST_BIN:-${HOME}/.foundry/bin/cast}"

if [[ ! -x "$cast_bin" ]]; then
    printf 'Error: cast not found or not executable: %s\n' "$cast_bin" >&2
    exit 1
fi

IFS= read -r hex_value || {
    printf 'Error: failed to read input\n' >&2
    exit 1
}

"$cast_bin" keccak "$hex_value"