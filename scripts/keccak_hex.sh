#!/usr/bin/env bash
set -euo pipefail

cast_bin=${CAST_BIN:-/home/john/.foundry/bin/cast}
IFS= read -r hex_value
"$cast_bin" keccak "$hex_value"
