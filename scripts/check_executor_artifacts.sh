#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
forge_bin=${FORGE_BIN:-$(command -v forge || true)}
if [[ -z "$forge_bin" ]]; then
  fallback_forge="/home/${USER}/.foundry/bin/forge"
  if [[ -x "$fallback_forge" ]]; then
    forge_bin="$fallback_forge"
  else
    printf 'forge not found; install Foundry or set FORGE_BIN\n' >&2
    exit 1
  fi
fi

cd "$repo_dir"
"$forge_bin" build --force >/dev/null

artifact="out/UnifiedHardenedExecutor.sol/UnifiedHardenedExecutor.json"
standalone="data/UnifiedHardenedExecutor_abi.json"
global="data/global_data.json"

jq -e --slurpfile standalone "$standalone" \
  '.abi == $standalone[0]' "$artifact" >/dev/null
jq -e --slurpfile standalone "$standalone" \
  '.executor_abi == $standalone[0]' "$global" >/dev/null

runtime_bytecode=$(jq -r '.deployedBytecode.object' "$artifact")
runtime_hex=${runtime_bytecode#0x}
runtime_bytes=$((${#runtime_hex} / 2))
eip170_limit=24576
if ((runtime_bytes > eip170_limit)); then
  printf 'executor runtime exceeds EIP-170: %s > %s bytes\n' \
    "$runtime_bytes" "$eip170_limit" >&2
  exit 1
fi

runtime_hash=$(printf '%s' "$runtime_bytecode" | "$repo_dir/scripts/keccak_hex.sh")
creation_hash=$(jq -r '.bytecode.object' "$artifact" | "$repo_dir/scripts/keccak_hex.sh")
printf 'executor artifacts synchronized\nruntime_bytes=%s\neip170_headroom_bytes=%s\ncreation_bytecode_keccak=%s\nruntime_template_keccak=%s\n' \
  "$runtime_bytes" "$((eip170_limit - runtime_bytes))" "$creation_hash" "$runtime_hash"
