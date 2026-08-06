#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
forge_bin=${FORGE_BIN:-/home/john/.foundry/bin/forge}

cd "$repo_dir"
"$forge_bin" build --force >/dev/null

artifact="out/UnifiedHardenedExecutor.sol/UnifiedHardenedExecutor.json"
standalone="data/UnifiedHardenedExecutor_abi.json"
global="data/global_data.json"

jq -e --slurpfile standalone "$standalone" \
  '.abi == $standalone[0]' "$artifact" >/dev/null
jq -e --slurpfile standalone "$standalone" \
  '.executor_abi == $standalone[0]' "$global" >/dev/null

runtime_hash=$(jq -r '.deployedBytecode.object' "$artifact" | "$repo_dir/scripts/keccak_hex.sh")
creation_hash=$(jq -r '.bytecode.object' "$artifact" | "$repo_dir/scripts/keccak_hex.sh")
printf 'executor artifacts synchronized\ncreation_bytecode_keccak=%s\nruntime_template_keccak=%s\n' \
  "$creation_hash" "$runtime_hash"
