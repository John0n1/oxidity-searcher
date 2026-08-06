#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  printf 'usage: %s <rpc-url> <executor> <owner> <weth> <balancer-vault>\n' "$0" >&2
  exit 2
fi

rpc_url=$1
executor=$2
expected_owner=$3
expected_weth=$4
expected_vault=$5
cast_bin=${CAST_BIN:-/home/john/.foundry/bin/cast}

code=$($cast_bin code "$executor" --rpc-url "$rpc_url")
if [[ "$code" == "0x" ]]; then
  printf 'executor has no runtime code\n' >&2
  exit 1
fi

owner=$($cast_bin call "$executor" 'owner()(address)' --rpc-url "$rpc_url")
weth=$($cast_bin call "$executor" 'WETH()(address)' --rpc-url "$rpc_url")
vault=$($cast_bin call "$executor" 'balancerVault()(address)' --rpc-url "$rpc_url")
receiver=$($cast_bin call "$executor" 'profitReceiver()(address)' --rpc-url "$rpc_url")
paused=$($cast_bin call "$executor" 'paused()(bool)' --rpc-url "$rpc_url")
runtime_hash=$(printf '%s\n' "$code" | "$(dirname "$0")/keccak_hex.sh")

[[ "${owner,,}" == "${expected_owner,,}" ]] || { printf 'owner mismatch: %s\n' "$owner" >&2; exit 1; }
[[ "${weth,,}" == "${expected_weth,,}" ]] || { printf 'WETH mismatch: %s\n' "$weth" >&2; exit 1; }
[[ "${vault,,}" == "${expected_vault,,}" ]] || { printf 'Balancer Vault mismatch: %s\n' "$vault" >&2; exit 1; }
[[ "${receiver,,}" != "0x0000000000000000000000000000000000000000" ]] || { printf 'zero profit receiver\n' >&2; exit 1; }

printf 'executor deployment verified\naddress=%s\nowner=%s\nweth=%s\nbalancer_vault=%s\nprofit_receiver=%s\npaused=%s\nruntime_code_keccak=%s\n' \
  "$executor" "$owner" "$weth" "$vault" "$receiver" "$paused" "$runtime_hash"
