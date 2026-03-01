#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${ROOT_DIR}/data"
OUT_PATH="${DATA_DIR}/global_data.json"

jq -n \
  --slurpfile address_registry "${DATA_DIR}/address_registry.json" \
  --slurpfile tokenlist "${DATA_DIR}/tokenlist.json" \
  --slurpfile metamask "${DATA_DIR}/metamask-uniswap-tokenlist.json" \
  --slurpfile contract_map "${DATA_DIR}/contract-map.json" \
  --slurpfile chainlink_feeds "${DATA_DIR}/chainlink_feeds.json" \
  --slurpfile pairs "${DATA_DIR}/pairs.json" \
  --slurpfile executor_abi "${DATA_DIR}/UnifiedHardenedExecutor_abi.json" \
  '
  def explode_primary:
    .[] | . as $e | ($e.addresses // {}) | to_entries[] |
    {
      symbol: $e.symbol,
      name: ($e.name // $e.symbol),
      decimals: $e.decimals,
      tags: ($e.tags // []),
      coingecko_id: $e.coingecko_id,
      wrapped_symbol: $e.wrapped_symbol,
      chain: .key,
      address: .value
    };
  def explode_metamask:
    .tokens[] |
    {
      symbol: .symbol,
      name: (.name // .symbol),
      decimals: .decimals,
      tags: ["supplemental", "metamask_uniswap"],
      coingecko_id: null,
      wrapped_symbol: null,
      chain: (.chainId | tostring),
      address: .address
    };
  def explode_contract_map:
    to_entries[]
    | select((.value.erc20 // false) == true)
    | {
        symbol: .value.symbol,
        name: (.value.name // .value.symbol),
        decimals: .value.decimals,
        tags: ["supplemental", "contract_map"],
        coingecko_id: null,
        wrapped_symbol: null,
        chain: ((.value.chainId // 1) | tostring),
        address: .key
      };
  def dedupe_entries($entries):
    reduce $entries[] as $item (
      {seen: {}, out: []};
      ($item.chain + ":" + ($item.address | ascii_downcase)) as $k
      | if .seen[$k] then .
        else
          .seen[$k] = true
          | .out += [
              ({
                symbol: $item.symbol,
                name: $item.name,
                decimals: $item.decimals,
                tags: $item.tags,
                addresses: {($item.chain): $item.address}
              }
              + (if $item.coingecko_id != null then {coingecko_id: $item.coingecko_id} else {} end)
              + (if $item.wrapped_symbol != null then {wrapped_symbol: $item.wrapped_symbol} else {} end))
            ]
        end
    )
    | .out;

  ($tokenlist[0] | [explode_primary]) as $base_entries
  | ($metamask[0] | [explode_metamask]) as $metamask_entries
  | ($contract_map[0] | [explode_contract_map]) as $contract_entries
  | {
      version: 1,
      _notes: {
        _comment: "JSON does not support comments; use these notes as in-file documentation.",
        address_registry: "Per-chain protocol/router/feed addresses used for allowlists and defaults.",
        tokenlist: "Canonical merged token list (base tokenlist + MetaMask/Uniswap + ERC20 entries from contract-map), deduped by chain+address with first-entry wins.",
        chainlink_feeds: "Raw Chainlink feed candidates; runtime resolves canonical feed per symbol/chain.",
        pairs: "Optional preloaded AMM pairs used to warm reserve cache.",
        executor_abi: "UnifiedHardenedExecutor contract ABI used by executor tooling."
      },
      address_registry: $address_registry[0],
      tokenlist: dedupe_entries($base_entries + $metamask_entries + $contract_entries),
      chainlink_feeds: $chainlink_feeds[0],
      pairs: $pairs[0],
      executor_abi: $executor_abi[0]
    }
  ' > "${OUT_PATH}"

echo "Wrote ${OUT_PATH}"
