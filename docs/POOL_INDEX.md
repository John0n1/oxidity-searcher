# Curated pool index

`pool_indexer` discovers Uniswap V3/V4, Balancer V2, and Curve pools from canonical on-chain
sources, measures current liquidity and recent swap volume, and writes both accepted and rejected
records with explicit reasons. The searcher loads only `eligible=true` records and revalidates their
protocol identity against the active RPC node.

## Default policy

- canonical factory, PoolManager, Vault, or Curve registry provenance;
- at least 50,400 blocks old (roughly seven Ethereum days);
- at least $100,000 current liquidity for contract-held V3/Balancer/Curve assets;
- non-zero protocol liquidity from Uniswap V4 `StateView` (used instead of an invented per-pool
  USD TVL for the singleton manager);
- at least $10,000 volume and five swaps over the last 7,200 blocks;
- all currencies present in the chain tokenlist with a usable canonical Chainlink USD feed.
- Chainlink observations no older than 86,400 seconds.

USD amounts are stored as decimal strings scaled by `1e6`. This avoids floating-point and JSON
integer precision loss. Uniswap V4 liquidity is deliberately stored as a protocol-native scalar:
PoolManager token balances are shared across pools and must not be misrepresented as per-pool TVL.

## Incremental refresh

```bash
cargo run --release --bin pool_indexer -- \
  --global-data data/global_data.json \
  --rpc-url http://127.0.0.1:8545 \
  --update-global-data
```

The default discovery window is 250,000 blocks. Existing records are merged into the candidate set
and remeasured, so an incremental refresh does not discard older pools.

For the initial historical backfill, supply a deployment-era block and enable automatic capability
probing of the `httpRpcs` configured in `global_data.json`:

```bash
cargo run --release --bin pool_indexer -- \
  --global-data data/global_data.json \
  --rpc-url http://127.0.0.1:8545 \
  --from-block 12270000 \
  --auto-history-rpc \
  --history-rpc-count 15 \
  --max-candidates 500 \
  --update-global-data
```

Only endpoints that successfully serve an old canonical-factory log probe are selected. Historical
log chunks run concurrently with per-request failover; endpoint URLs are not copied into artifacts
or diagnostic output. The candidate cap is applied after listed-token filtering and measurement,
ranked by eligibility, liquidity, volume, and swap count—not by pool recency. Expensive volume logs
are fetched only after a candidate clears its protocol-specific liquidity floor. V4 swaps are fetched
once from the singleton manager and grouped by pool ID in memory.

The standalone evidence artifact defaults to `data/pool_index.generated.json`. `global_data.json`
is replaced atomically only when `--update-global-data` is present. Rejected candidates remain in
the output so changes in coverage and rejection causes can be audited between runs.

Use `--skip-discovery` to refresh metrics and regenerate an artifact solely from existing indexed
records. This is useful on pruned nodes; it is not a substitute for the initial archive backfill.
Curve registry enumeration records a conservative creation-block bound when exact deployment-event
proof is unavailable; `creation_block_exact=false` makes that provenance explicit.

## Important limitations

- Curation is not a permanent honeypot guarantee. Atomic round-trip simulation remains mandatory.
- Missing or stale price feeds cause rejection under the default `--require-usd-metrics true` mode.
- A short initial discovery window is not a complete historical backfill.
- V4 records preserve native currency as the zero address for pool identity; pricing maps it to the
  configured wrapped-native asset.
