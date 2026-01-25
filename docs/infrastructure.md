## Infrastructure overview

### High-level data flow
- **Block listener** (`block_listener.rs`): watches new heads and clears the bundle state per block; triggers periodic inventory sweeps.
- **Mempool listener** (`mempool.rs`) and **MEV-Share stream**: push decoded work into the strategy queue.
- **Strategy executor** (`strategy.rs` + modules): decodes swaps, plans front/back runs, simulates bundles, merges/signs them, and ships to builders.
- **Simulation** (`simulation.rs`): pluggable backend to replay bundles with state overrides; used for profit/gas checks and toxicity probes.
- **Gas oracle** (`network/gas.rs`): fetches EIP-1559 fees and applies dynamic boosts based on PnL and victim fees.
- **Nonce manager** (`nonce.rs`): caches per-block base nonces and supports leasing for bundled sequences.
- **Database** (`data/db.rs`): SQLite by default; stores tx history, profit records, and price quotes. Migrations run on startup.
- **Metrics** (`services/metrics.rs`): `/metrics` and `/log-level` endpoints, bound by `metrics_bind`; optional bearer token (`METRICS_TOKEN`).

### Key processes and modules
- **Bundles** (`bundles.rs`): builds access lists, signs EIP-1559 txs, merges multiple plans per block, and handles deferred send to builders.
- **Guards** (`guards.rs`): profit floors, gas/reward ratios, fee boosting rules tied to recent PnL.
- **Swaps** (`swaps.rs`): V2/V3 quoting helpers with a short-lived cache for V3 exactInput paths.
- **Planning** (`planning.rs`): assembles approvals, front/back runs, optional flashloan wrappers, and executor bundles.
- **Inventory** (`inventory.rs`): sweeps non-native balances back to wrapped/native, probes for honeypots, and marks toxic tokens.

### Configuration touchpoints
- `CHAINS`: comma-separated; runtime currently processes the first per process.
- `sandwich_attacks_enabled`: enables front-run legs for buy-with-ETH swaps.
- `simulation_backend`: selects the simulator (see `simulation.rs`).
- `metrics_bind` / `metrics_port` / `METRICS_TOKEN`: network surface for metrics/log control.
- `flashloan_enabled` and executor/bribe settings: required for flashloan paths and executor wrapping.

### Security considerations
- Keep metrics/log endpoints on `127.0.0.1` or behind a proxy; use `METRICS_TOKEN`.
- Avoid sending unrelated txs from the same key; the bundle lease will not account for them.
- Flashloan mode assumes a trusted executor contract and correct approvals.

### State and storage
- Default DB: `sqlite://oxidity_builder.db` in repo root (configurable).
- Token metadata: `data/tokenlist.json`; Chainlink feeds keyed per chain in config.
- Quote cache: in-memory V3 cache with short TTL (see `swaps.rs`).
