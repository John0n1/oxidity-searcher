# oxidity.builder

Rust-based MEV searcher that observes the mempool (plus optional MEV-Share hints), simulates sandwich/backrun bundles, and submits to builders/relays. It keeps lightweight PnL state in SQLite and exposes a small metrics/diagnostics endpoint.

## What it does
- Listens to pending txs and MEV-Share hints, decodes swaps, and plans backruns (with opt-in sandwiches and flashloans).
- Simulates bundles against chain state with configurable backends, then ships signed payloads to builders.
- Tracks balances/PnL locally, sweeps stray inventory, and defends against toxic tokens via simulation probes.
- Exposes metrics/log-level control on a bound address; optional bearer token auth for production.

## Quick start
1) Install Rust stable and SQLite.  
2) Copy a config: `cp config.example.toml config.dev.toml` and set secrets/env (`PRIVATE_KEY`, `RPC_URL`, `METRICS_TOKEN`, etc.).  
3) Run: `cargo run --release -- --config config.dev.toml`.  
4) Metrics: `curl -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:9090/metrics`.

See `docs/setup.md` for detailed bootstrapping and `docs/infrastructure.md` for service layout.

## Configuration highlights
- `CHAINS`: comma-separated chain IDs. Runtime currently processes the first entry per process; run multiple processes for multi-chain.
- `sandwich_attacks_enabled`: toggle sandwich legs for buy-with-ETH flows.
- `simulation_backend`: selects the simulator backend (see docs/infrastructure).
- `profit_receiver_address` / executor bribe fields: set where builder tips flow when using the on-chain executor.
- Metrics binding: defaults to `127.0.0.1`; set `METRICS_BIND=0.0.0.0` only behind a trusted proxy and gate with `METRICS_TOKEN`.

## Project structure (selected)
- `src/services/strategy/strategy.rs`: orchestration and tests; core loops are now split into modules:
  - `bundles.rs` (signing/nonce leasing/merge), `guards.rs` (profit/gas heuristics), `swaps.rs` (quoting/builds),
    `planning.rs` (front/back-run + flashloan planning), `handlers.rs` (mempool/MEV-Share flows), `inventory.rs` (sweeps).
- `src/services/strategy/block_listener.rs`, `mempool.rs`: listeners that feed the strategy channel.
- `docs/`: setup, infra, flashloan notes, and changelog.

## Safety notes
- Keep metrics/log endpoints bound to localhost or a private network and protect with `METRICS_TOKEN`.
- Flashloans require the executor contract and proper approvals; see `docs/flashloan.md`.
- Nonce management uses a leasing bundle state; avoid submitting independent txs from the same key.
- Treat config secrets as sensitive; prefer env vars over committed files.

## Development
- Format/lint/test: `cargo fmt && cargo clippy && cargo test -- --nocapture`.
- Strategy tests live alongside the split modules in `src/services/strategy/strategy.rs` and exercise the helpers.
- More guidance in `docs/dev-helper.md`.
