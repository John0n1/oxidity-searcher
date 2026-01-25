## Setup

### Prerequisites
- Rust toolchain (stable) with `cargo`.
- SQLite (for the default local DB path).
- An Ethereum RPC endpoint with mempool access and a funded private key.

### Configure
1) Copy a sample config:
   ```
   cp config.example.toml config.dev.toml
   ```
2) Set secrets via environment variables (recommended) or the config file:
   - `PRIVATE_KEY` (hex, 0x-prefixed)
   - `RPC_URL`
   - `METRICS_TOKEN` (if exposing metrics/log-level)
   - `CHAINLINK_RPC_URL`, `MEV_SHARE_URL` as needed
3) Multi-chain: `CHAINS` accepts comma-separated IDs, but each process currently handles the first entry. Run separate processes per chain if needed.
4) Optional toggles:
   - `sandwich_attacks_enabled = true` to allow front-runs on buy-with-ETH flows.
   - `simulation_backend` selects the simulation provider.
   - `metrics_bind` defaults to `127.0.0.1`; only expose `0.0.0.0` behind a trusted proxy.

### Run
```
cargo run --release -- --config config.dev.toml
```
Migrations run automatically on startup. Logs default to info; adjust with `RUST_LOG=debug` or hit the `/log-level` endpoint (see README).

### Observability
- Metrics endpoint: `http://127.0.0.1:<metrics_port>/metrics` with optional bearer token.
- Health/log-level: `http://127.0.0.1:<metrics_port>/log-level` (GET/POST).
- Database: defaults to `sqlite://oxidity_builder.db` in the repo root.

### Common pitfalls
- Nonce conflicts: avoid sending unrelated transactions from the same key; the strategy leases nonces internally.
- MEV-Share: ensure `MEV_SHARE_URL` is set if enabling hints.
- Flashloans: require a deployed executor and correct router approvals; see `docs/flashloan.md`.
