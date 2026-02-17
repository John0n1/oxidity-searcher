# Oxidity Searcher

Mainnet-first MEV search and execution engine in Rust, designed to run against a locally synced **Ethereum mainnet Nethermind node**.

[![CI](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml/badge.svg)](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml)

`Oxidity Searcher` ingests mempool and MEV-Share flow, decodes router interactions, applies risk/profit gates, simulates execution paths, and submits private bundles through Flashbots-compatible relays.

## Table of Contents

- [Project Scope](#project-scope)
- [Core Capabilities](#core-capabilities)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Runbook](#runbook)
- [Nethermind Compatibility Checks](#nethermind-compatibility-checks)
- [Data Files](#data-files)
- [Database and Migrations](#database-and-migrations)
- [Testing and Quality](#testing-and-quality)
- [Metrics Endpoint](#metrics-endpoint)
- [Security and Safety Guards](#security-and-safety-guards)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Project Scope

This repository is built for production-style opportunity search on **Ethereum mainnet** with tight operational controls:

- strict startup checks for RPC capability and executor deployment health
- protocol-aware decoding/planning for major DEX routers
- multi-backend simulation and fail-fast capability probing
- guarded bundle/tx submission pipeline with configurable risk controls
- replay tooling for historical stress calibration

## Core Capabilities

- Mainnet-first defaults and mainnet-only strict guards.
- Provider stack with deterministic fallback: IPC -> WS -> HTTP.
- Mempool + block streaming + optional Flashbots MEV-Share ingestion.
- Strategy pipeline with slippage, gas, liquidity, and profit/risk constraints.
- Flashloan paths for `Aave v3` and `Balancer`.
- Router allowlist + router discovery checks before execution.
- Chainlink feed selection/audit with per-symbol staleness thresholds.
- Metrics server with token auth and graceful shutdown endpoint.
- Historical replay binary for calibration and strategy stress profiling.

## Architecture

High-level runtime flow:

1. Load config (`config.*` + `.env`) and apply deterministic precedence.
2. Validate wallet key/address consistency.
3. Resolve chain set (or auto-detect from primary HTTP provider).
4. Initialize provider clients and protocol registries.
5. Build engine per chain (strategy, simulation, routing, pricing, metrics).
6. Run ingest/decode/plan/simulate/submit loops with risk gates.
7. Persist results and emit metrics/logs.

Primary modules:

- `src/main.rs`: bootstrap, chain wiring, engine creation
- `src/app/config.rs`: configuration parsing, defaults, and per-chain helpers
- `src/infrastructure/network/provider.rs`: IPC/WS/HTTP connection factory
- `src/infrastructure/network/pricing/price_feed.rs`: Chainlink + external fallback pricing
- `src/services/strategy/execution/engine.rs`: startup checks and execution orchestration
- `src/services/strategy/simulation.rs`: capability probing and simulation backend strategy
- `src/services/strategy/router_discovery.rs`: unknown router discovery and auto-allow validation
- `src/infrastructure/data/db.rs`: SQLite connection and migration path selection

## Repository Layout

- `src/`: application/library code
- `src/bin/historical_replay.rs`: replay harness binary
- `tests/`: integration and compatibility tests
- `data/`: protocol/address/feed/token artifacts
- `migrations/`: squashed baseline migration set
- `migrations_legacy/`: historical migration chain for legacy DB state
- `.github/workflows/ci.yml`: CI checks (`check`, `lint`, `test`)

## Requirements

- Rust stable toolchain
- Linux/macOS runtime environment
- SQLite (embedded through `sqlx`)
- Local Ethereum mainnet node (**Nethermind recommended**)

Recommended Nethermind modules/method families for full feature coverage:

- `Eth`
- `Subscribe`
- `Debug`
- `Trace`
- `TxPool`

## Quick Start

1. Create runtime env:

```bash
cp .env.example .env
```

2. Set required values (minimum mainnet run):

- `WALLET_KEY`
- `WALLET_ADDRESS`
- `CHAINS=1`
- `http_provider_1=http://127.0.0.1:8545`

3. Recommended provider additions:

- `WEBSOCKET_PROVIDER_1=ws://127.0.0.1:8546`
- `IPC_PROVIDER_1=/path/to/nethermind/nethermind.ipc`

4. Dry-run first:

```bash
cargo run --bin oxidity-searcher -- --dry-run
```

5. Run with selected config profile:

```bash
cargo run --bin oxidity-searcher -- --config config.prod.toml
```

## Configuration

Precedence order is:

1. CLI flags
2. Environment (`.env` / process env)
3. Config file (`config*.toml` and active-profile detection)

Provider env key conventions in current code:

- HTTP: `http_provider_<chain_id>`, fallback `http_provider`
- WS: `WEBSOCKET_PROVIDER_<chain_id>`, fallback `WEBSOCKET_PROVIDER`
- WS compatibility aliases: `WEBSOCKET_URL_<chain_id>`, `WEBSOCKET_URL`
- IPC: `IPC_PROVIDER_<chain_id>`, fallback `IPC_PROVIDER`
- IPC compatibility aliases: `IPC_PATH_<chain_id>`, `IPC_PATH`

## Environment Variables

### Required (Mainnet Minimum)

- `WALLET_KEY`: signer private key (hex)
- `WALLET_ADDRESS`: must match address derived from `WALLET_KEY`
- `CHAINS`: set to `1` for Ethereum mainnet
- `http_provider_1`: HTTP RPC endpoint for chain 1

### Strongly Recommended

- `BUNDLE_SIGNER_KEY`: dedicated bundle signer (defaults to `WALLET_KEY`)
- `WEBSOCKET_PROVIDER_1`: WS endpoint for streaming path
- `IPC_PROVIDER_1`: IPC endpoint for preferred low-latency path
- `METRICS_TOKEN`: enables authenticated metrics server

### Optional Runtime Paths and Persistence

- `DATABASE_URL` (default `sqlite://oxidity_searcher.db`)
- `TOKENLIST_PATH` (default `data/tokenlist.json`)
- `ADDRESS_REGISTRY_PATH` (default `data/address_registry.json`)
- `CHAINLINK_FEEDS_PATH` (default `data/chainlink_feeds.json`)

### Optional Relay and Market API Keys

- `FLASHBOTS_RELAY_URL` (default `https://relay.flashbots.net`)
- `MEV_SHARE_STREAM_URL` (default `https://mev-share.flashbots.net`)
- `MEV_SHARE_RELAY_URL` (auto-derived from `MEV_SHARE_STREAM_URL` when unset)
- `ETHERSCAN_API_KEY`
- `BINANCE_API_KEY`
- `COINMARKETCAP_API_KEY`
- `COINGECKO_API_KEY`
- `CRYPTOCOMPARE_API_KEY`
- `COINDESK_API_KEY`

### Optional Ops and Performance

- `METRICS_PORT` (default `9000`)
- `METRICS_BIND` (default `127.0.0.1`)
- `STRATEGY_WORKERS` (default `32`)
- `DEBUG`

### Optional Strategy and Risk Controls

- `STRATEGY_ENABLED`
- `SANDWICH_ATTACKS_ENABLED`
- `MEV_SHARE_ENABLED`
- `MEV_SHARE_HISTORY_LIMIT`
- `SIMULATION_BACKEND`
- `MAX_GAS_PRICE_GWEI`
- `SLIPPAGE_BPS`
- `FLASHLOAN_ENABLED`
- `FLASHLOAN_PROVIDER` (default `auto,aavev3,balancer`)
- `EXECUTOR_ADDRESS`
- `EXECUTOR_BRIBE_BPS`
- `EXECUTOR_BRIBE_RECIPIENT`
- `ALLOW_NON_WRAPPED_SWAPS`
- `GAS_CAP_MULTIPLIER_BPS`
- `PROFIT_GUARD_BASE_FLOOR_MULTIPLIER_BPS`
- `PROFIT_GUARD_COST_MULTIPLIER_BPS`
- `PROFIT_GUARD_MIN_MARGIN_BPS`
- `LIQUIDITY_RATIO_FLOOR_PPM`
- `SELL_MIN_NATIVE_OUT_WEI`
- `SKIP_LOG_EVERY`
- `RECEIPT_POLL_MS`
- `RECEIPT_TIMEOUT_MS`
- `RECEIPT_CONFIRM_BLOCKS`
- `RPC_CAPABILITY_STRICT` (enforced only on mainnet)
- `CHAINLINK_FEED_AUDIT_STRICT`
- `BUNDLE_USE_REPLACEMENT_UUID`
- `BUNDLE_CANCEL_PREVIOUS`
- `ROUTER_DISCOVERY_ENABLED`
- `ROUTER_DISCOVERY_AUTO_ALLOW`
- `ROUTER_DISCOVERY_MIN_HITS`
- `ROUTER_DISCOVERY_FLUSH_EVERY`
- `ROUTER_DISCOVERY_CHECK_INTERVAL_SECS`
- `ROUTER_DISCOVERY_MAX_ENTRIES`
- `EMERGENCY_EXIT_ON_UNKNOWN_RECEIPT`

## Runbook

Main runtime help:

```bash
cargo run --bin oxidity-searcher -- --help
```

Common runtime examples:

```bash
# Dry-run (simulate and log only)
cargo run --bin oxidity-searcher -- --dry-run

# Override slippage for one run
cargo run --bin oxidity-searcher -- --slippage-bps 30

# Disable strategy execution (ingest-only mode)
cargo run --bin oxidity-searcher --no-strategy
```

Historical replay help:

```bash
cargo run --bin historical_replay -- --help
```

Replay example:

```bash
cargo run --bin historical_replay -- \
  --chain-id 1 \
  --lookback-blocks 20000 \
  --window-size 250 \
  --trace-sim \
  --out historical-replay-report.json
```

## Nethermind Compatibility Checks

Targeted integration test for `eth_simulateV1` and `debug_traceCallMany` parameter shapes:

```bash
NETHERMIND_http_provider=http://127.0.0.1:8545 \
  cargo test --test nethermind_rpc_compat -- --nocapture
```

The test suite asserts the endpoint is mainnet (`eth_chainId == 0x1`) and fails on method-missing or invalid-param-shape responses.

## Data Files

- `data/address_registry.json`: known protocol addresses by chain
- `data/tokenlist.json`: token metadata and wrapped/native hints
- `data/chainlink_feeds.json`: Chainlink feed candidates/canonical selection source
- `data/pairs.json`: optional liquidity reserve warmup input
- `data/UnifiedHardenedExecutor.sol`: on-chain executor contract source

## Database and Migrations

Startup migration behavior is automatic:

- if legacy migration history is detected (`_sqlx_migrations` versions before `20260215000000`), run `migrations_legacy/`
- otherwise run squashed baseline `migrations/`

This supports clean bootstrap for new deployments while preserving upgrade safety for legacy databases.

## Testing and Quality

Local quality gate commands (matches CI expectations):

```bash
cargo check --workspace --all-targets --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
```

## Metrics Endpoint

Metrics server starts only when `METRICS_TOKEN` is non-empty.

- bind host: `METRICS_BIND` (default `127.0.0.1`)
- port: `METRICS_PORT` (or `--metrics-port`)
- auth header: `Authorization: Bearer <METRICS_TOKEN>`
- routes:
  - `/` Prometheus text metrics
  - `/health` JSON liveness
  - `/shutdown` graceful cancellation trigger

## Security and Safety Guards

- Wallet integrity check: runtime aborts if `WALLET_ADDRESS` and `WALLET_KEY` mismatch.
- Executor address validation: aborts on configured address with empty code.
- RPC capability probing: simulation methods and parameter-shape compatibility checked at startup.
- Chainlink canonical feed summary logged at startup for operator visibility.
- Chainlink audit behavior:
  - invalid feeds always fail startup
  - stale **critical** feeds (ETH/BTC/USDC/USDT on mainnet) always fail startup
  - non-critical stale feeds fail only when `CHAINLINK_FEED_AUDIT_STRICT=true`
- Router discovery auto-allow is guarded by additional verification (not selector hit count alone).

## Troubleshooting

### `Chainlink feed audit failed (...)`

- Verify node time synchronization and mainnet chain (`chain_id=1`).
- Check canonical feed selection logs and feed addresses in `data/chainlink_feeds.json`.
- Understand strictness semantics:
  - `stale_critical > 0` fails even if `strict=false`
  - `strict=true` additionally fails on non-critical stale feeds

### `rpc_capability_strict=true but ...`

- Ensure Nethermind exposes required debug/simulation methods.
- Run the compatibility test in [Nethermind Compatibility Checks](#nethermind-compatibility-checks).

### `wallet_address ... does not match wallet_key ...`

- Update `WALLET_KEY` or `WALLET_ADDRESS` so they resolve to the same signer address.

### `cargo run` cannot determine which binary to run

Use explicit binary selection:

```bash
cargo run --bin oxidity-searcher -- --help
cargo run --bin historical_replay -- --help
```

## License

MIT. See `LICENSE`.
