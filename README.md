# Oxidity Searcher

Mainnet-first MEV search and execution engine in Rust, designed to run against a locally synced **Ethereum mainnet RPC node** (Nethermind shown as the reference profile; Geth/Reth are also supported when capabilities match).

[![CI](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml/badge.svg)](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/language-rust-orange?logo=rust\&style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

`Oxidity Searcher` ingests mempool and MEV-Share flow, decodes router interactions, applies risk/profit gates, simulates execution paths, and submits private bundles through Flashbots-compatible relays.

## Table of Contents

- [Project Scope](#project-scope)
- [What This Project Is](#what-this-project-is)
- [Why This Design Is Distinct](#why-this-design-is-distinct)
- [How A Decision Is Made](#how-a-decision-is-made)
- [Core Capabilities](#core-capabilities)
- [Architecture](#architecture)
- [Flashloan and Executor Flow](#flashloan-and-executor-flow)
- [Router Coverage and Discovery](#router-coverage-and-discovery)
- [Global Data JSON](#global-data-json)
- [Pricing, Chainlink, and Optional APIs](#pricing-chainlink-and-optional-apis)
- [Flashbots and Relay Submission](#flashbots-and-relay-submission)
- [Simulation and RPC Client Compatibility](#simulation-and-rpc-client-compatibility)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Runbook](#runbook)
- [RPC Conformance Checks (Nethermind Example)](#rpc-conformance-checks-nethermind-example)
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

## What This Project Is

`Oxidity Searcher` is a deterministic execution system for on-chain opportunities.
It is not a price-prediction model and not a discretionary trading dashboard.

The implementation emphasizes:

- deterministic startup checks before execution is enabled
- explicit runtime contracts (`OXIDITY_*` identity keys + typed config)
- observable decision paths (why an opportunity executed or was skipped)
- bounded behavior under stress (queue limits, RPC budgets, cooldowns)

## Why This Design Is Distinct

The runtime is organized for operational predictability rather than convenience-first defaults:

- **Node-first architecture**: optimized for a local mainnet RPC node, with Nethermind used as the reference profile and equivalent capability checks for other clients.
- **Strict capability gating**: simulation/tracing method shapes are verified before strategy loops start.
- **Single canonical data artifact**: `data/global_data.json` is the source for token/address/feed/pair metadata.
- **Policy-driven planning**: decode, plan, simulate, score, then execute; each stage has explicit checks.
- **Constrained discovery**: router discovery is budgeted (RPC cap, timeout, cooldown) to prevent unbounded scans.
- **Operational visibility**: logs/metrics prioritize attribution (fallback reason, rejection reason, relay status, queue pressure).

## How A Decision Is Made

Per opportunity, the runtime follows a consistent lifecycle:

1. Ingest:
   mempool txs and optional MEV-Share hints are queued with bounded capacity.
2. Decode:
   calldata is classified by router/protocol path; non-actionable payloads are skipped with counters.
3. Plan:
   candidate routes and sizes are built from reserve/liquidity state.
4. Simulate:
   candidates are simulated using configured backend(s), with failure attribution where possible.
5. Score and gate:
   profitability and safety checks are applied (gas, slippage, liquidity, router quality, policy floors).
6. Execute:
   accepted plans are signed and submitted through configured private relay paths.
7. Persist and observe:
   outcomes, pnl components, and decision metrics are recorded for monitoring and replay.

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
- `src/infrastructure/data/db.rs`: SQLite connection and migration bootstrap

## Flashloan and Executor Flow

Flashloan-capable execution is built around the on-chain `UnifiedHardenedExecutor` contract and off-chain planner decisions:

- Contract source: `data/UnifiedHardenedExecutor.sol`
- ABI surface mirrored in Rust: `src/infrastructure/data/executor.rs`
- Runtime contract address source: `OXIDITY_FLASHLOAN_CONTRACT_ADDRESS`

Execution modes:

- `executeBundle(...)` for direct multicall bundle execution (owner-gated)
- `executeFlashLoan(...)` for Balancer flashloan callbacks
- `executeAaveFlashLoanSimple(...)` for Aave v3 simple flashloan callbacks

Planner integration (own-capital vs flashloan vs hybrid):

- `ExecutionPlanner` scores candidate families per opportunity (`own_capital`, `flashloan`, `hybrid`)
- Candidate score uses expected-value terms (`expected_net`, inclusion probability, dynamic floor, failure cost)
- Rejections are explicit and reason-coded (`net_negative_after_buffers` and normalized categories)
- In ingest, chosen plan type controls whether the backrun path uses flashloan callbacks or wallet-funded tx value

Operational guarantees:

- Flashloan path is never enabled without a deployed executor contract code check
- Provider viability checks ensure Aave/Balancer addresses are present and usable before execution
- Planner decision traces are recorded per opportunity for post-run attribution

## Router Coverage and Discovery

Router knowledge comes from two sources:

- Static allowlist from `global_data.json -> address_registry.chains.<chain_id>.routers`
- Dynamic discovery for unknown routers (`src/services/strategy/router_discovery.rs`)

Static classification:

- Router names are categorized into `routers`, `wrappers`, and `infra`
- Categories are used for decode metrics and allowlist hygiene
- On startup, allowlist entries are validated on-chain and no-code entries are dropped

Discovery behavior:

- Unknown routers are tracked with bounded state (`max_entries`, eviction of stale low-signal entries)
- Auto-allow requires hit thresholds plus classification checks (ABI selector behavior + bytecode signals), not hit count alone
- Budget guards prevent unbounded scans:
  - max blocks per cycle
  - max RPC calls per cycle
  - wall-clock timeout
  - failure budget with cooldown
- Approved discoveries are persisted to cache (`data/router_discovery_cache.json` by default) and reloaded on boot

## Global Data JSON

`data/global_data.json` is the canonical runtime artifact. Current top-level sections:

- `_notes`
- `address_registry`
- `chainlink_feeds`
- `executor_abi`
- `pairs`
- `tokenlist`
- `version`

How each section is used:

- `address_registry`: per-chain routers and protocol addresses (Balancer vault, Aave pool/provider, Curve registries, chain-local feed overrides)
- `tokenlist`: token symbol/decimals/tags plus per-chain addresses; consumed by `TokenManager` for decimal-aware execution logic
- `pairs`: preloaded V2-style pair address/token mapping used to warm reserve cache paths
- `chainlink_feeds`: global feed catalog consumed by config loader to resolve per-chain canonical feed selections
- `executor_abi`: ABI payload used to keep off-chain encoding aligned with deployed executor contract behavior

Current snapshot size (repository state now):

- `tokenlist`: 685 entries
- `pairs`: 476 entries
- `executor_abi`: 43 ABI items

Chain 1 address registry includes major routers and infra (examples): Uniswap V2/V3/Universal, 1inch variants, ParaSwap, Kyber, 0x, Relay routers, Balancer vault, Aave pool, and discovered router entries.

## Pricing, Chainlink, and Optional APIs

Pricing is Chainlink-first, with staged external fallback when needed (`src/infrastructure/network/pricing/price_feed.rs`).

Primary behavior:

- Load canonical feed set per chain from config + `global_data.json`
- Audit feeds at startup (invalid/stale rules, stricter handling for critical mainnet symbols)
- Query Chainlink on-chain first for live pricing

Fallback order when Chainlink cannot provide a quote:

1. Etherscan v2 (`module=stats`, `action=ethprice`) for ETH/USD only
2. Binance
3. OKX
4. CoinMarketCap
5. CoinGecko
6. CryptoCompare
7. CoinPaprika
8. CryptoCompare public BTC fallback

Notes:

- Optional API keys (`ETHERSCAN_API_KEY`, `COINGECKO_API_KEY`, etc.) improve coverage but are not required for startup
- Missing/invalid fallback keys are non-fatal; provider failures fall through to the next source
- Provider runtime outcomes track attempts/success/failure, `NOTOK` responses, latency, and quote age for diagnostics
- Stale-cache grace allows temporary degraded operation instead of hard failure when upstreams are unstable

## Flashbots and Relay Submission

Bundle submission path is implemented in `src/services/strategy/execution/executor.rs` (`BundleSender`).

Mainnet path:

- Uses `eth_sendBundle` across multiple builders/relays (Flashbots + additional builders)
- Supports replacement UUID workflow and optional `eth_cancelBundle` of previous target-block submissions
- Records relay attempt/retry/timeout/status metrics per relay

MEV-Share path:

- Uses `mev_sendBundle` with exactly one victim hash + one backrun tx leg
- Builder set is canonicalized against Flashbots builder registration data when available

Non-mainnet path:

- Falls back to direct raw transaction broadcast

Dry-run mode:

- Builds payloads and records decision/attempt telemetry but does not submit to relays

## Simulation and RPC Client Compatibility

Simulation backend order is configurable and probed at runtime (`src/services/strategy/simulation.rs`):

- `eth_simulateV1`
- `debug_traceCall` / `debug_traceCallMany`
- `eth_call` fallback

Startup capability probing checks:

- method availability
- parameter-shape conformance for `eth_simulateV1` and `debug_traceCallMany`
- `eth_feeHistory` availability for gas oracle quality

Client compatibility model:

- Nethermind is the reference profile used in examples
- Geth/Reth/other clients can run if required methods are available and shape-compatible
- The runtime does not hardcode one client implementation; it gates behavior by capability probes

Strict mode:

- `RPC_CAPABILITY_STRICT=true` enforces required simulation capability and shape checks
- If strict mode is disabled, runtime can degrade to available methods with explicit warnings

Important limitation:

- `eth_call` is treated as unsafe for multi-transaction bundle simulation and does not replace true stateful bundle simulation semantics

## Repository Layout

- `src/`: application/library code
- `src/bin/historical_replay.rs`: replay harness binary
- `tests/`: integration and conformance tests
- `data/`: protocol/address/feed/token artifacts
- `migrations/`: squashed baseline migration set
- `.github/workflows/ci.yml`: CI checks (`check`, `lint`, `test`)

## Requirements

- Rust stable toolchain
  - install: `curl https://sh.rustup.rs -sSf | sh` then `rustup default stable`
- Linux/macOS runtime environment
- SQLite (embedded through `sqlx`)
- Local Ethereum mainnet node (**Nethermind/Geth/Reth supported; Nethermind used as reference in examples**)

Recommended RPC modules/method families for full feature coverage (Nethermind naming shown):

- `Admin`
- `Eth`
- `Subscribe`
- `Debug`
- `Trace`
- `TxPool`
- `Web3`
- `Rpc`

## Quick Start

1. Create runtime env:

```bash
cp .env.example .env
```

2. Set required values (minimum mainnet run):

- `OXIDITY_WALLET_PRIVATE_KEY`
- `OXIDITY_WALLET_ADDRESS`
- `OXIDITY_FLASHLOAN_CONTRACT_ADDRESS`
- `OXIDITY_BUNDLE_PRIVATE_KEY`
- `CHAINS=1`
- `HTTP_PROVIDER_1=http://127.0.0.1:8545`

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

- HTTP: `HTTP_PROVIDER_<chain_id>`, fallback `HTTP_PROVIDER`
- WS: `WEBSOCKET_PROVIDER_<chain_id>`, fallback `WEBSOCKET_PROVIDER`
- IPC: `IPC_PROVIDER_<chain_id>`, fallback `IPC_PROVIDER`

## Environment Variables

### Required (Mainnet Minimum)

- `OXIDITY_WALLET_PRIVATE_KEY`: signer private key (hex)
- `OXIDITY_WALLET_ADDRESS`: must match address derived from `OXIDITY_WALLET_PRIVATE_KEY`
- `OXIDITY_FLASHLOAN_CONTRACT_ADDRESS`: on-chain executor/flashloan contract
- `OXIDITY_BUNDLE_PRIVATE_KEY`: dedicated bundle signer key
- `CHAINS`: set to `1` for Ethereum mainnet
- `HTTP_PROVIDER_1`: HTTP RPC endpoint for chain 1

### Strongly Recommended

- `OXIDITY_LOG_LEVEL`: logging level (default `info`)
- `WEBSOCKET_PROVIDER_1`: WS endpoint for streaming path
- `IPC_PROVIDER_1`: IPC endpoint for preferred low-latency path
- `METRICS_TOKEN`: enables authenticated metrics server

### Optional Runtime Paths and Persistence

- `DATABASE_URL` (default `sqlite://oxidity_searcher.db`)
- `GLOBAL_PATHS_PATH` (default `data/global_paths.json`)
- `GLOBAL_DATA_PATH` (default `data/global_data.json`)

### Optional Relay and Market API Keys

- `FLASHBOTS_RELAY_URL` (default `https://relay.flashbots.net`)
- `MEV_SHARE_STREAM_URL` (default `https://mev-share.flashbots.net`)
- `MEV_SHARE_RELAY_URL` (auto-derived from `MEV_SHARE_STREAM_URL` when unset)
- `ETHERSCAN_API_KEY`
- `BINANCE_API_KEY`
- `COINMARKETCAP_API_KEY`
- `COINGECKO_API_KEY`
- `CRYPTOCOMPARE_API_KEY`

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
- `OXIDITY_FLASHLOAN_CONTRACT_ADDRESS`
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

## RPC Conformance Checks (Nethermind Example)

Targeted integration test for `eth_simulateV1` and `debug_traceCallMany` parameter shapes.
The test command below uses a Nethermind-named env variable, but the endpoint can be Nethermind, Geth, Reth, or another client:

```bash
NETHERMIND_HTTP_PROVIDER=http://127.0.0.1:8545 \
  cargo test --test nethermind_rpc_compat -- --nocapture
```

The test suite asserts the endpoint is mainnet (`eth_chainId == 0x1`) and fails on method-missing or invalid-param-shape responses.

## Data Files

- `data/global_data.json`: single canonical data source for address registry, token list, Chainlink feeds, pairs, and executor ABI
- `GLOBAL_DATA_PATH`: optional override when running with an external global data artifact
- `data/UnifiedHardenedExecutor.sol`: on-chain executor contract source
- `data/global_data.json` includes `_notes` with inline section descriptions for maintainers

## Database and Migrations

Startup migration behavior is automatic:

- run squashed baseline `migrations/`

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

- Wallet integrity check: runtime aborts if `OXIDITY_WALLET_ADDRESS` and `OXIDITY_WALLET_PRIVATE_KEY` mismatch.
- Executor address validation: aborts on configured address with empty code.
- RPC capability probing: simulation methods and parameter-shape conformance checked at startup.
- Chainlink canonical feed summary logged at startup for operator visibility.
- Chainlink audit behavior:
  - invalid feeds always fail startup
  - stale **critical** feeds (ETH/BTC/USDC/USDT on mainnet) always fail startup
  - non-critical stale feeds fail only when `CHAINLINK_FEED_AUDIT_STRICT=true`
- Router discovery auto-allow is guarded by additional verification (not selector hit count alone).

## Troubleshooting

### `Chainlink feed audit failed (...)`

- Verify node time synchronization and mainnet chain (`chain_id=1`).
- Check canonical feed selection logs and feed addresses in `data/global_data.json` under `chainlink_feeds`.
- Understand strictness semantics:
  - `stale_critical > 0` fails even if `strict=false`
  - `strict=true` additionally fails on non-critical stale feeds

### `rpc_capability_strict=true but ...`

- Ensure your RPC client exposes required debug/simulation methods.
- Run the conformance test in [RPC Conformance Checks (Nethermind Example)](#rpc-conformance-checks-nethermind-example).

### `wallet_address ... does not match wallet private key ...`

- Update `OXIDITY_WALLET_PRIVATE_KEY` or `OXIDITY_WALLET_ADDRESS` so they resolve to the same signer address.

### `cargo run` cannot determine which binary to run

Use explicit binary selection:

```bash
cargo run --bin oxidity-searcher -- --help
cargo run --bin historical_replay -- --help
```

## License

MIT. See `LICENSE`.
