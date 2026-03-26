# Oxidity Searcher

[![CI](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml/badge.svg)](https://github.com/John0n1/oxidity-searcher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/John0n1/oxidity-searcher/blob/master/LICENSE)
[![Rust 2024 Edition](https://img.shields.io/badge/Rustc)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

Oxidity Searcher is an async Rust MEV searcher focused on Ethereum mainnet-style execution flows. The project combines on-chain data ingestion, router-aware decoding, route planning, risk gating, simulation, bundle construction, and execution against Flashbots / MEV-Share style relays.

This README is written for developers who need to understand how the codebase is structured, how the runtime is assembled, and where to make changes safely.

## Repository layout

```text
.
├── Cargo.toml                  # Rust package manifest and dependency graph
├── src/
│   ├── main.rs                 # Binary entrypoint; wires config, data, network, and engine
│   ├── lib.rs                  # Library exports and stable module aliases used in tests
│   ├── app/                    # Configuration loading and logging bootstrap
│   ├── bin/
│   │   ├── historical_replay.rs        # Historical block-window replay harness
│   │   └── router_discovery_review.rs  # Router discovery review/approval utility
│   ├── common/                 # Small reusable utilities (retry, parsing, data-path resolution)
│   ├── domain/                 # Errors, constants, protocol/static metadata
│   ├── infrastructure/
│   │   ├── data/               # Database, ABI wrappers, token/address registry, executor encoding
│   │   └── network/            # Providers, gas, nonce, pricing, liquidity, MEV-Share ingress
│   └── services/
│       └── strategy/           # Ingest → planning → risk → simulation → execution pipeline
├── tests/                      # Integration tests and repository guardrails
├── migrations/                 # SQLite schema migrations
├── data/                       # Static data and Solidity artifacts used at runtime / in tests
└── foundry.toml                # Foundry configuration for Solidity-side validation
```

## Key technologies

- **Rust 2024 edition** for the application and test suite.
- **Tokio** for async runtime, cancellation, timers, and concurrency primitives.
- **Alloy** for Ethereum providers, primitives, transaction types, signing, and contract encoding.
- **SQLx + SQLite** for local persistence and migration management.
- **Reqwest** for HTTP-based provider and relay communication.
- **Axum** for HTTP-facing service surfaces exposed by the binary.
- **Tracing** and `tracing-subscriber` for structured logs.
- **Foundry** for Solidity contract testing / compilation settings.

## High-level execution model

The runtime is assembled in `src/main.rs`:

1. Parse CLI flags via `clap`.
2. Load layered configuration through `GlobalSettings::load_with_report`.
3. Bootstrap tracing/logging.
4. Open the SQLite database and validate configured identities.
5. Create provider connections and chain-scoped network services.
6. Load static data sources such as token lists, address registries, and Chainlink feeds.
7. Construct stateful services:
   - `GasOracle`
   - `NonceManager`
   - `PriceFeed`
   - liquidity reserve trackers
   - `PortfolioManager`
   - `RouterDiscovery`
   - `Simulator`
   - execution engine / strategy runtime
8. Start ingest paths (mempool, blocks, MEV-Share) and submit work into the shared queue.
9. Execute planning + simulation + bundle submission pipelines until shutdown.

The central design choice is **layered orchestration** rather than a framework-heavy application skeleton. Most types are directly composed in `main.rs`, while behavior lives in modules below `services::strategy` and `infrastructure::*`.

## Module-by-module guide

### `src/app`

- `config.rs`
  - Defines `GlobalSettings` and configuration-resolution helpers.
  - Merges file config, environment overrides, default values, and redacted config reporting.
  - Contains a large amount of operational policy and normalization logic, especially around providers, feed loading, and strategy knobs.
- `logging.rs`
  - Centralizes tracing setup and terminal/table formatting helpers.

### `src/common`

Small, cross-cutting utilities:

- `data_path.rs`: resolves runtime-relative and configured paths into absolute file locations.
- `global_data.rs`: shared helpers for loading JSON data from disk.
- `parsing.rs`: hex, address, and boolean parsing helpers used by multiple layers.
- `retry.rs`: async retry primitive with exponential backoff.
- `seen_cache.rs`: bounded dedup bookkeeping for streaming/ingest paths.

### `src/domain`

Core domain definitions:

- `constants.rs`: protocol constants, address maps, router metadata, symbol defaults, and similar static knowledge.
- `error.rs`: application-wide `AppError` variants and conversions.

### `src/infrastructure/data`

Persistence and artifact handling:

- `db.rs`: SQLx-backed persistence and analytics helpers.
- `address_registry.rs`: registry validation / loading for known addresses.
- `token_manager.rs`: token metadata / token list loading and merge behavior.
- `executor.rs`, `abi.rs`: contract call encoding, ABI access, and execution payload helpers.

### `src/infrastructure/network`

External network integration:

- `provider.rs`: provider factory for HTTP / WS / IPC endpoints.
- `gas.rs`: gas oracle logic and fee history retrieval.
- `nonce.rs`: on-chain nonce tracking with retry protection.
- `mev_share.rs`: MEV-Share polling + SSE ingestion and hint normalization.
- `pricing/price_feed.rs`: external pricing adapters and Chainlink/market data selection.
- `liquidity/reserves.rs`: reserve and pair loading / quote support.
- `ingest/{block_listener,mempool}.rs`: live block and mempool subscriptions.

### `src/services/strategy`

This is the core searcher pipeline:

- `ingest/`
  - `decode.rs`: decodes router calldata, nested multicalls, and protocol-specific shapes.
  - `handlers.rs`: converts decoded opportunities into executable planning input and handles adaptive retries / simulation attribution.
- `planning/`
  - route and quote discovery, bundle composition, swap shaping, graph search, and deterministic plan selection.
- `risk/`
  - dynamic profit floor logic, safety trip mechanisms, replay/cooldown constraints, and policy utilities.
- `simulation/`
  - simulation backend configuration, revert decoding, and pre-execution validation.
- `execution/`
  - engine loop, relay submission, nonce leasing, queue draining, and receipt handling.
- `state/`
  - inventory and portfolio state derived from RPC calls and execution outcomes.
- `router_discovery.rs`
  - learns candidate routers and maintains discovery/risk metadata.
- `routers.rs`
  - router ABI details, selector registries, and canonical address utilities.

## Data and state surfaces

### Static data

The `data/` directory contains runtime artifacts such as:

- `global_data.json`
- executor Solidity source / ABI material
- token / address metadata consumed during startup

Static data path resolution is mediated through `src/common/data_path.rs`, which lets config values point to relative or explicit locations.

### Database

SQLite is the default persistence backend:

- default example URL: `sqlite://oxidity_searcher.db`
- migrations live in `migrations/`
- migration hygiene is enforced by `tests/migration_lint.rs`

### Environment contract

The repository ships `.env.example`, which documents the baseline runtime contract:

- wallet keys and derived wallet address
- HTTP / WebSocket / IPC providers
- relay endpoints
- pricing API keys
- metrics and operational endpoints
- strategy/risk controls
- flashloan and router discovery configuration

In practice, configuration can come from files and environment variables, but `.env.example` is the fastest way to understand the expected operational surface.

## Development workflow

### Prerequisites

- Rust toolchain compatible with this crate
- system packages used in CI: `pkg-config`, `libssl-dev`
- optional: Foundry (`forge`) for Solidity-side tests

### Common commands

These are taken directly from `.github/workflows/ci.yml`:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --locked
cargo test --workspace --locked --all-targets --all-features
forge test
cargo audit --ignore RUSTSEC-2023-0071
```

### What the tests cover

- `tests/config_guard.rs`: configuration contract regression checks
- `tests/flashloan_build.rs`: flashloan bundle construction
- `tests/mev_share_pipeline.rs` and `tests/pipeline_mev_share_v3.rs`: MEV-Share pipeline behavior
- `tests/nethermind_rpc_compat.rs`: provider compatibility assumptions
- `tests/migration_lint.rs`: schema/migration duplication guard
- inline module tests across `src/`: unit-level logic for parsing, planning, execution, simulation, and risk behavior

## Architectural characteristics

### 1. Strong emphasis on deterministic behavior

Several tests explicitly check deterministic plan ordering, stable normalization, duplicate handling, and selector uniqueness. This indicates the codebase prefers predictable execution over opportunistic nondeterminism.

### 2. Configuration-driven runtime

The codebase is highly configurable. The biggest concentration of runtime policy is `src/app/config.rs`, which means configuration changes can materially affect execution semantics without touching the execution engine itself.

### 3. Router-aware decoding and planning

The searcher is not a generic transaction sniffer; it carries explicit protocol/router knowledge. `decode.rs`, `routers.rs`, and `router_discovery.rs` work together to classify and evaluate routers before execution planning proceeds.

### 4. Pre-execution risk and simulation gates

The code is organized so that decoded opportunities are not sent directly to execution. They pass through:

1. planning
2. profitability/risk checks
3. simulation
4. bundle shaping / relay submission

That sequencing is important when making changes: most “opportunity accepted/rejected” behavior will span multiple modules rather than live in one place.

## Practical navigation tips

If you are changing…

- **configuration behavior**: start in `src/app/config.rs`
- **provider selection or RPC behavior**: start in `src/infrastructure/network/provider.rs`
- **MEV-Share streaming/history behavior**: start in `src/infrastructure/network/mev_share.rs`
- **router decoding bugs**: start in `src/services/strategy/ingest/decode.rs`
- **bundle construction or relay payload logic**: start in `src/services/strategy/execution/executor.rs` and `planning/bundles.rs`
- **risk thresholds / profitability checks**: start in `src/services/strategy/risk/guards.rs`
- **database or persistence issues**: start in `src/infrastructure/data/db.rs`

## Notes from current repository inspection

- The repository currently has strong inline/integration test coverage for many core behaviors.
- `src/app/config.rs` is the densest file in the codebase and the main concentration of configuration policy.
- CI expects both Rust-side and Foundry-side validation.
- `Cargo.toml` references this README through the `readme = "README.md"` field, so keeping this file present is part of packaging hygiene.

## Recent maintenance improvement

This repository now correctly honors the two most common representations of the HTTP `Retry-After` header in the MEV-Share client:

- delta-seconds (`Retry-After: 120`)
- HTTP-date in RFC 1123 / IMF-fixdate form only (for example, `Retry-After: Wed, 26 Mar 2026 11:00:45 GMT`)

Note: obsolete HTTP-date forms (such as RFC 850 or `asctime`-style dates) are not currently parsed. Relays using either supported representation will still have their requested backoff respected, which helps avoid unnecessary reconnect churn.
