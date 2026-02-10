## Oxidity Searcher

***Low-latency MEV searcher that scans mempools plus Flashbots MEV-Share hints, simulates sandwich/backrun bundles, and submits to builders/relays with safety, observability, and restart resilience.***


![Codecov](https://img.shields.io/codecov/c/github/John0n1/oxidity.searcher)
[![Rust](https://img.shields.io/badge/rust-1.94.0-orange?logo=rust&color=orange\&style=flat-square)](https://www.rust-lang.org/)

## Constraints

- Single-operator
- Rust
- SQLite state
- Optional flash-loan executor
- Per-chain configurable
- Designed for mainnet first
- Compatible with EVM L2s where RPC supports required methods

---

## 2. System Architecture

### Layers

- **App:** config loading, logging bootstrap, CLI overrides.
- **Common/Domain:** constants (routers, feeds, wrapped assets), error types, retry helpers.
- **Infrastructure:** RPC/WS/IPC providers (Alloy), gas oracle, price feeds, MEV-Share client, mempool/block ingest, reserve cache (UniV2), ABI registry, DB access.
- **Services/Strategy:** ingest decoding, risk & safety, planning (front/backrun, flash-loan wrapping), execution engine, simulation, metrics, portfolio tracking.

### Runtime composition (per chain)

- **Providers:** IPC > WS > HTTP preference.
- **Workers:** bounded ingest channel (2048), worker semaphore sized by `STRATEGY_WORKERS`.
- **Persistence:** SQLite migrations for transactions, profit, market prices, `nonce_state`.

---

## 3. Data Flow

- **Ingest:** WS pending tx subscription; MEV-Share SSE (with `Accept` header + `Retry-After` respect); dedup via DashSet with LRU order.
- **Block stream:** WS `newHeads` with fallback polling; updates nonce baseline.
- **Strategy path:** decode swap → validate router/amount/native presence → risk checks → build components → lease nonces → simulate bundle with state overrides → profit/gas guards → sign & merge → deferred send.
- **Persistence:** transactions, profit (ETH + integer wei fields), market price snapshots; `nonce_state` for restart-safe nonces and pool conflicts.

---

## 4. Key Algorithms & Math

- **UniV2 quoting:** standard 0.3% fee  
  `amountOut = amountIn*997*Rout / (Rin*1000 + amountIn*997)`
- **Gas costing:** profit scoring uses `gas_used * max(base_fee, next_base_fee) + tip`.
- **Dynamic backrun size:** derived from victim input & slippage; capped by wallet divisors and gas buffer; minimum `0.0001 ETH`.
- **Profit floor:** `max(0.00002 ETH, balance / 100000)`; gas ratio guard scales with PnL and balance.
- **Flash-loan path:** Balancer-style callback via `UnifiedHardenedExecutor`; approvals are scoped and zeroed post-loop.

---

## 5. Safety & Risk Controls

- Circuit breaker after consecutive failures with auto-reset window.
- Nonce leasing + persistence prevents reuse across restarts; pool-level conflict detection in bundle merge.
- Toxic token detection: simulation probes for V2/V3 sells; marks tokens to skip.
- Approval hygiene: flash-loan callbacks include approve→reset; non-flash runs keep approvals scoped to router; optional future tightening suggested.
- Gas cap per chain; skip on price caps or thin margins.

---

## 6. Connectivity & Fallbacks

- **GasOracle:** `feeHistory` primary; fallback to Etherscan gasoracle when RPC blocks; last-resort node basefee + `maxPriorityFeePerGas`.
- **PriceFeed:** Chainlink preferred, then Etherscan ethprice (ETH only), then Binance ticker; stale-cache grace on failures; Chainlink staleness flagged.
- **Providers:** IPC prioritized; WS streaming; HTTP fallback; mempool filter polling when pending subscription fails.
- **MEV-Share:** SSE client with seen-set, history backfill, rate-aware reconnect.

---

## 7. Strategy Construction

- **Sandwich (optional):** front-run for buy-with-ETH paths; amount sizing uses dynamic backrun value; optional approval.
- **Backrun:** V2/V3 aware; can wrap in executor or flash-loan; supports unwrap-to-native when profitable.
- **Executor wrapper:** bundles approvals + swap + optional unwrap + bribe; bribe bps configurable/recipient override.
- **Bundle merge:** nonces within lease, touched pools disjoint, debounce send; mempool path can merge multi-leg bundles, while MEV-Share path is constrained to one victim hash + one backrun tx.

---

## 8. Simulation

- Uses Alloy simulate bundle with state overrides locking balance/nonce; falls back to `estimate_gas` + `eth_call` if simulate unavailable.
- Decodes executor custom errors for diagnostics.

---

## 9. Persistence & Accounting

- **Tables:** `transactions`, `profit_records` (float + wei text), `market_prices`, `nonce_state`.
- PnL tracked as signed wei in `PortfolioManager`; token profits map.
- Migration added for integer precision fields: `20260128000000_profit_precision.sql`.

---

## 10. Metrics & Observability

- TCP mini-server with bearer auth; Prometheus-style text metrics endpoint.
- Counters for ingest, skips, nonce persistence, sim latency (by source), queue backpressure.
- Bundle history ring buffer.

---

## 11. Configuration

- `config.toml` / `.dev`: wallet/bundle signer, routers per chain, Chainlink feeds, RPC/WS/IPC maps, slippage/gas caps (set to `0` for auto-tuned), flash-loan toggle, sandwich toggle, MEV-Share enable/URL/history limit, metrics bind/token, executor address/bribe, and `address_registry_path`.
- Env overrides:
  - `ETHERSCAN_API_KEY`
  - `RPC_URL_n` / `WS_URL_n`
  - `CHAINLINK_FEEDS_PATH`
  - `TOKENLIST_PATH`
  - `STRATEGY_WORKERS`
  - `METRICS_*`

---

## 12. Operational Runbook

- **Start:** `oxidity_builder.db METRICS_TOKEN=… cargo run --release`.
- **Monitor:** metrics endpoint `/` (bearer); watch `nonce_state` counters and ingest queue depth.
- **Health:** metrics endpoint `/health` returns liveness + chain id for control-plane integrations.
- **Restart safety:** `nonce_state` persists `next_nonce`/`touched_pools` per block; engine reloads on boot.
- **Backpressure:** ingest queue bounded; drops counted; adjust `STRATEGY_WORKERS` and RPC rate limits accordingly.

---

## 13. Builder/Relay Submission

- **Mainnet:** `eth_sendBundle` to Flashbots primary, Beaver (unsigned), Titan (signed optional); MEV-Share path uses `mev_sendBundle` with exactly one victim hash + one backrun tx.
- **Non-mainnet:** direct `eth_sendRawTransaction` per tx.
- **Limits:** Flashbots bundle limits enforced at `<=100` txs and `<=300000` bytes.

---

## Windows Installer (Preview)

- Build installer: `.\scripts\build-installer.ps1`
- Installer script: `installer/oxidity_installer.iss`
- Setup wizard writes `{app}\config.prod.toml` with required runtime fields.

---

## 14. Extensibility

- Add new routers/feeds via constants or config maps.
- ABI registry supports directory load; future: remote ABI fetch via Etherscan `getabi`.
- Token metadata via tokenlist; empty defaults allowed.

---

## 15. Security Considerations

- Secrets must not live in tracked configs; use env for keys.
- Keep metrics bind to loopback or front with TLS/ACL.
- Validate executor address and flash-loan permissions before mainnet.
- Rate-limit external APIs; honor `Retry-After` (already implemented for MEV-Share).

---

## 16. Performance Notes

- IPC yields lowest latency; WS fallback; retry with exponential backoff for `feeHistory` and simulations.
- V3 quote cache TTL 250 ms to avoid repeated quoter calls; reserve cache for V2 keeps last `Sync` log state and does on-demand pair lookups bounded by semaphore.

---

## 17. Testing

- Unit tests cover retry, config parsing, nonce leasing, fee math, decoding, simulation guards, flash-loan encoding, MEV-Share pipeline.
- Integration-ish:
  - `flashloan_build`
  - `mev_share_pipeline`
  - `pipeline_mev_share_v3` (ignored; requires live dev node)

---

## 18. Roadmap (Short)

- Postgres optional backend for HA + shared state across instances.
- Adaptive MEV-Share builder list and relay health probing.
- Structured logging to disk + OpenTelemetry export.
- Sandbox approvals tightening for non-executor paths.
- Multi-chain orchestration with per-chain gas/price providers and Etherscan-equivalent (Snowtrace, Arbscan) abstraction.
- Risk module to include slippage/volatility from on-chain TWAPs and per-router reputation.

---

## 19. Deployment Checklist

- Set `ETHERSCAN_API_KEY`, `FLASHBOTS_RELAY_URL` (if custom), executor address, profit receiver, metrics token, and router allowlist for each chain.
- Ensure node supports `eth_feeHistory`, `eth_simulate` (or accept fallbacks).
- Fund wallet (~0.1–0.5 ETH recommended) or enable flash-loan path with deployed executor.
- Verify tokenlist path or accept empty list (decimals default to 18).

---

Updated: **05/02/2026**

### Mainnet operator notes (Nethermind + relays)
- Enable Nethermind modules: `JsonRpc.EnabledModules = ["Eth","Subscribe","TxPool","Trace","Debug","Net","Web3","Rpc","Admin"]`, `TraceStore.Enabled = true`, and expose IPC/WS locally for low-latency simulate/trace.
- Ensure `Trace`/`Debug` are enabled on the exact RPC endpoint used for simulation and diagnostics.
- For mainnet bundle submission configure builders: Flashbots (`https://relay.flashbots.net`), Beaver, Titan, Ultrasound, Agnostic (builder0x69), bloXroute ethical. All use Flashbots-style signed headers.
- Always provide `WALLET_KEY`, `BUNDLE_SIGNER_KEY`, `METRICS_TOKEN`, and RPC URLs via environment; repo configs are placeholders only.
