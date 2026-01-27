# Runtime Flow (0.1 ETH wallet, current codebase)

## Assumptions
- You have deployed the `UnifiedHardenedExecutor` contract and set its address in `config.toml` (`executor_address`), with `flashloan_enabled = true`.
- Wallet balance (the configured `wallet_address`) is ~0.1 ETH on the connected chain.
- Nethermind (or another RPC/WS node) is running and reachable via `RPC_URL`/`WEBSOCKET_URL`.
- Metrics token/env vars are set so the metrics server starts.

## Startup
1) Binary starts, loads `config.toml`, and migrates SQLite (includes `nonce_state` table).
2) Connects to RPC/WS; builds helpers (GasOracle, PriceFeed, Simulator, ReserveCache, NonceManager, PortfolioManager).
3) Strategy worker queue is bounded (2048). In-flight reserve lookups are semaphore-limited.
4) If `nonce_state` exists, it restores `block`, `next_nonce`, and `touched_pools`; otherwise it records a fresh base nonce for the current block.
5) Metrics server starts (requires `METRICS_TOKEN`), exposing counters (including nonce persistence) and recent bundles.

## Ingest loop
1) Mempool scanner subscribes to pending txs; MEV-Share client streams hints (if enabled). Each item is enqueued; depth/backpressure metrics update on send/drop.
2) Block listener updates `current_block`; on a new block it resets in-memory bundle state and persists a fresh nonce baseline to `nonce_state`.

## Strategy processing per item
1) SafetyGuard check (circuit breaker) then decode:
   - Rejects unknown routers, toxic tokens, token-transfer calls.
   - Extracts path/direction/target token.
2) Gas fees estimated and boosted; gas-cap applied.
3) Balance update: with 0.1 ETH, dynamic backrun value uses conservative divisors (wallet / 4 or /6 depending on cap).
4) Flashloan decision:
   - `should_use_flashloan` compares required_value + 0.002 ETH buffer to wallet balance. With 0.1 ETH, simple backruns usually use wallet funds; if required_value exceeds balance buffer, it switches to flashloan path via executor.
5) Build components:
   - Optional front‑run (only on buy-with-ETH paths if sandwiches enabled).
   - Optional approval (scoped amount) for front‑run token.
   - Backrun tx (V2/V3 or flashloan payload). If flashloan: approvals are amount-scoped and zeroed post-loop; forward+reverse swaps encoded in callbacks.
   - Optional executor wrapper if configured and not using flashloan.
6) Nonce lease:
   - Reserves exactly the needed nonces; lease persisted to `nonce_state`. Same lease used for sim and signing to avoid nonce gaps.

## Simulation and profit guard
1) Builds bundle requests (front-run, victim, approval, main/backrun/executor) with a state override that pins balance and nonce to the lease base.
2) Simulates bundle (`eth_simulate` if available, otherwise per-tx `eth_call` + `estimate_gas`).
3) Rejects on any failed leg, non-native profit, thin margins, gas/profit ratio, or dynamic profit floor (scaled by wallet PnL and balance).

## Sign, merge, and send
1) Signs transactions with access lists; attaches lease nonces.
2) Merges into per-block bundle_state if pools don’t conflict; persists updated `next_nonce` and touched pools.
3) Debounced send:
   - Mainnet: sends to Flashbots + secondary builders.
   - Other chains: direct `eth_sendRawTransaction`.
   - MEV-Share path: submits hashes + crafted legs via `mev_sendBundle`.
4) Records txs/profit to SQLite; awaits receipt (best-effort) and updates metrics/bundle history.

## Metrics & observability
- Counters: processed/submitted/skipped/failed, skip reasons, ingest drops/backpressure.
- New counters: `nonce_state_loads`, `nonce_state_load_fail`, `nonce_state_persist`, `nonce_state_persist_fail`.
- Queue depth gauge now reflects dequeues; bundle history exposed at `/bundles` and dashboard JSON.

## Failure / restart behavior
- On restart, `nonce_state` reloads block/next_nonce/touched_pools, preventing nonce reuse and duplicate pool merges.
- If load fails, stats flag it and strategy continues with fresh state.
- SafetyGuard trips after consecutive failures and auto-resets after the cooldown window.

## Staging on Nethermind (soak)
```
RPC_URL_1=http://127.0.0.1:8545 WEBSOCKET_URL_1=ws://127.0.0.1:8546 \
WALLET_KEY=0x<funded_dev_key> METRICS_TOKEN=changeme \
DATABASE_URL=sqlite://oxidity_builder.db \
cargo run --release
```
- Ensure wallet has ~0.1 ETH. Flashloan usage will trigger only if required trade size exceeds balance + 0.002 ETH buffer.
- Watch `/` and `/dashboard` metrics; verify nonce_state counters stay low and queue depth remains bounded.
