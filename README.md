# Oxidity Searcher 🚀

**Oxidity Searcher** is an ultra-low latency, multi-strategy Maximal Extractable Value (MEV) searcher written in Rust. Engineered for Ethereum Mainnet and EVM-compatible chains, it streams pending transactions directly from local node mempools (e.g. local Reth / Geth via JSON-RPC / WebSockets), decodes multi-DEX interactions in real-time, evaluates arbitrage and sandwich bundles, pre-simulates execution via local EVM calls (`eth_simulateV1` / `debug_traceCall`), and submits signed atomic bundles to private block builders (Flashbots, BeaverBuilder, Titan).

---

## Key Features & Architecture

* **High-Throughput Parallel Pipeline**: Built on Tokio and Rayon, utilizing 8+ worker threads for sub-millisecond mempool parsing, swap decoding, and candidate generation.
* **Full Multi-Strategy Suite**:
  * **Cross-DEX & Triangular Arbitrage**: Multi-hop graph search solver ($A \to B \to C \to A$) across Uniswap V2/V3, Sushiswap, Balancer, and Curve.
  * **Sandwich Attack Engine**: Frontrunning, victim, and backrunning 3-tx atomic bundle construction.
  * **Uniswap V3 JIT Liquidity Provisioning**: Concentrated liquidity minting/burning around large swaps ($> 1\text{ ETH}$).
  * **MEV Bot Trapping ("Bait & Trap")**: Detects un-guarded competitor transactions (`min_out <= 1`) and executes counter-trap extraction bundles.
  * **Honeypot Safety Audit**: Automated two-way sell simulation probes (`probe_v2_sell_for_toxicity` / `probe_v3_sell_for_toxicity`) and toxic token caching.
* **Analytical Optimal Trade Sizing ($S^*$)**: Dynamic sizing solver calculating exact peak profit trade sizes bound by pool price impact limits ($S_{\text{max}} = \frac{\text{max\_bps} \cdot R_1}{10000 - \text{max\_bps}}$).
* **Atomic Flashloan Integration**: Leverages zero-fee Balancer V2 vaults and Aave V3 pools for zero-capital trade execution ($0.01\text{ to }500+\text{ ETH}$).
* **Zero Capital Loss Guarantee**: Pre-simulates every bundle locally via `eth_simulateV1`. Non-profitable or reverting bundles are dropped locally with $0 gas spent.
* **Private Relay Execution**: Submits ECDSA-signed bundles directly to private builder endpoints (`https://relay.flashbots.net`).

---

## System Requirements

* **Operating System**: Linux (Ubuntu 22.04 LTS or Debian 12 recommended)
* **Compiler**: Rust 1.78+ (cargo, rustc)
* **Execution Node**: Local Reth node (`http://127.0.0.1:8545` & `ws://127.0.0.1:8546`) or high-performance local Geth node with `eth_subscribe` & `eth_simulateV1` / `debug_traceCall` capabilities.
* **Database**: SQLite3 (automatically created as `oxidity_searcher.db`).

---

## Quick Start Guide

### 1. Build from Source

```bash
git clone https://github.com/John0n1/oxidity-searcher.git
cd oxidity-searcher
cargo build --release
```

### 2. Configure Environment

Copy `.env.example` to `.env` and fill in your signer wallet private key and contract address:

```bash
cp .env.example .env
```

Edit `.env`:
```env
OXIDITY_WALLET_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
OXIDITY_WALLET_ADDRESS=0xYOUR_WALLET_ADDRESS
OXIDITY_BUNDLE_PRIVATE_KEY=0xYOUR_BUNDLE_SIGNER_KEY
OXIDITY_FLASHLOAN_CONTRACT_ADDRESS=0xYOUR_DEPLOYED_EXECUTOR_ADDRESS
```

### 3. Run in Mainnet Shadow Mode (Dry-Run / Simulation)

To monitor live Mainnet opportunities without broadcasting real transactions:

```bash
CHAINS=1 target/release/oxidity-searcher --config config.toml --shadow-mode
```

### 4. Run Live in Production Mode

Once your executor contract is deployed and funded with gas/bribe capital (~0.1 ETH):

In `config.toml`:
```toml
debug = false
shadow_mode = false
dry_run = false
flashloan_enabled = true
```

Launch:
```bash
CHAINS=1 target/release/oxidity-searcher --config config.toml
```

---

## Comprehensive Documentation

For detailed guides, refer to the `docs/` directory:

1. [Configuration Reference](docs/CONFIG.md)
2. [Contract Deployment Guide](docs/CONTRACT_DEPLOYMENT.md)
3. [Execution Client Setup (Local Reth)](docs/EXECUTION_CLIENT.md)
4. [Testing & Verification Guide](docs/TESTING.md)
5. [Contributing Guidelines](CONTRIBUTING.md)

---

## License

Copyright © 2026 John Hauger Mitander <john@oxidity.io>. All rights reserved.
Licensed under the MIT License.
