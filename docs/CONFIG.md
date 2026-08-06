# Configuration Guide (`config.toml` & `.env`) ⚙️

This document describes all configuration options available in `config.toml` and environment variables in `.env`.

---

## Environment Variables (`.env`)

Secrets and node endpoints are loaded from environment variables or a local `.env` file:

```env
# Signer Wallet & Keys
OXIDITY_WALLET_PRIVATE_KEY=0x...          # Private key of main execution wallet
OXIDITY_WALLET_ADDRESS=0x...              # Address of main execution wallet
OXIDITY_BUNDLE_PRIVATE_KEY=0x...          # Private key used for Flashbots bundle signature headers

# Deployed Contract Address
OXIDITY_FLASHLOAN_CONTRACT_ADDRESS=0x... # Address of deployed UnifiedHardenedExecutor contract

# Node Providers (Local Reth / Geth)
MAINNET_RPC_URL=http://127.0.0.1:8545     # Local Reth HTTP JSON-RPC endpoint
MAINNET_WS_URL=ws://127.0.0.1:8546        # Local Reth WebSocket endpoint for mempool streaming
```

---

## Core Configuration File (`config.toml`)

`config.toml` manages strategy parameters, risk thresholds, and execution modes.

### 1. Runtime & Chain Settings
```toml
chains = [1]                              # Ethereum Mainnet (Chain ID 1)
debug = true                              # Enable verbose debug logs and decision tracing
shadow_mode = true                        # Run in dry-run simulation mode (no live broadcasts)
dry_run = true                            # Skip live transaction submission
strategy_enabled = true                  # Master toggle for strategy engine
simulation_backend = "eth_simulate"       # EVM simulation mode ("eth_simulate" or "trace_call")
max_gas_price_gwei = 100                  # Maximum base fee threshold in Gwei
```

### 2. Flashloans & Strategy Toggles
```toml
flashloan_enabled = true                  # Enable zero-capital flashloan borrowing
flashloan_provider = "auto,aavev3,balancer" # Preferred flashloan liquidity providers
sandwich_attacks_enabled = true          # Enable 3-tx sandwich attack engine
mev_share_enabled = true                 # Enable MEV-Share backrun bundle engine
allow_non_wrapped_swaps = true           # Allow swaps through native ETH / WETH pools
```

### 3. Risk & Safety Guard Controls
```toml
max_daily_loss_usd = 50.0                # Daily stop-loss safety circuit breaker in USD
max_consecutive_reverts = 3              # Max consecutive simulation reverts before circuit trip
liquidity_impact_max_bps = 200           # Max allowed pool price impact tolerance (200 bps = 2.0%)
min_net_profit_wei = 100000000000000     # Absolute min profit floor (~0.0001 ETH)
```

---

## Live Production Configuration Profile

When deploying live with real funds, update `config.toml` as follows:

```toml
debug = false
shadow_mode = false
dry_run = false
flashloan_enabled = true
```
