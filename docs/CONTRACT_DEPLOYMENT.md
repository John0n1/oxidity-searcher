# Contract Deployment Guide 📜

This guide provides instructions for compiling and deploying the **`UnifiedHardenedExecutor`** smart contract to Ethereum Mainnet or EVM testnets (Sepolia).

---

## Contract Overview

The **`UnifiedHardenedExecutor`** contract is the on-chain execution contract for `oxidity-searcher`. It handles:

1. **Atomic Flashloan Callbacks**: Borrowing assets from Balancer V2 (0% fee) or Aave V3 (0.05% fee).
2. **Multi-DEX Swaps**: Executing multi-hop swaps across Uniswap V2, Uniswap V3, Sushiswap, Balancer, and Curve in a single transaction.
3. **Builder Bribe Settlement**: Paying Flashbots block builders directly via `block.coinbase.transfer` inside the atomic callback.
4. **Access Control**: Hardened `onlyOwner` access controls to prevent frontrunning or unauthorized withdrawals.

---

## Deployment Steps

### Option 1: Deploying via Foundry / Forge (Recommended)

#### Prerequisites
Install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

#### Compile Contract
```bash
forge build --release
```

#### Deploy to Ethereum Mainnet
```bash
forge create --rpc-url http://127.0.0.1:8545 \
  --private-key YOUR_WALLET_PRIVATE_KEY \
  contracts/UnifiedHardenedExecutor.sol:UnifiedHardenedExecutor \
  --verify
```

---

### Option 2: Deploying via Remix IDE

1. Open [Remix IDE](https://remix.ethereum.org/).
2. Upload `contracts/UnifiedHardenedExecutor.sol`.
3. Select Solidity Compiler version `0.8.24` (Enable EVM version `paris` or `shanghai`, 200 runs optimization).
4. Connect Remix to **Injected Provider (Metamask)** or **Custom External HTTP Provider** (`http://127.0.0.1:8545`).
5. Deploy `UnifiedHardenedExecutor` and copy the resulting deployed contract address.

---

## Post-Deployment Configuration

After deployment:

1. Copy the deployed executor contract address (e.g., `0x1234...5678`).
2. Add it to your `.env` file:
   ```env
   OXIDITY_FLASHLOAN_CONTRACT_ADDRESS=0x1234...5678
   ```
3. Fund your signer wallet with initial ETH (~0.1 ETH) for gas reserve and builder bribes.
4. Update `config.toml` to enable live flashloans:
   ```toml
   flashloan_enabled = true
   ```
