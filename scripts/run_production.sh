#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>
# ==============================================================================
# Oxidity Searcher - Full Production Launcher Script
# ==============================================================================

set -euo pipefail

# ANSI Color Definitions
BOLD='\033[1;37m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
MAGENTA='\033[1;35m'
RESET='\033[0m'

echo -e "${CYAN}=============================================================================="${RESET}
echo -e "${BOLD}${MAGENTA}       🚀 OXIDITY SEARCHER - FULL PRODUCTION ENGINE LAUNCHER 🚀${RESET}"
echo -e "${CYAN}=============================================================================="${RESET}

# 1. Environment File Check
if [ -f ".env" ]; then
    echo -e "${GREEN}[+] Loading environment variables from .env...${RESET}"
    set -a
    source .env
    set +a
else
    echo -e "${RED}[!] Error: .env file not found! Please copy .env.example to .env and configure keys.${RESET}"
    exit 1
fi

# 2. Key Verification
echo -e "${CYAN}[*] Verifying production environment configuration...${RESET}"

if [ -z "${OXIDITY_WALLET_PRIVATE_KEY:-}" ] || [ "${OXIDITY_WALLET_PRIVATE_KEY}" == "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo -e "${RED}[!] Error: OXIDITY_WALLET_PRIVATE_KEY is missing or unconfigured in .env!${RESET}"
    exit 1
fi

if [ -z "${OXIDITY_FLASHLOAN_CONTRACT_ADDRESS:-}" ] || [ "${OXIDITY_FLASHLOAN_CONTRACT_ADDRESS}" == "0x0000000000000000000000000000000000000000" ]; then
    echo -e "${YELLOW}[!] Warning: OXIDITY_FLASHLOAN_CONTRACT_ADDRESS is not set to a deployed contract address.${RESET}"
    echo -e "${YELLOW}    Flashloans will use EOA fallback until executor contract is deployed.${RESET}"
fi

# 3. Check Local Reth Node Connection
RPC_URL="${MAINNET_RPC_URL:-http://127.0.0.1:8545}"
echo -e "${CYAN}[*] Checking local Reth node connection at ${RPC_URL}...${RESET}"

if curl -s -X POST "${RPC_URL}" -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null; then
    BLOCK_HEX=$(curl -s -X POST "${RPC_URL}" -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    BLOCK_NUM=$((BLOCK_HEX))
    echo -e "${GREEN}[+] Local Reth node connected! Sync height: Block #${BLOCK_NUM}${RESET}"
else
    echo -e "${YELLOW}[!] Warning: Local Reth RPC at ${RPC_URL} is unresponsive. Please ensure Reth is running.${RESET}"
fi

# 4. Build Release Binary
echo -e "${CYAN}[*] Building optimized release binary (cargo build --release)...${RESET}"
cargo build --release --quiet
echo -e "${GREEN}[+] Release binary built successfully!${RESET}"

# 5. Enable Production Config Overrides
echo -e "${CYAN}[*] Strategy Suite Active:${RESET}"
echo -e "${GREEN}    ✓ Cross-DEX & Triangular Arbitrage Engine${RESET}"
echo -e "${GREEN}    ✓ Sandwich Attack Engine (Frontrun + Victim + Backrun)${RESET}"
echo -e "${GREEN}    ✓ Uniswap V3 JIT Liquidity Provisioning Engine${RESET}"
echo -e "${GREEN}    ✓ MEV Bot Trapping (\"Bait & Trap\") Engine${RESET}"
echo -e "${GREEN}    ✓ Honeypot Safety Audit & Toxic Token Shield${RESET}"
echo -e "${GREEN}    ✓ Dynamic Optimal Trade Sizing ($S^*)${RESET}"
echo -e "${GREEN}    ✓ Atomic Flashloan Capital Integration${RESET}"

echo -e "${CYAN}=============================================================================="${RESET}
echo -e "${BOLD}${GREEN}  STARTING PRODUCTION SEARCHER ON ETHEREUM MAINNET (CHAIN ID: 1)${RESET}"
echo -e "${CYAN}=============================================================================="${RESET}

# Execute Searcher Binary with Colored Log Environment
export RUST_LOG="info,oxidity_searcher=debug,strategy=debug,flashloan=info,planner=debug"
export RUST_BACKTRACE=1
export CHAINS=1

exec target/release/oxidity-searcher --config config.toml
