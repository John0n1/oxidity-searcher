# Execution Client Guide (Local Reth Node) ⚡

`oxidity-searcher` is engineered for sub-millisecond mempool streaming and execution by pairing directly with a local **Reth** or **Geth** execution client running on the same machine or local gigabit network.

---

## Why Local Reth Is Essential for MEV

* **Sub-Millisecond Mempool Ingestion**: A local WebSocket connection (`ws://127.0.0.1:8546`) delivers pending transactions within **$< 1\text{ ms}$** of network propagation.
* **Instant EVM State Calls**: Local HTTP RPC (`http://127.0.0.1:8545`) provides lightning-fast `eth_simulateV1` / `debug_traceCall` pre-simulation.
* **No RPC Rate Limits**: Zero rate limiting or artificial throttling compared to remote third-party RPC providers (Infura, Alchemy, QuickNode).

---

## Running Reth for MEV Searchers

### 1. Install Reth
```bash
cargo install --git https://github.com/paradigmxyz/reth --locked reth
```

### 2. Launch Reth Engine with Full RPC Capabilities

Run Reth with HTTP and WebSocket servers enabled, plus state simulation APIs (`eth`, `debug`, `trace`):

```bash
reth node \
  --chain mainnet \
  --http \
  --http.addr 127.0.0.1 \
  --http.port 8545 \
  --http.api eth,net,web3,debug,trace \
  --ws \
  --ws.addr 127.0.0.1 \
  --ws.port 8546 \
  --ws.api eth,net,web3,debug,trace
```

---

## Verifying Local Node Connection

Test HTTP connection via `curl`:

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Expected output:
```json
{"jsonrpc":"2.0","id":1,"result":"0x1337..."}
```

---

## Config Connection Settings

Ensure `config.toml` and `.env` point to your local node:

```env
MAINNET_RPC_URL=http://127.0.0.1:8545
MAINNET_WS_URL=ws://127.0.0.1:8546
```
