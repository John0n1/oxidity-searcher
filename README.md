# oxidity.builder

Rust-based MEV searcher that observes the mempool (plus optional MEV-Share hints), simulates sandwich/backrun bundles, and submits to builders/relays. It keeps lightweight PnL state in SQLite and exposes a small metrics/diagnostics endpoint.

## Important configuration

- `STRATEGY_WORKERS`: max concurrent strategy tasks (default 32). Tune for your CPU / RPC rate limits.
- `METRICS_TOKEN`: required bearer token for the metrics endpoint; the server will refuse to start without it.
- `METRICS_BIND`: optional bind host (defaults to `127.0.0.1`); keep it local unless you truly need remote scraping.

### RPC preference
The node connection order is **IPC → WebSocket → HTTP**. Set an IPC path per chain (e.g. `ipc_urls = { "1" = "/mnt/pool/ethereum/nethermind/nethermind.ipc" }`) to get the lowest latency and most reliable mempool/trace access; WS is the fallback, HTTP last.

### Metrics
The metrics server requires `METRICS_TOKEN` and will reject unauthenticated requests. Example:
```
METRICS_TOKEN=changeme
METRICS_BIND=127.0.0.1
METRICS_PORT=9000
```
Prometheus scrape example:
```
- job_name: oxidity
  metrics_path: /
  scheme: http
  bearer_token: changeme
  static_configs:
    - targets: ['127.0.0.1:9000']
```
