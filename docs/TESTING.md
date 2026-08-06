# Testing & Verification Guide 🧪

This document outlines testing methodologies, unit testing, integration tests, and local simulation workflows for `oxidity-searcher`.

---

## Running the Complete Test Suite

`oxidity-searcher` includes over 260 unit, integration, and RPC compatibility tests covering strategy logic, mathematical solvers, graph search, and risk controls.

Run the entire test suite in release mode:

```bash
cargo test --release
```

### Running Specific Module Test Suites

To run tests for a specific strategy or subsystem:

* **Strategy & Ingestion Handlers**:
  ```bash
  cargo test --release strategy::ingest
  ```
* **Execution Planner & Trade Sizing Math**:
  ```bash
  cargo test --release strategy::planning
  ```
* **Simulation & EVM Safety Filters**:
  ```bash
  cargo test --release strategy::simulation
  ```
* **Risk & Circuit Breaker Guards**:
  ```bash
  cargo test --release strategy::risk
  ```

---

## Mainnet Shadow Mode Testing

Shadow Mode allows testing against live Mainnet mempool transactions without sending real transactions to the blockchain or spending ETH.

### How to Run Shadow Mode

```bash
CHAINS=1 target/release/oxidity-searcher --config config.toml --shadow-mode
```

### What Happens in Shadow Mode

1. Streams live pending transactions from your local Reth node (`http://127.0.0.1:8545`).
2. Decodes multi-DEX interactions and calculates optimal trade sizing ($S^*$).
3. Pre-simulates execution against local state via `eth_simulateV1`.
4. Saves verified $P\&L$ estimates to `oxidity_searcher.db` (`execution_estimates` table).
5. **Skips RPC submission** to block builders.

### Inspecting Shadow Mode Database Results

You can query verified $P\&L$ records using `sqlite3`:

```bash
sqlite3 oxidity_searcher.db "SELECT * FROM execution_estimates ORDER BY created_at DESC LIMIT 10;"
```

---

## Code Quality & Linting

Ensure code meets compiler and linter standards:

```bash
cargo fmt --check
cargo clippy --release -- -D warnings
```
