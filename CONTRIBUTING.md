# Contributing to Oxidity Searcher 🤝

Thank you for your interest in contributing to **Oxidity Searcher**! As a high-performance, low-latency MEV searcher, maintaining code safety, performance, and mathematical rigor is paramount.

---

## Code of Conduct & Guidelines

1. **Safety First**: MEV code handles financial transactions. All code edits must preserve strict zero-loss safety guarantees (`eth_simulateV1` pre-simulation filters, circuit breakers, and toxic token checks).
2. **Performance Constraints**: Avoid blocking calls or unnecessary allocations on main event loops. Use Tokio tasks and async worker queues.
3. **No Breaking API Contracts**: Ensure changes to function signatures or struct fields are updated across all caller sites and unit tests.
4. **Zero Compiler Warnings**: All code must compile cleanly with `cargo build --release` without generating compiler or lint warnings.

---

## Development Workflow

### 1. Fork & Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Code Formatting & Linting

Format your code using standard Rust formatting rules:

```bash
cargo fmt --all
cargo clippy --release -- -D warnings
```

### 3. Running the Test Suite

Before submitting a Pull Request, verify that all 260+ unit and integration tests pass:

```bash
cargo test --release
```

---

## Pull Request Guidelines

* Provide a clear summary of changes and rationale in your Pull Request description.
* Include unit tests for any new strategy, math solver, or RPC client integration.
* Ensure all existing tests in `cargo test --release` pass cleanly.
