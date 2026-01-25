## Developer helper

### Everyday commands
- Format and lint: `cargo fmt && cargo clippy`.
- Tests: `cargo test -- --nocapture` (strategy unit tests live in `src/services/strategy/strategy.rs`).
- Targeted test runs: `cargo test strategy::strategy::tests::detects_nonce_gap_errors`.

### Structure notes
- Strategy logic is split into modules:
  - `bundles.rs` (nonce leasing + merge/sign),
  - `guards.rs` (profit/gas heuristics),
  - `swaps.rs` (V2/V3 quoting/building),
  - `planning.rs` (front/back-run and flashloan assembly),
  - `handlers.rs` (mempool + MEV-Share entry points),
  - `inventory.rs` (sweeps/toxicity probes).
- Keep new helpers small and colocated; prefer adding tests next to the modules they exercise.

### Debug tips
- Enable verbose logs: `RUST_LOG=debug` or bump at runtime via `/log-level`.
- Use `METRICS_TOKEN` locally to exercise auth paths even on localhost.
- When touching nonce logic, run the bundle/nonce tests to avoid regressions.

### Contributing hygiene
- Stick to ASCII in source/docs.
- Avoid introducing new public surfaces unless required for cross-module calls.
- Update docs (README + `docs/`) when behaviour changes; add a bullet to `docs/changelog.md`.
