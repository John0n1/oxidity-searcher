## Changelog

### Unreleased
- Split `strategy.rs` into modular files (`bundles`, `guards`, `swaps`, `planning`, `handlers`, `inventory`) for readability and testability.
- Wired previously unused config knobs (`sandwich_attacks_enabled`, `simulation_backend`, profit receiver/bribe controls).
- Hardened metrics endpoint defaults to localhost with optional bearer auth; added multi-chain port auto-increment note.
- Fixed flashloan/executor handling to lease nonces, and added inventory toxicity probes to a dedicated module.
- Added documentation in `docs/` and expanded README.
