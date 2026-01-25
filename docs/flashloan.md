## Flashloan and executor flow

### What it is
Backruns can optionally borrow the input asset via the on-chain executor instead of spending wallet balance. The executor performs:
1) Flashloan of the input asset.
2) Optional approval to the router.
3) Swap payload execution.
4) Repay + bribe accounting in the executor contract.

### When it triggers
- `flashloan_enabled = true` in config.
- An executor address is configured.
- The strategy decides balance + gas buffer are insufficient for a direct backrun (see `should_use_flashloan` in `planning.rs`).

### How it is built
- `planning.rs` assembles targets/payloads (approval + swap) into `executeFlashLoan` on `UnifiedHardenedExecutor`.
- Gas limit is padded to account for callbacks; value sent is zero (loan covers notional).
- Approvals are simulated before use to avoid honeypots; toxic tokens are marked and skipped.

### Safety checklist
- Deploy and verify the executor contract; ensure it unwraps WETH and pays itself back.
- Keep router approvals scoped; executor uses `approve(MAX)` by design—rotate keys if compromised.
- Monitor metrics/logs for `flashloan`-tagged bundles.
- Builder submission still uses nonce leasing; avoid sending unrelated txs from the same key.

### Troubleshooting
- Reverts in flashloan paths often come from missing approvals or insufficient gas padding—check simulation traces.
- If inventory sweeps keep failing, ensure the executor has allowance on the router for the swept token.
- Disable with `flashloan_enabled = false` to isolate issues.
