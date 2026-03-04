# UnifiedHardenedExecutor Threat Model

## Scope
- Contract: `data/UnifiedHardenedExecutor.sol`
- Entry points: `executeBundle`, `executeFlashLoan`, `executeAaveFlashLoanSimple`
- Callback paths: `receiveFlashLoan` (Balancer), `executeOperation` (Aave)

## Assets To Protect
- Loan principal + premium owed to Balancer/Aave.
- Residual profit balances (ERC20 and ETH) before sweep.
- Owner authority over all execution and admin controls.

## Trust Boundaries
- `owner` is fully trusted and controls strategy payloads.
- External protocols (`BalancerVault`, `AavePool`, routers/tokens) are untrusted call targets.
- `profitReceiver` may fail or be adversarial (should not brick flashloan repayment paths).

## Key Threats And Existing Mitigations
- Unauthorized execution:
  - Mitigation: `onlyOwner` and `onlySelfOrOwner` modifiers on privileged entry points.
- Callback spoofing/replay in flashloan flow:
  - Mitigation: strict sender checks (`OnlyVault`, `OnlyPool`), session flags, and context hash checks.
- Under-repayment on flashloans:
  - Mitigation: explicit `InsufficientFundsForRepayment` checks before repayment/approval.
- Balancer multi-asset canonical ordering risk:
  - Mitigation: strict ascending token ordering guard with `BalancerTokensNotSorted`.
- Token approval edge cases (USDT-style):
  - Mitigation: zero-reset approval strategy in `_lowLevelApprove`/`safeApprove`.
- Profit receiver failure causing bundle failure:
  - Mitigation: non-fatal distribution paths emit `DistributeFailed` while preserving repayment flow.

## Residual Risks
- Owner compromise is catastrophic by design (expected for owner-controlled executor).
- Arbitrary external calls are intentional; off-chain planner correctness remains critical.
- No explicit on-chain reentrancy guard; callback/session checks reduce replay classes but owner payloads still drive call graph complexity.

## Security Invariants Checked In CI
- Source-level invariant tests added in:
  - `tests/unified_hardened_executor_invariants.rs`
- Invariants covered:
  - owner/session guard presence.
  - Balancer callback auth + context + single-use session reset.
  - Aave callback auth + session reset semantics.
  - repayment sufficiency checks and repayment mechanisms.
  - flashloan input sanity checks (length/zero/sorted/token/pool validity).
