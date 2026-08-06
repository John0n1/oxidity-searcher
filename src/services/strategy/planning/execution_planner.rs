// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::U256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanType {
    OwnCapital,
    Flashloan,
}

impl PlanType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnCapital => "own_capital",
            Self::Flashloan => "flashloan",
        }
    }
}

/// Funding-only inputs. Economic authorization occurs only after an executable route has been
/// quoted and simulated; this planner must never invent an edge or expected profit.
#[derive(Clone, Debug)]
pub struct PlannerInput {
    pub wallet_balance: U256,
    pub gas_cost_estimate: U256,
    pub has_wrapped_path: bool,
    pub flashloan_available: bool,
    pub base_trade_hint: U256,
    pub min_size: U256,
    pub max_size: U256,
    pub safety_margin_bps: u64,
    pub uncertainty_bps: u64,
}

#[derive(Clone, Debug)]
pub struct PlanCandidate {
    pub plan_type: PlanType,
    pub size_wei: U256,
    pub funding_headroom_wei: U256,
    pub rejected_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DecisionTrace {
    pub best_plan: Option<PlanCandidate>,
    pub candidates: Vec<PlanCandidate>,
    pub rejection_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionPlanner;

impl ExecutionPlanner {
    pub fn plan(&self, input: &PlannerInput) -> DecisionTrace {
        let min_size = input.min_size.max(U256::from(1u64));
        let max_size = input.max_size.max(min_size);
        let reserve_bps = 10_000u64
            .saturating_add(input.safety_margin_bps)
            .saturating_add(input.uncertainty_bps);
        let gas_reserve = input
            .gas_cost_estimate
            .saturating_mul(U256::from(reserve_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(input.gas_cost_estimate);

        if input.wallet_balance < gas_reserve {
            return DecisionTrace {
                best_plan: None,
                candidates: Vec::new(),
                rejection_reason: Some("insufficient_native_for_gas_reserve".to_string()),
            };
        }

        let owned_budget = input.wallet_balance.saturating_sub(gas_reserve);
        let requested_size = input.base_trade_hint.max(min_size).min(max_size);
        let mut candidates = Vec::new();

        if owned_budget >= min_size {
            let size = requested_size.min(owned_budget);
            candidates.push(PlanCandidate {
                plan_type: PlanType::OwnCapital,
                size_wei: size,
                funding_headroom_wei: owned_budget.saturating_sub(size),
                rejected_reason: None,
            });
        }

        if input.flashloan_available && input.has_wrapped_path {
            candidates.push(PlanCandidate {
                plan_type: PlanType::Flashloan,
                size_wei: requested_size,
                funding_headroom_wei: input.wallet_balance.saturating_sub(gas_reserve),
                rejected_reason: None,
            });
        }

        // Prefer owned capital only when it can fund the complete requested size while preserving
        // the gas/risk reserve. Otherwise use atomic borrowed principal. Route quotes and
        // simulation still have final authority and can reject either plan.
        let best_plan = candidates
            .iter()
            .find(|candidate| candidate.plan_type == PlanType::Flashloan)
            .or_else(|| {
                candidates
                    .iter()
                    .find(|candidate| {
                        candidate.plan_type == PlanType::OwnCapital && candidate.size_wei == requested_size
                    })
            })
            .or_else(|| candidates.first())
            .cloned();
        let rejection_reason = best_plan
            .is_none()
            .then(|| "no_fundable_execution_family".to_string());

        DecisionTrace {
            best_plan,
            candidates,
            rejection_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PlannerInput {
        PlannerInput {
            wallet_balance: U256::from(100_000_000_000_000_000u128),
            gas_cost_estimate: U256::from(200_000_000_000_000u64),
            has_wrapped_path: true,
            flashloan_available: true,
            base_trade_hint: U256::from(15_000_000_000_000_000u64),
            min_size: U256::from(1u64),
            max_size: U256::from(150_000_000_000_000_000u128),
            safety_margin_bps: 800,
            uncertainty_bps: 400,
        }
    }

    #[test]
    fn prefers_fully_funded_owned_plan() {
        let mut input = input();
        input.flashloan_available = false;
        let decision = ExecutionPlanner.plan(&input);
        assert_eq!(
            decision.best_plan.expect("plan").plan_type,
            PlanType::OwnCapital
        );
    }

    #[test]
    fn chooses_flash_when_only_gas_is_owned() {
        let mut input = input();
        input.wallet_balance = U256::from(500_000_000_000_000u64);
        let decision = ExecutionPlanner.plan(&input);
        assert_eq!(
            decision.best_plan.expect("plan").plan_type,
            PlanType::Flashloan
        );
    }

    #[test]
    fn rejects_balance_below_risk_adjusted_gas_reserve() {
        let mut input = input();
        input.wallet_balance = U256::from(1u64);
        let decision = ExecutionPlanner.plan(&input);
        assert!(decision.best_plan.is_none());
        assert_eq!(
            decision.rejection_reason.as_deref(),
            Some("insufficient_native_for_gas_reserve")
        );
    }
}
