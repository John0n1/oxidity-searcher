// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::primitives::{I256, U256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanType {
    OwnCapital,
    Flashloan,
    Hybrid,
}

impl PlanType {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanType::OwnCapital => "own_capital",
            PlanType::Flashloan => "flashloan",
            PlanType::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlannerInput {
    pub wallet_balance: U256,
    pub victim_value: U256,
    pub gas_cost_estimate: U256,
    pub has_wrapped_path: bool,
    pub flashloan_available: bool,
    pub allow_hybrid: bool,
    pub base_trade_hint: U256,
    pub min_size: U256,
    pub max_size: U256,
    pub slippage_bps: u64,
    pub safety_margin_bps: u64,
    pub uncertainty_bps: u64,
}

#[derive(Clone, Debug)]
pub struct PlanScore {
    pub expected_net_wei: I256,
    pub profit_if_included_wei: I256,
    pub cost_if_failed_wei: U256,
    pub inclusion_probability_bps: u64,
    pub dynamic_profit_floor_wei: U256,
}

#[derive(Clone, Debug)]
pub struct PlanCandidate {
    pub plan_type: PlanType,
    pub size_wei: U256,
    pub score: PlanScore,
    pub rejected_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DecisionTrace {
    pub best_plan: Option<PlanCandidate>,
    pub candidates: Vec<PlanCandidate>,
    pub rejection_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExecutionPlanner {
    pub k_consecutive_declines: usize,
    pub marginal_epsilon_wei: U256,
    pub ladder_steps: usize,
}

impl Default for ExecutionPlanner {
    fn default() -> Self {
        Self {
            k_consecutive_declines: 3,
            marginal_epsilon_wei: U256::from(1_000_000_000_000u64),
            ladder_steps: 9,
        }
    }
}

impl ExecutionPlanner {
    pub fn plan(&self, input: &PlannerInput) -> DecisionTrace {
        let base_min = input.min_size.max(U256::from(1u64));
        let base_max = input.max_size.max(base_min);

        let own_max = input.wallet_balance.max(base_min).min(base_max);
        let flash_max = if input.flashloan_available && input.has_wrapped_path {
            base_max
                .saturating_add(input.victim_value)
                .saturating_add(input.base_trade_hint)
                .max(base_min)
        } else {
            U256::ZERO
        };
        let hybrid_max = if input.allow_hybrid && input.flashloan_available {
            own_max
                .saturating_add(flash_max.saturating_mul(U256::from(5u64)) / U256::from(10u64))
                .max(base_min)
        } else {
            U256::ZERO
        };

        let mut candidates = Vec::new();

        if own_max >= base_min {
            candidates.push(self.best_for_family(PlanType::OwnCapital, base_min, own_max, input));
        }
        if flash_max >= base_min {
            candidates.push(self.best_for_family(PlanType::Flashloan, base_min, flash_max, input));
        }
        if hybrid_max >= base_min {
            candidates.push(self.best_for_family(PlanType::Hybrid, base_min, hybrid_max, input));
        }

        let best_plan = candidates
            .iter()
            .filter(|c| c.score.expected_net_wei > I256::ZERO)
            .max_by(|a, b| a.score.expected_net_wei.cmp(&b.score.expected_net_wei))
            .cloned();

        let rejection_reason = if best_plan.is_none() {
            Some("net_negative_after_buffers".to_string())
        } else {
            None
        };

        DecisionTrace {
            best_plan,
            candidates,
            rejection_reason,
        }
    }

    fn best_for_family(
        &self,
        plan_type: PlanType,
        min_size: U256,
        max_size: U256,
        input: &PlannerInput,
    ) -> PlanCandidate {
        let ladder = self.build_ladder(min_size, max_size);
        let mut best: Option<PlanCandidate> = None;
        let mut declines = 0usize;
        let mut previous_expected: Option<I256> = None;

        for size in ladder {
            let score = self.score_candidate(plan_type, size, input);
            let candidate = PlanCandidate {
                plan_type,
                size_wei: size,
                rejected_reason: if score.expected_net_wei <= I256::ZERO {
                    Some("net_negative_after_buffers".to_string())
                } else {
                    None
                },
                score,
            };

            if let Some(prev) = previous_expected {
                let marginal = candidate.score.expected_net_wei - prev;
                if marginal <= I256::ZERO {
                    declines = declines.saturating_add(1);
                } else {
                    declines = 0;
                }
                if marginal >= I256::ZERO && marginal <= i256_from_u256(self.marginal_epsilon_wei) {
                    break;
                }
                if declines >= self.k_consecutive_declines {
                    break;
                }
            }
            previous_expected = Some(candidate.score.expected_net_wei);

            match &best {
                Some(current)
                    if current.score.expected_net_wei >= candidate.score.expected_net_wei => {}
                _ => best = Some(candidate),
            }
        }

        best.unwrap_or_else(|| PlanCandidate {
            plan_type,
            size_wei: min_size,
            score: self.score_candidate(plan_type, min_size, input),
            rejected_reason: Some("no_feasible_size".to_string()),
        })
    }

    fn build_ladder(&self, min_size: U256, max_size: U256) -> Vec<U256> {
        if max_size <= min_size {
            return vec![min_size];
        }
        let steps = self.ladder_steps.max(2);
        let span = max_size.saturating_sub(min_size);
        let mut out = Vec::with_capacity(steps + 1);
        for i in 0..=steps {
            let step = span
                .saturating_mul(U256::from(i as u64))
                .checked_div(U256::from(steps as u64))
                .unwrap_or(U256::ZERO);
            out.push(min_size.saturating_add(step));
        }
        out.sort();
        out.dedup();
        out
    }

    fn score_candidate(&self, plan_type: PlanType, size: U256, input: &PlannerInput) -> PlanScore {
        let plan_complexity_bps = match plan_type {
            PlanType::OwnCapital => 0u64,
            PlanType::Flashloan => 45,
            PlanType::Hybrid => 28,
        };
        let plan_failure_penalty_bps = match plan_type {
            PlanType::OwnCapital => 100u64,
            PlanType::Flashloan => 300,
            PlanType::Hybrid => 220,
        };
        let gross_edge_bps = self.estimated_edge_bps(size, input);
        let gross_profit = size
            .saturating_mul(U256::from(gross_edge_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(U256::ZERO);

        let dynamic_profit_floor = input
            .gas_cost_estimate
            .saturating_mul(U256::from(
                10_000u64.saturating_add(input.safety_margin_bps),
            ))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(input.gas_cost_estimate)
            .saturating_add(
                input
                    .gas_cost_estimate
                    .saturating_mul(U256::from(input.uncertainty_bps))
                    .checked_div(U256::from(10_000u64))
                    .unwrap_or(U256::ZERO),
            );

        let complexity_cost = size
            .saturating_mul(U256::from(plan_complexity_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(U256::ZERO);

        let profit_if_included = i256_from_u256(gross_profit)
            - i256_from_u256(dynamic_profit_floor)
            - i256_from_u256(complexity_cost);

        let cost_if_failed = input
            .gas_cost_estimate
            .saturating_add(complexity_cost)
            .saturating_add(
                input
                    .gas_cost_estimate
                    .saturating_mul(U256::from(plan_failure_penalty_bps))
                    .checked_div(U256::from(10_000u64))
                    .unwrap_or(U256::ZERO),
            );

        let inclusion_probability_bps = self.inclusion_probability_bps(plan_type, input);
        let inclusion = I256::from_raw(U256::from(inclusion_probability_bps));
        let exclusion = I256::from_raw(U256::from(
            10_000u64.saturating_sub(inclusion_probability_bps),
        ));

        let expected_net = (profit_if_included * inclusion
            - i256_from_u256(cost_if_failed) * exclusion)
            / I256::from_raw(U256::from(10_000u64));

        PlanScore {
            expected_net_wei: expected_net,
            profit_if_included_wei: profit_if_included,
            cost_if_failed_wei: cost_if_failed,
            inclusion_probability_bps,
            dynamic_profit_floor_wei: dynamic_profit_floor,
        }
    }

    fn estimated_edge_bps(&self, size: U256, input: &PlannerInput) -> u64 {
        if size.is_zero() {
            return 0;
        }
        let victim = input.victim_value.max(U256::from(1u64));
        let ratio_bps = size
            .saturating_mul(U256::from(10_000u64))
            .checked_div(victim.saturating_add(size))
            .unwrap_or(U256::from(10_000u64));
        let ratio = ratio_bps.to::<u64>();
        let slippage_penalty = input.slippage_bps.min(9_500) / 6;
        380u64
            .saturating_sub(ratio / 30)
            .saturating_sub(slippage_penalty)
            .clamp(15, 500)
    }

    fn inclusion_probability_bps(&self, plan_type: PlanType, input: &PlannerInput) -> u64 {
        let base = match plan_type {
            PlanType::OwnCapital => 8_400u64,
            PlanType::Flashloan => 7_900,
            PlanType::Hybrid => 8_050,
        };
        let slip_penalty = input.slippage_bps.min(2_000) / 3;
        let uncertainty_penalty = input.uncertainty_bps.min(2_500) / 2;
        base.saturating_sub(slip_penalty)
            .saturating_sub(uncertainty_penalty)
            .clamp(1_000, 9_900)
    }
}

fn i256_from_u256(value: U256) -> I256 {
    if value > U256::from(i128::MAX as u128) {
        I256::from_raw(U256::from(i128::MAX as u128))
    } else {
        I256::from_raw(U256::from(value.to::<u128>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PlannerInput {
        PlannerInput {
            wallet_balance: U256::from(100_000_000_000_000_000u128),
            victim_value: U256::from(50_000_000_000_000_000u128),
            gas_cost_estimate: U256::from(200_000_000_000_000u64),
            has_wrapped_path: true,
            flashloan_available: true,
            allow_hybrid: true,
            base_trade_hint: U256::from(15_000_000_000_000_000u64),
            min_size: U256::from(1_000_000_000_000_000u64),
            max_size: U256::from(150_000_000_000_000_000u128),
            slippage_bps: 120,
            safety_margin_bps: 800,
            uncertainty_bps: 400,
        }
    }

    #[test]
    fn planner_returns_deterministic_best_plan() {
        let planner = ExecutionPlanner::default();
        let decision = planner.plan(&input());
        assert!(!decision.candidates.is_empty());
        assert!(decision.best_plan.is_some());
    }

    #[test]
    fn planner_rejects_when_everything_is_negative() {
        let planner = ExecutionPlanner::default();
        let mut i = input();
        i.gas_cost_estimate = U256::from(50_000_000_000_000_000u128);
        let decision = planner.plan(&i);
        assert!(decision.best_plan.is_none());
        assert_eq!(
            decision.rejection_reason.as_deref(),
            Some("net_negative_after_buffers")
        );
    }
}
