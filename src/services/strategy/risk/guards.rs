// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::constants::MIN_PROFIT_THRESHOLD_WEI;
use crate::common::error::AppError;
use crate::network::gas::GasFees;
use crate::services::strategy::decode::{
    ObservedSwap, RouterKind, encode_v3_path, reverse_v3_path,
};
use crate::services::strategy::strategy::{StrategyExecutor, VICTIM_FEE_BUMP_BPS};
use alloy::primitives::{I256, U256};
use std::ops::Neg;

impl StrategyExecutor {
    pub(crate) fn price_ratio_ppm(amount_out: U256, amount_in: U256) -> U256 {
        if amount_in.is_zero() {
            return U256::ZERO;
        }
        amount_out.saturating_mul(U256::from(1_000_000u64)) / amount_in
    }

    #[cfg(test)]
    pub(crate) fn test_price_ratio_ppm_public(out: U256, inn: U256) -> U256 {
        Self::price_ratio_ppm(out, inn)
    }

    pub(crate) fn dynamic_profit_floor(wallet_balance: U256) -> U256 {
        let abs_floor = *MIN_PROFIT_THRESHOLD_WEI;
        let scaled = wallet_balance
            .checked_div(U256::from(100_000u64))
            .unwrap_or(U256::ZERO);
        if scaled > abs_floor {
            scaled
        } else {
            abs_floor
        }
    }

    /// Minimum profit that accounts for current gas/bribe costs plus a small safety margin.
    /// Uses fee history–derived gas_cost_wei supplied by the caller; extra_costs can include
    /// executor bribes and flash‑loan premiums.
    pub(crate) fn dynamic_profit_floor_with_costs(
        wallet_balance: U256,
        gas_cost_wei: U256,
        extra_costs: U256,
    ) -> U256 {
        // 10% margin over observed gas cost to guard against basefee drift between simulation and inclusion.
        let gas_margin = gas_cost_wei
            .saturating_mul(U256::from(110u64))
            .checked_div(U256::from(100u64))
            .unwrap_or(gas_cost_wei);

        let cost_floor = gas_margin.saturating_add(extra_costs);
        Self::dynamic_profit_floor(wallet_balance).max(cost_floor)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_profit_floor_public(balance: U256) -> U256 {
        Self::dynamic_profit_floor(balance)
    }

    pub(crate) fn boost_fees(
        &self,
        fees: &mut GasFees,
        victim_max_fee: Option<u128>,
        victim_tip: Option<u128>,
    ) {
        // Start from recent percentiles instead of static buckets.
        let tip_p50 = fees
            .p50_priority_fee_per_gas
            .unwrap_or(fees.max_priority_fee_per_gas);
        let tip_p90 = fees.p90_priority_fee_per_gas.unwrap_or(tip_p50);

        // Congestion factor from average utilisation (target 1.0). Clamp to sane bounds.
        let util = fees.gas_used_ratio.unwrap_or(1.0);
        let congestion_bps: u64 = if util > 1.1 {
            11500
        } else if util > 1.0 {
            11000
        } else if util > 0.95 {
            10500
        } else {
            10200
        };

        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        // -0.1 ETH threshold approx in I256
        let neg_threshold = I256::from_raw(U256::from(100_000_000_000_000_000u128)).neg();
        let mut boost_bps = congestion_bps;
        if pnl < neg_threshold {
            boost_bps = (boost_bps as f64 * 0.85) as u64;
        } else if pnl.is_positive() {
            boost_bps = (boost_bps as f64 * 1.05) as u64;
        }
        boost_bps = boost_bps.clamp(10100, 14500);

        // Anchor tips to recent p90, then apply boost.
        let tip_floor = tip_p90.max(tip_p50);
        let boosted_tip = tip_floor.saturating_mul(boost_bps as u128) / 10_000u128;

        // Keep max_fee aligned to next_base + boosted tip; allow victim hints to pull higher.
        let min_fee = fees
            .next_base_fee_per_gas
            .max(fees.base_fee_per_gas)
            .saturating_add(boosted_tip);
        let mut max_fee = fees.max_fee_per_gas.max(min_fee);
        let mut max_tip = fees.max_priority_fee_per_gas.max(boosted_tip);

        if let Some(v_fee) = victim_max_fee {
            let fee_target = v_fee.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            max_fee = max_fee.max(fee_target);
        }
        if let Some(v_tip) = victim_tip {
            let tip_target = v_tip.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            max_tip = max_tip.max(tip_target);
        }

        // Respect dynamic cap if provided by GasOracle to avoid runaway bids.
        if let Some(cap) = fees.suggested_max_fee_per_gas {
            if max_fee > cap {
                max_fee = cap;
            }
        }

        fees.max_priority_fee_per_gas = max_tip;
        fees.max_fee_per_gas = max_fee.max(
            fees.base_fee_per_gas
                .saturating_add(fees.max_priority_fee_per_gas),
        );

        if let Some(v_fee) = victim_max_fee {
            let fee_target = v_fee.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            fees.max_fee_per_gas = fees.max_fee_per_gas.max(fee_target);
        }
        if let Some(v_tip) = victim_tip {
            let tip_target = v_tip.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            fees.max_priority_fee_per_gas = fees.max_priority_fee_per_gas.max(tip_target);
        }
    }

    pub(crate) fn gas_ratio_ok(
        &self,
        gas_cost_wei: U256,
        gross_profit_wei: U256,
        wallet_balance: U256,
    ) -> bool {
        if gas_cost_wei.is_zero() {
            return !gross_profit_wei.is_zero();
        }
        if gross_profit_wei <= gas_cost_wei {
            return false;
        }
        let margin = gross_profit_wei.saturating_sub(gas_cost_wei);
        let min_margin = gas_cost_wei.saturating_mul(U256::from(1_200u64)) / U256::from(10_000u64);
        if margin < min_margin {
            return false;
        }
        if gross_profit_wei.is_zero() {
            return false;
        }
        let limit = self.dynamic_gas_ratio_limit(wallet_balance);
        gas_cost_wei.saturating_mul(U256::from(10_000u64))
            <= gross_profit_wei.saturating_mul(U256::from(limit))
    }

    pub(crate) fn dynamic_backrun_value(
        observed_in: U256,
        wallet_balance: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        max_fee_per_gas: u128,
    ) -> Result<U256, AppError> {
        let mut value =
            observed_in.saturating_mul(U256::from(slippage_bps)) / U256::from(10_000u64);

        // Ensure the trade value at least covers expected burn + typical bribe/premium.
        let gas_floor =
            U256::from(gas_limit_hint.max(210_000)).saturating_mul(U256::from(max_fee_per_gas));
        // 5% headroom to absorb basefee drift.
        let min_backrun = gas_floor
            .saturating_mul(U256::from(105u64))
            .checked_div(U256::from(100u64))
            .unwrap_or(gas_floor);
        if value < min_backrun {
            value = min_backrun;
        }

        let (max_divisor, gas_buffer_divisor) = Self::backrun_divisors(wallet_balance);
        let mut max_value = wallet_balance
            .checked_div(U256::from(max_divisor))
            .unwrap_or(wallet_balance);
        let gas_buffer =
            U256::from(max_fee_per_gas).saturating_mul(U256::from(gas_limit_hint.max(210_000)));
        if gas_buffer > wallet_balance / U256::from(gas_buffer_divisor) {
            max_value = wallet_balance
                .checked_div(U256::from(gas_buffer_divisor))
                .unwrap_or(wallet_balance);
        }
        if value > max_value {
            value = max_value;
        }
        if value.is_zero() {
            return Err(AppError::Strategy(
                "Backrun value is zero after caps".into(),
            ));
        }
        Ok(value)
    }

    pub(crate) async fn pool_backrun_value(
        &self,
        observed: &ObservedSwap,
        wallet_balance: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        gas_fees: &GasFees,
    ) -> Result<Option<U256>, AppError> {
        let gas_floor = U256::from(gas_limit_hint.max(210_000))
            .saturating_mul(U256::from(gas_fees.max_fee_per_gas));
        let min_backrun = gas_floor
            .saturating_mul(U256::from(105u64))
            .checked_div(U256::from(100u64))
            .unwrap_or(gas_floor);
        let mut base = observed
            .amount_in
            .saturating_mul(U256::from(slippage_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(U256::ZERO);
        base = base.max(min_backrun);

        let (max_divisor, gas_buffer_divisor) = Self::backrun_divisors(wallet_balance);
        let mut max_value = wallet_balance
            .checked_div(U256::from(max_divisor))
            .unwrap_or(wallet_balance);
        let gas_buffer = U256::from(gas_fees.max_fee_per_gas)
            .saturating_mul(U256::from(gas_limit_hint.max(210_000)));
        if gas_buffer > wallet_balance / U256::from(gas_buffer_divisor) {
            max_value = wallet_balance
                .checked_div(U256::from(gas_buffer_divisor))
                .unwrap_or(wallet_balance);
        }
        if max_value < min_backrun {
            max_value = min_backrun;
        }
        if base > max_value {
            base = max_value;
        }

        let fee_limit = gas_limit_hint.saturating_add(80_000).max(210_000);
        let gas_cost = U256::from(fee_limit).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
        let bribe = if self.executor_bribe_bps > 0 {
            let base_gas =
                U256::from(fee_limit).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
            base_gas
                .saturating_mul(U256::from(self.executor_bribe_bps))
                .checked_div(U256::from(10_000u64))
                .unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };
        let overhead_cost = gas_cost.saturating_add(bribe);

        let mut candidates = vec![base];
        let mut current = base;
        for _ in 0..4 {
            let next = current
                .saturating_mul(U256::from(3))
                .checked_div(U256::from(2))
                .unwrap_or(max_value);
            if next > max_value {
                break;
            }
            if next <= current {
                break;
            }
            candidates.push(next);
            current = next;
        }
        if max_value > *candidates.last().unwrap_or(&U256::ZERO) {
            candidates.push(max_value);
        }

        let mut best_value: Option<U256> = None;
        let mut best_margin = U256::ZERO;
        for candidate in candidates {
            if candidate.is_zero() {
                continue;
            }
            let round_trip = match self.pool_round_trip_weth(observed, candidate).await {
                Some(v) => v,
                None => continue,
            };
            if round_trip <= candidate {
                continue;
            }
            let profit = round_trip.saturating_sub(candidate);
            if profit <= overhead_cost {
                continue;
            }
            let margin = profit.saturating_sub(overhead_cost);
            if margin > best_margin {
                best_margin = margin;
                best_value = Some(candidate);
            }
        }

        Ok(best_value)
    }

    async fn pool_round_trip_weth(&self, observed: &ObservedSwap, amount: U256) -> Option<U256> {
        match observed.router_kind {
            RouterKind::V2Like => {
                let path = observed.path.clone();
                let tokens_out = self.reserve_cache.quote_v2_path(&path, amount)?;
                if tokens_out.is_zero() {
                    return None;
                }
                let rev_path: Vec<_> = path.iter().copied().rev().collect();
                self.reserve_cache.quote_v2_path(&rev_path, tokens_out)
            }
            RouterKind::V3Like => {
                let path_bytes = if let Some(bytes) = observed.v3_path.clone() {
                    bytes
                } else {
                    encode_v3_path(&observed.path, &observed.v3_fees)?
                };
                let tokens_out = self.quote_v3_path(&path_bytes, amount).await.ok()?;
                let rev_bytes = reverse_v3_path(&observed.path, &observed.v3_fees)?;
                self.quote_v3_path(&rev_bytes, tokens_out).await.ok()
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_backrun_value_public(
        observed_in: U256,
        wallet_balance: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        max_fee_per_gas: u128,
    ) -> Result<U256, AppError> {
        Self::dynamic_backrun_value(
            observed_in,
            wallet_balance,
            slippage_bps,
            gas_limit_hint,
            max_fee_per_gas,
        )
    }

    pub(crate) fn backrun_divisors(wallet_balance: U256) -> (u64, u64) {
        let thresholds = [
            (U256::from(100_000_000_000_000_000u128), (4u64, 6u64)), // <0.1 ETH
            (U256::from(500_000_000_000_000_000u128), (3u64, 5u64)), // <0.5 ETH
            (U256::from(2_000_000_000_000_000_000u128), (2u64, 4u64)), // <2 ETH
        ];
        for (limit, divisors) in thresholds {
            if wallet_balance < limit {
                return divisors;
            }
        }
        (2, 3)
    }

    #[cfg(test)]
    pub(crate) fn test_backrun_divisors_public(wallet_balance: U256) -> (u64, u64) {
        Self::backrun_divisors(wallet_balance)
    }

    pub(crate) fn dynamic_gas_ratio_limit(&self, wallet_balance: U256) -> u64 {
        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        let base = if wallet_balance < U256::from(100_000_000_000_000_000u128) {
            5000
        } else if wallet_balance < U256::from(500_000_000_000_000_000u128) {
            6500
        } else if wallet_balance < U256::from(2_000_000_000_000_000_000u128) {
            8000
        } else {
            9000
        };

        // Convert U256 PnL thresholds to I256 for comparison
        let neg_0_05 = I256::from_raw(U256::from(50_000_000_000_000_000u128)).neg();
        let pos_0_2 = I256::from_raw(U256::from(200_000_000_000_000_000u128));

        if pnl < neg_0_05 {
            (base * 85 / 100).max(3500) // tighten 15%
        } else if pnl.is_negative() {
            (base * 92 / 100).max(4000) // tighten 8%
        } else if pnl > pos_0_2 {
            (base * 105 / 100).min(9500)
        } else {
            base
        }
    }
}
