// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::constants::MIN_PROFIT_THRESHOLD_WEI;
use crate::common::error::AppError;
use crate::network::gas::GasFees;
use crate::services::strategy::decode::{
    ObservedSwap, RouterKind, encode_v3_path, reverse_v3_path,
};
use crate::services::strategy::strategy::{StrategyExecutor, VICTIM_FEE_BUMP_BPS};
use alloy::primitives::{I256, U256};
use std::ops::Neg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StressProfile {
    UltraLow,
    Low,
    Normal,
    Elevated,
    High,
}

impl StressProfile {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StressProfile::UltraLow => "ultra_low",
            StressProfile::Low => "low",
            StressProfile::Normal => "normal",
            StressProfile::Elevated => "elevated",
            StressProfile::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CalibratedRiskProfile {
    pub stress: StressProfile,
    pub base_floor_bps: u64,
    pub cost_floor_bps: u64,
    pub min_margin_bps: u64,
    pub liquidity_ratio_floor_ppm: u64,
}

impl StrategyExecutor {
    fn balance_to_eth_f64(balance: U256) -> f64 {
        let num = balance.to_string().parse::<f64>().unwrap_or(0.0);
        num / 1e18f64
    }

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

    fn dynamic_profit_floor_with_abs(wallet_balance: U256, abs_floor: U256) -> U256 {
        let scaled = wallet_balance
            .checked_div(U256::from(100_000u64))
            .unwrap_or(U256::ZERO);
        if scaled > abs_floor {
            scaled
        } else {
            abs_floor
        }
    }

    fn configured_abs_floor(&self) -> U256 {
        self.profit_floor_abs_wei
    }

    fn configured_dynamic_floor(&self, wallet_balance: U256) -> U256 {
        Self::dynamic_profit_floor_with_abs(wallet_balance, self.configured_abs_floor())
    }

    pub(crate) fn dynamic_profit_floor(wallet_balance: U256) -> U256 {
        Self::dynamic_profit_floor_with_abs(wallet_balance, *MIN_PROFIT_THRESHOLD_WEI)
    }

    /// Minimum profit that accounts for current gas/bribe costs plus a small safety margin.
    /// Uses fee history–derived gas_cost_wei supplied by the caller; extra_costs can include
    /// executor bribes and flash‑loan premiums.
    #[cfg(test)]
    pub(crate) fn dynamic_profit_floor_with_costs(
        wallet_balance: U256,
        gas_cost_wei: U256,
        extra_costs: U256,
    ) -> U256 {
        let base_floor = Self::dynamic_profit_floor(wallet_balance);
        let cost_basis = gas_cost_wei.saturating_add(extra_costs);
        // Mainnet-first safety floor: require recovery of direct execution costs
        // (gas + bribe/premium) in addition to baseline profit.
        base_floor.saturating_add(cost_basis)
    }

    pub(crate) fn tuned_profit_floor_with_costs(
        &self,
        wallet_balance: U256,
        gas_cost_wei: U256,
        extra_costs: U256,
        gas_fees: &GasFees,
    ) -> U256 {
        let base_bps = self.adaptive_base_floor_bps(gas_fees);
        let cost_bps = self.adaptive_cost_floor_bps(gas_fees);
        let base_floor = self.configured_dynamic_floor(wallet_balance);
        let scaled_base = base_floor
            .saturating_mul(U256::from(base_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(base_floor);

        let cost_basis = gas_cost_wei.saturating_add(extra_costs);
        let scaled_cost = cost_basis
            .saturating_mul(U256::from(cost_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(cost_basis);

        scaled_base.saturating_add(scaled_cost)
    }

    pub(crate) fn dynamic_policy_profit_floor_with_costs(
        &self,
        wallet_balance: U256,
        gas_cost_wei: U256,
        extra_costs: U256,
        gas_fees: &GasFees,
        min_usd_floor_wei: Option<U256>,
    ) -> U256 {
        let tuned_floor =
            self.tuned_profit_floor_with_costs(wallet_balance, gas_cost_wei, extra_costs, gas_fees);
        let abs_or_scaled = self.configured_dynamic_floor(wallet_balance);
        let gas_mult_floor = gas_cost_wei
            .saturating_mul(U256::from(self.profit_floor_mult_gas))
            .saturating_add(extra_costs);
        let volatility_bps = self
            .price_feed
            .volatility_bps_cached("ETH")
            .unwrap_or(0)
            .min(2_000);
        let volatility_guard = gas_cost_wei
            .saturating_add(extra_costs)
            .saturating_mul(U256::from(10_000u64.saturating_add(volatility_bps)))
            .checked_div(U256::from(10_000u64))
            .unwrap_or_else(|| gas_cost_wei.saturating_add(extra_costs));
        let usd_guard = min_usd_floor_wei.unwrap_or(U256::ZERO);
        tuned_floor
            .max(abs_or_scaled)
            .max(gas_mult_floor)
            .max(volatility_guard)
            .max(usd_guard)
    }

    pub(crate) fn classify_stress_profile(&self, gas_fees: &GasFees) -> StressProfile {
        let base = gas_fees
            .next_base_fee_per_gas
            .max(gas_fees.base_fee_per_gas);
        let base_gwei = (base as f64) / 1e9f64;
        let util = gas_fees.gas_used_ratio.unwrap_or(0.75);
        let tip_p50 = gas_fees
            .p50_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas)
            .max(1);
        let tip_p90 = gas_fees
            .p90_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas)
            .max(tip_p50);
        let tip_spread_x100 = tip_p90.saturating_mul(100) / tip_p50.max(1);

        let mut score: i32 = if base_gwei <= 0.15 {
            0
        } else if base_gwei <= 2.0 {
            1
        } else if base_gwei <= 20.0 {
            2
        } else if base_gwei <= 60.0 {
            3
        } else {
            4
        };
        if util > 1.12 {
            score += 2;
        } else if util > 0.98 {
            score += 1;
        } else if util < 0.55 {
            score -= 1;
        }
        if tip_spread_x100 > 4_000 {
            score += 1;
        } else if tip_spread_x100 < 900 {
            score -= 1;
        }
        match score.clamp(0, 4) {
            0 => StressProfile::UltraLow,
            1 => StressProfile::Low,
            2 => StressProfile::Normal,
            3 => StressProfile::Elevated,
            _ => StressProfile::High,
        }
    }

    fn congestion_factor_bps(&self, gas_fees: &GasFees) -> u64 {
        let profile = self.classify_stress_profile(gas_fees);
        let util = gas_fees.gas_used_ratio.unwrap_or(0.7);
        let tip_p50 = gas_fees
            .p50_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas)
            .max(1);
        let tip_p90 = gas_fees
            .p90_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas)
            .max(tip_p50);
        let tip_spread_x100 = tip_p90.saturating_mul(100) / tip_p50.max(1);
        let mut bps: i64 = match profile {
            StressProfile::UltraLow => 9_800,
            StressProfile::Low => 10_000,
            StressProfile::Normal => 10_600,
            StressProfile::Elevated => 11_600,
            StressProfile::High => 12_800,
        };
        if util > 1.05 {
            bps += 1_200;
        } else if util > 0.95 {
            bps += 700;
        } else if util < 0.55 {
            bps -= 900;
        } else if util < 0.70 {
            bps -= 500;
        }
        if tip_spread_x100 > 5_000 {
            bps += 900;
        } else if tip_spread_x100 > 2_500 {
            bps += 500;
        } else if tip_spread_x100 < 800 {
            bps -= 400;
        }
        let base = gas_fees.base_fee_per_gas.max(1);
        if gas_fees.next_base_fee_per_gas > base.saturating_mul(112) / 100 {
            bps += 400;
        } else if gas_fees.next_base_fee_per_gas < base.saturating_mul(95) / 100 {
            bps -= 250;
        }
        match profile {
            StressProfile::UltraLow => bps = bps.max(9_500),
            StressProfile::Low => bps = bps.max(9_700),
            StressProfile::Normal => bps = bps.max(10_000),
            StressProfile::Elevated => bps = bps.max(11_000),
            StressProfile::High => bps = bps.max(12_000),
        }
        bps.clamp(9_000, 16_000) as u64
    }

    pub(crate) fn calibrated_risk_profile(&self, gas_fees: &GasFees) -> CalibratedRiskProfile {
        let stress = self.classify_stress_profile(gas_fees);
        let congestion = self.congestion_factor_bps(gas_fees);
        let base_floor_bps = {
            let dynamic = self
                .profit_guard_base_floor_multiplier_bps
                .saturating_mul(congestion)
                / 10_000u64;
            let floor = match stress {
                StressProfile::UltraLow => 9_000,
                StressProfile::Low => 9_500,
                StressProfile::Normal => 10_000,
                StressProfile::Elevated => 10_750,
                StressProfile::High => 11_500,
            };
            dynamic.max(floor).clamp(8_000, 14_000)
        };
        let cost_floor_bps = {
            let extra = match stress {
                StressProfile::UltraLow => 9_800,
                StressProfile::Low => 9_950,
                StressProfile::Normal => 10_150,
                StressProfile::Elevated => 10_550,
                StressProfile::High => 10_900,
            };
            let dynamic = self
                .profit_guard_cost_multiplier_bps
                .max(9_500)
                .saturating_mul(extra)
                / 10_000u64;
            dynamic.clamp(9_500, 16_000)
        };
        let min_margin_bps = {
            let dynamic = self.profit_guard_min_margin_bps.saturating_mul(congestion) / 10_000u64;
            let floor = match stress {
                StressProfile::UltraLow => 450,
                StressProfile::Low => 550,
                StressProfile::Normal => 750,
                StressProfile::Elevated => 950,
                StressProfile::High => 1_150,
            };
            dynamic.max(floor).clamp(200, 3_000)
        };
        let liquidity_ratio_floor_ppm = {
            let dynamic = self.liquidity_ratio_floor_ppm.saturating_mul(congestion) / 10_000u64;
            let floor = match stress {
                StressProfile::UltraLow => 450,
                StressProfile::Low => 550,
                StressProfile::Normal => 700,
                StressProfile::Elevated => 850,
                StressProfile::High => 1_000,
            };
            dynamic.max(floor).clamp(220, 1_800)
        };
        CalibratedRiskProfile {
            stress,
            base_floor_bps,
            cost_floor_bps,
            min_margin_bps,
            liquidity_ratio_floor_ppm,
        }
    }

    pub(crate) fn adaptive_base_floor_bps(&self, gas_fees: &GasFees) -> u64 {
        self.calibrated_risk_profile(gas_fees).base_floor_bps
    }

    pub(crate) fn adaptive_cost_floor_bps(&self, gas_fees: &GasFees) -> u64 {
        self.calibrated_risk_profile(gas_fees).cost_floor_bps
    }

    pub(crate) fn adaptive_min_margin_bps(&self, gas_fees: &GasFees) -> u64 {
        self.calibrated_risk_profile(gas_fees).min_margin_bps
    }

    pub(crate) fn adaptive_liquidity_ratio_floor_ppm(&self, gas_fees: &GasFees) -> u64 {
        self.calibrated_risk_profile(gas_fees)
            .liquidity_ratio_floor_ppm
    }

    pub(crate) fn adaptive_sell_min_native_out_wei(&self, gas_fees: &GasFees) -> U256 {
        let stress_mult_bps = match self.classify_stress_profile(gas_fees) {
            StressProfile::UltraLow => 9_800,
            StressProfile::Low => 10_000,
            StressProfile::Normal => 10_800,
            StressProfile::Elevated => 11_800,
            StressProfile::High => 12_500,
        };
        let scaled_base = U256::from(self.sell_min_native_out_wei)
            .saturating_mul(U256::from(stress_mult_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or_else(|| U256::from(self.sell_min_native_out_wei));
        let fee = gas_fees
            .next_base_fee_per_gas
            .max(gas_fees.base_fee_per_gas)
            .saturating_add(
                gas_fees
                    .p50_priority_fee_per_gas
                    .unwrap_or(gas_fees.max_priority_fee_per_gas),
            );
        let gas_ref = U256::from(170_000u64).saturating_mul(U256::from(fee));
        let dynamic_floor = gas_ref
            .saturating_mul(U256::from(25u64))
            .checked_div(U256::from(100u64))
            .unwrap_or(gas_ref);
        scaled_base.max(dynamic_floor)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_profit_floor_public(balance: U256) -> U256 {
        Self::dynamic_profit_floor(balance)
    }

    #[cfg(test)]
    pub(crate) fn test_dynamic_policy_profit_floor_public(
        &self,
        wallet_balance: U256,
        gas_cost_wei: U256,
        extra_costs: U256,
        gas_fees: &GasFees,
        min_usd_floor_wei: Option<U256>,
    ) -> U256 {
        self.dynamic_policy_profit_floor_with_costs(
            wallet_balance,
            gas_cost_wei,
            extra_costs,
            gas_fees,
            min_usd_floor_wei,
        )
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

        let base_anchor = fees.next_base_fee_per_gas.max(fees.base_fee_per_gas);

        // Keep max_fee aligned to next_base + boosted tip; allow victim hints to pull higher.
        let min_fee = base_anchor.saturating_add(boosted_tip);
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

        // Suggested cap may be stale/low on some providers; never allow it to dip below base fee.
        let effective_cap = fees
            .suggested_max_fee_per_gas
            .map(|cap| cap.max(base_anchor));
        if let Some(cap) = effective_cap {
            max_fee = max_fee.min(cap);
        }

        // Keep tip bounded by available headroom under max_fee.
        let max_tip_under_fee = max_fee.saturating_sub(base_anchor);
        max_tip = max_tip.min(max_tip_under_fee);

        // Preserve invariant: max_fee >= base + tip while still respecting cap.
        max_fee = base_anchor.saturating_add(max_tip);
        if let Some(cap) = effective_cap {
            max_fee = max_fee.min(cap);
        }

        fees.max_priority_fee_per_gas = max_tip;
        fees.max_fee_per_gas = max_fee;
    }

    pub(crate) fn gas_ratio_ok_with_fees(
        &self,
        gas_cost_wei: U256,
        gross_profit_wei: U256,
        wallet_balance: U256,
        gas_fees: &GasFees,
    ) -> bool {
        if gas_cost_wei.is_zero() {
            return !gross_profit_wei.is_zero();
        }
        if gross_profit_wei <= gas_cost_wei {
            return false;
        }
        let margin = gross_profit_wei.saturating_sub(gas_cost_wei);
        let min_margin = gas_cost_wei
            .saturating_mul(U256::from(self.adaptive_min_margin_bps(gas_fees)))
            / U256::from(10_000u64);
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
        let eth_balance = Self::balance_to_eth_f64(wallet_balance).max(0.0001);
        // Low-balance wallets were previously over-capped (often wallet/6), producing
        // tiny opportunities that fail the gas-vs-gross gate. Relax divisors so backrun
        // sizing can reach profitable notional while still reserving gas headroom.
        if eth_balance < 0.01 {
            return (3, 4);
        }
        if eth_balance < 0.03 {
            return (3, 5);
        }
        let raw = 6.0 - 2.0 * (eth_balance * 100.0 + 1.0).log10();
        let max_div = raw.round().clamp(2.0, 6.0) as u64;
        let gas_div = if max_div <= 2 {
            3
        } else {
            (max_div + 2).min(6)
        };
        (max_div, gas_div)
    }

    #[cfg(test)]
    pub(crate) fn test_backrun_divisors_public(wallet_balance: U256) -> (u64, u64) {
        Self::backrun_divisors(wallet_balance)
    }

    pub(crate) fn dynamic_gas_ratio_limit(&self, wallet_balance: U256) -> u64 {
        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        let eth_balance = Self::balance_to_eth_f64(wallet_balance).max(0.0001);
        let base = 5000.0 + 1500.0 * (eth_balance * 100.0 + 1.0).log10();
        let mut base = base.round().clamp(4500.0, 9000.0) as u64;

        // Convert U256 PnL thresholds to I256 for comparison
        let neg_0_05 = I256::from_raw(U256::from(50_000_000_000_000_000u128)).neg();
        let pos_0_2 = I256::from_raw(U256::from(200_000_000_000_000_000u128));

        if pnl < neg_0_05 {
            base = (base * 85 / 100).max(3500); // tighten 15%
        } else if pnl.is_negative() {
            base = (base * 92 / 100).max(4000); // tighten 8%
        } else if pnl > pos_0_2 {
            base = (base * 105 / 100).min(9500);
        }
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::gas::GasFees;
    use crate::services::strategy::execution::strategy::dummy_executor_for_tests;

    #[test]
    fn dynamic_profit_floor_with_costs_keeps_base_floor_when_costs_zero() {
        let wallet_balance = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
        let floor = StrategyExecutor::dynamic_profit_floor_with_costs(
            wallet_balance,
            U256::ZERO,
            U256::ZERO,
        );
        assert_eq!(
            floor,
            StrategyExecutor::dynamic_profit_floor(wallet_balance)
        );
    }

    #[test]
    fn dynamic_profit_floor_with_costs_adds_full_execution_costs() {
        let wallet_balance = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
        let gas = U256::from(2_000_000_000_000_000u128); // 0.002 ETH
        let extra = U256::from(1_000_000_000_000_000u128); // 0.001 ETH
        let floor = StrategyExecutor::dynamic_profit_floor_with_costs(wallet_balance, gas, extra);
        let base = StrategyExecutor::dynamic_profit_floor(wallet_balance);
        let expected_buffer = gas.saturating_add(extra);
        assert_eq!(floor, base.saturating_add(expected_buffer));
    }

    #[tokio::test]
    async fn stress_profile_auto_calibration_scales_with_congestion() {
        let exec = dummy_executor_for_tests().await;
        let ultra_low = GasFees {
            max_fee_per_gas: 50_000_000,
            max_priority_fee_per_gas: 8_000_000,
            next_base_fee_per_gas: 40_000_000,
            base_fee_per_gas: 35_000_000,
            p50_priority_fee_per_gas: Some(7_000_000),
            p90_priority_fee_per_gas: Some(9_000_000),
            gas_used_ratio: Some(0.42),
            suggested_max_fee_per_gas: Some(55_000_000),
        };
        let high = GasFees {
            max_fee_per_gas: 180_000_000_000,
            max_priority_fee_per_gas: 6_000_000_000,
            next_base_fee_per_gas: 160_000_000_000,
            base_fee_per_gas: 145_000_000_000,
            p50_priority_fee_per_gas: Some(5_000_000_000),
            p90_priority_fee_per_gas: Some(12_000_000_000),
            gas_used_ratio: Some(1.18),
            suggested_max_fee_per_gas: Some(220_000_000_000),
        };

        let low_profile = exec.calibrated_risk_profile(&ultra_low);
        let high_profile = exec.calibrated_risk_profile(&high);
        assert_eq!(low_profile.stress, StressProfile::UltraLow);
        assert_eq!(high_profile.stress, StressProfile::High);
        assert!(high_profile.base_floor_bps > low_profile.base_floor_bps);
        assert!(high_profile.cost_floor_bps >= low_profile.cost_floor_bps);
        assert!(high_profile.min_margin_bps > low_profile.min_margin_bps);
        assert!(high_profile.liquidity_ratio_floor_ppm > low_profile.liquidity_ratio_floor_ppm);
    }

    #[tokio::test]
    async fn replay_window_profile_progression_is_monotonic() {
        let exec = dummy_executor_for_tests().await;
        let windows = vec![
            GasFees {
                max_fee_per_gas: 65_000_000,
                max_priority_fee_per_gas: 7_000_000,
                next_base_fee_per_gas: 55_000_000,
                base_fee_per_gas: 48_000_000,
                p50_priority_fee_per_gas: Some(6_000_000),
                p90_priority_fee_per_gas: Some(9_000_000),
                gas_used_ratio: Some(0.52),
                suggested_max_fee_per_gas: Some(75_000_000),
            },
            GasFees {
                max_fee_per_gas: 22_000_000_000,
                max_priority_fee_per_gas: 2_000_000_000,
                next_base_fee_per_gas: 19_000_000_000,
                base_fee_per_gas: 17_000_000_000,
                p50_priority_fee_per_gas: Some(1_800_000_000),
                p90_priority_fee_per_gas: Some(3_000_000_000),
                gas_used_ratio: Some(0.9),
                suggested_max_fee_per_gas: Some(30_000_000_000),
            },
            GasFees {
                max_fee_per_gas: 130_000_000_000,
                max_priority_fee_per_gas: 4_000_000_000,
                next_base_fee_per_gas: 120_000_000_000,
                base_fee_per_gas: 110_000_000_000,
                p50_priority_fee_per_gas: Some(3_500_000_000),
                p90_priority_fee_per_gas: Some(9_000_000_000),
                gas_used_ratio: Some(1.12),
                suggested_max_fee_per_gas: Some(170_000_000_000),
            },
        ];

        let mut prev_base_floor = 0u64;
        for fees in windows {
            let profile = exec.calibrated_risk_profile(&fees);
            assert!(profile.base_floor_bps >= prev_base_floor);
            prev_base_floor = profile.base_floor_bps;
        }
    }

    #[tokio::test]
    async fn dynamic_policy_floor_scales_with_fee_pressure() {
        let mut exec = dummy_executor_for_tests().await;
        exec.profit_floor_abs_wei = U256::from(900_000_000_000_000u64);
        exec.profit_floor_mult_gas = 15;
        let wallet = U256::from(800_000_000_000_000_000u128);

        let low_fees = GasFees {
            max_fee_per_gas: 45_000_000,
            max_priority_fee_per_gas: 5_000_000,
            next_base_fee_per_gas: 40_000_000,
            base_fee_per_gas: 35_000_000,
            p50_priority_fee_per_gas: Some(4_500_000),
            p90_priority_fee_per_gas: Some(6_000_000),
            gas_used_ratio: Some(0.45),
            suggested_max_fee_per_gas: Some(55_000_000),
        };
        let high_fees = GasFees {
            max_fee_per_gas: 220_000_000_000,
            max_priority_fee_per_gas: 8_000_000_000,
            next_base_fee_per_gas: 200_000_000_000,
            base_fee_per_gas: 185_000_000_000,
            p50_priority_fee_per_gas: Some(7_500_000_000),
            p90_priority_fee_per_gas: Some(14_000_000_000),
            gas_used_ratio: Some(1.2),
            suggested_max_fee_per_gas: Some(260_000_000_000),
        };

        let low_floor = exec.test_dynamic_policy_profit_floor_public(
            wallet,
            U256::from(150_000u64).saturating_mul(U256::from(low_fees.max_fee_per_gas)),
            U256::ZERO,
            &low_fees,
            None,
        );
        let high_floor = exec.test_dynamic_policy_profit_floor_public(
            wallet,
            U256::from(150_000u64).saturating_mul(U256::from(high_fees.max_fee_per_gas)),
            U256::ZERO,
            &high_fees,
            None,
        );

        assert!(low_floor >= exec.profit_floor_abs_wei);
        assert!(high_floor > low_floor);
    }

    #[tokio::test]
    async fn dynamic_policy_floor_respects_min_usd_guard_when_present() {
        let mut exec = dummy_executor_for_tests().await;
        exec.profit_floor_abs_wei = U256::from(900_000_000_000_000u64);
        exec.profit_floor_mult_gas = 10;
        let wallet = U256::from(1_000_000_000_000_000_000u128);
        let fees = GasFees {
            max_fee_per_gas: 40_000_000,
            max_priority_fee_per_gas: 5_000_000,
            next_base_fee_per_gas: 35_000_000,
            base_fee_per_gas: 30_000_000,
            p50_priority_fee_per_gas: Some(4_000_000),
            p90_priority_fee_per_gas: Some(5_000_000),
            gas_used_ratio: Some(0.4),
            suggested_max_fee_per_gas: Some(50_000_000),
        };
        let usd_guard = U256::from(2_000_000_000_000_000u64);
        let floor = exec.test_dynamic_policy_profit_floor_public(
            wallet,
            U256::from(150_000u64).saturating_mul(U256::from(fees.max_fee_per_gas)),
            U256::ZERO,
            &fees,
            Some(usd_guard),
        );
        assert!(floor >= usd_guard);
    }

    #[tokio::test]
    async fn dynamic_policy_floor_respects_lower_configured_abs_floor_override() {
        let mut exec = dummy_executor_for_tests().await;
        // Explicit runtime override below the historical baseline.
        exec.profit_floor_abs_wei = U256::from(150_000_000_000_000u64);
        exec.profit_floor_mult_gas = 10;
        let wallet = U256::from(1_000_000_000_000_000_000u128);
        let fees = GasFees {
            max_fee_per_gas: 40_000_000,
            max_priority_fee_per_gas: 5_000_000,
            next_base_fee_per_gas: 35_000_000,
            base_fee_per_gas: 30_000_000,
            p50_priority_fee_per_gas: Some(4_000_000),
            p90_priority_fee_per_gas: Some(5_000_000),
            gas_used_ratio: Some(0.4),
            suggested_max_fee_per_gas: Some(50_000_000),
        };
        let floor = exec.test_dynamic_policy_profit_floor_public(
            wallet,
            U256::ZERO,
            U256::ZERO,
            &fees,
            None,
        );
        assert_eq!(floor, U256::from(150_000_000_000_000u64));
        assert!(floor < *MIN_PROFIT_THRESHOLD_WEI);
    }
}
