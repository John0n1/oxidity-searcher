// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::constants::MIN_PROFIT_THRESHOLD_WEI;
use crate::common::error::AppError;
use crate::network::gas::GasFees;
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
        let base_gwei = fees.base_fee_per_gas / 1_000_000_000u128;
        let mut boost_bps: u64 = if base_gwei > 80 {
            13000 // +30%
        } else if base_gwei > 40 {
            12000 // +20%
        } else {
            11000 // +10%
        };

        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        // -0.1 ETH threshold approx in I256
        let neg_threshold = I256::from_raw(U256::from(100_000_000_000_000_000u128)).neg();

        if pnl < neg_threshold {
            boost_bps = (boost_bps as f64 * 0.8) as u64;
        } else if pnl.is_positive() {
            boost_bps = (boost_bps as f64 * 1.05) as u64;
        }
        boost_bps = boost_bps.max(10200).min(14500);

        let boost =
            |val: u128| -> u128 { (val.saturating_mul(boost_bps as u128) / 10_000u128).max(val) };
        fees.max_fee_per_gas = boost(fees.max_fee_per_gas);
        fees.max_priority_fee_per_gas = boost(fees.max_priority_fee_per_gas);

        let one_gwei: u128 = 1_000_000_000;
        let tip_floor = ((fees.base_fee_per_gas / 10).max(2 * one_gwei)).min(30 * one_gwei);
        if fees.max_priority_fee_per_gas < tip_floor {
            fees.max_priority_fee_per_gas = tip_floor;
        }
        let min_fee = fees
            .base_fee_per_gas
            .saturating_add(fees.max_priority_fee_per_gas);
        if fees.max_fee_per_gas < min_fee {
            fees.max_fee_per_gas = min_fee;
        }

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

        let min_backrun = U256::from(100_000_000_000_000u64);
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
