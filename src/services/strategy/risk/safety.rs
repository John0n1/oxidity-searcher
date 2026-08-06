// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate
)]

use crate::common::error::AppError;
use alloy::primitives::U256;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct DailyBudget {
    day: u64,
    gas_spent_wei: U256,
    realized_loss_wei: U256,
}

pub struct SafetyGuard {
    consecutive_failures: AtomicUsize,
    latched: AtomicBool,
    latched_at: Mutex<Option<Instant>>,
    max_failures: usize,
    max_tx_gas_wei: U256,
    max_daily_gas_wei: U256,
    max_daily_loss_wei: U256,
    cooldown: Duration,
    daily: Mutex<DailyBudget>,
}

impl Default for SafetyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGuard {
    pub fn new() -> Self {
        Self::with_limits(5, U256::ZERO, U256::ZERO, U256::ZERO)
    }

    /// A zero budget disables that particular daily limit. Latches automatically
    /// expire after the configured cooldown and can still be cleared manually.
    pub fn with_limits(
        max_failures: usize,
        max_tx_gas_wei: U256,
        max_daily_gas_wei: U256,
        max_daily_loss_wei: U256,
    ) -> Self {
        Self::with_limits_and_cooldown(
            max_failures,
            max_tx_gas_wei,
            max_daily_gas_wei,
            max_daily_loss_wei,
            15,
        )
    }

    pub fn with_limits_and_cooldown(
        max_failures: usize,
        max_tx_gas_wei: U256,
        max_daily_gas_wei: U256,
        max_daily_loss_wei: U256,
        cooldown_secs: u64,
    ) -> Self {
        Self {
            consecutive_failures: AtomicUsize::new(0),
            latched: AtomicBool::new(false),
            latched_at: Mutex::new(None),
            max_failures: max_failures.max(1),
            max_tx_gas_wei,
            max_daily_gas_wei,
            max_daily_loss_wei,
            cooldown: Duration::from_secs(cooldown_secs),
            daily: Mutex::new(DailyBudget::default()),
        }
    }

    pub fn is_latched(&self) -> bool {
        self.latched.load(Ordering::Acquire)
    }

    pub fn check(&self) -> Result<(), AppError> {
        if self.latched.load(Ordering::Acquire) {
            let expired = {
                let latched_at = self.latched_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                match *latched_at {
                    Some(start) => start.elapsed() >= self.cooldown,
                    None => true,
                }
            };
            if expired {
                self.latched.store(false, Ordering::Release);
                self.consecutive_failures.store(0, Ordering::Relaxed);
                *self.latched_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                tracing::warn!(
                    cooldown_secs = self.cooldown.as_secs(),
                    "Safety guard auto-cleared; normal execution has resumed."
                );
                return Ok(());
            }
            return Err(AppError::Strategy(
                "Circuit breaker is latched; operator intervention is required".into(),
            ));
        }
        Ok(())
    }

    pub fn check_transaction_gas(&self, estimated_gas_wei: U256) -> Result<(), AppError> {
        self.check()?;
        if !self.max_tx_gas_wei.is_zero() && estimated_gas_wei > self.max_tx_gas_wei {
            return Err(AppError::Strategy(format!(
                "estimated transaction gas {} exceeds per-transaction safety cap {}",
                estimated_gas_wei, self.max_tx_gas_wei
            )));
        }
        Ok(())
    }

    pub fn report_success(&self) {
        if self.latched.load(Ordering::Acquire) {
            return;
        }
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn report_failure(&self) {
        let count = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if count + 1 >= self.max_failures {
            self.latched.store(true, Ordering::Release);
            *self.latched_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
            tracing::error!(
                cooldown_secs = self.cooldown.as_secs(),
                "SAFETY GUARD: Circuit Breaker Tripped!"
            );
        }
    }

    pub fn report_settlement(
        &self,
        gas_spent_wei: U256,
        realized_net_wei: alloy::primitives::I256,
    ) {
        let now_day = chrono::Utc::now().timestamp().max(0) as u64 / 86_400;
        let mut daily = self
            .daily
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if daily.day != now_day {
            *daily = DailyBudget {
                day: now_day,
                ..DailyBudget::default()
            };
        }
        daily.gas_spent_wei = daily.gas_spent_wei.saturating_add(gas_spent_wei);
        if realized_net_wei < alloy::primitives::I256::ZERO {
            daily.realized_loss_wei = daily
                .realized_loss_wei
                .saturating_add(realized_net_wei.abs().into_raw());
        }
        let gas_exceeded =
            !self.max_daily_gas_wei.is_zero() && daily.gas_spent_wei >= self.max_daily_gas_wei;
        let loss_exceeded = !self.max_daily_loss_wei.is_zero()
            && daily.realized_loss_wei >= self.max_daily_loss_wei;
        if gas_exceeded || loss_exceeded {
            self.latched.store(true, Ordering::Release);
            *self.latched_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
            tracing::error!(
                gas_spent_wei = %daily.gas_spent_wei,
                realized_loss_wei = %daily.realized_loss_wei,
                gas_exceeded,
                loss_exceeded,
                cooldown_secs = self.cooldown.as_secs(),
                "SAFETY GUARD: daily budget exhausted; circuit breaker latched"
            );
        }
    }

    /// Explicit operator-only reset hook. This is intentionally never called by a timer.
    pub fn manual_reset(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.latched.store(false, Ordering::Release);
        *self.latched_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        tracing::warn!("Safety Guard: circuit breaker manually reset.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_max_failures() {
        let guard = SafetyGuard::new();
        for _ in 0..guard.max_failures {
            guard.report_failure();
        }
        let res = guard.check();
        assert!(res.is_err(), "guard should trip after max failures");
    }

    #[test]
    fn never_auto_resets() {
        let guard = SafetyGuard::with_limits(2, U256::ZERO, U256::ZERO, U256::ZERO);
        for _ in 0..guard.max_failures {
            guard.report_failure();
        }
        guard.report_success();
        assert!(
            guard.check().is_err(),
            "success must not clear a latched guard"
        );
        guard.manual_reset();
        assert!(guard.check().is_ok(), "manual reset should clear the latch");
    }

    #[test]
    fn auto_resets_after_cooldown() {
        let guard = SafetyGuard::with_limits_and_cooldown(2, U256::ZERO, U256::ZERO, U256::ZERO, 0);
        for _ in 0..guard.max_failures {
            guard.report_failure();
        }
        assert!(
            guard.check().is_ok(),
            "guard should self-clear after the cooldown expires"
        );
    }

    #[test]
    fn daily_loss_budget_latches() {
        let guard = SafetyGuard::with_limits(5, U256::ZERO, U256::ZERO, U256::from(10u64));
        guard.report_settlement(
            U256::from(1u64),
            alloy::primitives::I256::try_from(-10).unwrap(),
        );
        assert!(guard.check().is_err());
    }
}
