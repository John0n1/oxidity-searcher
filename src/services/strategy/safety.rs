// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SafetyGuard {
    consecutive_failures: AtomicUsize,
    last_failure_ts: AtomicUsize,
    max_failures: usize,
    reset_interval_sec: u64,
}

impl SafetyGuard {
    pub fn new() -> Self {
        Self {
            consecutive_failures: AtomicUsize::new(0),
            last_failure_ts: AtomicUsize::new(0),
            max_failures: 5,
            reset_interval_sec: 300, 
        }
    }

    pub fn check(&self) -> Result<(), AppError> {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        if failures >= self.max_failures {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let last = self.last_failure_ts.load(Ordering::Relaxed) as u64;

            if now - last > self.reset_interval_sec {
                self.reset();
            } else {
                return Err(AppError::Strategy(
                    "Circuit Breaker Tripped: Too many recent failures".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn report_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn report_failure(&self) {
        let count = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_failure_ts.store(now as usize, Ordering::Relaxed);

        if count + 1 >= self.max_failures {
            tracing::error!("SAFETY GUARD: Circuit Breaker Tripped!");
        }
    }

    fn reset(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        tracing::info!("Safety Guard: Circuit breaker auto-reset.");
    }
}
