// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Retry an async operation with exponential backoff.
pub async fn retry_async<F, Fut, T, E>(
    mut op: F,
    attempts: usize,
    initial_delay: Duration,
) -> Result<T, E>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = initial_delay;
    let mut attempt = 1;
    loop {
        match op(attempt).await {
            Ok(v) => return Ok(v),
            Err(_) if attempt < attempts => {
                sleep(delay).await;
                delay = delay.saturating_mul(2);
                attempt += 1;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn retries_until_success() {
        let counter = AtomicUsize::new(0);
        let res: Result<u32, ()> = retry_async(
            |_| {
                let current = counter.fetch_add(1, Ordering::Relaxed);
                async move { if current < 2 { Err(()) } else { Ok(7) } }
            },
            4,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(res.unwrap(), 7);
        assert!(counter.load(Ordering::Relaxed) >= 3);
    }

    #[tokio::test]
    async fn single_attempt_returns_error_without_retrying() {
        let counter = AtomicUsize::new(0);
        let res: Result<(), &'static str> = retry_async(
            |_| {
                counter.fetch_add(1, Ordering::Relaxed);
                async { Err("boom") }
            },
            1,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(res, Err("boom"));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
