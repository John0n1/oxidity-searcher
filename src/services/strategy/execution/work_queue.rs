// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::core::strategy::StrategyWork;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub struct PushResult {
    pub dropped_oldest: bool,
}

pub struct WorkQueue {
    capacity: usize,
    queue: Mutex<VecDeque<StrategyWork>>,
    notify: Notify,
}

pub type SharedWorkQueue = Arc<WorkQueue>;

impl WorkQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    pub async fn push(&self, work: StrategyWork) -> PushResult {
        let mut queue = self.queue.lock().await;
        let dropped_oldest = if queue.len() >= self.capacity {
            queue.pop_front();
            true
        } else {
            false
        };
        queue.push_back(work);
        drop(queue);
        self.notify.notify_one();
        PushResult { dropped_oldest }
    }

    pub async fn pop_latest(&self, shutdown: &CancellationToken) -> Option<StrategyWork> {
        loop {
            let notified = self.notify.notified();
            {
                let mut queue = self.queue.lock().await;
                if let Some(work) = queue.pop_back() {
                    return Some(work);
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => return None,
                _ = notified => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mev_share::MevShareHint;
    use alloy::primitives::{Address, B256, U256};

    fn hint_work(marker: u8) -> StrategyWork {
        StrategyWork::MevShareHint {
            hint: Box::new(MevShareHint {
                tx_hash: B256::from([marker; 32]),
                router: Address::from([marker; 20]),
                from: None,
                call_data: vec![marker],
                value: U256::ZERO,
                gas_limit: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
            }),
            received_at: std::time::Instant::now(),
        }
    }

    #[tokio::test]
    async fn queue_drops_oldest_when_full_and_pops_latest_first() {
        let q = WorkQueue::new(2);
        let shutdown = CancellationToken::new();

        let a = q.push(hint_work(1)).await;
        assert!(!a.dropped_oldest);
        let b = q.push(hint_work(2)).await;
        assert!(!b.dropped_oldest);
        let c = q.push(hint_work(3)).await;
        assert!(c.dropped_oldest);

        match q.pop_latest(&shutdown).await {
            Some(StrategyWork::MevShareHint { hint, .. }) => {
                assert_eq!(hint.tx_hash, B256::from([3u8; 32]));
            }
            _ => panic!("expected mev-share work"),
        }
        match q.pop_latest(&shutdown).await {
            Some(StrategyWork::MevShareHint { hint, .. }) => {
                assert_eq!(hint.tx_hash, B256::from([2u8; 32]));
            }
            _ => panic!("expected mev-share work"),
        }
    }
}
