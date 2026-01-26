// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::core::strategy::StrategyWork;
use crate::core::strategy::StrategyStats;
use crate::network::provider::WsProvider;
use alloy::consensus::Transaction as _;
use alloy::network::TransactionResponse;
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::Transaction;
use dashmap::DashSet;
use futures::StreamExt;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, error::TrySendError};
use tokio::time::{Duration, sleep};

pub struct MempoolScanner {
    provider: WsProvider,
    tx_sender: Sender<StrategyWork>,
    stats: Arc<StrategyStats>,
    capacity: usize,
    seen: DashSet<B256>,
    seen_order: tokio::sync::Mutex<VecDeque<B256>>,
}

#[cfg(test)]
const SEEN_MAX: usize = 4;
#[cfg(not(test))]
const SEEN_MAX: usize = 50_000;

impl MempoolScanner {
    pub fn new(
        provider: WsProvider,
        tx_sender: Sender<StrategyWork>,
        stats: Arc<StrategyStats>,
        capacity: usize,
    ) -> Self {
        Self {
            provider,
            tx_sender,
            stats,
            capacity,
            seen: DashSet::new(),
            seen_order: tokio::sync::Mutex::new(VecDeque::new()),
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("Mempool Scanner started...");

        loop {
            match self.provider.subscribe_full_pending_transactions().await {
                Ok(sub) => {
                    tracing::info!(target: "mempool", "Subscribed to full pendingTransactions");
                    let mut stream = sub.into_stream();
                    while let Some(tx) = stream.next().await {
                        if tx.input().len() > 4 && self.mark_seen(tx.tx_hash()).await {
                            self.enqueue(StrategyWork::Mempool(tx));
                        }
                    }
                    tracing::warn!(target: "mempool", "Pending tx subscription ended, retrying after backoff");
                }
                Err(e) => {
                    tracing::warn!(
                        target: "mempool",
                        error = %e,
                        "WS pending sub failed; falling back to polling filter"
                    );
                    self.poll_filter_loop().await?;
                }
            }

            sleep(Duration::from_secs(2)).await;
        }
    }
}

impl MempoolScanner {
    async fn poll_filter_loop(&self) -> Result<(), AppError> {
        let filter_id = self
            .provider
            .new_pending_transactions_filter(true)
            .await
            .map_err(|err| AppError::Connection(format!("Filter create failed: {}", err)))?;

        loop {
            match self
                .provider
                .get_filter_changes::<Transaction>(filter_id)
                .await
            {
                Ok(txs) => {
                    for tx in txs {
                        if tx.input().len() > 4 && self.mark_seen(tx.tx_hash()).await {
                            self.enqueue(StrategyWork::Mempool(tx));
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        target: "mempool",
                        error = %err,
                        "poll get_filter_changes failed"
                    );
                    break;
                }
            }
            sleep(Duration::from_millis(1200)).await;
        }

        Ok(())
    }

    async fn mark_seen(&self, hash: B256) -> bool {
        if !self.seen.insert(hash) {
            return false;
        }
        let mut order = self.seen_order.lock().await;
        order.push_back(hash);
        if order.len() > SEEN_MAX {
            if let Some(oldest) = order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

    fn enqueue(&self, work: StrategyWork) {
        match self.tx_sender.try_send(work) {
            Ok(()) => {
                self.stats
                    .ingest_queue_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.stats
                    .ingest_queue_full
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats
                    .ingest_queue_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats
                    .ingest_backpressure
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    target: "mempool",
                    capacity = self.capacity,
                    "ingest channel full; dropped work item"
                );
            }
            Err(TrySendError::Closed(_)) => {
                tracing::warn!(target: "mempool", "ingest channel closed; dropping work");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::channel;
    use url::Url;

    #[tokio::test]
    async fn retries_until_success() {
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let res: Result<u32, ()> = crate::common::retry::retry_async(
            |_| {
                let current = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move { if current < 2 { Err(()) } else { Ok(7) } }
            },
            4,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(res.unwrap(), 7);
        assert!(counter.load(std::sync::atomic::Ordering::Relaxed) >= 3);
    }

    #[tokio::test]
    async fn dedup_marks_and_bounds() {
        let provider = WsProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let (tx, _rx) = channel(4);
        let stats = Arc::new(StrategyStats::default());
        let scanner = MempoolScanner::new(provider, tx, stats, 4);

        let h1 = B256::from_slice(&[1u8; 32]);
        let h2 = B256::from_slice(&[2u8; 32]);
        assert!(scanner.mark_seen(h1).await);
        assert!(!scanner.mark_seen(h1).await);
        assert!(scanner.mark_seen(h2).await);
        scanner.mark_seen(B256::from_slice(&[3u8; 32])).await;
        scanner.mark_seen(B256::from_slice(&[4u8; 32])).await;
        scanner.mark_seen(B256::from_slice(&[5u8; 32])).await;
        assert!(scanner.mark_seen(h1).await);
    }
}
