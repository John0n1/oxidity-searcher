// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::common::seen_cache::remember_with_bounded_order;
use crate::core::strategy::StrategyStats;
use crate::core::strategy::StrategyWork;
use crate::network::provider::WsProvider;
use crate::services::strategy::execution::work_queue::SharedWorkQueue;
use alloy::consensus::Transaction as _;
use alloy::network::TransactionResponse;
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::Transaction;
use dashmap::DashSet;
use futures::StreamExt;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

pub struct MempoolScanner {
    provider: WsProvider,
    work_queue: SharedWorkQueue,
    stats: Arc<StrategyStats>,
    capacity: usize,
    shutdown: CancellationToken,
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
        work_queue: SharedWorkQueue,
        stats: Arc<StrategyStats>,
        capacity: usize,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            provider,
            work_queue,
            stats,
            capacity,
            shutdown,
            seen: DashSet::new(),
            seen_order: tokio::sync::Mutex::new(VecDeque::new()),
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("Mempool Scanner started...");

        loop {
            if self.shutdown.is_cancelled() {
                tracing::info!(target: "mempool", "Shutdown requested; stopping scanner");
                return Ok(());
            }

            match self.provider.subscribe_full_pending_transactions().await {
                Ok(sub) => {
                    tracing::info!(target: "mempool", "Subscribed to full pendingTransactions");
                    let mut stream = sub.into_stream();
                    loop {
                        tokio::select! {
                            _ = self.shutdown.cancelled() => {
                                tracing::info!(target: "mempool", "Shutdown requested; exiting pending tx stream");
                                return Ok(());
                            }
                            maybe_tx = stream.next() => {
                                match maybe_tx {
                                    Some(tx) => {
                                        if tx.input().len() > 4 && self.mark_seen(tx.tx_hash()).await {
                                            self.enqueue(StrategyWork::Mempool {
                                                tx: Box::new(tx),
                                                received_at: std::time::Instant::now(),
                                            }).await;
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                    tracing::warn!(target: "mempool", "Pending tx subscription ended, retrying after backoff");
                }
                Err(e) => {
                    tracing::warn!(
                        target: "mempool",
                        error = %e,
                        "Full pending sub failed; trying hash-only subscription"
                    );
                    match self.provider.subscribe_pending_transactions().await {
                        Ok(sub) => {
                            tracing::info!(target: "mempool", "Subscribed to pending tx hashes");
                            let mut stream = sub.into_stream();
                            loop {
                                tokio::select! {
                                    _ = self.shutdown.cancelled() => {
                                        tracing::info!(target: "mempool", "Shutdown requested; exiting pending hash stream");
                                        return Ok(());
                                    }
                                    maybe_hash = stream.next() => {
                                        match maybe_hash {
                                            Some(hash) => {
                                                if !self.mark_seen(hash).await {
                                                    continue;
                                                }
                                                match self.provider.get_transaction_by_hash(hash).await {
                                                    Ok(Some(tx)) => {
                                                        if tx.input().len() > 4 {
                                                            self.enqueue(StrategyWork::Mempool {
                                                                tx: Box::new(tx),
                                                                received_at: std::time::Instant::now(),
                                                            }).await;
                                                        }
                                                    }
                                                    Ok(None) => {
                                                        // Hash not yet available; skip
                                                    }
                                                    Err(err) => {
                                                        tracing::debug!(
                                                            target: "mempool",
                                                            error = %err,
                                                            "Failed to fetch pending tx by hash"
                                                        );
                                                    }
                                                }
                                            }
                                            None => break,
                                        }
                                    }
                                }
                            }
                            tracing::warn!(target: "mempool", "Pending hash subscription ended, retrying after backoff");
                        }
                        Err(e2) => {
                            tracing::warn!(
                                target: "mempool",
                                error = %e2,
                                "Hash-only subscription failed; falling back to polling filter"
                            );
                            self.poll_filter_loop().await?;
                        }
                    }
                }
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    tracing::info!(target: "mempool", "Shutdown requested during reconnect backoff");
                    return Ok(());
                }
                _ = sleep(Duration::from_secs(2)) => {}
            }
        }
    }
}

impl MempoolScanner {
    async fn poll_filter_loop(&self) -> Result<(), AppError> {
        let mut full = true;
        let filter_id = match self.provider.new_pending_transactions_filter(true).await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    target: "mempool",
                    error = %e,
                    "Full pending filter unsupported; falling back to hash filter"
                );
                full = false;
                self.provider
                    .new_pending_transactions_filter(false)
                    .await
                    .map_err(|err| AppError::Connection(format!("Filter create failed: {}", err)))?
            }
        };

        loop {
            if self.shutdown.is_cancelled() {
                tracing::info!(target: "mempool", "Shutdown requested; leaving filter poll loop");
                break;
            }

            if full {
                match self
                    .provider
                    .get_filter_changes::<Transaction>(filter_id)
                    .await
                {
                    Ok(txs) => {
                        for tx in txs {
                            if tx.input().len() > 4 && self.mark_seen(tx.tx_hash()).await {
                                self.enqueue(StrategyWork::Mempool {
                                    tx: Box::new(tx),
                                    received_at: std::time::Instant::now(),
                                })
                                .await;
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
            } else {
                match self.provider.get_filter_changes::<B256>(filter_id).await {
                    Ok(hashes) => {
                        for hash in hashes {
                            if !self.mark_seen(hash).await {
                                continue;
                            }
                            match self.provider.get_transaction_by_hash(hash).await {
                                Ok(Some(tx)) => {
                                    if tx.input().len() > 4 {
                                        self.enqueue(StrategyWork::Mempool {
                                            tx: Box::new(tx),
                                            received_at: std::time::Instant::now(),
                                        })
                                        .await;
                                    }
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    tracing::debug!(
                                        target: "mempool",
                                        error = %err,
                                        "poll hash fetch failed"
                                    );
                                }
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
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    tracing::info!(target: "mempool", "Shutdown requested during poll sleep");
                    break;
                }
                _ = sleep(Duration::from_millis(1200)) => {}
            }
        }

        Ok(())
    }

    async fn mark_seen(&self, hash: B256) -> bool {
        remember_with_bounded_order(&self.seen, &self.seen_order, hash, SEEN_MAX).await
    }

    async fn enqueue(&self, work: StrategyWork) {
        let pushed = self.work_queue.push(work).await;
        if pushed.dropped_oldest {
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
                "ingest queue full; dropped oldest work item"
            );
        } else {
            self.stats
                .ingest_queue_depth
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn dedup_marks_and_bounds() {
        let provider = WsProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let queue = Arc::new(crate::services::strategy::execution::work_queue::WorkQueue::new(4));
        let stats = Arc::new(StrategyStats::default());
        let scanner = MempoolScanner::new(provider, queue, stats, 4, CancellationToken::new());

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
