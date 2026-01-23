// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::core::strategy::StrategyWork;
use crate::network::provider::WsProvider;
use alloy::consensus::Transaction as _;
use alloy::providers::Provider;
use alloy::rpc::types::Transaction;
use futures::StreamExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{Duration, sleep};

pub struct MempoolScanner {
    provider: WsProvider,
    tx_sender: UnboundedSender<StrategyWork>,
}

impl MempoolScanner {
    pub fn new(provider: WsProvider, tx_sender: UnboundedSender<StrategyWork>) -> Self {
        Self {
            provider,
            tx_sender,
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
                        if tx.input().len() > 4 {
                            let _ = self.tx_sender.send(StrategyWork::Mempool(tx));
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
            match self.provider.get_filter_changes::<Transaction>(filter_id).await {
                Ok(txs) => {
                    for tx in txs {
                        if tx.input().len() > 4 {
                            let _ = self.tx_sender.send(StrategyWork::Mempool(tx));
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
}
