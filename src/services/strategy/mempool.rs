// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::network::provider::WsProvider;
use alloy::consensus::Transaction as _;
use alloy::primitives::B256;
use alloy::providers::Provider;
use futures::StreamExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{sleep, Duration};
use crate::core::strategy::StrategyWork;

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
            match self.provider.subscribe_pending_transactions().await {
                Ok(sub) => {
                    tracing::info!(target: "mempool", "Subscribed to pendingTransactions");
                    let mut stream = sub.into_stream();
                    while let Some(tx_hash) = stream.next().await {
                        let provider_clone = self.provider.clone();
                        let sender_clone = self.tx_sender.clone();

                        tokio::spawn(async move {
                            if let Ok(Some(tx)) = provider_clone.get_transaction_by_hash(tx_hash).await {
                                if tx.input().len() > 4 {
                                    let _ = sender_clone.send(StrategyWork::Mempool(tx));
                                }
                            }
                        });
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
            .new_pending_transactions_filter(false)
            .await
            .map_err(|err| AppError::Connection(format!("Filter create failed: {}", err)))?;

        loop {
            match self.provider.get_filter_changes::<B256>(filter_id).await {
                Ok(hashes) => {
                    for tx_hash in hashes {
                        let provider_clone = self.provider.clone();
                        let sender_clone = self.tx_sender.clone();
                        tokio::spawn(async move {
                            if let Ok(Some(tx)) = provider_clone.get_transaction_by_hash(tx_hash).await
                            {
                                if tx.input().len() > 4 {
                                    let _ = sender_clone.send(StrategyWork::Mempool(tx));
                                }
                            }
                        });
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
