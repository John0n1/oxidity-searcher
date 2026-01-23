// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::core::nonce::NonceManager;
use crate::network::provider::WsProvider;
use alloy::providers::Provider;
use alloy::rpc::types::BlockNumberOrTag;
use alloy::rpc::types::Header;
use futures::StreamExt;
use tokio::sync::broadcast::Sender;
use tokio::time::{Duration, sleep};

pub struct BlockListener {
    provider: WsProvider,
    broadcaster: Sender<Header>,
    nonce_manager: NonceManager,
}

impl BlockListener {
    pub fn new(
        provider: WsProvider,
        broadcaster: Sender<Header>,
        nonce_manager: NonceManager,
    ) -> Self {
        Self {
            provider,
            broadcaster,
            nonce_manager,
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("BlockListener: subscribing to newHeads");
        let mut last_hash: Option<alloy::primitives::B256> = None;
        loop {
            match self.provider.subscribe_blocks().await {
                Ok(sub) => {
                    let mut stream = sub.into_stream();
                    tracing::info!("BlockListener: subscribed to newHeads");
                    while let Some(header) = stream.next().await {
                        let _ = self.broadcaster.send(header.clone());

                        if let Err(e) = self.nonce_manager.resync().await {
                            tracing::warn!("Nonce resync failed on new block: {}", e);
                        }

                        tracing::debug!(
                            "New head received: number={:?} hash={:?}",
                            header.inner.number,
                            header.hash
                        );
                    }
                    tracing::warn!("BlockListener: subscription ended, retrying after backoff");
                }
                Err(e) => {
                    tracing::warn!("Block subscription failed ({}); falling back to polling", e);
                    self.poll_once(&mut last_hash).await;
                }
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    async fn poll_once(&self, last_hash: &mut Option<alloy::primitives::B256>) {
        match self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
        {
            Ok(Some(block)) => {
                let hash = block.header.hash;
                if last_hash.map(|h| h != hash).unwrap_or(true) {
                    *last_hash = Some(hash);
                    let header = block.header;
                    let _ = self.broadcaster.send(header.clone());
                    if let Err(e) = self.nonce_manager.resync().await {
                        tracing::warn!("Nonce resync failed on new block: {}", e);
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("Polling block returned None");
            }
            Err(e) => {
                tracing::warn!("Polling latest block failed: {}", e);
            }
        }
    }
}
