// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::providers::Provider;
use std::cmp::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct NonceManager {
    provider: HttpProvider,
    address: Address,
    cache: Arc<Mutex<Option<(u64, u64)>>>,
}

impl NonceManager {
    pub fn new(provider: HttpProvider, address: Address) -> Self {
        Self {
            provider,
            address,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_base_nonce(&self, current_block: u64) -> Result<u64, AppError> {
        if let Some((block, cached)) = *self.cache.lock().unwrap() {
            match current_block.cmp(&block) {
                Ordering::Equal => return Ok(cached),
                Ordering::Less if current_block == 0 => return Ok(cached),
                _ => {}
            }
        }

        let provider = self.provider.clone();
        let address = self.address;
        let on_chain_nonce: u64 = retry_async(
            move |_| {
                let provider = provider.clone();
                async move { provider.get_transaction_count(address).pending().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Failed to fetch nonce: {}", e)))?;

        *self.cache.lock().unwrap() = Some((current_block, on_chain_nonce));

        Ok(on_chain_nonce)
    }

    pub async fn get_next_nonce(&self) -> Result<u64, AppError> {
        self.get_base_nonce(0).await
    }

    pub async fn resync(&self) -> Result<(), AppError> {
        self.resync_at_block(0).await
    }

    pub async fn resync_at_block(&self, block: u64) -> Result<(), AppError> {
        let provider = self.provider.clone();
        let address = self.address;
        let on_chain_nonce: u64 = retry_async(
            move |_| {
                let provider = provider.clone();
                async move { provider.get_transaction_count(address).pending().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Failed to resync nonce: {}", e)))?;

        tracing::debug!("Nonce resynced to {}", on_chain_nonce);
        *self.cache.lock().unwrap() = Some((block, on_chain_nonce));
        Ok(())
    }
}
