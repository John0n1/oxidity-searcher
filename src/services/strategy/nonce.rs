// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::providers::Provider;
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
        if current_block > 0 {
            if let Some((block, cached)) = *self.cache.lock().unwrap() {
                if block == current_block {
                    return Ok(cached);
                }
            }
        }

        let provider = self.provider.clone();
        let address = self.address;
        let on_chain_nonce: u64 = retry_async(
            move |_| {
                let provider = provider.clone();
                async move { provider.get_transaction_count(address).await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Failed to fetch nonce: {}", e)))?;

        if current_block > 0 {
            *self.cache.lock().unwrap() = Some((current_block, on_chain_nonce));
        }

        Ok(on_chain_nonce)
    }

    pub async fn get_next_nonce(&self) -> Result<u64, AppError> {
        self.get_base_nonce(0).await
    }

    pub async fn resync(&self) -> Result<(), AppError> {
        let provider = self.provider.clone();
        let address = self.address;
        let on_chain_nonce: u64 = retry_async(
            move |_| {
                let provider = provider.clone();
                async move { provider.get_transaction_count(address).await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Failed to resync nonce: {}", e)))?;

        tracing::info!("Nonce resynced to {}", on_chain_nonce);
        Ok(())
    }
}
