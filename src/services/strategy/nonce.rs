// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::providers::Provider;
use std::time::Duration;

#[derive(Clone)]
pub struct NonceManager {
    provider: HttpProvider,
    address: Address,
}

impl NonceManager {
    pub fn new(provider: HttpProvider, address: Address) -> Self {
        Self {
            provider,
            address,
        }
    }

    pub async fn get_next_nonce(&self) -> Result<u64, AppError> {
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

        Ok(on_chain_nonce)
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
