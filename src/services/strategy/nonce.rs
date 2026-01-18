// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::providers::Provider;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::common::retry::retry_async;
use std::time::Duration;

#[derive(Clone)]
pub struct NonceManager {
    provider: HttpProvider,
    address: Address,
    local_nonce: Arc<Mutex<Option<u64>>>,
}

impl NonceManager {
    pub fn new(provider: HttpProvider, address: Address) -> Self {
        Self {
            provider,
            address,
            local_nonce: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_next_nonce(&self) -> Result<u64, AppError> {
        let mut nonce_guard = self.local_nonce.lock().await;

        if let Some(nonce) = *nonce_guard {
            *nonce_guard = Some(nonce + 1);
            return Ok(nonce);
        }

        // FIX: Explicit U64 return type hint to help compiler
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

        *nonce_guard = Some(on_chain_nonce + 1);
        Ok(on_chain_nonce)
    }

    pub async fn resync(&self) -> Result<(), AppError> {
        let mut nonce_guard = self.local_nonce.lock().await;
        // FIX: Explicit U64 return type hint
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

        *nonce_guard = Some(on_chain_nonce);
        tracing::info!("Nonce resynced to {}", on_chain_nonce);
        Ok(())
    }
}
