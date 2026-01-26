// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::providers::Provider;
use alloy::rpc::types::BlockNumberOrTag;
use alloy::rpc::types::eth::FeeHistory;
use std::time::Duration;

#[derive(Clone)]
pub struct GasOracle {
    provider: HttpProvider,
}

#[derive(Debug)]
pub struct GasFees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub base_fee_per_gas: u128,
}

impl GasOracle {
    pub fn new(provider: HttpProvider) -> Self {
        Self { provider }
    }

    pub async fn estimate_eip1559_fees(&self) -> Result<GasFees, AppError> {
        let history: FeeHistory = self.with_retry_history().await?;

        let last_base_fee = history
            .base_fee_per_gas
            .last()
            .ok_or(AppError::Initialization("No base fee history".into()))?;

        let next_base_fee = (last_base_fee * 1125) / 1000;

        let priority_fee = if let Some(rewards) = history.reward {
            let mut sum = 0u128;
            let mut count = 0;
            for block_reward in rewards {
                if let Some(r) = block_reward.first() {
                    sum += *r;
                    count += 1;
                }
            }
            if count > 0 {
                sum / count
            } else {
                2_000_000_000
            }
        } else {
            2_000_000_000
        };

        Ok(GasFees {
            max_fee_per_gas: next_base_fee + priority_fee,
            max_priority_fee_per_gas: priority_fee,
            base_fee_per_gas: *last_base_fee,
        })
    }
}

impl GasOracle {
    async fn with_retry_history(&self) -> Result<FeeHistory, AppError> {
        let provider = self.provider.clone();
        retry_async(
            move |_| {
                let provider = provider.clone();
                async move {
                    provider
                        .get_fee_history(5, BlockNumberOrTag::Latest, &[50.0f64])
                        .await
                }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Fee History failed: {}", e)))
    }
}
