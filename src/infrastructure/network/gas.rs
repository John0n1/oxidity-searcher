// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::providers::Provider;
use alloy::rpc::types::BlockNumberOrTag;
use alloy::rpc::types::eth::FeeHistory;
use serde::Deserialize;
use std::env;
use std::time::Duration;

#[derive(Clone)]
pub struct GasOracle {
    provider: HttpProvider,
}

#[derive(Debug)]
pub struct GasFees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub next_base_fee_per_gas: u128,
    pub base_fee_per_gas: u128,
}

impl GasOracle {
    pub fn new(provider: HttpProvider) -> Self {
        Self { provider }
    }

    pub async fn estimate_eip1559_fees(&self) -> Result<GasFees, AppError> {
        match self.with_retry_history().await {
            Ok(history) => Self::fees_from_history(history),
            Err(_) => self.fallback_estimate().await,
        }
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

    fn fees_from_history(history: FeeHistory) -> Result<GasFees, AppError> {
        let last_base_fee = history
            .base_fee_per_gas
            .last()
            .ok_or(AppError::Initialization("No base fee history".into()))?;

        // Approximate next base fee using EIP-1559 elastic rule (reuse 12.5% bump heuristic)
        let next_base_fee = (last_base_fee.saturating_mul(1125)) / 1000;

        let priority_fee = if let Some(rewards) = history.reward {
            let mut sum = 0u128;
            let mut count = 0;
            for block_reward in rewards {
                if let Some(r) = block_reward.first() {
                    sum = sum.saturating_add(*r);
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
            next_base_fee_per_gas: next_base_fee,
            base_fee_per_gas: *last_base_fee,
        })
    }

    async fn fallback_estimate(&self) -> Result<GasFees, AppError> {
        // 1) Try Etherscan gas oracle if API key present
        if let Ok(key) = env::var("ETHERSCAN_API_KEY") {
            if !key.is_empty() {
                if let Ok(fees) = self.etherscan_gas_oracle(&key).await {
                    return Ok(fees);
                }
            }
        }

        // 2) Fallback path for nodes that disable feeHistory (common on some public RPCs).
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|e| AppError::Connection(format!("Latest block fetch failed: {}", e)))?;

        let base: u128 = block
            .as_ref()
            .and_then(|b| b.header.base_fee_per_gas)
            .map(|v| v as u128)
            .unwrap_or(1_500_000_000u128); // 1.5 gwei conservative default

        let priority: u128 = self
            .provider
            .get_max_priority_fee_per_gas()
            .await
            .unwrap_or(2_000_000_000u128); // 2 gwei floor

        // Estimate next base fee with same heuristic
        let next_base = (base.saturating_mul(1125)) / 1000;

        Ok(GasFees {
            max_fee_per_gas: next_base + priority,
            max_priority_fee_per_gas: priority,
            next_base_fee_per_gas: next_base,
            base_fee_per_gas: base,
        })
    }

    async fn etherscan_gas_oracle(&self, api_key: &str) -> Result<GasFees, AppError> {
        // v2 endpoint supports chainid param; defaulting to mainnet (1)
        let url = format!(
            "https://api.etherscan.io/v2/api?chainid=1&module=gastracker&action=gasoracle&apikey={api_key}"
        );
        let resp = reqwest::get(&url)
            .await
            .map_err(|e| AppError::Connection(format!("Etherscan gasoracle failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(AppError::ApiCall {
                provider: "Etherscan gasoracle".into(),
                status: resp.status().as_u16(),
            });
        }
        let parsed: EtherscanGasOracleResponse = resp.json().await.map_err(|e| {
            AppError::Initialization(format!("Etherscan gasoracle decode failed: {e}"))
        })?;

        let result = parsed
            .result
            .ok_or_else(|| AppError::Initialization("Etherscan gasoracle missing result".into()))?;

        // Values are strings in gwei per docs.
        let base_gwei: f64 = result.suggest_base_fee.parse().map_err(|_| {
            AppError::Initialization("Invalid suggestBaseFee from Etherscan".into())
        })?;
        let tip_gwei: f64 = result.propose_gas_price.parse().map_err(|_| {
            AppError::Initialization("Invalid ProposeGasPrice from Etherscan".into())
        })?;

        let base = (base_gwei * 1e9_f64) as u128;
        let next_base = base;
        let priority = (tip_gwei * 1e9_f64) as u128;

        Ok(GasFees {
            max_fee_per_gas: next_base + priority,
            max_priority_fee_per_gas: priority,
            next_base_fee_per_gas: next_base,
            base_fee_per_gas: base,
        })
    }
}

#[derive(Debug, Deserialize)]
struct EtherscanGasOracleResponse {
    result: Option<EtherscanGasOracleResult>,
}

#[derive(Debug, Deserialize)]
struct EtherscanGasOracleResult {
    #[serde(rename = "suggestBaseFee")]
    suggest_base_fee: String,
    #[serde(rename = "ProposeGasPrice")]
    propose_gas_price: String,
}
