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
use std::sync::Mutex;

#[derive(Clone)]
pub struct GasOracle {
    provider: HttpProvider,
    chain_id: u64,
    last_good: std::sync::Arc<Mutex<Option<GasFees>>>,
}

#[derive(Debug, Clone)]
pub struct GasFees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub next_base_fee_per_gas: u128,
    pub base_fee_per_gas: u128,
    /// Median priority fee over the sampled blocks (when available).
    pub p50_priority_fee_per_gas: Option<u128>,
    /// 90th percentile priority fee over the sampled blocks (when available).
    pub p90_priority_fee_per_gas: Option<u128>,
    /// Average gas used ratio across the sampled blocks (0.0-2.0, since target is 1.0).
    pub gas_used_ratio: Option<f64>,
    /// Suggested dynamic cap derived from recent base fees (e.g. p95 * 1.2).
    pub suggested_max_fee_per_gas: Option<u128>,
}

impl GasOracle {
    pub fn new(provider: HttpProvider, chain_id: u64) -> Self {
        Self { provider, chain_id, last_good: std::sync::Arc::new(Mutex::new(None)) }
    }

    pub async fn estimate_eip1559_fees(&self) -> Result<GasFees, AppError> {
        match self.with_retry_history().await {
            Ok(history) => {
                let fees = Self::fees_from_history(history)?;
                if let Ok(mut guard) = self.last_good.lock() {
                    *guard = Some(fees.clone());
                }
                Ok(fees)
            }
            Err(_) => {
                if let Ok(guard) = self.last_good.lock() {
                    if let Some(fees) = guard.clone() {
                        return Ok(fees);
                    }
                }
                self.fallback_estimate().await
            }
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
                    // Ask for p50 and p90 tips to inform fee boosts.
                    provider
                        .get_fee_history(5, BlockNumberOrTag::Latest, &[50.0f64, 90.0f64])
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
        let latest_base_fee = history
            .latest_block_base_fee()
            .or_else(|| history.base_fee_per_gas.iter().rev().nth(1).copied())
            .ok_or(AppError::Initialization("No base fee history".into()))?;

        let raw_next_base = history.next_block_base_fee().unwrap_or(latest_base_fee);

        // Keep the original 12.5% buffer as a fallback for nodes that return zeroes.
        let next_base_fee = if raw_next_base == 0 {
            (latest_base_fee.saturating_mul(1125)) / 1000
        } else {
            raw_next_base
        };

        let mut p50_sum = 0u128;
        let mut p90_sum = 0u128;
        let mut p50_count = 0u128;
        let mut p90_count = 0u128;
        if let Some(rewards) = &history.reward {
            for block_reward in rewards {
                if let Some(r) = block_reward.get(0) {
                    p50_sum = p50_sum.saturating_add(*r);
                    p50_count = p50_count.saturating_add(1);
                }
                if let Some(r) = block_reward.get(1) {
                    p90_sum = p90_sum.saturating_add(*r);
                    p90_count = p90_count.saturating_add(1);
                }
            }
        }

        let avg_p50 = if p50_count > 0 {
            p50_sum / p50_count
        } else {
            2_000_000_000
        };
        let avg_p90 = if p90_count > 0 {
            p90_sum / p90_count
        } else {
            avg_p50
        };

        let util_sum: f64 = history.gas_used_ratio.iter().copied().sum();
        let util_avg = if history.gas_used_ratio.is_empty() {
            None
        } else {
            Some(util_sum / history.gas_used_ratio.len() as f64)
        };

        // Use a rough p95 base fee (max over sample) with a 20% headroom for a dynamic cap.
        let p95_base = history
            .base_fee_per_gas
            .iter()
            .copied()
            .max()
            .unwrap_or(next_base_fee);
        let suggested_cap = p95_base
            .saturating_mul(12)
            .checked_div(10)
            .unwrap_or(p95_base);

        Ok(GasFees {
            max_fee_per_gas: next_base_fee.saturating_add(avg_p50),
            max_priority_fee_per_gas: avg_p50,
            next_base_fee_per_gas: next_base_fee,
            base_fee_per_gas: latest_base_fee,
            p50_priority_fee_per_gas: Some(avg_p50),
            p90_priority_fee_per_gas: Some(avg_p90),
            gas_used_ratio: util_avg,
            suggested_max_fee_per_gas: Some(suggested_cap),
        })
    }

    async fn fallback_estimate(&self) -> Result<GasFees, AppError> {
        // 1) Try Etherscan gas oracle if API key present (mainnet only)
        if self.chain_id == 1 {
            if let Ok(key) = env::var("ETHERSCAN_API_KEY") {
                if !key.is_empty() {
                    if let Ok(fees) = self.etherscan_gas_oracle(&key).await {
                        return Ok(fees);
                    }
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
            p50_priority_fee_per_gas: None,
            p90_priority_fee_per_gas: None,
            gas_used_ratio: None,
            suggested_max_fee_per_gas: None,
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
            p50_priority_fee_per_gas: None,
            p90_priority_fee_per_gas: None,
            gas_used_ratio: None,
            suggested_max_fee_per_gas: None,
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
