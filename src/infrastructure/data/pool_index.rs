// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use std::collections::{HashMap, HashSet};
use std::path::Path;

use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::common::global_data::parse_global_data_file;
use crate::domain::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolProtocol {
    UniswapV3,
    UniswapV4,
    BalancerV2,
    Curve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolMetrics {
    pub measured_at_block: u64,
    pub volume_window_blocks: u64,
    pub swap_count: u64,
    /// USD values are fixed-point integers with six decimals. Strings avoid JSON precision loss.
    pub liquidity_usd_e6: Option<String>,
    pub volume_usd_e6: Option<String>,
    /// Protocol-native liquidity is required for V4, where manager token balances are shared.
    pub protocol_liquidity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CuratedPoolRecord {
    pub chain_id: u64,
    pub protocol: PoolProtocol,
    /// Contract pool address for V3/Balancer/Curve; PoolManager for V4.
    pub pool: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<B256>,
    pub tokens: Vec<Address>,
    /// Canonical factory, vault, registry, or PoolManager that established identity.
    pub canonical_source: Address,
    pub created_block: u64,
    /// False when `created_block` is a conservative upper bound from a pruned-history scan floor.
    #[serde(default)]
    pub creation_block_exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_spacing: Option<i32>,
    pub metrics: PoolMetrics,
    pub eligible: bool,
    #[serde(default)]
    pub rejection_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCurationPolicy {
    pub min_age_blocks: u64,
    pub min_liquidity_usd_e6: u128,
    pub min_volume_usd_e6: u128,
    pub min_swap_count: u64,
    pub require_usd_metrics: bool,
    pub min_v4_protocol_liquidity: u128,
}

impl Default for PoolCurationPolicy {
    fn default() -> Self {
        Self {
            // Roughly seven days on Ethereum at twelve seconds per block.
            min_age_blocks: 50_400,
            min_liquidity_usd_e6: 100_000 * 1_000_000,
            min_volume_usd_e6: 10_000 * 1_000_000,
            min_swap_count: 5,
            require_usd_metrics: true,
            min_v4_protocol_liquidity: 1,
        }
    }
}

impl PoolCurationPolicy {
    fn parse_metric(value: Option<&String>) -> Option<u128> {
        value.and_then(|v| v.parse::<u128>().ok())
    }

    pub fn rejection_reasons(
        &self,
        record: &CuratedPoolRecord,
        canonical_sources: &HashMap<PoolProtocol, HashSet<Address>>,
    ) -> Vec<String> {
        let mut reasons = Vec::new();
        if !canonical_sources
            .get(&record.protocol)
            .is_some_and(|sources| sources.contains(&record.canonical_source))
        {
            reasons.push("non_canonical_source".to_string());
        }
        let zero_currency_invalid =
            record.protocol != PoolProtocol::UniswapV4 && record.tokens.contains(&Address::ZERO);
        if record.tokens.len() < 2
            || zero_currency_invalid
            || record.tokens.iter().copied().collect::<HashSet<_>>().len() != record.tokens.len()
        {
            reasons.push("invalid_token_set".to_string());
        }
        let age = record
            .metrics
            .measured_at_block
            .saturating_sub(record.created_block);
        if age < self.min_age_blocks {
            reasons.push("pool_too_young".to_string());
        }
        if record.metrics.swap_count < self.min_swap_count {
            reasons.push("insufficient_swap_count".to_string());
        }

        let liquidity = Self::parse_metric(record.metrics.liquidity_usd_e6.as_ref());
        let volume = Self::parse_metric(record.metrics.volume_usd_e6.as_ref());
        if self.require_usd_metrics
            && liquidity.is_none()
            && record.protocol != PoolProtocol::UniswapV4
        {
            reasons.push("missing_liquidity_usd".to_string());
        } else if liquidity.is_some_and(|value| value < self.min_liquidity_usd_e6) {
            reasons.push("insufficient_liquidity".to_string());
        }
        if self.require_usd_metrics && volume.is_none() {
            reasons.push("missing_volume_usd".to_string());
        } else if volume.is_some_and(|value| value < self.min_volume_usd_e6) {
            reasons.push("insufficient_volume".to_string());
        }
        if record.protocol == PoolProtocol::UniswapV4
            && record
                .metrics
                .protocol_liquidity
                .as_ref()
                .and_then(|value| value.parse::<u128>().ok())
                .is_none_or(|value| value < self.min_v4_protocol_liquidity)
        {
            reasons.push("insufficient_protocol_liquidity".to_string());
        }
        reasons
    }

    pub fn curate(
        &self,
        record: &mut CuratedPoolRecord,
        canonical_sources: &HashMap<PoolProtocol, HashSet<Address>>,
    ) {
        record.rejection_reasons = self.rejection_reasons(record, canonical_sources);
        record.eligible = record.rejection_reasons.is_empty();
    }
}

#[derive(Debug, Deserialize)]
struct GlobalPoolIndex {
    #[serde(default)]
    pool_index: Vec<CuratedPoolRecord>,
}

pub fn load_pool_index(path: &Path, chain_id: u64) -> Result<Vec<CuratedPoolRecord>, AppError> {
    let data: GlobalPoolIndex = parse_global_data_file(path, "pool_index")?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for record in data
        .pool_index
        .into_iter()
        .filter(|record| record.chain_id == chain_id && record.eligible)
    {
        let identity = (record.protocol, record.pool, record.pool_id);
        if !seen.insert(identity) {
            return Err(AppError::Config(format!(
                "duplicate eligible pool_index identity: {:?} {:#x}",
                record.protocol, record.pool
            )));
        }
        out.push(record);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(protocol: PoolProtocol) -> CuratedPoolRecord {
        CuratedPoolRecord {
            chain_id: 1,
            protocol,
            pool: Address::from([1; 20]),
            pool_id: (protocol == PoolProtocol::UniswapV4).then_some(B256::from([2; 32])),
            tokens: vec![Address::from([3; 20]), Address::from([4; 20])],
            canonical_source: Address::from([5; 20]),
            created_block: 1,
            creation_block_exact: true,
            fee: Some(3_000),
            tick_spacing: Some(60),
            metrics: PoolMetrics {
                measured_at_block: 100_000,
                volume_window_blocks: 7_200,
                swap_count: 10,
                liquidity_usd_e6: Some("200000000000".into()),
                volume_usd_e6: Some("20000000000".into()),
                protocol_liquidity: Some("100".into()),
            },
            eligible: false,
            rejection_reasons: Vec::new(),
        }
    }

    #[test]
    fn curation_requires_canonical_source_and_thresholds() {
        let policy = PoolCurationPolicy::default();
        let mut sources = HashMap::new();
        sources.insert(
            PoolProtocol::UniswapV3,
            HashSet::from([Address::from([5; 20])]),
        );
        let mut candidate = record(PoolProtocol::UniswapV3);
        policy.curate(&mut candidate, &sources);
        assert!(candidate.eligible);

        candidate.canonical_source = Address::from([9; 20]);
        policy.curate(&mut candidate, &sources);
        assert_eq!(candidate.rejection_reasons, ["non_canonical_source"]);
    }

    #[test]
    fn v4_requires_protocol_liquidity_even_with_volume() {
        let policy = PoolCurationPolicy::default();
        let mut sources = HashMap::new();
        sources.insert(
            PoolProtocol::UniswapV4,
            HashSet::from([Address::from([5; 20])]),
        );
        let mut candidate = record(PoolProtocol::UniswapV4);
        candidate.metrics.protocol_liquidity = Some("0".into());
        policy.curate(&mut candidate, &sources);
        assert!(
            candidate
                .rejection_reasons
                .contains(&"insufficient_protocol_liquidity".to_string())
        );
    }
}
