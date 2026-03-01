// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::network::provider::{HttpProvider, WsProvider};
use crate::services::strategy::routers::{
    BalancerPoolId, BalancerStablePool, BalancerVault, BalancerWeightedPool, CurvePoolLike,
    CurveRegistry, UniV2Router,
};
use crate::services::strategy::time_utils::current_unix;
use alloy::primitives::{Address, B256, Bytes, I256, U256, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::{Filter, Log};
use alloy::sol;
use alloy_sol_types::SolCall;
use dashmap::{DashMap, DashSet};
use futures::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniswapV2Pair {
        function token0() external view returns (address);
        function token1() external view returns (address);
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct V2Reserves {
    pub token0: Address,
    pub token1: Address,
    pub reserve0: U256,
    pub reserve1: U256,
}

#[derive(Clone)]
pub struct ReserveCache {
    http_provider: HttpProvider,
    v2_reserves: DashMap<Address, V2Reserves>,
    v2_pairs_by_tokens: DashMap<(Address, Address), Vec<Address>>,
    inflight_pairs: DashSet<Address>,
    lookup_permits: std::sync::Arc<tokio::sync::Semaphore>,
    curve_registry: DashSet<Address>,
    curve_meta_registry: DashSet<Address>,
    curve_crypto_registry: DashSet<Address>,
    curve_pool_coins: DashMap<Address, Vec<Address>>,
    curve_pool_underlying: DashMap<Address, Vec<Address>>,
    curve_pool_decimals: DashMap<Address, Vec<u8>>,
    balancer_vault: std::sync::Arc<RwLock<Option<Address>>>,
    balancer_pool_meta: DashMap<Address, BalancerPoolMeta>,
}

#[derive(Clone, Debug)]
pub struct BalancerPoolMeta {
    pub pool_id: B256,
    pub tokens: Vec<Address>,
    pub weights: Option<Vec<U256>>,
    pub amp: Option<U256>,
    pub swap_fee: Option<U256>,
    pub last_change_block: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct PairMetadata {
    dex: Option<String>,
    factory: Option<Address>,
    pool_address: Option<Address>,
    fee: Option<u32>,
    chain_id: Option<u64>,
}

impl PairMetadata {
    fn is_empty(&self) -> bool {
        self.dex.is_none()
            && self.factory.is_none()
            && self.pool_address.is_none()
            && self.fee.is_none()
            && self.chain_id.is_none()
    }
}

#[derive(Clone, Debug)]
struct PairEntryResolved {
    pair: Address,
    token0: Address,
    token1: Address,
    metadata: PairMetadata,
}

#[derive(Deserialize)]
struct PairEntryRaw {
    pair: String,
    token0: String,
    token1: String,
    #[serde(default)]
    dex: Option<String>,
    #[serde(default)]
    factory: Option<String>,
    #[serde(default)]
    pool_address: Option<String>,
    #[serde(default)]
    fee: Option<u32>,
    #[serde(default)]
    chain_id: Option<u64>,
}

#[derive(Deserialize)]
struct GlobalDataPairs {
    #[serde(default)]
    pairs: Vec<PairEntryRaw>,
}

impl ReserveCache {
    pub fn new(http_provider: HttpProvider) -> Self {
        Self {
            http_provider,
            v2_reserves: DashMap::new(),
            v2_pairs_by_tokens: DashMap::new(),
            inflight_pairs: DashSet::new(),
            lookup_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(32)),
            curve_registry: DashSet::new(),
            curve_meta_registry: DashSet::new(),
            curve_crypto_registry: DashSet::new(),
            curve_pool_coins: DashMap::new(),
            curve_pool_underlying: DashMap::new(),
            curve_pool_decimals: DashMap::new(),
            balancer_vault: std::sync::Arc::new(RwLock::new(None)),
            balancer_pool_meta: DashMap::new(),
        }
    }

    pub fn curve_known_pools(&self) -> Vec<Address> {
        self.curve_pool_coins.iter().map(|e| *e.key()).collect()
    }

    pub fn balancer_known_pools(&self) -> Vec<Address> {
        self.balancer_pool_meta.iter().map(|e| *e.key()).collect()
    }

    // ------------------------------------------------------------------
    // Venue discovery helpers
    // ------------------------------------------------------------------
    pub fn add_curve_registry(&self, addr: Address) {
        self.curve_registry.insert(addr);
    }

    pub fn add_curve_meta_registry(&self, addr: Address) {
        self.curve_meta_registry.insert(addr);
    }

    pub fn add_curve_crypto_registry(&self, addr: Address) {
        self.curve_crypto_registry.insert(addr);
    }

    pub async fn set_balancer_vault(&self, addr: Address) {
        let mut guard = self.balancer_vault.write().await;
        *guard = Some(addr);
    }

    pub async fn discover_balancer_pool(&self, pool: Address) -> Option<BalancerPoolMeta> {
        if let Some(meta) = self.balancer_pool_meta.get(&pool) {
            return Some(meta.clone());
        }
        let vault = { (*self.balancer_vault.read().await)? };

        let pool_id: B256 = BalancerPoolId::new(pool, self.http_provider.clone())
            .getPoolId()
            .call()
            .await
            .ok()?;

        let vault_contract = BalancerVault::new(vault, self.http_provider.clone());
        let tokens_res = vault_contract.getPoolTokens(pool_id).call().await.ok()?;
        let token_list = tokens_res.tokens.clone();
        let last_change_block = tokens_res.lastChangeBlock.to::<u64>();

        let mut weights: Option<Vec<U256>> = None;
        let mut amp: Option<U256> = None;
        let mut swap_fee: Option<U256> = None;

        if let Ok(w) = BalancerWeightedPool::new(pool, self.http_provider.clone())
            .getNormalizedWeights()
            .call()
            .await
        {
            weights = Some(w);
            if let Ok(fee) = BalancerWeightedPool::new(pool, self.http_provider.clone())
                .getSwapFeePercentage()
                .call()
                .await
            {
                swap_fee = Some(fee);
            }
        } else if let Ok(ret) = BalancerStablePool::new(pool, self.http_provider.clone())
            .getAmplificationParameter()
            .call()
            .await
        {
            amp = Some(ret.value);
            if let Ok(fee) = BalancerStablePool::new(pool, self.http_provider.clone())
                .getSwapFeePercentage()
                .call()
                .await
            {
                swap_fee = Some(fee);
            }
        }

        let meta = BalancerPoolMeta {
            pool_id,
            tokens: token_list,
            weights,
            amp,
            swap_fee,
            last_change_block,
        };
        self.balancer_pool_meta.insert(pool, meta.clone());
        Some(meta)
    }

    async fn curve_pool_info(
        &self,
        pool: Address,
        use_underlying: bool,
    ) -> Option<(Vec<Address>, Vec<u8>)> {
        let (map_addr, map_dec) = if use_underlying {
            (&self.curve_pool_underlying, &self.curve_pool_decimals)
        } else {
            (&self.curve_pool_coins, &self.curve_pool_decimals)
        };
        if let Some(coins) = map_addr.get(&pool) {
            let decs = map_dec
                .get(&pool)
                .map(|d| d.value().clone())
                .unwrap_or_default();
            return Some((coins.value().clone(), decs));
        }

        let registries: Vec<Address> = self
            .curve_registry
            .iter()
            .map(|r| *r.key())
            .chain(self.curve_meta_registry.iter().map(|r| *r.key()))
            .chain(self.curve_crypto_registry.iter().map(|r| *r.key()))
            .collect();
        for reg in registries {
            let registry = CurveRegistry::new(reg, self.http_provider.clone());
            let coins_arr_res = if use_underlying {
                registry.get_underlying_coins(pool).call().await
            } else {
                registry.get_coins(pool).call().await
            };
            if let Ok(coins_arr) = coins_arr_res {
                let coins_vec: Vec<Address> = coins_arr
                    .into_iter()
                    .filter(|a| *a != Address::ZERO)
                    .collect();
                if coins_vec.is_empty() {
                    continue;
                }
                let decs_res = if use_underlying {
                    registry.get_underlying_decimals(pool).call().await
                } else {
                    registry.get_decimals(pool).call().await
                };
                let decimals_vec: Vec<u8> = decs_res
                    .ok()
                    .map(|arr| {
                        arr.into_iter()
                            .take(coins_vec.len())
                            .map(|d| d.to::<u8>())
                            .collect()
                    })
                    .unwrap_or_else(|| vec![18u8; coins_vec.len()]);
                map_addr.insert(pool, coins_vec.clone());
                self.curve_pool_decimals.insert(pool, decimals_vec.clone());
                return Some((coins_vec, decimals_vec));
            }
        }
        None
    }

    pub async fn quote_curve_pool(
        &self,
        pool: Address,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    ) -> Option<(U256, bool, i128, i128)> {
        for underlying in [false, true] {
            if let Some((coins, _)) = self.curve_pool_info(pool, underlying).await {
                let i = coins.iter().position(|t| *t == token_in)? as i128;
                let j = coins.iter().position(|t| *t == token_out)? as i128;
                let curve = CurvePoolLike::new(pool, self.http_provider.clone());
                let out = if underlying {
                    curve.get_dy_underlying(i, j, amount_in).call().await.ok()?
                } else {
                    curve.get_dy(i, j, amount_in).call().await.ok()?
                };
                if out > U256::ZERO {
                    return Some((out, underlying, i, j));
                }
            }
        }
        None
    }

    pub async fn quote_balancer_single(
        &self,
        pool: Address,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    ) -> Option<(U256, B256)> {
        let meta = self.discover_balancer_pool(pool).await?;
        let vault = { (*self.balancer_vault.read().await)? };
        let idx_in = meta.tokens.iter().position(|t| *t == token_in)?;
        let idx_out = meta.tokens.iter().position(|t| *t == token_out)?;
        let step = BalancerVault::BatchSwapStep {
            poolId: meta.pool_id,
            assetInIndex: U256::from(idx_in as u64),
            assetOutIndex: U256::from(idx_out as u64),
            amount: amount_in,
            userData: Bytes::new(),
        };
        let funds = BalancerVault::FundManagement {
            sender: Address::ZERO,
            fromInternalBalance: false,
            recipient: Address::ZERO,
            toInternalBalance: false,
        };
        let assets = meta.tokens.clone();
        let deltas = BalancerVault::new(vault, self.http_provider.clone())
            .queryBatchSwap(0u8, vec![step], assets, funds)
            .call()
            .await
            .ok()?;
        if deltas.len() <= idx_out {
            return None;
        }
        let out_signed = deltas[idx_out];
        if out_signed >= I256::ZERO {
            return None;
        }
        let expected_out = U256::try_from(out_signed.abs()).ok()?;
        if expected_out.is_zero() {
            return None;
        }
        Some((expected_out, meta.pool_id))
    }

    #[cfg(test)]
    fn parse_pairs_entries(raw: &str, chain_id: u64) -> Result<Vec<PairEntryResolved>, AppError> {
        let entries: Vec<PairEntryRaw> = serde_json::from_str(raw)
            .map_err(|e| AppError::Config(format!("global_data.pairs parse failed: {}", e)))?;
        Self::parse_pairs_entries_from_vec(entries, chain_id)
    }

    fn parse_pairs_entries_from_global_data(
        raw: &str,
        chain_id: u64,
    ) -> Result<Vec<PairEntryResolved>, AppError> {
        let file: GlobalDataPairs = serde_json::from_str(raw)
            .map_err(|e| AppError::Config(format!("global_data pairs parse failed: {}", e)))?;
        Self::parse_pairs_entries_from_vec(file.pairs, chain_id)
    }

    fn parse_pairs_entries_from_vec(
        entries: Vec<PairEntryRaw>,
        chain_id: u64,
    ) -> Result<Vec<PairEntryResolved>, AppError> {
        let mut out = Vec::new();
        let mut seen_by_key: HashMap<(Address, Address), Vec<PairMetadata>> = HashMap::new();
        for (idx, entry) in entries.into_iter().enumerate() {
            if let Some(entry_chain) = entry.chain_id
                && entry_chain != chain_id
            {
                continue;
            }

            let pair = Address::from_str(&entry.pair).map_err(|_| {
                AppError::Config(format!(
                    "Invalid pair address in global_data.pairs at index {}",
                    idx
                ))
            })?;
            let token0 = Address::from_str(&entry.token0).map_err(|_| {
                AppError::Config(format!(
                    "Invalid token0 in global_data.pairs at index {}",
                    idx
                ))
            })?;
            let token1 = Address::from_str(&entry.token1).map_err(|_| {
                AppError::Config(format!(
                    "Invalid token1 in global_data.pairs at index {}",
                    idx
                ))
            })?;
            let metadata = PairMetadata {
                dex: entry
                    .dex
                    .map(|v| v.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
                factory: entry
                    .factory
                    .as_deref()
                    .map(Address::from_str)
                    .transpose()
                    .map_err(|_| {
                        AppError::Config(format!(
                            "Invalid factory in global_data.pairs at index {}",
                            idx
                        ))
                    })?,
                pool_address: entry
                    .pool_address
                    .as_deref()
                    .map(Address::from_str)
                    .transpose()
                    .map_err(|_| {
                        AppError::Config(format!(
                            "Invalid pool_address in global_data.pairs at index {}",
                            idx
                        ))
                    })?,
                fee: entry.fee,
                chain_id: entry.chain_id,
            };

            let key = Self::token_pair_key(token0, token1);
            let seen = seen_by_key.entry(key).or_default();
            if seen.iter().any(|existing| existing == &metadata) {
                tracing::debug!(
                    target: "reserves",
                    pair = %format!("{:#x}", pair),
                    token0 = %format!("{:#x}", token0),
                    token1 = %format!("{:#x}", token1),
                    "Duplicate global_data.pairs entry with identical metadata; skipping duplicate"
                );
                continue;
            }
            if metadata.is_empty() && seen.iter().any(PairMetadata::is_empty) {
                tracing::warn!(
                    target: "reserves",
                    pair = %format!("{:#x}", pair),
                    token0 = %format!("{:#x}", token0),
                    token1 = %format!("{:#x}", token1),
                    "Duplicate token pair without disambiguating metadata; skipping ambiguous entry"
                );
                continue;
            }
            seen.push(metadata.clone());
            out.push(PairEntryResolved {
                pair,
                token0,
                token1,
                metadata,
            });
        }

        Ok(out)
    }

    /// Optional preload from global_data.pairs section.
    pub fn load_pairs_from_file(&self, path: &str, chain_id: u64) -> Result<(), AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("global_data read failed: {}", e)))?;
        let entries = Self::parse_pairs_entries_from_global_data(&raw, chain_id)?;

        for entry in entries {
            let pair = entry.pair;
            let token0 = entry.token0;
            let token1 = entry.token1;
            let key = Self::token_pair_key(token0, token1);
            self.register_v2_pair_for_tokens(key, pair);
            self.v2_reserves.insert(
                pair,
                V2Reserves {
                    token0,
                    token1,
                    reserve0: U256::ZERO,
                    reserve1: U256::ZERO,
                },
            );
        }
        Ok(())
    }

    /// Preload from JSON and drop entries whose contracts are missing on-chain.
    pub async fn load_pairs_from_file_validated(
        &self,
        path: &str,
        provider: &HttpProvider,
        chain_id: u64,
    ) -> Result<(), AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("global_data read failed: {}", e)))?;
        let entries = Self::parse_pairs_entries_from_global_data(&raw, chain_id)?;

        let mut kept = 0usize;
        let mut metadata_kept = 0usize;
        for entry in entries {
            let pair = entry.pair;
            let token0 = entry.token0;
            let token1 = entry.token1;
            let metadata = entry.metadata;

            let pair_code = provider.get_code_at(pair).await;
            let t0_code = provider.get_code_at(token0).await;
            let t1_code = provider.get_code_at(token1).await;
            if pair_code.map(|c| c.is_empty()).unwrap_or(true)
                || t0_code.map(|c| c.is_empty()).unwrap_or(true)
                || t1_code.map(|c| c.is_empty()).unwrap_or(true)
            {
                tracing::warn!(
                    target: "reserves",
                    pair = %format!("{:#x}", pair),
                    token0 = %format!("{:#x}", token0),
                    token1 = %format!("{:#x}", token1),
                    "global_data.pairs entry has missing code; skipping"
                );
                continue;
            }

            let key = Self::token_pair_key(token0, token1);
            self.register_v2_pair_for_tokens(key, pair);
            self.v2_reserves.insert(
                pair,
                V2Reserves {
                    token0,
                    token1,
                    reserve0: U256::ZERO,
                    reserve1: U256::ZERO,
                },
            );
            kept += 1;
            if !metadata.is_empty() {
                metadata_kept = metadata_kept.saturating_add(1);
            }
        }
        tracing::info!(
            target: "reserves",
            kept,
            metadata_kept,
            "✔ Validated global_data.pairs entries loaded"
        );
        Ok(())
    }

    /// Warm cached reserves by calling getReserves on preloaded V2 pairs.
    /// This avoids cold-start blindness while waiting for fresh Sync events.
    pub async fn warmup_v2_reserves(&self, max_pairs: usize) -> Result<(), AppError> {
        if max_pairs == 0 || self.v2_reserves.is_empty() {
            return Ok(());
        }

        let pairs: Vec<Address> = self
            .v2_reserves
            .iter()
            .take(max_pairs)
            .map(|entry| *entry.key())
            .collect();

        let mut warmed = 0usize;
        let mut failed = 0usize;
        for pair in pairs.iter().copied() {
            let contract = UniswapV2Pair::new(pair, self.http_provider.clone());
            match contract.getReserves().call().await {
                Ok(res) => {
                    if let Some(mut entry) = self.v2_reserves.get_mut(&pair) {
                        entry.reserve0 = U256::from(res.reserve0.to::<u128>());
                        entry.reserve1 = U256::from(res.reserve1.to::<u128>());
                        let key = Self::token_pair_key(entry.token0, entry.token1);
                        self.register_v2_pair_for_tokens(key, pair);
                        warmed = warmed.saturating_add(1);
                    }
                }
                Err(_) => {
                    failed = failed.saturating_add(1);
                }
            }
        }

        tracing::info!(
            target: "reserves",
            requested = pairs.len(),
            warmed,
            failed,
            "✔ V2 reserve warmup completed"
        );
        Ok(())
    }

    pub async fn run_v2_log_listener(self: Arc<Self>, ws: WsProvider, shutdown: CancellationToken) {
        // Seed a small set of pairs if none are known yet.
        if self.v2_reserves.is_empty() {
            self.seed_pairs_from_ws(ws.clone()).await;
        }

        // Restrict to known pair addresses to avoid a firehose of all V2 pairs on chain.
        let mut filter = Filter::new().event("Sync(uint112,uint112)");
        let addresses: Vec<Address> = self.v2_reserves.iter().map(|entry| *entry.key()).collect();
        if !addresses.is_empty() {
            filter = filter.address(addresses);
        }
        loop {
            if shutdown.is_cancelled() {
                tracing::info!(target: "reserves", "Shutdown requested; stopping V2 log listener");
                break;
            }
            match ws.subscribe_logs(&filter).await {
                Ok(sub) => {
                    let mut stream = sub.into_stream();
                    tracing::info!(target: "reserves", "Subscribed to V2 Sync logs");
                    loop {
                        let next = tokio::select! {
                            _ = shutdown.cancelled() => {
                                tracing::info!(target: "reserves", "Shutdown requested; closing Sync subscription");
                                return;
                            }
                            next = stream.next() => next,
                        };
                        let Some(log) = next else {
                            break;
                        };
                        if let Err(e) = self.handle_v2_log(log).await {
                            tracing::debug!(target: "reserves", error=%e, "Failed to process Sync log");
                        }
                    }
                    tracing::warn!(target: "reserves", "Sync subscription ended, retrying");
                }
                Err(e) => {
                    tracing::warn!(target: "reserves", error=%e, "Sync subscribe failed, retrying");
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(target: "reserves", "Shutdown requested; stopping V2 log listener retry loop");
                    break;
                }
                _ = sleep(Duration::from_secs(2)) => {}
            }
        }
    }

    /// One-time bounded discovery: listen briefly for Sync logs without address filter to seed pairs.
    async fn seed_pairs_from_ws(self: &Arc<Self>, ws: WsProvider) {
        let filter = Filter::new().event("Sync(uint112,uint112)");
        let Ok(sub) = ws.subscribe_logs(&filter).await else {
            return;
        };
        let mut stream = sub.into_stream();
        let max_samples = 30usize;
        let window = Duration::from_secs(3);
        let start = std::time::Instant::now();
        while self.v2_reserves.len() < max_samples && start.elapsed() < window {
            match timeout(Duration::from_millis(500), stream.next()).await {
                Ok(Some(log)) => {
                    // Populate reserves/pair maps; schedule lookups if tokens unknown.
                    let _ = self.handle_v2_log(log).await;
                }
                _ => break,
            }
        }
    }

    pub fn token_pair_key(a: Address, b: Address) -> (Address, Address) {
        if a < b { (a, b) } else { (b, a) }
    }

    fn register_v2_pair_for_tokens(&self, key: (Address, Address), pair: Address) {
        Self::register_v2_pair_for_tokens_map(&self.v2_pairs_by_tokens, key, pair);
    }

    fn register_v2_pair_for_tokens_map(
        map: &DashMap<(Address, Address), Vec<Address>>,
        key: (Address, Address),
        pair: Address,
    ) {
        map.entry(key)
            .and_modify(|pairs| {
                if !pairs.contains(&pair) {
                    pairs.push(pair);
                }
            })
            .or_insert_with(|| vec![pair]);
    }

    fn v2_pairs_for_tokens(&self, key: (Address, Address)) -> Vec<Address> {
        self.v2_pairs_by_tokens
            .get(&key)
            .map(|pairs| pairs.value().clone())
            .unwrap_or_default()
    }

    fn quote_v2_hop_best(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    ) -> Option<(U256, Address)> {
        let key = Self::token_pair_key(token_in, token_out);
        let pairs = self.v2_pairs_for_tokens(key);
        if pairs.is_empty() {
            return None;
        }

        let mut best: Option<(U256, Address)> = None;
        for pair in pairs {
            let Some(reserves) = self.v2_reserves.get(&pair).map(|r| r.clone()) else {
                continue;
            };
            let (reserve_in, reserve_out) = if token_in == reserves.token0 {
                (reserves.reserve0, reserves.reserve1)
            } else if token_in == reserves.token1 {
                (reserves.reserve1, reserves.reserve0)
            } else {
                continue;
            };
            if reserve_in.is_zero() || reserve_out.is_zero() {
                continue;
            }
            let amount_in_with_fee = amount_in.saturating_mul(U256::from(997u64));
            let numerator = amount_in_with_fee.saturating_mul(reserve_out);
            let denominator = reserve_in
                .saturating_mul(U256::from(1000u64))
                .saturating_add(amount_in_with_fee);
            if denominator.is_zero() {
                continue;
            }
            let out = numerator / denominator;
            match best {
                None => best = Some((out, pair)),
                Some((prev_out, _)) if out > prev_out => best = Some((out, pair)),
                _ => {}
            }
        }
        best
    }

    pub fn quote_v2_path(&self, path: &[Address], amount_in: U256) -> Option<U256> {
        if path.len() < 2 {
            return None;
        }
        let mut amount = amount_in;
        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];
            let (hop_out, _pair) = self.quote_v2_hop_best(from, to, amount)?;
            amount = hop_out;
        }
        Some(amount)
    }

    pub fn pairs_for_v2_path(&self, path: &[Address]) -> Vec<Address> {
        if path.len() < 2 {
            return Vec::new();
        }
        let mut pairs = Vec::new();
        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];
            let key = Self::token_pair_key(from, to);
            if let Some(found) = self.v2_pairs_by_tokens.get(&key) {
                for pair in found.value().iter().copied() {
                    if !pairs.contains(&pair) {
                        pairs.push(pair);
                    }
                }
            }
        }
        pairs
    }

    /// Returns V2 tokens ranked by observed pair connectivity (highest first).
    /// Useful for bounded opportunity scans that should focus on liquid hubs.
    pub fn top_v2_tokens_by_connectivity(&self, limit: usize) -> Vec<Address> {
        if limit == 0 {
            return Vec::new();
        }
        let mut counts: HashMap<Address, usize> = HashMap::new();
        for entry in self.v2_pairs_by_tokens.iter() {
            let (a, b) = *entry.key();
            *counts.entry(a).or_insert(0) += 1;
            *counts.entry(b).or_insert(0) += 1;
        }
        let mut ranked: Vec<(Address, usize)> = counts.into_iter().collect();
        ranked.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
        ranked
            .into_iter()
            .take(limit)
            .map(|(addr, _)| addr)
            .collect()
    }

    pub fn reserves_for_pair(&self, from: Address, to: Address) -> Option<V2Reserves> {
        let key = Self::token_pair_key(from, to);
        let mut best: Option<(V2Reserves, U256)> = None;
        for pair in self.v2_pairs_for_tokens(key) {
            let Some(res) = self.v2_reserves.get(&pair).map(|r| r.clone()) else {
                continue;
            };
            let reserve_in = if from == res.token0 {
                res.reserve0
            } else if from == res.token1 {
                res.reserve1
            } else {
                continue;
            };
            match best {
                None => best = Some((res, reserve_in)),
                Some((_, prev_reserve_in)) if reserve_in > prev_reserve_in => {
                    best = Some((res, reserve_in))
                }
                _ => {}
            }
        }
        best.map(|(res, _)| res)
    }

    async fn handle_v2_log(&self, log: Log) -> Result<(), AppError> {
        let Some(topic0) = log.topic0() else {
            return Ok(());
        };
        if topic0 != &keccak256("Sync(uint112,uint112)".as_bytes()) {
            return Ok(());
        }

        let data = log.data().data.as_ref();
        if data.len() < 64 {
            return Ok(());
        }

        let reserve0 = U256::from_be_slice(&data[0..32]);
        let reserve1 = U256::from_be_slice(&data[32..64]);
        let pair = log.address();

        let cached_tokens = self
            .v2_reserves
            .get(&pair)
            .map(|entry| (entry.token0, entry.token1));

        let (token0, token1) = if let Some(tokens) = cached_tokens {
            tokens
        } else {
            self.schedule_pair_lookup(pair);
            return Ok(());
        };

        self.v2_reserves.insert(
            pair,
            V2Reserves {
                token0,
                token1,
                reserve0,
                reserve1,
            },
        );
        let key = Self::token_pair_key(token0, token1);
        self.register_v2_pair_for_tokens(key, pair);
        Ok(())
    }

    fn schedule_pair_lookup(&self, pair: Address) {
        if !self.inflight_pairs.insert(pair) {
            return;
        }
        // Bound concurrent lookups to avoid runaway task spawning on noisy chains.
        let permit = match self.lookup_permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.inflight_pairs.remove(&pair);
                return;
            }
        };
        let provider = self.http_provider.clone();
        let pairs_map = self.v2_pairs_by_tokens.clone();
        let reserves_map = self.v2_reserves.clone();
        let inflight = self.inflight_pairs.clone();
        tokio::spawn(async move {
            let contract = UniswapV2Pair::new(pair, provider.clone());
            let token0: Result<Address, _> = contract.token0().call().await;
            let contract = UniswapV2Pair::new(pair, provider.clone());
            let token1: Result<Address, _> = contract.token1().call().await;
            if let (Ok(t0), Ok(t1)) = (token0, token1) {
                let key = if t0 < t1 { (t0, t1) } else { (t1, t0) };
                ReserveCache::register_v2_pair_for_tokens_map(&pairs_map, key, pair);
                reserves_map.insert(
                    pair,
                    V2Reserves {
                        token0: t0,
                        token1: t1,
                        reserve0: U256::ZERO,
                        reserve1: U256::ZERO,
                    },
                );
            }
            inflight.remove(&pair);
            drop(permit);
        });
    }

    pub fn build_v2_swap_payload(
        &self,
        path: Vec<Address>,
        amount_in: U256,
        amount_out_min: U256,
        recipient: Address,
        use_flashloan: bool,
        wrapped_native: Address,
    ) -> Vec<u8> {
        // Give bundled execution enough time across relay delays and node clock drift.
        let deadline = U256::from(current_unix().saturating_add(3600));

        let starts_with_wrapped = path.first().copied() == Some(wrapped_native);
        let ends_with_wrapped = path.last().copied() == Some(wrapped_native);

        if starts_with_wrapped && !ends_with_wrapped {
            if use_flashloan {
                UniV2Router::swapExactTokensForTokensCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            } else {
                UniV2Router::swapExactETHForTokensCall {
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            }
        } else if ends_with_wrapped && !starts_with_wrapped {
            if use_flashloan {
                UniV2Router::swapExactTokensForTokensCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            } else {
                UniV2Router::swapExactTokensForETHCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            }
        } else {
            UniV2Router::swapExactTokensForTokensCall {
                amountIn: amount_in,
                amountOutMin: amount_out_min,
                path,
                to: recipient,
                deadline,
            }
            .abi_encode()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn cache() -> ReserveCache {
        let provider = HttpProvider::new_http(
            Url::parse("http://127.0.0.1:8545").expect("valid local rpc url"),
        );
        ReserveCache::new(provider)
    }

    #[test]
    fn v2_reserve_updates_replace_previous_value() {
        let cache = cache();
        let pair = Address::from([1u8; 20]);
        let token0 = Address::from([2u8; 20]);
        let token1 = Address::from([3u8; 20]);
        let key = ReserveCache::token_pair_key(token0, token1);

        cache.register_v2_pair_for_tokens(key, pair);
        cache.v2_reserves.insert(
            pair,
            V2Reserves {
                token0,
                token1,
                reserve0: U256::from(10u64),
                reserve1: U256::from(20u64),
            },
        );
        cache.v2_reserves.insert(
            pair,
            V2Reserves {
                token0,
                token1,
                reserve0: U256::from(100u64),
                reserve1: U256::from(200u64),
            },
        );

        let quoted = cache.quote_v2_path(&[token0, token1], U256::from(10u64));
        assert!(
            quoted.is_some(),
            "latest reserve update must remain reachable"
        );
        let stored = cache
            .reserves_for_pair(token0, token1)
            .expect("pair reserves must exist");
        assert_eq!(stored.reserve0, U256::from(100u64));
        assert_eq!(stored.reserve1, U256::from(200u64));
        assert_eq!(cache.v2_reserves.len(), 1);
    }

    #[test]
    fn quote_v2_path_selects_best_pool_per_hop() {
        let cache = cache();
        let token0 = Address::from([2u8; 20]);
        let token1 = Address::from([3u8; 20]);
        let key = ReserveCache::token_pair_key(token0, token1);

        let pair_small = Address::from([11u8; 20]);
        let pair_large = Address::from([12u8; 20]);
        cache.register_v2_pair_for_tokens(key, pair_small);
        cache.register_v2_pair_for_tokens(key, pair_large);

        cache.v2_reserves.insert(
            pair_small,
            V2Reserves {
                token0,
                token1,
                reserve0: U256::from(5_000u64),
                reserve1: U256::from(5_000u64),
            },
        );
        cache.v2_reserves.insert(
            pair_large,
            V2Reserves {
                token0,
                token1,
                reserve0: U256::from(50_000u64),
                reserve1: U256::from(80_000u64),
            },
        );

        let out = cache
            .quote_v2_path(&[token0, token1], U256::from(1_000u64))
            .expect("quote");

        // The larger reserve pool yields a materially better output than the tiny pool.
        assert!(
            out > U256::from(800u64),
            "best-pool selection should not use the weaker reserve pair"
        );
        let touched = cache.pairs_for_v2_path(&[token0, token1]);
        assert!(touched.contains(&pair_small));
        assert!(touched.contains(&pair_large));
    }

    #[test]
    fn pairs_loader_dedupes_ambiguous_duplicates_without_metadata() {
        let raw = r#"
[
  {"pair":"0x1111111111111111111111111111111111111111","token0":"0x2222222222222222222222222222222222222222","token1":"0x3333333333333333333333333333333333333333"},
  {"pair":"0x4444444444444444444444444444444444444444","token0":"0x2222222222222222222222222222222222222222","token1":"0x3333333333333333333333333333333333333333"}
]
"#;
        let parsed = ReserveCache::parse_pairs_entries(raw, 1).expect("parse");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn pairs_loader_keeps_duplicates_with_disambiguating_metadata() {
        let raw = r#"
[
  {
    "pair":"0x1111111111111111111111111111111111111111",
    "token0":"0x2222222222222222222222222222222222222222",
    "token1":"0x3333333333333333333333333333333333333333",
    "dex":"uniswap_v3",
    "fee":500
  },
  {
    "pair":"0x4444444444444444444444444444444444444444",
    "token0":"0x2222222222222222222222222222222222222222",
    "token1":"0x3333333333333333333333333333333333333333",
    "dex":"uniswap_v3",
    "fee":3000
  }
]
"#;
        let parsed = ReserveCache::parse_pairs_entries(raw, 1).expect("parse");
        assert_eq!(parsed.len(), 2);
    }
}
