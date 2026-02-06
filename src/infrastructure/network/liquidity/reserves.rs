// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

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
use std::convert::TryFrom;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep, timeout};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniswapV2Pair {
        function token0() external view returns (address);
        function token1() external view returns (address);
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
    v2_pairs_by_tokens: DashMap<(Address, Address), Address>,
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
        let vault = { self.balancer_vault.read().await.clone()? };

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
                    curve
                        .get_dy_underlying(i.into(), j.into(), amount_in)
                        .call()
                        .await
                        .ok()?
                } else {
                    curve
                        .get_dy(i.into(), j.into(), amount_in)
                        .call()
                        .await
                        .ok()?
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
        let vault = { self.balancer_vault.read().await.clone()? };
        let Some(idx_in) = meta.tokens.iter().position(|t| *t == token_in) else {
            return None;
        };
        let Some(idx_out) = meta.tokens.iter().position(|t| *t == token_out) else {
            return None;
        };
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

    /// Optional preload from a JSON file: [{"pair":"0x...","token0":"0x...","token1":"0x..."}]
    pub fn load_pairs_from_file(&self, path: &str) -> Result<(), AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("pairs.json read failed: {}", e)))?;
        #[derive(Deserialize)]
        struct PairEntry {
            pair: String,
            token0: String,
            token1: String,
        }
        let entries: Vec<PairEntry> = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("pairs.json parse failed: {}", e)))?;

        for entry in entries {
            let pair = Address::from_str(&entry.pair)
                .map_err(|_| AppError::Config("Invalid pair address in pairs.json".into()))?;
            let token0 = Address::from_str(&entry.token0)
                .map_err(|_| AppError::Config("Invalid token0 in pairs.json".into()))?;
            let token1 = Address::from_str(&entry.token1)
                .map_err(|_| AppError::Config("Invalid token1 in pairs.json".into()))?;
            let key = Self::token_pair_key(token0, token1);
            self.v2_pairs_by_tokens.insert(key, pair);
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
    ) -> Result<(), AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("pairs.json read failed: {}", e)))?;
        #[derive(Deserialize)]
        struct PairEntry {
            pair: String,
            token0: String,
            token1: String,
        }
        let entries: Vec<PairEntry> = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("pairs.json parse failed: {}", e)))?;

        let mut kept = 0usize;
        for entry in entries {
            let pair = match Address::from_str(&entry.pair) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(target: "reserves", "Invalid pair address in pairs.json; skipping");
                    continue;
                }
            };
            let token0 = match Address::from_str(&entry.token0) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!(target: "reserves", "Invalid token0 in pairs.json; skipping");
                    continue;
                }
            };
            let token1 = match Address::from_str(&entry.token1) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!(target: "reserves", "Invalid token1 in pairs.json; skipping");
                    continue;
                }
            };

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
                    "pairs.json entry has missing code; skipping"
                );
                continue;
            }

            let key = Self::token_pair_key(token0, token1);
            self.v2_pairs_by_tokens.insert(key, pair);
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
        }
        tracing::info!(target: "reserves", kept, "Validated pairs.json entries loaded");
        Ok(())
    }

    pub async fn run_v2_log_listener(self: Arc<Self>, ws: WsProvider) {
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
            match ws.subscribe_logs(&filter).await {
                Ok(sub) => {
                    let mut stream = sub.into_stream();
                    tracing::info!(target: "reserves", "Subscribed to V2 Sync logs");
                    while let Some(log) = stream.next().await {
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
            sleep(Duration::from_secs(2)).await;
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

    pub fn quote_v2_path(&self, path: &[Address], amount_in: U256) -> Option<U256> {
        if path.len() < 2 {
            return None;
        }
        let mut amount = amount_in;
        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];
            let key = Self::token_pair_key(from, to);
            let pair = *self.v2_pairs_by_tokens.get(&key)?;
            let reserves = self.v2_reserves.get(&pair)?.clone();
            let (reserve_in, reserve_out) = if from == reserves.token0 {
                (reserves.reserve0, reserves.reserve1)
            } else if from == reserves.token1 {
                (reserves.reserve1, reserves.reserve0)
            } else {
                return None;
            };
            if reserve_in.is_zero() || reserve_out.is_zero() {
                return None;
            }
            let amount_in_with_fee = amount.saturating_mul(U256::from(997u64));
            let numerator = amount_in_with_fee.saturating_mul(reserve_out);
            let denominator = reserve_in
                .saturating_mul(U256::from(1000u64))
                .saturating_add(amount_in_with_fee);
            amount = if denominator.is_zero() {
                return None;
            } else {
                numerator / denominator
            };
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
            if let Some(pair) = self.v2_pairs_by_tokens.get(&key) {
                pairs.push(*pair);
            }
        }
        pairs
    }

    pub fn reserves_for_pair(&self, from: Address, to: Address) -> Option<V2Reserves> {
        let key = Self::token_pair_key(from, to);
        let pair_addr = *self.v2_pairs_by_tokens.get(&key)?;
        self.v2_reserves.get(&pair_addr).map(|entry| entry.clone())
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
        self.v2_pairs_by_tokens.insert(key, pair);
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
                pairs_map.insert(key, pair);
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
        let deadline = U256::from(current_unix().saturating_add(60));

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

        cache.v2_pairs_by_tokens.insert(key, pair);
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
}
