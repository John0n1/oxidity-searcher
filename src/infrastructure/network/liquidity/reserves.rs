// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::network::provider::{HttpProvider, WsProvider};
use crate::services::strategy::routers::UniV2Router;
use crate::services::strategy::time_utils::current_unix;
use alloy::primitives::{Address, U256, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::{Filter, Log};
use alloy::sol;
use alloy_sol_types::SolCall;
use dashmap::DashSet;
use futures::StreamExt;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

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
    v2_reserves: DashSet<(Address, V2Reserves)>,
    v2_pairs_by_tokens: DashSet<((Address, Address), Address)>,
    inflight_pairs: DashSet<Address>,
    lookup_permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl ReserveCache {
    pub fn new(http_provider: HttpProvider) -> Self {
        Self {
            http_provider,
            v2_reserves: DashSet::new(),
            v2_pairs_by_tokens: DashSet::new(),
            inflight_pairs: DashSet::new(),
            lookup_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(32)),
        }
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
            self.v2_pairs_by_tokens.insert((key, pair));
            self.v2_reserves.insert((
                pair,
                V2Reserves {
                    token0,
                    token1,
                    reserve0: U256::ZERO,
                    reserve1: U256::ZERO,
                },
            ));
        }
        Ok(())
    }

    pub async fn run_v2_log_listener(self: Arc<Self>, ws: WsProvider) {
        let filter = Filter::new().event("Sync(uint112,uint112)");
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
            let pair = self.v2_pairs_by_tokens.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == key { Some(k.1) } else { None }
            })?;
            let reserves = self.v2_reserves.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == pair { Some(k.1.clone()) } else { None }
            })?;
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
            if let Some(pair) = self.v2_pairs_by_tokens.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == key { Some(k.1) } else { None }
            }) {
                pairs.push(pair);
            }
        }
        pairs
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

        let cached_tokens = self.v2_reserves.iter().find_map(|entry| {
            let key = entry.key();
            if key.0 == pair {
                Some((key.1.token0, key.1.token1))
            } else {
                None
            }
        });

        let (token0, token1) = if let Some(tokens) = cached_tokens {
            tokens
        } else {
            self.schedule_pair_lookup(pair);
            return Ok(());
        };

        self.v2_reserves.insert((
            pair,
            V2Reserves {
                token0,
                token1,
                reserve0,
                reserve1,
            },
        ));
        let key = Self::token_pair_key(token0, token1);
        self.v2_pairs_by_tokens.insert((key, pair));
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
                pairs_map.insert((key, pair));
                reserves_map.insert((
                    pair,
                    V2Reserves {
                        token0: t0,
                        token1: t1,
                        reserve0: U256::ZERO,
                        reserve1: U256::ZERO,
                    },
                ));
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

        if path.first().copied() == Some(wrapped_native) {
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
        } else {
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
        }
    }
}
