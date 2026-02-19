// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::constants;
use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::gas::GasFees;
use crate::services::strategy::routers::{UniV2Router, UniV3Quoter, UniV3Router};
use crate::services::strategy::strategy::{StrategyExecutor, V3_QUOTE_CACHE_TTL_MS};
use crate::services::strategy::time_utils::current_unix;
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{Address, B256, U256, keccak256};
use std::time::{Duration, Instant};

pub struct V2SwapBuild {
    pub expected_out: U256,
    pub calldata: Vec<u8>,
    pub access_list: AccessList,
    pub gas_limit: u64,
    pub tx_value: U256,
}

pub struct V3QuoteCacheEntry {
    pub amount_out: U256,
    pub expires_at: Instant,
}

impl StrategyExecutor {
    pub(crate) fn v3_quote_cache_key(path: &[u8], amount_in: U256) -> B256 {
        let mut key_material = Vec::with_capacity(path.len() + 32);
        key_material.extend_from_slice(path);
        key_material.extend_from_slice(&amount_in.to_be_bytes::<32>());
        keccak256(key_material)
    }

    pub(crate) async fn quote_v3_path(
        &self,
        path: &[u8],
        amount_in: U256,
    ) -> Result<U256, AppError> {
        let cache_key = Self::v3_quote_cache_key(path, amount_in);
        let now = Instant::now();
        let expired = if let Some(entry) = self.v3_quote_cache.get(&cache_key) {
            if entry.expires_at > now {
                return Ok(entry.amount_out);
            }
            true
        } else {
            false
        };
        if expired {
            self.v3_quote_cache.remove(&cache_key);
        }

        let quoter_addr = Self::v3_quoter_for_chain(self.chain_id)
            .ok_or_else(|| AppError::Strategy("No V3 quoter configured for chain".into()))?;
        let quoter = UniV3Quoter::new(quoter_addr, self.http_provider.clone());
        let amount_in_cloned = amount_in;
        let path_vec = path.to_vec();
        let out: U256 = retry_async(
            move |_| {
                let q = quoter.clone();
                let p = path_vec.clone();
                async move { q.quoteExactInput(p.into(), amount_in_cloned).call().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Strategy(format!("V3 path quote failed: {}", e)))?;

        let expiry = now
            .checked_add(Duration::from_millis(V3_QUOTE_CACHE_TTL_MS))
            .unwrap_or(now);
        self.v3_quote_cache.insert(
            cache_key,
            V3QuoteCacheEntry {
                amount_out: out,
                expires_at: expiry,
            },
        );

        Ok(out)
    }

    pub(crate) fn v3_quoter_for_chain(chain_id: u64) -> Option<Address> {
        let routers = constants::default_routers_for_chain(chain_id);
        routers
            .get("uniswap_v3_quoter_v2")
            .copied()
            .or_else(|| routers.get("uniswap_v3_quoter").copied())
    }

    pub(crate) fn build_v3_swap_payload(
        &self,
        router: Address,
        path: Vec<u8>,
        amount_in: U256,
        amount_out_min: U256,
        recipient: Address,
    ) -> Vec<u8> {
        // Align with V2 payload horizon and tolerate timestamp drift across simulators.
        let deadline = current_unix().saturating_add(3600);
        UniV3Router::new(router, self.http_provider.clone())
            .exactInput(UniV3Router::ExactInputParams {
                path: path.into(),
                recipient,
                deadline: U256::from(deadline),
                amountIn: amount_in,
                amountOutMinimum: amount_out_min,
            })
            .calldata()
            .to_vec()
    }

    pub(crate) async fn build_v2_swap(
        &self,
        router: Address,
        path: Vec<Address>,
        amount_in: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        gas_multiplier_num: u64,
        gas_multiplier_den: u64,
        gas_floor: u64,
        use_flashloan: bool,
        recipient: Address,
        strict_liquidity: bool,
        gas_fees: &GasFees,
    ) -> Result<Option<V2SwapBuild>, AppError> {
        let router_contract = UniV2Router::new(router, self.http_provider.clone());
        let access_list = Self::build_access_list(router, &path);

        let expected_out = if let Some(q) = self.reserve_cache.quote_v2_path(&path, amount_in) {
            q
        } else {
            let quote_path = path.clone();
            let quote_contract = router_contract.clone();
            let quote_value = amount_in;
            let quote: Vec<U256> = retry_async(
                move |_| {
                    let c = quote_contract.clone();
                    let p = quote_path.clone();
                    async move { c.getAmountsOut(quote_value, p.clone()).call().await }
                },
                3,
                Duration::from_millis(100),
            )
            .await
            .map_err(|e| AppError::Strategy(format!("V2 quote failed: {}", e)))?;
            *quote
                .last()
                .ok_or_else(|| AppError::Strategy("V2 quote missing amounts".into()))?
        };

        if expected_out.is_zero() {
            if strict_liquidity {
                return Err(AppError::Strategy("V2 quote returned zero output".into()));
            } else {
                return Ok(None);
            }
        }

        // Do not apply raw ratio checks across heterogeneous token units
        // (e.g. WETH wei vs USDC 6 decimals), as that produces false negatives.
        // Liquidity/impact safety is handled by reserve depth checks + simulation.
        if path.first() == path.last() {
            let ratio_ppm = Self::price_ratio_ppm(expected_out, amount_in);
            if ratio_ppm < U256::from(self.adaptive_liquidity_ratio_floor_ppm(gas_fees)) {
                if strict_liquidity {
                    return Err(AppError::Strategy("V2 liquidity too low".into()));
                } else {
                    return Ok(None);
                }
            }
        }

        let min_out = expected_out.saturating_mul(U256::from(10_000u64 - slippage_bps))
            / U256::from(10_000u64);
        let calldata = self.reserve_cache.build_v2_swap_payload(
            path.clone(),
            amount_in,
            min_out,
            recipient,
            use_flashloan,
            self.wrapped_native,
        );

        let mut gas_limit = gas_limit_hint
            .saturating_mul(gas_multiplier_num)
            .checked_div(gas_multiplier_den)
            .unwrap_or(gas_floor);
        if gas_limit < gas_floor {
            gas_limit = gas_floor;
        }

        let tx_value = if path.first().copied() == Some(self.wrapped_native) && !use_flashloan {
            amount_in
        } else {
            U256::ZERO
        };

        Ok(Some(V2SwapBuild {
            expected_out,
            calldata,
            access_list,
            gas_limit,
            tx_value,
        }))
    }
}
