// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::core::executor::SharedBundleSender;
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::Simulator;
use crate::data::db::Database;
use crate::domain::constants;
use crate::infrastructure::data::token_manager::TokenManager;
use crate::network::gas::{GasFees, GasOracle};
use crate::network::mev_share::MevShareHint;
use crate::network::nonce::NonceManager;
use crate::network::price_feed::PriceFeed;
use crate::network::provider::HttpProvider;
use crate::network::reserves::ReserveCache;
use crate::services::strategy::bundles::BundleState;
use crate::services::strategy::decode::{ObservedSwap, parse_v3_path};
use crate::services::strategy::routers::{ERC20, UniV3Router};
use crate::services::strategy::swaps::V3QuoteCacheEntry;
use alloy::primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::Header;
use alloy::rpc::types::eth::Transaction;
use alloy::rpc::types::eth::TransactionInput;
use alloy::rpc::types::eth::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use dashmap::{DashMap, DashSet};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore, broadcast::Receiver as BroadcastReceiver, mpsc::Receiver};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum StrategyWork {
    Mempool {
        tx: Transaction,
        received_at: std::time::Instant,
    },
    MevShareHint {
        hint: MevShareHint,
        received_at: std::time::Instant,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    UnknownRouter,
    DecodeFailed,
    MissingWrappedOrZeroAmount,
    NonWrappedBalance,
    GasPriceCap,
    SimulationFailed,
    ProfitOrGasGuard,
    UnsupportedRouter,
    TokenCall,
    InsufficientBalance,
    ToxicToken,
    RouterRevertRate,
    LiquidityDepth,
    SandwichRisk,
    FrontRunBuildFailed,
    BackrunBuildFailed,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::UnknownRouter => "unknown_router",
            SkipReason::DecodeFailed => "decode_failed",
            SkipReason::MissingWrappedOrZeroAmount => "zero_amount_or_no_wrapped_native",
            SkipReason::NonWrappedBalance => "non_wrapped_balance",
            SkipReason::GasPriceCap => "gas_price_cap",
            SkipReason::SimulationFailed => "simulation_failed",
            SkipReason::ProfitOrGasGuard => "profit_or_gas_guard",
            SkipReason::UnsupportedRouter => "unsupported_router",
            SkipReason::TokenCall => "token_call",
            SkipReason::InsufficientBalance => "insufficient_balance",
            SkipReason::ToxicToken => "toxic_token",
            SkipReason::RouterRevertRate => "router_revert_rate",
            SkipReason::LiquidityDepth => "liquidity_depth",
            SkipReason::SandwichRisk => "sandwich_risk",
            SkipReason::FrontRunBuildFailed => "front_run_build_failed",
            SkipReason::BackrunBuildFailed => "backrun_build_failed",
        }
    }

    fn noisy(self) -> bool {
        matches!(
            self,
            SkipReason::UnknownRouter | SkipReason::TokenCall | SkipReason::DecodeFailed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    ConfirmedSuccess,
    ConfirmedRevert,
    UnknownTimeout,
}

#[derive(Clone, Debug, Default)]
pub struct RelayOutcomeStats {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub retries: u64,
}

pub(crate) const VICTIM_FEE_BUMP_BPS: u64 = 11_000;
pub(crate) const TAX_TOLERANCE_BPS: u64 = 500;
pub(crate) const PROBE_GAS_LIMIT: u64 = 220_000;
pub(crate) const V3_QUOTE_CACHE_TTL_MS: u64 = 250;

#[derive(Clone, Copy, Debug)]
pub struct DynamicGasCap {
    pub cap_wei: U256,
    pub base_plus_tip_wei: u128,
    pub base_dynamic_wei: u128,
    pub adjusted_dynamic_wei: u128,
    pub balance_factor_bps: u64,
    pub floor_wei: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlashloanProvider {
    Balancer,
    AaveV3,
}

#[derive(Default)]
pub struct StrategyStats {
    pub processed: AtomicU64,
    pub submitted: AtomicU64,
    pub skipped: AtomicU64,
    pub failed: AtomicU64,
    pub skip_unknown_router: AtomicU64,
    pub skip_decode_failed: AtomicU64,
    pub skip_missing_wrapped: AtomicU64,
    pub skip_non_wrapped_balance: AtomicU64,
    pub skip_gas_cap: AtomicU64,
    pub skip_sim_failed: AtomicU64,
    pub skip_profit_guard: AtomicU64,
    pub skip_unsupported_router: AtomicU64,
    pub skip_token_call: AtomicU64,
    pub skip_insufficient_balance: AtomicU64,
    pub skip_toxic_token: AtomicU64,
    pub ingest_queue_depth: AtomicU64,
    pub ingest_queue_dropped: AtomicU64,
    pub ingest_queue_full: AtomicU64,
    pub ingest_backpressure: AtomicU64,
    pub bundles: StdMutex<Vec<BundleTelemetry>>,
    pub nonce_state_loads: AtomicU64,
    pub nonce_state_load_fail: AtomicU64,
    pub nonce_state_persist: AtomicU64,
    pub nonce_state_persist_fail: AtomicU64,
    pub sim_latency_ms_sum: AtomicU64,
    pub sim_latency_ms_count: AtomicU64,
    pub sim_latency_ms_sum_mempool: AtomicU64,
    pub sim_latency_ms_count_mempool: AtomicU64,
    pub sim_latency_ms_sum_mevshare: AtomicU64,
    pub sim_latency_ms_count_mevshare: AtomicU64,
    pub relay_outcomes: StdMutex<HashMap<String, RelayOutcomeStats>>,
}

#[derive(Clone, Debug)]
pub struct BundleTelemetry {
    pub tx_hash: String,
    pub source: String,
    pub profit_eth: f64,
    pub gas_cost_eth: f64,
    pub net_eth: f64,
    pub timestamp_ms: i64,
}

impl StrategyStats {
    pub fn record_bundle(&self, entry: BundleTelemetry) {
        let mut guard = self.bundles.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(entry);
        if guard.len() > 50 {
            guard.remove(0);
        }
    }

    pub fn record_sim_latency(&self, source: &str, ms: u64) {
        self.sim_latency_ms_sum.fetch_add(ms, Ordering::Relaxed);
        self.sim_latency_ms_count.fetch_add(1, Ordering::Relaxed);
        match source {
            "mempool" => {
                self.sim_latency_ms_sum_mempool
                    .fetch_add(ms, Ordering::Relaxed);
                self.sim_latency_ms_count_mempool
                    .fetch_add(1, Ordering::Relaxed);
            }
            "mev_share" => {
                self.sim_latency_ms_sum_mevshare
                    .fetch_add(ms, Ordering::Relaxed);
                self.sim_latency_ms_count_mevshare
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_relay_attempt(
        &self,
        relay_name: &str,
        success: bool,
        timeout: bool,
        retries: u64,
    ) {
        let mut guard = self
            .relay_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(relay_name.to_string()).or_default();
        entry.attempts = entry.attempts.saturating_add(1);
        entry.retries = entry.retries.saturating_add(retries);
        if success {
            entry.successes = entry.successes.saturating_add(1);
        } else {
            entry.failures = entry.failures.saturating_add(1);
            if timeout {
                entry.timeouts = entry.timeouts.saturating_add(1);
            }
        }
    }
}

pub struct StrategyExecutor {
    pub(in crate::services::strategy) tx_rx: Mutex<Receiver<StrategyWork>>,
    pub(in crate::services::strategy) mut_block_rx: Mutex<BroadcastReceiver<Header>>,
    pub(in crate::services::strategy) safety_guard: Arc<SafetyGuard>,
    pub(in crate::services::strategy) bundle_sender: SharedBundleSender,
    pub(in crate::services::strategy) db: Database,
    pub(in crate::services::strategy) portfolio: Arc<PortfolioManager>,
    pub(in crate::services::strategy) gas_oracle: GasOracle,
    pub(in crate::services::strategy) price_feed: PriceFeed,
    pub(in crate::services::strategy) chain_id: u64,
    pub(in crate::services::strategy) stats: Arc<StrategyStats>,
    pub(in crate::services::strategy) max_gas_price_gwei: u64,
    pub(in crate::services::strategy) gas_cap_multiplier_bps: u64,
    pub(in crate::services::strategy) simulator: Simulator,
    pub(in crate::services::strategy) token_manager: Arc<TokenManager>,
    pub(in crate::services::strategy) signer: PrivateKeySigner,
    pub(in crate::services::strategy) nonce_manager: NonceManager,
    pub(in crate::services::strategy) slippage_bps: u64,
    pub(in crate::services::strategy) http_provider: HttpProvider,
    pub(in crate::services::strategy) dry_run: bool,
    pub(in crate::services::strategy) router_allowlist: Arc<DashSet<Address>>,
    pub(in crate::services::strategy) router_discovery:
        Option<Arc<crate::services::strategy::router_discovery::RouterDiscovery>>,
    pub(in crate::services::strategy) skip_log_every: u64,
    pub(in crate::services::strategy) wrapped_native: Address,
    pub(in crate::services::strategy) allow_non_wrapped_swaps: bool,
    pub(in crate::services::strategy) universal_router: Option<Address>,
    pub(in crate::services::strategy) exec_router_v2: Option<Address>,
    pub(in crate::services::strategy) exec_router_v3: Option<Address>,
    pub(in crate::services::strategy) inventory_tokens: DashSet<Address>,
    pub(in crate::services::strategy) last_rebalance: Mutex<Instant>,
    pub(in crate::services::strategy) toxic_tokens: DashSet<Address>,
    pub(in crate::services::strategy) executor: Option<Address>,
    pub(in crate::services::strategy) executor_bribe_bps: u64,
    pub(in crate::services::strategy) executor_bribe_recipient: Option<Address>,
    pub(in crate::services::strategy) flashloan_enabled: bool,
    pub(in crate::services::strategy) flashloan_providers: Vec<FlashloanProvider>,
    pub(in crate::services::strategy) aave_pool: Option<Address>,
    pub(in crate::services::strategy) reserve_cache: Arc<ReserveCache>,
    pub(in crate::services::strategy) bundle_state: Arc<Mutex<Option<BundleState>>>,
    pub(in crate::services::strategy) v3_quote_cache: DashMap<B256, V3QuoteCacheEntry>,
    pub(in crate::services::strategy) probe_gas_stats: DashMap<Address, (u64, u64)>,
    pub(in crate::services::strategy) router_sim_stats: DashMap<Address, (u64, u64)>,
    pub(in crate::services::strategy) current_block: AtomicU64,
    pub(in crate::services::strategy) sandwich_attacks_enabled: bool,
    pub(in crate::services::strategy) simulation_backend: String,
    pub(in crate::services::strategy) worker_semaphore: Arc<Semaphore>,
    pub(in crate::services::strategy) shutdown: CancellationToken,
    pub(in crate::services::strategy) receipt_poll_ms: u64,
    pub(in crate::services::strategy) receipt_timeout_ms: u64,
    pub(in crate::services::strategy) receipt_confirm_blocks: u64,
    pub(in crate::services::strategy) emergency_exit_on_unknown_receipt: bool,
}

impl StrategyExecutor {
    pub(crate) fn has_usable_flashloan_provider(&self) -> bool {
        if !self.flashloan_enabled || self.executor.is_none() {
            return false;
        }
        for p in &self.flashloan_providers {
            match p {
                FlashloanProvider::Balancer => return true,
                FlashloanProvider::AaveV3 => {
                    if self.aave_pool.is_some() {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn serialize_pools(pools: &HashSet<Address>) -> String {
        pools
            .iter()
            .map(|a| format!("{:#x}", a))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn deserialize_pools(s: &str) -> HashSet<Address> {
        s.split(',')
            .filter_map(|p| {
                if p.is_empty() {
                    None
                } else {
                    p.parse::<Address>().ok()
                }
            })
            .collect()
    }

    pub(in crate::services::strategy) fn balance_cap_multiplier_bps(&self, balance: U256) -> u64 {
        let eth_balance = wei_to_eth_f64(balance).max(0.0001);
        let sqrt = eth_balance.sqrt();
        let scale = sqrt / (sqrt + 0.8);
        let min_bps = 6_000.0;
        let max_bps = 13_000.0;
        let bps = min_bps + (max_bps - min_bps) * scale;
        bps.round().clamp(min_bps, max_bps) as u64
    }

    pub(in crate::services::strategy) fn effective_slippage_bps(&self) -> u64 {
        if self.slippage_bps > 0 {
            return self.slippage_bps.min(9_999).max(1);
        }
        let wallet_balance = self.portfolio.get_eth_balance_cached(self.chain_id);
        let eth_balance = wei_to_eth_f64(wallet_balance).max(0.0001);
        let base = 120.0 - 30.0 * (eth_balance * 100.0 + 1.0).log10();
        let volatility = self.price_feed.volatility_bps_cached("ETH").unwrap_or(0) as f64;
        let vol_adjust = volatility * 0.35;
        let slippage = base + vol_adjust;
        slippage.round().clamp(15.0, 500.0) as u64
    }

    pub(in crate::services::strategy) fn max_price_impact_bps(&self) -> u64 {
        let wallet_balance = self.portfolio.get_eth_balance_cached(self.chain_id);
        let eth_balance = wei_to_eth_f64(wallet_balance).max(0.0001);
        let base = 170.0 - 40.0 * (eth_balance * 100.0 + 1.0).log10();
        let volatility = self.price_feed.volatility_bps_cached("ETH").unwrap_or(0) as f64;
        let vol_adjust = volatility * 0.15;
        let impact = base - vol_adjust;
        impact.round().clamp(30.0, 200.0) as u64
    }

    pub(in crate::services::strategy) fn hard_gas_cap_wei(&self) -> U256 {
        if self.max_gas_price_gwei == 0 {
            U256::MAX
        } else {
            U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64)
        }
    }

    pub(in crate::services::strategy) fn dynamic_gas_cap(
        &self,
        wallet_balance: U256,
        gas_fees: &GasFees,
        hard_cap: U256,
    ) -> DynamicGasCap {
        let base_plus_tip_wei = gas_fees
            .next_base_fee_per_gas
            .saturating_add(gas_fees.max_priority_fee_per_gas);
        let fallback_dynamic_wei =
            base_plus_tip_wei.saturating_mul(self.gas_cap_multiplier_bps as u128) / 10_000u128;
        let base_dynamic_wei = gas_fees
            .suggested_max_fee_per_gas
            .unwrap_or(fallback_dynamic_wei);
        let balance_factor_bps = self.balance_cap_multiplier_bps(wallet_balance);
        let adjusted_dynamic_wei =
            base_dynamic_wei.saturating_mul(balance_factor_bps as u128) / 10_000u128;

        // Avoid impossible caps below current base fee on tiny balances.
        let floor_wei = gas_fees.base_fee_per_gas.max(gas_fees.next_base_fee_per_gas);
        let cap_wei = U256::from(adjusted_dynamic_wei.max(floor_wei)).min(hard_cap);

        DynamicGasCap {
            cap_wei,
            base_plus_tip_wei,
            base_dynamic_wei,
            adjusted_dynamic_wei,
            balance_factor_bps,
            floor_wei,
        }
    }

    pub(in crate::services::strategy) fn enforce_dynamic_gas_cap(
        gas_fees: &mut GasFees,
        cap_wei: U256,
    ) -> bool {
        if U256::from(gas_fees.max_fee_per_gas) <= cap_wei {
            return false;
        }

        let cap_u128 = if cap_wei > U256::from(u128::MAX) {
            u128::MAX
        } else {
            cap_wei.to::<u128>()
        };
        let base_anchor = gas_fees.next_base_fee_per_gas.max(gas_fees.base_fee_per_gas);
        if cap_u128 < base_anchor {
            return true;
        }

        gas_fees.max_fee_per_gas = cap_u128;
        let tip_cap = cap_u128.saturating_sub(base_anchor);
        gas_fees.max_priority_fee_per_gas = gas_fees.max_priority_fee_per_gas.min(tip_cap);
        false
    }

    pub(in crate::services::strategy) fn record_router_sim(&self, router: Address, success: bool) {
        self.router_sim_stats
            .entry(router)
            .and_modify(|(fails, total)| {
                *total = total.saturating_add(1);
                if !success {
                    *fails = fails.saturating_add(1);
                }
            })
            .or_insert((if success { 0 } else { 1 }, 1));
    }

    pub(in crate::services::strategy) fn router_is_risky(&self, router: Address) -> bool {
        if let Some(entry) = self.router_sim_stats.get(&router) {
            let (fails, total) = *entry;
            if total < 20 {
                return false;
            }
            let rate = fails as f64 / total as f64;
            return rate >= 0.40;
        }
        false
    }

    pub(in crate::services::strategy) fn liquidity_depth_ok(
        &self,
        observed: &crate::services::strategy::decode::ObservedSwap,
        wallet_balance: U256,
    ) -> bool {
        if observed.path.len() < 2 {
            return true;
        }
        if observed.router_kind != crate::services::strategy::decode::RouterKind::V2Like {
            return true;
        }
        let token_in = observed.path[0];
        let token_out = observed.path[1];
        let Some(reserves) = self.reserve_cache.reserves_for_pair(token_in, token_out) else {
            return true;
        };
        let reserve_in = if token_in == reserves.token0 {
            reserves.reserve0
        } else {
            reserves.reserve1
        };
        if reserve_in.is_zero() {
            return false;
        }
        let impact_bps = observed
            .amount_in
            .saturating_mul(U256::from(10_000u64))
            .checked_div(reserve_in.saturating_add(observed.amount_in))
            .unwrap_or(U256::from(10_000u64));
        let max_bps = U256::from(self.max_price_impact_bps());
        if impact_bps > max_bps {
            tracing::debug!(
                target: "risk",
                impact_bps = %impact_bps,
                max_bps = %max_bps,
                wallet = %wallet_balance,
                "Liquidity impact too high; skipping"
            );
            return false;
        }
        true
    }

    pub(crate) async fn persist_nonce_state(
        &self,
        block: u64,
        next_nonce: u64,
        touched: &HashSet<Address>,
    ) {
        let pools = Self::serialize_pools(touched);
        match self
            .db
            .upsert_nonce_state(self.chain_id, block, next_nonce, &pools)
            .await
        {
            Ok(_) => {
                self.stats
                    .nonce_state_persist
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.stats
                    .nonce_state_persist_fail
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(target: "bundle_state", error=%e, "Persist nonce state failed");
            }
        }
    }

    async fn restore_bundle_state(&self) -> Result<(), AppError> {
        let loaded = self.db.load_nonce_state(self.chain_id).await;
        if let Ok(Some((block, next, touched_raw))) = loaded {
            let touched = Self::deserialize_pools(&touched_raw);
            {
                let mut guard = self.bundle_state.lock().await;
                *guard = Some(BundleState {
                    block,
                    next_nonce: next,
                    raw: Vec::new(),
                    touched_pools: touched,
                    send_pending: false,
                });
            }
            self.current_block.store(block, Ordering::Relaxed);
            self.stats.nonce_state_loads.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                target: "bundle_state",
                block,
                next_nonce = next,
                "Restored nonce state from DB"
            );
        } else if let Ok(None) = loaded {
            self.stats.nonce_state_loads.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(target: "bundle_state", "No persisted nonce state found");
        } else if let Err(e) = loaded {
            self.stats
                .nonce_state_load_fail
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(target: "bundle_state", error=%e, "Failed to load nonce state");
        }
        Ok(())
    }

    pub(in crate::services::strategy) fn is_nonce_gap_error(err: &AppError) -> bool {
        let msg = err.to_string().to_lowercase();
        msg.contains("nonce too high")
            || msg.contains("nonce too low")
            || msg.contains("nonce gap")
            || msg.contains("missing nonce")
    }

    pub(in crate::services::strategy) fn log_skip(&self, reason: SkipReason, detail: &str) {
        let count = match reason {
            SkipReason::UnknownRouter => {
                self.stats
                    .skip_unknown_router
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::DecodeFailed => {
                self.stats
                    .skip_decode_failed
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::MissingWrappedOrZeroAmount => {
                self.stats
                    .skip_missing_wrapped
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::NonWrappedBalance => {
                self.stats
                    .skip_non_wrapped_balance
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::GasPriceCap => self.stats.skip_gas_cap.fetch_add(1, Ordering::Relaxed) + 1,
            SkipReason::SimulationFailed => {
                self.stats.skip_sim_failed.fetch_add(1, Ordering::Relaxed) + 1
            }
            SkipReason::ProfitOrGasGuard => {
                self.stats.skip_profit_guard.fetch_add(1, Ordering::Relaxed) + 1
            }
            SkipReason::UnsupportedRouter => {
                self.stats
                    .skip_unsupported_router
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::TokenCall => self.stats.skip_token_call.fetch_add(1, Ordering::Relaxed) + 1,
            SkipReason::ToxicToken => self.stats.skip_toxic_token.fetch_add(1, Ordering::Relaxed) + 1,
            SkipReason::InsufficientBalance => {
                self.stats
                    .skip_insufficient_balance
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::RouterRevertRate
            | SkipReason::LiquidityDepth
            | SkipReason::SandwichRisk
            | SkipReason::FrontRunBuildFailed
            | SkipReason::BackrunBuildFailed => 0,
        };

        let noisy = reason.noisy();
        let should_log = self.dry_run || !noisy || count % self.skip_log_every == 0;
        let reason_str = reason.as_str();

        if should_log {
            if self.dry_run {
                tracing::info!(target: "strategy_skip", reason = %reason_str, %detail, count, "Dry-run skip");
            } else {
                tracing::debug!(target: "strategy_skip", reason = %reason_str, %detail, count);
            }
        }
    }

    pub(in crate::services::strategy) fn amount_to_display(
        &self,
        amount: U256,
        token: Address,
    ) -> f64 {
        let decimals = self
            .token_manager
            .decimals(self.chain_id, token)
            .unwrap_or(18);
        units_to_float(amount, decimals)
    }

    #[allow(dead_code)]
    pub(in crate::services::strategy) fn ensure_native_out(
        &self,
        amount: U256,
        token: Address,
    ) -> Option<U256> {
        if token == self.wrapped_native {
            Some(amount)
        } else {
            None
        }
    }

    pub(in crate::services::strategy) fn execution_router(
        &self,
        observed: &ObservedSwap,
    ) -> Address {
        if Some(observed.router) == self.universal_router {
            match observed.router_kind {
                crate::services::strategy::decode::RouterKind::V2Like => {
                    self.exec_router_v2.unwrap_or(observed.router)
                }
                crate::services::strategy::decode::RouterKind::V3Like => {
                    self.exec_router_v3.unwrap_or(observed.router)
                }
            }
        } else {
            observed.router
        }
    }

    pub(in crate::services::strategy) async fn estimate_native_out(
        &self,
        amount: U256,
        token: Address,
    ) -> Option<U256> {
        if token == self.wrapped_native {
            return Some(amount);
        }
        if !self.allow_non_wrapped_swaps {
            return None;
        }
        let info = self.token_manager.info(self.chain_id, token)?;
        let symbol = info.symbol.clone();
        let token_quote = self
            .price_feed
            .get_price(&format!("{symbol}USD"))
            .await
            .ok()?;
        let native_symbol = crate::common::constants::native_symbol_for_chain(self.chain_id);
        let native_quote = self
            .price_feed
            .get_price(&format!("{native_symbol}USD"))
            .await
            .ok()?;
        if token_quote.price <= 0.0 || native_quote.price <= 0.0 {
            return None;
        }
        let amount_float = self.amount_to_display(amount, token);
        let usd_value = amount_float * token_quote.price;
        let native_value = usd_value / native_quote.price;
        if !native_value.is_finite() || native_value <= 0.0 {
            return None;
        }
        let wei_estimate = native_value * 1_000_000_000_000_000_000.0;
        Some(U256::from(wei_estimate as u128))
    }

    /// Deterministic pseudo-identifier for a V3 pool based on token path and fee tiers.
    /// We hash the canonical path encoding and take the last 20 bytes so it fits into Address.
    pub(crate) fn v3_pool_identifier(tokens: &[Address], fees: &[u32]) -> Option<Address> {
        if tokens.len() < 2 || fees.len() + 1 != tokens.len() {
            return None;
        }
        let mut buf = Vec::with_capacity(tokens.len() * 23);
        buf.extend_from_slice(tokens[0].as_slice());
        for (i, fee) in fees.iter().enumerate() {
            buf.extend_from_slice(&fee.to_be_bytes()[1..]); // 3-byte fee tier
            buf.extend_from_slice(tokens[i + 1].as_slice());
        }
        let h = keccak256(buf);
        Some(Address::from_slice(&h.as_slice()[12..]))
    }

    pub fn new(
        tx_rx: Receiver<StrategyWork>,
        block_rx: BroadcastReceiver<Header>,
        safety_guard: Arc<SafetyGuard>,
        bundle_sender: SharedBundleSender,
        db: Database,
        portfolio: Arc<PortfolioManager>,
        gas_oracle: GasOracle,
        price_feed: PriceFeed,
        chain_id: u64,
        max_gas_price_gwei: u64,
        gas_cap_multiplier_bps: u64,
        simulator: Simulator,
        token_manager: Arc<TokenManager>,
        stats: Arc<StrategyStats>,
        signer: PrivateKeySigner,
        nonce_manager: NonceManager,
        slippage_bps: u64,
        http_provider: HttpProvider,
        dry_run: bool,
        router_allowlist: Arc<DashSet<Address>>,
        router_discovery: Option<Arc<crate::services::strategy::router_discovery::RouterDiscovery>>,
        skip_log_every: u64,
        wrapped_native: Address,
        allow_non_wrapped_swaps: bool,
        executor: Option<Address>,
        executor_bribe_bps: u64,
        executor_bribe_recipient: Option<Address>,
        flashloan_enabled: bool,
        flashloan_providers: Vec<FlashloanProvider>,
        aave_pool: Option<Address>,
        reserve_cache: Arc<ReserveCache>,
        sandwich_attacks_enabled: bool,
        simulation_backend: String,
        worker_limit: usize,
        shutdown: CancellationToken,
        receipt_poll_ms: u64,
        receipt_timeout_ms: u64,
        receipt_confirm_blocks: u64,
        emergency_exit_on_unknown_receipt: bool,
    ) -> Self {
        let semaphore_size = worker_limit.max(1);
        let universal_router = constants::default_uniswap_universal_router(chain_id);
        let exec_router_v2 = constants::default_uniswap_v2_router(chain_id);
        let exec_router_v3 = constants::default_uniswap_v3_router(chain_id);
        Self {
            tx_rx: Mutex::new(tx_rx),
            mut_block_rx: Mutex::new(block_rx),
            safety_guard,
            bundle_sender,
            db,
            portfolio,
            gas_oracle,
            price_feed,
            chain_id,
            stats,
            max_gas_price_gwei,
            gas_cap_multiplier_bps: gas_cap_multiplier_bps.max(10_000),
            simulator,
            token_manager,
            signer,
            nonce_manager,
            slippage_bps,
            http_provider,
            dry_run,
            router_allowlist,
            router_discovery,
            skip_log_every: skip_log_every.max(1),
            wrapped_native,
            allow_non_wrapped_swaps,
            universal_router,
            exec_router_v2,
            exec_router_v3,
            inventory_tokens: DashSet::new(),
            last_rebalance: Mutex::new(Instant::now()),
            toxic_tokens: DashSet::new(),
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            flashloan_providers,
            aave_pool,
            reserve_cache,
            bundle_state: Arc::new(Mutex::new(None)),
            v3_quote_cache: DashMap::new(),
            probe_gas_stats: DashMap::new(),
            router_sim_stats: DashMap::new(),
            current_block: AtomicU64::new(0),
            sandwich_attacks_enabled,
            simulation_backend,
            worker_semaphore: Arc::new(Semaphore::new(semaphore_size)),
            shutdown,
            receipt_poll_ms: receipt_poll_ms.max(100),
            receipt_timeout_ms: receipt_timeout_ms.max(receipt_poll_ms.max(100)),
            receipt_confirm_blocks: receipt_confirm_blocks.max(1),
            emergency_exit_on_unknown_receipt,
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("StrategyExecutor: waiting for pending transactions");
        tracing::info!(
            target: "strategy",
            chain = self.chain_id,
            backend = %self.simulation_backend,
            sandwiches_enabled = self.sandwich_attacks_enabled,
            "Strategy configured"
        );

        let executor = Arc::new(self);

        // Attempt to restore persisted nonce state before processing work.
        let _ = executor.restore_bundle_state().await;

        // Spawn a lightweight block watcher so work processing never waits on block stream.
        let block_exec = executor.clone();
        tokio::spawn(async move {
            block_exec.block_watcher().await;
        });

        loop {
            let work_opt = tokio::select! {
                _ = executor.shutdown.cancelled() => {
                    tracing::info!(target: "strategy", "Shutdown requested; stopping strategy work loop");
                    None
                }
                work = async {
                    let mut rx = executor.tx_rx.lock().await;
                    rx.recv().await
                } => work
            };

            match work_opt {
                Some(work) => {
                    executor
                        .stats
                        .ingest_queue_depth
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        })
                        .ok();
                    let permit = executor
                        .worker_semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("semaphore closed");
                    let exec = executor.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        exec.process_work(work).await;
                    });
                }
                None => break,
            }
        }

        Ok(())
    }

    async fn block_watcher(self: Arc<Self>) {
        loop {
            let msg = tokio::select! {
                _ = self.shutdown.cancelled() => {
                    tracing::info!(target: "strategy", "Shutdown requested; stopping block watcher");
                    break;
                }
                msg = async {
                    let mut rx = self.mut_block_rx.lock().await;
                    rx.recv().await
                } => msg
            };

            match msg {
                Ok(header) => {
                    tracing::debug!("StrategyExecutor: observed new block {:?}", header.hash);
                    let number = header.inner.number;
                    let prev = self.current_block.swap(number as u64, Ordering::Relaxed);
                    if prev != number as u64 {
                        let mut guard = self.bundle_state.lock().await;
                        *guard = None;
                        // Persist fresh state baseline for the new block.
                        if let Ok(base) = self.nonce_manager.get_base_nonce(number as u64).await {
                            self.persist_nonce_state(number as u64, base, &HashSet::new())
                                .await;
                        }
                    }
                    let _ = self.maybe_rebalance_inventory().await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    }

    /// Rolling probe gas estimate per router with a 20% safety margin.
    pub(crate) fn probe_gas_limit(&self, router: Address) -> u64 {
        let base = PROBE_GAS_LIMIT;
        if let Some(entry) = self.probe_gas_stats.get(&router) {
            let (sum, count) = *entry;
            if count > 0 {
                let avg = sum.saturating_div(count);
                return avg
                    .saturating_mul(12)
                    .checked_div(10)
                    .unwrap_or(avg)
                    .clamp(150_000, 500_000);
            }
        }
        base
    }

    pub(crate) fn record_probe_gas(&self, router: Address, used: u64) {
        let used = used.clamp(60_000, 600_000);
        self.probe_gas_stats
            .entry(router)
            .and_modify(|(sum, count)| {
                // Decaying average: keep weights bounded to avoid overflow.
                let new_sum = sum.saturating_mul(9).checked_div(10).unwrap_or(*sum);
                *sum = new_sum.saturating_add(used);
                *count = count.saturating_add(1).min(10);
            })
            .or_insert((used, 1));
    }

    pub(in crate::services::strategy) async fn probe_v3_sell_for_toxicity(
        &self,
        router: Address,
        path: Vec<u8>,
        amount_in: U256,
        expected_out: U256,
    ) -> Result<bool, AppError> {
        if amount_in.is_zero() || expected_out.is_zero() {
            return Ok(false);
        }
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 60);
        let token_in = match parse_v3_path(&path).and_then(|p| p.tokens.first().copied()) {
            Some(t) => t,
            None => return Ok(true),
        };
        let approve_calldata = ERC20::new(token_in, self.http_provider.clone())
            .approve(router, amount_in)
            .calldata()
            .to_vec();
        let calldata = UniV3Router::new(router, self.http_provider.clone())
            .exactInput(UniV3Router::ExactInputParams {
                path: path.clone().into(),
                recipient: self.signer.address(),
                deadline,
                amountIn: amount_in,
                amountOutMinimum: U256::ZERO,
            })
            .calldata()
            .to_vec();
        let probe_gas = self.probe_gas_limit(router);
        let approve_req = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(token_in)),
            gas: Some(70_000),
            value: Some(U256::ZERO),
            input: TransactionInput::new(Bytes::from(approve_calldata)),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let req = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            gas: Some(probe_gas.saturating_mul(2)),
            value: Some(U256::ZERO),
            input: TransactionInput::new(Bytes::from(calldata)),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let sims = self
            .simulator
            .simulate_bundle_requests(&[approve_req, req], None)
            .await?;
        if sims.len() < 2 {
            return Ok(true);
        }
        if !sims[0].success {
            return Ok(true);
        }
        let outcome = &sims[1];
        if !outcome.success {
            tracing::debug!(target: "strategy", "V3 probe revert; marking toxic");
            return Ok(false);
        }
        self.record_probe_gas(router, outcome.gas_used);
        if outcome.return_data.is_empty() {
            return Ok(true);
        }
        match UniV3Router::exactInputCall::abi_decode_returns(&outcome.return_data) {
            Ok(amount_out) => {
                let tolerance_bps = U256::from(10_000u64 - TAX_TOLERANCE_BPS);
                let ok = amount_out.saturating_mul(U256::from(10_000u64))
                    >= expected_out.saturating_mul(tolerance_bps);
                Ok(ok)
            }
            Err(_) => Ok(true),
        }
    }

    fn current_head_or(&self, fallback: u64) -> u64 {
        let head = self.current_block.load(Ordering::Relaxed);
        if head > 0 { head } else { fallback }
    }

    fn receipt_is_confirmed(
        current_head: u64,
        receipt_block: u64,
        confirm_blocks: u64,
    ) -> bool {
        let needed_head = receipt_block.saturating_add(confirm_blocks.saturating_sub(1));
        current_head >= needed_head
    }

    pub(in crate::services::strategy) async fn await_receipt(
        &self,
        hash: &B256,
    ) -> Result<ReceiptStatus, AppError> {
        let timeout = std::time::Duration::from_millis(self.receipt_timeout_ms.max(1));
        let poll = std::time::Duration::from_millis(self.receipt_poll_ms.max(1));
        let started = std::time::Instant::now();

        loop {
            if started.elapsed() >= timeout {
                break;
            }

            let mut current_head = self.current_head_or(0);
            if current_head == 0 {
                if let Ok(head) = self.http_provider.get_block_number().await {
                    current_head = head;
                    self.current_block.store(head, Ordering::Relaxed);
                }
            }

            match self.http_provider.get_transaction_receipt(*hash).await {
                Ok(Some(rcpt)) => {
                    let block_num = rcpt.block_number;
                    let status = rcpt.status();
                    if let Err(e) = self
                        .db
                        .update_status(
                            &format!("{:#x}", hash),
                            block_num.map(|b| b as i64),
                            Some(status),
                        )
                        .await
                    {
                        tracing::warn!(target: "strategy", error = %e, "Failed to persist tx status");
                    }

                    if !status {
                        return Ok(ReceiptStatus::ConfirmedRevert);
                    }

                    if let Some(receipt_block) = block_num {
                        if Self::receipt_is_confirmed(
                            current_head.max(receipt_block),
                            receipt_block,
                            self.receipt_confirm_blocks.max(1),
                        ) {
                            return Ok(ReceiptStatus::ConfirmedSuccess);
                        }
                    } else {
                        return Ok(ReceiptStatus::ConfirmedSuccess);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(
                        target: "strategy",
                        error = %e,
                        hash = %format!("{:#x}", hash),
                        "Receipt lookup error; retrying"
                    );
                }
            }

            tokio::time::sleep(poll).await;
        }

        Ok(ReceiptStatus::UnknownTimeout)
    }
}

#[allow(dead_code)]
fn wei_to_eth_f64(value: U256) -> f64 {
    units_to_float(value, 18)
}

#[allow(dead_code)]
fn units_to_float(value: U256, decimals: u8) -> f64 {
    let scale = 10f64.powi(decimals as i32);
    let num = value.to_string().parse::<f64>().unwrap_or(0.0);
    num / scale
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::WETH_MAINNET;
    use crate::core::executor::BundleSender;
    use crate::core::simulation::SimulationBackend;
    use crate::network::gas::GasFees;
    use crate::network::price_feed::PriceApiKeys;
    use crate::services::strategy::decode::{
        ObservedSwap, RouterKind, SwapDirection, decode_swap_input, direction, encode_v3_path,
        parse_v3_path, target_token, v3_fee_sane,
    };
    use crate::services::strategy::routers::UniV2Router;
    use alloy::rpc::types::Header;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::Ordering;
    use url::Url;

    #[test]
    fn decodes_eth_swap() {
        let router = WETH_MAINNET;
        let call = UniV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(5u64),
            path: vec![WETH_MAINNET, Address::from([2u8; 20])],
            to: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
        };
        let data = call.abi_encode();
        let decoded = decode_swap_input(router, &data, U256::from(1_000_000_000_000_000_000u128))
            .expect("decode");
        assert_eq!(decoded.path.len(), 2);
        assert_eq!(decoded.min_out, U256::from(5u64));
    }

    #[test]
    fn wei_to_eth_conversion() {
        let two_eth = U256::from(2_000_000_000_000_000_000u128);
        let eth = wei_to_eth_f64(two_eth);
        assert!((eth - 2.0).abs() < 1e-9);
    }

    #[test]
    fn decodes_uniswap_v3_exact_input_single() {
        use alloy::primitives::{U160, aliases::U24};
        let params = UniV3Router::ExactInputSingleParams {
            tokenIn: WETH_MAINNET,
            tokenOut: Address::from([2u8; 20]),
            fee: U24::from(500u32),
            recipient: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
            amountIn: U256::from(1_000_000_000_000_000_000u128),
            amountOutMinimum: U256::from(5u64),
            sqrtPriceLimitX96: U160::ZERO,
        };
        let call = UniV3Router::exactInputSingleCall { params };
        let data = call.abi_encode();
        let decoded =
            decode_swap_input(WETH_MAINNET, &data, U256::from(0u64)).expect("decode v3 single");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path.len(), 2);
    }

    #[test]
    fn decodes_uniswap_v2_exact_out_variant() {
        let router = WETH_MAINNET;
        let token = Address::from([2u8; 20]);
        let call = UniV2Router::swapTokensForExactETHCall {
            amountOut: U256::from(3_000u64),
            amountInMax: U256::from(10_000u64),
            path: vec![token, WETH_MAINNET],
            to: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
        };
        let data = call.abi_encode();
        let decoded = decode_swap_input(router, &data, U256::ZERO).expect("decode v2 exact out");
        assert_eq!(decoded.router_kind, RouterKind::V2Like);
        assert_eq!(decoded.amount_in, U256::from(10_000u64));
        assert_eq!(decoded.min_out, U256::from(3_000u64));
    }

    #[test]
    fn decodes_uniswap_v2_fee_on_transfer_variant() {
        let router = WETH_MAINNET;
        let token = Address::from([2u8; 20]);
        let call = UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall {
            amountIn: U256::from(9_000u64),
            amountOutMin: U256::from(2_000u64),
            path: vec![token, WETH_MAINNET],
            to: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
        };
        let data = call.abi_encode();
        let decoded = decode_swap_input(router, &data, U256::ZERO).expect("decode v2 fot");
        assert_eq!(decoded.router_kind, RouterKind::V2Like);
        assert_eq!(decoded.amount_in, U256::from(9_000u64));
        assert_eq!(decoded.min_out, U256::from(2_000u64));
    }

    #[test]
    fn decodes_uniswap_v3_exact_output_single() {
        use alloy::primitives::{U160, aliases::U24};
        let token_out = Address::from([2u8; 20]);
        let params = UniV3Router::ExactOutputSingleParams {
            tokenIn: WETH_MAINNET,
            tokenOut: token_out,
            fee: U24::from(500u32),
            recipient: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
            amountOut: U256::from(8_000u64),
            amountInMaximum: U256::from(10_000u64),
            sqrtPriceLimitX96: U160::ZERO,
        };
        let call = UniV3Router::exactOutputSingleCall { params };
        let data = call.abi_encode();
        let decoded = decode_swap_input(WETH_MAINNET, &data, U256::ZERO).expect("decode v3 out");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path, vec![WETH_MAINNET, token_out]);
        assert_eq!(decoded.v3_fees, vec![500u32]);
        assert_eq!(decoded.amount_in, U256::from(10_000u64));
        assert_eq!(decoded.min_out, U256::from(8_000u64));
    }

    #[test]
    fn decodes_uniswap_v3_exact_output_reverses_path_to_canonical() {
        let token_mid = Address::from([7u8; 20]);
        let token_out = Address::from([9u8; 20]);
        // exactOutput path is encoded in reverse order: out -> ... -> in
        let reverse_path = encode_v3_path(&[token_out, token_mid, WETH_MAINNET], &[3000, 500])
            .expect("encode reverse v3 path");
        let params = UniV3Router::ExactOutputParams {
            path: reverse_path.into(),
            recipient: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
            amountOut: U256::from(5_000u64),
            amountInMaximum: U256::from(9_000u64),
        };
        let call = UniV3Router::exactOutputCall { params };
        let data = call.abi_encode();
        let decoded =
            decode_swap_input(WETH_MAINNET, &data, U256::ZERO).expect("decode v3 exact out");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path, vec![WETH_MAINNET, token_mid, token_out]);
        assert_eq!(decoded.v3_fees, vec![500u32, 3000u32]);
        assert_eq!(decoded.amount_in, U256::from(9_000u64));
        assert_eq!(decoded.min_out, U256::from(5_000u64));
        assert_eq!(
            decoded.v3_path,
            encode_v3_path(&[WETH_MAINNET, token_mid, token_out], &[500, 3000])
        );
    }

    #[test]
    fn parses_uniswap_v3_path() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 1u8, 244u8]); // fee 500
        let out = Address::from([9u8; 20]);
        path.extend_from_slice(out.as_slice());
        let parsed = parse_v3_path(&path).expect("parse path");
        assert_eq!(parsed.tokens.len(), 2);
        assert_eq!(parsed.tokens[1], out);
        assert_eq!(parsed.fees, vec![500]);
    }

    #[test]
    fn target_token_prefers_terminal_on_buy_paths() {
        let token_mid = Address::from([2u8; 20]);
        let token_final = Address::from([3u8; 20]);
        let path = vec![WETH_MAINNET, token_mid, token_final];
        assert_eq!(target_token(&path, WETH_MAINNET), Some(token_final));
    }

    #[test]
    fn target_token_prefers_source_on_sell_paths() {
        let token_start = Address::from([4u8; 20]);
        let token_mid = Address::from([5u8; 20]);
        let path = vec![token_start, token_mid, WETH_MAINNET];
        assert_eq!(target_token(&path, WETH_MAINNET), Some(token_start));
    }

    #[test]
    fn rejects_invalid_v3_path_length() {
        // Missing last token bytes.
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 1u8, 244u8]); // fee 500
        path.extend_from_slice(&[1u8; 10]); // truncated address
        assert!(parse_v3_path(&path).is_none());
    }

    #[test]
    fn rejects_invalid_v3_fee() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 0u8, 1u8]); // fee 1 (not standard)
        path.extend_from_slice([2u8; 20].as_slice());
        assert!(parse_v3_path(&path).is_none());
    }

    #[test]
    fn accepts_low_v3_fee_tier() {
        assert!(v3_fee_sane(100));
    }

    #[test]
    fn detects_token_calls() {
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb, 0u8];
        assert!(StrategyExecutor::is_common_token_call(&transfer_selector));
        let random = [0x12, 0x34, 0x56, 0x78];
        assert!(!StrategyExecutor::is_common_token_call(&random));
    }

    #[test]
    fn classifies_swap_direction() {
        let buy = ObservedSwap {
            router: Address::ZERO,
            path: vec![WETH_MAINNET, Address::from([2u8; 20])],
            v3_fees: Vec::new(),
            v3_path: None,
            amount_in: U256::from(1u64),
            min_out: U256::ZERO,
            recipient: Address::ZERO,
            router_kind: RouterKind::V2Like,
        };
        assert_eq!(direction(&buy, WETH_MAINNET), SwapDirection::BuyWithEth);
        let sell = ObservedSwap {
            path: vec![Address::from([2u8; 20]), WETH_MAINNET],
            ..buy
        };
        assert_eq!(direction(&sell, WETH_MAINNET), SwapDirection::SellForEth);
    }

    #[test]
    fn price_ratio_handles_zero_and_scales() {
        assert_eq!(
            StrategyExecutor::test_price_ratio_ppm_public(U256::from(10u64), U256::ZERO),
            U256::ZERO
        );
        let ratio =
            StrategyExecutor::test_price_ratio_ppm_public(U256::from(2u64), U256::from(1u64));
        assert_eq!(ratio, U256::from(2_000_000u64));
    }

    #[test]
    fn backrun_divisors_change_with_balance() {
        let small =
            StrategyExecutor::test_backrun_divisors_public(U256::from(50_000_000_000_000_000u128));
        let mid =
            StrategyExecutor::test_backrun_divisors_public(U256::from(300_000_000_000_000_000u128));
        let large = StrategyExecutor::test_backrun_divisors_public(U256::from(
            3_000_000_000_000_000_000u128,
        ));
        assert!(small.0 >= mid.0 && mid.0 >= large.0);
        assert!(small.1 >= mid.1 && mid.1 >= large.1);
        assert!(small.1 >= small.0);
        assert!(mid.1 >= mid.0);
        assert!(large.1 >= large.0);
    }

    #[test]
    fn dynamic_profit_floor_scales_up() {
        let floor_small = StrategyExecutor::test_dynamic_profit_floor_public(U256::from(
            10_000_000_000_000_000u128,
        ));
        let floor_large = StrategyExecutor::test_dynamic_profit_floor_public(U256::from(
            20_000_000_000_000_000_000u128,
        ));
        assert!(
            floor_large > floor_small,
            "profit floor should scale with balance"
        );
        assert!(floor_small >= U256::from(20_000_000_000_000u64));
    }

    #[test]
    fn dynamic_backrun_value_respects_minimum() {
        let value = StrategyExecutor::test_dynamic_backrun_value_public(
            U256::from(1u64),
            U256::from(10_000_000_000_000_000_000u128),
            500,
            220_000,
            50_000_000_000,
        )
        .expect("backrun value");
        assert!(
            value >= U256::from(100_000_000_000_000u64),
            "should enforce minimum backrun size"
        );
    }

    #[test]
    fn dynamic_backrun_value_caps_by_wallet_and_gas_buffer() {
        let wallet = U256::from(50_000_000_000_000_000u128); // 0.05 ETH
        let value = StrategyExecutor::test_dynamic_backrun_value_public(
            U256::from(10_000_000_000_000_000u128),
            wallet,
            500,
            220_000,
            100_000_000_000, // 100 gwei
        )
        .expect("backrun value");
        // With wallet <0.1 ETH, max divisor (4,6) applies; gas buffer will cap to wallet/6.
        assert!(
            value <= wallet / U256::from(6u64),
            "value should be capped by wallet/gas buffer"
        );
    }

    #[tokio::test]
    async fn ensure_native_out_only_allows_wrapped_native() {
        let exec = dummy_executor_for_tests().await;
        let other = Address::from([9u8; 20]);
        assert!(exec.ensure_native_out(U256::from(10u64), other).is_none());
        assert_eq!(
            exec.ensure_native_out(U256::from(5u64), WETH_MAINNET),
            Some(U256::from(5u64))
        );
    }

    #[tokio::test]
    async fn lease_and_peek_respects_reserved_nonces() {
        use std::collections::HashSet;

        let exec = dummy_executor_for_tests().await;
        exec.current_block.store(10, Ordering::Relaxed);
        {
            let mut guard = exec.bundle_state.lock().await;
            *guard = Some(BundleState {
                block: 10,
                next_nonce: 5,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }

        let lease = exec.lease_nonces(3).await.expect("lease");
        assert_eq!(lease.base, 5);
        let peek = exec.peek_nonce_for_sim().await.expect("peek");
        assert_eq!(peek, 8);
    }

    #[test]
    fn flashloan_request_template_sets_fields() {
        let gas_fees = GasFees {
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 5,
            next_base_fee_per_gas: 0,
            base_fee_per_gas: 0,
            p50_priority_fee_per_gas: None,
            p90_priority_fee_per_gas: None,
            gas_used_ratio: None,
            suggested_max_fee_per_gas: None,
        };
        let calldata = vec![0x01, 0x02];
        let req = StrategyExecutor::flashloan_request_template(
            Address::from([1u8; 20]),
            Address::from([2u8; 20]),
            &gas_fees,
            300_000,
            7,
            calldata.clone(),
            1,
        );
        assert_eq!(req.nonce, Some(7));
        assert_eq!(req.gas, Some(300_000));
        assert_eq!(req.max_fee_per_gas, Some(100));
        assert_eq!(req.max_priority_fee_per_gas, Some(5));
        assert_eq!(req.to, Some(TxKind::Call(Address::from([2u8; 20]))));
        assert_eq!(req.from, Some(Address::from([1u8; 20])));
        assert_eq!(req.chain_id, Some(1));
        assert_eq!(req.input.clone().into_input().unwrap_or_default(), calldata);
    }

    #[test]
    fn detects_nonce_gap_errors() {
        let gap_errs = [
            AppError::Strategy("nonce too high".into()),
            AppError::Strategy("Nonce gap detected".into()),
            AppError::Strategy("missing nonce".into()),
        ];
        for e in gap_errs {
            assert!(StrategyExecutor::is_nonce_gap_error(&e));
        }

        let other = AppError::Strategy("insufficient funds".into());
        assert!(!StrategyExecutor::is_nonce_gap_error(&other));
    }

    #[tokio::test]
    async fn lease_nonces_advances_bundle_state_without_rpc() {
        let exec = dummy_executor_for_tests().await;
        exec.current_block.store(100, Ordering::Relaxed);
        {
            let mut guard = exec.bundle_state.lock().await;
            *guard = Some(BundleState {
                block: 100,
                next_nonce: 5,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }

        let lease = exec.lease_nonces(2).await.expect("lease");
        assert_eq!(lease.base, 5);
        let guard = exec.bundle_state.lock().await;
        assert_eq!(guard.as_ref().unwrap().next_nonce, 7);
    }

    #[tokio::test]
    async fn gas_ratio_rejects_thin_margin() {
        let exec = dummy_executor_for_tests().await;
        assert!(
            !exec.gas_ratio_ok(
                U256::from(1_000u64),
                U256::from(1_050u64),
                U256::from(1_000_000u64)
            ),
            "margin below 12% should be rejected"
        );
    }

    #[tokio::test]
    async fn gas_ratio_accepts_healthy_margin() {
        let exec = dummy_executor_for_tests().await;
        assert!(exec.gas_ratio_ok(
            U256::from(1_000u64),
            U256::from(3_000u64),
            U256::from(1_000_000u64)
        ));
    }

    #[tokio::test]
    async fn skip_reason_maps_to_expected_counter() {
        let exec = dummy_executor_for_tests().await;
        exec.log_skip(SkipReason::UnsupportedRouter, "unsupported");
        assert_eq!(
            exec.stats
                .skip_unsupported_router
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        exec.log_skip(SkipReason::DecodeFailed, "decode");
        assert_eq!(
            exec.stats
                .skip_decode_failed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn receipt_confirmation_depth_window() {
        assert!(!StrategyExecutor::receipt_is_confirmed(100, 100, 4));
        assert!(!StrategyExecutor::receipt_is_confirmed(102, 100, 4));
        assert!(StrategyExecutor::receipt_is_confirmed(103, 100, 4));
    }

    #[tokio::test]
    async fn receipt_timeout_returns_unknown_status() {
        let mut exec = dummy_executor_for_tests().await;
        exec.receipt_poll_ms = 100;
        exec.receipt_timeout_ms = 100;
        let status = exec.await_receipt(&B256::ZERO).await.expect("receipt status");
        assert_eq!(status, ReceiptStatus::UnknownTimeout);
    }

    #[tokio::test]
    async fn zero_gas_cap_is_unbounded() {
        let mut exec = dummy_executor_for_tests().await;
        exec.max_gas_price_gwei = 0;
        assert_eq!(exec.hard_gas_cap_wei(), U256::MAX);
    }

    #[tokio::test]
    async fn dynamic_gas_cap_never_drops_below_base_fee_floor() {
        let exec = dummy_executor_for_tests().await;
        let fees = GasFees {
            max_fee_per_gas: 130,
            max_priority_fee_per_gas: 25,
            next_base_fee_per_gas: 120,
            base_fee_per_gas: 110,
            p50_priority_fee_per_gas: Some(20),
            p90_priority_fee_per_gas: Some(40),
            gas_used_ratio: Some(0.6),
            suggested_max_fee_per_gas: Some(150),
        };
        let cap = exec.dynamic_gas_cap(U256::from(1u64), &fees, U256::MAX);
        assert_eq!(cap.floor_wei, 120);
        assert_eq!(cap.cap_wei, U256::from(120u64));
    }

    #[tokio::test]
    async fn enforce_dynamic_gas_cap_clamps_tip_and_fee() {
        let _exec = dummy_executor_for_tests().await;
        let mut fees = GasFees {
            max_fee_per_gas: 180,
            max_priority_fee_per_gas: 60,
            next_base_fee_per_gas: 120,
            base_fee_per_gas: 110,
            p50_priority_fee_per_gas: Some(20),
            p90_priority_fee_per_gas: Some(40),
            gas_used_ratio: Some(0.6),
            suggested_max_fee_per_gas: Some(150),
        };
        let impossible = StrategyExecutor::enforce_dynamic_gas_cap(&mut fees, U256::from(145u64));
        assert!(!impossible);
        assert_eq!(fees.max_fee_per_gas, 145);
        assert_eq!(fees.max_priority_fee_per_gas, 25);
    }

    #[tokio::test]
    async fn enforce_dynamic_gas_cap_flags_impossible_cap() {
        let _exec = dummy_executor_for_tests().await;
        let mut fees = GasFees {
            max_fee_per_gas: 180,
            max_priority_fee_per_gas: 60,
            next_base_fee_per_gas: 120,
            base_fee_per_gas: 110,
            p50_priority_fee_per_gas: Some(20),
            p90_priority_fee_per_gas: Some(40),
            gas_used_ratio: Some(0.6),
            suggested_max_fee_per_gas: Some(150),
        };
        let impossible = StrategyExecutor::enforce_dynamic_gas_cap(&mut fees, U256::from(100u64));
        assert!(impossible);
        assert_eq!(fees.max_fee_per_gas, 180);
        assert_eq!(fees.max_priority_fee_per_gas, 60);
    }

    #[tokio::test]
    async fn boost_fees_respects_suggested_cap_with_tip_outlier() {
        let exec = dummy_executor_for_tests().await;
        let mut fees = GasFees {
            max_fee_per_gas: 200_000_000,
            max_priority_fee_per_gas: 100_000_000,
            next_base_fee_per_gas: 120_000_000,
            base_fee_per_gas: 110_000_000,
            p50_priority_fee_per_gas: Some(400_000_000),
            p90_priority_fee_per_gas: Some(20_000_000_000),
            gas_used_ratio: Some(0.5),
            suggested_max_fee_per_gas: Some(160_000_000),
        };
        exec.boost_fees(&mut fees, None, None);
        assert!(fees.max_fee_per_gas <= 160_000_000);
        assert!(fees.max_priority_fee_per_gas <= 40_000_000);
        assert!(fees.max_fee_per_gas >= 120_000_000);
    }

    #[tokio::test]
    async fn boost_fees_never_drops_below_base_when_suggested_cap_is_tiny() {
        let exec = dummy_executor_for_tests().await;
        let mut fees = GasFees {
            max_fee_per_gas: 22_000_000_000,
            max_priority_fee_per_gas: 2_000_000_000,
            next_base_fee_per_gas: 19_800_000_000,
            base_fee_per_gas: 19_500_000_000,
            p50_priority_fee_per_gas: Some(2_000_000_000),
            p90_priority_fee_per_gas: Some(4_000_000_000),
            gas_used_ratio: Some(0.7),
            suggested_max_fee_per_gas: Some(155_000_000),
        };
        exec.boost_fees(&mut fees, None, None);
        assert_eq!(fees.max_fee_per_gas, 19_800_000_000);
        assert_eq!(fees.max_priority_fee_per_gas, 0);
    }

    pub(crate) async fn dummy_executor_for_tests() -> StrategyExecutor {
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let (_block_tx, block_rx) = tokio::sync::broadcast::channel::<Header>(1);
        let http = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let safety_guard = Arc::new(SafetyGuard::new());
        let stats = Arc::new(StrategyStats::default());
        let bundle_sender = Arc::new(BundleSender::new(
            http.clone(),
            true,
            "http://localhost:8545".to_string(),
            "http://localhost:8545".to_string(),
            vec![
                "flashbots".to_string(),
                "beaverbuild.org".to_string(),
                "rsync".to_string(),
                "Titan".to_string(),
            ],
            PrivateKeySigner::random(),
            stats.clone(),
        ));
        let db = Database::new("sqlite::memory:").await.expect("db");
        let portfolio = Arc::new(PortfolioManager::new(http.clone(), Address::ZERO));
        let gas_oracle = GasOracle::new(http.clone(), 1);
        let price_feed = PriceFeed::new(http.clone(), HashMap::new(), PriceApiKeys::default());
        let simulator = Simulator::new(http.clone(), SimulationBackend::new("revm"));
        let token_manager = Arc::new(TokenManager::default());
        let nonce_manager = NonceManager::new(http.clone(), Address::ZERO);
        let reserve_cache = Arc::new(ReserveCache::new(http.clone()));
        let router_allowlist = Arc::new(DashSet::new());

        StrategyExecutor::new(
            rx,
            block_rx,
            safety_guard,
            bundle_sender,
            db,
            portfolio,
            gas_oracle,
            price_feed,
            1,
            100,
            12_000,
            simulator,
            token_manager,
            stats,
            PrivateKeySigner::random(),
            nonce_manager,
            50,
            http.clone(),
            true,
            router_allowlist,
            None,
            500,
            WETH_MAINNET,
            false,
            None,
            0,
            None,
            false,
            vec![FlashloanProvider::Balancer],
            None,
            reserve_cache,
            true,
            "revm".to_string(),
            8,
            CancellationToken::new(),
            500,
            60_000,
            4,
            false,
        )
    }

    #[test]
    fn records_simulation_latency_metrics() {
        let stats = StrategyStats::default();
        stats.record_sim_latency("mempool", 42);
        stats.record_sim_latency("mev_share", 58);

        assert_eq!(
            stats
                .sim_latency_ms_sum
                .load(std::sync::atomic::Ordering::Relaxed),
            100
        );
        assert_eq!(
            stats
                .sim_latency_ms_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            stats
                .sim_latency_ms_sum_mempool
                .load(std::sync::atomic::Ordering::Relaxed),
            42
        );
        assert_eq!(
            stats
                .sim_latency_ms_count_mempool
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .sim_latency_ms_sum_mevshare
                .load(std::sync::atomic::Ordering::Relaxed),
            58
        );
        assert_eq!(
            stats
                .sim_latency_ms_count_mevshare
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}

#[cfg(test)]
pub(crate) use tests::dummy_executor_for_tests;
