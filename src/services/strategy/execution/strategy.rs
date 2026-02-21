// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::app::logging::{
    ansi_tables_enabled, format_framed_table, format_framed_table_with_blue_title,
};
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
use crate::services::strategy::decode::{ObservedSwap, RouterKind, encode_v3_path, parse_v3_path};
use crate::services::strategy::execution::work_queue::SharedWorkQueue;
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
use tokio::sync::{Mutex, Semaphore, broadcast::Receiver as BroadcastReceiver};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum StrategyWork {
    Mempool {
        tx: Box<Transaction>,
        received_at: std::time::Instant,
    },
    MevShareHint {
        hint: Box<MevShareHint>,
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
            SkipReason::UnknownRouter
                | SkipReason::TokenCall
                | SkipReason::DecodeFailed
                | SkipReason::RouterRevertRate
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllowlistCategory {
    Routers,
    Wrappers,
    Infra,
}

impl AllowlistCategory {
    pub fn metric_label(self) -> &'static str {
        match self {
            AllowlistCategory::Routers => "routers",
            AllowlistCategory::Wrappers => "wrappers",
            AllowlistCategory::Infra => "infra",
        }
    }
}

pub fn classify_allowlist_entry(name: &str) -> AllowlistCategory {
    let lower = name.trim().to_ascii_lowercase();
    if lower.contains("wrapped_native")
        || lower.contains("weth")
        || lower.contains("wsteth")
        || lower.contains("steth")
        || lower.contains("cbeth")
        || lower.contains("reth")
    {
        return AllowlistCategory::Wrappers;
    }
    if lower.contains("permit2")
        || lower.contains("multicall")
        || lower.contains("quoter")
        || lower.contains("approval_proxy")
        || lower.contains("addresses_provider")
    {
        return AllowlistCategory::Infra;
    }
    AllowlistCategory::Routers
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

#[derive(Clone, Debug, Default)]
pub struct RelayBundleStatus {
    pub replacement_uuid: Option<String>,
    pub bundle_id: Option<String>,
    pub status: String,
    pub updated_at_ms: i64,
}

pub(crate) const VICTIM_FEE_BUMP_BPS: u64 = 11_000;
pub(crate) const TAX_TOLERANCE_BPS: u64 = 500;
pub(crate) const PROBE_GAS_LIMIT: u64 = 220_000;
pub(crate) const V3_QUOTE_CACHE_TTL_MS: u64 = 250;
pub(crate) const TOXIC_PROBE_FAILURE_THRESHOLD: u32 = 3;
pub(crate) const TOXIC_PROBE_FAILURE_WINDOW_SECS: u64 = 1_800;
const DEFAULT_FALLBACK_GAS_CAP_GWEI: u64 = 500;
const DEFAULT_ROUTER_RISK_MIN_SAMPLES: u64 = 20;
const DEFAULT_ROUTER_RISK_FAIL_RATE_BPS: u64 = 4_000;
const DEFAULT_ROUTER_RISK_HARD_BLOCK: bool = false;
const DEFAULT_SANDWICH_RISK_MAX_VICTIM_SLIPPAGE_BPS: u64 = 1_500;
const DEFAULT_SANDWICH_RISK_SMALL_WALLET_WEI: u128 = 100_000_000_000_000_000u128; // 0.1 ETH

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
    pub skip_router_revert_rate: AtomicU64,
    pub skip_liquidity_depth: AtomicU64,
    pub skip_sandwich_risk: AtomicU64,
    pub skip_front_run_build_failed: AtomicU64,
    pub skip_backrun_build_failed: AtomicU64,
    pub decode_attempts_router: AtomicU64,
    pub decode_success_router: AtomicU64,
    pub decode_attempts_wrapper: AtomicU64,
    pub decode_success_wrapper: AtomicU64,
    pub decode_attempts_infra: AtomicU64,
    pub decode_success_infra: AtomicU64,
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
    pub relay_bundle_status: StdMutex<HashMap<String, RelayBundleStatus>>,
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

#[derive(Clone, Debug)]
pub(in crate::services::strategy) struct PerBlockInputs {
    pub block_number: u64,
    pub gas_fees: GasFees,
    pub wallet_balance: U256,
}

impl StrategyStats {
    pub fn record_decode_attempt(&self, category: AllowlistCategory, success: bool) {
        let (attempts, successes) = match category {
            AllowlistCategory::Routers => {
                (&self.decode_attempts_router, &self.decode_success_router)
            }
            AllowlistCategory::Wrappers => {
                (&self.decode_attempts_wrapper, &self.decode_success_wrapper)
            }
            AllowlistCategory::Infra => (&self.decode_attempts_infra, &self.decode_success_infra),
        };
        attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            successes.fetch_add(1, Ordering::Relaxed);
        }
    }

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

    pub fn record_relay_bundle_status(
        &self,
        relay_name: &str,
        status: &str,
        replacement_uuid: Option<&str>,
        bundle_id: Option<&str>,
    ) {
        let mut guard = self
            .relay_bundle_status
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(relay_name.to_string()).or_default();
        entry.status = status.to_string();
        entry.replacement_uuid = replacement_uuid.map(ToString::to_string);
        entry.bundle_id = bundle_id.map(ToString::to_string);
        entry.updated_at_ms = chrono::Utc::now().timestamp_millis();
    }
}

pub struct StrategyExecutor {
    pub(in crate::services::strategy) work_queue: SharedWorkQueue,
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
    pub(in crate::services::strategy) profit_guard_base_floor_multiplier_bps: u64,
    pub(in crate::services::strategy) profit_guard_cost_multiplier_bps: u64,
    pub(in crate::services::strategy) profit_guard_min_margin_bps: u64,
    pub(in crate::services::strategy) liquidity_ratio_floor_ppm: u64,
    pub(in crate::services::strategy) sell_min_native_out_wei: u64,
    pub(in crate::services::strategy) http_provider: HttpProvider,
    pub(in crate::services::strategy) dry_run: bool,
    pub(in crate::services::strategy) router_allowlist: Arc<DashSet<Address>>,
    pub(in crate::services::strategy) wrapper_allowlist: Arc<DashSet<Address>>,
    pub(in crate::services::strategy) infra_allowlist: Arc<DashSet<Address>>,
    pub(in crate::services::strategy) router_discovery:
        Option<Arc<crate::services::strategy::router_discovery::RouterDiscovery>>,
    pub(in crate::services::strategy) skip_log_every: u64,
    pub(in crate::services::strategy) wrapped_native: Address,
    pub(in crate::services::strategy) allow_non_wrapped_swaps: bool,
    pub(in crate::services::strategy) universal_routers: HashSet<Address>,
    pub(in crate::services::strategy) oneinch_routers: HashSet<Address>,
    pub(in crate::services::strategy) exec_router_v2: Option<Address>,
    pub(in crate::services::strategy) exec_router_v3: Option<Address>,
    pub(in crate::services::strategy) inventory_tokens: DashSet<Address>,
    pub(in crate::services::strategy) toxic_tokens: DashSet<Address>,
    pub(in crate::services::strategy) toxic_probe_failures: DashMap<Address, (u32, Instant)>,
    pub(in crate::services::strategy) executor: Option<Address>,
    pub(in crate::services::strategy) executor_bribe_bps: u64,
    pub(in crate::services::strategy) executor_bribe_recipient: Option<Address>,
    pub(in crate::services::strategy) flashloan_enabled: bool,
    pub(in crate::services::strategy) flashloan_providers: Vec<FlashloanProvider>,
    pub(in crate::services::strategy) aave_pool: Option<Address>,
    pub(in crate::services::strategy) reserve_cache: Arc<ReserveCache>,
    pub(in crate::services::strategy) bundle_state: Arc<Mutex<Option<BundleState>>>,
    pub(in crate::services::strategy) per_block_inputs: Arc<Mutex<Option<PerBlockInputs>>>,
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
    pub(in crate::services::strategy) profit_floor_abs_wei: U256,
    pub(in crate::services::strategy) profit_floor_mult_gas: u64,
    pub(in crate::services::strategy) profit_floor_min_usd: Option<f64>,
    pub(in crate::services::strategy) gas_ratio_limit_floor_bps: Option<u64>,
}

impl StrategyExecutor {
    fn env_u64_bounded(key: &str, default: u64, min: u64, max: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
            .clamp(min, max)
    }

    fn env_u32_bounded(key: &str, default: u32, min: u32, max: u32) -> u32 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(default)
            .clamp(min, max)
    }

    fn env_u128_bounded(key: &str, default: u128, min: u128, max: u128) -> u128 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<u128>().ok())
            .unwrap_or(default)
            .clamp(min, max)
    }

    fn env_bool(key: &str, default: bool) -> bool {
        std::env::var(key)
            .ok()
            .map(|v| {
                let t = v.trim().to_ascii_lowercase();
                matches!(t.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(default)
    }

    pub(in crate::services::strategy) fn router_risk_min_samples(&self) -> u64 {
        Self::env_u64_bounded(
            "ROUTER_RISK_MIN_SAMPLES",
            DEFAULT_ROUTER_RISK_MIN_SAMPLES,
            1,
            500,
        )
    }

    pub(in crate::services::strategy) fn router_risk_fail_rate_bps(&self) -> u64 {
        Self::env_u64_bounded(
            "ROUTER_RISK_FAIL_RATE_BPS",
            DEFAULT_ROUTER_RISK_FAIL_RATE_BPS,
            500,
            10_000,
        )
    }

    pub(in crate::services::strategy) fn router_risk_hard_block(&self) -> bool {
        Self::env_bool("ROUTER_RISK_HARD_BLOCK", DEFAULT_ROUTER_RISK_HARD_BLOCK)
    }

    pub(in crate::services::strategy) fn sandwich_risk_max_victim_slippage_bps(&self) -> u64 {
        Self::env_u64_bounded(
            "SANDWICH_RISK_MAX_VICTIM_SLIPPAGE_BPS",
            DEFAULT_SANDWICH_RISK_MAX_VICTIM_SLIPPAGE_BPS,
            100,
            9_500,
        )
    }

    pub(in crate::services::strategy) fn sandwich_risk_small_wallet_wei(&self) -> U256 {
        U256::from(Self::env_u128_bounded(
            "SANDWICH_RISK_SMALL_WALLET_WEI",
            DEFAULT_SANDWICH_RISK_SMALL_WALLET_WEI,
            1_000_000_000_000_000u128,     // 0.001 ETH
            5_000_000_000_000_000_000u128, // 5 ETH
        ))
    }

    pub(in crate::services::strategy) fn toxic_probe_failure_threshold(&self) -> u32 {
        Self::env_u32_bounded(
            "TOXIC_PROBE_FAILURE_THRESHOLD",
            TOXIC_PROBE_FAILURE_THRESHOLD,
            1,
            20,
        )
    }

    pub(in crate::services::strategy) fn toxic_probe_failure_window_secs(&self) -> u64 {
        Self::env_u64_bounded(
            "TOXIC_PROBE_FAILURE_WINDOW_SECS",
            TOXIC_PROBE_FAILURE_WINDOW_SECS,
            30,
            86_400,
        )
    }

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
        let min_bps = 8_000.0;
        let max_bps = 14_000.0;
        let bps = min_bps + (max_bps - min_bps) * scale;
        bps.round().clamp(min_bps, max_bps) as u64
    }

    pub(in crate::services::strategy) fn effective_slippage_bps(&self) -> u64 {
        if self.slippage_bps > 0 {
            return self.slippage_bps.clamp(1, 9_999);
        }
        let wallet_balance = self.portfolio.get_eth_balance_cached(self.chain_id);
        let eth_balance = wei_to_eth_f64(wallet_balance).max(0.0001);
        let base = 120.0 - 30.0 * (eth_balance * 100.0 + 1.0).log10();
        let volatility = self.price_feed.volatility_bps_cached("ETH").unwrap_or(0) as f64;
        let vol_adjust = volatility * 0.35;
        let mut slippage = base + vol_adjust;
        if let Some(gas_fees) = self.cached_gas_fees() {
            let stress_mult_bps = match self.classify_stress_profile(&gas_fees) {
                crate::services::strategy::risk::guards::StressProfile::UltraLow => 9_500u64,
                crate::services::strategy::risk::guards::StressProfile::Low => 9_800u64,
                crate::services::strategy::risk::guards::StressProfile::Normal => 10_000u64,
                crate::services::strategy::risk::guards::StressProfile::Elevated => 10_800u64,
                crate::services::strategy::risk::guards::StressProfile::High => 11_800u64,
            } as f64;
            slippage *= stress_mult_bps / 10_000f64;
        }
        slippage.round().clamp(15.0, 500.0) as u64
    }

    pub(in crate::services::strategy) fn max_price_impact_bps(&self) -> u64 {
        let wallet_balance = self.portfolio.get_eth_balance_cached(self.chain_id);
        let eth_balance = wei_to_eth_f64(wallet_balance).max(0.0001);
        // Keep this adaptive but less brittle for small balances so we don't
        // discard nearly all candidates before simulation.
        let base = 230.0 - 30.0 * (eth_balance * 100.0 + 1.0).log10();
        let volatility = self.price_feed.volatility_bps_cached("ETH").unwrap_or(0) as f64;
        let vol_adjust = volatility * 0.15;
        let impact = base - vol_adjust;
        impact.round().clamp(50.0, 300.0) as u64
    }

    pub(in crate::services::strategy) fn hard_gas_cap_wei(&self) -> U256 {
        let cap_gwei = self.max_gas_price_gwei.max(DEFAULT_FALLBACK_GAS_CAP_GWEI);
        U256::from(cap_gwei) * U256::from(1_000_000_000u64)
    }

    pub(in crate::services::strategy) fn dynamic_gas_cap(
        &self,
        wallet_balance: U256,
        gas_fees: &GasFees,
        hard_cap: U256,
    ) -> DynamicGasCap {
        let stress_mult_bps = match self.classify_stress_profile(gas_fees) {
            crate::services::strategy::risk::guards::StressProfile::UltraLow => 9_500u64,
            crate::services::strategy::risk::guards::StressProfile::Low => 10_000u64,
            crate::services::strategy::risk::guards::StressProfile::Normal => 10_500u64,
            crate::services::strategy::risk::guards::StressProfile::Elevated => 11_500u64,
            crate::services::strategy::risk::guards::StressProfile::High => 12_500u64,
        };
        let effective_gas_mult_bps = self
            .gas_cap_multiplier_bps
            .saturating_mul(stress_mult_bps)
            .checked_div(10_000u64)
            .unwrap_or(self.gas_cap_multiplier_bps);
        let base_plus_tip_wei = gas_fees
            .next_base_fee_per_gas
            .saturating_add(gas_fees.max_priority_fee_per_gas);
        let fallback_dynamic_wei =
            base_plus_tip_wei.saturating_mul(effective_gas_mult_bps as u128) / 10_000u128;
        let base_dynamic_wei = gas_fees
            .suggested_max_fee_per_gas
            .unwrap_or(fallback_dynamic_wei);
        let balance_factor_bps = self.balance_cap_multiplier_bps(wallet_balance);
        let adjusted_dynamic_wei =
            base_dynamic_wei.saturating_mul(balance_factor_bps as u128) / 10_000u128;

        // Avoid impossible caps below current base fee on tiny balances.
        let floor_wei = gas_fees
            .base_fee_per_gas
            .max(gas_fees.next_base_fee_per_gas);
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

    fn cached_gas_fees(&self) -> Option<GasFees> {
        let guard = self.per_block_inputs.try_lock().ok()?;
        guard.as_ref().map(|entry| entry.gas_fees.clone())
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
        let base_anchor = gas_fees
            .next_base_fee_per_gas
            .max(gas_fees.base_fee_per_gas);
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
        let threshold_bps = self.router_risk_fail_rate_bps();
        // Allow explicit disable of router revert-rate gating via 10000 bps.
        if threshold_bps >= 10_000 {
            return false;
        }
        if let Some(entry) = self.router_sim_stats.get(&router) {
            let (fails, total) = *entry;
            let min_samples = self.router_risk_min_samples();
            if total < min_samples {
                return false;
            }
            let fail_rate_bps = ((fails as u128).saturating_mul(10_000u128))
                .checked_div((total as u128).max(1))
                .unwrap_or(10_000u128) as u64;
            return fail_rate_bps >= threshold_bps;
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
                "🔢 Restored nonce state from DB"
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
            SkipReason::ToxicToken => {
                self.stats.skip_toxic_token.fetch_add(1, Ordering::Relaxed) + 1
            }
            SkipReason::InsufficientBalance => {
                self.stats
                    .skip_insufficient_balance
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::RouterRevertRate => {
                self.stats
                    .skip_router_revert_rate
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::LiquidityDepth => {
                self.stats
                    .skip_liquidity_depth
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::SandwichRisk => {
                self.stats
                    .skip_sandwich_risk
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::FrontRunBuildFailed => {
                self.stats
                    .skip_front_run_build_failed
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            SkipReason::BackrunBuildFailed => {
                self.stats
                    .skip_backrun_build_failed
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
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
        } else if self.allow_non_wrapped_swaps {
            // Non-wrapped mode permits token-denominated settlement.
            Some(amount)
        } else {
            None
        }
    }

    pub(in crate::services::strategy) fn execution_router(
        &self,
        observed: &ObservedSwap,
    ) -> Address {
        if self.universal_routers.contains(&observed.router) {
            match observed.router_kind {
                crate::services::strategy::decode::RouterKind::V2Like => {
                    self.exec_router_v2.unwrap_or(observed.router)
                }
                crate::services::strategy::decode::RouterKind::V3Like => {
                    self.exec_router_v3.unwrap_or(observed.router)
                }
            }
        } else if self.oneinch_routers.contains(&observed.router) {
            // We can decode 1inch intents, but execute against a deterministic
            // canonical router path to keep strategy behavior predictable.
            self.exec_router_v2.unwrap_or(observed.router)
        } else {
            observed.router
        }
    }

    pub(in crate::services::strategy) fn allowlist_category_for(
        &self,
        address: Address,
    ) -> Option<AllowlistCategory> {
        if self.router_allowlist.contains(&address) {
            return Some(AllowlistCategory::Routers);
        }
        if self.wrapper_allowlist.contains(&address) {
            return Some(AllowlistCategory::Wrappers);
        }
        if self.infra_allowlist.contains(&address) {
            return Some(AllowlistCategory::Infra);
        }
        None
    }

    pub(in crate::services::strategy) fn min_usd_floor_wei(
        &self,
        native_price_usd: f64,
    ) -> Option<U256> {
        let min_usd = self.profit_floor_min_usd?;
        if !native_price_usd.is_finite() || native_price_usd <= 0.0 {
            return None;
        }
        f64_native_to_wei(min_usd / native_price_usd)
    }

    pub(in crate::services::strategy) fn allow_unknown_router_decode(&self) -> bool {
        Self::env_bool("ALLOW_UNKNOWN_ROUTER_DECODE", true)
    }

    pub(in crate::services::strategy) fn canonical_exec_router_for_kind(
        &self,
        kind: RouterKind,
    ) -> Option<Address> {
        match kind {
            RouterKind::V2Like => self.exec_router_v2,
            RouterKind::V3Like => self.exec_router_v3,
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
        if let Some(out) = self
            .reserve_cache
            .quote_v2_path(&[token, self.wrapped_native], amount)
            && !out.is_zero()
        {
            return Some(out);
        }
        for fee in [500u32, 3_000u32, 10_000u32] {
            if let Some(path) = encode_v3_path(&[token, self.wrapped_native], &[fee])
                && let Ok(out) = self.quote_v3_path(&path, amount).await
                && !out.is_zero()
            {
                return Some(out);
            }
        }
        if let Some(plan) = self
            .best_route_plan(token, self.wrapped_native, amount, 0)
            .await
            && !plan.expected_out.is_zero()
        {
            return Some(plan.expected_out);
        }
        None
    }

    pub(in crate::services::strategy) async fn estimate_settlement_native_out(
        &self,
        amount: U256,
        token: Address,
    ) -> Option<U256> {
        if token == self.wrapped_native {
            return Some(amount);
        }
        if let Some(native_out) = self.estimate_native_out(amount, token).await {
            return Some(native_out);
        }
        if !self.allow_non_wrapped_swaps {
            return None;
        }

        // Fallback valuation path for non-wrapped settlement tokens:
        // estimate token USD value and convert to native USD with a haircut.
        let token_info = self.token_manager.info(self.chain_id, token)?;
        let token_units = units_to_float(amount, token_info.decimals);
        if !token_units.is_finite() || token_units <= 0.0 {
            return None;
        }
        let token_symbol = token_info.symbol.to_uppercase();
        let native_symbol = constants::native_symbol_for_chain(self.chain_id);
        let token_price = self
            .price_feed
            .get_price(&format!("{token_symbol}USD"))
            .await
            .ok()?;
        let native_price = self
            .price_feed
            .get_price(&format!("{native_symbol}USD"))
            .await
            .ok()?;
        if token_price.price <= 0.0 || native_price.price <= 0.0 {
            return None;
        }
        let native_units = (token_units * token_price.price / native_price.price) * 0.97f64;
        f64_native_to_wei(native_units)
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
        work_queue: SharedWorkQueue,
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
        profit_guard_base_floor_multiplier_bps: u64,
        profit_guard_cost_multiplier_bps: u64,
        profit_guard_min_margin_bps: u64,
        liquidity_ratio_floor_ppm: u64,
        sell_min_native_out_wei: u64,
        http_provider: HttpProvider,
        dry_run: bool,
        router_allowlist: Arc<DashSet<Address>>,
        wrapper_allowlist: Arc<DashSet<Address>>,
        infra_allowlist: Arc<DashSet<Address>>,
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
        let profit_floor_abs_wei = std::env::var("PROFIT_FLOOR_ABS_ETH")
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .and_then(f64_native_to_wei)
            .unwrap_or(*constants::MIN_PROFIT_THRESHOLD_WEI);
        let default_mult_gas = if chain_id == constants::CHAIN_ETHEREUM {
            15u64
        } else {
            10u64
        };
        let profit_floor_mult_gas = std::env::var("PROFIT_FLOOR_MULT_GAS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default_mult_gas)
            .clamp(1, 100);
        let profit_floor_min_usd = std::env::var("PROFIT_FLOOR_MIN_USD")
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0);
        let gas_ratio_limit_floor_bps = std::env::var("GAS_RATIO_LIMIT_FLOOR_BPS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|v| v.clamp(3_500, 9_500));
        let universal_router = constants::default_uniswap_universal_router(chain_id);
        let mut universal_routers: HashSet<Address> =
            constants::default_uniswap_universal_routers(chain_id)
                .into_iter()
                .collect();
        if let Some(primary) = universal_router {
            universal_routers.insert(primary);
        }
        let mut oneinch_routers: HashSet<Address> = constants::default_oneinch_routers(chain_id)
            .into_iter()
            .collect();
        // Routers whose intent can be decoded but should execute via canonical v2/v3 routers.
        for (name, addr) in constants::default_routers_for_chain(chain_id) {
            if name.starts_with("oneinch_aggregation_router")
                || name.starts_with("paraswap_")
                || name.starts_with("kyberswap_")
                || name.starts_with("zerox_")
                || name == "dex_router"
                || name == "transit_swap_router_v5"
                || name.starts_with("balancer_")
            {
                oneinch_routers.insert(addr);
            }
        }
        let exec_router_v2 = constants::default_uniswap_v2_router(chain_id);
        let exec_router_v3 = constants::default_uniswap_v3_router(chain_id);
        Self {
            work_queue,
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
            profit_guard_base_floor_multiplier_bps: profit_guard_base_floor_multiplier_bps
                .clamp(75, 20_000),
            profit_guard_cost_multiplier_bps: profit_guard_cost_multiplier_bps.clamp(1_000, 20_000),
            profit_guard_min_margin_bps: profit_guard_min_margin_bps.clamp(35, 5_000),
            liquidity_ratio_floor_ppm: liquidity_ratio_floor_ppm.clamp(35, 10_000),
            sell_min_native_out_wei: sell_min_native_out_wei.max(500_000_000_000),
            http_provider,
            dry_run,
            router_allowlist,
            wrapper_allowlist,
            infra_allowlist,
            router_discovery,
            skip_log_every: skip_log_every.max(1),
            wrapped_native,
            allow_non_wrapped_swaps,
            universal_routers,
            oneinch_routers,
            exec_router_v2,
            exec_router_v3,
            inventory_tokens: DashSet::new(),
            toxic_tokens: DashSet::new(),
            toxic_probe_failures: DashMap::new(),
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            flashloan_providers,
            aave_pool,
            reserve_cache,
            bundle_state: Arc::new(Mutex::new(None)),
            per_block_inputs: Arc::new(Mutex::new(None)),
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
            profit_floor_abs_wei,
            profit_floor_mult_gas,
            profit_floor_min_usd,
            gas_ratio_limit_floor_bps,
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("StrategyExecutor: waiting for pending transactions");
        let panel_lines = vec![
            "Strategy configured".to_string(),
            format!(
                "chain={} backend={} sandwiches_enabled={} strict_atomic_mode={}",
                self.chain_id,
                self.simulation_backend,
                self.sandwich_attacks_enabled,
                !self.allow_non_wrapped_swaps
            ),
            format!(
                "profit_base_floor_bps={} profit_cost_bps={} profit_min_margin_bps={}",
                self.profit_guard_base_floor_multiplier_bps,
                self.profit_guard_cost_multiplier_bps,
                self.profit_guard_min_margin_bps
            ),
            format!(
                "liquidity_ratio_floor_ppm={} sell_min_native_out_wei={}",
                self.liquidity_ratio_floor_ppm, self.sell_min_native_out_wei
            ),
            format!(
                "profit_floor_abs_wei={} profit_floor_mult_gas={} profit_floor_min_usd={:?}",
                self.profit_floor_abs_wei, self.profit_floor_mult_gas, self.profit_floor_min_usd
            ),
            format!(
                "gas_ratio_limit_floor_bps={:?}",
                self.gas_ratio_limit_floor_bps
            ),
        ];
        if ansi_tables_enabled() {
            let framed =
                format_framed_table_with_blue_title(panel_lines.iter().map(String::as_str));
            eprintln!("{framed}");
        } else {
            let framed = format_framed_table(panel_lines.iter().map(String::as_str));
            tracing::info!(target: "strategy", "\n{framed}");
        }

        let executor = Arc::new(self);

        // Attempt to restore persisted nonce state before processing work.
        let _ = executor.restore_bundle_state().await;

        // Spawn a lightweight block watcher so work processing never waits on block stream.
        let block_exec = executor.clone();
        let block_watcher = tokio::spawn(async move {
            block_exec.block_watcher().await;
        });
        let mut worker_tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                joined = worker_tasks.join_next(), if !worker_tasks.is_empty() => {
                    if let Some(Err(e)) = joined {
                        tracing::warn!(target: "strategy", error = %e, "Strategy worker task failed");
                    }
                }
                work_opt = executor.work_queue.pop_latest(&executor.shutdown) => {
                    let Some(work) = work_opt else {
                        tracing::info!(target: "strategy", "Shutdown requested; stopping strategy work loop");
                        break;
                    };
                    executor
                        .stats
                        .ingest_queue_depth
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        })
                        .ok();
                    let permit = match executor.worker_semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(e) => {
                            tracing::warn!(target: "strategy", error = %e, "Worker semaphore closed; requesting shutdown");
                            executor.shutdown.cancel();
                            break;
                        }
                    };
                    let exec = executor.clone();
                    worker_tasks.spawn(async move {
                        let _permit = permit;
                        exec.process_work(work).await;
                    });
                }
            }
        }

        executor.shutdown.cancel();

        while let Some(joined) = worker_tasks.join_next().await {
            if let Err(e) = joined {
                tracing::warn!(target: "strategy", error = %e, "Strategy worker task failed during shutdown");
            }
        }

        if let Err(e) = block_watcher.await {
            tracing::warn!(target: "strategy", error = %e, "Block watcher task join failed");
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
                    let prev = self.current_block.swap(number, Ordering::Relaxed);
                    if prev != number {
                        let mut guard = self.bundle_state.lock().await;
                        *guard = None;
                        drop(guard);
                        let mut inputs = self.per_block_inputs.lock().await;
                        *inputs = None;
                        // Persist fresh state baseline for the new block.
                        if let Ok(base) = self.nonce_manager.get_base_nonce(number).await {
                            self.persist_nonce_state(number, base, &HashSet::new())
                                .await;
                        }
                    }
                    // Strict atomic mode: do not run periodic inventory rebalancing.
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
            let _ = self.record_toxic_probe_failure(token_in, "v3_probe_revert");
            return Ok(false);
        }
        self.record_probe_gas(router, outcome.gas_used);
        if outcome.return_data.is_empty() {
            self.clear_toxic_probe_failures(token_in);
            return Ok(true);
        }
        match UniV3Router::exactInputCall::abi_decode_returns(&outcome.return_data) {
            Ok(amount_out) => {
                let tolerance_bps = U256::from(10_000u64 - TAX_TOLERANCE_BPS);
                let ok = amount_out.saturating_mul(U256::from(10_000u64))
                    >= expected_out.saturating_mul(tolerance_bps);
                if ok {
                    self.clear_toxic_probe_failures(token_in);
                } else {
                    let _ = self.record_toxic_probe_failure(token_in, "v3_probe_output_too_low");
                }
                Ok(ok)
            }
            Err(_) => {
                self.clear_toxic_probe_failures(token_in);
                Ok(true)
            }
        }
    }

    fn current_head_or(&self, fallback: u64) -> u64 {
        let head = self.current_block.load(Ordering::Relaxed);
        if head > 0 { head } else { fallback }
    }

    fn receipt_is_confirmed(current_head: u64, receipt_block: u64, confirm_blocks: u64) -> bool {
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
            if current_head == 0
                && let Ok(head) = self.http_provider.get_block_number().await
            {
                current_head = head;
                self.current_block.store(head, Ordering::Relaxed);
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

fn f64_native_to_wei(value_native: f64) -> Option<U256> {
    if !value_native.is_finite() || value_native <= 0.0 {
        return None;
    }
    let wei = (value_native * 1e18f64).floor();
    if !wei.is_finite() || wei <= 0.0 {
        return None;
    }
    let as_u128 = wei.min(u128::MAX as f64) as u128;
    Some(U256::from(as_u128))
}

#[cfg(test)]
pub(crate) use tests::dummy_executor_for_tests;

#[cfg(test)]
mod tests {
    use super::*;
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

    fn weth_mainnet() -> Address {
        crate::common::constants::wrapped_native_for_chain(crate::common::constants::CHAIN_ETHEREUM)
    }

    #[test]
    fn decodes_eth_swap() {
        let router = weth_mainnet();
        let call = UniV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(5u64),
            path: vec![weth_mainnet(), Address::from([2u8; 20])],
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
            tokenIn: weth_mainnet(),
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
            decode_swap_input(weth_mainnet(), &data, U256::from(0u64)).expect("decode v3 single");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path.len(), 2);
    }

    #[test]
    fn decodes_uniswap_v2_exact_out_variant() {
        let router = weth_mainnet();
        let token = Address::from([2u8; 20]);
        let call = UniV2Router::swapTokensForExactETHCall {
            amountOut: U256::from(3_000u64),
            amountInMax: U256::from(10_000u64),
            path: vec![token, weth_mainnet()],
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
        let router = weth_mainnet();
        let token = Address::from([2u8; 20]);
        let call = UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall {
            amountIn: U256::from(9_000u64),
            amountOutMin: U256::from(2_000u64),
            path: vec![token, weth_mainnet()],
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
            tokenIn: weth_mainnet(),
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
        let decoded = decode_swap_input(weth_mainnet(), &data, U256::ZERO).expect("decode v3 out");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path, vec![weth_mainnet(), token_out]);
        assert_eq!(decoded.v3_fees, vec![500u32]);
        assert_eq!(decoded.amount_in, U256::from(10_000u64));
        assert_eq!(decoded.min_out, U256::from(8_000u64));
    }

    #[test]
    fn decodes_uniswap_v3_exact_output_reverses_path_to_canonical() {
        let token_mid = Address::from([7u8; 20]);
        let token_out = Address::from([9u8; 20]);
        // exactOutput path is encoded in reverse order: out -> ... -> in
        let reverse_path = encode_v3_path(&[token_out, token_mid, weth_mainnet()], &[3000, 500])
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
            decode_swap_input(weth_mainnet(), &data, U256::ZERO).expect("decode v3 exact out");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path, vec![weth_mainnet(), token_mid, token_out]);
        assert_eq!(decoded.v3_fees, vec![500u32, 3000u32]);
        assert_eq!(decoded.amount_in, U256::from(9_000u64));
        assert_eq!(decoded.min_out, U256::from(5_000u64));
        assert_eq!(
            decoded.v3_path,
            encode_v3_path(&[weth_mainnet(), token_mid, token_out], &[500, 3000])
        );
    }

    #[test]
    fn parses_uniswap_v3_path() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(weth_mainnet().as_slice());
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
        let path = vec![weth_mainnet(), token_mid, token_final];
        assert_eq!(target_token(&path, weth_mainnet()), Some(token_final));
    }

    #[test]
    fn target_token_prefers_source_on_sell_paths() {
        let token_start = Address::from([4u8; 20]);
        let token_mid = Address::from([5u8; 20]);
        let path = vec![token_start, token_mid, weth_mainnet()];
        assert_eq!(target_token(&path, weth_mainnet()), Some(token_start));
    }

    #[test]
    fn rejects_invalid_v3_path_length() {
        // Missing last token bytes.
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(weth_mainnet().as_slice());
        path.extend_from_slice(&[0u8, 1u8, 244u8]); // fee 500
        path.extend_from_slice(&[1u8; 10]); // truncated address
        assert!(parse_v3_path(&path).is_none());
    }

    #[test]
    fn rejects_invalid_v3_fee() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(weth_mainnet().as_slice());
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
            path: vec![weth_mainnet(), Address::from([2u8; 20])],
            v3_fees: Vec::new(),
            v3_path: None,
            amount_in: U256::from(1u64),
            min_out: U256::ZERO,
            recipient: Address::ZERO,
            router_kind: RouterKind::V2Like,
        };
        assert_eq!(direction(&buy, weth_mainnet()), SwapDirection::BuyWithEth);
        let sell = ObservedSwap {
            path: vec![Address::from([2u8; 20]), weth_mainnet()],
            ..buy
        };
        assert_eq!(direction(&sell, weth_mainnet()), SwapDirection::SellForEth);
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
            2_000_000_000_000_000_000_000u128,
        ));
        assert!(
            floor_large > floor_small,
            "profit floor should scale with balance"
        );
        assert!(
            floor_large >= floor_small.saturating_mul(U256::from(10u64)),
            "scaled floor should grow by a meaningful multiple"
        );
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
    async fn ensure_native_out_respects_non_wrapped_setting() {
        let mut exec = dummy_executor_for_tests().await;
        let other = Address::from([9u8; 20]);
        assert!(exec.ensure_native_out(U256::from(10u64), other).is_none());
        exec.allow_non_wrapped_swaps = true;
        assert_eq!(
            exec.ensure_native_out(U256::from(10u64), other),
            Some(U256::from(10u64))
        );
        assert_eq!(
            exec.ensure_native_out(U256::from(5u64), weth_mainnet()),
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

    #[tokio::test]
    async fn has_usable_flashloan_provider_matrix() {
        let mut exec = dummy_executor_for_tests().await;

        exec.flashloan_enabled = false;
        exec.executor = Some(Address::from([0x10; 20]));
        exec.flashloan_providers = vec![FlashloanProvider::Balancer];
        assert!(!exec.has_usable_flashloan_provider());

        exec.flashloan_enabled = true;
        exec.executor = None;
        assert!(!exec.has_usable_flashloan_provider());

        exec.executor = Some(Address::from([0x10; 20]));
        exec.flashloan_providers = vec![FlashloanProvider::Balancer];
        assert!(exec.has_usable_flashloan_provider());

        exec.flashloan_providers = vec![FlashloanProvider::AaveV3];
        exec.aave_pool = None;
        assert!(!exec.has_usable_flashloan_provider());

        exec.aave_pool = Some(Address::from([0x44; 20]));
        assert!(exec.has_usable_flashloan_provider());
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
        let fees = GasFees {
            max_fee_per_gas: 55_000_000,
            max_priority_fee_per_gas: 1_000_000,
            next_base_fee_per_gas: 50_000_000,
            base_fee_per_gas: 48_000_000,
            p50_priority_fee_per_gas: Some(900_000),
            p90_priority_fee_per_gas: Some(1_800_000),
            gas_used_ratio: Some(0.85),
            suggested_max_fee_per_gas: Some(70_000_000),
        };
        assert!(
            !exec.gas_ratio_ok_with_fees(
                U256::from(1_000u64),
                U256::from(1_050u64),
                U256::from(1_000_000u64),
                &fees,
            ),
            "margin below 12% should be rejected"
        );
    }

    #[tokio::test]
    async fn gas_ratio_accepts_healthy_margin() {
        let exec = dummy_executor_for_tests().await;
        let fees = GasFees {
            max_fee_per_gas: 55_000_000,
            max_priority_fee_per_gas: 1_000_000,
            next_base_fee_per_gas: 50_000_000,
            base_fee_per_gas: 48_000_000,
            p50_priority_fee_per_gas: Some(900_000),
            p90_priority_fee_per_gas: Some(1_800_000),
            gas_used_ratio: Some(0.85),
            suggested_max_fee_per_gas: Some(70_000_000),
        };
        assert!(exec.gas_ratio_ok_with_fees(
            U256::from(1_000u64),
            U256::from(3_000u64),
            U256::from(1_000_000u64),
            &fees,
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
        let status = exec
            .await_receipt(&B256::ZERO)
            .await
            .expect("receipt status");
        assert_eq!(status, ReceiptStatus::UnknownTimeout);
    }

    #[tokio::test]
    async fn zero_gas_cap_falls_back_to_safe_default() {
        let mut exec = dummy_executor_for_tests().await;
        exec.max_gas_price_gwei = 0;
        assert_eq!(exec.hard_gas_cap_wei(), U256::from(500_000_000_000u64));
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
        assert!(cap.cap_wei >= U256::from(120u64));
        assert!(cap.cap_wei <= U256::from(150u64));
    }

    #[tokio::test]
    async fn dynamic_gas_cap_auto_scales_by_stress_profile() {
        let exec = dummy_executor_for_tests().await;
        let low = GasFees {
            max_fee_per_gas: 60_000_000,
            max_priority_fee_per_gas: 8_000_000,
            next_base_fee_per_gas: 50_000_000,
            base_fee_per_gas: 45_000_000,
            p50_priority_fee_per_gas: Some(7_000_000),
            p90_priority_fee_per_gas: Some(9_000_000),
            gas_used_ratio: Some(0.5),
            suggested_max_fee_per_gas: None,
        };
        let high = GasFees {
            max_fee_per_gas: 160_000_000_000,
            max_priority_fee_per_gas: 6_000_000_000,
            next_base_fee_per_gas: 150_000_000_000,
            base_fee_per_gas: 140_000_000_000,
            p50_priority_fee_per_gas: Some(5_000_000_000),
            p90_priority_fee_per_gas: Some(11_000_000_000),
            gas_used_ratio: Some(1.15),
            suggested_max_fee_per_gas: None,
        };

        let low_cap =
            exec.dynamic_gas_cap(U256::from(100_000_000_000_000_000u128), &low, U256::MAX);
        let high_cap =
            exec.dynamic_gas_cap(U256::from(100_000_000_000_000_000u128), &high, U256::MAX);
        assert!(high_cap.base_dynamic_wei > low_cap.base_dynamic_wei);
        assert!(high_cap.adjusted_dynamic_wei > low_cap.adjusted_dynamic_wei);
    }

    #[tokio::test]
    async fn effective_slippage_auto_calibrates_by_cached_gas_profile() {
        let low_exec = dummy_executor_for_tests().await;
        {
            let mut cache = low_exec.per_block_inputs.lock().await;
            *cache = Some(PerBlockInputs {
                block_number: 1,
                gas_fees: GasFees {
                    max_fee_per_gas: 60_000_000,
                    max_priority_fee_per_gas: 8_000_000,
                    next_base_fee_per_gas: 50_000_000,
                    base_fee_per_gas: 45_000_000,
                    p50_priority_fee_per_gas: Some(7_000_000),
                    p90_priority_fee_per_gas: Some(9_000_000),
                    gas_used_ratio: Some(0.5),
                    suggested_max_fee_per_gas: Some(70_000_000),
                },
                wallet_balance: U256::from(10_000_000_000_000_000u128),
            });
        }
        let high_exec = dummy_executor_for_tests().await;
        {
            let mut cache = high_exec.per_block_inputs.lock().await;
            *cache = Some(PerBlockInputs {
                block_number: 1,
                gas_fees: GasFees {
                    max_fee_per_gas: 160_000_000_000,
                    max_priority_fee_per_gas: 6_000_000_000,
                    next_base_fee_per_gas: 150_000_000_000,
                    base_fee_per_gas: 140_000_000_000,
                    p50_priority_fee_per_gas: Some(5_000_000_000),
                    p90_priority_fee_per_gas: Some(12_000_000_000),
                    gas_used_ratio: Some(1.15),
                    suggested_max_fee_per_gas: Some(220_000_000_000),
                },
                wallet_balance: U256::from(10_000_000_000_000_000u128),
            });
        }
        let low = low_exec.effective_slippage_bps();
        let high = high_exec.effective_slippage_bps();
        assert!(high >= low);
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
        let work_queue =
            Arc::new(crate::services::strategy::execution::work_queue::WorkQueue::new(8));
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
            true,
            false,
        ));
        let db = Database::new("sqlite::memory:").await.expect("db");
        let portfolio = Arc::new(PortfolioManager::new(http.clone(), Address::ZERO));
        let gas_oracle = GasOracle::new(http.clone(), 1);
        let price_feed = PriceFeed::new(http.clone(), 1, HashMap::new(), PriceApiKeys::default())
            .expect("price feed");
        let simulator = Simulator::new(http.clone(), SimulationBackend::new("revm"));
        let token_manager = Arc::new(TokenManager::default());
        let nonce_manager = NonceManager::new(http.clone(), Address::ZERO);
        let reserve_cache = Arc::new(ReserveCache::new(http.clone()));
        let router_allowlist = Arc::new(DashSet::new());
        let wrapper_allowlist = Arc::new(DashSet::new());
        let infra_allowlist = Arc::new(DashSet::new());

        StrategyExecutor::new(
            work_queue,
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
            10_000,
            10_000,
            1_200,
            1_000,
            5_000_000_000_000,
            http.clone(),
            true,
            router_allowlist,
            wrapper_allowlist,
            infra_allowlist,
            None,
            500,
            weth_mainnet(),
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
