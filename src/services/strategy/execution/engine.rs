// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::constants::default_balancer_vault_for_chain;
use crate::common::error::AppError;
use crate::core::executor::{BundleSender, SharedBundleSender};
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::{RpcCapabilities, Simulator};
use crate::core::strategy::{StrategyExecutor, StrategyStats};
use crate::data::db::Database;
use crate::infrastructure::data::address_registry::AddressRegistry;
use crate::infrastructure::data::token_manager::TokenManager;
use crate::network::block_listener::BlockListener;
use crate::network::gas::GasOracle;
use crate::network::mempool::MempoolScanner;
use crate::network::mev_share::MevShareClient;
use crate::network::nonce::NonceManager;
use crate::network::price_feed::{ChainlinkFeedAuditOptions, PriceFeed};
use crate::network::provider::{ConnectionFactory, HttpProvider, WsProvider};
use crate::network::reserves::ReserveCache;
use crate::services::strategy::execution::work_queue::WorkQueue;
use crate::services::strategy::router_discovery::RouterDiscovery;
use crate::services::strategy::strategy::classify_allowlist_entry;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy_rpc_client::NoParams;
use dashmap::DashSet;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

const INGEST_QUEUE_BOUND: usize = 2048;
const DEFAULT_FEED_AUDIT_MAX_LAG_BLOCKS: u64 = 20;
const DEFAULT_FEED_AUDIT_RECHECK_SECS: u64 = 20;
const DEFAULT_FEED_AUDIT_PUBLIC_TIP_LAG_BLOCKS: u64 = 2;

#[derive(Default, Debug, Clone)]
struct SyncLagState {
    is_lagging: bool,
    eth_syncing: bool,
    current_block: Option<u64>,
    highest_block: Option<u64>,
    local_tip: Option<u64>,
    public_tip: Option<u64>,
    protocol_lag: Option<u64>,
    public_tip_lag: Option<u64>,
    reasons: Vec<String>,
}

pub struct Engine {
    http_provider: HttpProvider,
    websocket_provider: WsProvider,
    db: Database,
    nonce_manager: NonceManager,
    portfolio: Arc<PortfolioManager>,
    safety_guard: Arc<SafetyGuard>,
    dry_run: bool,
    gas_oracle: GasOracle,
    price_feed: PriceFeed,
    chain_id: u64,
    relay_url: String,
    mev_share_relay_url: String,
    wallet_signer: PrivateKeySigner,
    bundle_signer: PrivateKeySigner,
    executor: Option<Address>,
    executor_bribe_bps: u64,
    executor_bribe_recipient: Option<Address>,
    flashloan_enabled: bool,
    flashloan_providers: Vec<crate::services::strategy::strategy::FlashloanProvider>,
    aave_pool: Option<Address>,
    max_gas_price_gwei: u64,
    gas_cap_multiplier_bps: u64,
    simulator: Simulator,
    token_manager: Arc<TokenManager>,
    metrics_port: u16,
    strategy_enabled: bool,
    slippage_bps: u64,
    profit_guard_base_floor_multiplier_bps: u64,
    profit_guard_cost_multiplier_bps: u64,
    profit_guard_min_margin_bps: u64,
    liquidity_ratio_floor_ppm: u64,
    sell_min_native_out_wei: u64,
    router_allowlist: Arc<DashSet<Address>>,
    wrapper_allowlist: Arc<DashSet<Address>>,
    infra_allowlist: Arc<DashSet<Address>>,
    router_discovery: Option<Arc<RouterDiscovery>>,
    skip_log_every: u64,
    wrapped_native: Address,
    allow_non_wrapped_swaps: bool,
    mev_share_stream_url: String,
    mev_share_history_limit: u32,
    mev_share_enabled: bool,
    mevshare_builders: Vec<String>,
    sandwich_attacks_enabled: bool,
    simulation_backend: String,
    chainlink_feed_strict: bool,
    bundle_use_replacement_uuid: bool,
    bundle_cancel_previous: bool,
    worker_limit: usize,
    address_registry_path: String,
    pairs_path: String,
    receipt_poll_ms: u64,
    receipt_timeout_ms: u64,
    receipt_confirm_blocks: u64,
    emergency_exit_on_unknown_receipt: bool,
    rpc_capability_strict: bool,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http_provider: HttpProvider,
        websocket_provider: WsProvider,
        db: Database,
        nonce_manager: NonceManager,
        portfolio: Arc<PortfolioManager>,
        safety_guard: Arc<SafetyGuard>,
        dry_run: bool,
        gas_oracle: GasOracle,
        price_feed: PriceFeed,
        chain_id: u64,
        relay_url: String,
        mev_share_relay_url: String,
        wallet_signer: PrivateKeySigner,
        bundle_signer: PrivateKeySigner,
        executor: Option<Address>,
        executor_bribe_bps: u64,
        executor_bribe_recipient: Option<Address>,
        flashloan_enabled: bool,
        flashloan_providers: Vec<crate::services::strategy::strategy::FlashloanProvider>,
        aave_pool: Option<Address>,
        max_gas_price_gwei: u64,
        gas_cap_multiplier_bps: u64,
        simulator: Simulator,
        token_manager: Arc<TokenManager>,
        metrics_port: u16,
        strategy_enabled: bool,
        slippage_bps: u64,
        profit_guard_base_floor_multiplier_bps: u64,
        profit_guard_cost_multiplier_bps: u64,
        profit_guard_min_margin_bps: u64,
        liquidity_ratio_floor_ppm: u64,
        sell_min_native_out_wei: u64,
        router_allowlist: Arc<DashSet<Address>>,
        wrapper_allowlist: Arc<DashSet<Address>>,
        infra_allowlist: Arc<DashSet<Address>>,
        router_discovery: Option<Arc<RouterDiscovery>>,
        skip_log_every: u64,
        wrapped_native: Address,
        allow_non_wrapped_swaps: bool,
        mev_share_stream_url: String,
        mev_share_history_limit: u32,
        mev_share_enabled: bool,
        mevshare_builders: Vec<String>,
        sandwich_attacks_enabled: bool,
        simulation_backend: String,
        chainlink_feed_strict: bool,
        bundle_use_replacement_uuid: bool,
        bundle_cancel_previous: bool,
        worker_limit: usize,
        address_registry_path: String,
        pairs_path: String,
        receipt_poll_ms: u64,
        receipt_timeout_ms: u64,
        receipt_confirm_blocks: u64,
        emergency_exit_on_unknown_receipt: bool,
        rpc_capability_strict: bool,
    ) -> Self {
        Self {
            http_provider,
            websocket_provider,
            db,
            nonce_manager,
            portfolio,
            safety_guard,
            dry_run,
            gas_oracle,
            price_feed,
            chain_id,
            relay_url,
            mev_share_relay_url,
            wallet_signer,
            bundle_signer,
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            flashloan_providers,
            aave_pool,
            max_gas_price_gwei,
            gas_cap_multiplier_bps,
            simulator,
            token_manager,
            metrics_port,
            strategy_enabled,
            slippage_bps,
            profit_guard_base_floor_multiplier_bps,
            profit_guard_cost_multiplier_bps,
            profit_guard_min_margin_bps,
            liquidity_ratio_floor_ppm,
            sell_min_native_out_wei,
            router_allowlist,
            wrapper_allowlist,
            infra_allowlist,
            router_discovery,
            skip_log_every,
            wrapped_native,
            allow_non_wrapped_swaps,
            mev_share_stream_url,
            mev_share_history_limit,
            mev_share_enabled,
            mevshare_builders,
            sandwich_attacks_enabled,
            simulation_backend,
            chainlink_feed_strict,
            bundle_use_replacement_uuid,
            bundle_cancel_previous,
            worker_limit,
            address_registry_path,
            pairs_path,
            receipt_poll_ms,
            receipt_timeout_ms,
            receipt_confirm_blocks,
            emergency_exit_on_unknown_receipt,
            rpc_capability_strict,
        }
    }

    async fn log_rpc_modules(&self, label: &str, provider: &HttpProvider, require_subscribe: bool) {
        let modules: Result<HashMap<String, String>, _> = provider
            .raw_request("rpc_modules".into(), NoParams::default())
            .await;
        match modules {
            Ok(module_map) => {
                let mut names: Vec<String> = module_map.keys().cloned().collect();
                names.sort();
                tracing::debug!(
                    target: "rpc",
                    transport = label,
                    modules = %names.join(","),
                    "RPC modules reported"
                );
                let lower: HashSet<String> = names.into_iter().map(|m| m.to_lowercase()).collect();
                if !lower.contains("eth") {
                    tracing::warn!(
                        target: "rpc",
                        transport = label,
                        "RPC module 'eth' missing; core calls may fail"
                    );
                }
                if !lower.contains("debug") {
                    tracing::warn!(
                        target: "rpc",
                        transport = label,
                        "RPC module 'debug' missing; debug_traceCall fallbacks disabled"
                    );
                }
                if require_subscribe && !lower.contains("subscribe") {
                    tracing::warn!(
                        target: "rpc",
                        transport = label,
                        "RPC module 'subscribe' missing; eth_subscribe streaming may fail (Nethermind: JsonRpc.EnabledModules should include Subscribe)"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "rpc",
                    transport = label,
                    error = %e,
                    "rpc_modules call failed; cannot verify enabled namespaces"
                );
            }
        }
    }

    async fn log_rpc_capabilities(&self) -> Option<String> {
        let mut client_version: Option<String> = None;
        match self.http_provider.get_client_version().await {
            Ok(version) => {
                client_version = Some(version.clone());
                tracing::info!(target: "rpc", client = %version, "✔  RPC client version");
            }
            Err(e) => {
                tracing::warn!(
                    target: "rpc",
                    error = %e,
                    "web3_clientVersion failed; continuing"
                );
            }
        }
        self.log_rpc_modules("http", &self.http_provider, false)
            .await;
        self.log_rpc_modules("ws", &self.websocket_provider, true)
            .await;
        client_version
    }

    fn log_nethermind_tuning_hint(
        &self,
        client_version: Option<&str>,
        capabilities: &RpcCapabilities,
    ) {
        let Some(version) = client_version else {
            return;
        };
        if !version.to_ascii_lowercase().contains("nethermind") {
            return;
        }

        tracing::debug!(
            target: "rpc",
            chain_id = self.chain_id,
            "Nethermind tuning guidance: JsonRpc.EnabledModules should include Eth,Subscribe,Debug,Trace,TxPool; raise JsonRpc.EthModuleConcurrentInstances for concurrent eth_* load; tune JsonRpc.RequestQueueLimit and JsonRpc.Timeout for burst traffic."
        );
        if !capabilities.eth_simulate {
            tracing::warn!(
                target: "rpc",
                "Nethermind eth_simulateV1 unavailable. Ensure Eth namespace is enabled and node version supports eth_simulateV1."
            );
        } else if !capabilities.eth_simulate_shape_ok {
            tracing::warn!(
                target: "rpc",
                "Nethermind eth_simulateV1 responded, but the expected parameter shape check failed; verify eth_simulateV1 payload semantics for this node version."
            );
        }
        if !capabilities.debug_trace_call_many {
            tracing::warn!(
                target: "rpc",
                "Nethermind debug_traceCallMany unavailable. Ensure Debug/Trace namespaces are enabled for bundle-level tracing fallback."
            );
        } else if !capabilities.debug_trace_call_many_shape_ok {
            tracing::warn!(
                target: "rpc",
                "Nethermind debug_traceCallMany responded, but the expected parameter shape check failed; verify callMany bundle payload semantics for this node version."
            );
        }
    }

    fn feed_audit_max_lag_blocks() -> u64 {
        std::env::var("FEED_AUDIT_MAX_LAG_BLOCKS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_FEED_AUDIT_MAX_LAG_BLOCKS)
            .max(1)
    }

    fn feed_audit_recheck_secs() -> u64 {
        std::env::var("FEED_AUDIT_RECHECK_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_FEED_AUDIT_RECHECK_SECS)
            .max(5)
    }

    fn feed_audit_public_tip_rpc(&self) -> Option<String> {
        if let Ok(url) = std::env::var("FEED_AUDIT_PUBLIC_RPC_URL")
            && !url.trim().is_empty()
        {
            return Some(url);
        }
        if self.chain_id == crate::common::constants::CHAIN_ETHEREUM {
            return Some("https://ethereum-rpc.publicnode.com".to_string());
        }
        None
    }

    fn feed_audit_public_tip_lag_blocks() -> u64 {
        std::env::var("FEED_AUDIT_PUBLIC_TIP_LAG_BLOCKS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_FEED_AUDIT_PUBLIC_TIP_LAG_BLOCKS)
            .clamp(1, 64)
    }

    fn parse_block_field(value: &Value) -> Option<u64> {
        match value {
            Value::String(s) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                }
            }
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    async fn check_sync_lag_state(
        provider: &HttpProvider,
        chain_id: u64,
        max_lag_blocks: u64,
        public_tip_rpc: Option<&str>,
        public_tip_lag_blocks: u64,
    ) -> SyncLagState {
        let mut state = SyncLagState::default();
        let syncing: Result<Value, _> = provider
            .raw_request("eth_syncing".into(), NoParams::default())
            .await;
        match syncing {
            Ok(Value::Bool(is_syncing)) => {
                state.eth_syncing = is_syncing;
                if is_syncing {
                    state.reasons.push("eth_syncing=true".to_string());
                }
            }
            Ok(Value::Object(map)) => {
                state.eth_syncing = true;
                state.current_block = map.get("currentBlock").and_then(Self::parse_block_field);
                state.highest_block = map.get("highestBlock").and_then(Self::parse_block_field);
                if let (Some(current), Some(highest)) = (state.current_block, state.highest_block) {
                    let lag = highest.saturating_sub(current);
                    state.protocol_lag = Some(lag);
                    if lag > max_lag_blocks {
                        state.reasons.push(format!(
                            "eth_syncing_lag={} (highest={} current={} threshold={})",
                            lag, highest, current, max_lag_blocks
                        ));
                    }
                }
            }
            Ok(other) => {
                tracing::debug!(
                    target: "price_feed",
                    chain_id,
                    response = %other,
                    "Unexpected eth_syncing response shape"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "price_feed",
                    chain_id,
                    error = %e,
                    "eth_syncing check failed; falling back to tip comparison"
                );
            }
        }

        if state.current_block.is_none() {
            state.current_block = provider.get_block_number().await.ok();
        }
        state.local_tip = state.current_block;

        if let Some(url) = public_tip_rpc {
            match ConnectionFactory::http(url) {
                Ok(public_provider) => match public_provider.get_block_number().await {
                    Ok(public_tip) => {
                        state.public_tip = Some(public_tip);
                        if let Some(local_tip) = state.local_tip
                            && public_tip > local_tip
                        {
                            let lag = public_tip.saturating_sub(local_tip);
                            state.public_tip_lag = Some(lag);
                            if lag > public_tip_lag_blocks {
                                state.reasons.push(format!(
                                    "public_tip_ahead_by={} (public={} local={} threshold={})",
                                    lag, public_tip, local_tip, public_tip_lag_blocks
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "price_feed",
                            chain_id,
                            rpc = %url,
                            error = %e,
                            "Failed to fetch public tip for feed-audit lag detection"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        target: "price_feed",
                        chain_id,
                        rpc = %url,
                        error = %e,
                        "Invalid FEED_AUDIT_PUBLIC_RPC_URL"
                    );
                }
            }
        }

        state.is_lagging = state.eth_syncing
            || state
                .protocol_lag
                .map(|lag| lag > max_lag_blocks)
                .unwrap_or(false)
            || state
                .public_tip_lag
                .map(|lag| lag > public_tip_lag_blocks)
                .unwrap_or(false);
        state
    }

    async fn prune_allowlist_without_code(
        &self,
        category: &'static str,
        allowlist: &DashSet<Address>,
    ) {
        let mut invalid = Vec::new();
        for addr in allowlist.iter() {
            match self.http_provider.get_code_at(*addr).await {
                Ok(code) if code.is_empty() => invalid.push(*addr),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        target: "router",
                        category,
                        address = %format!("{:#x}", *addr),
                        error = %e,
                        "Failed to validate allowlist entry; dropping"
                    );
                    invalid.push(*addr);
                }
            }
        }
        for addr in invalid.iter() {
            allowlist.remove(addr);
        }
        if !invalid.is_empty() {
            tracing::warn!(
                target: "router",
                category,
                count = invalid.len(),
                "Dropped allowlist entries with missing code"
            );
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        if self.flashloan_enabled && self.executor.is_none() {
            return Err(AppError::Config(
                "flashloan_enabled requires executor_address".into(),
            ));
        }
        if let Some(exec) = self.executor {
            let code = self.http_provider.get_code_at(exec).await.map_err(|e| {
                AppError::Initialization(format!("Executor code check failed: {e}"))
            })?;
            if code.is_empty() {
                return Err(AppError::Config(format!(
                    "executor_address {:#x} has no code deployed",
                    exec
                )));
            }
        }

        let client_version = self.log_rpc_capabilities().await;
        let capabilities = self.simulator.probe_capabilities().await;
        self.log_nethermind_tuning_hint(client_version.as_deref(), &capabilities);
        if !capabilities.fee_history {
            tracing::warn!(
                target: "rpc",
                "eth_feeHistory probe failed; GasOracle will use fallback strategy"
            );
        }
        let shutdown = CancellationToken::new();
        {
            let shutdown_on_ctrlc = shutdown.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!(target: "shutdown", "Ctrl+C received; requesting graceful shutdown");
                    shutdown_on_ctrlc.cancel();
                }
            });
        }

        let feed_audit_max_lag_blocks = Self::feed_audit_max_lag_blocks();
        let feed_audit_public_tip_lag_blocks = Self::feed_audit_public_tip_lag_blocks();
        let feed_audit_public_rpc = self.feed_audit_public_tip_rpc();
        let sync_state = Self::check_sync_lag_state(
            &self.http_provider,
            self.chain_id,
            feed_audit_max_lag_blocks,
            feed_audit_public_rpc.as_deref(),
            feed_audit_public_tip_lag_blocks,
        )
        .await;
        if sync_state.is_lagging {
            tracing::warn!(
                target: "price_feed",
                chain_id = self.chain_id,
                reasons = %sync_state.reasons.join("; "),
                current_block = ?sync_state.current_block,
                highest_block = ?sync_state.highest_block,
                local_tip = ?sync_state.local_tip,
                public_tip = ?sync_state.public_tip,
                "Node is still syncing/lagging; downgrading critical Chainlink feed audit to warn+continue"
            );
        }
        self.price_feed
            .audit_chainlink_feeds_with_options(ChainlinkFeedAuditOptions {
                strict: self.chainlink_feed_strict,
                allow_stale_critical: sync_state.is_lagging,
            })
            .await?;
        if sync_state.is_lagging {
            let provider = self.http_provider.clone();
            let price_feed = self.price_feed.clone();
            let chain_id = self.chain_id;
            let strict = self.chainlink_feed_strict;
            let shutdown_monitor = shutdown.clone();
            let public_rpc_for_monitor = feed_audit_public_rpc.clone();
            tokio::spawn(async move {
                let poll_interval = Duration::from_secs(Self::feed_audit_recheck_secs());
                loop {
                    tokio::select! {
                        _ = shutdown_monitor.cancelled() => break,
                        _ = sleep(poll_interval) => {}
                    }
                    let state = Self::check_sync_lag_state(
                        &provider,
                        chain_id,
                        feed_audit_max_lag_blocks,
                        public_rpc_for_monitor.as_deref(),
                        feed_audit_public_tip_lag_blocks,
                    )
                    .await;
                    if state.is_lagging {
                        continue;
                    }

                    tracing::info!(
                        target: "price_feed",
                        chain_id,
                        "Node recovered into freshness window; rerunning strict Chainlink feed audit"
                    );
                    let strict_result = price_feed
                        .audit_chainlink_feeds_with_options(ChainlinkFeedAuditOptions {
                            strict,
                            allow_stale_critical: false,
                        })
                        .await;
                    if let Err(e) = strict_result {
                        tracing::error!(
                            target: "price_feed",
                            chain_id,
                            error = %e,
                            "Strict Chainlink feed audit failed after sync recovery; requesting shutdown"
                        );
                        shutdown_monitor.cancel();
                    } else {
                        tracing::info!(
                            target: "price_feed",
                            chain_id,
                            "Strict Chainlink feed audit passed after sync recovery"
                        );
                    }
                    break;
                }
            });
        }
        if self.rpc_capability_strict
            && !(capabilities.eth_simulate || capabilities.debug_trace_call_many)
        {
            return Err(AppError::Config(
                "rpc_capability_strict=true but neither eth_simulateV1 nor debug_traceCallMany is available"
                    .into(),
            ));
        }
        if self.rpc_capability_strict
            && capabilities.eth_simulate
            && !capabilities.eth_simulate_shape_ok
        {
            return Err(AppError::Config(
                "rpc_capability_strict=true but eth_simulateV1 parameter-shape compatibility check failed"
                    .into(),
            ));
        }
        if self.rpc_capability_strict
            && capabilities.debug_trace_call_many
            && !capabilities.debug_trace_call_many_shape_ok
        {
            return Err(AppError::Config(
                "rpc_capability_strict=true but debug_traceCallMany parameter-shape compatibility check failed"
                    .into(),
            ));
        }
        if capabilities.debug_trace_call && !capabilities.debug_trace_call_many {
            tracing::warn!(
                target: "rpc",
                "debug_traceCall is available but debug_traceCallMany is not; bundle simulation will fall back to per-transaction execution when eth_simulateV1 is unavailable"
            );
        }
        let stats = Arc::new(StrategyStats::default());
        let work_queue = Arc::new(WorkQueue::new(INGEST_QUEUE_BOUND));
        let (block_sender, block_receiver) = broadcast::channel(32);
        let mevshare_builders =
            BundleSender::canonicalize_mevshare_builders(self.mevshare_builders.clone()).await;

        let mempool = MempoolScanner::new(
            self.websocket_provider.clone(),
            work_queue.clone(),
            stats.clone(),
            INGEST_QUEUE_BOUND,
            shutdown.clone(),
        );
        let block_listener = BlockListener::new(
            self.websocket_provider.clone(),
            block_sender.clone(),
            self.nonce_manager.clone(),
            shutdown.clone(),
        );
        let bundle_sender: SharedBundleSender = Arc::new(BundleSender::new(
            self.http_provider.clone(),
            self.dry_run,
            self.relay_url.clone(),
            self.mev_share_relay_url.clone(),
            mevshare_builders,
            self.bundle_signer.clone(),
            stats.clone(),
            self.bundle_use_replacement_uuid,
            self.bundle_cancel_previous,
        ));
        let reserve_cache = Arc::new(ReserveCache::new(self.http_provider.clone()));
        if Path::new(&self.pairs_path).exists() {
            if let Err(e) = reserve_cache
                .load_pairs_from_file_validated(
                    &self.pairs_path,
                    &self.http_provider,
                    self.chain_id,
                )
                .await
            {
                tracing::warn!(target: "reserves", error=%e, "Failed to preload pairs.json");
            } else if let Err(e) = reserve_cache.warmup_v2_reserves(1_000).await {
                tracing::warn!(
                    target: "reserves",
                    error = %e,
                    "Failed to warm V2 reserves from preloaded pairs"
                );
            }
        }

        let mut aave_pool = self.aave_pool;
        // Address registry: validate and apply optional protocol addresses.
        if let Ok(registry) = AddressRegistry::load_from_file(&self.address_registry_path) {
            if let Some(chain_reg) = registry.chain(self.chain_id) {
                let chain_reg = chain_reg.validate_with_provider(&self.http_provider).await;
                for (name, addr) in chain_reg.routers {
                    match classify_allowlist_entry(&name) {
                        crate::services::strategy::strategy::AllowlistCategory::Routers => {
                            self.router_allowlist.insert(addr);
                        }
                        crate::services::strategy::strategy::AllowlistCategory::Wrappers => {
                            self.wrapper_allowlist.insert(addr);
                        }
                        crate::services::strategy::strategy::AllowlistCategory::Infra => {
                            self.infra_allowlist.insert(addr);
                        }
                    }
                }
                if let Some(vault) = chain_reg.balancer_vault {
                    reserve_cache.set_balancer_vault(vault).await;
                }
                for addr in chain_reg.curve_registries {
                    reserve_cache.add_curve_registry(addr);
                }
                for addr in chain_reg.curve_meta_registries {
                    reserve_cache.add_curve_meta_registry(addr);
                }
                for addr in chain_reg.curve_crypto_registries {
                    reserve_cache.add_curve_crypto_registry(addr);
                }
                if let Some(aave_pool_reg) = chain_reg.aave_pool
                    && aave_pool.is_none()
                {
                    tracing::info!(
                        target: "registry",
                        chain_id = self.chain_id,
                        pool = %format!("{:#x}", aave_pool_reg),
                        "Using Aave pool from registry"
                    );
                    aave_pool = Some(aave_pool_reg);
                }
            }
        } else {
            tracing::warn!(
                target: "registry",
                path = %self.address_registry_path,
                "Address registry not loaded; proceeding with defaults"
            );
        }

        if let Some(vault) = default_balancer_vault_for_chain(self.chain_id) {
            reserve_cache.set_balancer_vault(vault).await;
        }

        if let Some(pool) = aave_pool {
            match self.http_provider.get_code_at(pool).await {
                Ok(code) => {
                    if code.is_empty() {
                        tracing::warn!(
                            target: "registry",
                            pool = %format!("{:#x}", pool),
                            "Aave pool has no code; disabling"
                        );
                        aave_pool = None;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "registry",
                        pool = %format!("{:#x}", pool),
                        error = %e,
                        "Failed to validate Aave pool; disabling"
                    );
                    aave_pool = None;
                }
            }
        }

        // Validate categorized allowlists against on-chain code.
        self.prune_allowlist_without_code("routers", &self.router_allowlist)
            .await;
        self.prune_allowlist_without_code("wrappers", &self.wrapper_allowlist)
            .await;
        self.prune_allowlist_without_code("infra", &self.infra_allowlist)
            .await;
        let reserve_listener = {
            let cache = reserve_cache.clone();
            let ws_for_cache = self.websocket_provider.clone();
            let reserve_shutdown = shutdown.clone();
            async move {
                cache
                    .run_v2_log_listener(ws_for_cache, reserve_shutdown)
                    .await;
                Ok::<(), AppError>(())
            }
        };
        let _metrics_addr = crate::common::metrics::spawn_metrics_server(
            self.metrics_port,
            self.chain_id,
            shutdown.clone(),
            stats.clone(),
            self.portfolio.clone(),
        )
        .await;
        if self.strategy_enabled {
            // Validate tokenlist addresses for this chain before strategy uses them.
            let invalid = self
                .token_manager
                .validate_chain_addresses(&self.http_provider, self.chain_id)
                .await;
            if invalid > 0 {
                tracing::warn!(
                    target: "token_manager",
                    chain_id = self.chain_id,
                    invalid,
                    "Tokenlist contains addresses without code; filtered"
                );
            }

            let strategy = StrategyExecutor::new(
                work_queue.clone(),
                block_receiver,
                self.safety_guard.clone(),
                bundle_sender.clone(),
                self.db.clone(),
                self.portfolio.clone(),
                self.gas_oracle.clone(),
                self.price_feed,
                self.chain_id,
                self.max_gas_price_gwei,
                self.gas_cap_multiplier_bps,
                self.simulator,
                self.token_manager.clone(),
                stats.clone(),
                self.wallet_signer.clone(),
                self.nonce_manager.clone(),
                self.slippage_bps,
                self.profit_guard_base_floor_multiplier_bps,
                self.profit_guard_cost_multiplier_bps,
                self.profit_guard_min_margin_bps,
                self.liquidity_ratio_floor_ppm,
                self.sell_min_native_out_wei,
                self.http_provider.clone(),
                self.dry_run,
                self.router_allowlist.clone(),
                self.wrapper_allowlist.clone(),
                self.infra_allowlist.clone(),
                self.router_discovery.clone(),
                self.skip_log_every,
                self.wrapped_native,
                self.allow_non_wrapped_swaps,
                self.executor,
                self.executor_bribe_bps,
                self.executor_bribe_recipient,
                self.flashloan_enabled,
                self.flashloan_providers.clone(),
                aave_pool,
                reserve_cache.clone(),
                self.sandwich_attacks_enabled,
                self.simulation_backend.clone(),
                self.worker_limit,
                shutdown.clone(),
                self.receipt_poll_ms,
                self.receipt_timeout_ms,
                self.receipt_confirm_blocks,
                self.emergency_exit_on_unknown_receipt,
            );

            if self.mev_share_enabled {
                match MevShareClient::new(
                    self.mev_share_stream_url.clone(),
                    self.chain_id,
                    work_queue.clone(),
                    stats.clone(),
                    INGEST_QUEUE_BOUND,
                    self.mev_share_history_limit,
                    shutdown.clone(),
                ) {
                    Ok(mev_share) => {
                        drop(block_sender);
                        tokio::try_join!(
                            mempool.run(),
                            block_listener.run(),
                            strategy.run(),
                            mev_share.run(),
                            reserve_listener
                        )
                        .map(|_| ())
                        .map_err(|e| AppError::Unknown(e.into()))
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "mev_share",
                            error = %e,
                            "MEV-Share client init failed; continuing without MEV-Share stream"
                        );
                        drop(block_sender);
                        tokio::try_join!(
                            mempool.run(),
                            block_listener.run(),
                            strategy.run(),
                            reserve_listener
                        )
                        .map(|_| ())
                        .map_err(|e| AppError::Unknown(e.into()))
                    }
                }
            } else {
                drop(block_sender);
                tokio::try_join!(
                    mempool.run(),
                    block_listener.run(),
                    strategy.run(),
                    reserve_listener
                )
                .map(|_| ())
                .map_err(|e| AppError::Unknown(e.into()))
            }
        } else {
            drop(block_sender);
            tokio::try_join!(mempool.run(), block_listener.run(), reserve_listener)
                .map(|_| ())
                .map_err(|e| AppError::Unknown(e.into()))
        }
    }
}
