// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use dashmap::DashSet;
use oxidity_searcher::common::constants::{CHAIN_ETHEREUM, wrapped_native_for_chain};
use oxidity_searcher::core::executor::BundleSender;
use oxidity_searcher::core::portfolio::PortfolioManager;
use oxidity_searcher::core::safety::SafetyGuard;
use oxidity_searcher::core::simulation::{SimulationBackend, Simulator};
use oxidity_searcher::core::strategy::{
    FlashloanProvider, StrategyConfig, StrategyExecutor, StrategyStats,
};
use oxidity_searcher::data::db::Database;
use oxidity_searcher::infrastructure::data::token_manager::TokenManager;
use oxidity_searcher::network::gas::GasOracle;
use oxidity_searcher::network::nonce::NonceManager;
use oxidity_searcher::network::price_feed::{PriceApiKeys, PriceFeed};
use oxidity_searcher::network::provider::HttpProvider;
use oxidity_searcher::network::reserves::ReserveCache;
use oxidity_searcher::services::strategy::execution::work_queue::WorkQueue;
use std::sync::Arc;
use tokio::sync::broadcast;
use url::Url;

#[allow(dead_code)]
pub struct ExecutorHarness {
    pub http: HttpProvider,
    pub signer: PrivateKeySigner,
    pub stats: Arc<StrategyStats>,
    pub router_allowlist: Arc<DashSet<Address>>,
}

#[derive(Clone)]
pub struct ExecutorHarnessOptions {
    pub rpc_url: String,
    pub chain_id: u64,
    pub signer: Option<PrivateKeySigner>,
    pub dry_run: bool,
    pub wrapped_native: Address,
    pub executor: Option<Address>,
    pub flashloan_enabled: bool,
    pub flashloan_providers: Vec<FlashloanProvider>,
    pub aave_pool: Option<Address>,
}

impl Default for ExecutorHarnessOptions {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            chain_id: CHAIN_ETHEREUM,
            signer: None,
            dry_run: true,
            wrapped_native: wrapped_native_for_chain(CHAIN_ETHEREUM),
            executor: None,
            flashloan_enabled: false,
            flashloan_providers: vec![FlashloanProvider::Balancer],
            aave_pool: None,
        }
    }
}

pub async fn build_strategy_executor(
    options: ExecutorHarnessOptions,
) -> (StrategyExecutor, ExecutorHarness) {
    let http = HttpProvider::new_http(Url::parse(&options.rpc_url).expect("rpc url"));
    let signer = options
        .signer
        .clone()
        .unwrap_or_else(PrivateKeySigner::random);
    let bundle_signer = PrivateKeySigner::random();
    let safety_guard = Arc::new(SafetyGuard::new());
    let stats = Arc::new(StrategyStats::default());
    let bundle_sender = Arc::new(BundleSender::new(
        http.clone(),
        reqwest::Client::new(),
        options.dry_run,
        "https://relay.flashbots.net".to_string(),
        "https://mev-share.flashbots.net".to_string(),
        vec![
            "flashbots".to_string(),
            "beaverbuild.org".to_string(),
            "rsync".to_string(),
            "Titan".to_string(),
        ],
        bundle_signer,
        stats.clone(),
        true,
        false,
        1,
    ));
    let db = Database::new("sqlite::memory:").await.expect("db");
    let portfolio = Arc::new(PortfolioManager::new(http.clone(), signer.address()));
    let gas_oracle = GasOracle::new(http.clone(), options.chain_id);
    let price_feed = PriceFeed::new(
        http.clone(),
        options.chain_id,
        std::collections::HashMap::new(),
        PriceApiKeys::default(),
    )
    .expect("price feed");
    let simulator = Simulator::new(http.clone(), SimulationBackend::new("revm"));
    let token_manager = Arc::new(TokenManager::default());
    let nonce_manager = NonceManager::new(http.clone(), signer.address());
    let reserve_cache = Arc::new(ReserveCache::new(http.clone()));
    let router_allowlist = Arc::new(DashSet::new());
    let wrapper_allowlist = Arc::new(DashSet::new());
    let infra_allowlist = Arc::new(DashSet::new());
    let work_queue = Arc::new(WorkQueue::new(4));
    let (_block_tx, block_rx) = broadcast::channel(4);

    let exec = StrategyExecutor::from_config(StrategyConfig {
        work_queue,
        block_rx,
        safety_guard,
        bundle_sender,
        db,
        portfolio,
        gas_oracle,
        price_feed,
        chain_id: options.chain_id,
        max_gas_price_gwei: 200,
        gas_cap_multiplier_bps: 12_000,
        simulator,
        token_manager,
        stats: stats.clone(),
        signer: signer.clone(),
        nonce_manager,
        slippage_bps: 50,
        profit_guard_base_floor_multiplier_bps: 10_000,
        profit_guard_cost_multiplier_bps: 10_000,
        profit_guard_min_margin_bps: 1_200,
        liquidity_ratio_floor_ppm: 1_000,
        sell_min_native_out_wei: 5_000_000_000_000,
        http_provider: http.clone(),
        dry_run: options.dry_run,
        router_allowlist: router_allowlist.clone(),
        wrapper_allowlist,
        infra_allowlist,
        router_discovery: None,
        skip_log_every: 500,
        wrapped_native: options.wrapped_native,
        allow_non_wrapped_swaps: false,
        executor: options.executor,
        executor_bribe_bps: 0,
        executor_bribe_recipient: None,
        flashloan_enabled: options.flashloan_enabled,
        flashloan_providers: options.flashloan_providers,
        aave_pool: options.aave_pool,
        reserve_cache,
        sandwich_attacks_enabled: true,
        simulation_backend: "revm".to_string(),
        worker_limit: 4,
        shutdown: tokio_util::sync::CancellationToken::new(),
        receipt_poll_ms: 500,
        receipt_timeout_ms: 60_000,
        receipt_confirm_blocks: 4,
        emergency_exit_on_unknown_receipt: false,
        runtime: Default::default(),
    });

    (
        exec,
        ExecutorHarness {
            http,
            signer,
            stats,
            router_allowlist,
        },
    )
}
