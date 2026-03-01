// SPDX-License-Identifier: MIT
// Lightweight integration test for MEV-Share hint handling. Uses in-memory DB
// and mock payloads to drive the pipeline through simulate_and_score and bundle
// assembly without sending to a real relay.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use dashmap::DashSet;
use oxidity_searcher::common::constants::{
    CHAIN_ETHEREUM, default_uniswap_v2_router, wrapped_native_for_chain,
};
use oxidity_searcher::core::executor::BundleSender;
use oxidity_searcher::core::portfolio::PortfolioManager;
use oxidity_searcher::core::safety::SafetyGuard;
use oxidity_searcher::core::simulation::{SimulationBackend, Simulator};
use oxidity_searcher::core::strategy::{
    FlashloanProvider, StrategyConfig, StrategyExecutor, StrategyWork,
};
use oxidity_searcher::data::db::Database;
use oxidity_searcher::infrastructure::data::token_manager::TokenManager;
use oxidity_searcher::network::gas::GasOracle;
use oxidity_searcher::network::mev_share::MevShareHint;
use oxidity_searcher::network::nonce::NonceManager;
use oxidity_searcher::network::price_feed::{PriceApiKeys, PriceFeed};
use oxidity_searcher::network::provider::HttpProvider;
use oxidity_searcher::network::reserves::ReserveCache;
use oxidity_searcher::services::strategy::execution::work_queue::WorkQueue;
use oxidity_searcher::services::strategy::routers::UniV2Router;
use oxidity_searcher::services::strategy::strategy::StrategyStats as Stats;
use std::sync::Arc;
use tokio::sync::broadcast;
use url::Url;

/// Ensures a MEV-Share hint can be decoded, simulated, and queued without panic.
#[tokio::test]
async fn mev_share_hint_round_trip() {
    let http = HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").unwrap());
    let signer = PrivateKeySigner::random();
    let bundle_signer = PrivateKeySigner::random();
    let safety_guard = Arc::new(SafetyGuard::new());
    let stats = Arc::new(Stats::default());
    let bundle_sender = Arc::new(BundleSender::new(
        http.clone(),
        reqwest::Client::new(),
        true,
        "https://relay.flashbots.net".to_string(),
        "https://mev-share.flashbots.net".to_string(),
        vec![
            "flashbots".to_string(),
            "beaverbuild.org".to_string(),
            "rsync".to_string(),
            "Titan".to_string(),
        ],
        bundle_signer.clone(),
        stats.clone(),
        true,
        false,
        1,
    ));
    let db = Database::new("sqlite::memory:").await.expect("db");
    let portfolio = Arc::new(PortfolioManager::new(http.clone(), signer.address()));
    let gas_oracle = GasOracle::new(http.clone(), 1);
    let price_feed = PriceFeed::new(
        http.clone(),
        1,
        std::collections::HashMap::new(),
        PriceApiKeys::default(),
    )
    .expect("price feed");
    let simulator = Simulator::new(http.clone(), SimulationBackend::new("revm"));
    let token_manager = Arc::new(TokenManager::default());
    let nonce_manager = NonceManager::new(http.clone(), signer.address());
    let reserve_cache = Arc::new(ReserveCache::new(http.clone()));

    let work_queue = Arc::new(WorkQueue::new(4));
    let (_block_tx, block_rx) = broadcast::channel(4);

    let allowlist = Arc::new(DashSet::new());
    let wrapper_allowlist = Arc::new(DashSet::new());
    let infra_allowlist = Arc::new(DashSet::new());
    let router =
        default_uniswap_v2_router(CHAIN_ETHEREUM).unwrap_or_else(|| Address::from([0x11; 20]));
    allowlist.insert(router);

    let exec = StrategyExecutor::from_config(StrategyConfig {
        work_queue,
        block_rx,
        safety_guard,
        bundle_sender,
        db,
        portfolio,
        gas_oracle,
        price_feed,
        chain_id: 1,
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
        dry_run: true,
        router_allowlist: allowlist,
        wrapper_allowlist,
        infra_allowlist,
        router_discovery: None,
        skip_log_every: 500,
        wrapped_native: wrapped_native_for_chain(CHAIN_ETHEREUM),
        allow_non_wrapped_swaps: false,
        executor: None,
        executor_bribe_bps: 0,
        executor_bribe_recipient: None,
        flashloan_enabled: false,
        flashloan_providers: vec![FlashloanProvider::Balancer],
        aave_pool: None,
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

    // Craft a simple V2 swapExactETHForTokens payload WETH->token.
    let token_out = Address::from([0x44; 20]);
    let calldata = UniV2Router::swapExactETHForTokensCall {
        amountOutMin: U256::from(1u64),
        path: vec![wrapped_native_for_chain(CHAIN_ETHEREUM), token_out],
        to: signer.address(),
        deadline: U256::from(999_999u64),
    }
    .abi_encode();

    let hint = MevShareHint {
        tx_hash: B256::from_slice(&[0x55; 32]),
        router,
        from: Some(signer.address()),
        call_data: Bytes::from(calldata).to_vec(),
        value: U256::from(1_000_000_000_000_000u128),
        gas_limit: Some(220_000),
        max_fee_per_gas: Some(30_000_000_000),
        max_priority_fee_per_gas: Some(2_000_000_000),
    };

    // We don't assert profitability; just ensure the path runs without panic and
    // increments processed/skip counters appropriately.
    let exec = Arc::new(exec);
    exec.process_work(StrategyWork::MevShareHint {
        hint: Box::new(hint),
        received_at: std::time::Instant::now(),
    })
    .await;

    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(processed, 1, "hint should have been processed");
}
