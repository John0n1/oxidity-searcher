// SPDX-License-Identifier: MIT
// Lightweight integration test for MEV-Share hint handling. Uses in-memory DB
// and mock payloads to drive the pipeline through simulate_and_score and bundle
// assembly without sending to a real relay.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use oxidity_builder::common::constants::WETH_MAINNET;
use oxidity_builder::core::executor::BundleSender;
use oxidity_builder::core::portfolio::PortfolioManager;
use oxidity_builder::core::safety::SafetyGuard;
use oxidity_builder::core::simulation::Simulator;
use oxidity_builder::core::strategy::{FlashloanProvider, StrategyExecutor, StrategyWork};
use oxidity_builder::data::db::Database;
use oxidity_builder::infrastructure::data::token_manager::TokenManager;
use oxidity_builder::network::gas::GasOracle;
use oxidity_builder::network::mev_share::MevShareHint;
use oxidity_builder::network::nonce::NonceManager;
use oxidity_builder::network::price_feed::PriceFeed;
use oxidity_builder::network::provider::HttpProvider;
use oxidity_builder::network::reserves::ReserveCache;
use oxidity_builder::services::strategy::routers::UniV2Router;
use oxidity_builder::services::strategy::strategy::StrategyStats as Stats;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use url::Url;

/// Ensures a MEV-Share hint can be decoded, simulated, and queued without panic.
#[tokio::test]
async fn mev_share_hint_round_trip() {
    let http = HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").unwrap());
    let signer = PrivateKeySigner::random();
    let bundle_signer = PrivateKeySigner::random();
    let safety_guard = Arc::new(SafetyGuard::new());
    let bundle_sender = Arc::new(BundleSender::new(
        http.clone(),
        true,
        "https://relay.flashbots.net".to_string(),
        bundle_signer.clone(),
    ));
    let db = Database::new("sqlite::memory:").await.expect("db");
    let portfolio = Arc::new(PortfolioManager::new(http.clone(), signer.address()));
    let gas_oracle = GasOracle::new(http.clone());
    let price_feed = PriceFeed::new(http.clone(), std::collections::HashMap::new());
    let simulator = Simulator::new(http.clone());
    let token_manager = Arc::new(TokenManager::default());
    let stats = Arc::new(Stats::default());
    let nonce_manager = NonceManager::new(http.clone(), signer.address());
    let reserve_cache = Arc::new(ReserveCache::new(http.clone()));

    let (_tx, rx) = mpsc::channel::<StrategyWork>(4);
    let (_block_tx, block_rx) = broadcast::channel(4);

    let mut allowlist = HashSet::new();
    let router = Address::from_str("7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap();
    allowlist.insert(router);

    let exec = StrategyExecutor::new(
        rx,
        block_rx,
        safety_guard,
        bundle_sender,
        db,
        portfolio,
        gas_oracle,
        price_feed,
        1,
        200,
        simulator,
        token_manager,
        stats.clone(),
        signer.clone(),
        nonce_manager,
        50,
        http.clone(),
        true,
        allowlist,
        WETH_MAINNET,
        None,
        0,
        None,
        false,
        vec![FlashloanProvider::Balancer],
        None,
        reserve_cache,
        true,
        "revm".to_string(),
        4,
    );

    // Craft a simple V2 swapExactETHForTokens payload WETH->token.
    let token_out = Address::from([0x44; 20]);
    let calldata = UniV2Router::swapExactETHForTokensCall {
        amountOutMin: U256::from(1u64),
        path: vec![WETH_MAINNET, token_out],
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
        hint,
        received_at: std::time::Instant::now(),
    })
    .await;

    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(processed, 1, "hint should have been processed");
}
