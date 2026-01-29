// SPDX-License-Identifier: MIT

use alloy::primitives::{Address, B256, Bytes, U160, U256, aliases::U24};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use oxidity_builder::common::constants::WETH_MAINNET;
use oxidity_builder::core::executor::BundleSender;
use oxidity_builder::core::portfolio::PortfolioManager;
use oxidity_builder::core::safety::SafetyGuard;
use oxidity_builder::core::simulation::Simulator;
use oxidity_builder::core::strategy::{
    FlashloanProvider, StrategyExecutor, StrategyStats, StrategyWork,
};
use oxidity_builder::data::db::Database;
use oxidity_builder::infrastructure::data::token_manager::TokenManager;
use oxidity_builder::network::gas::GasOracle;
use oxidity_builder::network::mev_share::MevShareHint;
use oxidity_builder::network::nonce::NonceManager;
use oxidity_builder::network::price_feed::PriceFeed;
use oxidity_builder::network::provider::HttpProvider;
use oxidity_builder::network::reserves::ReserveCache;
use oxidity_builder::services::strategy::routers::UniV3Router;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use url::Url;

#[tokio::test]
async fn mev_share_v3_pipeline_manual() {
    use std::env;

    let rpc = match env::var("RPC_URL_1") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: set RPC_URL_1 / WEBSOCKET_URL_1 (Nethermind/Anvil)");
            return;
        }
    };
    let _ws = match env::var("WEBSOCKET_URL_1") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: set WEBSOCKET_URL_1 (Nethermind/Anvil)");
            return;
        }
    };
    let wallet_key = env::var("WALLET_KEY").unwrap_or_else(|_| {
        // dev key funded by most test nodes; change via env for production‑like runs.
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string()
    });

    let http = HttpProvider::new_http(Url::parse(&rpc).expect("rpc url"));
    let signer = PrivateKeySigner::from_str(&wallet_key).expect("parse signer");
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
    let stats = Arc::new(StrategyStats::default());
    let nonce_manager = NonceManager::new(http.clone(), signer.address());
    let reserve_cache = Arc::new(ReserveCache::new(http.clone()));

    let (_tx, rx) = mpsc::channel::<StrategyWork>(4);
    let (_block_tx, block_rx) = broadcast::channel(4);
    let mut router_allowlist = HashSet::new();
    let uni_v3_router =
        Address::from_str("E592427A0AEce92De3Edee1F18E0157C05861564").expect("router addr");
    router_allowlist.insert(uni_v3_router);

    // Discover chain id from the node so we don't assume mainnet.
    let chain_id = http.get_chain_id().await.unwrap_or(1u64);

    let exec = StrategyExecutor::new(
        rx,
        block_rx,
        safety_guard,
        bundle_sender,
        db,
        portfolio,
        gas_oracle,
        price_feed,
        chain_id,
        200,
        simulator,
        token_manager,
        stats.clone(),
        signer.clone(),
        nonce_manager,
        50,
        http.clone(),
        true,
        router_allowlist,
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

    // Build a simple V3 exactInputSingle payload swapping WETH -> WETH (no-op) for smoke test.
    let params = UniV3Router::ExactInputSingleParams {
        tokenIn: WETH_MAINNET,
        tokenOut: WETH_MAINNET,
        fee: U24::from(500u32),
        recipient: signer.address(),
        deadline: U256::from(999_999_999u64),
        amountIn: U256::from(1_000_000_000_000_000u128),
        amountOutMinimum: U256::ZERO,
        sqrtPriceLimitX96: U160::ZERO,
    };
    let call = UniV3Router::exactInputSingleCall { params };
    let call_data = call.abi_encode();

    let hint = MevShareHint {
        tx_hash: B256::from_slice(&[9u8; 32]),
        router: uni_v3_router,
        from: Some(signer.address()),
        call_data: Bytes::from(call_data).to_vec(),
        value: U256::ZERO,
        gas_limit: Some(300_000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };

    let exec = Arc::new(exec);
    exec.clone()
        .process_work(StrategyWork::MevShareHint {
            hint,
            received_at: std::time::Instant::now(),
        })
        .await;
}
