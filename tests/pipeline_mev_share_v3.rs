// SPDX-License-Identifier: MIT

use alloy::primitives::{Address, B256, Bytes, U160, U256, aliases::U24};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use dashmap::DashSet;
use mitander_search::common::constants::{CHAIN_ETHEREUM, wrapped_native_for_chain};
use mitander_search::core::executor::BundleSender;
use mitander_search::core::portfolio::PortfolioManager;
use mitander_search::core::safety::SafetyGuard;
use mitander_search::core::simulation::{SimulationBackend, Simulator};
use mitander_search::core::strategy::{
    FlashloanProvider, StrategyExecutor, StrategyStats, StrategyWork,
};
use mitander_search::data::db::Database;
use mitander_search::infrastructure::data::token_manager::TokenManager;
use mitander_search::network::gas::GasOracle;
use mitander_search::network::mev_share::MevShareHint;
use mitander_search::network::nonce::NonceManager;
use mitander_search::network::price_feed::{PriceApiKeys, PriceFeed};
use mitander_search::network::provider::HttpProvider;
use mitander_search::network::reserves::ReserveCache;
use mitander_search::services::strategy::execution::work_queue::WorkQueue;
use mitander_search::services::strategy::routers::UniV3Router;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::broadcast;
use url::Url;

#[tokio::test]
async fn mev_share_v3_pipeline_manual() {
    use std::env;

    let rpc = match env::var("http_provider_1") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skipping: set http_provider_1 / WEBSOCKET_URL_1 (Nethermind/Anvil)");
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
    // Discover chain id from the node so we don't assume mainnet.
    let chain_id = http.get_chain_id().await.unwrap_or(1u64);
    let bundle_signer = PrivateKeySigner::random();
    let safety_guard = Arc::new(SafetyGuard::new());
    let stats = Arc::new(StrategyStats::default());
    let bundle_sender = Arc::new(BundleSender::new(
        http.clone(),
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
    ));
    let db = Database::new("sqlite::memory:").await.expect("db");
    let portfolio = Arc::new(PortfolioManager::new(http.clone(), signer.address()));
    let gas_oracle = GasOracle::new(http.clone(), chain_id);
    let price_feed = PriceFeed::new(
        http.clone(),
        chain_id,
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
    let router_allowlist = Arc::new(DashSet::new());
    let uni_v3_router =
        Address::from_str("E592427A0AEce92De3Edee1F18E0157C05861564").expect("router addr");
    router_allowlist.insert(uni_v3_router);

    let exec = StrategyExecutor::new(
        work_queue,
        block_rx,
        safety_guard,
        bundle_sender,
        db,
        portfolio,
        gas_oracle,
        price_feed,
        chain_id,
        200,
        12_000,
        simulator,
        token_manager,
        stats.clone(),
        signer.clone(),
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
        None,
        500,
        wrapped_native_for_chain(CHAIN_ETHEREUM),
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
        4,
        tokio_util::sync::CancellationToken::new(),
        500,
        60_000,
        4,
        false,
    );

    // Build a simple V3 exactInputSingle payload swapping WETH -> WETH (no-op) for smoke test.
    let params = UniV3Router::ExactInputSingleParams {
        tokenIn: wrapped_native_for_chain(CHAIN_ETHEREUM),
        tokenOut: wrapped_native_for_chain(CHAIN_ETHEREUM),
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
            hint: Box::new(hint),
            received_at: std::time::Instant::now(),
        })
        .await;
}
