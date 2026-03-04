// SPDX-License-Identifier: MIT

use alloy::primitives::{Address, B256, Bytes, U160, U256, aliases::U24};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use oxidity_searcher::common::constants::{CHAIN_ETHEREUM, wrapped_native_for_chain};
use oxidity_searcher::core::strategy::StrategyWork;
use oxidity_searcher::network::mev_share::MevShareHint;
use oxidity_searcher::network::provider::HttpProvider;
use oxidity_searcher::services::strategy::routers::UniV3Router;
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

mod support;
use support::{ExecutorHarnessOptions, build_strategy_executor};

#[tokio::test]
async fn mev_share_v3_pipeline_manual() {
    use std::env;

    let rpc = match env::var("HTTP_PROVIDER_1") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skip: set HTTP_PROVIDER_1 and WEBSOCKET_PROVIDER_1 (Nethermind/Anvil)");
            return;
        }
    };
    let _ws = match env::var("WEBSOCKET_PROVIDER_1") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("skip: set WEBSOCKET_PROVIDER_1 (Nethermind/Anvil)");
            return;
        }
    };
    let wallet_key = env::var("OXIDITY_WALLET_PRIVATE_KEY").unwrap_or_else(|_| {
        // dev key funded by most test nodes; change via env for production‑like runs.
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string()
    });

    let http = HttpProvider::new_http(Url::parse(&rpc).expect("rpc url"));
    let signer = PrivateKeySigner::from_str(&wallet_key).expect("parse signer");
    // Discover chain id from the node so we don't assume mainnet.
    let chain_id = http.get_chain_id().await.unwrap_or(1u64);
    let (exec, harness) = build_strategy_executor(ExecutorHarnessOptions {
        rpc_url: rpc.clone(),
        chain_id,
        signer: Some(signer.clone()),
        wrapped_native: wrapped_native_for_chain(CHAIN_ETHEREUM),
        ..ExecutorHarnessOptions::default()
    })
    .await;
    let uni_v3_router =
        Address::from_str("E592427A0AEce92De3Edee1F18E0157C05861564").expect("router addr");
    harness.router_allowlist.insert(uni_v3_router);

    // Build a simple V3 exactInputSingle payload swapping WETH -> WETH (no-op) for smoke test.
    let params = UniV3Router::ExactInputSingleParams {
        tokenIn: wrapped_native_for_chain(CHAIN_ETHEREUM),
        tokenOut: wrapped_native_for_chain(CHAIN_ETHEREUM),
        fee: U24::from(500u32),
        recipient: harness.signer.address(),
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
        from: Some(harness.signer.address()),
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
