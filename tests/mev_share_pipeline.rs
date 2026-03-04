// SPDX-License-Identifier: MIT
// Lightweight integration test for MEV-Share hint handling. Uses in-memory DB
// and mock payloads to drive the pipeline through simulate_and_score and bundle
// assembly without sending to a real relay.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;
use oxidity_searcher::common::constants::{
    CHAIN_ETHEREUM, default_uniswap_v2_router, wrapped_native_for_chain,
};
use oxidity_searcher::core::strategy::StrategyWork;
use oxidity_searcher::network::mev_share::MevShareHint;
use oxidity_searcher::services::strategy::routers::UniV2Router;
use std::sync::Arc;

mod support;
use support::{ExecutorHarnessOptions, build_strategy_executor};

/// Ensures a MEV-Share hint can be decoded, simulated, and queued without panic.
#[tokio::test]
async fn mev_share_hint_round_trip() {
    let (exec, harness) = build_strategy_executor(ExecutorHarnessOptions::default()).await;
    let stats = harness.stats.clone();
    let router =
        default_uniswap_v2_router(CHAIN_ETHEREUM).unwrap_or_else(|| Address::from([0x11; 20]));
    harness.router_allowlist.insert(router);

    // Craft a simple V2 swapExactETHForTokens payload WETH->token.
    let token_out = Address::from([0x44; 20]);
    let calldata = UniV2Router::swapExactETHForTokensCall {
        amountOutMin: U256::from(1u64),
        path: vec![wrapped_native_for_chain(CHAIN_ETHEREUM), token_out],
        to: harness.signer.address(),
        deadline: U256::from(999_999u64),
    }
    .abi_encode();

    let hint = MevShareHint {
        tx_hash: B256::from_slice(&[0x55; 32]),
        router,
        from: Some(harness.signer.address()),
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
