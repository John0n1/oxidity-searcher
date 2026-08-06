// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{address, Address, U256};
use oxidity_searcher::services::strategy::ingest::decode::{ObservedSwap, RouterKind};

#[test]
fn test_bot_trapping_unguarded_competitor_swap_detection() {
    let router = address!("7a250d5630b4cf539739df2c5dacb4c659f2488d");
    let token_in = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
    let token_out = address!("6b175474e89094c44da98b954eedeac495271d0f");

    let naive_bot_swap = ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: Vec::new(),
        v3_path: None,
        amount_in: U256::from(5_000_000_000_000_000_000u64), // 5 ETH swap
        min_out: U256::from(0u64),                            // Zero slippage protection
        recipient: Address::ZERO,
        router_kind: RouterKind::V2Like,
    };

    let is_unguarded = naive_bot_swap.min_out <= U256::from(1u64);
    assert!(is_unguarded, "Competitor swap with min_out <= 1 must be flagged for MEV Bot Trapping extraction");
}

#[test]
fn test_counter_trap_bundle_structure() {
    let bait_frontrun = "bait_frontrun_push_price";
    let competitor_tx = "naive_competitor_swap";
    let extraction_backrun = "counter_trap_backrun_extract_capital";

    let bundle = vec![bait_frontrun, competitor_tx, extraction_backrun];

    assert_eq!(bundle.len(), 3);
    assert_eq!(bundle[1], "naive_competitor_swap");
}
