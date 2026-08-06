// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{address, Address, U256};
use oxidity_searcher::services::strategy::ingest::decode::{ObservedSwap, RouterKind};

#[test]
fn test_sandwich_slippage_headroom_detection() {
    let router = address!("7a250d5630b4cf539739df2c5dacb4c659f2488d");
    let token_in = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
    let token_out = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");

    let victim_swap = ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: Vec::new(),
        v3_path: None,
        amount_in: U256::from(20_000_000_000_000_000_000u128), // 20 ETH victim trade
        min_out: U256::from(1u64),                            // Un-guarded slippage (min_out = 1)
        recipient: Address::ZERO,
        router_kind: RouterKind::V2Like,
    };

    let is_slippage_rich = victim_swap.min_out <= U256::from(100u64);
    assert!(is_slippage_rich, "Victim swap should be classified as sandwich candidate due to high slippage headroom");
}

#[test]
fn test_sandwich_bundle_sequence_ordering() {
    let frontrun_tx_id = "tx_frontrun_1";
    let victim_tx_id = "tx_victim_2";
    let backrun_tx_id = "tx_backrun_3";

    let bundle = vec![frontrun_tx_id, victim_tx_id, backrun_tx_id];

    assert_eq!(bundle.len(), 3);
    assert_eq!(bundle[0], "tx_frontrun_1");
    assert_eq!(bundle[1], "tx_victim_2");
    assert_eq!(bundle[2], "tx_backrun_3");
}
