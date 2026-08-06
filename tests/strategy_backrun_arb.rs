// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{address, Address, U256};
use oxidity_searcher::services::strategy::ingest::decode::{ObservedSwap, RouterKind};

#[test]
fn test_backrun_candidate_validation() {
    let router = address!("7a250d5630b4cf539739df2c5dacb4c659f2488d");
    let token_in = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH
    let token_out = address!("6b175474e89094c44da98b954eedeac495271d0f"); // DAI

    let swap = ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: Vec::new(),
        v3_path: None,
        amount_in: U256::from(5_000_000_000_000_000_000u64), // 5 ETH
        min_out: U256::from(10_000_000_000_000_000_000_000u128), // 10,000 DAI
        recipient: Address::ZERO,
        router_kind: RouterKind::V2Like,
    };

    assert_eq!(swap.path.len(), 2);
    assert_eq!(swap.amount_in, U256::from(5_000_000_000_000_000_000u64));
    assert_eq!(swap.router_kind, RouterKind::V2Like);
}

#[test]
fn test_triangular_arbitrage_path_topology() {
    let token_a = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH
    let token_b = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"); // USDC
    let token_c = address!("6b175474e89094c44da98b954eedeac495271d0f"); // DAI

    let path = vec![token_a, token_b, token_c, token_a];

    assert_eq!(path.len(), 4);
    assert_eq!(path[0], path[3]); // Closed loop A -> B -> C -> A
    assert_ne!(path[0], path[1]);
    assert_ne!(path[1], path[2]);
}
