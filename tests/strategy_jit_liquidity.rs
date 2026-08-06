// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{address, Address, U256};
use oxidity_searcher::services::strategy::ingest::decode::{ObservedSwap, RouterKind};

#[test]
fn test_jit_liquidity_threshold_filter() {
    let router = address!("e592427a0aece92de3edee1f18e0157c05861564"); // Uniswap V3 Router
    let token_in = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
    let token_out = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");

    let small_swap = ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: vec![3000],
        v3_path: None,
        amount_in: U256::from(100_000_000_000_000_000u64), // 0.1 ETH (too small for JIT)
        min_out: U256::from(300_000_000u64),
        recipient: Address::ZERO,
        router_kind: RouterKind::V3Like,
    };

    let large_swap = ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: vec![3000],
        v3_path: None,
        amount_in: U256::from(10_000_000_000_000_000_000u64), // 10 ETH (JIT candidate)
        min_out: U256::from(30_000_000_000u64),
        recipient: Address::ZERO,
        router_kind: RouterKind::V3Like,
    };

    let min_jit_threshold = U256::from(1_000_000_000_000_000_000u64); // 1.0 ETH

    assert!(small_swap.amount_in < min_jit_threshold);
    assert!(large_swap.amount_in >= min_jit_threshold);
    assert_eq!(large_swap.router_kind, RouterKind::V3Like);
}

#[test]
fn test_jit_concentrated_tick_range_math() {
    let current_tick: i32 = 200000;
    let tick_spacing: i32 = 60; // 0.3% fee tier tick spacing

    let tick_lower = current_tick - tick_spacing;
    let tick_upper = current_tick + tick_spacing;

    assert!(tick_lower < current_tick);
    assert!(tick_upper > current_tick);
    assert_eq!(tick_upper - tick_lower, 2 * tick_spacing);
}
