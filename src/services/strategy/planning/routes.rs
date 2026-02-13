// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::primitives::{Address, Bytes, U256};

/// Supported venues for routing and flash liquidity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteVenue {
    UniV2,
    UniV3,
    Sushi,
    CurvePool,
    BalancerPool,
    AaveV3Flash,
    BalancerFlash,
}

/// One hop or action in a composed route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLeg {
    pub venue: RouteVenue,
    /// Pool, router, or vault address involved in this leg.
    pub target: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub min_out: U256,
    /// Optional fee tier (e.g., UniV3 fee or Curve pool fee in bps/ppm).
    pub fee: Option<u32>,
    /// Venue-specific extra data (encoded path, pool params, etc.).
    pub params: Option<Bytes>,
    /// Marks whether this leg sources a flash loan rather than a swap.
    pub is_flash_leg: bool,
}

/// A full plan describing chained legs with token continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub legs: Vec<RouteLeg>,
    /// Aggregate input of the first leg.
    pub total_in: U256,
    /// Expected minimum output of the final leg.
    pub expected_out: U256,
}

impl RoutePlan {
    /// Builds a plan if legs are non-empty and token continuity holds.
    pub fn try_new(legs: Vec<RouteLeg>) -> Option<Self> {
        if legs.is_empty() {
            return None;
        }
        if !Self::is_continuous(&legs) {
            return None;
        }
        let total_in = legs.first().map(|l| l.amount_in).unwrap_or(U256::ZERO);
        let expected_out = legs.last().map(|l| l.min_out).unwrap_or(U256::ZERO);
        Some(Self {
            legs,
            total_in,
            expected_out,
        })
    }

    /// Validates token continuity: each leg's output matches the next leg's input.
    pub fn is_continuous(legs: &[RouteLeg]) -> bool {
        if legs.len() < 2 {
            return true;
        }
        for window in legs.windows(2) {
            if let [a, b] = window
                && a.token_out != b.token_in
            {
                return false;
            }
        }
        true
    }
}
