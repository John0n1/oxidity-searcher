// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::primitives::{Address, Bytes, U256};

use super::{RouteLeg, RoutePlan, RouteVenue};

#[derive(Clone, Debug)]
struct Path {
    legs: Vec<QuoteEdge>,
    current_token: Address,
    current_amount: U256,
    gas: u64,
    score: U256,
}

/// Directed liquidity edge for a specific trade size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteEdge {
    pub venue: RouteVenue,
    pub pool: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub expected_out: U256,
    pub min_out: U256,
    pub gas_overhead: u64,
    pub fee: Option<u32>,
    pub params: Option<Bytes>,
    pub is_flash: bool,
}

/// Collection of candidate edges between tokens.
#[derive(Clone, Debug, Default)]
pub struct QuoteGraph {
    pub edges: Vec<QuoteEdge>,
}

impl QuoteGraph {
    pub fn add_edge(&mut self, edge: QuoteEdge) {
        self.edges.push(edge);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteSearchOptions {
    pub gas_price: u128,
    pub max_hops: usize,
    pub beam_size: usize,
    pub min_ratio_ppm: u64,
}

impl QuoteGraph {
    /// Beam search for up to `k` best routes (descending net value).
    pub fn k_best(
        &self,
        start: Address,
        target: Address,
        amount_in: U256,
        k: usize,
        opts: QuoteSearchOptions,
    ) -> Vec<RoutePlan> {
        if amount_in.is_zero() || k == 0 {
            return Vec::new();
        }

        let mut frontier: Vec<Path> = vec![Path {
            legs: Vec::new(),
            current_token: start,
            current_amount: amount_in,
            gas: 0,
            score: U256::ZERO,
        }];

        let mut solutions: Vec<RoutePlan> = Vec::new();

        for _depth in 0..opts.max_hops {
            let mut next: Vec<Path> = Vec::new();
            for path in frontier.into_iter() {
                // Expand outgoing edges from current token.
                for edge in self
                    .edges
                    .iter()
                    .filter(|e| e.token_in == path.current_token)
                {
                    // Size adjust expected_out linearly; edge.amount_in > 0 guaranteed by construction.
                    if edge.amount_in.is_zero() {
                        continue;
                    }
                    let scaled_out =
                        path.current_amount.saturating_mul(edge.expected_out) / edge.amount_in;
                    if scaled_out.is_zero() {
                        continue;
                    }
                    // Basic liquidity ratio pruning.
                    let ratio_ppm =
                        scaled_out.saturating_mul(U256::from(1_000_000u64)) / path.current_amount;
                    if ratio_ppm < U256::from(opts.min_ratio_ppm) {
                        continue;
                    }

                    let mut new_legs = path.legs.clone();
                    let mut gas = path.gas.saturating_add(edge.gas_overhead);
                    if gas == 0 {
                        gas = edge.gas_overhead;
                    }
                    let min_out = edge.min_out.saturating_mul(path.current_amount) / edge.amount_in;
                    new_legs.push(QuoteEdge {
                        venue: edge.venue,
                        pool: edge.pool,
                        token_in: edge.token_in,
                        token_out: edge.token_out,
                        amount_in: path.current_amount,
                        expected_out: scaled_out,
                        min_out,
                        gas_overhead: edge.gas_overhead,
                        fee: edge.fee,
                        params: edge.params.clone(),
                        is_flash: edge.is_flash,
                    });

                    let mut score = scaled_out;
                    // Subtract paid in (first leg amount) and gas cost.
                    let gas_cost = U256::from(opts.gas_price).saturating_mul(U256::from(gas));
                    score = score.saturating_sub(amount_in);
                    score = score.saturating_sub(gas_cost);

                    let new_path = Path {
                        legs: new_legs,
                        current_token: edge.token_out,
                        current_amount: scaled_out,
                        gas,
                        score,
                    };

                    if edge.token_out == target {
                        if let Some(plan) = Self::to_plan(&new_path.legs) {
                            solutions.push(plan);
                            if solutions.len() >= k {
                                return solutions;
                            }
                        }
                    } else {
                        next.push(new_path);
                    }
                }
            }

            // Beam prune by score
            next.sort_by(|a, b| b.score.cmp(&a.score));
            if next.len() > opts.beam_size {
                next.truncate(opts.beam_size);
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        solutions
    }

    fn to_plan(legs: &[QuoteEdge]) -> Option<RoutePlan> {
        let legs: Vec<RouteLeg> = legs
            .iter()
            .map(|e| RouteLeg {
                venue: e.venue,
                target: e.pool,
                token_in: e.token_in,
                token_out: e.token_out,
                amount_in: e.amount_in,
                min_out: e.min_out,
                fee: e.fee,
                params: e.params.clone(),
                is_flash_leg: e.is_flash,
            })
            .collect();
        RoutePlan::try_new(legs)
    }
}
