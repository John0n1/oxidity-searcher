// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::primitives::{Address, Bytes, U256};

use super::{RouteLeg, RoutePlan, RouteVenue};

#[derive(Clone, Debug)]
struct Path {
    legs: Vec<QuoteEdge>,
    current_token: Address,
    current_amount: U256,
    gas: u64,
    score_ratio_ppm: U256,
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
            score_ratio_ppm: U256::ZERO,
        }];

        // Rank by dimensionless route ratio (output/input) and use gas as a tie-breaker.
        let mut solutions: Vec<(U256, u64, RoutePlan)> = Vec::new();

        for _depth in 0..opts.max_hops {
            let mut next: Vec<Path> = Vec::new();
            for path in frontier.into_iter() {
                // Expand outgoing edges from current token.
                for edge in self
                    .edges
                    .iter()
                    .filter(|e| e.token_in == path.current_token)
                {
                    if edge.token_out != target
                        && Self::token_seen_in_path(start, &path.legs, edge.token_out)
                    {
                        continue;
                    }
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

                    // Keep scoring dimensionless across heterogeneous token decimals/units.
                    let route_ratio_ppm =
                        scaled_out.saturating_mul(U256::from(1_000_000u64)) / amount_in;

                    let new_path = Path {
                        legs: new_legs,
                        current_token: edge.token_out,
                        current_amount: scaled_out,
                        gas,
                        score_ratio_ppm: route_ratio_ppm,
                    };

                    if edge.token_out == target {
                        if let Some(plan) = Self::to_plan(&new_path.legs) {
                            solutions.push((new_path.score_ratio_ppm, new_path.gas, plan));
                        }
                    } else {
                        next.push(new_path);
                    }
                }
            }

            // Beam prune by ratio (descending), then by gas overhead (ascending).
            next.sort_by(|a, b| {
                b.score_ratio_ppm
                    .cmp(&a.score_ratio_ppm)
                    .then_with(|| a.gas.cmp(&b.gas))
            });
            if next.len() > opts.beam_size {
                next.truncate(opts.beam_size);
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        solutions.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        if solutions.len() > k {
            solutions.truncate(k);
        }
        solutions.into_iter().map(|(_, _, plan)| plan).collect()
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

    fn token_seen_in_path(start: Address, legs: &[QuoteEdge], token: Address) -> bool {
        if token == start {
            return true;
        }
        legs.iter().any(|l| l.token_out == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(
        token_in: Address,
        token_out: Address,
        expected_out: u64,
        min_out: u64,
        gas: u64,
    ) -> QuoteEdge {
        QuoteEdge {
            venue: RouteVenue::UniV2,
            pool: Address::from([0x11; 20]),
            token_in,
            token_out,
            amount_in: U256::from(100u64),
            expected_out: U256::from(expected_out),
            min_out: U256::from(min_out),
            gas_overhead: gas,
            fee: None,
            params: None,
            is_flash: false,
        }
    }

    #[test]
    fn k_best_prunes_cyclic_paths() {
        let a = Address::from([0x01; 20]);
        let b = Address::from([0x02; 20]);
        let c = Address::from([0x03; 20]);
        let mut graph = QuoteGraph::default();
        graph.add_edge(edge(a, b, 115, 110, 40_000));
        graph.add_edge(edge(b, a, 120, 115, 40_000)); // would form a cycle
        graph.add_edge(edge(a, c, 106, 104, 50_000)); // direct

        let plans = graph.k_best(
            a,
            c,
            U256::from(100u64),
            3,
            QuoteSearchOptions {
                gas_price: 0,
                max_hops: 3,
                beam_size: 8,
                min_ratio_ppm: 500_000,
            },
        );
        assert!(!plans.is_empty(), "at least one plan must be found");
        assert_eq!(plans[0].legs.len(), 1, "cyclic expansion should be pruned");
        assert_eq!(plans[0].legs[0].token_in, a);
        assert_eq!(plans[0].legs[0].token_out, c);
    }

    #[test]
    fn k_best_sorts_by_score_not_discovery_order() {
        let a = Address::from([0x11; 20]);
        let c = Address::from([0x33; 20]);
        let mut graph = QuoteGraph::default();

        let mut lower = edge(a, c, 105, 104, 0);
        lower.pool = Address::from([0xaa; 20]);
        graph.add_edge(lower);

        let mut higher = edge(a, c, 120, 119, 0);
        higher.pool = Address::from([0xbb; 20]);
        graph.add_edge(higher.clone());

        let plans = graph.k_best(
            a,
            c,
            U256::from(100u64),
            1,
            QuoteSearchOptions {
                gas_price: 0,
                max_hops: 2,
                beam_size: 8,
                min_ratio_ppm: 500_000,
            },
        );
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].legs[0].target, higher.pool);
    }

    #[test]
    fn k_best_prefers_lower_gas_when_ratio_is_equal() {
        let a = Address::from([0x21; 20]);
        let c = Address::from([0x31; 20]);
        let mut graph = QuoteGraph::default();

        let mut high_gas = edge(a, c, 120, 110, 120_000);
        high_gas.pool = Address::from([0xaa; 20]);
        graph.add_edge(high_gas);

        let mut low_gas = edge(a, c, 120, 110, 40_000);
        low_gas.pool = Address::from([0xbb; 20]);
        graph.add_edge(low_gas.clone());

        let plans = graph.k_best(
            a,
            c,
            U256::from(100u64),
            1,
            QuoteSearchOptions {
                gas_price: u128::MAX,
                max_hops: 2,
                beam_size: 8,
                min_ratio_ppm: 500_000,
            },
        );
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].legs[0].target, low_gas.pool);
    }
}
