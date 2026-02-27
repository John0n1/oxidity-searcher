// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::app::logging::ansi_tables_enabled;
use crate::common::constants::default_routers_for_chain;
use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::core::executor::BundleItem;
use crate::data::executor::UnifiedHardenedExecutor;
use crate::network::gas::GasFees;
use crate::network::mev_share::MevShareHint;
use crate::network::price_feed::PriceQuote;
use crate::services::strategy::bundles::BundlePlan;
use crate::services::strategy::decode::{
    ObservedSwap, RouterKind, SwapDirection, decode_swap, decode_swap_input, direction,
    extract_swap_deadline, target_token,
};
use crate::services::strategy::planning::bundles::NonceLease;
use crate::services::strategy::planning::{
    ApproveTx, BackrunTx, ExecutionPlanner, FrontRunTx, PlanType, PlannerInput,
};
use crate::services::strategy::strategy::{
    AllowlistCategory, ReceiptStatus, SkipReason, StrategyExecutor, StrategyWork,
};
use crate::services::strategy::strategy::{BundleTelemetry, PerBlockInputs};
use alloy::consensus::Transaction as ConsensusTx;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TransactionResponse;
use alloy::primitives::TxKind;
use alloy::primitives::{Address, B256, I256, U256, keccak256};
use alloy::rpc::types::eth::state::StateOverridesBuilder;
use alloy::rpc::types::eth::{Transaction, TransactionInput, TransactionRequest};
use alloy_sol_types::SolCall;

impl StrategyExecutor {
    fn deadline_min_seconds_ahead(&self) -> u64 {
        self.runtime.deadline_min_seconds_ahead
    }

    fn deadline_allow_past_secs(&self) -> u64 {
        self.runtime.deadline_allow_past_secs
    }

    fn deadline_guard_threshold(&self, now: u64) -> u64 {
        now.saturating_add(self.deadline_min_seconds_ahead())
            .saturating_sub(self.deadline_allow_past_secs())
    }

    fn simulation_failure_is_flashloan_insolvency_like(detail: &str) -> bool {
        let d = detail.to_ascii_lowercase();
        d.contains("insolvent")
            || d.contains("insufficientfundsforrepayment")
            || d.contains("transfer_from_failed")
            || d.contains("standard revert: stf")
            || d.contains("stf")
    }

    fn record_sim_latency_ms(&self, source: &'static str, started_at: std::time::Instant) {
        let sim_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.stats.record_sim_latency(source, sim_ms);
    }

    fn selector(input: &[u8]) -> Option<[u8; 4]> {
        input
            .get(..4)
            .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
    }

    fn sig_selector(signature: &str) -> [u8; 4] {
        let h = keccak256(signature.as_bytes());
        [h[0], h[1], h[2], h[3]]
    }

    fn liquidation_selectors() -> &'static [[u8; 4]] {
        static SELECTORS: std::sync::OnceLock<Vec<[u8; 4]>> = std::sync::OnceLock::new();
        SELECTORS.get_or_init(|| {
            vec![
                Self::sig_selector("liquidationCall(address,address,address,uint256,bool)"),
                Self::sig_selector("liquidateBorrow(address,uint256,address)"),
                Self::sig_selector("liquidateBorrow(address,address,uint256,bool)"),
                Self::sig_selector("absorb(address,address[])"),
                Self::sig_selector("absorb(address,address)"),
            ]
        })
    }

    fn is_liquidation_signal_tx(&self, tx: &Transaction, to_addr: Address) -> bool {
        if self.aave_pool.map(|pool| pool == to_addr).unwrap_or(false) {
            return true;
        }
        let Some(selector) = Self::selector(tx.input()) else {
            return false;
        };
        Self::liquidation_selectors().contains(&selector)
    }

    fn should_run_signal_scan(&self, liquidation: bool, now_unix: u64) -> bool {
        let cooldown = if liquidation {
            self.runtime.liquidation_scan_cooldown_secs
        } else {
            self.runtime.atomic_arb_scan_cooldown_secs
        };
        let counter = if liquidation {
            &self.last_liquidation_scan_unix
        } else {
            &self.last_atomic_arb_scan_unix
        };
        let last = counter.load(std::sync::atomic::Ordering::Relaxed);
        if now_unix < last.saturating_add(cooldown) {
            return false;
        }
        counter
            .compare_exchange(
                last,
                now_unix,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    }

    async fn try_signal_driven_arb(
        &self,
        tx: &Transaction,
        to_addr: Address,
        received_at: std::time::Instant,
        reason: &str,
    ) -> Result<Option<String>, AppError> {
        if !self.runtime.strategy_atomic_arb_enabled {
            return Ok(None);
        }
        let liquidation_signal =
            self.runtime.strategy_liquidation_enabled && self.is_liquidation_signal_tx(tx, to_addr);
        let now_unix = crate::services::strategy::time_utils::current_unix();
        if !self.should_run_signal_scan(liquidation_signal, now_unix) {
            return Ok(None);
        }
        let Some(router) = self.exec_router_v2 else {
            return Ok(None);
        };

        let gas_hint = self.runtime.atomic_arb_gas_hint;
        let max_candidates = self.runtime.atomic_arb_max_candidates;
        let max_attempts = self.runtime.atomic_arb_max_attempts;
        let seed_floor = self.runtime.atomic_arb_seed_wei;

        let mut candidates = self
            .reserve_cache
            .top_v2_tokens_by_connectivity(max_candidates)
            .into_iter()
            .filter(|token| *token != self.wrapped_native)
            .collect::<Vec<_>>();

        if liquidation_signal {
            candidates.sort_by_key(|token| {
                self.token_manager
                    .info(self.chain_id, *token)
                    .map(|info| {
                        let symbol = info.symbol.to_ascii_uppercase();
                        if symbol.contains("USDC")
                            || symbol.contains("USDT")
                            || symbol.contains("DAI")
                            || symbol.contains("WBTC")
                            || symbol.contains("CBBTC")
                        {
                            0usize
                        } else {
                            1usize
                        }
                    })
                    .unwrap_or(2usize)
            });
        }

        if candidates.is_empty() {
            return Ok(None);
        }

        for token in candidates.into_iter().take(max_attempts) {
            let observed = ObservedSwap {
                router,
                path: vec![self.wrapped_native, token],
                v3_fees: Vec::new(),
                v3_path: None,
                amount_in: seed_floor.max(U256::from(1u64)),
                min_out: U256::from(1u64),
                recipient: self.signer.address(),
                router_kind: RouterKind::V2Like,
            };
            let Some(parts) = self
                .build_components(
                    &observed,
                    SwapDirection::Other,
                    token,
                    gas_hint,
                    U256::ZERO,
                    (None, None),
                )
                .await?
            else {
                continue;
            };

            let needed_nonces = 1u64 + parts.approvals.len() as u64;
            let lease = self.lease_nonces(needed_nonces).await?;
            let mut approvals = parts.approvals;
            let backrun = parts.backrun;
            let mut main_request = parts
                .executor_request
                .clone()
                .unwrap_or_else(|| backrun.request.clone());
            Self::apply_nonce_plan(
                &lease,
                &mut None,
                approvals.as_mut_slice(),
                &mut main_request,
            )?;

            let mut bundle_requests = Vec::new();
            for approval in &approvals {
                bundle_requests.push(approval.request.clone());
            }
            bundle_requests.push(main_request.clone());

            let overrides = StateOverridesBuilder::default()
                .with_balance(self.signer.address(), parts.sim_balance)
                .with_nonce(self.signer.address(), lease.base);
            let Some(profit) = self
                .simulate_and_score(
                    bundle_requests,
                    overrides,
                    &backrun,
                    parts.attack_value_eth,
                    parts.bribe_wei,
                    parts.wallet_balance,
                    gas_hint,
                    &parts.gas_fees,
                    observed.router,
                )
                .await?
            else {
                continue;
            };

            let plan = BundlePlan {
                front_run: None,
                approvals: approvals.iter().map(|a| a.request.clone()).collect(),
                main: main_request.clone(),
                victims: Vec::new(),
            };
            let touched_pools = self.reserve_cache.pairs_for_v2_path(&observed.path);
            let Some(plan_hashes) = self
                .merge_and_send_bundle(plan, touched_pools, lease)
                .await?
            else {
                continue;
            };
            let submitted_hash = plan_hashes.main;

            let strategy_label = if liquidation_signal {
                "strategy_liquidation"
            } else {
                "strategy_atomic_arb"
            };
            self.db
                .save_transaction(
                    &format!("{submitted_hash:#x}"),
                    self.chain_id,
                    &format!("{:#x}", self.signer.address()),
                    main_request
                        .to
                        .as_ref()
                        .and_then(|k| match k {
                            TxKind::Call(addr) => Some(format!("{addr:#x}")),
                            _ => None,
                        })
                        .as_deref(),
                    main_request
                        .value
                        .unwrap_or(U256::ZERO)
                        .to_string()
                        .as_str(),
                    Some(strategy_label),
                )
                .await?;
            self.db
                .save_profit_record(
                    &format!("{submitted_hash:#x}"),
                    self.chain_id,
                    strategy_label,
                    profit.profit_eth_f64,
                    profit.gas_cost_eth_f64,
                    profit.net_profit_eth_f64,
                    &profit.gross_profit_wei.to_string(),
                    &profit.gas_cost_wei.to_string(),
                    &profit.net_profit_wei.to_string(),
                    &profit.bribe_wei.to_string(),
                    &profit.flashloan_premium_wei.to_string(),
                    &profit.effective_cost_wei.to_string(),
                )
                .await?;
            self.stats.record_bundle(BundleTelemetry {
                tx_hash: format!("{submitted_hash:#x}"),
                source: if liquidation_signal {
                    "liquidation"
                } else {
                    "atomic_arb"
                }
                .to_string(),
                profit_eth: profit.profit_eth_f64,
                gas_cost_eth: profit.gas_cost_eth_f64,
                net_eth: profit.net_profit_eth_f64,
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
            });
            tracing::info!(
                target: "strategy",
                strategy = if liquidation_signal { "liquidation" } else { "atomic_arb" },
                trigger = reason,
                tx_hash = %format!("{submitted_hash:#x}"),
                token = %format!("{token:#x}"),
                net_profit_eth = profit.net_profit_eth_f64,
                elapsed_ms = received_at.elapsed().as_millis() as u64,
                "Signal-driven strategy submitted"
            );
            return Ok(Some(format!("{submitted_hash:#x}")));
        }

        Ok(None)
    }

    fn simulation_failure_is_router_attributable(
        detail: &str,
        failed_to: Option<Address>,
        router: Address,
    ) -> bool {
        let lower = detail.to_ascii_lowercase();
        // Exclude systemic / infra failures that are not router quality signals.
        const NON_ROUTER_MARKERS: &[&str] = &[
            "victim_deadline_passed",
            "nonce too low",
            "nonce too high",
            "already known",
            "insufficient funds",
            "underpriced",
            "max fee per gas less than block base fee",
            "intrinsic gas too low",
            "timeout",
            "connection failed",
            "header not found",
            "aavecallbacknotreceived",
            "balancercallbacknotreceived",
            "insufficientfundsforrepayment",
            "approvalfailed",
            "bribefailed",
            "tokentransferfailed",
            "lengthmismatch",
        ];
        if NON_ROUTER_MARKERS.iter().any(|m| lower.contains(m)) {
            return false;
        }

        let target_is_router = failed_to.map(|addr| addr == router).unwrap_or(false);
        if target_is_router {
            return true;
        }
        // If we know the failure target and it is not the router, do not count this
        // against router quality. Heuristics are only for unknown failure targets.
        if failed_to.is_some() {
            return false;
        }
        let looks_router_revert = [
            "revert",
            "execution reverted",
            "insufficient output amount",
            "too little received",
            "uniswapv2",
            "uniswapv3",
            "panic code",
            "transfer_failed",
            "transfer failed",
        ]
        .iter()
        .any(|m| lower.contains(m));

        target_is_router || looks_router_revert
    }

    fn required_wallet_upfront_wei(
        uses_flashloan: bool,
        principal_wei: U256,
        bribe_wei: U256,
        gas_cost_wei: U256,
    ) -> U256 {
        let value_and_bribe = if uses_flashloan {
            bribe_wei
        } else {
            principal_wei.saturating_add(bribe_wei)
        };
        value_and_bribe.saturating_add(gas_cost_wei)
    }

    fn tx_max_upfront_wei(
        req: &TransactionRequest,
        fallback_max_fee_per_gas: u128,
        fallback_gas_limit: u64,
    ) -> U256 {
        let gas_limit = req.gas.unwrap_or(fallback_gas_limit.max(120_000));
        let max_fee_per_gas = req.max_fee_per_gas.unwrap_or(fallback_max_fee_per_gas);
        let value = req.value.unwrap_or(U256::ZERO);
        U256::from(gas_limit)
            .saturating_mul(U256::from(max_fee_per_gas))
            .saturating_add(value)
    }

    fn signer_bundle_max_upfront_wei(
        bundle_requests: &[TransactionRequest],
        signer: Address,
        fallback_max_fee_per_gas: u128,
        fallback_gas_limit: u64,
    ) -> U256 {
        bundle_requests
            .iter()
            .filter(|req| req.from == Some(signer))
            .fold(U256::ZERO, |acc, req| {
                acc.saturating_add(Self::tx_max_upfront_wei(
                    req,
                    fallback_max_fee_per_gas,
                    fallback_gas_limit,
                ))
            })
    }

    fn adaptive_min_bundle_gas_estimate(
        &self,
        observed_swap: &ObservedSwap,
        gas_limit_hint: u64,
        allow_front_run: bool,
        has_wrapped: bool,
    ) -> u64 {
        // Start from both external hint and local rolling probe stats.
        let mut estimate = gas_limit_hint.max(self.probe_gas_limit(observed_swap.router));
        let router_floor = match observed_swap.router_kind {
            RouterKind::V2Like => 130_000u64,
            RouterKind::V3Like => 150_000u64,
        };
        estimate = estimate.max(router_floor);
        if allow_front_run {
            estimate = estimate.saturating_add(60_000);
        }
        if has_wrapped && self.flashloan_enabled && self.has_usable_flashloan_provider() {
            estimate = estimate.saturating_add(45_000);
        }
        let with_headroom = estimate
            .saturating_mul(105)
            .checked_div(100)
            .unwrap_or(estimate);
        with_headroom.clamp(120_000, 500_000)
    }

    fn adaptive_min_bundle_gas_from_plan(
        &self,
        baseline_gas: u64,
        gas_limit_hint: u64,
        approvals: &[ApproveTx],
        front_run: &Option<FrontRunTx>,
        backrun: &BackrunTx,
        executor_request: &Option<TransactionRequest>,
    ) -> u64 {
        let mut planned = 0u64;

        for approval in approvals {
            let gas = approval.request.gas.unwrap_or(70_000).clamp(40_000, 90_000);
            planned = planned.saturating_add(gas);
        }

        if let Some(front) = front_run.as_ref() {
            let gas = front
                .request
                .gas
                .unwrap_or(gas_limit_hint)
                .clamp(70_000, 280_000);
            planned = planned.saturating_add(gas);
        }

        let main_req = executor_request.as_ref().unwrap_or(&backrun.request);
        let main_default = gas_limit_hint.max(self.probe_gas_limit(backrun.to));
        let main_gas = main_req.gas.unwrap_or(main_default).clamp(100_000, 500_000);
        planned = planned.saturating_add(main_gas);

        if backrun.uses_flashloan
            // Flashloan requests produced by planner already include provider overhead
            // inside the request gas limit. Avoid double-counting that overhead here.
            && main_req.gas.is_none()
        {
            planned = planned.saturating_add(backrun.flashloan_overhead_gas.max(50_000));
        }

        let with_headroom = planned
            .saturating_mul(105)
            .checked_div(100)
            .unwrap_or(planned);
        with_headroom.max(baseline_gas).clamp(120_000, 650_000)
    }

    pub async fn process_work(self: std::sync::Arc<Self>, work: StrategyWork) {
        if let Err(e) = self.handle_work(work).await {
            tracing::error!(target: "strategy", error=%e, "Strategy task failed");
        }
    }

    async fn handle_work(&self, work: StrategyWork) -> Result<(), AppError> {
        self.safety_guard.check()?;

        let outcome = match work {
            StrategyWork::Mempool { tx, received_at } => {
                let from = tx.from();
                let res = self.evaluate_mempool_tx(&tx, received_at).await;
                (res, Some(from), Some(tx.tx_hash()))
            }
            StrategyWork::MevShareHint { hint, received_at } => {
                let res = self.evaluate_mev_share_hint(&hint, received_at).await;
                (res, hint.from, Some(hint.tx_hash))
            }
        };

        match outcome {
            (Ok(Some(tx_hash)), from, _) => {
                tracing::info!(
                    target: "strategy",
                    from = ?from,
                    tx_hash = %tx_hash,
                    "Bundle submitted"
                );
                self.safety_guard.report_success();
                self.stats
                    .submitted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            (Ok(None), from, tx_hash) => {
                let skipped = self
                    .stats
                    .skipped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if skipped.is_multiple_of(self.skip_log_every) {
                    tracing::debug!(
                        target: "strategy",
                        from=?from,
                        tx_hash=?tx_hash,
                        skipped,
                        "Skipped item (sampled)"
                    );
                } else {
                    tracing::trace!(
                        target: "strategy",
                        from=?from,
                        tx_hash=?tx_hash,
                        "Skipped item"
                    );
                }
            }
            (Err(e), _, _) => {
                let nonce_gap = Self::is_nonce_gap_error(&e);
                if nonce_gap {
                    tracing::warn!(
                        target: "strategy",
                        error=%e,
                        "Nonce gap detected; suppressing safety guard trip"
                    );
                    self.safety_guard.report_success();
                } else {
                    self.safety_guard.report_failure();
                    self.stats
                        .failed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(target: "strategy", error=%e, "Strategy failed");
                }
            }
        };

        let processed = self
            .stats
            .processed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if processed.is_multiple_of(500) {
            tracing::info!(
            target: "strategy",
            processed,
            "Monitoring Mainnet..."
            );
        }

        if processed.is_multiple_of(5000) {
            let submitted = self
                .stats
                .submitted
                .load(std::sync::atomic::Ordering::Relaxed);
            let skipped = self
                .stats
                .skipped
                .load(std::sync::atomic::Ordering::Relaxed);
            let failed = self.stats.failed.load(std::sync::atomic::Ordering::Relaxed);

            let skip_unknown_router = self
                .stats
                .skip_unknown_router
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_decode = self
                .stats
                .skip_decode_failed
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_missing_wrapped = self
                .stats
                .skip_missing_wrapped
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_non_wrapped_balance = self
                .stats
                .skip_non_wrapped_balance
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_gas_cap = self
                .stats
                .skip_gas_cap
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_sim_failed = self
                .stats
                .skip_sim_failed
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_profit_guard = self
                .stats
                .skip_profit_guard
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_unsupported_router = self
                .stats
                .skip_unsupported_router
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_token_call = self
                .stats
                .skip_token_call
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_toxic_token = self
                .stats
                .skip_toxic_token
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_insufficient_balance = self
                .stats
                .skip_insufficient_balance
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_router_revert_rate = self
                .stats
                .skip_router_revert_rate
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_liquidity_depth = self
                .stats
                .skip_liquidity_depth
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_sandwich_risk = self
                .stats
                .skip_sandwich_risk
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_front_run_build_failed = self
                .stats
                .skip_front_run_build_failed
                .load(std::sync::atomic::Ordering::Relaxed);
            let skip_backrun_build_failed = self
                .stats
                .skip_backrun_build_failed
                .load(std::sync::atomic::Ordering::Relaxed);

            let pct_of = |value: u64, total: u64| -> f64 {
                if total == 0 {
                    0.0
                } else {
                    (value as f64 * 100.0) / (total as f64)
                }
            };
            const ANSI_RESET: &str = "\x1b[0m";
            const ANSI_BOLD: &str = "\x1b[1m";
            const ANSI_DIM: &str = "\x1b[2m";
            const ANSI_RED: &str = "\x1b[31m";
            const ANSI_GREEN: &str = "\x1b[32m";
            const ANSI_YELLOW: &str = "\x1b[33m";
            const ANSI_CYAN: &str = "\x1b[36m";
            let colorize = |text: String, color: &str, enabled: bool| -> String {
                if enabled {
                    format!("{color}{text}{ANSI_RESET}")
                } else {
                    text
                }
            };
            let visible_len = |text: &str| -> usize {
                let mut count = 0usize;
                let mut in_escape = false;
                let mut in_csi = false;
                for ch in text.chars() {
                    if in_escape {
                        if !in_csi {
                            if ch == '[' {
                                in_csi = true;
                            } else {
                                in_escape = false;
                            }
                            continue;
                        }
                        if ('@'..='~').contains(&ch) {
                            in_escape = false;
                            in_csi = false;
                        }
                        continue;
                    }
                    if ch == '\x1b' {
                        in_escape = true;
                        continue;
                    }
                    count += 1;
                }
                count
            };

            let mut skip_rows = vec![
                ("token_call", skip_token_call),
                ("unknown_router", skip_unknown_router),
                ("decode", skip_decode),
                ("missing_wrapped", skip_missing_wrapped),
                ("insufficient_balance", skip_insufficient_balance),
                ("backrun_build_failed", skip_backrun_build_failed),
                ("toxic_token", skip_toxic_token),
                ("sandwich_risk", skip_sandwich_risk),
                ("front_run_build_failed", skip_front_run_build_failed),
                ("sim_failed", skip_sim_failed),
                ("profit_guard", skip_profit_guard),
                ("router_revert_rate", skip_router_revert_rate),
                ("liquidity_depth", skip_liquidity_depth),
                ("gas_cap", skip_gas_cap),
                ("non_wrapped_balance", skip_non_wrapped_balance),
                ("unsupported_router", skip_unsupported_router),
            ];
            let categorized_skips = skip_rows.iter().map(|(_, value)| *value).sum::<u64>();
            let uncategorized_skips = skipped.saturating_sub(categorized_skips);
            if uncategorized_skips > 0 {
                skip_rows.push(("uncategorized_none", uncategorized_skips));
            }
            skip_rows.sort_by(|a, b| b.1.cmp(&a.1));

            let submit_rate = pct_of(submitted, processed);
            let skip_rate = pct_of(skipped, processed);
            let fail_rate = pct_of(failed, processed);

            let submit_rate_col = if submit_rate > 0.0 {
                ANSI_GREEN
            } else {
                ANSI_RED
            };
            let skip_rate_col = if skip_rate >= 95.0 {
                ANSI_RED
            } else if skip_rate >= 60.0 {
                ANSI_YELLOW
            } else {
                ANSI_GREEN
            };
            let fail_rate_col = if fail_rate >= 1.0 {
                ANSI_RED
            } else if fail_rate > 0.0 {
                ANSI_YELLOW
            } else {
                ANSI_GREEN
            };

            let top_skip_rows = skip_rows
                .iter()
                .take(6)
                .map(|(name, value)| {
                    let pct = pct_of(*value, skipped);
                    let plain = format!("{name}={value} ({pct:.2}%)");
                    let severity = if pct >= 25.0 {
                        ANSI_RED
                    } else if pct >= 5.0 {
                        ANSI_YELLOW
                    } else {
                        ANSI_DIM
                    };
                    (plain.clone(), colorize(plain, severity, true))
                })
                .collect::<Vec<_>>();

            let highlighted_count =
                |label: &str, value: u64, warn_if_nonzero: bool, color_enabled: bool| -> String {
                    let text = format!("{label}={value}");
                    if !warn_if_nonzero {
                        return colorize(text, ANSI_GREEN, color_enabled);
                    }
                    if value == 0 {
                        colorize(text, ANSI_GREEN, color_enabled)
                    } else if value < 10 {
                        colorize(text, ANSI_YELLOW, color_enabled)
                    } else {
                        colorize(text, ANSI_RED, color_enabled)
                    }
                };

            let build_lines = |color_enabled: bool| {
                let mut lines = vec![
                    colorize(
                        format!("{ANSI_BOLD}Strategy Summary @ {processed}"),
                        ANSI_CYAN,
                        color_enabled,
                    ),
                    format!(
                        "totals : {} {} {}",
                        highlighted_count("submitted", submitted, false, color_enabled),
                        highlighted_count("skipped", skipped, true, color_enabled),
                        highlighted_count("failed", failed, true, color_enabled)
                    ),
                    format!(
                        "rates  : submit={} skip={} fail={}",
                        colorize(format!("{submit_rate:.2}%"), submit_rate_col, color_enabled),
                        colorize(format!("{skip_rate:.2}%"), skip_rate_col, color_enabled),
                        colorize(format!("{fail_rate:.2}%"), fail_rate_col, color_enabled),
                    ),
                    "top skips (of skipped):".to_string(),
                ];
                for (idx, row) in top_skip_rows.iter().enumerate() {
                    let rendered = if color_enabled {
                        row.1.clone()
                    } else {
                        row.0.clone()
                    };
                    lines.push(format!("  {}. {}", idx + 1, rendered));
                }
                lines.push(format!(
                    "build/sim/funding: {} {} {} {}",
                    highlighted_count(
                        "backrun_build_failed",
                        skip_backrun_build_failed,
                        true,
                        color_enabled
                    ),
                    highlighted_count(
                        "front_run_build_failed",
                        skip_front_run_build_failed,
                        true,
                        color_enabled
                    ),
                    highlighted_count("sim_failed", skip_sim_failed, true, color_enabled),
                    highlighted_count(
                        "insufficient_balance",
                        skip_insufficient_balance,
                        true,
                        color_enabled
                    ),
                ));
                lines
            };

            let build_framed = |lines: &[String], color_border: bool| {
                let width = lines
                    .iter()
                    .map(|line| visible_len(line))
                    .max()
                    .unwrap_or(0);
                let border_raw = format!("+{}+", "-".repeat(width + 2));
                let border = colorize(border_raw, ANSI_CYAN, color_border);
                let mut framed = String::new();
                framed.push_str(&border);
                for line in lines {
                    let line_len = visible_len(line);
                    let pad = width.saturating_sub(line_len);
                    framed.push('\n');
                    framed.push_str(&format!("| {}{} |", line, " ".repeat(pad)));
                }
                framed.push('\n');
                framed.push_str(&border);
                framed
            };

            let lines_plain = build_lines(false);
            let lines_color = build_lines(true);
            let framed_plain = build_framed(&lines_plain, false);
            let framed_color = build_framed(&lines_color, true);

            let ansi_enabled = ansi_tables_enabled();

            if ansi_enabled {
                tracing::info!(
                    target: "strategy_summary",
                    processed,
                    submitted,
                    skipped,
                    failed,
                    "Strategy loop summary"
                );
                eprintln!("{framed_color}");
            } else {
                tracing::info!(target: "strategy_summary", "\n{framed_plain}");
            }
        }

        Ok(())
    }

    fn validate_swap(
        &self,
        _router: Address,
        observed_swap: &ObservedSwap,
    ) -> Option<(SwapDirection, Address)> {
        let has_wrapped = observed_swap.path.contains(&self.wrapped_native);
        if observed_swap.amount_in.is_zero() || (!has_wrapped && !self.allow_non_wrapped_swaps) {
            self.log_skip(
                SkipReason::MissingWrappedOrZeroAmount,
                "path missing wrapped native or zero amount",
            );
            return None;
        }

        let direction = direction(observed_swap, self.wrapped_native);
        let target_token = match target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip(SkipReason::DecodeFailed, "no target token");
                return None;
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip(
                SkipReason::ToxicToken,
                &format!("token={:#x}", target_token),
            );
            return None;
        }
        if self.runtime.strategy_require_tokenlist
            && self
                .token_manager
                .info(self.chain_id, target_token)
                .is_none()
        {
            self.log_skip(
                SkipReason::DecodeFailed,
                &format!("token_not_in_tokenlist={:#x}", target_token),
            );
            return None;
        }
        Some((direction, target_token))
    }

    fn is_wrapper_call_selector(selector: &[u8; 4]) -> bool {
        // Common wrapper operations (WETH-like): deposit()/withdraw(uint256).
        matches!(
            selector,
            [0xd0, 0xe3, 0x0d, 0xb0] | [0x2e, 0x1a, 0x7d, 0x4d]
        )
    }

    fn is_infra_call_selector(selector: &[u8; 4]) -> bool {
        // Common multicall/aggregate selectors used by infra contracts.
        matches!(
            selector,
            [0xac, 0x96, 0x50, 0xd8]
                | [0x5a, 0xe4, 0x01, 0xdc]
                | [0x82, 0xad, 0x56, 0xcb]
                | [0x25, 0x2d, 0xba, 0x42]
        )
    }

    fn handle_wrapper_or_infra_noise(
        &self,
        router: Address,
        input: &[u8],
        category: AllowlistCategory,
    ) -> bool {
        let selector = input
            .get(..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .unwrap_or([0u8; 4]);
        let decoded = match category {
            AllowlistCategory::Wrappers => Self::is_wrapper_call_selector(&selector),
            AllowlistCategory::Infra => Self::is_infra_call_selector(&selector),
            AllowlistCategory::Routers => false,
        };
        self.stats.record_decode_attempt(category, decoded);
        let category_label = category.metric_label();
        if decoded {
            self.log_skip(
                SkipReason::TokenCall,
                &format!(
                    "decoded_{category_label}_noise router={:#x} selector=0x{}",
                    router,
                    hex::encode(selector)
                ),
            );
        } else {
            self.log_skip(
                SkipReason::DecodeFailed,
                &format!(
                    "unsupported_{category_label}_call router={:#x} selector=0x{}",
                    router,
                    hex::encode(selector)
                ),
            );
        }
        decoded
    }

    async fn evaluate_mempool_tx(
        &self,
        tx: &Transaction,
        received_at: std::time::Instant,
    ) -> Result<Option<String>, AppError> {
        if let Some(deadline) = extract_swap_deadline(tx.input()) {
            let now = crate::services::strategy::time_utils::current_unix();
            let threshold = self.deadline_guard_threshold(now);
            if deadline <= threshold {
                self.log_skip(
                    SkipReason::SimulationFailed,
                    &format!(
                        "victim_deadline_passed deadline={deadline} now={now} threshold={threshold} min_ahead={} allow_past={}",
                        self.deadline_min_seconds_ahead(),
                        self.deadline_allow_past_secs()
                    ),
                );
                return Ok(None);
            }
        }
        let to_addr = match tx.kind() {
            TxKind::Call(addr) => addr,
            TxKind::Create => {
                self.log_skip(SkipReason::DecodeFailed, "tx_create_not_strategy_candidate");
                return Ok(None);
            }
        };
        if self.runtime.strategy_liquidation_enabled
            && self.is_liquidation_signal_tx(tx, to_addr)
            && let Some(submitted) = self
                .try_signal_driven_arb(tx, to_addr, received_at, "liquidation_signal")
                .await?
        {
            return Ok(Some(submitted));
        }
        let mut predecoded_unknown_router: Option<ObservedSwap> = None;
        let mut decode_recorded = false;
        let category = self.allowlist_category_for(to_addr);
        match category {
            Some(AllowlistCategory::Wrappers) => {
                let _ = self.handle_wrapper_or_infra_noise(
                    to_addr,
                    tx.input(),
                    AllowlistCategory::Wrappers,
                );
                return Ok(None);
            }
            Some(AllowlistCategory::Infra) => {
                let _ = self.handle_wrapper_or_infra_noise(
                    to_addr,
                    tx.input(),
                    AllowlistCategory::Infra,
                );
                return Ok(None);
            }
            Some(AllowlistCategory::Routers) => {}
            None => {
                if Self::is_common_token_call(tx.input()) {
                    // Plain ERC20 transfer/approve noise is not a strategy candidate.
                    self.log_skip(SkipReason::TokenCall, "erc20_transfer_or_approve_noise");
                    return Ok(None);
                }
                if self.allow_unknown_router_decode() {
                    let decoded = decode_swap(tx);
                    self.stats
                        .record_decode_attempt(AllowlistCategory::Routers, decoded.is_some());
                    decode_recorded = true;
                    if let Some(mut observed) = decoded
                        && let Some(exec_router) =
                            self.canonical_exec_router_for_kind(observed.router_kind)
                    {
                        if let Some(discovery) = &self.router_discovery {
                            discovery.record_unknown_router(to_addr, "mempool_decoded");
                        }
                        tracing::debug!(
                            target: "strategy",
                            unknown_router = %format!("{to_addr:#x}"),
                            exec_router = %format!("{exec_router:#x}"),
                            kind = ?observed.router_kind,
                            "Decoded unknown router swap; routing execution through canonical router"
                        );
                        observed.router = exec_router;
                        predecoded_unknown_router = Some(observed);
                    }
                }
                if predecoded_unknown_router.is_none() {
                    if let Some(discovery) = &self.router_discovery {
                        discovery.record_unknown_router(to_addr, "mempool");
                    }
                    self.log_skip(SkipReason::UnknownRouter, &format!("to={to_addr:#x}"));
                    if let Some(submitted) = self
                        .try_signal_driven_arb(tx, to_addr, received_at, "unknown_router")
                        .await?
                    {
                        return Ok(Some(submitted));
                    }
                    return Ok(None);
                }
            }
        }

        let observed_swap = if let Some(observed) = predecoded_unknown_router {
            Some(observed)
        } else {
            decode_swap(tx)
        };
        if !decode_recorded {
            self.stats
                .record_decode_attempt(AllowlistCategory::Routers, observed_swap.is_some());
        }
        let Some(observed_swap) = observed_swap else {
            self.log_skip(SkipReason::DecodeFailed, "unable to decode swap input");
            if let Some(submitted) = self
                .try_signal_driven_arb(tx, to_addr, received_at, "decode_failed")
                .await?
            {
                return Ok(Some(submitted));
            }
            return Ok(None);
        };
        let (direction, target_token) = match self.validate_swap(to_addr, &observed_swap) {
            Some(v) => v,
            None => return Ok(None),
        };

        let parts = match self
            .build_components(
                &observed_swap,
                direction,
                target_token,
                tx.gas_limit(),
                tx.value(),
                (None, None),
            )
            .await?
        {
            Some(p) => p,
            None => return Ok(None),
        };

        let needed_nonces = 1u64 + parts.front_run.is_some() as u64 + parts.approvals.len() as u64;
        let lease = self.lease_nonces(needed_nonces).await?;

        let mut front_run = parts.front_run;
        let mut approvals = parts.approvals;
        let mut backrun = parts.backrun;
        let mut executor_request = parts.executor_request;
        let mut main_request = executor_request
            .clone()
            .unwrap_or_else(|| backrun.request.clone());

        // If we're wrapping everything inside the executor, drop standalone approval txes to
        // avoid double approvals (they are already encoded in the executor payload).
        if executor_request.is_some() {
            approvals.clear();
        }

        Self::apply_nonce_plan(
            &lease,
            &mut front_run,
            approvals.as_mut_slice(),
            &mut main_request,
        )?;
        if let Some(exec) = executor_request.as_mut() {
            exec.nonce = main_request.nonce;
        }
        backrun.request.nonce = main_request.nonce;

        let victim_request = tx.clone().into_request();

        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        for a in &approvals {
            bundle_requests.push(a.request.clone());
        }
        if let Some(f) = &front_run {
            bundle_requests.push(f.request.clone());
        }
        bundle_requests.push(victim_request.clone());
        bundle_requests.push(main_request.clone());

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), parts.sim_balance)
            .with_nonce(self.signer.address(), lease.base);

        let sim_start = received_at;
        let profit = match self
            .simulate_and_score(
                bundle_requests,
                overrides,
                &backrun,
                parts.attack_value_eth,
                parts.bribe_wei,
                parts.wallet_balance,
                tx.gas_limit(),
                &parts.gas_fees,
                observed_swap.router,
            )
            .await?
        {
            Some(p) => p,
            None => {
                self.record_sim_latency_ms("mempool", sim_start);
                return Ok(None);
            }
        };
        self.record_sim_latency_ms("mempool", sim_start);

        tracing::info!(
            target: "strategy",
            gas_limit = profit.bundle_gas_limit,
            max_fee_per_gas = parts.gas_fees.max_fee_per_gas,
            gas_cost_wei = %profit.gas_cost_wei,
            bribe_wei = %profit.bribe_wei,
            flashloan_premium_wei = %profit.flashloan_premium_wei,
            effective_cost_wei = %profit.effective_cost_wei,
            net_profit_wei = %profit.net_profit_wei,
            net_profit_eth = profit.net_profit_eth_f64,
            wallet_eth = self.amount_to_display(parts.wallet_balance, self.wrapped_native),
            price_source = %profit.eth_quote.source,
            price = profit.eth_quote.price,
            victim_min_out = ?observed_swap.min_out,
            victim_recipient = ?observed_swap.recipient,
            path_len = observed_swap.path.len(),
            path = ?observed_swap.path,
            router = ?observed_swap.router,
            used_mock_balance = self.dry_run,
            sandwich = front_run.is_some(),
            "Strategy evaluation"
        );

        let tx_hash = tx.tx_hash();

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %format!("{:#x}", tx_hash),
                net_profit_eth = profit.net_profit_eth_f64,
                gross_profit_eth = profit.profit_eth_f64,
                gas_cost_eth = profit.gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(parts.attack_value_eth, self.wrapped_native),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable bundle (not sent)"
            );
            return Ok(Some(format!("{tx_hash:#x}")));
        }

        let plan = BundlePlan {
            front_run: front_run.as_ref().map(|f| f.request.clone()),
            approvals: approvals.iter().map(|a| a.request.clone()).collect(),
            main: main_request.clone(),
            victims: vec![tx.inner.encoded_2718()],
        };
        let mut touched_pools = self.reserve_cache.pairs_for_v2_path(&observed_swap.path);
        if observed_swap.router_kind == crate::services::strategy::decode::RouterKind::V3Like
            && let Some(v3_id) =
                StrategyExecutor::v3_pool_identifier(&observed_swap.path, &observed_swap.v3_fees)
        {
            touched_pools.push(v3_id);
        }
        let plan_hashes = match self.merge_and_send_bundle(plan, touched_pools, lease).await {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let to_addr = match tx.kind() {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };

        self.db
            .save_transaction(
                &format!("{tx_hash:#x}"),
                self.chain_id,
                &format!("{:#x}", tx.from()),
                to_addr.as_ref().map(|a| format!("{:#x}", a)).as_deref(),
                tx.value().to_string().as_str(),
                Some("strategy_v1"),
            )
            .await?;
        let submitted_hash = plan_hashes.main;
        let recorded_to = main_request.to.or(Some(TxKind::Call(backrun.to)));
        let recorded_value = main_request.value.unwrap_or(backrun.value);
        self.db
            .save_transaction(
                &format!("{:#x}", submitted_hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                recorded_to
                    .as_ref()
                    .and_then(|k| match k {
                        TxKind::Call(a) => Some(format!("{:#x}", a)),
                        _ => None,
                    })
                    .as_deref(),
                recorded_value.to_string().as_str(),
                Some("strategy_backrun"),
            )
            .await?;
        if let Some(f) = &front_run {
            self.db
                .save_transaction(
                    &format!("{:#x}", plan_hashes.front_run.unwrap_or(f.hash)),
                    self.chain_id,
                    &format!("{:#x}", self.signer.address()),
                    Some(format!("{:#x}", f.to)).as_deref(),
                    f.value.to_string().as_str(),
                    Some("strategy_front_run"),
                )
                .await?;
        }

        self.db
            .save_profit_record(
                &format!("{tx_hash:#x}"),
                self.chain_id,
                "strategy_v1",
                profit.profit_eth_f64,
                profit.gas_cost_eth_f64,
                profit.net_profit_eth_f64,
                &profit.gross_profit_wei.to_string(),
                &profit.gas_cost_wei.to_string(),
                &profit.net_profit_wei.to_string(),
                &profit.bribe_wei.to_string(),
                &profit.flashloan_premium_wei.to_string(),
                &profit.effective_cost_wei.to_string(),
            )
            .await?;

        self.portfolio.record_trade_components(
            self.chain_id,
            profit.gross_profit_wei,
            profit.gas_cost_wei,
            profit.bribe_wei,
            profit.flashloan_premium_wei,
            profit.net_profit_wei,
        );

        let price_symbol = format!(
            "{}USD",
            crate::common::constants::native_symbol_for_chain(self.chain_id)
        );
        let _ = self
            .db
            .save_market_price(
                self.chain_id,
                &price_symbol,
                profit.eth_quote.price,
                &profit.eth_quote.source,
            )
            .await;

        let receipt_target = submitted_hash;
        match self.await_receipt(&receipt_target).await? {
            ReceiptStatus::ConfirmedSuccess => {}
            ReceiptStatus::ConfirmedRevert => {
                self.emergency_exit_inventory("bundle receipt reverted")
                    .await;
            }
            ReceiptStatus::UnknownTimeout => {
                if self.emergency_exit_on_unknown_receipt {
                    self.emergency_exit_inventory("bundle receipt unknown timeout")
                        .await;
                } else {
                    tracing::warn!(
                        target: "strategy",
                        tx_hash = %format!("{:#x}", receipt_target),
                        "Receipt timeout without confirmed revert; emergency exit suppressed"
                    );
                }
            }
        }

        self.stats.record_bundle(BundleTelemetry {
            tx_hash: format!("{submitted_hash:#x}"),
            source: "mempool".to_string(),
            profit_eth: profit.profit_eth_f64,
            gas_cost_eth: profit.gas_cost_eth_f64,
            net_eth: profit.net_profit_eth_f64,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });

        Ok(Some(format!("{submitted_hash:#x}")))
    }

    async fn evaluate_mev_share_hint(
        &self,
        hint: &MevShareHint,
        received_at: std::time::Instant,
    ) -> Result<Option<String>, AppError> {
        if let Some(deadline) = extract_swap_deadline(&hint.call_data) {
            let now = crate::services::strategy::time_utils::current_unix();
            let threshold = self.deadline_guard_threshold(now);
            if deadline <= threshold {
                self.log_skip(
                    SkipReason::SimulationFailed,
                    &format!(
                        "hint_deadline_passed deadline={deadline} now={now} threshold={threshold} min_ahead={} allow_past={}",
                        self.deadline_min_seconds_ahead(),
                        self.deadline_allow_past_secs()
                    ),
                );
                return Ok(None);
            }
        }
        let mut predecoded_unknown_router: Option<ObservedSwap> = None;
        let mut decode_recorded = false;
        let category = self.allowlist_category_for(hint.router);
        match category {
            Some(AllowlistCategory::Wrappers) => {
                let _ = self.handle_wrapper_or_infra_noise(
                    hint.router,
                    &hint.call_data,
                    AllowlistCategory::Wrappers,
                );
                return Ok(None);
            }
            Some(AllowlistCategory::Infra) => {
                let _ = self.handle_wrapper_or_infra_noise(
                    hint.router,
                    &hint.call_data,
                    AllowlistCategory::Infra,
                );
                return Ok(None);
            }
            Some(AllowlistCategory::Routers) => {}
            None => {
                if self.allow_unknown_router_decode() {
                    let decoded = decode_swap_input(hint.router, &hint.call_data, hint.value);
                    self.stats
                        .record_decode_attempt(AllowlistCategory::Routers, decoded.is_some());
                    decode_recorded = true;
                    if let Some(mut observed) = decoded
                        && let Some(exec_router) =
                            self.canonical_exec_router_for_kind(observed.router_kind)
                    {
                        if let Some(discovery) = &self.router_discovery {
                            discovery.record_unknown_router(hint.router, "mev_share_decoded");
                        }
                        tracing::debug!(
                            target: "strategy",
                            unknown_router = %format!("{:#x}", hint.router),
                            exec_router = %format!("{exec_router:#x}"),
                            kind = ?observed.router_kind,
                            "Decoded unknown MEV-Share router; routing execution through canonical router"
                        );
                        observed.router = exec_router;
                        predecoded_unknown_router = Some(observed);
                    }
                }
                if predecoded_unknown_router.is_none() {
                    if let Some(discovery) = &self.router_discovery {
                        discovery.record_unknown_router(hint.router, "mev_share");
                    }
                    self.log_skip(SkipReason::UnknownRouter, &format!("to={:#x}", hint.router));
                    return Ok(None);
                }
            }
        }

        let observed_swap = if let Some(observed) = predecoded_unknown_router {
            Some(observed)
        } else {
            decode_swap_input(hint.router, &hint.call_data, hint.value)
        };
        if !decode_recorded {
            self.stats
                .record_decode_attempt(AllowlistCategory::Routers, observed_swap.is_some());
        }
        let Some(observed_swap) = observed_swap else {
            self.log_skip(SkipReason::DecodeFailed, "unable to decode swap input");
            return Ok(None);
        };
        let (direction, target_token) = match self.validate_swap(hint.router, &observed_swap) {
            Some(v) => v,
            None => return Ok(None),
        };
        let gas_limit_hint = hint.gas_limit.unwrap_or(220_000);

        let parts = match self
            .build_components(
                &observed_swap,
                direction,
                target_token,
                gas_limit_hint,
                hint.value,
                (hint.max_fee_per_gas, hint.max_priority_fee_per_gas),
            )
            .await?
        {
            Some(p) => p,
            None => return Ok(None),
        };

        if parts.front_run.is_some() {
            self.log_skip(
                SkipReason::UnsupportedRouter,
                "MEV-Share path requires single backrun tx (no frontrun)",
            );
            return Ok(None);
        }
        if parts.executor_request.is_none() && !parts.approvals.is_empty() {
            self.log_skip(
                SkipReason::UnsupportedRouter,
                "MEV-Share path requires executor-wrapped approvals",
            );
            return Ok(None);
        }

        let lease = self.lease_nonces(1).await?;

        let mut front_run = None;
        let mut approvals: Vec<ApproveTx> = Vec::new();
        let mut backrun = parts.backrun;
        let mut executor_request = parts.executor_request;
        let mut main_request = executor_request
            .clone()
            .unwrap_or_else(|| backrun.request.clone());

        Self::apply_nonce_plan(
            &lease,
            &mut front_run,
            approvals.as_mut_slice(),
            &mut main_request,
        )?;
        if let Some(exec) = executor_request.as_mut() {
            exec.nonce = main_request.nonce;
        }
        backrun.request.nonce = main_request.nonce;

        let max_fee_hint = hint
            .max_fee_per_gas
            .unwrap_or(parts.gas_fees.max_fee_per_gas);
        let max_prio_hint = hint
            .max_priority_fee_per_gas
            .unwrap_or(parts.gas_fees.max_priority_fee_per_gas);
        let victim_request = TransactionRequest {
            from: hint.from,
            to: Some(TxKind::Call(hint.router)),
            max_fee_per_gas: Some(max_fee_hint),
            max_priority_fee_per_gas: Some(max_prio_hint),
            gas: Some(gas_limit_hint),
            value: Some(hint.value),
            input: TransactionInput::new(hint.call_data.clone().into()),
            nonce: None,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        let bundle_requests: Vec<TransactionRequest> =
            vec![victim_request.clone(), main_request.clone()];

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), parts.sim_balance)
            .with_nonce(self.signer.address(), lease.base);

        let sim_start = received_at;
        let profit = match self
            .simulate_and_score(
                bundle_requests,
                overrides,
                &backrun,
                parts.attack_value_eth,
                parts.bribe_wei,
                parts.wallet_balance,
                gas_limit_hint,
                &parts.gas_fees,
                observed_swap.router,
            )
            .await?
        {
            Some(p) => p,
            None => {
                self.record_sim_latency_ms("mev_share", sim_start);
                return Ok(None);
            }
        };
        self.record_sim_latency_ms("mev_share", sim_start);

        tracing::info!(
            target: "strategy",
            gas_limit = profit.bundle_gas_limit,
            max_fee_per_gas = parts.gas_fees.max_fee_per_gas,
            gas_cost_wei = %profit.gas_cost_wei,
            bribe_wei = %profit.bribe_wei,
            flashloan_premium_wei = %profit.flashloan_premium_wei,
            effective_cost_wei = %profit.effective_cost_wei,
            net_profit_wei = %profit.net_profit_wei,
            net_profit_eth = profit.net_profit_eth_f64,
            wallet_eth = self.amount_to_display(parts.wallet_balance, self.wrapped_native),
            price_source = %profit.eth_quote.source,
            price = profit.eth_quote.price,
            victim_min_out = ?observed_swap.min_out,
            victim_recipient = ?observed_swap.recipient,
            path_len = observed_swap.path.len(),
            path = ?observed_swap.path,
            router = ?observed_swap.router,
            used_mock_balance = self.dry_run,
            profit_floor_wei = %StrategyExecutor::dynamic_profit_floor(parts.wallet_balance),
            sandwich = false,
            "MEV-Share strategy evaluation"
        );

        let victim_tx_hash = format!("{:#x}", hint.tx_hash);

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %victim_tx_hash,
                net_profit_eth = profit.net_profit_eth_f64,
                gross_profit_eth = profit.profit_eth_f64,
                gas_cost_eth = profit.gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(parts.attack_value_eth, self.wrapped_native),
                wallet_eth = self.amount_to_display(parts.wallet_balance, self.wrapped_native),
                path_len = observed_swap.path.len(),
                router = ?observed_swap.router,
                used_mock_balance = self.dry_run,
                profit_floor_wei = %StrategyExecutor::dynamic_profit_floor(parts.wallet_balance),
                sandwich = false,
                "Dry-run only: simulated profitable MEV-Share bundle (not sent)"
            );
            return Ok(Some(victim_tx_hash));
        }

        let mut bundle_body: Vec<BundleItem> = Vec::new();
        bundle_body.push(BundleItem::Hash {
            hash: victim_tx_hash.clone(),
        });

        let mut executor_hash: Option<B256> = None;

        if let Some(req) = executor_request.take() {
            let fallback = req.access_list.clone().unwrap_or_default();
            let (raw, _signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            executor_hash = Some(hash);
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        } else {
            let fallback = backrun.request.access_list.clone().unwrap_or_default();
            let req = backrun.request.clone();
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            backrun.raw = raw.clone();
            backrun.request = signed_req;
            backrun.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        }

        let _ = self
            .db
            .update_status(&victim_tx_hash, None, Some(false))
            .await;

        self.bundle_sender
            .send_mev_share_bundle(&bundle_body)
            .await?;

        let from_addr = hint.from.unwrap_or(Address::ZERO);
        self.db
            .save_transaction(
                &victim_tx_hash,
                self.chain_id,
                &format!("{:#x}", from_addr),
                Some(format!("{:#x}", hint.router)).as_deref(),
                hint.value.to_string().as_str(),
                Some("strategy_mev_share"),
            )
            .await?;

        let submitted_hash = executor_hash.unwrap_or(backrun.hash);
        self.db
            .save_transaction(
                &format!("{:#x}", submitted_hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                main_request
                    .to
                    .as_ref()
                    .and_then(|k| match k {
                        TxKind::Call(addr) => Some(format!("{:#x}", addr)),
                        _ => None,
                    })
                    .as_deref(),
                main_request
                    .value
                    .unwrap_or(backrun.value)
                    .to_string()
                    .as_str(),
                Some("strategy_backrun"),
            )
            .await?;

        self.db
            .save_profit_record(
                &victim_tx_hash,
                self.chain_id,
                "strategy_mev_share",
                profit.profit_eth_f64,
                profit.gas_cost_eth_f64,
                profit.net_profit_eth_f64,
                &profit.gross_profit_wei.to_string(),
                &profit.gas_cost_wei.to_string(),
                &profit.net_profit_wei.to_string(),
                &profit.bribe_wei.to_string(),
                &profit.flashloan_premium_wei.to_string(),
                &profit.effective_cost_wei.to_string(),
            )
            .await?;

        self.portfolio.record_trade_components(
            self.chain_id,
            profit.gross_profit_wei,
            profit.gas_cost_wei,
            profit.bribe_wei,
            profit.flashloan_premium_wei,
            profit.net_profit_wei,
        );

        let price_symbol = format!(
            "{}USD",
            crate::common::constants::native_symbol_for_chain(self.chain_id)
        );
        let _ = self
            .db
            .save_market_price(
                self.chain_id,
                &price_symbol,
                profit.eth_quote.price,
                &profit.eth_quote.source,
            )
            .await;

        let receipt_target = submitted_hash;
        match self.await_receipt(&receipt_target).await? {
            ReceiptStatus::ConfirmedSuccess => {}
            ReceiptStatus::ConfirmedRevert => {
                self.emergency_exit_inventory("mev_share receipt reverted")
                    .await;
            }
            ReceiptStatus::UnknownTimeout => {
                if self.emergency_exit_on_unknown_receipt {
                    self.emergency_exit_inventory("mev_share receipt unknown timeout")
                        .await;
                } else {
                    tracing::warn!(
                        target: "strategy",
                        tx_hash = %format!("{:#x}", receipt_target),
                        "MEV-Share receipt timeout without confirmed revert; emergency exit suppressed"
                    );
                }
            }
        }

        self.stats.record_bundle(BundleTelemetry {
            tx_hash: format!("{submitted_hash:#x}"),
            source: "mev_share".to_string(),
            profit_eth: profit.profit_eth_f64,
            gas_cost_eth: profit.gas_cost_eth_f64,
            net_eth: profit.net_profit_eth_f64,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });

        Ok(Some(format!("{submitted_hash:#x}")))
    }

    async fn build_components(
        &self,
        observed_swap: &ObservedSwap,
        direction: SwapDirection,
        target_token: Address,
        gas_limit_hint: u64,
        victim_value: U256,
        fee_hints: (Option<u128>, Option<u128>),
    ) -> Result<Option<BundleParts>, AppError> {
        let (mut gas_fees, real_balance) = self.per_block_inputs().await?;
        self.boost_fees(&mut gas_fees, fee_hints.0, fee_hints.1);
        let hard_cap = self.hard_gas_cap_wei();

        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom = U256::from(gas_limit_hint) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = victim_value.saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };

        if self.router_is_risky(observed_swap.router) {
            self.log_skip(SkipReason::RouterRevertRate, "router failure rate too high");
            if self.router_risk_hard_block() {
                return Ok(None);
            }
            let router_revert_skips = self
                .stats
                .skip_router_revert_rate
                .load(std::sync::atomic::Ordering::Relaxed);
            if self.dry_run || router_revert_skips.is_multiple_of(self.skip_log_every) {
                tracing::warn!(
                    target: "strategy",
                    router = %format!("{:#x}", observed_swap.router),
                    skips = router_revert_skips,
                    "Router marked risky, but continuing (ROUTER_RISK_HARD_BLOCK=false)"
                );
            }
        }
        if !self.liquidity_depth_ok(observed_swap, wallet_chain_balance) {
            self.log_skip(SkipReason::LiquidityDepth, "price impact too high");
            return Ok(None);
        }
        if observed_swap.router_kind == RouterKind::V2Like
            && let Some(expected_out) = self
                .reserve_cache
                .quote_v2_path(&observed_swap.path, observed_swap.amount_in)
            && !expected_out.is_zero()
            && !observed_swap.min_out.is_zero()
        {
            let min_ratio =
                observed_swap.min_out.saturating_mul(U256::from(10_000u64)) / expected_out;
            let slippage_room_bps = 10_000u64.saturating_sub(min_ratio.to::<u64>());
            if slippage_room_bps > self.sandwich_risk_max_victim_slippage_bps()
                && wallet_chain_balance < self.sandwich_risk_small_wallet_wei()
            {
                self.log_skip(
                    SkipReason::SandwichRisk,
                    "victim slippage too loose for small wallet",
                );
                return Ok(None);
            }
        }

        let dynamic_cap = self.dynamic_gas_cap(wallet_chain_balance, &gas_fees, hard_cap);
        let max_fee_before_cap = gas_fees.max_fee_per_gas;
        let max_tip_before_cap = gas_fees.max_priority_fee_per_gas;
        if StrategyExecutor::enforce_dynamic_gas_cap(&mut gas_fees, dynamic_cap.cap_wei) {
            self.log_skip(
                SkipReason::GasPriceCap,
                &format!(
                    "max_fee_per_gas={} cap_wei={} base_plus_tip={} base_dynamic={} adjusted_dynamic={} balance_factor_bps={} floor_wei={} hard_cap={} wallet_wei={}",
                    max_fee_before_cap,
                    dynamic_cap.cap_wei,
                    dynamic_cap.base_plus_tip_wei,
                    dynamic_cap.base_dynamic_wei,
                    dynamic_cap.adjusted_dynamic_wei,
                    dynamic_cap.balance_factor_bps,
                    dynamic_cap.floor_wei,
                    hard_cap,
                    wallet_chain_balance
                ),
            );
            return Ok(None);
        }
        if gas_fees.max_fee_per_gas != max_fee_before_cap {
            tracing::debug!(
                target: "strategy",
                max_fee_before = max_fee_before_cap,
                max_fee_after = gas_fees.max_fee_per_gas,
                max_tip_before = max_tip_before_cap,
                max_tip_after = gas_fees.max_priority_fee_per_gas,
                cap_wei = %dynamic_cap.cap_wei,
                floor_wei = dynamic_cap.floor_wei,
                "Clamped gas fees to dynamic cap"
            );
        }

        let has_wrapped = observed_swap.path.contains(&self.wrapped_native);
        if !has_wrapped && !self.allow_non_wrapped_swaps {
            self.log_skip(
                SkipReason::MissingWrappedOrZeroAmount,
                "strict atomic mode requires wrapped-native path",
            );
            return Ok(None);
        }
        let allow_front_run = self.sandwich_attacks_enabled
            && (direction == SwapDirection::BuyWithEth || !has_wrapped);
        let min_bundle_gas = self.adaptive_min_bundle_gas_estimate(
            observed_swap,
            gas_limit_hint,
            allow_front_run,
            has_wrapped,
        );
        let min_bundle_gas_cost =
            U256::from(min_bundle_gas).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
        if wallet_chain_balance < min_bundle_gas_cost {
            self.log_skip(
                SkipReason::InsufficientBalance,
                &format!(
                    "wallet={} below adaptive_min_bundle_gas_cost={} (gas={} max_fee={} phase=baseline)",
                    wallet_chain_balance,
                    min_bundle_gas_cost,
                    min_bundle_gas,
                    gas_fees.max_fee_per_gas
                ),
            );
            return Ok(None);
        }

        let planner = ExecutionPlanner::default();
        let planner_input = PlannerInput {
            wallet_balance: wallet_chain_balance,
            victim_value,
            gas_cost_estimate: min_bundle_gas_cost,
            has_wrapped_path: has_wrapped,
            flashloan_available: self.has_usable_flashloan_provider(),
            allow_hybrid: true,
            base_trade_hint: observed_swap.amount_in.max(victim_value),
            min_size: U256::from(1_000_000_000_000u64),
            max_size: wallet_chain_balance
                .saturating_add(victim_value)
                .saturating_add(observed_swap.amount_in)
                .max(U256::from(1_000_000_000_000u64)),
            slippage_bps: self.effective_slippage_bps(),
            safety_margin_bps: self
                .adaptive_base_floor_bps(&gas_fees)
                .saturating_sub(10_000),
            uncertainty_bps: self
                .adaptive_cost_floor_bps(&gas_fees)
                .saturating_sub(10_000),
        };
        let planner_decision = planner.plan(&planner_input);
        let planner_trace = if let Some(best) = planner_decision.best_plan.as_ref() {
            format!(
                "plan={} size={} expected_net={} inclusion_bps={} floor={} candidates={}",
                best.plan_type.as_str(),
                best.size_wei,
                best.score.expected_net_wei,
                best.score.inclusion_probability_bps,
                best.score.dynamic_profit_floor_wei,
                planner_decision.candidates.len()
            )
        } else {
            format!(
                "plan=rejected reason={} candidates={}",
                planner_decision
                    .rejection_reason
                    .as_deref()
                    .unwrap_or("no_candidate"),
                planner_decision.candidates.len()
            )
        };
        self.stats.record_decision_trace(planner_trace.clone());
        tracing::debug!(target: "planner", trace = %planner_trace, "Execution planner decision");

        let Some(best_plan) = planner_decision.best_plan.as_ref() else {
            let reason = planner_decision
                .rejection_reason
                .as_deref()
                .unwrap_or("net_negative_after_buffers");
            self.stats.record_opportunity_rejection(reason);
            self.log_skip(
                SkipReason::ProfitOrGasGuard,
                &format!("planner_rejected reason={reason}"),
            );
            return Ok(None);
        };
        let planned_plan_type = best_plan.plan_type;
        let planned_trade_size = best_plan.size_wei.max(U256::from(1u64));
        let allow_front_run = allow_front_run && planned_plan_type == PlanType::OwnCapital;

        let mut attack_value_eth = U256::ZERO;
        let mut front_run: Option<FrontRunTx> = None;
        if allow_front_run {
            match self
                .build_front_run_tx(
                    observed_swap,
                    &gas_fees,
                    planned_trade_size.min(wallet_chain_balance),
                    gas_limit_hint,
                    0,
                )
                .await
            {
                Ok(Some(f)) => {
                    attack_value_eth = f.value;
                    front_run = Some(f);
                }
                Ok(None) => {}
                Err(e) => {
                    self.log_skip(SkipReason::FrontRunBuildFailed, &e.to_string());
                    // Keep candidate alive as backrun-only when sandwich leg cannot be built.
                    front_run = None;
                }
            }
        }

        let mut approvals: Vec<ApproveTx> = Vec::new();
        if let Some(f) = &front_run {
            let exec_router = self.execution_router(observed_swap);
            if (f.input_token != self.wrapped_native || f.value.is_zero())
                && self
                    .needs_approval(f.input_token, exec_router, f.input_amount)
                    .await?
            {
                approvals.push(
                    self.build_approval_tx(
                        f.input_token,
                        exec_router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        0,
                    )
                    .await?,
                );
            }
            if self
                .needs_approval(target_token, exec_router, f.expected_tokens)
                .await?
            {
                approvals.push(
                    self.build_approval_tx(
                        target_token,
                        exec_router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        0,
                    )
                    .await?,
                );
            }
        }

        if front_run.is_some() && planned_plan_type != PlanType::OwnCapital {
            front_run = None;
            approvals.clear();
            attack_value_eth = U256::ZERO;
        }
        let use_flashloan = has_wrapped
            && matches!(planned_plan_type, PlanType::Flashloan | PlanType::Hybrid)
            && front_run.is_none();
        let trade_balance = if use_flashloan {
            let flashloan_floor = U256::from(5_000_000_000_000_000u128); // 0.005 ETH
            planned_trade_size
                .max(wallet_chain_balance.saturating_add(victim_value))
                .max(flashloan_floor)
        } else {
            planned_trade_size.min(wallet_chain_balance.max(U256::from(1u64)))
        };

        let backrun = match self
            .build_backrun_tx(
                observed_swap,
                &gas_fees,
                trade_balance,
                gas_limit_hint,
                front_run.as_ref().map(|f| f.expected_tokens),
                use_flashloan,
                0,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                let err_msg = e.to_string();
                let flashloan_insolvent_like = use_flashloan
                    && (err_msg.contains("Flashloan quoted roundtrip insolvent")
                        || err_msg.contains("Flashloan quoted V3 roundtrip insolvent")
                        || err_msg.contains("Flashloan prefilter failed")
                        || err_msg.contains("Flashloan V3 prefilter failed")
                        || err_msg.contains("Flashloan same-router roundtrip non-positive")
                        || err_msg.contains("Flashloan same-router V3 roundtrip non-positive"));
                if flashloan_insolvent_like {
                    let flashloan_asset = observed_swap
                        .path
                        .first()
                        .copied()
                        .unwrap_or(self.wrapped_native);
                    self.record_flashloan_insolvency(flashloan_asset, &err_msg);
                }

                let recovered_flashloan_scaled: Option<BackrunTx> = 'adaptive_retry: {
                    if !flashloan_insolvent_like {
                        break 'adaptive_retry None;
                    }
                    // Borderline insolvency often clears at lower notional; retry with
                    // progressively smaller effective sizing before hard-skipping.
                    let retry_scales_bps = [8_000u64, 6_000, 4_500, 3_000, 2_000, 1_500, 1_000];
                    for scale_bps in retry_scales_bps {
                        let retry_trade_balance = trade_balance
                            .saturating_mul(U256::from(scale_bps))
                            .checked_div(U256::from(10_000u64))
                            .unwrap_or(trade_balance);
                        if retry_trade_balance.is_zero() || retry_trade_balance >= trade_balance {
                            continue;
                        }
                        match self
                            .build_backrun_tx(
                                observed_swap,
                                &gas_fees,
                                retry_trade_balance,
                                gas_limit_hint,
                                front_run.as_ref().map(|f| f.expected_tokens),
                                true,
                                0,
                            )
                            .await
                        {
                            Ok(backrun) => {
                                tracing::debug!(
                                    target: "strategy",
                                    initial_error = %err_msg,
                                    original_trade_balance = %trade_balance,
                                    retry_trade_balance = %retry_trade_balance,
                                    scale_bps,
                                    "Recovered flashloan backrun via adaptive notional downshift"
                                );
                                break 'adaptive_retry Some(backrun);
                            }
                            Err(inner) => {
                                tracing::debug!(
                                    target: "strategy",
                                    scale_bps,
                                    retry_trade_balance = %retry_trade_balance,
                                    retry_error = %inner,
                                    "Adaptive flashloan downshift retry failed"
                                );
                            }
                        }
                    }
                    None
                };

                if let Some(backrun) = recovered_flashloan_scaled {
                    backrun
                } else {
                    let mut recovered_non_flash: Option<BackrunTx> = None;
                    let allow_non_flash_fallback = self.runtime.flashloan_allow_nonflash_fallback;
                    if use_flashloan && allow_non_flash_fallback {
                        match self
                            .build_backrun_tx(
                                observed_swap,
                                &gas_fees,
                                wallet_chain_balance,
                                gas_limit_hint,
                                front_run.as_ref().map(|f| f.expected_tokens),
                                false,
                                0,
                            )
                            .await
                        {
                            Ok(backrun) => {
                                tracing::debug!(
                                    target: "strategy",
                                    flashloan_error = %err_msg,
                                    "Recovered candidate via non-flashloan fallback after flashloan build failure"
                                );
                                recovered_non_flash = Some(backrun);
                            }
                            Err(non_flash_err) => {
                                tracing::debug!(
                                    target: "strategy",
                                    flashloan_error = %err_msg,
                                    non_flash_error = %non_flash_err,
                                    "Flashloan-first build failed and non-flashloan fallback also failed"
                                );
                            }
                        }
                    } else if use_flashloan {
                        tracing::debug!(
                            target: "strategy",
                            flashloan_error = %err_msg,
                            "Flashloan build failed and non-flashloan fallback is disabled"
                        );
                    }

                    if let Some(backrun) = recovered_non_flash {
                        backrun
                    } else {
                        let is_v3_fallback_eligible = observed_swap.router_kind
                            == RouterKind::V3Like
                            && (err_msg.contains("V3 liquidity too low")
                                || err_msg
                                    .contains("Flashloan same-router V3 roundtrip non-positive")
                                || err_msg.contains("Flashloan quoted V3 roundtrip insolvent"));
                        if !is_v3_fallback_eligible {
                            self.log_skip(SkipReason::BackrunBuildFailed, &err_msg);
                            return Ok(None);
                        }

                        let routers = default_routers_for_chain(self.chain_id);
                        let mut alt_v2_candidates: Vec<(u8, String, Address)> = routers
                            .iter()
                            .filter_map(|(name, addr)| {
                                let n = name.to_ascii_lowercase();
                                let is_non_v2_surface = n.contains("universal")
                                    || n.contains("aggregation")
                                    || n.contains("aggregator")
                                    || n.contains("proxy")
                                    || n.contains("permit")
                                    || n.contains("quoter")
                                    || n.contains("vault")
                                    || n.contains("relay");
                                if is_non_v2_surface {
                                    return None;
                                }
                                let priority = match n.as_str() {
                                    "uniswap_v2_router02" | "uniswap_v2_router" => Some(0),
                                    "sushiswap_router" => Some(1),
                                    "pancakeswap_v2_router" => Some(2),
                                    _ => {
                                        let generic_v2 = (n.contains("v2_router")
                                            || n.contains("router_v2"))
                                            && !n.contains("universal");
                                        if generic_v2 { Some(10) } else { None }
                                    }
                                }?;
                                Some((priority, n, *addr))
                            })
                            .collect();
                        alt_v2_candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                        let mut alt_v2_routers: Vec<Address> = Vec::new();
                        for (_, _, addr) in alt_v2_candidates {
                            if !alt_v2_routers.contains(&addr) {
                                alt_v2_routers.push(addr);
                            }
                        }
                        if alt_v2_routers.is_empty() {
                            self.log_skip(SkipReason::BackrunBuildFailed, &err_msg);
                            return Ok(None);
                        }

                        let mut fallback_errors: Vec<String> = Vec::new();
                        let recovered_backrun = 'fallback: {
                            for alt_router in alt_v2_routers {
                                let mut alt_observed = observed_swap.clone();
                                alt_observed.router_kind = RouterKind::V2Like;
                                alt_observed.router = alt_router;
                                alt_observed.v3_fees.clear();
                                alt_observed.v3_path = None;
                                let token_in = observed_swap
                                    .path
                                    .first()
                                    .copied()
                                    .unwrap_or(self.wrapped_native);
                                let token_out =
                                    observed_swap.path.last().copied().unwrap_or(target_token);
                                alt_observed.path = vec![token_in, token_out];

                                match self
                                    .build_backrun_tx(
                                        &alt_observed,
                                        &gas_fees,
                                        trade_balance,
                                        gas_limit_hint,
                                        front_run.as_ref().map(|f| f.expected_tokens),
                                        use_flashloan,
                                        0,
                                    )
                                    .await
                                {
                                    Ok(backrun) => break 'fallback Some((alt_router, backrun)),
                                    Err(inner) => {
                                        fallback_errors
                                            .push(format!("router={:#x}: {}", alt_router, inner));
                                    }
                                }
                            }
                            None
                        };

                        if let Some((alt_router, backrun)) = recovered_backrun {
                            tracing::debug!(
                                target: "strategy",
                                fallback_router = %format!("{:#x}", alt_router),
                                original_router = %format!("{:#x}", observed_swap.router),
                                "Recovered backrun via automatic V2 fallback route"
                            );
                            backrun
                        } else {
                            self.log_skip(
                                SkipReason::BackrunBuildFailed,
                                &format!(
                                    "{}; v2_fallback_failed=[{}]",
                                    err_msg,
                                    fallback_errors.join(" | ")
                                ),
                            );
                            return Ok(None);
                        }
                    }
                }
            }
        };

        let executor_request = if Some(backrun.to) == self.executor {
            None
        } else {
            self.build_executor_wrapper(&approvals, &backrun, &gas_fees, gas_limit_hint, 0)
                .await?
        };

        let bribe_wei = if let Some((_, req, _)) = executor_request.as_ref() {
            req.value
                .unwrap_or(U256::ZERO)
                .saturating_sub(backrun.value)
        } else if Some(backrun.to) == self.executor {
            backrun
                .request
                .input
                .clone()
                .into_input()
                .and_then(|input| {
                    UnifiedHardenedExecutor::executeBundleCall::abi_decode(&input)
                        .ok()
                        .map(|call| call.bribeAmount)
                })
                .unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };
        let main_request_for_gas = executor_request.as_ref().map(|(_, req, _)| req.clone());
        let refined_bundle_gas = self.adaptive_min_bundle_gas_from_plan(
            min_bundle_gas,
            gas_limit_hint,
            &approvals,
            &front_run,
            &backrun,
            &main_request_for_gas,
        );
        let refined_bundle_gas_cost =
            U256::from(refined_bundle_gas).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
        if wallet_chain_balance < refined_bundle_gas_cost {
            self.log_skip(
                SkipReason::InsufficientBalance,
                &format!(
                    "wallet={} below adaptive_min_bundle_gas_cost={} (gas={} max_fee={} phase=planned)",
                    wallet_chain_balance,
                    refined_bundle_gas_cost,
                    refined_bundle_gas,
                    gas_fees.max_fee_per_gas
                ),
            );
            return Ok(None);
        }

        // Flashloans remove principal requirement, but sender must still fund gas.
        // Keep real wallet balance in simulation overrides to avoid false
        // "insufficient MaxFeePerGas for sender balance" rejections.
        let sim_balance = wallet_chain_balance;

        Ok(Some(BundleParts {
            gas_fees,
            wallet_balance: wallet_chain_balance,
            sim_balance,
            attack_value_eth,
            bribe_wei,
            front_run,
            approvals,
            backrun,
            executor_request: executor_request.map(|(_, req, _)| req),
        }))
    }

    async fn per_block_inputs(&self) -> Result<(GasFees, U256), AppError> {
        let block_number = self
            .current_block
            .load(std::sync::atomic::Ordering::Relaxed);
        {
            let cache = self.per_block_inputs.lock().await;
            if let Some(entry) = cache.as_ref()
                && entry.block_number == block_number
            {
                return Ok((entry.gas_fees.clone(), entry.wallet_balance));
            }
        }

        let (gas_fees, wallet_balance) = tokio::try_join!(
            self.gas_oracle.estimate_eip1559_fees(),
            self.portfolio.update_eth_balance(self.chain_id)
        )?;
        let calibrated = self.calibrated_risk_profile(&gas_fees);
        tracing::debug!(
            target: "risk_calibration",
            chain_id = self.chain_id,
            stress = calibrated.stress.as_str(),
            base_floor_bps = calibrated.base_floor_bps,
            cost_floor_bps = calibrated.cost_floor_bps,
            min_margin_bps = calibrated.min_margin_bps,
            liquidity_floor_ppm = calibrated.liquidity_ratio_floor_ppm,
            base_fee_gwei = (gas_fees.base_fee_per_gas as f64) / 1e9f64,
            next_base_fee_gwei = (gas_fees.next_base_fee_per_gas as f64) / 1e9f64,
            "Applied automatic risk calibration profile"
        );
        let mut cache = self.per_block_inputs.lock().await;
        *cache = Some(PerBlockInputs {
            block_number,
            gas_fees: gas_fees.clone(),
            wallet_balance,
        });
        Ok((gas_fees, wallet_balance))
    }

    fn apply_nonce_plan(
        lease: &NonceLease,
        front_run: &mut Option<FrontRunTx>,
        approvals: &mut [ApproveTx],
        main: &mut TransactionRequest,
    ) -> Result<(), AppError> {
        let needed = 1 + front_run.is_some() as u64 + approvals.len() as u64;
        if needed > lease.count && lease.count != 0 {
            return Err(AppError::Strategy("nonce lease too small".into()));
        }
        let mut nonce_cursor = lease.base;
        for app in approvals.iter_mut() {
            app.request.nonce = Some(nonce_cursor);
            nonce_cursor = nonce_cursor.saturating_add(1);
        }
        if let Some(f) = front_run.as_mut() {
            f.request.nonce = Some(nonce_cursor);
            nonce_cursor = nonce_cursor.saturating_add(1);
        }
        main.nonce = Some(nonce_cursor);
        Ok(())
    }

    async fn simulate_and_score(
        &self,
        mut bundle_requests: Vec<TransactionRequest>,
        overrides: StateOverridesBuilder,
        backrun: &BackrunTx,
        attack_value_eth: U256,
        bribe_wei: U256,
        wallet_chain_balance: U256,
        gas_limit_hint: u64,
        gas_fees: &GasFees,
        router: Address,
    ) -> Result<Option<ProfitOutcome>, AppError> {
        let signer_upfront_need = Self::signer_bundle_max_upfront_wei(
            &bundle_requests,
            self.signer.address(),
            gas_fees.max_fee_per_gas,
            gas_limit_hint,
        );
        if wallet_chain_balance < signer_upfront_need {
            self.log_skip(
                SkipReason::InsufficientBalance,
                &format!(
                    "wallet={} below signer_bundle_max_upfront={} (phase=pre_sim)",
                    wallet_chain_balance, signer_upfront_need
                ),
            );
            return Ok(None);
        }
        for req in bundle_requests.iter_mut() {
            self.populate_access_list(req).await;
        }
        let override_state = overrides.build();
        let simulation_requests = bundle_requests.clone();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let requests = simulation_requests.clone();
                let overrides = override_state.clone();
                async move {
                    simulator
                        .simulate_bundle_requests(&requests, Some(overrides))
                        .await
                }
            },
            2,
            std::time::Duration::from_millis(100),
        )
        .await?;
        if bundle_sims.len() != bundle_requests.len() {
            self.log_skip(
                SkipReason::SimulationFailed,
                &format!(
                    "bundle sim outcome count mismatch expected={} got={}",
                    bundle_requests.len(),
                    bundle_sims.len()
                ),
            );
            tracing::warn!(
                target: "simulation",
                expected = bundle_requests.len(),
                got = bundle_sims.len(),
                router = %format!("{:#x}", router),
                "bundle simulation returned unexpected number of outcomes"
            );
            return Ok(None);
        }
        if let Some((failed_idx, failure)) =
            bundle_sims.iter().enumerate().find(|(_, o)| !o.success)
        {
            let detail = failure
                .reason
                .clone()
                .unwrap_or_else(|| "bundle sim returned failure".to_string());
            let (
                failed_to,
                failed_to_addr,
                failed_gas,
                failed_value,
                failed_selector,
                failed_flashloan_asset,
                failed_flashloan_amount,
                failed_is_last,
            ) = if let Some(req) = bundle_requests.get(failed_idx) {
                let to_addr = match req.to.as_ref() {
                    Some(alloy::primitives::TxKind::Call(addr)) => Some(*addr),
                    _ => None,
                };
                let to = match req.to.as_ref() {
                    Some(alloy::primitives::TxKind::Call(addr)) => format!("{addr:#x}"),
                    Some(alloy::primitives::TxKind::Create) => "create".to_string(),
                    None => "none".to_string(),
                };
                let input = req.input.clone().into_input().unwrap_or_default();
                let selector = if input.len() >= 4 {
                    format!("0x{}", hex::encode(&input[..4]))
                } else {
                    "0x".to_string()
                };
                let mut flashloan_asset = "n/a".to_string();
                let mut flashloan_amount = U256::ZERO;
                if selector == "0x76ec49ba" {
                    if let Ok(decoded) =
                        UnifiedHardenedExecutor::executeFlashLoanCall::abi_decode(&input)
                    {
                        if let Some(asset) = decoded.assets.first().copied() {
                            flashloan_asset = format!("{asset:#x}");
                        }
                        if let Some(amount) = decoded.amounts.first().copied() {
                            flashloan_amount = amount;
                        }
                    }
                } else if selector == "0xba0eef35"
                    && let Ok(decoded) =
                        UnifiedHardenedExecutor::executeAaveFlashLoanSimpleCall::abi_decode(&input)
                {
                    flashloan_asset = format!("{:#x}", decoded.asset);
                    flashloan_amount = decoded.amount;
                }
                (
                    to,
                    to_addr,
                    req.gas.unwrap_or_default(),
                    req.value.unwrap_or(U256::ZERO),
                    selector,
                    flashloan_asset,
                    flashloan_amount,
                    failed_idx + 1 == bundle_requests.len(),
                )
            } else {
                (
                    "unknown".to_string(),
                    None,
                    0u64,
                    U256::ZERO,
                    "0x".to_string(),
                    "n/a".to_string(),
                    U256::ZERO,
                    false,
                )
            };
            let router_fail_attributed =
                Self::simulation_failure_is_router_attributable(&detail, failed_to_addr, router);
            if router_fail_attributed {
                self.record_router_sim(router, false);
            } else {
                tracing::trace!(
                    target: "simulation",
                    router = %format!("{:#x}", router),
                    fail_to = %failed_to,
                    detail = %detail,
                    "simulation failure not attributed to router risk score"
                );
            }
            self.log_skip(SkipReason::SimulationFailed, &detail);
            if backrun.uses_flashloan
                && Self::simulation_failure_is_flashloan_insolvency_like(&detail)
                && let Ok(asset) = failed_flashloan_asset.parse::<Address>()
            {
                self.record_flashloan_insolvency(asset, &detail);
            }
            tracing::debug!(
                target: "simulation",
                fail_idx = failed_idx,
                fail_to = %failed_to,
                fail_gas = failed_gas,
                fail_value = %failed_value,
                fail_selector = %failed_selector,
                flashloan_asset = %failed_flashloan_asset,
                flashloan_amount = %failed_flashloan_amount,
                fail_is_last = failed_is_last,
                uses_flashloan = backrun.uses_flashloan,
                exec_to = %format!("{:#x}", backrun.to),
                router = %format!("{:#x}", router),
                out_token = %format!("{:#x}", backrun.expected_out_token),
                out_amount = %backrun.expected_out,
                "bundle_sim_failure_context"
            );
            return Ok(None);
        }
        self.record_router_sim(router, true);

        let mut gas_used_total = 0u64;
        for sim in &bundle_sims {
            gas_used_total = gas_used_total.saturating_add(sim.gas_used);
        }
        let bundle_gas_limit = gas_used_total.max(gas_limit_hint);

        // EIP-1559 effective fee actually paid: base_fee + min(tip, max_fee - base_fee).
        let paid_tip = gas_fees.max_priority_fee_per_gas.min(
            gas_fees
                .max_fee_per_gas
                .saturating_sub(gas_fees.base_fee_per_gas),
        );
        // Add a small drift multiplier (5%) to cushion basefee movement across a couple blocks.
        let paid_fee = gas_fees
            .base_fee_per_gas
            .saturating_add(paid_tip)
            .saturating_mul(105)
            .checked_div(100)
            .unwrap_or_else(|| gas_fees.base_fee_per_gas.saturating_add(paid_tip));
        let gas_cost_wei = U256::from(gas_used_total).saturating_mul(U256::from(paid_fee));

        // Include any wrapper‑level bribe/value delta even if backrun.value itself is zero.
        let backrun_value = backrun
            .request
            .value
            .unwrap_or(backrun.value)
            .max(backrun.value);
        let principal_wei = backrun_value.saturating_add(attack_value_eth);
        let total_eth_in = principal_wei.saturating_add(bribe_wei);
        let upfront_need = Self::required_wallet_upfront_wei(
            backrun.uses_flashloan,
            principal_wei,
            bribe_wei,
            gas_cost_wei,
        );
        if wallet_chain_balance < upfront_need {
            self.log_skip(
                SkipReason::InsufficientBalance,
                &format!(
                    "need {} wei (principal+bribe+gas; flashloan={}) have {}",
                    upfront_need, backrun.uses_flashloan, wallet_chain_balance
                ),
            );
            return Ok(None);
        }
        let Some(native_out) = self
            .estimate_settlement_native_out(backrun.expected_out, backrun.expected_out_token)
            .await
        else {
            self.log_skip(
                SkipReason::ProfitOrGasGuard,
                &format!(
                    "unpriced_settlement_token_out token={:#x} amount={}",
                    backrun.expected_out_token, backrun.expected_out
                ),
            );
            return Ok(None);
        };
        let gross_profit_wei = native_out.saturating_sub(total_eth_in);

        if gas_cost_wei > gross_profit_wei {
            self.log_skip(SkipReason::ProfitOrGasGuard, "Gas > Gross Profit");
            return Ok(None);
        }

        let effective_cost_wei = gas_cost_wei
            .saturating_add(bribe_wei)
            .saturating_add(backrun.flashloan_premium);
        let net_profit_wei = gross_profit_wei.saturating_sub(effective_cost_wei);
        let native_symbol = crate::common::constants::native_symbol_for_chain(self.chain_id);
        let price_symbol = format!("{native_symbol}USD");
        let eth_quote = match self.price_feed.get_price(&price_symbol).await {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!(
                    target: "price_feed",
                    error = %e,
                    symbol = %price_symbol,
                    "Price fetch failed; continuing with placeholder quote"
                );
                PriceQuote {
                    price: 0.0,
                    source: "unavailable".into(),
                }
            }
        };
        let base_profit_floor = StrategyExecutor::dynamic_profit_floor(wallet_chain_balance);
        let extra_costs = bribe_wei.saturating_add(backrun.flashloan_premium);
        let min_usd_floor_wei = self.min_usd_floor_wei(eth_quote.price);
        let adaptive_base_bps = self.adaptive_base_floor_bps(gas_fees);
        let adaptive_cost_bps = self.adaptive_cost_floor_bps(gas_fees);
        let profit_floor = self.dynamic_policy_profit_floor_with_costs(
            wallet_chain_balance,
            gas_cost_wei,
            extra_costs,
            gas_fees,
            min_usd_floor_wei,
        );
        let profit_if_included_wei = net_profit_wei.saturating_sub(profit_floor);
        let inclusion_probability_bps = self.inclusion_probability_bps(gas_fees);
        let cost_if_failed_wei =
            self.failure_cost_wei(gas_cost_wei, extra_costs, backrun.uses_flashloan);
        let to_i256 = |value: U256| {
            if value > U256::from(i128::MAX as u128) {
                I256::from_raw(U256::from(i128::MAX as u128))
            } else {
                I256::from_raw(U256::from(value.to::<u128>()))
            }
        };
        let expected_net_wei = (to_i256(profit_if_included_wei)
            * I256::from_raw(U256::from(inclusion_probability_bps))
            - to_i256(cost_if_failed_wei)
                * I256::from_raw(U256::from(
                    10_000u64.saturating_sub(inclusion_probability_bps),
                )))
            / I256::from_raw(U256::from(10_000u64));

        if expected_net_wei <= I256::ZERO {
            self.log_skip(
                SkipReason::ProfitOrGasGuard,
                &format!(
                    "expected_net={} <= 0 (net={} floor={} profit_if_included={} cost_if_failed={} p_inclusion_bps={} base_floor={} gas_cost={} extra_costs={} base_bps={} cost_bps={} min_usd_floor={})",
                    expected_net_wei,
                    net_profit_wei,
                    profit_floor,
                    profit_if_included_wei,
                    cost_if_failed_wei,
                    inclusion_probability_bps,
                    base_profit_floor,
                    gas_cost_wei,
                    extra_costs,
                    adaptive_base_bps,
                    adaptive_cost_bps,
                    min_usd_floor_wei.unwrap_or(U256::ZERO)
                ),
            );
            return Ok(None);
        }

        if !self.gas_ratio_ok_with_fees(
            gas_cost_wei,
            gross_profit_wei,
            wallet_chain_balance,
            gas_fees,
        ) {
            self.log_skip(SkipReason::ProfitOrGasGuard, "Bad Risk/Reward");
            return Ok(None);
        }

        let profit_eth_f64 = self.amount_to_display(gross_profit_wei, self.wrapped_native);
        let gas_cost_eth_f64 = self.amount_to_display(gas_cost_wei, self.wrapped_native);
        let net_profit_eth_f64 = self.amount_to_display(net_profit_wei, self.wrapped_native);

        Ok(Some(ProfitOutcome {
            gas_used_total,
            bundle_gas_limit,
            gas_cost_wei,
            gross_profit_wei,
            net_profit_wei,
            bribe_wei,
            flashloan_premium_wei: backrun.flashloan_premium,
            effective_cost_wei,
            profit_eth_f64,
            gas_cost_eth_f64,
            net_profit_eth_f64,
            eth_quote,
        }))
    }
}

struct BundleParts {
    gas_fees: GasFees,
    wallet_balance: U256,
    sim_balance: U256,
    attack_value_eth: U256,
    bribe_wei: U256,
    front_run: Option<FrontRunTx>,
    approvals: Vec<ApproveTx>,
    backrun: BackrunTx,
    executor_request: Option<TransactionRequest>,
}

struct ProfitOutcome {
    #[allow(dead_code)]
    gas_used_total: u64,
    bundle_gas_limit: u64,
    gas_cost_wei: U256,
    gross_profit_wei: U256,
    net_profit_wei: U256,
    bribe_wei: U256,
    flashloan_premium_wei: U256,
    effective_cost_wei: U256,
    profit_eth_f64: f64,
    gas_cost_eth_f64: f64,
    net_profit_eth_f64: f64,
    eth_quote: PriceQuote,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::strategy::execution::strategy::dummy_executor_for_tests;
    use alloy::rpc::types::eth::TransactionRequest;

    #[test]
    fn apply_nonce_plan_orders_txes() {
        let lease = NonceLease {
            block: 1,
            base: 7,
            count: 3,
        };
        let mut front = Some(FrontRunTx {
            raw: Vec::new(),
            hash: B256::ZERO,
            to: Address::ZERO,
            value: U256::ZERO,
            request: TransactionRequest::default(),
            expected_tokens: U256::ZERO,
            input_token: Address::ZERO,
            input_amount: U256::ZERO,
        });
        let mut approvals = vec![ApproveTx {
            raw: Vec::new(),
            request: TransactionRequest::default(),
            token: Address::ZERO,
        }];
        let mut main = TransactionRequest::default();

        StrategyExecutor::apply_nonce_plan(&lease, &mut front, approvals.as_mut_slice(), &mut main)
            .unwrap();

        assert_eq!(approvals[0].request.nonce, Some(7));
        assert_eq!(front.unwrap().request.nonce, Some(8));
        assert_eq!(main.nonce, Some(9));
    }

    #[test]
    fn apply_nonce_plan_handles_single_tx() {
        let lease = NonceLease {
            block: 1,
            base: 42,
            count: 1,
        };
        let mut main = TransactionRequest::default();
        let mut approvals = Vec::new();
        StrategyExecutor::apply_nonce_plan(&lease, &mut None, approvals.as_mut_slice(), &mut main)
            .unwrap();
        assert_eq!(main.nonce, Some(42));
    }

    #[test]
    fn required_wallet_upfront_includes_principal_without_flashloan() {
        let upfront = StrategyExecutor::required_wallet_upfront_wei(
            false,
            U256::from(100u64),
            U256::from(10u64),
            U256::from(5u64),
        );
        assert_eq!(upfront, U256::from(115u64));
    }

    #[test]
    fn required_wallet_upfront_excludes_principal_with_flashloan() {
        let upfront = StrategyExecutor::required_wallet_upfront_wei(
            true,
            U256::from(100u64),
            U256::from(10u64),
            U256::from(5u64),
        );
        assert_eq!(upfront, U256::from(15u64));
    }

    #[test]
    fn signer_bundle_max_upfront_sums_only_signer_requests() {
        let signer = Address::from([0x11; 20]);
        let other = Address::from([0x22; 20]);
        let req_a = TransactionRequest {
            from: Some(signer),
            gas: Some(100_000),
            max_fee_per_gas: Some(10),
            value: Some(U256::from(50u64)),
            ..Default::default()
        };
        let req_b = TransactionRequest {
            from: Some(other),
            gas: Some(500_000),
            max_fee_per_gas: Some(100),
            value: Some(U256::from(999u64)),
            ..Default::default()
        };
        let req_c = TransactionRequest {
            from: Some(signer),
            gas: Some(200_000),
            max_fee_per_gas: Some(20),
            value: Some(U256::from(70u64)),
            ..Default::default()
        };
        let total = StrategyExecutor::signer_bundle_max_upfront_wei(
            &[req_a, req_b, req_c],
            signer,
            1,
            210_000,
        );
        // (100_000*10 + 50) + (200_000*20 + 70) = 5_000_120
        assert_eq!(total, U256::from(5_000_120u64));
    }

    #[tokio::test]
    async fn signal_scan_cooldown_is_executor_local() {
        let exec_a = dummy_executor_for_tests().await;
        let exec_b = dummy_executor_for_tests().await;
        let now = 1_700_000_000u64;

        assert!(exec_a.should_run_signal_scan(false, now));
        // Separate executor should not be throttled by another instance.
        assert!(exec_b.should_run_signal_scan(false, now));
        // Same executor should still obey cooldown.
        assert!(!exec_a.should_run_signal_scan(false, now));
    }

    #[test]
    fn simulation_failure_attribution_ignores_non_router_target_even_on_revert_text() {
        let router = Address::from([0x11; 20]);
        let other = Address::from([0x22; 20]);
        let detail = "execution reverted: TRANSFER_FAILED";

        let attributed = StrategyExecutor::simulation_failure_is_router_attributable(
            detail,
            Some(other),
            router,
        );
        assert!(!attributed);
    }

    #[test]
    fn simulation_failure_attribution_counts_router_target() {
        let router = Address::from([0x11; 20]);
        let detail = "execution reverted: TRANSFER_FAILED";

        let attributed = StrategyExecutor::simulation_failure_is_router_attributable(
            detail,
            Some(router),
            router,
        );
        assert!(attributed);
    }

    #[test]
    fn simulation_failure_attribution_uses_heuristics_only_when_target_unknown() {
        let router = Address::from([0x11; 20]);
        let detail = "execution reverted: insufficient output amount";

        let attributed =
            StrategyExecutor::simulation_failure_is_router_attributable(detail, None, router);
        assert!(attributed);
    }

    #[test]
    fn simulation_failure_attribution_excludes_infra_markers() {
        let router = Address::from([0x11; 20]);
        let detail = "timeout while waiting for upstream";

        let attributed =
            StrategyExecutor::simulation_failure_is_router_attributable(detail, None, router);
        assert!(!attributed);
    }

    #[tokio::test]
    async fn adaptive_min_bundle_gas_avoids_flashloan_overhead_double_count_when_gas_is_set() {
        let exec = dummy_executor_for_tests().await;
        let backrun = BackrunTx {
            raw: Vec::new(),
            hash: B256::ZERO,
            to: Address::from([0x33; 20]),
            value: U256::ZERO,
            request: TransactionRequest {
                gas: Some(500_000),
                ..Default::default()
            },
            expected_out: U256::ZERO,
            expected_out_token: Address::ZERO,
            unwrap_to_native: false,
            uses_flashloan: true,
            flashloan_premium: U256::ZERO,
            flashloan_overhead_gas: 200_000,
            router_kind: crate::services::strategy::decode::RouterKind::V2Like,
            route_plan: None,
        };

        let planned =
            exec.adaptive_min_bundle_gas_from_plan(120_000, 220_000, &[], &None, &backrun, &None);

        // 500k main gas with 5% headroom; no extra flashloan overhead should be added.
        assert_eq!(planned, 525_000);
    }
}
