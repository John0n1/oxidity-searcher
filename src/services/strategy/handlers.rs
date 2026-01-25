// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::core::executor::BundleItem;
use crate::network::gas::GasFees;
use crate::network::mev_share::MevShareHint;
use crate::services::strategy::bundles::BundlePlan;
use crate::services::strategy::decode::{
    decode_swap, decode_swap_input, direction, target_token, RouterKind, SwapDirection,
};
use crate::services::strategy::planning::{ApproveTx, FrontRunTx};
use crate::services::strategy::strategy::{StrategyExecutor, StrategyWork};
use alloy::consensus::Transaction as ConsensusTx;
use alloy::eips::eip2718::Encodable2718;
use alloy::sol_types::SolCall;
use alloy::network::TransactionResponse;
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::eth::state::StateOverridesBuilder;
use alloy::rpc::types::eth::{Transaction, TransactionInput, TransactionRequest};
use alloy::primitives::TxKind;
use std::str::FromStr;

impl StrategyExecutor {
    pub async fn process_work(self: std::sync::Arc<Self>, work: StrategyWork) {
        if let Err(e) = self.handle_work(work).await {
            tracing::error!(target: "strategy", error=%e, "Strategy task failed");
        }
    }

    async fn handle_work(&self, work: StrategyWork) -> Result<(), AppError> {
        self.safety_guard.check()?;

        let outcome = match work {
            StrategyWork::Mempool(tx) => {
                let from = tx.from();
                let res = self.evaluate_mempool_tx(&tx).await;
                (res, Some(from), Some(tx.tx_hash()))
            }
            StrategyWork::MevShareHint(hint) => {
                let res = self.evaluate_mev_share_hint(&hint).await;
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
                self.stats.submitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            (Ok(None), from, tx_hash) => {
                tracing::debug!(
                    target: "strategy",
                    from=?from,
                    tx_hash=?tx_hash,
                    "Skipped item"
                );
                self.stats.skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                    self.stats.failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(target: "strategy", error=%e, "Strategy failed");
                }
            }
        };

        let processed = self.stats.processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if processed % 50 == 0 {
            tracing::info!(
                target: "strategy_summary",
                processed,
                submitted = self.stats.submitted.load(std::sync::atomic::Ordering::Relaxed),
                skipped = self.stats.skipped.load(std::sync::atomic::Ordering::Relaxed),
                failed = self.stats.failed.load(std::sync::atomic::Ordering::Relaxed),
                skip_unknown_router = self.stats.skip_unknown_router.load(std::sync::atomic::Ordering::Relaxed),
                skip_decode = self.stats.skip_decode_failed.load(std::sync::atomic::Ordering::Relaxed),
                skip_missing_wrapped = self.stats.skip_missing_wrapped.load(std::sync::atomic::Ordering::Relaxed),
                skip_gas_cap = self.stats.skip_gas_cap.load(std::sync::atomic::Ordering::Relaxed),
                skip_sim_failed = self.stats.skip_sim_failed.load(std::sync::atomic::Ordering::Relaxed),
                skip_profit_guard = self.stats.skip_profit_guard.load(std::sync::atomic::Ordering::Relaxed),
                skip_unsupported_router = self.stats.skip_unsupported_router.load(std::sync::atomic::Ordering::Relaxed),
                skip_token_call = self.stats.skip_token_call.load(std::sync::atomic::Ordering::Relaxed),
                "Strategy loop summary"
            );
        }

        Ok(())
    }

    async fn evaluate_mempool_tx(&self, tx: &Transaction) -> Result<Option<String>, AppError> {
        let to_addr = match tx.kind() {
            TxKind::Call(addr) => addr,
            TxKind::Create => return Ok(None),
        };

        if !self.router_allowlist.contains(&to_addr) {
            if Self::is_common_token_call(tx.input()) {
                self.log_skip("token_call", "erc20 transfer/approve");
                return Ok(None);
            }
            self.log_skip("unknown_router", &format!("to={to_addr:#x}"));
            return Ok(None);
        }

        let Some(observed_swap) = decode_swap(tx) else {
            self.log_skip("decode_failed", "unable to decode swap input");
            return Ok(None);
        };
        if observed_swap.amount_in.is_zero() || !observed_swap.path.contains(&self.wrapped_native) {
            self.log_skip(
                "zero_amount_or_no_wrapped_native",
                "path missing wrapped native or zero amount",
            );
            return Ok(None);
        }
        let direction = direction(&observed_swap, self.wrapped_native);
        let target_token = match target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip("decode_failed", "no target token");
                return Ok(None);
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip("toxic_token", &format!("token={:#x}", target_token));
            return Ok(None);
        }
        self.inventory_tokens.insert(target_token);
        let tx_value = tx.value();

        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(&mut gas_fees, None, None);
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            self.log_skip(
                "gas_price_cap",
                &format!(
                    "max_fee_per_gas={} cap_gwei={}",
                    gas_fees.max_fee_per_gas, self.max_gas_price_gwei
                ),
            );
            return Ok(None);
        }

        let real_balance = self.portfolio.update_eth_balance(self.chain_id).await?;
        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom = U256::from(tx.gas_limit()) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = tx.value().saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let executor_tx: Option<(Vec<u8>, TransactionRequest, B256)>;
        let main_request: TransactionRequest;

        let mut nonce_cursor = self.peek_nonce_for_sim().await?;

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth && self.sandwich_attacks_enabled {
            let nonce_front = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
            match self
                .build_front_run_tx(
                    &observed_swap,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    wallet_chain_balance,
                    tx.gas_limit(),
                    nonce_front,
                )
                .await
            {
                Ok(Some(f)) => {
                    attack_value_eth = f.value;
                    bundle_requests.push(f.request.clone());
                    front_run = Some(f);
                }
                Ok(None) => {}
                Err(e) => {
                    self.log_skip("front_run_build_failed", &e.to_string());
                    return Ok(None);
                }
            }
        }

        if let Some(f) = &front_run {
            if self
                .needs_approval(target_token, observed_swap.router, f.expected_tokens)
                .await?
            {
                let needed_nonce = nonce_cursor;
                nonce_cursor = nonce_cursor.saturating_add(1);
                approval = Some(
                    self.build_approval_tx(
                        target_token,
                        observed_swap.router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        needed_nonce,
                    )
                    .await?,
                );
            }
        }

        let use_flashloan =
            self.should_use_flashloan(observed_swap.amount_in, wallet_chain_balance, &gas_fees)
                && front_run.is_none();

        let sim_balance =
            U256::from_str("10000000000000000000000").unwrap_or_else(|_| U256::from(u128::MAX));
        let trade_balance = if use_flashloan {
            sim_balance
        } else {
            wallet_chain_balance
        };

        let nonce_backrun = nonce_cursor;

        let backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                trade_balance,
                tx.gas_limit(),
                front_run.as_ref().map(|f| f.expected_tokens),
                use_flashloan,
                nonce_backrun,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), sim_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        executor_tx = self
            .build_executor_wrapper(
                approval.as_ref(),
                &backrun,
                &gas_fees,
                tx.gas_limit(),
                nonce_backrun,
            )
            .await?;
        if let Some(f) = &front_run {
            bundle_requests.push(f.request.clone());
        }
        bundle_requests.push(tx.clone().into_request());

        if let Some((_, req, _)) = &executor_tx {
            bundle_requests.push(req.clone());
            main_request = req.clone();
        } else {
            if let Some(app) = &approval {
                bundle_requests.push(app.request.clone());
            }
            bundle_requests.push(backrun.request.clone());
            main_request = backrun.request.clone();
        }
        let mut bundle_reqs_for_sim = bundle_requests.clone();
        for req in bundle_reqs_for_sim.iter_mut() {
            self.populate_access_list(req).await;
        }
        let overrides_for_sim = overrides.clone();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let overrides = overrides_for_sim.clone();
                let reqs = bundle_reqs_for_sim.clone();
                async move {
                    simulator
                        .simulate_bundle_requests(&reqs, Some(overrides))
                        .await
                }
            },
            2,
            std::time::Duration::from_millis(100),
        )
        .await?;
        if bundle_sims.iter().any(|o| !o.success) {
            self.log_skip("simulation_failed", "bundle sim returned failure");
            return Ok(None);
        }

        let mut gas_used_total = 0u64;
        for sim in &bundle_sims {
            gas_used_total = gas_used_total.saturating_add(sim.gas_used);
        }
        let bundle_gas_limit = gas_used_total.max(tx.gas_limit());
        let gas_cost_wei = U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        let total_eth_in = backrun.value.saturating_add(attack_value_eth);
        let gross_profit_wei = backrun.expected_out.saturating_sub(total_eth_in);

        if gas_cost_wei > gross_profit_wei {
            self.log_skip("profit_or_gas_guard", "Gas > Gross Profit");
            return Ok(None);
        }

        let net_profit_wei = gross_profit_wei.saturating_sub(gas_cost_wei);
        let profit_floor = StrategyExecutor::dynamic_profit_floor(wallet_chain_balance);

        if net_profit_wei < profit_floor {
            self.log_skip(
                "profit_or_gas_guard",
                &format!("Net {} < Floor {}", net_profit_wei, profit_floor),
            );
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = self.amount_to_display(gross_profit_wei, self.wrapped_native);
        let gas_cost_eth_f64 = self.amount_to_display(gas_cost_wei, self.wrapped_native);
        let net_profit_eth_f64 = self.amount_to_display(net_profit_wei, self.wrapped_native);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_wei = %gas_cost_wei,
            net_profit_wei = %net_profit_wei,
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
            price_source = %eth_quote.source,
            price = eth_quote.price,
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
                net_profit_eth = net_profit_eth_f64,
                gross_profit_eth = profit_eth_f64,
                gas_cost_eth = gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(attack_value_eth, self.wrapped_native),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable bundle (not sent)"
            );
            return Ok(Some(format!("{tx_hash:#x}")));
        }

        let plan = BundlePlan {
            front_run: front_run.as_ref().map(|f| f.request.clone()),
            approval: approval.as_ref().map(|a| a.request.clone()),
            main: main_request.clone(),
            victims: vec![tx.inner.encoded_2718()],
        };
        let touched_pools = self.reserve_cache.pairs_for_v2_path(&observed_swap.path);
        let plan_hashes = match self.merge_and_send_bundle(plan, touched_pools).await {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.emergency_exit_inventory("bundle send failed").await;
                return Err(e);
            }
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
                tx_value.to_string().as_str(),
                Some("strategy_v1"),
            )
            .await?;
        let recorded_hash = plan_hashes.main;
        let recorded_to = main_request
            .to
            .clone()
            .or_else(|| Some(TxKind::Call(backrun.to)));
        let recorded_value = main_request.value.unwrap_or(backrun.value);
        self.db
            .save_transaction(
                &format!("{:#x}", recorded_hash),
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
                    &format!("{:#x}", plan_hashes.front_run.unwrap_or_else(|| f.hash)),
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
                profit_eth_f64,
                gas_cost_eth_f64,
                net_profit_eth_f64,
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, gross_profit_wei, gas_cost_wei);

        let _ = self
            .db
            .save_market_price(self.chain_id, "ETHUSD", eth_quote.price, &eth_quote.source)
            .await;

        let receipt_target = plan_hashes.main;
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("bundle receipt missing/failed")
                .await;
        }

        Ok(Some(format!("{tx_hash:#x}")))
    }

    async fn evaluate_mev_share_hint(
        &self,
        hint: &MevShareHint,
    ) -> Result<Option<String>, AppError> {
        if !self.router_allowlist.contains(&hint.router) {
            self.log_skip("unknown_router", &format!("to={:#x}", hint.router));
            return Ok(None);
        }

        let Some(observed_swap) = decode_swap_input(hint.router, &hint.call_data, hint.value)
        else {
            self.log_skip("decode_failed", "unable to decode swap input");
            return Ok(None);
        };

        if observed_swap.router_kind == RouterKind::V3Like {
            self.log_skip(
                "unsupported_router_type",
                "uniswap_v3 not yet implemented for backrun",
            );
            return Ok(None);
        }

        if observed_swap.amount_in.is_zero() || !observed_swap.path.contains(&self.wrapped_native) {
            self.log_skip(
                "zero_amount_or_no_wrapped_native",
                "path missing wrapped native or zero amount",
            );
            return Ok(None);
        }

        let direction = direction(&observed_swap, self.wrapped_native);
        let target_token = match target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip("decode_failed", "no target token");
                return Ok(None);
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip("toxic_token", &format!("token={:#x}", target_token));
            return Ok(None);
        }
        self.inventory_tokens.insert(target_token);
        let gas_limit_hint = hint.gas_limit.unwrap_or(220_000);

        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(
            &mut gas_fees,
            hint.max_fee_per_gas,
            hint.max_priority_fee_per_gas,
        );
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            self.log_skip(
                "gas_price_cap",
                &format!(
                    "max_fee_per_gas={} cap_gwei={}",
                    gas_fees.max_fee_per_gas, self.max_gas_price_gwei
                ),
            );
            return Ok(None);
        }

        let real_balance = self.portfolio.update_eth_balance(self.chain_id).await?;
        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom = U256::from(gas_limit_hint) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = hint.value.saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let mut bundle_body: Vec<BundleItem> = Vec::new();
        let mut executor_request: Option<TransactionRequest> = None;
        let mut executor_hash: Option<B256> = None;

        let mut nonce_cursor = self.peek_nonce_for_sim().await?;

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth && self.sandwich_attacks_enabled {
            let nonce_front = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
            match self
                .build_front_run_tx(
                    &observed_swap,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    wallet_chain_balance,
                    gas_limit_hint,
                    nonce_front,
                )
                .await
            {
                Ok(Some(f)) => {
                    attack_value_eth = f.value;
                    bundle_requests.push(f.request.clone());
                    front_run = Some(f);
                }
                Ok(None) => {}
                Err(e) => {
                    self.log_skip("front_run_build_failed", &e.to_string());
                    return Ok(None);
                }
            }
        }

        if let Some(f) = &front_run {
            if self
                .needs_approval(target_token, observed_swap.router, f.expected_tokens)
                .await?
            {
                let needed_nonce = nonce_cursor;
                nonce_cursor = nonce_cursor.saturating_add(1);
                approval = Some(
                    self.build_approval_tx(
                        target_token,
                        observed_swap.router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        needed_nonce,
                    )
                    .await?,
                );
            }
        }

        let use_flashloan =
            self.should_use_flashloan(observed_swap.amount_in, wallet_chain_balance, &gas_fees)
                && front_run.is_none();
        let sim_balance =
            U256::from_str("10000000000000000000000").unwrap_or_else(|_| U256::from(u128::MAX));
        let trade_balance = if use_flashloan {
            sim_balance
        } else {
            wallet_chain_balance
        };
        let nonce_backrun = nonce_cursor;
        nonce_cursor = nonce_cursor.saturating_add(1);
        let mut backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                trade_balance,
                gas_limit_hint,
                front_run.as_ref().map(|f| f.expected_tokens),
                use_flashloan,
                nonce_cursor,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), sim_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        let max_fee_hint = hint.max_fee_per_gas.unwrap_or(gas_fees.max_fee_per_gas);
        let max_prio_hint = hint
            .max_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas);
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
        if let Some(app) = &approval {
            bundle_requests.push(app.request.clone());
        }
        bundle_requests.push(victim_request);
        bundle_requests.push(backrun.request.clone());

        if self.executor.is_some() && front_run.is_none() {
            if let Some(exec_addr) = self.executor {
                let mut targets = Vec::new();
                let mut payloads = Vec::new();
                let mut values = Vec::new();

                if let Some(app) = &approval {
                    if let Some(TxKind::Call(addr)) = app.request.to {
                        targets.push(addr);
                        let bytes = app.request.input.clone().into_input().unwrap_or_default();
                        payloads.push(bytes);
                        values.push(U256::ZERO);
                    }
                }
                if let Some(TxKind::Call(addr)) = backrun.request.to {
                    targets.push(addr);
                    let bytes = backrun
                        .request
                        .input
                        .clone()
                        .into_input()
                        .unwrap_or_default();
                    payloads.push(bytes);
                    values.push(backrun.value);
                }

                if !targets.is_empty() {
                    let total_value = values
                        .iter()
                        .copied()
                        .fold(U256::ZERO, |acc, v| acc.saturating_add(v));
                    let exec_call = crate::data::executor::UnifiedHardenedExecutor::executeBundleCall {
                        targets,
                        payloads,
                        values,
                        bribeRecipient: Address::ZERO,
                        bribeAmount: U256::ZERO,
                        allowPartial: true,
                        balanceCheckToken: self.wrapped_native,
                    };
                    let calldata = exec_call.abi_encode();
                    let gas_limit = backrun
                        .request
                        .gas
                        .unwrap_or(gas_limit_hint)
                        .saturating_add(approval.as_ref().and_then(|a| a.request.gas).unwrap_or(0))
                        .saturating_add(80_000);

                    let (_raw, request, hash) = self
                        .sign_swap_request(
                            exec_addr,
                            gas_limit,
                            total_value,
                            gas_fees.max_fee_per_gas,
                            gas_fees.max_priority_fee_per_gas,
                            nonce_backrun,
                            calldata,
                            AccessList::default(),
                        )
                        .await?;
                    executor_hash = Some(hash);
                    executor_request = Some(request);
                }
            }
        }

        let exec_req_for_sim = executor_request.clone();
        let mut bundle_reqs_for_sim = bundle_requests.clone();
        for req in bundle_reqs_for_sim.iter_mut() {
            self.populate_access_list(req).await;
        }
        let overrides_for_sim = overrides.clone();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let reqs = if let Some(r) = exec_req_for_sim.clone() {
                    vec![r]
                } else {
                    bundle_reqs_for_sim.clone()
                };
                let overrides = overrides_for_sim.clone();
                async move {
                    simulator
                        .simulate_bundle_requests(&reqs, Some(overrides))
                        .await
                }
            },
            2,
            std::time::Duration::from_millis(100),
        )
        .await?;
        if bundle_sims.iter().any(|o| !o.success) {
            self.log_skip("simulation_failed", "bundle sim returned failure");
            return Ok(None);
        }

        let mut gas_used_total = 0u64;
        for sim in &bundle_sims {
            gas_used_total = gas_used_total.saturating_add(sim.gas_used);
        }
        let bundle_gas_limit = gas_used_total.max(gas_limit_hint);
        let gas_cost_wei = U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        let total_eth_in = backrun.value.saturating_add(attack_value_eth);
        let gross_profit_wei = backrun.expected_out.saturating_sub(total_eth_in);

        if gas_cost_wei > gross_profit_wei {
            self.log_skip("profit_or_gas_guard", "Gas > Gross Profit");
            return Ok(None);
        }

        let net_profit_wei = gross_profit_wei.saturating_sub(gas_cost_wei);
        let profit_floor = StrategyExecutor::dynamic_profit_floor(wallet_chain_balance);

        if net_profit_wei < profit_floor {
            self.log_skip(
                "profit_or_gas_guard",
                &format!("Net {} < Floor {}", net_profit_wei, profit_floor),
            );
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = self.amount_to_display(gross_profit_wei, self.wrapped_native);
        let gas_cost_eth_f64 = self.amount_to_display(gas_cost_wei, self.wrapped_native);
        let net_profit_eth_f64 = self.amount_to_display(net_profit_wei, self.wrapped_native);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_wei = %gas_cost_wei,
            net_profit_wei = %net_profit_wei,
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
            price_source = %eth_quote.source,
            price = eth_quote.price,
            victim_min_out = ?observed_swap.min_out,
            victim_recipient = ?observed_swap.recipient,
            path_len = observed_swap.path.len(),
            path = ?observed_swap.path,
            router = ?observed_swap.router,
            used_mock_balance = self.dry_run,
            profit_floor_wei = %StrategyExecutor::dynamic_profit_floor(wallet_chain_balance),
            sandwich = front_run.is_some(),
            "MEV-Share strategy evaluation"
        );

        let tx_hash = format!("{:#x}", hint.tx_hash);

        let used_nonces = 1 + front_run.is_some() as u64 + approval.is_some() as u64;
        let base_nonce = self.lease_nonces(used_nonces).await?;
        let mut nonce_cursor = base_nonce;

        bundle_body.clear();
        bundle_body.push(BundleItem::Hash {
            hash: tx_hash.clone(),
        });

        if let Some(f) = front_run.as_mut() {
            let fallback = f.request.access_list.clone().unwrap_or_default();
            let mut req = f.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            f.raw = raw.clone();
            f.request = signed_req;
            f.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
            nonce_cursor = nonce_cursor.saturating_add(1);
        }

        if let Some(app) = approval.as_mut() {
            let fallback = app.request.access_list.clone().unwrap_or_default();
            let mut req = app.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, _) = self.sign_with_access_list(req, fallback).await?;
            app.raw = raw.clone();
            app.request = signed_req;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
            nonce_cursor = nonce_cursor.saturating_add(1);
        }

        if let Some(mut req) = executor_request.take() {
            let fallback = req.access_list.clone().unwrap_or_default();
            req.nonce = Some(nonce_cursor);
            let (raw, _signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            executor_hash = Some(hash);
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        } else {
            let fallback = backrun.request.access_list.clone().unwrap_or_default();
            let mut req = backrun.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            backrun.raw = raw.clone();
            backrun.request = signed_req;
            backrun.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        }

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %tx_hash,
                net_profit_eth = net_profit_eth_f64,
                gross_profit_eth = profit_eth_f64,
                gas_cost_eth = gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(attack_value_eth, self.wrapped_native),
                wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
                path_len = observed_swap.path.len(),
                router = ?observed_swap.router,
                used_mock_balance = self.dry_run,
                profit_floor_wei = %StrategyExecutor::dynamic_profit_floor(wallet_chain_balance),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable MEV-Share bundle (not sent)"
            );
            return Ok(Some(tx_hash));
        }

        let _ = self.db.update_status(&tx_hash, None, Some(false)).await;

        if let Err(e) = self.bundle_sender.send_mev_share_bundle(&bundle_body).await {
            self.emergency_exit_inventory("mev_share bundle send failed")
                .await;
            return Err(e);
        }

        let from_addr = hint.from.unwrap_or(Address::ZERO);
        self.db
            .save_transaction(
                &tx_hash,
                self.chain_id,
                &format!("{:#x}", from_addr),
                Some(format!("{:#x}", hint.router)).as_deref(),
                hint.value.to_string().as_str(),
                Some("strategy_mev_share"),
            )
            .await?;

        self.db
            .save_transaction(
                &format!("{:#x}", backrun.hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                Some(format!("{:#x}", backrun.to)).as_deref(),
                backrun.value.to_string().as_str(),
                Some("strategy_backrun"),
            )
            .await?;
        if let Some(f) = &front_run {
            self.db
                .save_transaction(
                    &format!("{:#x}", f.hash),
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
                &tx_hash,
                self.chain_id,
                "strategy_mev_share",
                profit_eth_f64,
                gas_cost_eth_f64,
                net_profit_eth_f64,
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, gross_profit_wei, gas_cost_wei);

        let _ = self
            .db
            .save_market_price(self.chain_id, "ETHUSD", eth_quote.price, &eth_quote.source)
            .await;

        let receipt_target = executor_hash.unwrap_or(backrun.hash);
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("mev_share receipt missing/failed")
                .await;
        }

        Ok(Some(tx_hash))
    }
}
