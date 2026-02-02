// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::core::executor::BundleItem;
use crate::network::gas::GasFees;
use crate::network::mev_share::MevShareHint;
use crate::network::price_feed::PriceQuote;
use crate::services::strategy::bundles::BundlePlan;
use crate::services::strategy::decode::{
    ObservedSwap, SwapDirection, decode_swap, decode_swap_input, direction, target_token,
};
use crate::services::strategy::planning::bundles::NonceLease;
use crate::services::strategy::planning::{ApproveTx, BackrunTx, FrontRunTx};
use crate::services::strategy::strategy::BundleTelemetry;
use crate::services::strategy::strategy::{StrategyExecutor, StrategyWork};
use alloy::consensus::Transaction as ConsensusTx;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TransactionResponse;
use alloy::primitives::TxKind;
use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::eth::state::StateOverridesBuilder;
use alloy::rpc::types::eth::{Transaction, TransactionInput, TransactionRequest};

impl StrategyExecutor {
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
                tracing::debug!(
                    target: "strategy",
                    from=?from,
                    tx_hash=?tx_hash,
                    "Skipped item"
                );
                self.stats
                    .skipped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    fn validate_swap(
        &self,
        _router: Address,
        observed_swap: &ObservedSwap,
    ) -> Option<(SwapDirection, Address)> {
        if observed_swap.amount_in.is_zero() || !observed_swap.path.contains(&self.wrapped_native) {
            self.log_skip(
                "zero_amount_or_no_wrapped_native",
                "path missing wrapped native or zero amount",
            );
            return None;
        }

        let direction = direction(observed_swap, self.wrapped_native);
        let target_token = match target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip("decode_failed", "no target token");
                return None;
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip("toxic_token", &format!("token={:#x}", target_token));
            return None;
        }
        self.inventory_tokens.insert(target_token);
        Some((direction, target_token))
    }

    async fn evaluate_mempool_tx(
        &self,
        tx: &Transaction,
        received_at: std::time::Instant,
    ) -> Result<Option<String>, AppError> {
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

        let needed_nonces =
            1u64 + parts.front_run.is_some() as u64 + parts.approval.is_some() as u64;
        let lease = self.lease_nonces(needed_nonces).await?;

        let mut front_run = parts.front_run;
        let mut approval = parts.approval;
        let mut backrun = parts.backrun;
        let mut executor_request = parts.executor_request;
        let mut main_request = executor_request
            .clone()
            .unwrap_or_else(|| backrun.request.clone());

        Self::apply_nonce_plan(&lease, &mut front_run, &mut approval, &mut main_request)?;
        if let Some(exec) = executor_request.as_mut() {
            exec.nonce = main_request.nonce;
        }
        backrun.request.nonce = main_request.nonce;

        let victim_request = tx.clone().into_request();

        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        if let Some(f) = &front_run {
            bundle_requests.push(f.request.clone());
        }
        bundle_requests.push(victim_request.clone());
        if let Some(a) = &approval {
            bundle_requests.push(a.request.clone());
        }
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
            )
            .await?
        {
            Some(p) => p,
            None => return Ok(None),
        };
        let sim_ms = sim_start.elapsed().as_millis() as u64;
        self.stats.record_sim_latency("mempool", sim_ms);

        tracing::info!(
            target: "strategy",
            gas_limit = profit.bundle_gas_limit,
            max_fee_per_gas = parts.gas_fees.max_fee_per_gas,
            gas_cost_wei = %profit.gas_cost_wei,
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
            approval: approval.as_ref().map(|a| a.request.clone()),
            main: main_request.clone(),
            victims: vec![tx.inner.encoded_2718()],
        };
        let mut touched_pools = self.reserve_cache.pairs_for_v2_path(&observed_swap.path);
        if observed_swap.router_kind == crate::services::strategy::decode::RouterKind::V3Like {
            if let Some(v3_id) =
                StrategyExecutor::v3_pool_identifier(&observed_swap.path, &observed_swap.v3_fees)
            {
                touched_pools.push(v3_id);
            }
        }
        let plan_hashes = match self.merge_and_send_bundle(plan, touched_pools, lease).await {
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
                tx.value().to_string().as_str(),
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
                profit.profit_eth_f64,
                profit.gas_cost_eth_f64,
                profit.net_profit_eth_f64,
                &profit.gross_profit_wei.to_string(),
                &profit.gas_cost_wei.to_string(),
                &profit.net_profit_wei.to_string(),
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, profit.gross_profit_wei, profit.gas_cost_wei);

        let _ = self
            .db
            .save_market_price(
                self.chain_id,
                "ETHUSD",
                profit.eth_quote.price,
                &profit.eth_quote.source,
            )
            .await;

        let receipt_target = plan_hashes.main;
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("bundle receipt missing/failed")
                .await;
        }

        self.stats.record_bundle(BundleTelemetry {
            tx_hash: format!("{tx_hash:#x}"),
            source: "mempool".to_string(),
            profit_eth: profit.profit_eth_f64,
            gas_cost_eth: profit.gas_cost_eth_f64,
            net_eth: profit.net_profit_eth_f64,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });

        Ok(Some(format!("{tx_hash:#x}")))
    }

    async fn evaluate_mev_share_hint(
        &self,
        hint: &MevShareHint,
        received_at: std::time::Instant,
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

        let needed_nonces =
            1u64 + parts.front_run.is_some() as u64 + parts.approval.is_some() as u64;
        let lease = self.lease_nonces(needed_nonces).await?;

        let mut front_run = parts.front_run;
        let mut approval = parts.approval;
        let mut backrun = parts.backrun;
        let mut executor_request = parts.executor_request;
        let mut main_request = executor_request
            .clone()
            .unwrap_or_else(|| backrun.request.clone());

        Self::apply_nonce_plan(&lease, &mut front_run, &mut approval, &mut main_request)?;
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

        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        if let Some(f) = &front_run {
            bundle_requests.push(f.request.clone());
        }
        if let Some(a) = &approval {
            bundle_requests.push(a.request.clone());
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
                gas_limit_hint,
                &parts.gas_fees,
            )
            .await?
        {
            Some(p) => p,
            None => return Ok(None),
        };
        let sim_ms = sim_start.elapsed().as_millis() as u64;
        self.stats.record_sim_latency("mev_share", sim_ms);

        tracing::info!(
            target: "strategy",
            gas_limit = profit.bundle_gas_limit,
            max_fee_per_gas = parts.gas_fees.max_fee_per_gas,
            gas_cost_wei = %profit.gas_cost_wei,
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
            sandwich = front_run.is_some(),
            "MEV-Share strategy evaluation"
        );

        let tx_hash = format!("{:#x}", hint.tx_hash);

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %tx_hash,
                net_profit_eth = profit.net_profit_eth_f64,
                gross_profit_eth = profit.profit_eth_f64,
                gas_cost_eth = profit.gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(parts.attack_value_eth, self.wrapped_native),
                wallet_eth = self.amount_to_display(parts.wallet_balance, self.wrapped_native),
                path_len = observed_swap.path.len(),
                router = ?observed_swap.router,
                used_mock_balance = self.dry_run,
                profit_floor_wei = %StrategyExecutor::dynamic_profit_floor(parts.wallet_balance),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable MEV-Share bundle (not sent)"
            );
            return Ok(Some(tx_hash));
        }

        let mut bundle_body: Vec<BundleItem> = Vec::new();
        bundle_body.push(BundleItem::Hash {
            hash: tx_hash.clone(),
        });

        let mut executor_hash: Option<B256> = None;

        if let Some(f) = front_run.as_mut() {
            let fallback = f.request.access_list.clone().unwrap_or_default();
            let req = f.request.clone();
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            f.raw = raw.clone();
            f.request = signed_req;
            f.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        }

        if let Some(app) = approval.as_mut() {
            let fallback = app.request.access_list.clone().unwrap_or_default();
            let req = app.request.clone();
            let (raw, signed_req, _) = self.sign_with_access_list(req, fallback).await?;
            app.raw = raw.clone();
            app.request = signed_req;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        }

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
                profit.profit_eth_f64,
                profit.gas_cost_eth_f64,
                profit.net_profit_eth_f64,
                &profit.gross_profit_wei.to_string(),
                &profit.gas_cost_wei.to_string(),
                &profit.net_profit_wei.to_string(),
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, profit.gross_profit_wei, profit.gas_cost_wei);

        let _ = self
            .db
            .save_market_price(
                self.chain_id,
                "ETHUSD",
                profit.eth_quote.price,
                &profit.eth_quote.source,
            )
            .await;

        let receipt_target = executor_hash.unwrap_or(backrun.hash);
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("mev_share receipt missing/failed")
                .await;
        }

        self.stats.record_bundle(BundleTelemetry {
            tx_hash: tx_hash.clone(),
            source: "mev_share".to_string(),
            profit_eth: profit.profit_eth_f64,
            gas_cost_eth: profit.gas_cost_eth_f64,
            net_eth: profit.net_profit_eth_f64,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        });

        Ok(Some(tx_hash))
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
        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(&mut gas_fees, fee_hints.0, fee_hints.1);
        let dynamic_cap = gas_fees
            .suggested_max_fee_per_gas
            .map(U256::from)
            .unwrap_or(U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64));
        if U256::from(gas_fees.max_fee_per_gas) > dynamic_cap {
            self.log_skip(
                "gas_price_cap",
                &format!(
                    "max_fee_per_gas={} cap_wei={}",
                    gas_fees.max_fee_per_gas, dynamic_cap
                ),
            );
            return Ok(None);
        }

        let real_balance = self.portfolio.update_eth_balance(self.chain_id).await?;
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

        let mut attack_value_eth = U256::ZERO;
        let mut front_run: Option<FrontRunTx> = None;
        if direction == SwapDirection::BuyWithEth && self.sandwich_attacks_enabled {
            match self
                .build_front_run_tx(
                    observed_swap,
                    &gas_fees,
                    wallet_chain_balance,
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
                    self.log_skip("front_run_build_failed", &e.to_string());
                    return Ok(None);
                }
            }
        }

        let mut approval: Option<ApproveTx> = None;
        if let Some(f) = &front_run {
            if self
                .needs_approval(target_token, observed_swap.router, f.expected_tokens)
                .await?
            {
                approval = Some(
                    self.build_approval_tx(
                        target_token,
                        observed_swap.router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        0,
                    )
                    .await?,
                );
            }
        }

        let required_value = victim_value.saturating_add(attack_value_eth);
        let use_flashloan =
            self.should_use_flashloan(required_value, wallet_chain_balance, &gas_fees)
                && front_run.is_none();
        // For sizing, flashloans can extend to wallet balance plus victim value instead of a fixed 10k override.
        let trade_balance = if use_flashloan {
            wallet_chain_balance.saturating_add(victim_value)
        } else {
            wallet_chain_balance
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
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };

        let executor_request = self
            .build_executor_wrapper(approval.as_ref(), &backrun, &gas_fees, gas_limit_hint, 0)
            .await?;

        let bribe_wei = if let Some((_, req, _)) = executor_request.as_ref() {
            req.value
                .unwrap_or(U256::ZERO)
                .saturating_sub(backrun.value)
        } else {
            U256::ZERO
        };

        let sim_balance = wallet_chain_balance;

        Ok(Some(BundleParts {
            gas_fees,
            wallet_balance: wallet_chain_balance,
            sim_balance,
            attack_value_eth,
            bribe_wei,
            front_run,
            approval,
            backrun,
            executor_request: executor_request.map(|(_, req, _)| req),
        }))
    }

    fn apply_nonce_plan(
        lease: &NonceLease,
        front_run: &mut Option<FrontRunTx>,
        approval: &mut Option<ApproveTx>,
        main: &mut TransactionRequest,
    ) -> Result<(), AppError> {
        let needed = 1 + front_run.is_some() as u64 + approval.is_some() as u64;
        if needed > lease.count && lease.count != 0 {
            return Err(AppError::Strategy("nonce lease too small".into()));
        }
        let mut nonce_cursor = lease.base;
        if let Some(f) = front_run.as_mut() {
            f.request.nonce = Some(nonce_cursor);
            nonce_cursor = nonce_cursor.saturating_add(1);
        }
        if let Some(app) = approval.as_mut() {
            app.request.nonce = Some(nonce_cursor);
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
    ) -> Result<Option<ProfitOutcome>, AppError> {
        for req in bundle_requests.iter_mut() {
            self.populate_access_list(req).await;
        }
        let override_state = overrides.build();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let requests = bundle_requests.clone();
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
        if let Some(failure) = bundle_sims.iter().find(|o| !o.success) {
            let detail = failure
                .reason
                .clone()
                .unwrap_or_else(|| "bundle sim returned failure".to_string());
            self.log_skip("simulation_failed", &detail);
            return Ok(None);
        }

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
        let total_eth_in = backrun_value
            .saturating_add(attack_value_eth)
            .saturating_add(bribe_wei);

        let upfront_need = total_eth_in.saturating_add(gas_cost_wei);
        if wallet_chain_balance < upfront_need {
            self.log_skip(
                "insufficient_balance",
                &format!(
                    "need {} wei (value+bribe+gas) have {}",
                    upfront_need, wallet_chain_balance
                ),
            );
            return Ok(None);
        }
        let Some(native_out) =
            self.ensure_native_out(backrun.expected_out, backrun.expected_out_token)
        else {
            self.log_skip("profit_or_gas_guard", "non_native_expected_out");
            return Ok(None);
        };
        let gross_profit_wei = native_out.saturating_sub(total_eth_in);

        if gas_cost_wei > gross_profit_wei {
            self.log_skip("profit_or_gas_guard", "Gas > Gross Profit");
            return Ok(None);
        }

        let net_profit_wei = gross_profit_wei
            .saturating_sub(gas_cost_wei)
            .saturating_sub(backrun.flashloan_premium);
        let profit_floor = StrategyExecutor::dynamic_profit_floor_with_costs(
            wallet_chain_balance,
            gas_cost_wei,
            bribe_wei.saturating_add(backrun.flashloan_premium),
        );

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

        Ok(Some(ProfitOutcome {
            gas_used_total,
            bundle_gas_limit,
            gas_cost_wei,
            gross_profit_wei,
            net_profit_wei,
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
    approval: Option<ApproveTx>,
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
    profit_eth_f64: f64,
    gas_cost_eth_f64: f64,
    net_profit_eth_f64: f64,
    eth_quote: PriceQuote,
}

#[cfg(test)]
mod tests {
    use super::*;
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
        });
        let mut approval = Some(ApproveTx {
            raw: Vec::new(),
            request: TransactionRequest::default(),
        });
        let mut main = TransactionRequest::default();

        StrategyExecutor::apply_nonce_plan(&lease, &mut front, &mut approval, &mut main).unwrap();

        assert_eq!(front.unwrap().request.nonce, Some(7));
        assert_eq!(approval.unwrap().request.nonce, Some(8));
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
        StrategyExecutor::apply_nonce_plan(&lease, &mut None, &mut None, &mut main).unwrap();
        assert_eq!(main.nonce, Some(42));
    }
}
