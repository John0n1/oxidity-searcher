// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::services::strategy::routers::{ERC20, UniV2Router};
use crate::services::strategy::strategy::StrategyExecutor;
use alloy::primitives::TxKind;
use alloy::primitives::{Address, U256};
use alloy::rpc::types::eth::TransactionInput;
use alloy::sol_types::SolCall;
use std::time::Duration;

impl StrategyExecutor {
    pub async fn maybe_rebalance_inventory(&self) -> Result<(), AppError> {
        let mut guard = self.last_rebalance.lock().await;
        if guard.elapsed().as_secs() < 60 {
            return Ok(());
        }
        *guard = std::time::Instant::now();
        drop(guard);

        let routers: Vec<Address> = self.router_allowlist.iter().map(|r| *r).collect();
        if routers.is_empty() {
            return Ok(());
        }

        let tokens: Vec<Address> = self.inventory_tokens.iter().map(|t| *t).collect();
        for token in tokens.into_iter().take(2) {
            for router in routers.iter().copied().take(3) {
                if self.rebalance_token(token, router).await.is_ok() {
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn rebalance_token(&self, token: Address, router: Address) -> Result<(), AppError> {
        if token == self.wrapped_native {
            return Ok(());
        }
        if self.toxic_tokens.contains(&token) {
            return Ok(());
        }

        let erc20 = ERC20::new(token, self.http_provider.clone());
        let bal: U256 = retry_async(
            move |_| {
                let c = erc20.clone();
                async move { c.balanceOf(self.signer.address()).call().await }
            },
            2,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Strategy(format!("Inventory balance failed: {}", e)))?;
        if bal.is_zero() {
            return Ok(());
        }

        let mut gas_fees: crate::network::gas::GasFees =
            self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(&mut gas_fees, None, None);
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            return Ok(());
        }

        let router_contract = UniV2Router::new(router, self.http_provider.clone());
        let sell_path = vec![token, self.wrapped_native];
        let sell_amount = bal;
        let expected_out =
            if let Some(q) = self.reserve_cache.quote_v2_path(&sell_path, sell_amount) {
                q
            } else {
                let quote_path = sell_path.clone();
                let quote_contract = router_contract.clone();
                let quote_value = sell_amount;
                let quote: Vec<U256> = match retry_async(
                    move |_| {
                        let c = quote_contract.clone();
                        let p = quote_path.clone();
                        async move { c.getAmountsOut(quote_value, p.clone()).call().await }
                    },
                    2,
                    Duration::from_millis(100),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                };
                let Some(expected_out) = quote.last().copied() else {
                    return Ok(());
                };
                expected_out
            };

        let min_eth = U256::from(10_000_000_000_000_000u128);
        if expected_out < min_eth {
            return Ok(());
        }
        if sell_amount > U256::ZERO {
            let ratio = expected_out.saturating_mul(U256::from(1_000_000u64)) / sell_amount;
            if ratio < U256::from(1_000u64) {
                return Ok(());
            }
        }
        if !self
            .probe_v2_sell_for_toxicity(token, router, sell_amount, expected_out)
            .await?
        {
            return Ok(());
        }
        let min_out = expected_out.saturating_mul(U256::from(10_000u64 - self.slippage_bps))
            / U256::from(10_000u64);
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);

        let needs_approval = self
            .needs_approval(token, router, sell_amount)
            .await
            .unwrap_or(true);
        let reserved_nonces = 1u64 + if needs_approval { 1 } else { 0 };
        let lease = self.lease_nonces(reserved_nonces).await?;
        let mut nonce_cursor = lease.base;

        if needs_approval {
            let nonce = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
            let approval = self
                .build_approval_tx(
                    token,
                    router,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    nonce,
                )
                .await?;
            let _ = self
                .bundle_sender
                .send_bundle(&[approval.raw.clone()], self.chain_id)
                .await;
        }

        let nonce_sell = nonce_cursor;
        let gas_limit = 180_000u64;
        let calldata = router_contract
            .swapExactTokensForETH(
                sell_amount,
                min_out,
                sell_path,
                self.signer.address(),
                deadline,
            )
            .calldata()
            .to_vec();
        let mut request = alloy::rpc::types::eth::TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
            max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(U256::ZERO),
            input: TransactionInput::new(calldata.clone().into()),
            nonce: Some(nonce_sell),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let access_list = self
            .apply_access_list(
                &mut request,
                StrategyExecutor::build_access_list(router, &[token]),
            )
            .await;
        let (raw, _, _) = self.sign_with_access_list(request, access_list).await?;
        let _ = self.bundle_sender.send_bundle(&[raw], self.chain_id).await;

        Ok(())
    }

    pub async fn emergency_exit_inventory(&self, reason: &str) {
        let routers: Vec<Address> = self.router_allowlist.iter().map(|r| *r).collect();
        if routers.is_empty() {
            tracing::warn!(target: "inventory", reason=%reason, "No routers available for emergency exit");
            return;
        }

        let tokens: Vec<Address> = self.inventory_tokens.iter().map(|t| *t).collect();
        for token in tokens {
            for router in routers.iter().copied() {
                match self.rebalance_token(token, router).await {
                    Ok(_) => {
                        tracing::warn!(
                            target: "inventory",
                            reason=%reason,
                            token=%format!("{:#x}", token),
                            router=%format!("{:#x}", router),
                            "Emergency exit attempted"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "inventory",
                            reason=%reason,
                            token=%format!("{:#x}", token),
                            router=%format!("{:#x}", router),
                            error=%e,
                            "Emergency exit failed, trying next router"
                        );
                        continue;
                    }
                }
            }
        }
    }

    pub fn mark_toxic_token(&self, token: Address, reason: &str) {
        if self.toxic_tokens.insert(token) {
            tracing::warn!(
                target: "strategy",
                token = %format!("{:#x}", token),
                %reason,
                "Token marked toxic; skipping sweeps"
            );
        }
    }

    pub async fn probe_v2_sell_for_toxicity(
        &self,
        token: Address,
        router: Address,
        sell_amount: U256,
        expected_out: U256,
    ) -> Result<bool, AppError> {
        if sell_amount.is_zero() || expected_out.is_zero() {
            return Ok(false);
        }
        if self.toxic_tokens.contains(&token) {
            return Ok(false);
        }
        let approve_calldata = ERC20::new(token, self.http_provider.clone())
            .approve(router, U256::MAX)
            .calldata()
            .to_vec();
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 60);
        let sell_calldata = UniV2Router::new(router, self.http_provider.clone())
            .swapExactTokensForETH(
                sell_amount,
                U256::ZERO,
                vec![token, self.wrapped_native],
                self.signer.address(),
                deadline,
            )
            .calldata()
            .to_vec();

        let approve_req = alloy::rpc::types::eth::TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(token)),
            gas: Some(70_000),
            value: Some(U256::ZERO),
            input: TransactionInput::new(approve_calldata.into()),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let sell_req = alloy::rpc::types::eth::TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            gas: Some(self.probe_gas_limit(router)),
            value: Some(U256::ZERO),
            input: TransactionInput::new(sell_calldata.into()),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        let sims = self
            .simulator
            .simulate_bundle_requests(&[approve_req, sell_req], None)
            .await?;
        if sims.len() < 2 {
            return Ok(true);
        }
        let outcome = &sims[1];
        if !outcome.success {
            self.mark_toxic_token(token, "probe_revert");
            return Ok(false);
        }
        self.record_probe_gas(router, outcome.gas_used);

        if outcome.return_data.is_empty() {
            return Ok(true);
        }

        match UniV2Router::swapExactTokensForETHCall::abi_decode_returns(&outcome.return_data) {
            Ok(amounts) => {
                let Some(actual_out) = amounts.last() else {
                    return Ok(true);
                };
                let tolerance_bps =
                    U256::from(10_000u64 - crate::services::strategy::strategy::TAX_TOLERANCE_BPS);
                let ok = actual_out.saturating_mul(U256::from(10_000u64))
                    >= expected_out.saturating_mul(tolerance_bps);
                if !ok {
                    self.mark_toxic_token(token, "probe_output_too_low");
                }
                Ok(ok)
            }
            Err(_) => Ok(true),
        }
    }
}
