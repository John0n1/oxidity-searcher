// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::services::strategy::strategy::StrategyExecutor;
use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::network::TxSignerSync;
use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::TransactionInput;
use alloy::rpc::types::eth::TransactionRequest;
use alloy_consensus::TxEnvelope;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::sleep;

pub const BUNDLE_DEBOUNCE_MS: u64 = 5;

#[derive(Clone)]
pub struct BundlePlan {
    pub front_run: Option<TransactionRequest>,
    pub approval: Option<TransactionRequest>,
    pub main: TransactionRequest,
    pub victims: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct PlanHashes {
    pub front_run: Option<B256>,
    pub approval: Option<B256>,
    pub main: B256,
}

pub struct BundleState {
    pub block: u64,
    pub next_nonce: u64,
    pub raw: Vec<Vec<u8>>,
    pub touched_pools: HashSet<Address>,
    pub send_pending: bool,
}

impl StrategyExecutor {
    pub fn build_access_list(router: Address, tokens: &[Address]) -> AccessList {
        let mut seen = HashSet::new();
        let mut items: Vec<AccessListItem> = Vec::new();
        let push = |addr: Address, seen: &mut HashSet<Address>, items: &mut Vec<AccessListItem>| {
            if seen.insert(addr) {
                items.push(AccessListItem {
                    address: addr,
                    storage_keys: Vec::new(),
                });
            }
        };
        push(router, &mut seen, &mut items);
        for t in tokens {
            push(*t, &mut seen, &mut items);
        }
        AccessList(items)
    }

    pub async fn populate_access_list(&self, req: &mut TransactionRequest) {
        match self.http_provider.create_access_list(&req.clone()).await {
            Ok(res) => {
                let list = res.ensure_ok().map(|r| r.access_list).unwrap_or_default();
                if !list.0.is_empty() {
                    req.access_list = Some(list);
                }
            }
            Err(e) => {
                tracing::debug!(
                    target: "access_list",
                    error=%e,
                    "eth_createAccessList failed; continuing without access list"
                );
            }
        }
    }

    pub async fn apply_access_list(
        &self,
        req: &mut TransactionRequest,
        fallback: AccessList,
    ) -> AccessList {
        self.populate_access_list(req).await;
        req.access_list.clone().unwrap_or(fallback)
    }

    pub async fn sign_with_access_list(
        &self,
        mut request: TransactionRequest,
        fallback: AccessList,
    ) -> Result<(Vec<u8>, TransactionRequest, B256), AppError> {
        let access_list = self.apply_access_list(&mut request, fallback).await;

        let to = request
            .to
            .ok_or_else(|| AppError::Strategy("Missing `to` in tx request".into()))?;
        let gas = request
            .gas
            .ok_or_else(|| AppError::Strategy("Missing `gas` in tx request".into()))?;
        let value = request.value.unwrap_or_default();
        let max_fee_per_gas = request
            .max_fee_per_gas
            .ok_or_else(|| AppError::Strategy("Missing max_fee_per_gas in tx request".into()))?;
        let max_priority_fee_per_gas = request.max_priority_fee_per_gas.ok_or_else(|| {
            AppError::Strategy("Missing max_priority_fee_per_gas in tx request".into())
        })?;
        let nonce = request
            .nonce
            .ok_or_else(|| AppError::Strategy("Missing nonce in tx request".into()))?;
        let chain_id = request.chain_id.unwrap_or(self.chain_id);
        let input_bytes = request
            .input
            .clone()
            .into_input()
            .map(Bytes::from)
            .unwrap_or_default();

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: gas,
            to,
            value,
            access_list,
            input: input_bytes,
        };

        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign tx failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();
        Ok((raw, request, *signed.tx_hash()))
    }

    pub async fn sign_swap_request(
        &self,
        to: Address,
        gas_limit: u64,
        value: U256,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        nonce: u64,
        calldata: Vec<u8>,
        access_list: AccessList,
    ) -> Result<(Vec<u8>, TransactionRequest, B256), AppError> {
        let request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(to)),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(value),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        self.sign_with_access_list(request, access_list).await
    }

    pub async fn merge_and_send_bundle(
        &self,
        plan: BundlePlan,
        touched_pools: Vec<Address>,
    ) -> Result<Option<PlanHashes>, AppError> {
        let mut state_guard = self.bundle_state.lock().await;
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .map_err(|e| AppError::Connection(format!("Failed to fetch block: {}", e)))?;
        }

        if state_guard
            .as_ref()
            .map(|s| s.block != block)
            .unwrap_or(true)
        {
            let base_nonce = self.nonce_manager.get_base_nonce(block).await?;
            *state_guard = Some(BundleState {
                block,
                next_nonce: base_nonce,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }

        let state = state_guard.as_mut().unwrap();

        for pool in &touched_pools {
            if state.touched_pools.contains(pool) {
                tracing::warn!(target: "bundle_merge", pool=%format!("{:#x}", pool), "Pool conflict; skipping merge");
                return Ok(None);
            }
        }

        let mut nonce = state.next_nonce;
        let mut hashes = PlanHashes::default();
        let mut new_raw: Vec<Vec<u8>> = Vec::new();

        if let Some(mut fr) = plan.front_run {
            fr.nonce = Some(nonce);
            let fallback = fr.access_list.clone().unwrap_or_default();
            let (raw, _, hash) = self.sign_with_access_list(fr, fallback).await?;
            hashes.front_run = Some(hash);
            nonce = nonce.saturating_add(1);
            new_raw.push(raw);
        }

        for victim in plan.victims {
            new_raw.push(victim);
        }

        if let Some(mut approval) = plan.approval {
            approval.nonce = Some(nonce);
            let fallback = approval.access_list.clone().unwrap_or_default();
            let (raw, _, hash) = self.sign_with_access_list(approval, fallback).await?;
            hashes.approval = Some(hash);
            nonce = nonce.saturating_add(1);
            new_raw.push(raw);
        }

        let mut main = plan.main;
        main.nonce = Some(nonce);
        let fallback = main.access_list.clone().unwrap_or_default();
        let (raw, _, hash) = self.sign_with_access_list(main, fallback).await?;
        hashes.main = hash;
        nonce = nonce.saturating_add(1);
        new_raw.push(raw);

        state.next_nonce = nonce;
        state.raw.extend(new_raw);
        for pool in touched_pools {
            state.touched_pools.insert(pool);
        }
        let bundle_len = state.raw.len();
        drop(state_guard);

        if self.dry_run {
            tracing::info!(
                target: "executor",
                "Dry-run: would send merged bundle with {} txs",
                bundle_len
            );
            return Ok(Some(hashes));
        }

        self.schedule_bundle_send().await;

        Ok(Some(hashes))
    }

    pub async fn schedule_bundle_send(&self) {
        let mut guard = self.bundle_state.lock().await;
        let Some(state) = guard.as_mut() else {
            return;
        };
        if state.send_pending {
            return;
        }
        state.send_pending = true;

        let bundle_state = self.bundle_state.clone();
        let sender = self.bundle_sender.clone();
        let chain_id = self.chain_id;
        let dry_run = self.dry_run;

        tokio::spawn(async move {
            sleep(Duration::from_millis(BUNDLE_DEBOUNCE_MS)).await;
            let maybe_bundle = {
                let mut guard = bundle_state.lock().await;
                if let Some(state) = guard.as_mut() {
                    state.send_pending = false;
                    Some((state.block, state.raw.clone()))
                } else {
                    None
                }
            };

            if dry_run {
                if let Some((_, bundle)) = maybe_bundle {
                    tracing::info!(
                        target: "executor",
                        "Dry-run: would send merged bundle with {} txs",
                        bundle.len()
                    );
                }
                return;
            }

            if let Some((block, bundle)) = maybe_bundle {
                if bundle.is_empty() {
                    return;
                }
                if let Err(e) = sender.send_bundle(&bundle, chain_id).await {
                    tracing::error!(
                        target: "bundle_merge",
                        block,
                        error = %e,
                        "Deferred bundle send failed"
                    );
                }
            }
        });
    }

    pub async fn peek_nonce_for_sim(&self) -> Result<u64, AppError> {
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .unwrap_or_default();
        }
        if let Some(state) = self.bundle_state.lock().await.as_ref() {
            return Ok(state.next_nonce);
        }
        self.nonce_manager.get_base_nonce(block).await
    }

    pub async fn lease_nonces(&self, count: u64) -> Result<u64, AppError> {
        if count == 0 {
            return self.peek_nonce_for_sim().await;
        }
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .unwrap_or_default();
        }
        let mut guard = self.bundle_state.lock().await;
        if guard.as_ref().map(|s| s.block != block).unwrap_or(true) {
            let base_nonce = self.nonce_manager.get_base_nonce(block).await?;
            *guard = Some(BundleState {
                block,
                next_nonce: base_nonce,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }
        let state = guard.as_mut().unwrap();
        let start = state.next_nonce;
        state.next_nonce = state.next_nonce.saturating_add(count);
        Ok(start)
    }
}
