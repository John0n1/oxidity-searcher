// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use crate::common::error::AppError;
use crate::domain::constants::{FLASHBOTS_MAX_BYTES, FLASHBOTS_MAX_TXS};
use crate::services::strategy::strategy::StrategyExecutor;
use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::network::TxSignerSync;
use alloy::primitives::{Address, B256, TxKind, U256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::TransactionInput;
use alloy::rpc::types::eth::TransactionRequest;
use alloy_consensus::TxEnvelope;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::sleep;

pub const BUNDLE_DEBOUNCE_MS: u64 = 5;

fn bundle_bytes(bundle: &[Vec<u8>]) -> usize {
    bundle.iter().map(|b| b.len()).sum()
}

#[derive(Clone)]
pub struct BundlePlan {
    pub front_run: Option<TransactionRequest>,
    pub approvals: Vec<TransactionRequest>,
    pub main: TransactionRequest,
    pub victims: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct PlanHashes {
    pub front_run: Option<B256>,
    pub approvals: Vec<B256>,
    pub main: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceLease {
    pub block: u64,
    pub base: u64,
    pub count: u64,
}

impl NonceLease {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.count)
    }
}

pub struct BundleState {
    pub block: u64,
    pub next_nonce: u64,
    pub raw: Vec<Vec<u8>>,
    pub touched_pools: HashSet<Address>,
    pub send_pending: bool,
}

impl BundleState {
    pub(crate) fn new(block: u64, next_nonce: u64) -> Self {
        Self::with_touched(block, next_nonce, HashSet::new())
    }

    pub(crate) fn with_touched(
        block: u64,
        next_nonce: u64,
        touched_pools: HashSet<Address>,
    ) -> Self {
        Self {
            block,
            next_nonce,
            raw: Vec::new(),
            touched_pools,
            send_pending: false,
        }
    }

    fn drain_for_flush(&mut self) -> (Vec<Vec<u8>>, u64, u64) {
        let flush_bundle = self.raw.clone();
        let block_for_flush = self.block;
        let next_nonce_flush = self.next_nonce;
        // Clear current buffer before releasing lock to avoid duplicate sends via scheduler.
        self.raw.clear();
        self.touched_pools.clear();
        self.send_pending = false;
        (flush_bundle, block_for_flush, next_nonce_flush)
    }
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
        // We only need access lists for our own signed txs. Victim txs can have fee envelopes
        // that are invalid against the node's current base fee, which causes noisy
        // `eth_createAccessList` failures on some clients.
        if req.from != Some(self.signer.address()) {
            return;
        }

        // Access list derivation is fee-agnostic; strip fee fields in the probe request so
        // Nethermind does not reject low-fee envelopes (`miner premium is negative`).
        let mut probe_req = req.clone();
        probe_req.gas_price = None;
        probe_req.max_fee_per_gas = None;
        probe_req.max_priority_fee_per_gas = None;

        match self.http_provider.create_access_list(&probe_req).await {
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
        let input_bytes = request.input.clone().into_input().unwrap_or_default();

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

    async fn flush_pending_bundle(
        &self,
        flush_bundle: &[Vec<u8>],
        dry_run_message: &str,
    ) -> Result<(), AppError> {
        if self.dry_run {
            tracing::info!(
                target: "bundle_merge",
                txs = flush_bundle.len(),
                bytes = bundle_bytes(flush_bundle),
                "{dry_run_message}"
            );
            return Ok(());
        }
        self.bundle_sender
            .send_bundle(flush_bundle, self.chain_id)
            .await
            .map_err(|e| AppError::Strategy(format!("Flush bundle failed: {e}")))?;
        Ok(())
    }

    async fn sign_planned_request(
        &self,
        mut request: TransactionRequest,
        nonce_cursor: &mut u64,
        lease_end: u64,
        nonce_label: &str,
    ) -> Result<(Vec<u8>, B256), AppError> {
        let next = request.nonce.unwrap_or(*nonce_cursor);
        if next < *nonce_cursor || next >= lease_end {
            return Err(AppError::Strategy(format!(
                "{nonce_label} nonce outside lease"
            )));
        }
        *nonce_cursor = next;
        request.nonce = Some(*nonce_cursor);
        let fallback = request.access_list.clone().unwrap_or_default();
        let (raw, _, hash) = self.sign_with_access_list(request, fallback).await?;
        *nonce_cursor = nonce_cursor.saturating_add(1);
        Ok((raw, hash))
    }

    pub async fn merge_and_send_bundle(
        &self,
        plan: BundlePlan,
        touched_pools: Vec<Address>,
        lease: NonceLease,
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
            *state_guard = Some(BundleState::new(block, lease.end()));
        } else if let Some(state) = state_guard.as_mut() {
            state.next_nonce = state.next_nonce.max(lease.end());
        }

        let conflict = {
            let Some(state) = state_guard.as_ref() else {
                return Err(AppError::Strategy(
                    "bundle state missing while checking pool conflicts".into(),
                ));
            };
            touched_pools
                .iter()
                .copied()
                .find(|pool| state.touched_pools.contains(pool))
        };
        if let Some(pool) = conflict {
            tracing::warn!(
                target: "bundle_merge",
                pool = %format!("{:#x}", pool),
                "Pool conflict; flushing pending bundle before merge"
            );
            let (flush_bundle, block_for_flush, next_nonce_flush) = {
                let Some(state) = state_guard.as_mut() else {
                    return Err(AppError::Strategy(
                        "bundle state missing while flushing conflicting pools".into(),
                    ));
                };
                if state.raw.is_empty() {
                    return Ok(None);
                }
                state.drain_for_flush()
            };
            drop(state_guard);

            self.flush_pending_bundle(
                &flush_bundle,
                "Dry-run: would flush bundle due to pool conflict",
            )
            .await?;

            state_guard = self.bundle_state.lock().await;
            *state_guard = Some(BundleState::new(block_for_flush, next_nonce_flush));
        }

        let mut nonce = lease.base;
        let lease_end = lease.end();
        let mut hashes = PlanHashes::default();
        let mut new_raw: Vec<Vec<u8>> = Vec::new();

        // Approvals must precede any tx that depends on them (front-run/backrun).
        for approval in plan.approvals {
            let (raw, hash) = self
                .sign_planned_request(approval, &mut nonce, lease_end, "approval")
                .await?;
            hashes.approvals.push(hash);
            new_raw.push(raw);
        }

        if let Some(fr) = plan.front_run {
            let (raw, hash) = self
                .sign_planned_request(fr, &mut nonce, lease_end, "front-run")
                .await?;
            hashes.front_run = Some(hash);
            new_raw.push(raw);
        }

        for victim in plan.victims {
            new_raw.push(victim);
        }

        let (raw, hash) = self
            .sign_planned_request(plan.main, &mut nonce, lease_end, "main")
            .await?;
        hashes.main = hash;
        new_raw.push(raw);

        if nonce > lease_end {
            return Err(AppError::Strategy(
                "nonce lease exhausted while building bundle".into(),
            ));
        }

        let new_raw_bytes = bundle_bytes(&new_raw);
        if new_raw.len() > FLASHBOTS_MAX_TXS || new_raw_bytes > FLASHBOTS_MAX_BYTES {
            return Err(AppError::Strategy(
                "Single merge would exceed Flashbots bundle limits".into(),
            ));
        }

        // If adding this plan would overflow builder limits, flush existing bundle first.
        let Some(state) = state_guard.as_mut() else {
            return Err(AppError::Strategy(
                "bundle state missing while enforcing bundle limits".into(),
            ));
        };
        let combined_txs = state.raw.len().saturating_add(new_raw.len());
        let combined_bytes = bundle_bytes(&state.raw).saturating_add(new_raw_bytes);
        if (combined_txs > FLASHBOTS_MAX_TXS || combined_bytes > FLASHBOTS_MAX_BYTES)
            && !state.raw.is_empty()
        {
            let (flush_bundle, block_for_flush, next_nonce_flush) = state.drain_for_flush();
            drop(state_guard);

            self.flush_pending_bundle(
                &flush_bundle,
                "Dry-run: would flush bundle before exceeding limits",
            )
            .await?;

            // Re-establish state after flush
            state_guard = self.bundle_state.lock().await;
            *state_guard = Some(BundleState::new(block_for_flush, next_nonce_flush));
        }

        let Some(state) = state_guard.as_mut() else {
            return Err(AppError::Strategy(
                "bundle state missing while finalizing merge".into(),
            ));
        };

        state.next_nonce = state.next_nonce.max(nonce.max(lease_end));
        state.raw.extend(new_raw);
        for pool in touched_pools {
            state.touched_pools.insert(pool);
        }
        // Persist state so a restart does not re-use nonces or pools.
        self.persist_nonce_state(state.block, state.next_nonce, &state.touched_pools)
            .await;
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

    pub async fn lease_nonces(&self, count: u64) -> Result<NonceLease, AppError> {
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
            *guard = Some(BundleState::new(block, base_nonce));
        }
        let Some(state) = guard.as_mut() else {
            return Err(AppError::Strategy(
                "bundle state missing while leasing nonces".into(),
            ));
        };
        let start = state.next_nonce;
        if count > 0 {
            state.next_nonce = state.next_nonce.saturating_add(count);
        }
        // Persist reservation so restart does not double-spend nonces.
        self.persist_nonce_state(state.block, state.next_nonce, &state.touched_pools)
            .await;
        Ok(NonceLease {
            block,
            base: start,
            count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::strategy::execution::strategy::dummy_executor_for_tests;
    use alloy::primitives::address;

    fn request_with_nonce(nonce: u64, to: Address) -> TransactionRequest {
        TransactionRequest {
            to: Some(TxKind::Call(to)),
            nonce: Some(nonce),
            gas: Some(21_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn approvals_precede_front_run_and_victim() {
        let exec = dummy_executor_for_tests().await;

        let lease = NonceLease {
            block: 1,
            base: 10,
            count: 4,
        };
        let approval_req = TransactionRequest {
            to: Some(TxKind::Call(address!(
                "1111111111111111111111111111111111111111"
            ))),
            nonce: Some(10),
            gas: Some(21_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        };
        let front_req = TransactionRequest {
            to: Some(TxKind::Call(address!(
                "2222222222222222222222222222222222222222"
            ))),
            nonce: Some(11),
            gas: Some(21_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        };
        let victim = vec![0u8; 1];
        let main_req = TransactionRequest {
            to: Some(TxKind::Call(address!(
                "3333333333333333333333333333333333333333"
            ))),
            nonce: Some(12),
            gas: Some(21_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        };

        let plan = BundlePlan {
            front_run: Some(front_req),
            approvals: vec![approval_req],
            main: main_req,
            victims: vec![victim],
        };

        let merge = exec.merge_and_send_bundle(plan, Vec::new(), lease).await;
        let hashes = match merge {
            Ok(Some(h)) => h,
            Ok(None) => return,                     // nothing merged
            Err(AppError::Connection(_)) => return, // skip when no local RPC
            Err(e) => panic!("merge failed: {e}"),
        };

        // Approval hash should be present, and front_run should not be None, proving ordering worked.
        assert_eq!(hashes.approvals.len(), 1);
        assert!(hashes.front_run.is_some());
    }

    #[tokio::test]
    async fn approval_nonce_outside_lease_is_rejected() {
        let exec = dummy_executor_for_tests().await;
        let lease = NonceLease {
            block: 1,
            base: 10,
            count: 2,
        };
        let plan = BundlePlan {
            front_run: None,
            approvals: vec![request_with_nonce(
                12,
                address!("1111111111111111111111111111111111111111"),
            )],
            main: request_with_nonce(10, address!("3333333333333333333333333333333333333333")),
            victims: Vec::new(),
        };

        let res = exec.merge_and_send_bundle(plan, Vec::new(), lease).await;
        let err = match res {
            Ok(_) => panic!("approval nonce outside lease should fail"),
            Err(AppError::Connection(_)) => return, // skip when no local RPC
            Err(e) => e,
        };
        eprintln!("approval err: {:?}", err);
        assert!(
            matches!(err, AppError::Strategy(msg) if msg.contains("approval nonce outside lease"))
        );
    }

    #[tokio::test]
    async fn main_nonce_outside_lease_is_rejected() {
        let exec = dummy_executor_for_tests().await;
        let lease = NonceLease {
            block: 1,
            base: 10,
            count: 2,
        };
        let plan = BundlePlan {
            front_run: None,
            approvals: Vec::new(),
            main: request_with_nonce(12, address!("3333333333333333333333333333333333333333")),
            victims: Vec::new(),
        };

        let res = exec.merge_and_send_bundle(plan, Vec::new(), lease).await;
        let err = match res {
            Ok(_) => panic!("main nonce outside lease should fail"),
            Err(AppError::Connection(_)) => return, // skip when no local RPC
            Err(e) => e,
        };
        eprintln!("main err: {:?}", err);
        assert!(matches!(err, AppError::Strategy(msg) if msg.contains("main nonce outside lease")));
    }

    #[tokio::test]
    async fn single_merge_over_flashbots_tx_count_is_rejected() {
        let exec = dummy_executor_for_tests().await;
        let lease = NonceLease {
            block: 1,
            base: 10,
            count: 256,
        };
        let plan = BundlePlan {
            front_run: None,
            approvals: Vec::new(),
            main: request_with_nonce(10, address!("3333333333333333333333333333333333333333")),
            victims: vec![vec![0u8; 1]; FLASHBOTS_MAX_TXS],
        };

        let res = exec.merge_and_send_bundle(plan, Vec::new(), lease).await;
        let err = match res {
            Ok(_) => panic!("bundle larger than tx limit should fail"),
            Err(AppError::Connection(_)) => return, // skip when no local RPC
            Err(e) => e,
        };
        eprintln!("single merge err: {:?}", err);
        assert!(matches!(
            err,
            AppError::Strategy(msg) if msg.contains("Single merge would exceed Flashbots bundle limits")
        ));
    }
}
