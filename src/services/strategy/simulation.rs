// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::data::executor::UnifiedHardenedExecutor;
use crate::network::provider::HttpProvider;
use alloy::primitives::{Address, TxKind, U256};
use alloy::providers::Provider;
use alloy::providers::ext::DebugApi;
use alloy::rpc::types::eth::simulate::{SimBlock, SimCallResult, SimulatePayload};
use alloy::rpc::types::eth::state::StateOverride;
use alloy::rpc::types::eth::{
    BlockId, BlockNumberOrTag, Bundle, StateContext, Transaction, TransactionRequest,
};
use alloy::rpc::types::trace::geth::{DefaultFrame, GethDebugTracingCallOptions};
use alloy::sol_types::SolInterface;
use alloy::transports::{RpcError as TransportRpcError, TransportError};
use alloy_sol_types::{Revert, SolError};
use serde_json::json;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct SimulationOutcome {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub reason: Option<String>,
}

static ETH_SIMULATE_MISSING: OnceLock<()> = OnceLock::new();
static DEBUG_TRACE_MISSING: OnceLock<()> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default)]
pub struct RpcCapabilities {
    pub fee_history: bool,
    pub eth_simulate: bool,
    pub debug_trace_call: bool,
    pub debug_trace_call_many: bool,
    pub eth_simulate_shape_ok: bool,
    pub debug_trace_call_many_shape_ok: bool,
}

#[derive(Clone, Debug)]
struct RpcErrorInfo {
    code: Option<i64>,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationBackendMethod {
    EthSimulate,
    DebugTraceCall,
    EthCall,
}

#[derive(Clone, Debug)]
pub struct SimulationBackend {
    order: Vec<SimulationBackendMethod>,
}

impl SimulationBackend {
    pub fn new(config: impl AsRef<str>) -> Self {
        let primary = SimulationBackendMethod::from_config(config.as_ref());
        Self {
            order: SimulationBackendMethod::build_order(primary),
        }
    }

    pub fn mainnet_priority() -> Self {
        Self {
            order: vec![
                SimulationBackendMethod::EthSimulate,
                SimulationBackendMethod::DebugTraceCall,
                SimulationBackendMethod::EthCall,
            ],
        }
    }

    pub fn order(&self) -> &[SimulationBackendMethod] {
        &self.order
    }
}

impl SimulationBackendMethod {
    fn from_config(config: &str) -> Self {
        for token in config
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            let lowercase = token.to_lowercase();
            match lowercase.as_str() {
                "debug" | "debug_trace" | "debug-trace" | "debugtrace" | "debug_tracecall"
                | "debugtracecall" | "trace" | "tracecall" | "trace_call" => {
                    return Self::DebugTraceCall;
                }
                "eth_call" | "ethcall" | "call" => return Self::EthCall,
                "eth_simulate" | "ethsimulate" | "eth_simulatev1" | "ethsimulatev1"
                | "simulate" | "revm" | "revmv1" | "anvil" => return Self::EthSimulate,
                _ => {}
            }
        }
        Self::EthSimulate
    }

    fn build_order(primary: Self) -> Vec<Self> {
        let mut order = Vec::with_capacity(3);
        order.push(primary);
        for candidate in &[Self::EthSimulate, Self::DebugTraceCall, Self::EthCall] {
            if *candidate != primary {
                order.push(*candidate);
            }
        }
        order
    }
}

#[derive(Clone)]
pub struct Simulator {
    provider: HttpProvider,
    backend: SimulationBackend,
}

impl Simulator {
    pub fn new(provider: HttpProvider, backend: SimulationBackend) -> Self {
        Self { provider, backend }
    }

    async fn probe_eth_simulate_v1_internal(&self) -> bool {
        if ETH_SIMULATE_MISSING.get().is_some() {
            return false;
        }
        let req = TransactionRequest {
            from: Some(Address::ZERO),
            to: Some(TxKind::Call(Address::ZERO)),
            value: Some(U256::ZERO),
            ..Default::default()
        };

        let block = SimBlock {
            block_overrides: None,
            state_overrides: None,
            calls: vec![req],
        };
        let payload = SimulatePayload {
            block_state_calls: vec![block],
            trace_transfers: false,
            validation: false,
            return_full_transactions: false,
        };

        match self.provider.simulate(&payload).await {
            Ok(_) => {
                tracing::info!(target: "simulation", "✔ eth_simulateV1 available");
                true
            }
            Err(e) => {
                if rpc_method_unavailable(&e) {
                    let _ = ETH_SIMULATE_MISSING.set(());
                    tracing::warn!(
                        target: "simulation",
                        "eth_simulateV1 not available on node; falling back"
                    );
                    false
                } else {
                    tracing::warn!(
                        target: "simulation",
                        error = %e,
                        "eth_simulateV1 probe failed; falling back"
                    );
                    false
                }
            }
        }
    }

    async fn probe_eth_simulate_shape_internal(&self) -> bool {
        let params = json!([
            {
                "blockStateCalls": [
                    {
                        "calls": [
                            {
                                "from": format!("{:#x}", Address::ZERO),
                                "to": format!("{:#x}", Address::ZERO),
                                "value": "0x0"
                            }
                        ]
                    }
                ],
                "traceTransfers": false,
                "validation": false,
                "returnFullTransactions": false
            },
            "latest"
        ]);
        let result: Result<serde_json::Value, TransportError> = self
            .provider
            .raw_request("eth_simulateV1".into(), params)
            .await;
        match result {
            Ok(value) => value.is_array(),
            Err(e) => !rpc_method_unavailable(&e),
        }
    }

    async fn probe_debug_trace_call_internal(&self) -> bool {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return false;
        }
        let req = TransactionRequest {
            from: Some(Address::ZERO),
            to: Some(TxKind::Call(Address::ZERO)),
            value: Some(U256::ZERO),
            ..Default::default()
        };
        let block = BlockId::Number(BlockNumberOrTag::Pending);
        let trace_options = GethDebugTracingCallOptions::default();
        match self
            .provider
            .debug_trace_call(req, block, trace_options)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                if rpc_method_unavailable(&e) {
                    let _ = DEBUG_TRACE_MISSING.set(());
                    tracing::warn!(
                        target: "simulation",
                        "debug_traceCall not available on node; falling back"
                    );
                    false
                } else {
                    tracing::debug!(
                        target: "simulation",
                        error = %e,
                        "debug_traceCall probe failed"
                    );
                    false
                }
            }
        }
    }

    async fn probe_debug_trace_many_shape_internal(&self) -> bool {
        let params = json!([
            [
                {
                    "transactions": [
                        {
                            "from": format!("{:#x}", Address::ZERO),
                            "to": format!("{:#x}", Address::ZERO),
                            "value": "0x0"
                        }
                    ]
                }
            ],
            "latest",
            {}
        ]);
        let result: Result<serde_json::Value, TransportError> = self
            .provider
            .raw_request("debug_traceCallMany".into(), params)
            .await;
        match result {
            Ok(value) => value.is_array(),
            Err(e) => !rpc_method_unavailable(&e),
        }
    }

    async fn probe_debug_trace_many_internal(&self) -> bool {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return false;
        }
        let req = TransactionRequest {
            from: Some(Address::ZERO),
            to: Some(TxKind::Call(Address::ZERO)),
            value: Some(U256::ZERO),
            ..Default::default()
        };
        let bundle = Bundle::from(vec![req]);
        let context = StateContext {
            block_number: Some(BlockId::Number(BlockNumberOrTag::Pending)),
            transaction_index: None,
        };
        let trace_options = GethDebugTracingCallOptions::default();
        match self
            .provider
            .debug_trace_call_many(vec![bundle], context, trace_options)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                if rpc_method_unavailable(&e) {
                    let _ = DEBUG_TRACE_MISSING.set(());
                    tracing::warn!(
                        target: "simulation",
                        "debug_traceCallMany not available on node; falling back"
                    );
                    false
                } else {
                    tracing::debug!(
                        target: "simulation",
                        error = %e,
                        "debug_traceCallMany probe failed"
                    );
                    false
                }
            }
        }
    }

    async fn probe_fee_history_internal(&self) -> bool {
        self.provider
            .get_fee_history(1, BlockNumberOrTag::Latest, &[50.0f64])
            .await
            .is_ok()
    }

    pub async fn probe_capabilities(&self) -> RpcCapabilities {
        let fee_history = self.probe_fee_history_internal().await;
        let eth_simulate = self.probe_eth_simulate_v1_internal().await;
        let debug_trace_call = self.probe_debug_trace_call_internal().await;
        let debug_trace_call_many = self.probe_debug_trace_many_internal().await;
        let eth_simulate_shape_ok = if eth_simulate {
            self.probe_eth_simulate_shape_internal().await
        } else {
            false
        };
        let debug_trace_call_many_shape_ok = if debug_trace_call_many {
            self.probe_debug_trace_many_shape_internal().await
        } else {
            false
        };
        tracing::info!(
            target: "simulation",
            fee_history,
            eth_simulate,
            debug_trace_call,
            debug_trace_call_many,
            eth_simulate_shape_ok,
            debug_trace_call_many_shape_ok,
            "RPC simulation capabilities"
        );
        RpcCapabilities {
            fee_history,
            eth_simulate,
            debug_trace_call,
            debug_trace_call_many,
            eth_simulate_shape_ok,
            debug_trace_call_many_shape_ok,
        }
    }

    pub async fn probe_eth_simulate_v1(&self) {
        let _ = self.probe_eth_simulate_v1_internal().await;
    }

    pub async fn simulate_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SimulationOutcome, AppError> {
        let req = tx.clone().into_request();
        self.simulate_request(req, None).await
    }

    pub async fn simulate_request(
        &self,
        req: TransactionRequest,
        state_override: Option<StateOverride>,
    ) -> Result<SimulationOutcome, AppError> {
        for method in self.backend.order() {
            let outcome_opt = self
                .try_simulation_method(req.clone(), state_override.clone(), *method)
                .await?;
            if let Some(outcome) = outcome_opt {
                return Ok(outcome);
            }
        }
        self.simulate_request_with_eth_call(req).await
    }

    async fn try_simulation_method(
        &self,
        req: TransactionRequest,
        state_override: Option<StateOverride>,
        method: SimulationBackendMethod,
    ) -> Result<Option<SimulationOutcome>, AppError> {
        match method {
            SimulationBackendMethod::EthSimulate => {
                self.simulate_request_with_eth_simulate(req, state_override)
                    .await
            }
            SimulationBackendMethod::DebugTraceCall => {
                self.simulate_request_with_debug_trace(req).await
            }
            SimulationBackendMethod::EthCall => {
                Ok(Some(self.simulate_request_with_eth_call(req).await?))
            }
        }
    }

    async fn simulate_request_with_eth_simulate(
        &self,
        req: TransactionRequest,
        state_override: Option<StateOverride>,
    ) -> Result<Option<SimulationOutcome>, AppError> {
        if ETH_SIMULATE_MISSING.get().is_some() {
            return Ok(None);
        }
        let block = SimBlock {
            block_overrides: None,
            state_overrides: state_override.clone(),
            calls: vec![req.clone()],
        };
        let payload = SimulatePayload {
            block_state_calls: vec![block],
            trace_transfers: false,
            validation: false,
            return_full_transactions: false,
        };

        match self.provider.simulate(&payload).await {
            Ok(simulated) => {
                if let Some(call) = simulated.first().and_then(|blk| blk.calls.first()) {
                    return Ok(Some(sim_call_result_to_outcome(call)));
                }
            }
            Err(e) => {
                let rpc_code = rpc_error_info(&e).code;
                if rpc_method_unavailable(&e) {
                    if ETH_SIMULATE_MISSING.set(()).is_ok() {
                        tracing::warn!(
                            target: "simulation",
                            "eth_simulateV1 not available on node; falling back"
                        );
                    }
                } else if rpc_insufficient_sender_balance(&e) {
                    tracing::debug!(
                        target: "simulation",
                        backend = "eth_simulate",
                        rpc_code = rpc_code,
                        error = %e,
                        "simulate_request eth_simulate insufficient sender balance"
                    );
                } else {
                    tracing::warn!(
                        target: "simulation",
                        backend = "eth_simulate",
                        rpc_code = rpc_code,
                        error = %e,
                        "simulate_request eth_simulate failed"
                    );
                }
            }
        }
        Ok(None)
    }

    async fn simulate_request_with_debug_trace(
        &self,
        req: TransactionRequest,
    ) -> Result<Option<SimulationOutcome>, AppError> {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return Ok(None);
        }
        let trace_options = GethDebugTracingCallOptions::default();
        let block = BlockId::Number(BlockNumberOrTag::Pending);
        match self
            .provider
            .debug_trace_call(req.clone(), block, trace_options)
            .await
        {
            Ok(trace) => match trace.try_into_default_frame() {
                Ok(frame) => Ok(Some(default_frame_to_outcome(frame))),
                Err(err) => {
                    tracing::warn!(
                        target: "simulation",
                        backend = "debug_trace_call",
                        error = ?err,
                        "unexpected trace frame"
                    );
                    Ok(None)
                }
            },
            Err(e) => {
                let rpc_code = rpc_error_info(&e).code;
                if rpc_method_unavailable(&e) {
                    if DEBUG_TRACE_MISSING.set(()).is_ok() {
                        tracing::warn!(
                            target: "simulation",
                            "debug_traceCall not available on node; falling back"
                        );
                    }
                    Ok(None)
                } else {
                    tracing::warn!(
                        target: "simulation",
                        backend = "debug_trace_call",
                        rpc_code = rpc_code,
                        error = %e,
                        "debug_trace_call failed"
                    );
                    Ok(None)
                }
            }
        }
    }

    async fn simulate_request_with_eth_call(
        &self,
        req: TransactionRequest,
    ) -> Result<SimulationOutcome, AppError> {
        let gas_used = match self.provider.estimate_gas(req.clone()).await {
            Ok(g) => g,
            Err(e) => {
                let msg = format!("estimate_gas failed: {e}");
                return Ok(SimulationOutcome {
                    success: false,
                    gas_used: 0,
                    return_data: msg.clone().into_bytes(),
                    reason: Some(msg),
                });
            }
        };

        let call_res = self.provider.call(req).await;
        let (success, return_data, reason) = match call_res {
            Ok(bytes) => (true, bytes.to_vec(), None),
            Err(e) => {
                let msg = format!("eth_call failed: {e}");
                // This path does not reliably expose raw ABI revert bytes; decoding the provider
                // message as revert payload turns clear RPC errors into noisy hex output.
                (false, msg.clone().into_bytes(), Some(msg))
            }
        };

        Ok(SimulationOutcome {
            success,
            gas_used,
            return_data,
            reason,
        })
    }

    pub async fn simulate_bundle(
        &self,
        txs: &[Transaction],
        state_override: Option<StateOverride>,
    ) -> Result<Vec<SimulationOutcome>, AppError> {
        let reqs: Vec<TransactionRequest> = txs.iter().cloned().map(|t| t.into_request()).collect();
        self.simulate_bundle_requests(&reqs, state_override).await
    }

    pub async fn simulate_bundle_requests(
        &self,
        txs: &[TransactionRequest],
        state_override: Option<StateOverride>,
    ) -> Result<Vec<SimulationOutcome>, AppError> {
        if txs.is_empty() {
            return Ok(Vec::new());
        }

        for method in self.backend.order() {
            match method {
                SimulationBackendMethod::EthSimulate => {
                    if let Some(outcomes) = self
                        .try_bundle_with_eth_simulate(txs, state_override.clone())
                        .await?
                    {
                        if outcomes.len() != txs.len() {
                            tracing::warn!(
                                target: "simulation",
                                backend = "eth_simulate",
                                expected = txs.len(),
                                got = outcomes.len(),
                                "bundle simulation outcome count mismatch; falling back"
                            );
                            continue;
                        }
                        return Ok(outcomes);
                    }
                }
                SimulationBackendMethod::DebugTraceCall => {
                    if let Some(outcomes) = self.try_bundle_with_debug_trace(txs).await? {
                        if outcomes.len() != txs.len() {
                            tracing::warn!(
                                target: "simulation",
                                backend = "debug_trace_call_many",
                                expected = txs.len(),
                                got = outcomes.len(),
                                "bundle simulation outcome count mismatch; falling back"
                            );
                            continue;
                        }
                        return Ok(outcomes);
                    }
                }
                SimulationBackendMethod::EthCall => {
                    if txs.len() > 1 {
                        return Ok(non_stateful_eth_call_bundle_outcomes(txs.len()));
                    }
                    let mut outcomes = Vec::with_capacity(txs.len());
                    for tx in txs {
                        outcomes.push(self.simulate_request_with_eth_call(tx.clone()).await?);
                    }
                    return Ok(outcomes);
                }
            }
        }

        if txs.len() > 1 {
            return Ok(non_stateful_eth_call_bundle_outcomes(txs.len()));
        }

        let mut outcomes = Vec::with_capacity(txs.len());
        for tx in txs {
            outcomes.push(self.simulate_request_with_eth_call(tx.clone()).await?);
        }
        Ok(outcomes)
    }

    async fn try_bundle_with_eth_simulate(
        &self,
        txs: &[TransactionRequest],
        state_override: Option<StateOverride>,
    ) -> Result<Option<Vec<SimulationOutcome>>, AppError> {
        if ETH_SIMULATE_MISSING.get().is_some() {
            return Ok(None);
        }
        let block = SimBlock {
            block_overrides: None,
            state_overrides: state_override.clone(),
            calls: txs.to_vec(),
        };
        let payload = SimulatePayload {
            block_state_calls: vec![block],
            trace_transfers: false,
            validation: false,
            return_full_transactions: false,
        };

        match self.provider.simulate(&payload).await {
            Ok(blocks) => {
                let mut outcomes = Vec::new();
                for blk in blocks {
                    for call in &blk.calls {
                        outcomes.push(sim_call_result_to_outcome(call));
                    }
                }
                if outcomes.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(outcomes))
                }
            }
            Err(e) => {
                let rpc_code = rpc_error_info(&e).code;
                if rpc_method_unavailable(&e) && ETH_SIMULATE_MISSING.set(()).is_ok() {
                    tracing::warn!(
                        target: "simulation",
                        "eth_simulateV1 unavailable for bundles; cached fallback"
                    );
                }
                if rpc_insufficient_sender_balance(&e) {
                    tracing::debug!(
                        target: "simulation",
                        backend = "eth_simulate",
                        rpc_code = rpc_code,
                        error = %e,
                        "simulate_bundle_requests insufficient sender balance"
                    );
                } else {
                    tracing::warn!(
                        target: "simulation",
                        backend = "eth_simulate",
                        rpc_code = rpc_code,
                        error = %e,
                        "simulate_bundle_requests failed"
                    );
                }
                Ok(None)
            }
        }
    }

    async fn try_bundle_with_debug_trace(
        &self,
        txs: &[TransactionRequest],
    ) -> Result<Option<Vec<SimulationOutcome>>, AppError> {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return Ok(None);
        }
        if txs.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let bundle = Bundle::from(txs.to_vec());
        let context = StateContext {
            block_number: Some(BlockId::Number(BlockNumberOrTag::Pending)),
            transaction_index: None,
        };
        let trace_options = GethDebugTracingCallOptions::default();

        match self
            .provider
            .debug_trace_call_many(vec![bundle], context, trace_options)
            .await
        {
            Ok(traces) => {
                if traces.is_empty() {
                    return Ok(None);
                }
                let mut outcomes = Vec::new();
                for trace_set in traces {
                    for trace in trace_set {
                        match trace.try_into_default_frame() {
                            Ok(frame) => outcomes.push(default_frame_to_outcome(frame)),
                            Err(err) => {
                                tracing::warn!(
                                    target: "simulation",
                                    backend = "debug_trace_call",
                                    error = ?err,
                                    "unexpected trace frame in bundle"
                                );
                                return Ok(None);
                            }
                        }
                    }
                }
                Ok(Some(outcomes))
            }
            Err(e) => {
                let rpc_code = rpc_error_info(&e).code;
                if rpc_method_unavailable(&e) && DEBUG_TRACE_MISSING.set(()).is_ok() {
                    tracing::warn!(
                        target: "simulation",
                        "debug_traceCallMany unavailable; cached fallback"
                    );
                }
                tracing::warn!(
                    target: "simulation",
                    backend = "debug_trace_call",
                    rpc_code = rpc_code,
                    error = %e,
                    "debug_trace_call_many failed"
                );
                Ok(None)
            }
        }
    }
}

fn non_stateful_eth_call_bundle_outcomes(count: usize) -> Vec<SimulationOutcome> {
    let reason = "eth_call fallback is non-stateful for multi-tx bundles; treating as failed simulation".to_string();
    tracing::warn!(
        target: "simulation",
        tx_count = count,
        "eth_call fallback cannot safely simulate multi-transaction bundles"
    );
    (0..count)
        .map(|_| SimulationOutcome {
            success: false,
            gas_used: 0,
            return_data: reason.as_bytes().to_vec(),
            reason: Some(reason.clone()),
        })
        .collect()
}

fn parse_rpc_error_from_text(text: &str) -> Option<RpcErrorInfo> {
    let parsed: serde_json::Value = serde_json::from_str(text).ok()?;
    if let Some(err) = parsed.get("error") {
        let code = err.get("code").and_then(|v| v.as_i64());
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        return Some(RpcErrorInfo { code, message });
    }
    let code = parsed.get("code").and_then(|v| v.as_i64());
    let message = parsed
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Some(RpcErrorInfo { code, message })
}

fn rpc_error_info(err: &TransportError) -> RpcErrorInfo {
    match err {
        TransportRpcError::ErrorResp(payload) => RpcErrorInfo {
            code: Some(payload.code),
            message: payload.message.to_string(),
        },
        TransportRpcError::DeserError { text, .. } => parse_rpc_error_from_text(text)
            .unwrap_or_else(|| RpcErrorInfo {
                code: None,
                message: err.to_string(),
            }),
        _ => RpcErrorInfo {
            code: None,
            message: err.to_string(),
        },
    }
}

fn rpc_method_unavailable(err: &TransportError) -> bool {
    let info = rpc_error_info(err);
    if matches!(info.code, Some(-32601)) {
        return true;
    }
    rpc_method_unavailable_message(&info.message)
}

fn rpc_insufficient_sender_balance(err: &TransportError) -> bool {
    let info = rpc_error_info(err);
    if matches!(info.code, Some(-38014)) {
        return true;
    }
    rpc_insufficient_sender_balance_message(&info.message)
}

fn rpc_method_unavailable_message(msg: &str) -> bool {
    let msg = msg.to_lowercase();
    (msg.contains("method") && msg.contains("not found"))
        || (msg.contains("namespace") && msg.contains("disabled"))
}

fn rpc_insufficient_sender_balance_message(msg: &str) -> bool {
    let msg = msg.to_lowercase();
    (msg.contains("insufficient") && msg.contains("sender balance"))
        || msg.contains("insufficient maxfeepergas for sender balance")
        || msg.contains("error code -38014")
}

fn sim_call_result_to_outcome(call: &SimCallResult) -> SimulationOutcome {
    let success = call.error.is_none() && call.status;
    if !success {
        tracing::debug!(
            target: "simulation",
            "Simulation Revert Reason: {}",
            decode_flashloan_revert(&call.return_data)
        );
    }
    let reason = if success {
        None
    } else {
        call.error.as_ref().map(|e| format!("{:?}", e)).or_else(|| {
            if call.return_data.is_empty() {
                None
            } else {
                Some(decode_flashloan_revert(&call.return_data))
            }
        })
    };
    SimulationOutcome {
        success,
        gas_used: call.gas_used,
        return_data: call.return_data.to_vec(),
        reason,
    }
}

fn default_frame_to_outcome(frame: DefaultFrame) -> SimulationOutcome {
    let success = !frame.failed;
    if !success {
        tracing::debug!(
            target: "simulation",
            "Simulation Revert Reason: {}",
            decode_flashloan_revert(&frame.return_value)
        );
    }
    let reason = if success {
        None
    } else {
        Some(decode_flashloan_revert(&frame.return_value))
    };
    SimulationOutcome {
        success,
        gas_used: frame.gas,
        return_data: frame.return_value.to_vec(),
        reason,
    }
}

pub fn decode_flashloan_revert(revert_data: &[u8]) -> String {
    if revert_data.is_empty() {
        return "Reverted with no data (OOG or empty)".to_string();
    }

    if let Ok(decoded) =
        UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::abi_decode(revert_data)
    {
        #[allow(unreachable_patterns)]
        return match decoded {
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InsufficientFundsForRepayment(
                e,
            ) => format!(
                "📉 INSOLVENT: Needed {} of token {:?}, but only had {}",
                e.required, e.token, e.available
            ),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ExecutionFailed(e) => {
                let inner_msg = String::from_utf8(e.reason.to_vec())
                    .unwrap_or_else(|_| format!("0x{}", hex::encode(&e.reason)));
                format!("💥 STRATEGY FAILED at index {}: {}", e.index, inner_msg)
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::LengthMismatch(_) => {
                "🚫 Array Length Mismatch".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ZeroAssets(_) => {
                "🚫 Zero Assets requested".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::TokenTransferFailed(_) => {
                "🔒 Token Transfer Failed (USDT?)".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ApprovalFailed(_) => {
                "🔒 Approval failed (USDT-style)".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidWETHAddress(_) => {
                "🚫 Invalid WETH address".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidProfitReceiver(_) => {
                "🚫 Invalid profit receiver".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BribeFailed(_) => {
                "💰 Bribe payment failed".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalanceInvariantBroken(e) => format!(
                "🔒 Balance invariant broke for token {:?}: before {}, after {}",
                e.token, e.beforeBalance, e.afterBalance
            ),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyOwner(_) => {
                "🚫 Caller is not owner".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyVault(_) => {
                "🚫 Caller is not Balancer Vault".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyPool(_) => {
                "🚫 Caller is not configured Aave pool".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidPool(_) => {
                "🚫 Invalid Aave pool address".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidAsset(_) => {
                "🚫 Invalid flashloan asset".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidBalancerVault(_) => {
                "🚫 Invalid Balancer vault address".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalancerTokensNotSorted(e) => {
                format!(
                    "🚫 Balancer tokens must be sorted ascending (idx {}, prev {:?}, current {:?})",
                    e.index, e.previous, e.current
                )
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalancerLoanNotActive(_) => {
                "🚫 Balancer callback without active loan".to_string()
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalancerLoanContextMismatch(
                _,
            ) => "🚫 Balancer callback context mismatch".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalancerCallbackNotReceived(
                _,
            ) => "🚫 Balancer callback not received (bad vault or no-op call)".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::AaveCallbackNotReceived(_) => {
                "🚫 Aave callback not received (bad pool or no-op call)".to_string()
            }
            _ => "Reverted with known custom error".to_string(),
        };
    }

    if let Ok(msg) = Revert::abi_decode(revert_data) {
        return format!("Standard Revert: {}", msg.reason());
    }

    format!("Unknown Revert: 0x{}", hex::encode(revert_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256};
    use alloy::rpc::types::eth::simulate::SimulateError;
    use alloy_sol_types::SolError;

    #[test]
    fn backend_config_respects_first_known_token_and_order() {
        let backend = SimulationBackend::new("debug,eth_call");
        assert_eq!(
            backend.order(),
            &[
                SimulationBackendMethod::DebugTraceCall,
                SimulationBackendMethod::EthSimulate,
                SimulationBackendMethod::EthCall
            ]
        );

        let backend = SimulationBackend::new("eth_call debug");
        assert_eq!(
            backend.order(),
            &[
                SimulationBackendMethod::EthCall,
                SimulationBackendMethod::EthSimulate,
                SimulationBackendMethod::DebugTraceCall
            ]
        );
    }

    #[test]
    fn backend_config_defaults_to_eth_simulate_for_unknown_config() {
        let backend = SimulationBackend::new("not_a_backend");
        assert_eq!(backend.order()[0], SimulationBackendMethod::EthSimulate);
    }

    #[test]
    fn decodes_insufficient_funds_error() {
        let err =
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InsufficientFundsForRepayment(
                UnifiedHardenedExecutor::InsufficientFundsForRepayment {
                    token: Address::from([1u8; 20]),
                    required: U256::from(10u64),
                    available: U256::from(5u64),
                },
            );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("INSOLVENT"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn decodes_execution_failed_error() {
        let reason = b"boom".to_vec();
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ExecutionFailed(
            UnifiedHardenedExecutor::ExecutionFailed {
                index: U256::from(2u64),
                reason: reason.clone().into(),
            },
        );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("boom"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn decodes_balance_invariant_broken() {
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalanceInvariantBroken(
            UnifiedHardenedExecutor::BalanceInvariantBroken {
                token: Address::from([9u8; 20]),
                beforeBalance: U256::from(100u64),
                afterBalance: U256::from(50u64),
            },
        );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("Balance invariant"));
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn decodes_empty_revert() {
        let msg = decode_flashloan_revert(&[]);
        assert!(msg.contains("Reverted with no data"));
    }

    #[test]
    fn decodes_only_pool_error() {
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyPool(
            UnifiedHardenedExecutor::OnlyPool {},
        );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("configured Aave pool"));
    }

    #[test]
    fn decodes_invalid_pool_error() {
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidPool(
            UnifiedHardenedExecutor::InvalidPool {},
        );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("Invalid Aave pool"));
    }

    #[test]
    fn decodes_invalid_asset_error() {
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidAsset(
            UnifiedHardenedExecutor::InvalidAsset {},
        );
        let data = err.abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert!(msg.contains("Invalid flashloan asset"));
    }

    #[test]
    fn decodes_standard_revert_reason() {
        let data = Revert::from("slippage exceeded").abi_encode();
        let msg = decode_flashloan_revert(&data);
        assert_eq!(msg, "Standard Revert: slippage exceeded");
    }

    #[test]
    fn decodes_unknown_revert_payload_as_hex() {
        let msg = decode_flashloan_revert(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(msg, "Unknown Revert: 0xdeadbeef");
    }

    #[test]
    fn execution_failed_with_non_utf8_reason_is_hex_encoded() {
        let err = UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ExecutionFailed(
            UnifiedHardenedExecutor::ExecutionFailed {
                index: U256::from(7u64),
                reason: Bytes::from(vec![0xff, 0xfe, 0xfd]),
            },
        );
        let msg = decode_flashloan_revert(&err.abi_encode());
        assert!(msg.contains("index 7"));
        assert!(msg.contains("0xfffefd"));
    }

    #[test]
    fn sim_call_result_uses_rpc_error_reason_when_present() {
        let call = SimCallResult {
            return_data: Bytes::new(),
            logs: Vec::new(),
            gas_used: 42_000,
            status: false,
            error: Some(SimulateError {
                code: -32000,
                message: "execution reverted".to_string(),
            }),
        };
        let outcome = sim_call_result_to_outcome(&call);
        assert!(!outcome.success);
        assert_eq!(outcome.gas_used, 42_000);
        let reason = outcome.reason.expect("reason");
        assert!(reason.contains("execution reverted"));
    }

    #[test]
    fn default_frame_failure_decodes_reason() {
        let frame = DefaultFrame {
            failed: true,
            gas: 123_456,
            return_value: Bytes::from(Revert::from("bad route").abi_encode()),
            struct_logs: Vec::new(),
        };
        let outcome = default_frame_to_outcome(frame);
        assert!(!outcome.success);
        assert_eq!(outcome.gas_used, 123_456);
        assert_eq!(
            outcome.reason.as_deref(),
            Some("Standard Revert: bad route")
        );
    }

    #[test]
    fn rpc_unavailable_detection_matches_nethermind_patterns() {
        assert!(rpc_method_unavailable_message(
            "RPC error -32601: Method eth_simulateV1 not found"
        ));
        assert!(rpc_method_unavailable_message(
            "RPC error -32600: Namespace debug is disabled"
        ));
        assert!(!rpc_method_unavailable_message(
            "execution reverted: custom error"
        ));
    }

    #[test]
    fn insufficient_sender_balance_detection_matches_nethermind_patterns() {
        assert!(rpc_insufficient_sender_balance_message(
            "error code -38014: insufficient MaxFeePerGas for sender balance"
        ));
        assert!(rpc_insufficient_sender_balance_message(
            "insufficient sender balance for transaction"
        ));
        assert!(!rpc_insufficient_sender_balance_message(
            "execution reverted: custom error"
        ));
    }
}
