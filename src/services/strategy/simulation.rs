// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::data::executor::UnifiedHardenedExecutor;
use crate::network::provider::HttpProvider;
use alloy::providers::Provider;
use alloy::providers::ext::DebugApi;
use alloy::primitives::{Address, TxKind, U256};
use alloy::rpc::types::eth::simulate::{SimBlock, SimCallResult, SimulatePayload};
use alloy::rpc::types::eth::state::StateOverride;
use alloy::rpc::types::eth::{
    BlockId, BlockNumberOrTag, Bundle, StateContext, Transaction, TransactionRequest,
};
use alloy::rpc::types::trace::geth::{DefaultFrame, GethDebugTracingCallOptions};
use alloy::sol_types::SolInterface;
use alloy_sol_types::{Revert, SolError};
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
                "eth_simulate"
                | "ethsimulate"
                | "eth_simulatev1"
                | "ethsimulatev1"
                | "simulate"
                | "revm"
                | "revmv1"
                | "anvil" => return Self::EthSimulate,
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
        let mut req = TransactionRequest::default();
        req.from = Some(Address::ZERO);
        req.to = Some(TxKind::Call(Address::ZERO));
        req.value = Some(U256::ZERO);

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
                tracing::info!(target: "simulation", "eth_simulateV1 available");
                true
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) {
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

    async fn probe_debug_trace_call_internal(&self) -> bool {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return false;
        }
        let mut req = TransactionRequest::default();
        req.from = Some(Address::ZERO);
        req.to = Some(TxKind::Call(Address::ZERO));
        req.value = Some(U256::ZERO);
        let block = BlockId::Number(BlockNumberOrTag::Pending);
        let trace_options = GethDebugTracingCallOptions::default();
        match self.provider.debug_trace_call(req, block, trace_options).await {
            Ok(_) => true,
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) {
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

    async fn probe_debug_trace_many_internal(&self) -> bool {
        if DEBUG_TRACE_MISSING.get().is_some() {
            return false;
        }
        let mut req = TransactionRequest::default();
        req.from = Some(Address::ZERO);
        req.to = Some(TxKind::Call(Address::ZERO));
        req.value = Some(U256::ZERO);
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
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) {
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
        tracing::info!(
            target: "simulation",
            fee_history,
            eth_simulate,
            debug_trace_call,
            debug_trace_call_many,
            "RPC simulation capabilities"
        );
        RpcCapabilities {
            fee_history,
            eth_simulate,
            debug_trace_call,
            debug_trace_call_many,
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
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) {
                    if ETH_SIMULATE_MISSING.set(()).is_ok() {
                        tracing::warn!(
                            target: "simulation",
                            "eth_simulateV1 not available on node; falling back"
                        );
                    }
                } else {
                    tracing::warn!(
                        target: "simulation",
                        backend = "eth_simulate",
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
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) {
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
        let (success, return_data) = match call_res {
            Ok(bytes) => (true, bytes.to_vec()),
            Err(e) => (false, format!("eth_call failed: {e}").into_bytes()),
        };

        let reason = if success {
            None
        } else {
            Some(decode_flashloan_revert(&return_data))
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
                        return Ok(outcomes);
                    }
                }
                SimulationBackendMethod::DebugTraceCall => {
                    if let Some(outcomes) = self.try_bundle_with_debug_trace(txs).await? {
                        return Ok(outcomes);
                    }
                }
                SimulationBackendMethod::EthCall => {
                    let mut outcomes = Vec::with_capacity(txs.len());
                    for tx in txs {
                        outcomes.push(self.simulate_request_with_eth_call(tx.clone()).await?);
                    }
                    return Ok(outcomes);
                }
            }
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
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) && ETH_SIMULATE_MISSING.set(()).is_ok() {
                    tracing::warn!(
                        target: "simulation",
                        "eth_simulateV1 unavailable for bundles; cached fallback"
                    );
                }
                tracing::warn!(
                    target: "simulation",
                    backend = "eth_simulate",
                    error = %e,
                    "simulate_bundle_requests failed"
                );
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
                let msg = e.to_string().to_lowercase();
                if rpc_method_unavailable(&msg) && DEBUG_TRACE_MISSING.set(()).is_ok() {
                    tracing::warn!(
                        target: "simulation",
                        "debug_traceCallMany unavailable; cached fallback"
                    );
                }
                tracing::warn!(
                    target: "simulation",
                    backend = "debug_trace_call",
                    error = %e,
                    "debug_trace_call_many failed"
                );
                Ok(None)
            }
        }
    }
}

fn rpc_method_unavailable(message: &str) -> bool {
    let msg = message.to_lowercase();
    (msg.contains("method") && msg.contains("not found"))
        || (msg.contains("namespace") && msg.contains("disabled"))
}

fn sim_call_result_to_outcome(call: &SimCallResult) -> SimulationOutcome {
    let success = call.error.is_none() && call.status;
    if !success {
        tracing::warn!(
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
        tracing::warn!(
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
    use alloy::primitives::{Address, U256};

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
}
