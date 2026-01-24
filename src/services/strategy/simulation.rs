// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::data::executor::UnifiedHardenedExecutor;
use crate::network::provider::HttpProvider;
use alloy::providers::Provider;
use alloy::rpc::types::eth::Transaction;
use alloy::rpc::types::eth::TransactionRequest;
use alloy::rpc::types::eth::simulate::{SimBlock, SimulatePayload};
use alloy::rpc::types::eth::state::StateOverride;
use alloy::sol_types::SolInterface;
use alloy_sol_types::{Revert, SolError};

#[derive(Debug, Clone)]
pub struct SimulationOutcome {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
}

#[derive(Clone)]
pub struct Simulator {
    provider: HttpProvider,
}

impl Simulator {
    pub fn new(provider: HttpProvider) -> Self {
        Self { provider }
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
        if state_override.is_some() {
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

            if let Ok(simulated) = self.provider.simulate(&payload).await {
                if let Some(call) = simulated.first().and_then(|b| b.calls.first()) {
                    let success = call.error.is_none() && call.status;

                    if !success {
                        let reason = decode_flashloan_revert(&call.return_data);
                        tracing::warn!("Simulation Revert Reason: {}", reason);
                    }

                    return Ok(SimulationOutcome {
                        success,
                        gas_used: call.gas_used,
                        return_data: call.return_data.to_vec(),
                    });
                }
            }
        }

        let gas_used = match self.provider.estimate_gas(req.clone()).await {
            Ok(g) => g,
            Err(e) => {
                return Ok(SimulationOutcome {
                    success: false,
                    gas_used: 0,
                    return_data: format!("estimate_gas failed: {e}").into_bytes(),
                });
            }
        };

        let call_res = self.provider.call(req).await;

        let (success, return_data) = match call_res {
            Ok(bytes) => (true, bytes.to_vec()),
            Err(_) => (false, Vec::new()),
        };

        Ok(SimulationOutcome {
            success,
            gas_used,
            return_data,
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

        let calls = txs.to_vec();
        let block = SimBlock {
            block_overrides: None,
            state_overrides: state_override.clone(),
            calls,
        };
        let payload = SimulatePayload {
            block_state_calls: vec![block],
            trace_transfers: false,
            validation: false,
            return_full_transactions: false,
        };

        match self.provider.simulate(&payload).await {
            Ok(blocks) => {
                let mut out = Vec::new();
                for blk in blocks {
                    for (i, tx) in blk.calls.iter().enumerate() {
                        let success = tx.error.is_none() && tx.status;

                        if !success {
                            let reason = decode_flashloan_revert(&tx.return_data);
                            tracing::warn!("Bundle Tx {} Revert: {}", i, reason);
                        }

                        out.push(SimulationOutcome {
                            success,
                            gas_used: tx.gas_used,
                            return_data: tx.return_data.to_vec(),
                        });
                    }
                }
                return Ok(out);
            }
            Err(_) => {
                let mut out = Vec::new();
                for tx in txs {
                    out.push(
                        self.simulate_request(tx.clone(), state_override.clone())
                            .await?,
                    );
                }
                Ok(out)
            }
        }
    }
}

pub fn decode_flashloan_revert(revert_data: &[u8]) -> String {
    if revert_data.is_empty() {
        return "Reverted with no data (OOG or empty)".to_string();
    }

    // Try decoding against our custom errors
    // Note: SolError trait provides abi_decode for the enum generated by sol!
    if let Ok(decoded) =
        UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::abi_decode(revert_data)
    {
        #[allow(unreachable_patterns)]
        return match decoded {
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InsufficientFundsForRepayment(e) => {
                format!(
                    "📉 INSOLVENT: Needed {} of token {:?}, but only had {}",
                    e.required, e.token, e.available
                )
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ExecutionFailed(e) => {
                let inner_msg = String::from_utf8(e.reason.to_vec())
                    .unwrap_or_else(|_| format!("0x{}", hex::encode(&e.reason)));
                format!("💥 STRATEGY FAILED at index {}: {}", e.index, inner_msg)
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::LengthMismatch(_) => "🚫 Array Length Mismatch".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ZeroAssets(_) => "🚫 Zero Assets requested".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::TokenTransferFailed(_) => "🔒 Token Transfer Failed (USDT?)".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::ApprovalFailed(_) => "🔒 Approval failed (USDT-style)".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidWETHAddress(_) => "🚫 Invalid WETH address".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::InvalidProfitReceiver(_) => "🚫 Invalid profit receiver".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BribeFailed(_) => "💰 Bribe payment failed".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::BalanceInvariantBroken(e) => {
                format!(
                    "🔒 Balance invariant broke for token {:?}: before {}, after {}",
                    e.token, e.beforeBalance, e.afterBalance
                )
            }
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyOwner(_) => "🚫 Caller is not owner".to_string(),
            UnifiedHardenedExecutor::UnifiedHardenedExecutorErrors::OnlyVault(_) => "🚫 Caller is not Balancer Vault".to_string(),
            _ => "Reverted with known custom error".to_string(), // Fallback if Debug is missing
        };
    }

    // Try decoding standard Error(string)
    if let Ok(msg) = Revert::abi_decode(revert_data) {
        return format!("Standard Revert: {}", msg.reason());
    }

    // Unknown binary data
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
