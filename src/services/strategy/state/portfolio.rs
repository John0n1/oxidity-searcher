// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::{Address, I256, U256};
use alloy::providers::Provider;
use dashmap::DashMap;
use std::time::Duration;

pub struct PortfolioManager {
    provider: HttpProvider,
    wallet_address: Address,

    // Cache current on-chain balances
    token_balances: DashMap<(u64, Address), U256>,
    eth_balance: DashMap<u64, U256>,

    // Metrics: Track Profit & Loss in Signed Wei (I256) to handle negative PnL accurately
    net_pnl_wei: DashMap<u64, I256>,
    total_gas_spent_wei: DashMap<u64, U256>,

    // Token profit in signed integer amounts
    token_profit_wei: DashMap<(u64, Address), I256>,
}

impl PortfolioManager {
    pub fn new(provider: HttpProvider, wallet_address: Address) -> Self {
        Self {
            provider,
            wallet_address,
            token_balances: DashMap::new(),
            eth_balance: DashMap::new(),
            net_pnl_wei: DashMap::new(),
            total_gas_spent_wei: DashMap::new(),
            token_profit_wei: DashMap::new(),
        }
    }

    pub async fn update_eth_balance(&self, chain_id: u64) -> Result<U256, AppError> {
        let provider = self.provider.clone();
        let addr = self.wallet_address;
        let bal = retry_async(
            move |_| {
                let provider = provider.clone();
                async move { provider.get_balance(addr).await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Balance check failed: {}", e)))?;

        self.eth_balance.insert(chain_id, bal);
        Ok(bal)
    }

    pub fn get_eth_balance_cached(&self, chain_id: u64) -> U256 {
        self.eth_balance
            .get(&chain_id)
            .map(|v| *v)
            .unwrap_or(U256::ZERO)
    }

    pub fn ensure_funding(&self, chain_id: u64, amount_needed: U256) -> Result<(), AppError> {
        let bal = self
            .eth_balance
            .get(&chain_id)
            .map(|v| *v)
            .unwrap_or(U256::ZERO);
        let gas_reserve = U256::from(10_000_000_000_000_000u64); // 0.01 ETH Safety Buffer

        if bal < amount_needed.saturating_add(gas_reserve) {
            return Err(AppError::InsufficientFunds {
                required: amount_needed.to_string(),
                available: bal.to_string(),
            });
        }
        Ok(())
    }

    pub async fn update_token_balance(
        &self,
        chain_id: u64,
        token: Address,
    ) -> Result<U256, AppError> {
        alloy::sol! {
            #[derive(Debug, PartialEq, Eq)]
            #[sol(rpc)]
            contract ERC20 {
                function balanceOf(address) external view returns (uint256);
            }
        }

        let contract = ERC20::new(token, self.provider.clone());
        let bal: U256 = retry_async(
            move |_| {
                let contract = contract.clone();
                async move { contract.balanceOf(self.wallet_address).call().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Token balance failed: {}", e)))?;

        self.token_balances.insert((chain_id, token), bal);
        Ok(bal)
    }

    pub fn get_token_balance(&self, chain_id: u64, token: Address) -> U256 {
        self.token_balances
            .get(&(chain_id, token))
            .map(|v| *v)
            .unwrap_or(U256::ZERO)
    }

    /// Record a completed trade.
    /// Takes raw Wei (U256) for revenue and cost to avoid float precision loss.
    pub fn record_profit(&self, chain_id: u64, revenue_wei: U256, gas_cost_wei: U256) {
        let rev_i256 = I256::from_raw(revenue_wei);
        let cost_i256 = I256::from_raw(gas_cost_wei);

        // Net = Revenue - Cost (Can be negative)
        let net = rev_i256.saturating_sub(cost_i256);

        self.net_pnl_wei
            .entry(chain_id)
            .and_modify(|v| *v = v.saturating_add(net))
            .or_insert(net);

        self.total_gas_spent_wei
            .entry(chain_id)
            .and_modify(|v| *v = v.saturating_add(gas_cost_wei))
            .or_insert(gas_cost_wei);
    }

    pub fn record_token_profit(&self, chain_id: u64, token: Address, delta_wei: I256) {
        self.token_profit_wei
            .entry((chain_id, token))
            .and_modify(|v| *v = v.saturating_add(delta_wei))
            .or_insert(delta_wei);
    }

    /// Used by StrategyExecutor for logic checks (e.g. gas boost decisions)
    pub fn get_net_profit_i256(&self, chain_id: u64) -> I256 {
        self.net_pnl_wei
            .get(&chain_id)
            .map(|v| *v)
            .unwrap_or(I256::ZERO)
    }

    /// For Logging/Metrics only (Returns f64 approximate)
    pub fn net_profit_eth(&self, chain_id: u64) -> f64 {
        let wei = self.get_net_profit_i256(chain_id);
        i256_to_eth_f64(wei)
    }

    pub fn net_profit_all(&self) -> Vec<(u64, f64)> {
        self.net_pnl_wei
            .iter()
            .map(|entry| {
                let chain = *entry.key();
                let wei = *entry.value();
                (chain, i256_to_eth_f64(wei))
            })
            .collect()
    }

    pub fn token_profit_all(&self) -> Vec<(u64, Address, f64)> {
        self.token_profit_wei
            .iter()
            .map(|entry| {
                let (chain, token) = *entry.key();
                let wei = *entry.value();
                (chain, token, i256_to_eth_f64(wei))
            })
            .collect()
    }
}

// Helpers for Display only
fn i256_to_eth_f64(val: I256) -> f64 {
    let sign = if val.is_negative() { -1.0 } else { 1.0 };
    // Convert abs value to string then parse to avoid u64 overflow on very large accumulators
    let abs = val.abs().into_raw();
    let num = abs.to_string().parse::<f64>().unwrap_or(0.0);
    sign * (num / 1e18)
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn records_profit_and_net() {
        let dummy_provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let pm = PortfolioManager::new(dummy_provider, Address::ZERO);

        let revenue = U256::from(1_500_000_000_000_000_000u128); // 1.5 ETH
        let cost = U256::from(400_000_000_000_000_000u128); // 0.4 ETH

        pm.record_profit(1, revenue, cost); // Net +1.1

        let pnl = pm.get_net_profit_i256(1);
        let expected = I256::from_raw(U256::from(1_100_000_000_000_000_000u128));
        assert_eq!(pnl, expected);

        // Float conversion check
        let float_pnl = pm.net_profit_eth(1);
        assert!((float_pnl - 1.1).abs() < 1e-9);
    }
}
