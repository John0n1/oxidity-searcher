// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use alloy::primitives::{Address, I256, U256};
use alloy::providers::Provider;
use alloy::sol;
use std::collections::HashSet;

sol! {
    #[sol(rpc)]
    interface SettlementToken {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountBalance {
    pub account: Address,
    pub native: U256,
    pub wrapped_native: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementSnapshot {
    pub wrapped_native: Address,
    pub balances: Vec<AccountBalance>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDelta {
    pub account: Address,
    pub native_before: U256,
    pub native_after: U256,
    pub native_delta: I256,
    pub wrapped_before: U256,
    pub wrapped_after: U256,
    pub wrapped_delta: I256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementDelta {
    pub net_native_and_wrapped: I256,
    pub accounts: Vec<AccountDelta>,
}

impl SettlementSnapshot {
    pub async fn capture(
        provider: &HttpProvider,
        wrapped_native: Address,
        accounts: impl IntoIterator<Item = Address>,
    ) -> Result<Self, AppError> {
        let mut seen = HashSet::new();
        let accounts = accounts
            .into_iter()
            .filter(|account| *account != Address::ZERO && seen.insert(*account))
            .collect::<Vec<_>>();
        let token = SettlementToken::new(wrapped_native, provider.clone());
        let mut balances = Vec::with_capacity(accounts.len());
        for account in accounts {
            let native = provider.get_balance(account).await.map_err(|e| {
                AppError::Connection(format!("Settlement native balance snapshot failed: {e}"))
            })?;
            let wrapped_native = token.balanceOf(account).call().await.map_err(|e| {
                AppError::Connection(format!("Settlement WETH balance snapshot failed: {e}"))
            })?;
            balances.push(AccountBalance {
                account,
                native,
                wrapped_native,
            });
        }
        Ok(Self {
            wrapped_native,
            balances,
        })
    }

    pub fn delta(&self, after: &Self) -> Result<SettlementDelta, AppError> {
        if self.wrapped_native != after.wrapped_native {
            return Err(AppError::Strategy(
                "Settlement snapshots use different wrapped-native assets".into(),
            ));
        }
        let mut accounts = Vec::with_capacity(self.balances.len());
        let mut total = I256::ZERO;
        for before in &self.balances {
            let Some(after_balance) = after
                .balances
                .iter()
                .find(|candidate| candidate.account == before.account)
            else {
                return Err(AppError::Strategy(format!(
                    "Settlement snapshot missing account {:#x}",
                    before.account
                )));
            };
            let native_delta = signed_delta(before.native, after_balance.native);
            let wrapped_delta = signed_delta(before.wrapped_native, after_balance.wrapped_native);
            total = total
                .saturating_add(native_delta)
                .saturating_add(wrapped_delta);
            accounts.push(AccountDelta {
                account: before.account,
                native_before: before.native,
                native_after: after_balance.native,
                native_delta,
                wrapped_before: before.wrapped_native,
                wrapped_after: after_balance.wrapped_native,
                wrapped_delta,
            });
        }
        Ok(SettlementDelta {
            net_native_and_wrapped: total,
            accounts,
        })
    }
}

pub fn signed_delta(before: U256, after: U256) -> I256 {
    if after >= before {
        u256_to_i256_saturating(after - before)
    } else {
        u256_to_i256_saturating(before - after)
            .checked_neg()
            .unwrap_or(I256::MIN)
    }
}

pub fn u256_to_i256_saturating(value: U256) -> I256 {
    I256::try_from(value).unwrap_or(I256::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_native_and_wrapped_across_custody_accounts() {
        let a = Address::from([1u8; 20]);
        let b = Address::from([2u8; 20]);
        let weth = Address::from([3u8; 20]);
        let before = SettlementSnapshot {
            wrapped_native: weth,
            balances: vec![
                AccountBalance {
                    account: a,
                    native: U256::from(100u64),
                    wrapped_native: U256::ZERO,
                },
                AccountBalance {
                    account: b,
                    native: U256::ZERO,
                    wrapped_native: U256::ZERO,
                },
            ],
        };
        let after = SettlementSnapshot {
            wrapped_native: weth,
            balances: vec![
                AccountBalance {
                    account: a,
                    native: U256::from(80u64),
                    wrapped_native: U256::ZERO,
                },
                AccountBalance {
                    account: b,
                    native: U256::ZERO,
                    wrapped_native: U256::from(25u64),
                },
            ],
        };
        let delta = before.delta(&after).expect("delta");
        assert_eq!(delta.net_native_and_wrapped, I256::try_from(5).unwrap());
    }

    #[test]
    fn preserves_losses_as_signed_values() {
        assert_eq!(
            signed_delta(U256::from(12u64), U256::from(7u64)),
            I256::try_from(-5).unwrap()
        );
    }
}
