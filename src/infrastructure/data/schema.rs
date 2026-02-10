// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use chrono::NaiveDateTime;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct TransactionRecord {
    pub id: i64,
    pub tx_hash: String,
    pub chain_id: i64,
    pub block_number: Option<i64>,
    pub from_address: String,
    pub to_address: Option<String>,
    pub value_wei: String,
    pub gas_used: Option<i64>,
    pub gas_price_wei: Option<String>,
    pub status: Option<bool>,
    pub strategy: Option<String>,
    pub timestamp: NaiveDateTime,
    pub execution_time_ms: Option<f64>,
}

#[derive(Debug, FromRow)]
pub struct ProfitRecord {
    pub id: i64,
    pub tx_hash: String,
    pub chain_id: i64,
    pub strategy: String,
    pub profit_eth: f64,
    pub gas_cost_eth: f64,
    pub net_profit_eth: f64,
    pub profit_wei: String,
    pub gas_cost_wei: String,
    pub net_profit_wei: String,
    pub bribe_wei: String,
    pub flashloan_premium_wei: String,
    pub effective_cost_wei: String,
    pub timestamp: NaiveDateTime,
}
