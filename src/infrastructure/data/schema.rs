// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use chrono::NaiveDateTime;
use sqlx::{FromRow, Row, sqlite::SqliteRow};

#[derive(Debug)]
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

impl<'r> FromRow<'r, SqliteRow> for TransactionRecord {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tx_hash: row.try_get("tx_hash")?,
            chain_id: row.try_get("chain_id")?,
            block_number: row.try_get("block_number")?,
            from_address: row.try_get("from_address")?,
            to_address: row.try_get("to_address")?,
            value_wei: row.try_get("value_wei")?,
            gas_used: row.try_get("gas_used")?,
            gas_price_wei: row.try_get("gas_price_wei")?,
            status: row.try_get("status")?,
            strategy: row.try_get("strategy")?,
            timestamp: row.try_get("timestamp")?,
            execution_time_ms: row.try_get("execution_time_ms")?,
        })
    }
}

#[derive(Debug)]
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

impl<'r> FromRow<'r, SqliteRow> for ProfitRecord {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tx_hash: row.try_get("tx_hash")?,
            chain_id: row.try_get("chain_id")?,
            strategy: row.try_get("strategy")?,
            profit_eth: row.try_get("profit_eth")?,
            gas_cost_eth: row.try_get("gas_cost_eth")?,
            net_profit_eth: row.try_get("net_profit_eth")?,
            profit_wei: row.try_get("profit_wei")?,
            gas_cost_wei: row.try_get("gas_cost_wei")?,
            net_profit_wei: row.try_get("net_profit_wei")?,
            bribe_wei: row.try_get("bribe_wei")?,
            flashloan_premium_wei: row.try_get("flashloan_premium_wei")?,
            effective_cost_wei: row.try_get("effective_cost_wei")?,
            timestamp: row.try_get("timestamp")?,
        })
    }
}
