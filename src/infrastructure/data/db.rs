// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::data::schema::TransactionRecord;
use sqlx::{Pool, Row, Sqlite, sqlite::SqlitePoolOptions};

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| AppError::Initialization(format!("DB Connect failed: {}", e)))?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| AppError::Initialization(format!("DB Migration failed: {}", e)))?;

        Ok(Self { pool })
    }

    pub async fn save_transaction(
        &self,
        tx_hash: &str,
        chain_id: u64,
        from: &str,
        to: Option<&str>,
        value: &str,
        strategy: Option<&str>,
    ) -> Result<i64, AppError> {
        let chain_id_i64 = chain_id as i64;

        let row = sqlx::query(
            r#"
            INSERT INTO transactions (tx_hash, chain_id, from_address, to_address, value_wei, strategy)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(tx_hash)
        .bind(chain_id_i64)
        .bind(from)
        .bind(to)
        .bind(value)
        .bind(strategy)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Transaction {
            hash: tx_hash.to_string(),
            reason: e.to_string(),
        })?;
        let id: i64 = row.get("id");

        Ok(id)
    }

    pub async fn upsert_nonce_state(
        &self,
        chain_id: u64,
        block_number: u64,
        next_nonce: u64,
        touched_pools: &str,
    ) -> Result<(), AppError> {
        let chain_id_i64 = chain_id as i64;
        let block_i64 = block_number as i64;
        let next_i64 = next_nonce as i64;
        sqlx::query(
            r#"
            INSERT INTO nonce_state (chain_id, block_number, next_nonce, touched_pools)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_id) DO UPDATE SET
                block_number=excluded.block_number,
                next_nonce=excluded.next_nonce,
                touched_pools=excluded.touched_pools,
                updated_at=CURRENT_TIMESTAMP
            "#,
        )
        .bind(chain_id_i64)
        .bind(block_i64)
        .bind(next_i64)
        .bind(touched_pools)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Nonce state upsert failed: {}", e)))?;
        Ok(())
    }

    pub async fn load_nonce_state(
        &self,
        chain_id: u64,
    ) -> Result<Option<(u64, u64, String)>, AppError> {
        let chain_id_i64 = chain_id as i64;
        let row = sqlx::query(
            "SELECT block_number, next_nonce, touched_pools FROM nonce_state WHERE chain_id = ?",
        )
        .bind(chain_id_i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Nonce state load failed: {}", e)))?;

        if let Some(row) = row {
            let block: i64 = row.get("block_number");
            let next: i64 = row.get("next_nonce");
            let touched: String = row.get("touched_pools");
            return Ok(Some((block as u64, next as u64, touched)));
        }
        Ok(None)
    }

    pub async fn get_recent_txs(&self, limit: i64) -> Result<Vec<TransactionRecord>, AppError> {
        let recs = sqlx::query_as::<_, TransactionRecord>(
            "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Query failed: {}", e)))?;

        Ok(recs)
    }

    pub async fn save_profit_record(
        &self,
        tx_hash: &str,
        chain_id: u64,
        strategy: &str,
        profit_eth: f64,
        gas_cost_eth: f64,
        net_profit_eth: f64,
    ) -> Result<i64, AppError> {
        let chain_id_i64 = chain_id as i64;
        let row = sqlx::query(
            r#"
            INSERT INTO profit_records (tx_hash, chain_id, strategy, profit_eth, gas_cost_eth, net_profit_eth)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(tx_hash)
        .bind(chain_id_i64)
        .bind(strategy)
        .bind(profit_eth)
        .bind(gas_cost_eth)
        .bind(net_profit_eth)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Profit insert failed: {}", e)))?;
        let id: i64 = row.get("id");

        Ok(id)
    }

    pub async fn update_status(
        &self,
        tx_hash: &str,
        block_number: Option<i64>,
        status: Option<bool>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE transactions
            SET block_number = COALESCE(?, block_number),
                status = COALESCE(?, status)
            WHERE tx_hash = ?
            "#,
        )
        .bind(block_number)
        .bind(status)
        .bind(tx_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Status update failed: {}", e)))?;

        Ok(())
    }

    pub async fn save_market_price(
        &self,
        chain_id: u64,
        symbol: &str,
        price_usd: f64,
        source: &str,
    ) -> Result<i64, AppError> {
        let chain_id_i64 = chain_id as i64;
        let row = sqlx::query(
            r#"
            INSERT INTO market_prices (chain_id, symbol, price_usd, source)
            VALUES (?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(chain_id_i64)
        .bind(symbol)
        .bind(price_usd)
        .bind(source)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Market price insert failed: {}", e)))?;
        let id: i64 = row.get("id");

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn profit_and_price_inserts() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        let profit_id = db
            .save_profit_record("0xabc", 1, "test", 0.2, 0.05, 0.15)
            .await
            .unwrap();
        assert!(profit_id > 0);
        let price_id = db
            .save_market_price(1, "ETHUSD", 3200.0, "test")
            .await
            .unwrap();
        assert!(price_id > 0);
    }
}
