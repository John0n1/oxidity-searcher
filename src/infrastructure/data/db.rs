// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::data::schema::TransactionRecord;
use alloy::primitives::Address;
use sqlx::{
    Pool, Row, Sqlite,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::str::FromStr;

const SQUASHED_BASELINE_VERSION: i64 = 20260215000000;

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| AppError::Initialization(format!("DB Connect failed: {}", e)))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| AppError::Initialization(format!("DB Connect failed: {}", e)))?;

        let has_migration_table = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Initialization(format!("DB Migration introspection failed: {e}")))?
            > 0;
        let legacy_history_present = if has_migration_table {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM _sqlx_migrations WHERE version < ?")
                .bind(SQUASHED_BASELINE_VERSION)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    AppError::Initialization(format!("DB Migration history check failed: {e}"))
                })?
                > 0
        } else {
            false
        };

        if legacy_history_present {
            tracing::info!(
                target: "db",
                "Detected legacy migration history; applying ./migrations_legacy plan"
            );
            sqlx::migrate!("./migrations_legacy")
                .run(&pool)
                .await
                .map_err(|e| {
                    AppError::Initialization(format!("DB legacy migration failed: {}", e))
                })?;
        } else {
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .map_err(|e| AppError::Initialization(format!("DB Migration failed: {}", e)))?;
        }

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
            if block < 0 || next < 0 {
                return Err(AppError::Initialization(format!(
                    "Nonce state row contains negative value(s): block_number={block} next_nonce={next}"
                )));
            }
            let block_u64 = u64::try_from(block).map_err(|e| {
                AppError::Initialization(format!("Nonce state block_number conversion failed: {e}"))
            })?;
            let next_u64 = u64::try_from(next).map_err(|e| {
                AppError::Initialization(format!("Nonce state next_nonce conversion failed: {e}"))
            })?;
            return Ok(Some((block_u64, next_u64, touched)));
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
        profit_wei: &str,
        gas_cost_wei: &str,
        net_profit_wei: &str,
        bribe_wei: &str,
        flashloan_premium_wei: &str,
        effective_cost_wei: &str,
    ) -> Result<i64, AppError> {
        let chain_id_i64 = chain_id as i64;
        let row = sqlx::query(
            r#"
            INSERT INTO profit_records (
                tx_hash,
                chain_id,
                strategy,
                profit_eth,
                gas_cost_eth,
                net_profit_eth,
                profit_wei,
                gas_cost_wei,
                net_profit_wei,
                bribe_wei,
                flashloan_premium_wei,
                effective_cost_wei
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(tx_hash)
        .bind(chain_id_i64)
        .bind(strategy)
        .bind(profit_eth)
        .bind(gas_cost_eth)
        .bind(net_profit_eth)
        .bind(profit_wei)
        .bind(gas_cost_wei)
        .bind(net_profit_wei)
        .bind(bribe_wei)
        .bind(flashloan_premium_wei)
        .bind(effective_cost_wei)
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

    pub async fn record_router_observation(
        &self,
        chain_id: u64,
        address: &str,
        source: &str,
        reason: &str,
        increment: u64,
    ) -> Result<(), AppError> {
        let chain_id_i64 = chain_id as i64;
        let inc_i64 = increment as i64;
        sqlx::query(
            r#"
            INSERT INTO router_discovery (chain_id, address, seen_count, last_source, last_reason)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, address) DO UPDATE SET
                seen_count = router_discovery.seen_count + excluded.seen_count,
                last_seen = CURRENT_TIMESTAMP,
                last_source = excluded.last_source,
                last_reason = excluded.last_reason
            "#,
        )
        .bind(chain_id_i64)
        .bind(address)
        .bind(inc_i64)
        .bind(source)
        .bind(reason)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Router discovery upsert failed: {}", e)))?;
        Ok(())
    }

    pub async fn set_router_status(
        &self,
        chain_id: u64,
        address: &str,
        status: &str,
        router_kind: Option<&str>,
        notes: Option<&str>,
    ) -> Result<(), AppError> {
        let chain_id_i64 = chain_id as i64;
        sqlx::query(
            r#"
            INSERT INTO router_discovery (chain_id, address, seen_count, status, router_kind, notes)
            VALUES (?, ?, 0, ?, ?, ?)
            ON CONFLICT(chain_id, address) DO UPDATE SET
                status = excluded.status,
                router_kind = excluded.router_kind,
                notes = excluded.notes,
                last_seen = CURRENT_TIMESTAMP
            "#,
        )
        .bind(chain_id_i64)
        .bind(address)
        .bind(status)
        .bind(router_kind)
        .bind(notes)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Router discovery status failed: {}", e)))?;
        Ok(())
    }

    pub async fn approved_routers(&self, chain_id: u64) -> Result<Vec<Address>, AppError> {
        let chain_id_i64 = chain_id as i64;
        let rows = sqlx::query(
            "SELECT address FROM router_discovery WHERE chain_id = ? AND status = 'approved'",
        )
        .bind(chain_id_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Router discovery load failed: {}", e)))?;

        let mut out = Vec::new();
        for row in rows {
            let addr_str: String = row.get("address");
            if let Ok(addr) = Address::from_str(&addr_str) {
                out.push(addr);
            } else {
                tracing::warn!(
                    target: "router_discovery",
                    address = %addr_str,
                    "Invalid router address stored"
                );
            }
        }
        Ok(out)
    }

    pub async fn top_unknown_routers(
        &self,
        chain_id: u64,
        limit: u64,
    ) -> Result<Vec<(Address, u64)>, AppError> {
        let chain_id_i64 = chain_id as i64;
        let limit_i64 = (limit as i64).max(1);
        let rows = sqlx::query(
            r#"
            SELECT address, seen_count
            FROM router_discovery
            WHERE chain_id = ?
              AND COALESCE(status, '') != 'approved'
            ORDER BY seen_count DESC
            LIMIT ?
            "#,
        )
        .bind(chain_id_i64)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::Initialization(format!("Router discovery top load failed: {}", e))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let addr_str: String = row.get("address");
            let seen_i64: i64 = row.get("seen_count");
            if let Ok(addr) = Address::from_str(&addr_str) {
                out.push((addr, seen_i64.max(0) as u64));
            } else {
                tracing::warn!(
                    target: "router_discovery",
                    address = %addr_str,
                    "Invalid router address in top unknown list"
                );
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn profit_and_price_inserts() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        let profit_id = db
            .save_profit_record(
                "0xabc",
                1,
                "test",
                0.2,
                0.05,
                0.15,
                "200000000000000000",
                "50000000000000000",
                "150000000000000000",
                "0",
                "0",
                "50000000000000000",
            )
            .await
            .unwrap();
        assert!(profit_id > 0);
        let price_id = db
            .save_market_price(1, "ETHUSD", 3200.0, "test")
            .await
            .unwrap();
        assert!(price_id > 0);
    }

    #[tokio::test]
    async fn load_nonce_state_rejects_negative_values() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        sqlx::query(
            "INSERT INTO nonce_state (chain_id, block_number, next_nonce, touched_pools) VALUES (?, ?, ?, ?)",
        )
        .bind(1i64)
        .bind(-1i64)
        .bind(7i64)
        .bind("[]")
        .execute(&db.pool)
        .await
        .expect("insert nonce_state");

        let err = db
            .load_nonce_state(1)
            .await
            .expect_err("negative nonce row should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("negative value"),
            "unexpected error message: {msg}"
        );
    }
}
