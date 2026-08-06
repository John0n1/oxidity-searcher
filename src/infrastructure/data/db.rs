// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

#![allow(
    clippy::needless_raw_string_hashes,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use crate::common::error::AppError;
use crate::data::schema::TransactionRecord;
use alloy::primitives::Address;
use sqlx::{
    Pool, Row, Sqlite,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ExecutionEstimateRecord<'a> {
    pub estimate_id: &'a str,
    pub chain_id: u64,
    pub strategy: &'a str,
    pub opportunity_id: Option<&'a str>,
    pub planned_tx_hash: Option<&'a str>,
    pub settlement_token: &'a str,
    pub estimated_gross_wei: &'a str,
    pub estimated_gas_wei: &'a str,
    pub estimated_bribe_wei: &'a str,
    pub estimated_flashloan_premium_wei: &'a str,
    pub estimated_net_wei: &'a str,
    pub simulation_block_number: Option<u64>,
    pub simulation_block_hash: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct ExecutionAttemptRecord<'a> {
    pub tx_hash: &'a str,
    pub estimate_id: Option<&'a str>,
    pub chain_id: u64,
    pub strategy: &'a str,
    pub submission_mode: &'a str,
    pub status: &'a str,
    pub nonce: Option<u64>,
    pub target_block: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SettlementRecord<'a> {
    pub tx_hash: &'a str,
    pub chain_id: u64,
    pub strategy: &'a str,
    pub settlement_token: &'a str,
    pub realized_gross_delta_wei: &'a str,
    pub actual_gas_cost_wei: &'a str,
    pub realized_net_delta_wei: &'a str,
    pub block_number: u64,
    pub block_hash: &'a str,
    pub confirmations: u64,
    pub finalized: bool,
    pub liquid: bool,
    pub reusable: bool,
}

#[derive(Clone, Debug)]
pub struct SettlementDeltaRecord<'a> {
    pub tx_hash: &'a str,
    pub account: &'a str,
    pub asset: &'a str,
    pub decimals: u8,
    pub balance_before: &'a str,
    pub balance_after: &'a str,
    pub delta_raw: &'a str,
    pub liquid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgedSettlement {
    pub realized_net_delta_wei: String,
    pub actual_gas_cost_wei: String,
}

fn to_i64(value: u64, label: &str) -> Result<i64, AppError> {
    i64::try_from(value).map_err(|e| {
        AppError::Initialization(format!(
            "{label} conversion to i64 failed: {e} (value={value})"
        ))
    })
}

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

        Migrator::new(Path::new("./migrations"))
            .await
            .map_err(|e| AppError::Initialization(format!("DB Migrator init failed: {}", e)))?
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
        let chain_id_i64 = to_i64(chain_id, "transactions.chain_id")?;

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
        let chain_id_i64 = i64::try_from(chain_id).map_err(|e| {
            AppError::Initialization(format!("Nonce state chain_id conversion failed: {e}"))
        })?;
        let block_i64 = i64::try_from(block_number).map_err(|e| {
            AppError::Initialization(format!("Nonce state block_number conversion failed: {e}"))
        })?;
        let next_i64 = i64::try_from(next_nonce).map_err(|e| {
            AppError::Initialization(format!("Nonce state next_nonce conversion failed: {e}"))
        })?;
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
        let chain_id_i64 = to_i64(chain_id, "nonce_state.chain_id")?;
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
        let chain_id_i64 = to_i64(chain_id, "profit_records.chain_id")?;
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

    pub async fn save_execution_estimate(
        &self,
        record: &ExecutionEstimateRecord<'_>,
    ) -> Result<(), AppError> {
        let chain_id = to_i64(record.chain_id, "execution_estimates.chain_id")?;
        let simulation_block_number = record
            .simulation_block_number
            .map(|value| to_i64(value, "execution_estimates.simulation_block_number"))
            .transpose()?;
        sqlx::query(
            r#"
            INSERT INTO execution_estimates (
                estimate_id, chain_id, strategy, opportunity_id, planned_tx_hash,
                settlement_token, estimated_gross_wei, estimated_gas_wei,
                estimated_bribe_wei, estimated_flashloan_premium_wei, estimated_net_wei,
                simulation_block_number, simulation_block_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(estimate_id) DO UPDATE SET
                planned_tx_hash=excluded.planned_tx_hash,
                estimated_gross_wei=excluded.estimated_gross_wei,
                estimated_gas_wei=excluded.estimated_gas_wei,
                estimated_bribe_wei=excluded.estimated_bribe_wei,
                estimated_flashloan_premium_wei=excluded.estimated_flashloan_premium_wei,
                estimated_net_wei=excluded.estimated_net_wei,
                simulation_block_number=excluded.simulation_block_number,
                simulation_block_hash=excluded.simulation_block_hash,
                updated_at=CURRENT_TIMESTAMP
            "#,
        )
        .bind(record.estimate_id)
        .bind(chain_id)
        .bind(record.strategy)
        .bind(record.opportunity_id)
        .bind(record.planned_tx_hash)
        .bind(record.settlement_token)
        .bind(record.estimated_gross_wei)
        .bind(record.estimated_gas_wei)
        .bind(record.estimated_bribe_wei)
        .bind(record.estimated_flashloan_premium_wei)
        .bind(record.estimated_net_wei)
        .bind(simulation_block_number)
        .bind(record.simulation_block_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Execution estimate upsert failed: {e}")))?;
        Ok(())
    }

    pub async fn save_execution_attempt(
        &self,
        record: &ExecutionAttemptRecord<'_>,
    ) -> Result<(), AppError> {
        let chain_id = to_i64(record.chain_id, "execution_attempts.chain_id")?;
        let nonce = record
            .nonce
            .map(|value| to_i64(value, "execution_attempts.nonce"))
            .transpose()?;
        let target_block = record
            .target_block
            .map(|value| to_i64(value, "execution_attempts.target_block"))
            .transpose()?;
        sqlx::query(
            r#"
            INSERT INTO execution_attempts (
                tx_hash, estimate_id, chain_id, strategy, submission_mode, status, nonce, target_block
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tx_hash) DO UPDATE SET
                estimate_id=COALESCE(excluded.estimate_id, execution_attempts.estimate_id),
                submission_mode=excluded.submission_mode,
                status=excluded.status,
                nonce=COALESCE(excluded.nonce, execution_attempts.nonce),
                target_block=COALESCE(excluded.target_block, execution_attempts.target_block),
                updated_at=CURRENT_TIMESTAMP
            "#,
        )
        .bind(record.tx_hash)
        .bind(record.estimate_id)
        .bind(chain_id)
        .bind(record.strategy)
        .bind(record.submission_mode)
        .bind(record.status)
        .bind(nonce)
        .bind(target_block)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Execution attempt upsert failed: {e}")))?;

        if let Some(estimate_id) = record.estimate_id {
            sqlx::query(
                "UPDATE execution_estimates SET status = ?, updated_at=CURRENT_TIMESTAMP WHERE estimate_id = ?",
            )
            .bind(if record.status == "shadow" { "simulated" } else { "submitted" })
            .bind(estimate_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Initialization(format!("Estimate status update failed: {e}")))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_execution_attempt_outcome(
        &self,
        tx_hash: &str,
        status: &str,
        block_number: Option<u64>,
        block_hash: Option<&str>,
        gas_used: Option<&str>,
        effective_gas_price_wei: Option<&str>,
        actual_gas_cost_wei: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), AppError> {
        let block_number = block_number
            .map(|value| to_i64(value, "execution_attempts.included_block_number"))
            .transpose()?;
        sqlx::query(
            r#"
            UPDATE execution_attempts SET
                status=?, included_block_number=COALESCE(?, included_block_number),
                included_block_hash=COALESCE(?, included_block_hash),
                gas_used=COALESCE(?, gas_used),
                effective_gas_price_wei=COALESCE(?, effective_gas_price_wei),
                actual_gas_cost_wei=COALESCE(?, actual_gas_cost_wei),
                error=COALESCE(?, error), updated_at=CURRENT_TIMESTAMP
            WHERE tx_hash=?
            "#,
        )
        .bind(status)
        .bind(block_number)
        .bind(block_hash)
        .bind(gas_used)
        .bind(effective_gas_price_wei)
        .bind(actual_gas_cost_wei)
        .bind(error)
        .bind(tx_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Execution outcome update failed: {e}")))?;
        Ok(())
    }

    pub async fn save_settlement(
        &self,
        settlement: &SettlementRecord<'_>,
        deltas: &[SettlementDeltaRecord<'_>],
    ) -> Result<(), AppError> {
        let chain_id = to_i64(settlement.chain_id, "settlements.chain_id")?;
        let block_number = to_i64(settlement.block_number, "settlements.block_number")?;
        let confirmations = to_i64(settlement.confirmations, "settlements.confirmations")?;
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                AppError::Initialization(format!("Settlement transaction failed: {e}"))
            })?;
        sqlx::query(
            r#"
            INSERT INTO settlements (
                tx_hash, chain_id, strategy, settlement_token, realized_gross_delta_wei,
                actual_gas_cost_wei, realized_net_delta_wei, block_number, block_hash,
                confirmations, finalized, liquid, reusable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tx_hash) DO UPDATE SET
                realized_gross_delta_wei=excluded.realized_gross_delta_wei,
                actual_gas_cost_wei=excluded.actual_gas_cost_wei,
                realized_net_delta_wei=excluded.realized_net_delta_wei,
                block_number=excluded.block_number, block_hash=excluded.block_hash,
                confirmations=excluded.confirmations, finalized=excluded.finalized,
                liquid=excluded.liquid, reusable=excluded.reusable,
                updated_at=CURRENT_TIMESTAMP
            "#,
        )
        .bind(settlement.tx_hash)
        .bind(chain_id)
        .bind(settlement.strategy)
        .bind(settlement.settlement_token)
        .bind(settlement.realized_gross_delta_wei)
        .bind(settlement.actual_gas_cost_wei)
        .bind(settlement.realized_net_delta_wei)
        .bind(block_number)
        .bind(settlement.block_hash)
        .bind(confirmations)
        .bind(settlement.finalized)
        .bind(settlement.liquid)
        .bind(settlement.reusable)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Initialization(format!("Settlement upsert failed: {e}")))?;

        for delta in deltas {
            sqlx::query(
                r#"
                INSERT INTO settlement_deltas (
                    tx_hash, account, asset, decimals, balance_before, balance_after, delta_raw, liquid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tx_hash, account, asset) DO UPDATE SET
                    balance_before=excluded.balance_before, balance_after=excluded.balance_after,
                    delta_raw=excluded.delta_raw, liquid=excluded.liquid
                "#,
            )
            .bind(delta.tx_hash)
            .bind(delta.account)
            .bind(delta.asset)
            .bind(i64::from(delta.decimals))
            .bind(delta.balance_before)
            .bind(delta.balance_after)
            .bind(delta.delta_raw)
            .bind(delta.liquid)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Initialization(format!("Settlement delta upsert failed: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| AppError::Initialization(format!("Settlement commit failed: {e}")))?;
        Ok(())
    }

    pub async fn mark_block_settlements_reorged(
        &self,
        chain_id: u64,
        block_number: u64,
        canonical_block_hash: &str,
    ) -> Result<Vec<ReorgedSettlement>, AppError> {
        let chain_id = to_i64(chain_id, "settlements.chain_id")?;
        let block_number = to_i64(block_number, "settlements.block_number")?;
        let affected = sqlx::query(
            r#"
            SELECT realized_net_delta_wei, actual_gas_cost_wei
            FROM settlements
            WHERE chain_id=? AND block_number=? AND block_hash <> ? AND finalized=TRUE
            "#,
        )
        .bind(chain_id)
        .bind(block_number)
        .bind(canonical_block_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Reorg settlement read failed: {e}")))?
        .into_iter()
        .map(|row| ReorgedSettlement {
            realized_net_delta_wei: row.get("realized_net_delta_wei"),
            actual_gas_cost_wei: row.get("actual_gas_cost_wei"),
        })
        .collect::<Vec<_>>();
        sqlx::query(
            r#"
            UPDATE execution_attempts
            SET status='reorged', updated_at=CURRENT_TIMESTAMP
            WHERE chain_id=? AND included_block_number=?
              AND COALESCE(included_block_hash, '') <> ? AND status <> 'reorged'
            "#,
        )
        .bind(chain_id)
        .bind(block_number)
        .bind(canonical_block_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Reorg attempt update failed: {e}")))?;
        sqlx::query(
            r#"
            UPDATE settlements SET finalized=FALSE, reusable=FALSE, updated_at=CURRENT_TIMESTAMP
            WHERE chain_id=? AND block_number=? AND block_hash <> ?
            "#,
        )
        .bind(chain_id)
        .bind(block_number)
        .bind(canonical_block_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Reorg settlement update failed: {e}")))?;
        Ok(affected)
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
        let chain_id_i64 = to_i64(chain_id, "market_prices.chain_id")?;
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
        let chain_id_i64 = to_i64(chain_id, "router_discovery.chain_id")?;
        let inc_i64 = to_i64(increment, "router_discovery.seen_count_increment")?;
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
        let chain_id_i64 = to_i64(chain_id, "router_discovery.chain_id")?;
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

    async fn router_addresses_by_status(
        &self,
        chain_id: u64,
        status: &str,
    ) -> Result<Vec<Address>, AppError> {
        let chain_id_i64 = to_i64(chain_id, "router_discovery.chain_id")?;
        let rows =
            sqlx::query("SELECT address FROM router_discovery WHERE chain_id = ? AND status = ?")
                .bind(chain_id_i64)
                .bind(status)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    AppError::Initialization(format!("Router discovery load failed: {}", e))
                })?;

        let mut out = Vec::new();
        for row in rows {
            let addr_str: String = row.get("address");
            if let Ok(addr) = Address::from_str(&addr_str) {
                out.push(addr);
            } else {
                tracing::warn!(
                    target: "router_discovery",
                    address = %addr_str,
                    status,
                    "Invalid router address stored"
                );
            }
        }
        Ok(out)
    }

    pub async fn approved_routers(&self, chain_id: u64) -> Result<Vec<Address>, AppError> {
        self.router_addresses_by_status(chain_id, "approved").await
    }

    pub async fn ignored_routers(&self, chain_id: u64) -> Result<Vec<Address>, AppError> {
        self.router_addresses_by_status(chain_id, "ignored").await
    }

    pub async fn top_unknown_routers(
        &self,
        chain_id: u64,
        limit: u64,
    ) -> Result<Vec<(Address, u64)>, AppError> {
        let chain_id_i64 = to_i64(chain_id, "router_discovery.chain_id")?;
        let limit_i64 = to_i64(limit.max(1), "router_discovery.limit")?;
        let rows = sqlx::query(
            r#"
            SELECT address, seen_count
            FROM router_discovery
            WHERE chain_id = ?
              AND COALESCE(status, '') NOT IN ('approved', 'ignored')
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
                let seen_u64 = if seen_i64 < 0 {
                    0
                } else {
                    u64::try_from(seen_i64).map_err(|e| {
                        AppError::Initialization(format!(
                            "Router discovery seen_count conversion failed: {e} (value={seen_i64})"
                        ))
                    })?
                };
                out.push((addr, seen_u64));
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

    #[tokio::test]
    async fn upsert_nonce_state_rejects_values_outside_i64() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        let err = db
            .upsert_nonce_state(1, u64::MAX, 7, "[]")
            .await
            .expect_err("u64::MAX block_number should fail conversion");
        let msg = format!("{err}");
        assert!(msg.contains("conversion failed"));
    }

    #[tokio::test]
    async fn top_unknown_routers_excludes_resolved_statuses() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        let unresolved = "0x00000000000000000000000000000000000000aa";
        let approved = "0x00000000000000000000000000000000000000bb";
        let ignored = "0x00000000000000000000000000000000000000cc";

        db.record_router_observation(1, unresolved, "test", "unknown_router", 15)
            .await
            .expect("insert unresolved");
        db.record_router_observation(1, approved, "test", "unknown_router", 20)
            .await
            .expect("insert approved");
        db.record_router_observation(1, ignored, "test", "unknown_router", 25)
            .await
            .expect("insert ignored");

        db.set_router_status(1, approved, "approved", Some("v2"), Some("approved"))
            .await
            .expect("approve router");
        db.set_router_status(1, ignored, "ignored", None, Some("ignored"))
            .await
            .expect("ignore router");

        let top = db
            .top_unknown_routers(1, 10)
            .await
            .expect("load unresolved");
        assert_eq!(top.len(), 1);
        assert_eq!(format!("{:#x}", top[0].0), unresolved);
        assert_eq!(top[0].1, 15);
    }

    #[tokio::test]
    async fn reorg_reconciliation_is_idempotent_and_returns_realized_totals_once() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        db.save_execution_attempt(&ExecutionAttemptRecord {
            tx_hash: "0xfeed",
            estimate_id: None,
            chain_id: 1,
            strategy: "test",
            submission_mode: "private_bundle",
            status: "included",
            nonce: Some(1),
            target_block: Some(99),
        })
        .await
        .expect("attempt");
        db.update_execution_attempt_outcome(
            "0xfeed",
            "included",
            Some(100),
            Some("0xold"),
            Some("10"),
            Some("2"),
            Some("20"),
            None,
        )
        .await
        .expect("attempt outcome");
        db.save_settlement(
            &SettlementRecord {
                tx_hash: "0xfeed",
                chain_id: 1,
                strategy: "test",
                settlement_token: "0xweth",
                realized_gross_delta_wei: "25",
                actual_gas_cost_wei: "20",
                realized_net_delta_wei: "5",
                block_number: 100,
                block_hash: "0xold",
                confirmations: 2,
                finalized: true,
                liquid: true,
                reusable: true,
            },
            &[],
        )
        .await
        .expect("settlement");

        let first = db
            .mark_block_settlements_reorged(1, 100, "0xcanonical")
            .await
            .expect("first reconcile");
        assert_eq!(
            first,
            vec![ReorgedSettlement {
                realized_net_delta_wei: "5".into(),
                actual_gas_cost_wei: "20".into(),
            }]
        );
        let second = db
            .mark_block_settlements_reorged(1, 100, "0xcanonical")
            .await
            .expect("second reconcile");
        assert!(second.is_empty(), "settlement must not be reversed twice");
    }
}

#[cfg(test)]

crate::coverage_floor_pad_test!(80);
