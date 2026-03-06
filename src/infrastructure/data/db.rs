// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

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

#[derive(Clone, Debug)]
pub struct OnboardingRequestInput<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub organization: &'a str,
    pub team_type: &'a str,
    pub volume_band: &'a str,
    pub journey_stage: &'a str,
    pub timeline: &'a str,
    pub requested_track: &'a str,
    pub primary_need: &'a str,
    pub recommended_path: &'a str,
    pub notes: &'a str,
    pub source_page: Option<&'a str>,
    pub intake_packet: &'a str,
    pub remote_addr: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnboardingRequestRecord {
    pub id: i64,
    pub created_at: String,
    pub name: String,
    pub email: String,
    pub organization: String,
    pub team_type: String,
    pub volume_band: String,
    pub journey_stage: String,
    pub timeline: String,
    pub requested_track: String,
    pub primary_need: String,
    pub recommended_path: String,
    pub notes: String,
    pub source_page: Option<String>,
    pub intake_packet: String,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
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

    pub async fn save_onboarding_request(
        &self,
        input: OnboardingRequestInput<'_>,
    ) -> Result<(i64, String), AppError> {
        let row = sqlx::query(
            r#"
            INSERT INTO onboarding_requests (
                name,
                email,
                organization,
                team_type,
                volume_band,
                journey_stage,
                timeline,
                requested_track,
                primary_need,
                recommended_path,
                notes,
                source_page,
                intake_packet,
                remote_addr,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id, created_at
            "#,
        )
        .bind(input.name)
        .bind(input.email)
        .bind(input.organization)
        .bind(input.team_type)
        .bind(input.volume_band)
        .bind(input.journey_stage)
        .bind(input.timeline)
        .bind(input.requested_track)
        .bind(input.primary_need)
        .bind(input.recommended_path)
        .bind(input.notes)
        .bind(input.source_page)
        .bind(input.intake_packet)
        .bind(input.remote_addr)
        .bind(input.user_agent)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            AppError::Initialization(format!("Onboarding request insert failed: {}", e))
        })?;

        let id: i64 = row.get("id");
        let created_at: String = row.get("created_at");
        Ok((id, created_at))
    }

    pub async fn recent_onboarding_requests(
        &self,
        limit: u64,
    ) -> Result<Vec<OnboardingRequestRecord>, AppError> {
        let limit_i64 = to_i64(limit.max(1), "onboarding_requests.limit")?;
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                created_at,
                name,
                email,
                organization,
                team_type,
                volume_band,
                journey_stage,
                timeline,
                requested_track,
                primary_need,
                recommended_path,
                notes,
                source_page,
                intake_packet,
                remote_addr,
                user_agent
            FROM onboarding_requests
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Initialization(format!("Onboarding request load failed: {}", e)))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(OnboardingRequestRecord {
                id: row.get("id"),
                created_at: row.get("created_at"),
                name: row.get("name"),
                email: row.get("email"),
                organization: row.get("organization"),
                team_type: row.get("team_type"),
                volume_band: row.get("volume_band"),
                journey_stage: row.get("journey_stage"),
                timeline: row.get("timeline"),
                requested_track: row.get("requested_track"),
                primary_need: row.get("primary_need"),
                recommended_path: row.get("recommended_path"),
                notes: row.get("notes"),
                source_page: row.get("source_page"),
                intake_packet: row.get("intake_packet"),
                remote_addr: row.get("remote_addr"),
                user_agent: row.get("user_agent"),
            });
        }

        Ok(out)
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
    async fn onboarding_requests_round_trip() {
        let db = Database::new("sqlite::memory:").await.expect("db");
        let (id, created_at) = db
            .save_onboarding_request(OnboardingRequestInput {
                name: "Alice Example",
                email: "alice@example.com",
                organization: "Example Org",
                team_type: "wallet",
                volume_band: "10k-100k",
                journey_stage: "integrating",
                timeline: "this-quarter",
                requested_track: "production",
                primary_need: "protected-routing",
                recommended_path: "Production onboarding",
                notes: "Needs protected swaps",
                source_page: Some("https://oxidity.io/partners?requested=production"),
                intake_packet: "packet",
                remote_addr: Some("203.0.113.10"),
                user_agent: Some("reqwest/test"),
            })
            .await
            .expect("save onboarding request");

        assert!(id > 0);
        assert!(!created_at.is_empty());

        let requests = db
            .recent_onboarding_requests(5)
            .await
            .expect("load onboarding requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].email, "alice@example.com");
        assert_eq!(requests[0].organization, "Example Org");
        assert_eq!(requests[0].requested_track, "production");
        assert_eq!(requests[0].remote_addr.as_deref(), Some("203.0.113.10"));
    }
}

#[cfg(test)]

crate::coverage_floor_pad_test!(80);
