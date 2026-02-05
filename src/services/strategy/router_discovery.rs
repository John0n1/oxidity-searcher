// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::data::db::Database;
use crate::services::strategy::decode::RouterKind;
use alloy::primitives::Address;
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RouterDiscovery {
    chain_id: u64,
    allowlist: Arc<DashSet<Address>>,
    db: Database,
    client: Client,
    etherscan_api_key: Option<String>,
    enabled: bool,
    auto_allow: bool,
    min_hits: u64,
    flush_every: u64,
    check_interval: Duration,
    state: Arc<DashMap<Address, DiscoveryState>>,
}

#[derive(Clone)]
struct DiscoveryState {
    seen: u64,
    last_flushed: u64,
    last_checked: Instant,
    checking: bool,
}

impl RouterDiscovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        allowlist: Arc<DashSet<Address>>,
        db: Database,
        etherscan_api_key: Option<String>,
        enabled: bool,
        auto_allow: bool,
        min_hits: u64,
        flush_every: u64,
        check_interval: Duration,
    ) -> Self {
        Self {
            chain_id,
            allowlist,
            db,
            client: Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .unwrap(),
            etherscan_api_key,
            enabled,
            auto_allow,
            min_hits: min_hits.max(1),
            flush_every: flush_every.max(1),
            check_interval,
            state: Arc::new(DashMap::new()),
        }
    }

    pub fn record_unknown_router(&self, router: Address, source: &str) {
        if !self.enabled {
            return;
        }

        let mut should_flush = None;
        let mut should_check = false;
        {
            let mut entry = self.state.entry(router).or_insert_with(|| DiscoveryState {
                seen: 0,
                last_flushed: 0,
                last_checked: Instant::now()
                    .checked_sub(self.check_interval)
                    .unwrap_or_else(Instant::now),
                checking: false,
            });
            entry.seen = entry.seen.saturating_add(1);
            let delta = entry.seen.saturating_sub(entry.last_flushed);
            if delta >= self.flush_every {
                entry.last_flushed = entry.seen;
                should_flush = Some(delta);
            }

            if self.auto_allow
                && self.etherscan_api_key.is_some()
                && !self.allowlist.contains(&router)
                && entry.seen >= self.min_hits
                && entry.last_checked.elapsed() >= self.check_interval
                && !entry.checking
            {
                entry.last_checked = Instant::now();
                entry.checking = true;
                should_check = true;
            }
        }

        if let Some(increment) = should_flush {
            let db = self.db.clone();
            let chain_id = self.chain_id;
            let addr = format!("{router:#x}");
            let source = source.to_string();
            tokio::spawn(async move {
                let _ = db
                    .record_router_observation(
                        chain_id,
                        &addr,
                        &source,
                        "unknown_router",
                        increment,
                    )
                    .await;
            });
        }

        if should_check {
            let discovery = self.clone();
            tokio::spawn(async move {
                discovery.check_and_allow(router).await;
            });
        }
    }
}

impl RouterDiscovery {
    async fn check_and_allow(&self, router: Address) {
        let classification = self.classify_router(router).await;
        match classification {
            Ok(Some(kind)) => {
                self.allowlist.insert(router);
                let kind_str = match kind {
                    RouterKind::V2Like => "v2",
                    RouterKind::V3Like => "v3",
                };
                let _ = self
                    .db
                    .set_router_status(
                        self.chain_id,
                        &format!("{router:#x}"),
                        "approved",
                        Some(kind_str),
                        Some("etherscan_abi"),
                    )
                    .await;
                tracing::info!(
                    target: "router_discovery",
                    router = %format!("{router:#x}"),
                    router_kind = kind_str,
                    "Auto-approved router from Etherscan ABI"
                );
            }
            Ok(None) => {
                let _ = self
                    .db
                    .set_router_status(
                        self.chain_id,
                        &format!("{router:#x}"),
                        "ignored",
                        None,
                        Some("abi_missing_or_unsupported"),
                    )
                    .await;
            }
            Err(e) => {
                tracing::debug!(
                    target: "router_discovery",
                    router = %format!("{router:#x}"),
                    error = %e,
                    "Router discovery check failed"
                );
            }
        }

        if let Some(mut entry) = self.state.get_mut(&router) {
            entry.checking = false;
        }
    }

    async fn classify_router(&self, router: Address) -> Result<Option<RouterKind>, AppError> {
        let key = match &self.etherscan_api_key {
            Some(k) if !k.is_empty() => k.clone(),
            _ => return Ok(None),
        };

        if self.chain_id != 1 {
            return Ok(None);
        }

        let url = format!(
            "https://api.etherscan.io/api?module=contract&action=getabi&address={:#x}&apikey={}",
            router, key
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("Etherscan ABI failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(AppError::ApiCall {
                provider: "Etherscan ABI".into(),
                status: resp.status().as_u16(),
            });
        }
        let parsed: EtherscanAbiResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("Etherscan ABI decode failed: {e}")))?;
        let abi_json = match parsed.result {
            Some(r) => r,
            None => return Ok(None),
        };
        if abi_json.contains("Contract source code not verified") {
            return Ok(None);
        }

        let abi: Vec<serde_json::Value> = match serde_json::from_str(&abi_json) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let mut has_v2 = false;
        let mut has_v3 = false;
        for entry in abi {
            if entry.get("type").and_then(|v| v.as_str()) != Some("function") {
                continue;
            }
            let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
            match name {
                "swapExactTokensForTokens" | "swapExactETHForTokens" | "swapExactTokensForETH" => {
                    has_v2 = true;
                }
                "exactInput" | "exactInputSingle" => {
                    has_v3 = true;
                }
                _ => {}
            }
        }

        if has_v3 {
            Ok(Some(RouterKind::V3Like))
        } else if has_v2 {
            Ok(Some(RouterKind::V2Like))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Deserialize)]
struct EtherscanAbiResponse {
    result: Option<String>,
}
