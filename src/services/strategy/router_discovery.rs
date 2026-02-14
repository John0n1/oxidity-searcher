// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::data::db::Database;
use crate::services::strategy::decode::RouterKind;
use crate::services::strategy::routers::{
    BalancerVault, DexRouter, KyberAggregationRouterV2, OneInchAggregationRouter,
    OneInchAggregationRouterV5, ParaSwapAugustusV6, RelayApprovalProxyV3, RelayRouterV3,
    TransitSwapRouterV5, UniV2Router, UniV3Multicall, UniV3MulticallDeadline, UniV3Router,
    UniversalRouter, UniversalRouterDeadline, ZeroXExchangeProxy,
};
use alloy::primitives::Address;
use alloy_sol_types::SolCall;
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RouterDiscovery {
    chain_id: u64,
    allowlist: Arc<DashSet<Address>>,
    db: Database,
    client: Client,
    rpc_url: Option<String>,
    etherscan_api_key: Option<String>,
    enabled: bool,
    auto_allow: bool,
    min_hits: u64,
    flush_every: u64,
    check_interval: Duration,
    max_entries: usize,
    state: Arc<DashMap<Address, DiscoveryState>>,
}

#[derive(Clone)]
struct DiscoveryState {
    seen: u64,
    last_flushed: u64,
    last_checked: Instant,
    checking: bool,
}

#[derive(Clone)]
struct RouterClassification {
    kind: RouterKind,
    note: String,
}

impl RouterDiscovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        allowlist: Arc<DashSet<Address>>,
        db: Database,
        rpc_url: Option<String>,
        etherscan_api_key: Option<String>,
        enabled: bool,
        auto_allow: bool,
        min_hits: u64,
        flush_every: u64,
        check_interval: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            chain_id,
            allowlist,
            db,
            client: Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .unwrap(),
            rpc_url,
            etherscan_api_key,
            enabled,
            auto_allow,
            min_hits: min_hits.max(1),
            flush_every: flush_every.max(1),
            check_interval,
            max_entries: max_entries.max(1),
            state: Arc::new(DashMap::new()),
        }
    }

    pub fn record_unknown_router(&self, router: Address, source: &str) {
        if !self.enabled {
            return;
        }
        if self.state.len() >= self.max_entries && !self.state.contains_key(&router) {
            // Prefer evicting a stale/low-signal entry over dropping new unknowns forever.
            let victim = self
                .state
                .iter()
                .min_by(|a, b| {
                    a.value()
                        .seen
                        .cmp(&b.value().seen)
                        .then_with(|| a.value().last_checked.cmp(&b.value().last_checked))
                })
                .map(|entry| *entry.key());
            if let Some(victim) = victim {
                self.state.remove(&victim);
                tracing::debug!(
                    target: "router_discovery",
                    evicted = %format!("{victim:#x}"),
                    len = self.state.len(),
                    max = self.max_entries,
                    "Router discovery at capacity; evicted stale entry"
                );
            } else {
                tracing::debug!(
                    target: "router_discovery",
                    len = self.state.len(),
                    max = self.max_entries,
                    "Router discovery at capacity; dropping new router"
                );
                return;
            }
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

    pub fn spawn_bootstrap_top_unknown(&self, limit: usize, lookback_blocks: u64) {
        let discovery = self.clone();
        tokio::spawn(async move {
            discovery
                .bootstrap_top_unknown_allowlist(limit, lookback_blocks)
                .await;
        });
    }
}

impl RouterDiscovery {
    async fn check_and_allow(&self, router: Address) {
        let classification = self.classify_router(router).await;
        match classification {
            Ok(Some(classification)) => {
                self.allowlist.insert(router);
                let kind_str = match classification.kind {
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
                        Some(&classification.note),
                    )
                    .await;
                tracing::info!(
                    target: "router_discovery",
                    router = %format!("{router:#x}"),
                    router_kind = kind_str,
                    note = %classification.note,
                    "Auto-approved router"
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
                        Some("abi_or_selector_unsupported"),
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

    async fn classify_router(
        &self,
        router: Address,
    ) -> Result<Option<RouterClassification>, AppError> {
        if let Some(classification) = self.classify_router_via_etherscan(router).await? {
            return Ok(Some(classification));
        }

        self.classify_router_via_recent_selectors(router, 96).await
    }

    async fn classify_router_via_etherscan(
        &self,
        router: Address,
    ) -> Result<Option<RouterClassification>, AppError> {
        let key = match &self.etherscan_api_key {
            Some(k) if !k.is_empty() => k.clone(),
            _ => return Ok(None),
        };

        if self.chain_id != 1 {
            return Ok(None);
        }

        let url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getabi&address={:#x}&apikey={}",
            self.chain_id, router, key
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
            Ok(Some(RouterClassification {
                kind: RouterKind::V3Like,
                note: "etherscan_abi".to_string(),
            }))
        } else if has_v2 {
            Ok(Some(RouterClassification {
                kind: RouterKind::V2Like,
                note: "etherscan_abi".to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn classify_router_via_recent_selectors(
        &self,
        router: Address,
        lookback_blocks: u64,
    ) -> Result<Option<RouterClassification>, AppError> {
        let mut candidates = HashSet::new();
        let key = format!("{router:#x}").to_ascii_lowercase();
        candidates.insert(key.clone());
        let observed = self
            .collect_recent_selectors(&candidates, lookback_blocks)
            .await?;
        let Some(selector_counts) = observed.get(&key) else {
            return Ok(None);
        };

        let mut ranked: Vec<(&String, &u64)> = selector_counts.iter().collect();
        ranked.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        if let Some((selector, _)) = ranked
            .into_iter()
            .find(|(selector, _)| Self::selector_kind(selector).is_some())
        {
            let kind = Self::selector_kind(selector).ok_or_else(|| {
                AppError::Initialization("selector classification missing".into())
            })?;
            return Ok(Some(RouterClassification {
                kind,
                note: format!("selector_observed:{selector}"),
            }));
        }
        Ok(None)
    }

    async fn bootstrap_top_unknown_allowlist(&self, limit: usize, lookback_blocks: u64) {
        if !self.enabled || !self.auto_allow {
            return;
        }

        let candidates = match self
            .db
            .top_unknown_routers(self.chain_id, limit as u64)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "router_discovery",
                    error = %e,
                    "Failed loading top unknown routers for bootstrap"
                );
                return;
            }
        };
        if candidates.is_empty() {
            return;
        }

        let candidate_hex: HashSet<String> = candidates
            .iter()
            .map(|(addr, _)| format!("{addr:#x}").to_ascii_lowercase())
            .collect();
        let observed = match self
            .collect_recent_selectors(&candidate_hex, lookback_blocks)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "router_discovery",
                    error = %e,
                    "Failed collecting selector activity for bootstrap"
                );
                return;
            }
        };

        let mut approved = 0u64;
        for (router, seen) in candidates {
            if self.allowlist.contains(&router) {
                continue;
            }
            let key = format!("{router:#x}").to_ascii_lowercase();
            let Some(selector_counts) = observed.get(&key) else {
                continue;
            };

            let mut ranked: Vec<(&String, &u64)> = selector_counts.iter().collect();
            ranked.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
            let Some((selector, hits)) = ranked
                .into_iter()
                .find(|(selector, _)| Self::selector_kind(selector).is_some())
            else {
                continue;
            };
            let Some(kind) = Self::selector_kind(selector) else {
                continue;
            };
            let kind_str = match kind {
                RouterKind::V2Like => "v2",
                RouterKind::V3Like => "v3",
            };

            self.allowlist.insert(router);
            let note = format!("top_unknown_selector:{selector}");
            let _ = self
                .db
                .set_router_status(
                    self.chain_id,
                    &format!("{router:#x}"),
                    "approved",
                    Some(kind_str),
                    Some(&note),
                )
                .await;
            approved = approved.saturating_add(1);
            tracing::info!(
                target: "router_discovery",
                router = %format!("{router:#x}"),
                seen,
                selector = %selector,
                selector_hits = *hits,
                router_kind = kind_str,
                "Bootstrap-approved top unknown router"
            );
        }

        if approved > 0 {
            tracing::info!(
                target: "router_discovery",
                approved,
                "Router discovery bootstrap completed"
            );
        }
    }

    async fn collect_recent_selectors(
        &self,
        candidates: &HashSet<String>,
        lookback_blocks: u64,
    ) -> Result<HashMap<String, HashMap<String, u64>>, AppError> {
        if candidates.is_empty() {
            return Ok(HashMap::new());
        }
        let Some(_) = &self.rpc_url else {
            return Ok(HashMap::new());
        };

        let head_val = self.rpc_request("eth_blockNumber", json!([])).await?;
        let Some(head_hex) = head_val.as_str() else {
            return Err(AppError::Initialization(
                "eth_blockNumber returned non-string".into(),
            ));
        };
        let head = u64::from_str_radix(head_hex.trim_start_matches("0x"), 16)
            .map_err(|e| AppError::Initialization(format!("Invalid block number hex: {e}")))?;
        let window = lookback_blocks.max(1);
        let start = head.saturating_sub(window.saturating_sub(1));

        let mut out: HashMap<String, HashMap<String, u64>> = HashMap::new();
        for block_number in start..=head {
            let block_hex = format!("0x{block_number:x}");
            let block_val = self
                .rpc_request("eth_getBlockByNumber", json!([block_hex, true]))
                .await?;
            let Some(txs) = block_val.get("transactions").and_then(|v| v.as_array()) else {
                continue;
            };
            for tx in txs {
                let Some(to) = tx.get("to").and_then(|v| v.as_str()) else {
                    continue;
                };
                let to = to.to_ascii_lowercase();
                if !candidates.contains(&to) {
                    continue;
                }
                let input = tx
                    .get("input")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x")
                    .to_ascii_lowercase();
                let selector = if input.len() >= 10 {
                    input[..10].to_string()
                } else {
                    input
                };
                out.entry(to)
                    .or_default()
                    .entry(selector)
                    .and_modify(|c| *c = c.saturating_add(1))
                    .or_insert(1);
            }
        }
        Ok(out)
    }

    async fn rpc_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        let Some(rpc_url) = &self.rpc_url else {
            return Err(AppError::Config(
                "Router discovery RPC URL is not configured".into(),
            ));
        };
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let resp = self
            .client
            .post(rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("Router discovery RPC failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::ApiCall {
                provider: "router_discovery_rpc".into(),
                status: resp.status().as_u16(),
            });
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            AppError::Initialization(format!("Router discovery RPC decode failed: {e}"))
        })?;
        if let Some(err) = body.get("error") {
            return Err(AppError::Initialization(format!(
                "Router discovery RPC error for {method}: {err}"
            )));
        }
        Ok(body
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    fn selector_kind(selector: &str) -> Option<RouterKind> {
        let parsed = parse_selector_hex(selector)?;
        if matches!(
            parsed,
            UniversalRouter::executeCall::SELECTOR
                | UniversalRouterDeadline::executeCall::SELECTOR
                | UniV3Router::exactInputCall::SELECTOR
                | UniV3Router::exactInputSingleCall::SELECTOR
                | UniV3Router::exactOutputCall::SELECTOR
                | UniV3Router::exactOutputSingleCall::SELECTOR
                | UniV3Multicall::multicallCall::SELECTOR
                | UniV3MulticallDeadline::multicallCall::SELECTOR
        ) {
            return Some(RouterKind::V3Like);
        }
        if matches!(
            parsed,
            UniV2Router::swapExactETHForTokensCall::SELECTOR
                | UniV2Router::swapETHForExactTokensCall::SELECTOR
                | UniV2Router::swapExactTokensForETHCall::SELECTOR
                | UniV2Router::swapTokensForExactETHCall::SELECTOR
                | UniV2Router::swapExactTokensForTokensCall::SELECTOR
                | UniV2Router::swapTokensForExactTokensCall::SELECTOR
                | UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::SELECTOR
                | UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::SELECTOR
                | UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::SELECTOR
                | OneInchAggregationRouter::swapCall::SELECTOR
                | OneInchAggregationRouterV5::swapCall::SELECTOR
                | ParaSwapAugustusV6::swapExactAmountInCall::SELECTOR
                | ParaSwapAugustusV6::swapExactAmountOutCall::SELECTOR
                | KyberAggregationRouterV2::swapCall::SELECTOR
                | KyberAggregationRouterV2::swapGenericCall::SELECTOR
                | KyberAggregationRouterV2::swapSimpleModeCall::SELECTOR
                | ZeroXExchangeProxy::transformERC20Call::SELECTOR
                | DexRouter::dagSwapByOrderIdCall::SELECTOR
                | DexRouter::dagSwapToCall::SELECTOR
                | DexRouter::smartSwapByOrderIdCall::SELECTOR
                | DexRouter::smartSwapToCall::SELECTOR
                | DexRouter::smartSwapByInvestCall::SELECTOR
                | DexRouter::smartSwapByInvestWithRefundCall::SELECTOR
                | DexRouter::swapWrapToWithBaseRequestCall::SELECTOR
                | DexRouter::uniswapV3SwapToWithBaseRequestCall::SELECTOR
                | DexRouter::unxswapToWithBaseRequestCall::SELECTOR
                | TransitSwapRouterV5::exactInputV2SwapCall::SELECTOR
                | TransitSwapRouterV5::exactInputV2SwapAndGasUsedCall::SELECTOR
                | TransitSwapRouterV5::exactInputV3SwapCall::SELECTOR
                | TransitSwapRouterV5::exactInputV3SwapAndGasUsedCall::SELECTOR
                | RelayRouterV3::multicallCall::SELECTOR
                | RelayApprovalProxyV3::transferAndMulticallCall::SELECTOR
                | RelayApprovalProxyV3::permitTransferAndMulticallCall::SELECTOR
                | RelayApprovalProxyV3::permit3009TransferAndMulticallCall::SELECTOR
                | RelayApprovalProxyV3::permit2TransferAndMulticallCall::SELECTOR
                | BalancerVault::swapCall::SELECTOR
                | BalancerVault::batchSwapCall::SELECTOR
        ) {
            return Some(RouterKind::V2Like);
        }
        None
    }
}

fn parse_selector_hex(raw: &str) -> Option<[u8; 4]> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.len() != 8 {
        return None;
    }
    let mut out = [0u8; 4];
    for i in 0..4 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}

#[derive(Debug, Deserialize)]
struct EtherscanAbiResponse {
    result: Option<String>,
}
