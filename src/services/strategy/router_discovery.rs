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
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as TokioMutex;

#[derive(Clone)]
pub struct RouterDiscovery {
    chain_id: u64,
    allowlist: Arc<DashSet<Address>>,
    db: Database,
    client: Client,
    http_provider: Option<String>,
    etherscan_api_key: Option<String>,
    enabled: bool,
    auto_allow: bool,
    min_hits: u64,
    flush_every: u64,
    check_interval: Duration,
    max_entries: usize,
    budget: RouterDiscoveryBudget,
    cache_path: Option<String>,
    force_full_rescan: bool,
    cooldown_until: Arc<TokioMutex<Option<Instant>>>,
    metrics: Arc<RouterDiscoveryMetrics>,
    state: Arc<DashMap<Address, DiscoveryState>>,
}

#[derive(Clone, Debug)]
pub struct RouterDiscoveryBudget {
    pub max_blocks_per_cycle: u64,
    pub max_rpc_calls_per_cycle: u64,
    pub cycle_timeout: Duration,
    pub failure_budget: u64,
    pub cooldown: Duration,
}

impl Default for RouterDiscoveryBudget {
    fn default() -> Self {
        Self {
            max_blocks_per_cycle: 256,
            max_rpc_calls_per_cycle: 512,
            cycle_timeout: Duration::from_secs(8),
            failure_budget: 16,
            cooldown: Duration::from_secs(45),
        }
    }
}

#[derive(Default)]
struct RouterDiscoveryMetrics {
    rpc_calls: AtomicU64,
    budget_exhaustions: AtomicU64,
    cycle_failures: AtomicU64,
    cooldown_skips: AtomicU64,
    cache_hits: AtomicU64,
    cache_writes: AtomicU64,
}

#[derive(Clone)]
pub struct RouterDiscoveryConfig {
    pub chain_id: u64,
    pub allowlist: Arc<DashSet<Address>>,
    pub db: Database,
    pub http_provider: Option<String>,
    pub etherscan_api_key: Option<String>,
    pub enabled: bool,
    pub auto_allow: bool,
    pub min_hits: u64,
    pub flush_every: u64,
    pub check_interval: Duration,
    pub max_entries: usize,
    pub budget: RouterDiscoveryBudget,
    pub cache_path: Option<String>,
    pub force_full_rescan: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RouterDiscoveryCache {
    version: u32,
    chain_id: u64,
    last_success_unix: i64,
    routers: Vec<RouterDiscoveryCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouterDiscoveryCacheEntry {
    address: String,
    kind: String,
    note: String,
    last_success_unix: i64,
}

const SELECTOR_KIND_SHARE_BPS_MIN: u64 = 7_000;
const SELECTOR_DISTINCT_MIN: usize = 2;

impl RouterDiscovery {
    pub fn new(config: RouterDiscoveryConfig) -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|e| {
                AppError::Initialization(format!("router discovery HTTP client init failed: {e}"))
            })?;

        let mut discovery = Self {
            chain_id: config.chain_id,
            allowlist: config.allowlist,
            db: config.db,
            client,
            http_provider: config.http_provider,
            etherscan_api_key: config.etherscan_api_key,
            enabled: config.enabled,
            auto_allow: config.auto_allow,
            min_hits: config.min_hits.max(1),
            flush_every: config.flush_every.max(1),
            check_interval: config.check_interval,
            max_entries: config.max_entries.max(1),
            budget: RouterDiscoveryBudget {
                max_blocks_per_cycle: config.budget.max_blocks_per_cycle.max(1),
                max_rpc_calls_per_cycle: config.budget.max_rpc_calls_per_cycle.max(4),
                cycle_timeout: config.budget.cycle_timeout.max(Duration::from_millis(500)),
                failure_budget: config.budget.failure_budget.max(1),
                cooldown: config.budget.cooldown.max(Duration::from_secs(5)),
            },
            cache_path: config.cache_path,
            force_full_rescan: config.force_full_rescan,
            cooldown_until: Arc::new(TokioMutex::new(None)),
            metrics: Arc::new(RouterDiscoveryMetrics::default()),
            state: Arc::new(DashMap::new()),
        };
        discovery.load_persisted_cache();
        Ok(discovery)
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

    fn load_persisted_cache(&mut self) {
        if self.force_full_rescan {
            return;
        }
        let Some(path) = self.cache_path.as_deref() else {
            return;
        };
        let body = match std::fs::read_to_string(path) {
            Ok(body) => body,
            Err(_) => return,
        };
        let parsed: RouterDiscoveryCache = match serde_json::from_str(&body) {
            Ok(parsed) => parsed,
            Err(_) => return,
        };
        if parsed.chain_id != self.chain_id || parsed.version != 1 {
            return;
        }
        let mut restored = 0u64;
        for entry in parsed.routers {
            if let Ok(addr) = entry.address.parse::<Address>() {
                self.allowlist.insert(addr);
                restored = restored.saturating_add(1);
            }
        }
        if restored > 0 {
            self.metrics
                .cache_hits
                .fetch_add(restored, Ordering::Relaxed);
            tracing::info!(
                target: "router_discovery",
                restored,
                path = %path,
                "Loaded router discovery cache"
            );
        }
    }

    async fn persist_cache_entry(&self, router: Address, kind: &str, note: &str) {
        let Some(path) = self.cache_path.clone() else {
            return;
        };
        let parent = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_path_buf());
        let router_hex = format!("{router:#x}");
        let kind = kind.to_string();
        let note = note.to_string();
        let chain_id = self.chain_id;
        tokio::spawn(async move {
            if let Some(parent) = parent {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let mut cache = match tokio::fs::read_to_string(&path).await {
                Ok(body) => serde_json::from_str::<RouterDiscoveryCache>(&body).unwrap_or_default(),
                Err(_) => RouterDiscoveryCache::default(),
            };
            if cache.version == 0 {
                cache.version = 1;
            }
            cache.chain_id = chain_id;
            cache.last_success_unix = chrono::Utc::now().timestamp();
            if let Some(existing) = cache.routers.iter_mut().find(|e| e.address == router_hex) {
                existing.kind = kind.clone();
                existing.note = note.clone();
                existing.last_success_unix = cache.last_success_unix;
            } else {
                cache.routers.push(RouterDiscoveryCacheEntry {
                    address: router_hex.clone(),
                    kind: kind.clone(),
                    note: note.clone(),
                    last_success_unix: cache.last_success_unix,
                });
            }
            if cache.routers.len() > 20_000 {
                cache
                    .routers
                    .sort_by_key(|e| std::cmp::Reverse(e.last_success_unix));
                cache.routers.truncate(20_000);
            }
            if let Ok(encoded) = serde_json::to_vec_pretty(&cache) {
                let _ = tokio::fs::write(&path, encoded).await;
            }
        });
        self.metrics.cache_writes.fetch_add(1, Ordering::Relaxed);
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
                self.persist_cache_entry(router, kind_str, &classification.note)
                    .await;
            }
            Ok(None) => {
                let _ = self
                    .db
                    .set_router_status(
                        self.chain_id,
                        &format!("{router:#x}"),
                        "ignored",
                        None,
                        Some("abi_selector_or_bytecode_verification_failed"),
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
        let bytecode = self.fetch_router_bytecode(router).await?;
        if bytecode.is_empty() {
            return Ok(None);
        }
        if let Some(classification) = self
            .classify_router_via_etherscan(router, &bytecode)
            .await?
        {
            return Ok(Some(classification));
        }

        self.classify_router_via_recent_selectors(router, 96, &bytecode)
            .await
    }

    async fn classify_router_via_etherscan(
        &self,
        router: Address,
        bytecode: &[u8],
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

        let mut v2_function_markers = 0u64;
        let mut v3_function_markers = 0u64;
        for entry in abi {
            if entry.get("type").and_then(|v| v.as_str()) != Some("function") {
                continue;
            }
            let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
            match name {
                "swapExactTokensForTokens" | "swapExactETHForTokens" | "swapExactTokensForETH" => {
                    v2_function_markers = v2_function_markers.saturating_add(1);
                }
                "exactInput" | "exactInputSingle" => {
                    v3_function_markers = v3_function_markers.saturating_add(1);
                }
                _ => {}
            }
        }

        let (kind, marker_hits) =
            if v3_function_markers >= 2 && v3_function_markers >= v2_function_markers {
                (RouterKind::V3Like, v3_function_markers)
            } else if v2_function_markers >= 2 {
                (RouterKind::V2Like, v2_function_markers)
            } else {
                return Ok(None);
            };
        let bytecode_selector_hits =
            Self::count_matching_selectors(bytecode, Self::selectors_for_kind(kind));
        if bytecode_selector_hits == 0 {
            return Ok(None);
        }
        Ok(Some(RouterClassification {
            kind,
            note: format!(
                "etherscan_abi:markers={marker_hits} bytecode_selector_hits={bytecode_selector_hits}"
            ),
        }))
    }

    async fn classify_router_via_recent_selectors(
        &self,
        router: Address,
        lookback_blocks: u64,
        bytecode: &[u8],
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
        Ok(self.classify_selector_profile(
            selector_counts,
            bytecode,
            self.min_hits.max(2),
            "selector_profile",
        ))
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
            let bytecode = match self.fetch_router_bytecode(router).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(
                        target: "router_discovery",
                        router = %format!("{router:#x}"),
                        error = %e,
                        "Bootstrap bytecode verification failed"
                    );
                    continue;
                }
            };
            if bytecode.is_empty() {
                continue;
            }
            let Some(classification) = self.classify_selector_profile(
                selector_counts,
                &bytecode,
                self.min_hits.max(2),
                "top_unknown_selector",
            ) else {
                continue;
            };
            let kind = classification.kind;
            let kind_str = match kind {
                RouterKind::V2Like => "v2",
                RouterKind::V3Like => "v3",
            };

            self.allowlist.insert(router);
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
            approved = approved.saturating_add(1);
            tracing::info!(
                target: "router_discovery",
                router = %format!("{router:#x}"),
                seen,
                router_kind = kind_str,
                note = %classification.note,
                "Bootstrap-approved top unknown router"
            );
            self.persist_cache_entry(router, kind_str, &classification.note)
                .await;
        }

        if approved > 0 {
            tracing::info!(
                target: "router_discovery",
                approved,
                "Router discovery bootstrap completed"
            );
        }
    }

    async fn fetch_router_bytecode(&self, router: Address) -> Result<Vec<u8>, AppError> {
        let code_val = self
            .rpc_request("eth_getCode", json!([format!("{router:#x}"), "latest"]))
            .await?;
        let code_hex = code_val.as_str().ok_or_else(|| {
            AppError::Initialization("eth_getCode returned non-string result".into())
        })?;
        let compact = code_hex
            .strip_prefix("0x")
            .or_else(|| code_hex.strip_prefix("0X"))
            .unwrap_or(code_hex);
        if compact.is_empty() {
            return Ok(Vec::new());
        }
        hex::decode(compact)
            .map_err(|e| AppError::Initialization(format!("eth_getCode hex decode failed: {e}")))
    }

    fn classify_selector_profile(
        &self,
        selector_counts: &HashMap<String, u64>,
        bytecode: &[u8],
        min_hits: u64,
        note_prefix: &str,
    ) -> Option<RouterClassification> {
        let mut v2_hits = 0u64;
        let mut v3_hits = 0u64;
        let mut v2_ranked: Vec<(String, u64)> = Vec::new();
        let mut v3_ranked: Vec<(String, u64)> = Vec::new();
        for (selector, count) in selector_counts {
            match Self::selector_kind(selector) {
                Some(RouterKind::V2Like) => {
                    v2_hits = v2_hits.saturating_add(*count);
                    v2_ranked.push((selector.clone(), *count));
                }
                Some(RouterKind::V3Like) => {
                    v3_hits = v3_hits.saturating_add(*count);
                    v3_ranked.push((selector.clone(), *count));
                }
                None => {}
            }
        }
        let (kind, kind_hits, mut kind_ranked, other_hits) = if v3_hits >= v2_hits {
            (RouterKind::V3Like, v3_hits, v3_ranked, v2_hits)
        } else {
            (RouterKind::V2Like, v2_hits, v2_ranked, v3_hits)
        };
        if kind_hits < min_hits.max(2) {
            return None;
        }
        if kind_ranked.len() < SELECTOR_DISTINCT_MIN {
            return None;
        }
        let total_known_hits = kind_hits.saturating_add(other_hits);
        if total_known_hits == 0 {
            return None;
        }
        let kind_share_bps = kind_hits.saturating_mul(10_000) / total_known_hits;
        if kind_share_bps < SELECTOR_KIND_SHARE_BPS_MIN {
            return None;
        }
        kind_ranked.sort_by_key(|(_, hits)| std::cmp::Reverse(*hits));
        let bytecode_matches = kind_ranked
            .iter()
            .filter_map(|(selector, _)| parse_selector_hex(selector))
            .filter(|selector| Self::bytecode_contains_selector(bytecode, *selector))
            .count();
        if bytecode_matches == 0 {
            return None;
        }
        let kind_name = match kind {
            RouterKind::V2Like => "v2",
            RouterKind::V3Like => "v3",
        };
        let top = kind_ranked
            .iter()
            .take(3)
            .map(|(selector, hits)| format!("{selector}:{hits}"))
            .collect::<Vec<_>>()
            .join(",");
        Some(RouterClassification {
            kind,
            note: format!(
                "{note_prefix}:kind={kind_name} known_hits={kind_hits} distinct={} share_bps={kind_share_bps} bytecode_matches={bytecode_matches} top={top}",
                kind_ranked.len()
            ),
        })
    }

    fn selectors_for_kind(kind: RouterKind) -> &'static [[u8; 4]] {
        match kind {
            RouterKind::V2Like => V2_ROUTER_SELECTORS,
            RouterKind::V3Like => V3_ROUTER_SELECTORS,
        }
    }

    fn count_matching_selectors(bytecode: &[u8], selectors: &[[u8; 4]]) -> usize {
        selectors
            .iter()
            .filter(|selector| Self::bytecode_contains_selector(bytecode, **selector))
            .count()
    }

    fn bytecode_contains_selector(bytecode: &[u8], selector: [u8; 4]) -> bool {
        if bytecode.len() < 5 {
            return false;
        }
        for idx in 0..=bytecode.len() - 5 {
            if bytecode[idx] == 0x63 && bytecode[idx + 1..idx + 5] == selector {
                return true;
            }
        }
        false
    }

    async fn collect_recent_selectors(
        &self,
        candidates: &HashSet<String>,
        lookback_blocks: u64,
    ) -> Result<HashMap<String, HashMap<String, u64>>, AppError> {
        if candidates.is_empty() {
            return Ok(HashMap::new());
        }
        let Some(_) = &self.http_provider else {
            return Ok(HashMap::new());
        };
        if let Some(until) = *self.cooldown_until.lock().await
            && Instant::now() < until
        {
            self.metrics.cooldown_skips.fetch_add(1, Ordering::Relaxed);
            return Ok(HashMap::new());
        }

        let cycle_started = Instant::now();
        let mut exhausted_budget = false;
        let mut failures = 0u64;
        let mut cooldown_reason = "ok";
        let mut cycle_rpc_calls = 0u64;

        let head_val = match self.rpc_request("eth_blockNumber", json!([])).await {
            Ok(v) => v,
            Err(e) => {
                self.metrics.cycle_failures.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        cycle_rpc_calls = cycle_rpc_calls.saturating_add(1);
        let Some(head_hex) = head_val.as_str() else {
            return Err(AppError::Initialization(
                "eth_blockNumber returned non-string".into(),
            ));
        };
        let head = u64::from_str_radix(head_hex.trim_start_matches("0x"), 16)
            .map_err(|e| AppError::Initialization(format!("Invalid block number hex: {e}")))?;
        let window = lookback_blocks.min(self.budget.max_blocks_per_cycle).max(1);
        if lookback_blocks > window {
            exhausted_budget = true;
            cooldown_reason = "max_blocks_per_cycle";
        }
        let start = head.saturating_sub(window.saturating_sub(1));

        let mut out: HashMap<String, HashMap<String, u64>> = HashMap::new();
        for block_number in start..=head {
            if cycle_started.elapsed() >= self.budget.cycle_timeout {
                exhausted_budget = true;
                cooldown_reason = "cycle_timeout";
                break;
            }
            if cycle_rpc_calls >= self.budget.max_rpc_calls_per_cycle {
                exhausted_budget = true;
                cooldown_reason = "max_rpc_calls_per_cycle";
                break;
            }
            let block_hex = format!("0x{block_number:x}");
            let block_val = match self
                .rpc_request("eth_getBlockByNumber", json!([block_hex, true]))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    cycle_rpc_calls = cycle_rpc_calls.saturating_add(1);
                    failures = failures.saturating_add(1);
                    self.metrics.cycle_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        target: "router_discovery",
                        error = %e,
                        block_number,
                        failures,
                        "Failed block selector collection request"
                    );
                    if failures >= self.budget.failure_budget {
                        exhausted_budget = true;
                        cooldown_reason = "failure_budget";
                        break;
                    }
                    continue;
                }
            };
            cycle_rpc_calls = cycle_rpc_calls.saturating_add(1);
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
        if exhausted_budget {
            self.metrics
                .budget_exhaustions
                .fetch_add(1, Ordering::Relaxed);
            let mut guard = self.cooldown_until.lock().await;
            *guard = Some(Instant::now() + self.budget.cooldown);
            tracing::warn!(
                target: "router_discovery",
                reason = cooldown_reason,
                cooldown_secs = self.budget.cooldown.as_secs(),
                "Router discovery budget exhausted; applying cooldown"
            );
        }
        Ok(out)
    }

    async fn rpc_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        self.metrics.rpc_calls.fetch_add(1, Ordering::Relaxed);
        let Some(http_provider) = &self.http_provider else {
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
            .post(http_provider)
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
        if V3_ROUTER_SELECTORS.contains(&parsed) {
            return Some(RouterKind::V3Like);
        }
        if V2_ROUTER_SELECTORS.contains(&parsed) {
            return Some(RouterKind::V2Like);
        }
        None
    }
}

const V3_ROUTER_SELECTORS: &[[u8; 4]] = &[
    UniversalRouter::executeCall::SELECTOR,
    UniversalRouterDeadline::executeCall::SELECTOR,
    UniV3Router::exactInputCall::SELECTOR,
    UniV3Router::exactInputSingleCall::SELECTOR,
    UniV3Router::exactOutputCall::SELECTOR,
    UniV3Router::exactOutputSingleCall::SELECTOR,
    UniV3Multicall::multicallCall::SELECTOR,
    UniV3MulticallDeadline::multicallCall::SELECTOR,
];

const V2_ROUTER_SELECTORS: &[[u8; 4]] = &[
    UniV2Router::swapExactETHForTokensCall::SELECTOR,
    UniV2Router::swapETHForExactTokensCall::SELECTOR,
    UniV2Router::swapExactTokensForETHCall::SELECTOR,
    UniV2Router::swapTokensForExactETHCall::SELECTOR,
    UniV2Router::swapExactTokensForTokensCall::SELECTOR,
    UniV2Router::swapTokensForExactTokensCall::SELECTOR,
    UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::SELECTOR,
    UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::SELECTOR,
    UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::SELECTOR,
    OneInchAggregationRouter::swapCall::SELECTOR,
    OneInchAggregationRouterV5::swapCall::SELECTOR,
    ParaSwapAugustusV6::swapExactAmountInCall::SELECTOR,
    ParaSwapAugustusV6::swapExactAmountOutCall::SELECTOR,
    KyberAggregationRouterV2::swapCall::SELECTOR,
    KyberAggregationRouterV2::swapGenericCall::SELECTOR,
    KyberAggregationRouterV2::swapSimpleModeCall::SELECTOR,
    ZeroXExchangeProxy::transformERC20Call::SELECTOR,
    DexRouter::dagSwapByOrderIdCall::SELECTOR,
    DexRouter::dagSwapToCall::SELECTOR,
    DexRouter::smartSwapByOrderIdCall::SELECTOR,
    DexRouter::smartSwapToCall::SELECTOR,
    DexRouter::smartSwapByInvestCall::SELECTOR,
    DexRouter::smartSwapByInvestWithRefundCall::SELECTOR,
    DexRouter::swapWrapToWithBaseRequestCall::SELECTOR,
    DexRouter::uniswapV3SwapToWithBaseRequestCall::SELECTOR,
    DexRouter::unxswapToWithBaseRequestCall::SELECTOR,
    TransitSwapRouterV5::exactInputV2SwapCall::SELECTOR,
    TransitSwapRouterV5::exactInputV2SwapAndGasUsedCall::SELECTOR,
    TransitSwapRouterV5::exactInputV3SwapCall::SELECTOR,
    TransitSwapRouterV5::exactInputV3SwapAndGasUsedCall::SELECTOR,
    RelayRouterV3::multicallCall::SELECTOR,
    RelayApprovalProxyV3::transferAndMulticallCall::SELECTOR,
    RelayApprovalProxyV3::permitTransferAndMulticallCall::SELECTOR,
    RelayApprovalProxyV3::permit3009TransferAndMulticallCall::SELECTOR,
    RelayApprovalProxyV3::permit2TransferAndMulticallCall::SELECTOR,
    BalancerVault::swapCall::SELECTOR,
    BalancerVault::batchSwapCall::SELECTOR,
];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_parser_handles_hex_prefix_and_rejects_invalid_lengths() {
        assert_eq!(
            parse_selector_hex("0x12345678"),
            Some([0x12, 0x34, 0x56, 0x78])
        );
        assert_eq!(
            parse_selector_hex("12345678"),
            Some([0x12, 0x34, 0x56, 0x78])
        );
        assert!(parse_selector_hex("0x1234").is_none());
        assert!(parse_selector_hex("0xzzzzzzzz").is_none());
    }

    #[test]
    fn selector_kind_classifies_protocol_specific_entrypoints() {
        let universal = format!("0x{}", hex::encode(UniversalRouter::executeCall::SELECTOR));
        let balancer_swap = format!("0x{}", hex::encode(BalancerVault::swapCall::SELECTOR));
        let v2_swap = format!(
            "0x{}",
            hex::encode(UniV2Router::swapExactTokensForTokensCall::SELECTOR)
        );
        assert_eq!(
            RouterDiscovery::selector_kind(&universal),
            Some(RouterKind::V3Like)
        );
        assert_eq!(
            RouterDiscovery::selector_kind(&balancer_swap),
            Some(RouterKind::V2Like)
        );
        assert_eq!(
            RouterDiscovery::selector_kind(&v2_swap),
            Some(RouterKind::V2Like)
        );
    }

    #[test]
    fn bytecode_selector_scan_detects_push4_dispatch_entries() {
        let known = UniV2Router::swapExactTokensForTokensCall::SELECTOR;
        let unknown = [0xde, 0xad, 0xbe, 0xef];
        let mut bytecode = vec![0x60, 0x00, 0x63];
        bytecode.extend_from_slice(&known);
        bytecode.extend_from_slice(&[0x14, 0x57, 0x5b, 0x00]);
        assert!(RouterDiscovery::bytecode_contains_selector(
            &bytecode, known
        ));
        assert!(!RouterDiscovery::bytecode_contains_selector(
            &bytecode, unknown
        ));
        assert_eq!(
            RouterDiscovery::count_matching_selectors(&bytecode, &[known]),
            1
        );
    }
}
