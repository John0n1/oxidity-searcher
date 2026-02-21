// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::data_path::{resolve_data_path, resolve_required_data_path};
use crate::domain::constants;
use crate::domain::error::AppError;
use alloy::primitives::Address;
use config::{Config, Environment, File};
use serde::{Deserialize, Deserializer};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct GlobalSettings {
    // General
    #[serde(default = "default_debug")]
    pub debug: bool,
    #[serde(default = "default_chain", deserialize_with = "deserialize_chain_list")]
    pub chains: Vec<u64>,
    pub database_url: Option<String>,

    // Identity
    pub wallet_key: String,
    pub wallet_address: Address,
    pub profit_receiver_address: Option<Address>,

    // Transaction
    #[serde(default = "default_max_gas")]
    pub max_gas_price_gwei: u64,
    #[serde(default = "default_sim_backend")]
    pub simulation_backend: String, // "revm", "anvil", etc.

    // MEV
    #[serde(default = "default_true")]
    pub flashloan_enabled: bool,
    /// Comma-separated list; supports "auto" prefix, "balancer", "aavev3"
    #[serde(default = "default_flashloan_provider")]
    pub flashloan_provider: String,
    pub executor_address: Option<Address>,
    #[serde(default = "default_true")]
    pub sandwich_attacks_enabled: bool,
    pub http_providers: Option<HashMap<String, String>>,
    pub websocket_providers: Option<HashMap<String, String>>,
    pub ipc_providers: Option<HashMap<String, String>>,
    pub chainlink_feeds: Option<HashMap<String, String>>, // Symbol -> aggregator address
    pub chainlink_feeds_path: Option<String>,
    pub pairs_path: Option<String>,
    pub aave_pools_by_chain: Option<HashMap<String, String>>,
    pub flashbots_relay_url: Option<String>,
    pub bundle_signer_key: Option<String>,
    #[serde(default = "default_bribe_bps")]
    pub executor_bribe_bps: u64,
    pub executor_bribe_recipient: Option<Address>,
    pub tokenlist_path: Option<String>,
    pub address_registry_path: Option<String>,
    pub data_dir: Option<String>,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    #[serde(default = "default_true")]
    pub strategy_enabled: bool,
    pub strategy_workers: Option<usize>,
    pub metrics_bind: Option<String>,
    pub metrics_token: Option<String>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u64,
    /// Multiplier applied to the base dynamic profit floor.
    #[serde(default = "default_profit_guard_base_floor_multiplier_bps")]
    pub profit_guard_base_floor_multiplier_bps: u64,
    /// Multiplier applied to direct execution costs (gas + bribe + premium).
    #[serde(default = "default_profit_guard_cost_multiplier_bps")]
    pub profit_guard_cost_multiplier_bps: u64,
    /// Minimum margin above gas cost required by risk/reward gate.
    #[serde(default = "default_profit_guard_min_margin_bps")]
    pub profit_guard_min_margin_bps: u64,
    /// Liquidity floor used by ratio-based build checks (parts-per-million).
    #[serde(default = "default_liquidity_ratio_floor_ppm")]
    pub liquidity_ratio_floor_ppm: u64,
    /// Minimum native output floor for sell-path checks.
    #[serde(default = "default_sell_min_native_out_wei")]
    pub sell_min_native_out_wei: u64,
    #[serde(default = "default_gas_cap_multiplier_bps")]
    pub gas_cap_multiplier_bps: u64,
    #[serde(default = "default_skip_log_every")]
    pub skip_log_every: u64,
    #[serde(default = "default_allow_non_wrapped_swaps")]
    pub allow_non_wrapped_swaps: bool,
    pub gas_caps_gwei: Option<HashMap<String, u64>>,
    #[serde(default = "default_mev_share_url")]
    pub mev_share_stream_url: String,
    pub mev_share_relay_url: Option<String>,
    #[serde(default = "default_mev_share_history_limit")]
    pub mev_share_history_limit: u32,
    #[serde(default = "default_true")]
    pub mev_share_enabled: bool,
    #[serde(default = "default_mevshare_builders")]
    pub mevshare_builders: Vec<String>,
    #[serde(default = "default_receipt_poll_ms")]
    pub receipt_poll_ms: u64,
    #[serde(default = "default_receipt_timeout_ms")]
    pub receipt_timeout_ms: u64,
    #[serde(default = "default_receipt_confirm_blocks")]
    pub receipt_confirm_blocks: u64,
    #[serde(default = "default_false")]
    pub emergency_exit_on_unknown_receipt: bool,
    #[serde(default = "default_rpc_capability_strict")]
    pub rpc_capability_strict: bool,
    #[serde(default = "default_chainlink_feed_conflict_strict")]
    pub chainlink_feed_conflict_strict: bool,
    #[serde(default = "default_chainlink_feed_audit_strict")]
    pub chainlink_feed_audit_strict: bool,
    #[serde(default = "default_bundle_use_replacement_uuid")]
    pub bundle_use_replacement_uuid: bool,
    #[serde(default = "default_bundle_cancel_previous")]
    pub bundle_cancel_previous: bool,

    // Router discovery
    #[serde(default = "default_router_discovery_enabled")]
    pub router_discovery_enabled: bool,
    #[serde(default = "default_router_discovery_min_hits")]
    pub router_discovery_min_hits: u64,
    #[serde(default = "default_router_discovery_flush_every")]
    pub router_discovery_flush_every: u64,
    #[serde(default = "default_router_discovery_check_interval_secs")]
    pub router_discovery_check_interval_secs: u64,
    #[serde(default = "default_router_discovery_auto_allow")]
    pub router_discovery_auto_allow: bool,
    #[serde(default = "default_router_discovery_max_entries")]
    pub router_discovery_max_entries: usize,

    // Per-chain maps
    pub router_allowlist_by_chain: Option<HashMap<String, HashMap<String, String>>>,
    pub chainlink_feeds_by_chain: Option<HashMap<String, HashMap<String, String>>>,
    pub chainlink_feeds_by_chain_eth: Option<HashMap<String, HashMap<String, String>>>,
    pub binance_api_key: Option<String>,
    pub coinmarketcap_api_key: Option<String>,
    pub coingecko_api_key: Option<String>,
    pub cryptocompare_api_key: Option<String>,
    pub coindesk_api_key: Option<String>,
    pub etherscan_api_key: Option<String>,
}

// Defaults
fn default_debug() -> bool {
    false
}
fn default_chain() -> Vec<u64> {
    Vec::new()
}
fn default_max_gas() -> u64 {
    500
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_metrics_port() -> u16 {
    9000
}
fn default_slippage_bps() -> u64 {
    0
}
fn default_profit_guard_base_floor_multiplier_bps() -> u64 {
    7_000
}
fn default_profit_guard_cost_multiplier_bps() -> u64 {
    10_000
}
fn default_profit_guard_min_margin_bps() -> u64 {
    700
}
fn default_liquidity_ratio_floor_ppm() -> u64 {
    700
}
fn default_sell_min_native_out_wei() -> u64 {
    3_000_000_000_000
}
fn default_gas_cap_multiplier_bps() -> u64 {
    12_000
}
fn default_skip_log_every() -> u64 {
    500
}
fn default_allow_non_wrapped_swaps() -> bool {
    true
}
fn default_sim_backend() -> String {
    "revm".to_string()
}
fn default_flashloan_provider() -> String {
    "auto,aavev3,balancer".to_string()
}
fn default_mev_share_url() -> String {
    "https://mev-share.flashbots.net".to_string()
}
fn default_mev_share_history_limit() -> u32 {
    200
}
fn default_mevshare_builders() -> Vec<String> {
    vec![
        "flashbots".to_string(),
        "beaverbuild.org".to_string(),
        "rsync".to_string(),
        "Titan".to_string(),
    ]
}
fn default_receipt_poll_ms() -> u64 {
    500
}
fn default_receipt_timeout_ms() -> u64 {
    12_000
}
fn default_receipt_confirm_blocks() -> u64 {
    4
}
fn default_rpc_capability_strict() -> bool {
    true
}
fn default_chainlink_feed_conflict_strict() -> bool {
    true
}
fn default_chainlink_feed_audit_strict() -> bool {
    false
}
fn default_bundle_use_replacement_uuid() -> bool {
    true
}
fn default_bundle_cancel_previous() -> bool {
    false
}
fn default_bribe_bps() -> u64 {
    0
}
fn default_router_discovery_enabled() -> bool {
    true
}
fn default_router_discovery_min_hits() -> u64 {
    25
}
fn default_router_discovery_flush_every() -> u64 {
    50
}
fn default_router_discovery_check_interval_secs() -> u64 {
    300
}
fn default_router_discovery_auto_allow() -> bool {
    true
}
fn default_router_discovery_max_entries() -> usize {
    10_000
}

fn deserialize_chain_list<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error, SeqAccess, Visitor};
    use std::fmt;

    struct ChainVisitor;

    impl<'de> Visitor<'de> for ChainVisitor {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of chain ids or a string with comma-separated ids")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            parse_chain_list(v).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(elem) = seq.next_element::<u64>()? {
                out.push(elem);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(ChainVisitor)
}

impl GlobalSettings {
    pub fn load_with_path(path: Option<&str>) -> Result<Self, AppError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let selected_config = resolve_config_path(path);
        let mut builder = Config::builder();

        if let Some(ref selected_path) = selected_config {
            builder = builder.add_source(File::from(Path::new(selected_path)).required(true));
        } else {
            builder = builder.add_source(File::with_name("config").required(false));
        }
        // Deterministic precedence: CLI (in main) > env/.env > selected profile file.
        builder = builder.add_source(Environment::default());

        let mut settings: GlobalSettings = builder.build()?.try_deserialize()?;

        // Allow CHAINS env to be comma/space separated string (e.g. "1,137")
        if let Ok(chains_str) = std::env::var("CHAINS") {
            settings.chains = parse_chain_list(&chains_str)?;
        }

        // Basic Validation
        if settings.wallet_key.is_empty() {
            return Err(AppError::Config("WALLET_KEY is missing".to_string()));
        }

        Ok(settings)
    }

    fn data_dir_value(&self) -> Option<String> {
        std::env::var("DATA_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.data_dir
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
    }

    pub fn data_dir(&self) -> Option<String> {
        self.data_dir_value()
    }

    fn resolve_path_setting(
        &self,
        env_key: &str,
        configured: Option<&str>,
        default_path: &str,
        required: bool,
    ) -> Result<String, AppError> {
        let raw = std::env::var(env_key)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                configured
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| default_path.to_string());
        let data_dir = self.data_dir_value();
        let resolved = if required {
            resolve_required_data_path(&raw, data_dir.as_deref())?
        } else {
            resolve_data_path(&raw, data_dir.as_deref())
        };
        Ok(resolved.to_string_lossy().to_string())
    }

    pub fn load() -> Result<Self, AppError> {
        Self::load_with_path(None)
    }

    /// Best-effort primary HTTP RPC URL for chain auto-detection.
    pub fn primary_http_provider(&self) -> Option<String> {
        // Prefer explicit map entry with smallest key
        if let Some(map) = &self.http_providers {
            if let Some((_, v)) = map.iter().min_by_key(|(k, _)| k.parse::<u64>().ok()) {
                return Some(v.clone());
            }
            if let Some((_, v)) = map.iter().next() {
                return Some(v.clone());
            }
        }
        // Environment fallbacks
        std::env::var("http_provider")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::env::var("http_provider_1")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
    }

    /// Helper to get RPC URL for a specific chain
    pub fn get_http_provider(&self, chain_id: u64) -> Result<String, AppError> {
        // Try looking for explicit map
        if let Some(urls) = &self.http_providers
            && let Some(url) = urls.get(&chain_id.to_string())
        {
            return Ok(url.clone());
        }

        // Fallback to env var convention: http_provider_1, http_provider_137, then generic http_provider
        let candidates = [
            format!("http_provider_{}", chain_id),
            "http_provider".to_string(),
        ];
        for key in candidates {
            if let Ok(v) = std::env::var(&key) {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
            }
        }

        Err(AppError::Config(format!(
            "No RPC URL found for chain {}",
            chain_id
        )))
    }

    /// Helper to get WS URL for a specific chain
    pub fn get_websocket_provider(&self, chain_id: u64) -> Result<String, AppError> {
        if let Some(urls) = &self.websocket_providers
            && let Some(url) = urls.get(&chain_id.to_string())
        {
            return Ok(url.clone());
        }

        let candidates = [
            format!("WEBSOCKET_PROVIDER_{}", chain_id),
            format!("WEBSOCKET_URL_{}", chain_id),
            "WEBSOCKET_PROVIDER".to_string(),
            "WEBSOCKET_URL".to_string(),
        ];

        for key in candidates {
            if let Ok(v) = std::env::var(&key) {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
            }
        }

        Err(AppError::Config(format!(
            "No WS URL found for chain {}",
            chain_id
        )))
    }

    /// Optional IPC URL for a specific chain, preferring explicit config and then env.
    pub fn get_ipc_provider(&self, chain_id: u64) -> Option<String> {
        if let Some(urls) = &self.ipc_providers
            && let Some(url) = urls.get(&chain_id.to_string())
        {
            return Some(url.clone());
        }

        let candidates = [
            format!("IPC_PROVIDER_{}", chain_id),
            format!("IPC_PATH_{}", chain_id),
            "IPC_PROVIDER".to_string(),
            "IPC_PATH".to_string(),
        ];

        for key in candidates {
            if let Ok(v) = std::env::var(&key)
                && !v.trim().is_empty()
            {
                return Some(v);
            }
        }

        None
    }

    pub fn get_chainlink_feed(&self, symbol: &str) -> Option<String> {
        self.chainlink_feeds
            .as_ref()
            .and_then(|m| m.get(&symbol.to_uppercase()).cloned())
    }

    pub fn profit_receiver_or_wallet(&self) -> Address {
        self.profit_receiver_address.unwrap_or(self.wallet_address)
    }

    pub fn tokenlist_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "TOKENLIST_PATH",
            self.tokenlist_path.as_deref(),
            "data/tokenlist.json",
            true,
        )
    }

    pub fn address_registry_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "ADDRESS_REGISTRY_PATH",
            self.address_registry_path.as_deref(),
            "data/address_registry.json",
            true,
        )
    }

    pub fn pairs_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "PAIRS_PATH",
            self.pairs_path.as_deref(),
            "data/pairs.json",
            false,
        )
    }

    pub fn database_url(&self) -> String {
        std::env::var("DATABASE_URL")
            .ok()
            .or_else(|| self.database_url.clone())
            .unwrap_or_else(|| "sqlite://oxidity_searcher.db".to_string())
    }

    pub fn flashbots_relay_url(&self) -> String {
        self.flashbots_relay_url
            .clone()
            .or_else(|| std::env::var("FLASHBOTS_RELAY_URL").ok())
            .unwrap_or_else(|| "https://relay.flashbots.net".to_string())
    }

    pub fn router_discovery_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.router_discovery_check_interval_secs.max(30))
    }

    pub fn bundle_signer_key(&self) -> String {
        self.bundle_signer_key
            .clone()
            .or_else(|| std::env::var("BUNDLE_SIGNER_KEY").ok())
            .unwrap_or_else(|| self.wallet_key.clone())
    }

    pub fn strategy_worker_limit(&self) -> usize {
        if let Ok(v) = std::env::var("STRATEGY_WORKERS")
            && let Ok(parsed) = v.parse::<usize>()
        {
            return parsed.max(1);
        }
        self.strategy_workers.unwrap_or(32).max(1)
    }

    pub fn metrics_bind_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("METRICS_BIND")
            && !v.trim().is_empty()
        {
            return Some(v);
        }
        self.metrics_bind.clone()
    }

    pub fn metrics_token_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("METRICS_TOKEN")
            && !v.trim().is_empty()
        {
            return Some(v);
        }
        self.metrics_token.clone()
    }

    pub fn etherscan_api_key_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("ETHERSCAN_API_KEY")
            && !v.trim().is_empty()
        {
            return Some(v);
        }
        self.etherscan_api_key.clone()
    }

    pub fn gas_cap_for_chain(&self, chain_id: u64) -> Option<u64> {
        self.gas_caps_gwei
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()).cloned())
    }

    pub fn flashloan_providers(
        &self,
    ) -> Vec<crate::services::strategy::strategy::FlashloanProvider> {
        use crate::services::strategy::strategy::FlashloanProvider::*;
        let raw = self.flashloan_provider.to_lowercase();
        let mut parts: Vec<&str> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let mut auto = false;
        if let Some(pos) = parts.iter().position(|p| *p == "auto") {
            auto = true;
            parts.remove(pos);
        }
        let mut out = Vec::new();
        for p in parts {
            match p {
                "aave" | "aavev3" | "aave_v3" => out.push(AaveV3),
                "balancer" => out.push(Balancer),
                _ => {}
            }
        }
        if out.is_empty() && auto {
            out = vec![AaveV3, Balancer];
        }
        if out.is_empty() {
            out = vec![Balancer];
        }
        out
    }

    pub fn routers_for_chain(&self, chain_id: u64) -> Result<HashMap<String, Address>, AppError> {
        let mut out = constants::default_routers_for_chain(chain_id);

        if let Some(map) = self
            .router_allowlist_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            let parsed = parse_address_map(map, "router_allowlist_by_chain")?;
            out.extend(parsed);
        }

        Ok(out)
    }

    pub fn gas_cap_multiplier_bps_value(&self) -> u64 {
        self.gas_cap_multiplier_bps.max(10_000)
    }

    pub fn profit_guard_base_floor_multiplier_bps_value(&self) -> u64 {
        self.profit_guard_base_floor_multiplier_bps
            .clamp(75, 20_000)
    }

    pub fn profit_guard_cost_multiplier_bps_value(&self) -> u64 {
        self.profit_guard_cost_multiplier_bps.clamp(1_000, 20_000)
    }

    pub fn profit_guard_min_margin_bps_value(&self) -> u64 {
        self.profit_guard_min_margin_bps.clamp(35, 5_000)
    }

    pub fn liquidity_ratio_floor_ppm_value(&self) -> u64 {
        self.liquidity_ratio_floor_ppm.clamp(35, 10_000)
    }

    pub fn sell_min_native_out_wei_value(&self) -> u64 {
        self.sell_min_native_out_wei.max(500_000_000_000)
    }

    pub fn skip_log_every_value(&self) -> u64 {
        self.skip_log_every.max(1)
    }

    pub fn aave_pool_for_chain(&self, chain_id: u64) -> Option<Address> {
        if let Some(map) = self
            .aave_pools_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
            && let Ok(addr) = Address::from_str(map)
        {
            return Some(addr);
        }
        constants::default_aave_pool(chain_id)
    }

    pub fn chainlink_feeds_for_chain(
        &self,
        chain_id: u64,
    ) -> Result<HashMap<String, Address>, AppError> {
        let mut out: HashMap<String, Address> = HashMap::new();

        if let Some(map) = self
            .chainlink_feeds_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            out.extend(parse_address_map(map, "chainlink_feeds_by_chain")?);
        }

        if let Some(map) = self
            .chainlink_feeds_by_chain_eth
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            let parsed = parse_address_map(map, "chainlink_feeds_by_chain_eth")?;
            for (k, v) in parsed {
                out.insert(format!("{}_ETH", k), v);
            }
        }

        if out.is_empty()
            && let Some(map) = &self.chainlink_feeds
        {
            out.extend(parse_address_map(map, "chainlink_feeds")?);
        }

        if out.is_empty()
            && let Some(map) = load_chainlink_feeds_from_file(
                &self.chainlink_feeds_path()?,
                chain_id,
                self.chainlink_feed_conflict_strict_for_chain(chain_id),
            )?
        {
            out.extend(map);
        }

        if out.is_empty() {
            out = constants::default_chainlink_feeds(chain_id);
        }

        Ok(out)
    }

    pub fn chainlink_feeds_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "CHAINLINK_FEEDS_PATH",
            self.chainlink_feeds_path.as_deref(),
            "data/chainlink_feeds.json",
            false,
        )
    }

    pub fn mev_share_relay_url(&self) -> String {
        if let Ok(v) = std::env::var("MEV_SHARE_RELAY_URL")
            && !v.trim().is_empty()
        {
            return v;
        }
        if let Some(v) = &self.mev_share_relay_url
            && !v.trim().is_empty()
        {
            return v.clone();
        }
        if let Ok(mut parsed) = Url::parse(&self.mev_share_stream_url) {
            parsed.set_path("");
            parsed.set_query(None);
            parsed.set_fragment(None);
            return parsed.to_string().trim_end_matches('/').to_string();
        }
        self.mev_share_stream_url.clone()
    }

    pub fn mevshare_builders_value(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .mevshare_builders
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if out.is_empty() {
            out = default_mevshare_builders();
        }
        out
    }

    pub fn receipt_poll_ms_value(&self) -> u64 {
        self.receipt_poll_ms.max(100)
    }

    pub fn receipt_timeout_ms_value(&self) -> u64 {
        self.receipt_timeout_ms.max(self.receipt_poll_ms_value())
    }

    pub fn receipt_confirm_blocks_value(&self) -> u64 {
        self.receipt_confirm_blocks.max(1)
    }

    pub fn rpc_capability_strict_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.rpc_capability_strict
        } else {
            false
        }
    }

    pub fn chainlink_feed_conflict_strict_for_chain(&self, _chain_id: u64) -> bool {
        env_bool("CHAINLINK_FEED_CONFLICT_STRICT").unwrap_or(self.chainlink_feed_conflict_strict)
    }

    pub fn chainlink_feed_audit_strict_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.chainlink_feed_audit_strict
        } else {
            false
        }
    }

    pub fn bundle_use_replacement_uuid_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.bundle_use_replacement_uuid
        } else {
            false
        }
    }

    pub fn bundle_cancel_previous_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.bundle_cancel_previous
        } else {
            false
        }
    }

    pub fn price_api_keys(&self) -> crate::network::price_feed::PriceApiKeys {
        use std::env::var;
        crate::network::price_feed::PriceApiKeys {
            binance: var("BINANCE_API_KEY")
                .ok()
                .or_else(|| self.binance_api_key.clone()),
            coinmarketcap: var("COINMARKETCAP_API_KEY")
                .ok()
                .or_else(|| self.coinmarketcap_api_key.clone()),
            coingecko: var("COINGECKO_API_KEY")
                .ok()
                .or_else(|| self.coingecko_api_key.clone()),
            cryptocompare: var("CRYPTOCOMPARE_API_KEY")
                .ok()
                .or_else(|| self.cryptocompare_api_key.clone()),
            coindesk: var("COINDESK_API_KEY")
                .ok()
                .or_else(|| self.coindesk_api_key.clone()),
        }
    }
}

fn env_bool(key: &str) -> Option<bool> {
    let value = std::env::var(key).ok()?;
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn resolve_config_path(path: Option<&str>) -> Option<String> {
    if let Some(path) = path {
        return Some(path.to_string());
    }
    detect_active_config_file()
}

fn detect_active_config_file() -> Option<String> {
    // Check common config.*.toml files first
    let priority_files = [
        "config.prod.toml",
        "config.dev.toml",
        "config.testnet.toml",
        "config.example.toml",
        "config.toml",
    ];

    for file in priority_files.iter() {
        if let Some(true) = config_has_active_flag(file) {
            return Some((*file).to_string());
        }
    }

    // Fallback: scan current dir for config.*.toml with THIS_ACTIVE = true
    if let Ok(entries) = fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("config.")
                && name.ends_with(".toml")
                && let Some(true) = config_has_active_flag(name)
            {
                return Some(name.to_string());
            }
        }
    }

    None
}

fn config_has_active_flag(path: &str) -> Option<bool> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }

    Config::builder()
        .add_source(File::from(p))
        .build()
        .ok()?
        .get_bool("THIS_ACTIVE")
        .ok()
}

fn parse_chain_list(raw: &str) -> Result<Vec<u64>, AppError> {
    let cleaned = raw.trim_matches(|c| c == '`' || c == '"' || c == '\'');
    let mut out = Vec::new();
    for part in cleaned.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let id: u64 = p
            .parse()
            .map_err(|_| AppError::Config(format!("Invalid chain id '{}'", p)))?;
        out.push(id);
    }
    if out.is_empty() {
        return Err(AppError::Config("CHAINS env is empty".into()));
    }
    Ok(out)
}

fn parse_address_map(
    raw: &HashMap<String, String>,
    field: &str,
) -> Result<HashMap<String, Address>, AppError> {
    raw.iter()
        .map(|(k, v)| {
            Address::from_str(v)
                .map(|addr| (k.to_uppercase(), addr))
                .map_err(|_| AppError::InvalidAddress(format!("{field}:{k} -> {v}")))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainlinkFeedEntry {
    base: String,
    quote: String,
    chain_id: u64,
    address: String,
}

fn alias_base_symbol(base: &str) -> String {
    match base.to_uppercase().as_str() {
        "WETH" => "ETH".to_string(),
        "WBTC" => "BTC".to_string(),
        other => other.to_string(),
    }
}

fn quote_priority(quote: &str) -> usize {
    match quote {
        "USD" => 0,
        "USDT" | "USDC" => 1,
        "ETH" => 2,
        _ => 3,
    }
}

#[derive(Clone, Debug)]
struct NormalizedChainlinkFeedEntry {
    base: String,
    quote: String,
    address: Address,
    index: usize,
}

fn normalize_chainlink_feed_entries(
    entries: Vec<ChainlinkFeedEntry>,
    chain_id: u64,
) -> Result<(Vec<NormalizedChainlinkFeedEntry>, usize), AppError> {
    let mut dedupe = HashSet::new();
    let mut normalized = Vec::new();
    let mut deduped_count = 0usize;

    for (index, entry) in entries.into_iter().enumerate() {
        if entry.chain_id != chain_id {
            continue;
        }
        let base = alias_base_symbol(&entry.base);
        let quote = entry.quote.to_uppercase();
        let address = Address::from_str(&entry.address).map_err(|_| {
            AppError::InvalidAddress(format!("chainlink_feeds:{base} -> {}", entry.address))
        })?;
        let dedupe_key = format!("{base}|{quote}|{:#x}", address);
        if !dedupe.insert(dedupe_key) {
            deduped_count = deduped_count.saturating_add(1);
            continue;
        }
        normalized.push(NormalizedChainlinkFeedEntry {
            base,
            quote,
            address,
            index,
        });
    }

    Ok((normalized, deduped_count))
}

fn load_chainlink_feeds_from_file(
    path: &str,
    chain_id: u64,
    strict_conflicts: bool,
) -> Result<Option<HashMap<String, Address>>, AppError> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(file_path)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json read failed: {}", e)))?;
    let entries: Vec<ChainlinkFeedEntry> = serde_json::from_str(&raw)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json parse failed: {}", e)))?;
    let (normalized_entries, deduped_count) = normalize_chainlink_feed_entries(entries, chain_id)?;

    let canonical = constants::default_chainlink_feeds(chain_id);
    let mut selected: HashMap<String, (String, Address, usize, usize)> = HashMap::new();
    let mut by_base_quote: HashMap<(String, String), Vec<Address>> = HashMap::new();
    let seen_any = !normalized_entries.is_empty() || deduped_count > 0;
    for entry in normalized_entries {
        let base = entry.base;
        let quote = entry.quote;
        let addr = entry.address;
        let index = entry.index;
        by_base_quote
            .entry((base.clone(), quote.clone()))
            .or_default()
            .push(addr);

        let new_score = quote_priority(&quote);
        let canonical_key = format!("{}_{}", base, quote);
        let canonical_rank = match canonical.get(&canonical_key) {
            Some(expected) if *expected == addr => 0usize,
            _ => 1usize,
        };
        let replace = match selected.get(&base) {
            None => true,
            Some((existing_quote, existing_addr, existing_canonical_rank, existing_index)) => {
                let existing_score = quote_priority(existing_quote);
                if new_score != existing_score {
                    new_score < existing_score
                } else if canonical_rank != *existing_canonical_rank {
                    canonical_rank < *existing_canonical_rank
                } else if addr != *existing_addr {
                    addr.to_string().to_lowercase() < existing_addr.to_string().to_lowercase()
                } else {
                    index < *existing_index
                }
            }
        };

        if replace {
            selected.insert(base, (quote, addr, canonical_rank, index));
        }
    }
    if deduped_count > 0 {
        tracing::debug!(
            target: "config",
            chain_id,
            deduped = deduped_count,
            "Chainlink feed normalization removed duplicate entries"
        );
    }

    let mut resolved_conflicts: Vec<String> = Vec::new();
    let mut unresolved_conflicts: Vec<String> = Vec::new();
    for ((base, quote), addrs) in by_base_quote {
        let mut uniq: Vec<Address> = Vec::new();
        for addr in addrs {
            if !uniq.contains(&addr) {
                uniq.push(addr);
            }
        }
        if uniq.len() > 1 {
            uniq.sort();
            let list = uniq
                .iter()
                .map(|a| format!("{:#x}", a))
                .collect::<Vec<_>>()
                .join(",");
            let key = format!("{}_{}", base, quote);
            let canonical_addr = canonical.get(&key).copied();
            let selected_for_quote =
                selected
                    .get(&base)
                    .and_then(|(selected_quote, selected_addr, _, _)| {
                        if selected_quote == &quote {
                            Some(*selected_addr)
                        } else {
                            None
                        }
                    });
            let selected_str = selected_for_quote
                .map(|a| format!("{:#x}", a))
                .unwrap_or_else(|| "<not-selected>".to_string());
            let canonical_str = canonical_addr
                .map(|a| format!("{:#x}", a))
                .unwrap_or_else(|| "<none>".to_string());

            let canonical_resolves = canonical_addr
                .map(|addr| uniq.contains(&addr))
                .unwrap_or(false);
            let record = format!(
                "{base}/{quote} -> [{list}] selected={selected_str} canonical={canonical_str}"
            );
            if canonical_resolves {
                resolved_conflicts.push(record);
            } else {
                unresolved_conflicts.push(record);
            }
        }
    }
    if !resolved_conflicts.is_empty() {
        for conflict in resolved_conflicts.iter().take(12) {
            tracing::debug!(
                target: "config",
                chain_id,
                strict = strict_conflicts,
                conflict = %conflict,
                "Chainlink feed conflict resolved via canonical tie-break"
            );
        }
    }
    if !unresolved_conflicts.is_empty() {
        for conflict in unresolved_conflicts.iter().take(12) {
            tracing::warn!(
                target: "config",
                chain_id,
                strict = strict_conflicts,
                conflict = %conflict,
                "Chainlink feed conflict unresolved"
            );
        }
        if strict_conflicts {
            return Err(AppError::Config(format!(
                "chainlink_feeds contains unresolved conflicting duplicate base/quote feeds on chain {} ({} unresolved, {} resolved); strict mode rejects ambiguous feed sets",
                chain_id,
                unresolved_conflicts.len(),
                resolved_conflicts.len()
            )));
        }
    }

    if selected.is_empty() {
        if seen_any {
            tracing::warn!(
                target: "config",
                chain_id,
                "No usable Chainlink feed entries selected from chainlink_feeds file"
            );
        }
        return Ok(None);
    }

    let out = selected
        .into_iter()
        .map(|(base, (_, addr, _, _))| (base, addr))
        .collect();

    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn env_lock_guard() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn base_settings() -> GlobalSettings {
        GlobalSettings {
            debug: default_debug(),
            chains: Vec::new(),
            database_url: None,
            wallet_key: "0x0".to_string(),
            wallet_address: Address::ZERO,
            profit_receiver_address: None,
            max_gas_price_gwei: default_max_gas(),
            simulation_backend: default_sim_backend(),
            flashloan_enabled: default_true(),
            flashloan_provider: default_flashloan_provider(),
            executor_address: None,
            sandwich_attacks_enabled: default_true(),
            http_providers: None,
            websocket_providers: None,
            ipc_providers: None,
            chainlink_feeds: None,
            chainlink_feeds_path: None,
            pairs_path: None,
            flashbots_relay_url: None,
            bundle_signer_key: None,
            executor_bribe_bps: default_bribe_bps(),
            executor_bribe_recipient: None,
            tokenlist_path: None,
            address_registry_path: None,
            data_dir: None,
            metrics_port: default_metrics_port(),
            strategy_enabled: default_true(),
            strategy_workers: None,
            metrics_bind: None,
            metrics_token: None,
            slippage_bps: default_slippage_bps(),
            profit_guard_base_floor_multiplier_bps: default_profit_guard_base_floor_multiplier_bps(
            ),
            profit_guard_cost_multiplier_bps: default_profit_guard_cost_multiplier_bps(),
            profit_guard_min_margin_bps: default_profit_guard_min_margin_bps(),
            liquidity_ratio_floor_ppm: default_liquidity_ratio_floor_ppm(),
            sell_min_native_out_wei: default_sell_min_native_out_wei(),
            gas_cap_multiplier_bps: default_gas_cap_multiplier_bps(),
            skip_log_every: default_skip_log_every(),
            allow_non_wrapped_swaps: default_allow_non_wrapped_swaps(),
            gas_caps_gwei: None,
            mev_share_stream_url: default_mev_share_url(),
            mev_share_relay_url: None,
            mev_share_history_limit: default_mev_share_history_limit(),
            mev_share_enabled: default_true(),
            mevshare_builders: default_mevshare_builders(),
            receipt_poll_ms: default_receipt_poll_ms(),
            receipt_timeout_ms: default_receipt_timeout_ms(),
            receipt_confirm_blocks: default_receipt_confirm_blocks(),
            emergency_exit_on_unknown_receipt: default_false(),
            rpc_capability_strict: default_rpc_capability_strict(),
            chainlink_feed_conflict_strict: default_chainlink_feed_conflict_strict(),
            chainlink_feed_audit_strict: default_chainlink_feed_audit_strict(),
            bundle_use_replacement_uuid: default_bundle_use_replacement_uuid(),
            bundle_cancel_previous: default_bundle_cancel_previous(),
            router_discovery_enabled: default_router_discovery_enabled(),
            router_discovery_min_hits: default_router_discovery_min_hits(),
            router_discovery_flush_every: default_router_discovery_flush_every(),
            router_discovery_check_interval_secs: default_router_discovery_check_interval_secs(),
            router_discovery_auto_allow: default_router_discovery_auto_allow(),
            router_discovery_max_entries: default_router_discovery_max_entries(),
            router_allowlist_by_chain: None,
            chainlink_feeds_by_chain: None,
            chainlink_feeds_by_chain_eth: None,
            aave_pools_by_chain: None,
            binance_api_key: None,
            coinmarketcap_api_key: None,
            coingecko_api_key: None,
            cryptocompare_api_key: None,
            coindesk_api_key: None,
            etherscan_api_key: None,
        }
    }

    #[test]
    fn ipc_provider_prefers_configured_map() {
        let mut settings = base_settings();
        settings.ipc_providers = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/test.ipc".to_string(),
        )]));
        assert_eq!(
            settings.get_ipc_provider(1).as_deref(),
            Some("/tmp/test.ipc")
        );
    }

    #[test]
    fn ws_lookup_does_not_use_ipc_entries() {
        let _env_lock = env_lock_guard();
        let old_ws_1 = std::env::var("WEBSOCKET_PROVIDER_1").ok();
        let old_ws = std::env::var("WEBSOCKET_PROVIDER").ok();
        let old_websocket_1 = std::env::var("WEBSOCKET_URL_1").ok();
        let old_websocket = std::env::var("WEBSOCKET_URL").ok();
        unsafe {
            std::env::remove_var("WEBSOCKET_PROVIDER_1");
            std::env::remove_var("WEBSOCKET_PROVIDER");
            std::env::remove_var("WEBSOCKET_URL_1");
            std::env::remove_var("WEBSOCKET_URL");
        }

        let mut settings = base_settings();
        settings.ipc_providers = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/socket.ipc".to_string(),
        )]));
        settings.websocket_providers = None;

        let err = settings.get_websocket_provider(1).unwrap_err();
        match err {
            AppError::Config(msg) => assert!(msg.contains("No WS URL")),
            other => panic!("Unexpected error variant: {other:?}"),
        }

        if let Some(v) = old_ws_1 {
            unsafe { std::env::set_var("WEBSOCKET_PROVIDER_1", v) };
        }
        if let Some(v) = old_ws {
            unsafe { std::env::set_var("WEBSOCKET_PROVIDER", v) };
        }
        if let Some(v) = old_websocket_1 {
            unsafe { std::env::set_var("WEBSOCKET_URL_1", v) };
        }
        if let Some(v) = old_websocket {
            unsafe { std::env::set_var("WEBSOCKET_URL", v) };
        }
    }

    #[test]
    fn mev_share_relay_url_prefers_config_value() {
        let _env_lock = env_lock_guard();
        unsafe { std::env::remove_var("MEV_SHARE_RELAY_URL") };
        let mut settings = base_settings();
        settings.mev_share_relay_url = Some("https://relay.example".to_string());
        assert_eq!(
            settings.mev_share_relay_url(),
            "https://relay.example".to_string()
        );
    }

    #[test]
    fn flashloan_providers_ignore_removed_aave_v2_aliases() {
        use crate::services::strategy::strategy::FlashloanProvider::Balancer;

        let mut settings = base_settings();
        settings.flashloan_provider = "aavev2,aave_v2".to_string();
        assert_eq!(settings.flashloan_providers(), vec![Balancer]);
    }

    #[test]
    fn flashloan_providers_auto_uses_supported_provider_set_only() {
        use crate::services::strategy::strategy::FlashloanProvider::{AaveV3, Balancer};

        let mut settings = base_settings();
        settings.flashloan_provider = "auto,aavev2".to_string();
        assert_eq!(settings.flashloan_providers(), vec![AaveV3, Balancer]);
    }

    #[test]
    fn ipc_provider_requires_explicit_config_or_env() {
        let _env_lock = env_lock_guard();
        unsafe {
            std::env::remove_var("IPC_PROVIDER_1");
            std::env::remove_var("IPC_PATH_1");
            std::env::remove_var("IPC_PROVIDER");
            std::env::remove_var("IPC_PATH");
        }
        let settings = base_settings();
        assert!(settings.get_ipc_provider(1).is_none());
    }

    #[test]
    fn mevshare_builders_defaults_when_empty() {
        let mut settings = base_settings();
        settings.mevshare_builders.clear();
        assert_eq!(
            settings.mevshare_builders_value(),
            default_mevshare_builders()
        );
    }

    #[test]
    fn receipt_tuning_values_have_safe_floor() {
        let mut settings = base_settings();
        settings.receipt_poll_ms = 0;
        settings.receipt_timeout_ms = 1;
        settings.receipt_confirm_blocks = 0;
        assert_eq!(settings.receipt_poll_ms_value(), 100);
        assert_eq!(settings.receipt_timeout_ms_value(), 100);
        assert_eq!(settings.receipt_confirm_blocks_value(), 1);
    }

    #[test]
    fn rpc_capability_strict_defaults_to_mainnet_only() {
        let settings = base_settings();
        assert!(settings.rpc_capability_strict_for_chain(1));
        assert!(!settings.rpc_capability_strict_for_chain(137));
    }

    #[test]
    fn chainlink_feed_conflict_strict_applies_globally() {
        let settings = base_settings();
        assert!(settings.chainlink_feed_conflict_strict_for_chain(1));
        assert!(settings.chainlink_feed_conflict_strict_for_chain(137));
    }

    #[test]
    fn chainlink_feed_conflict_strict_respects_env_override() {
        let _env_lock = env_lock_guard();
        let old = std::env::var("CHAINLINK_FEED_CONFLICT_STRICT").ok();
        unsafe {
            std::env::set_var("CHAINLINK_FEED_CONFLICT_STRICT", "false");
        }
        let settings = base_settings();
        assert!(!settings.chainlink_feed_conflict_strict_for_chain(1));
        assert!(!settings.chainlink_feed_conflict_strict_for_chain(137));
        if let Some(v) = old {
            unsafe { std::env::set_var("CHAINLINK_FEED_CONFLICT_STRICT", v) };
        } else {
            unsafe { std::env::remove_var("CHAINLINK_FEED_CONFLICT_STRICT") };
        }
    }

    #[test]
    fn chainlink_feed_audit_strict_defaults_disabled() {
        let settings = base_settings();
        assert!(!settings.chainlink_feed_audit_strict_for_chain(1));
        assert!(!settings.chainlink_feed_audit_strict_for_chain(137));
    }

    #[test]
    fn chainlink_loader_prefers_canonical_on_equal_priority_quotes() {
        let tmp =
            std::env::temp_dir().join(format!("chainlink-feeds-test-{}.json", std::process::id()));
        let body = r#"
[
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5147eA642CAEF7BD9c1265AadcA78f997AbB9649"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, false)
            .expect("loader result")
            .expect("selected feeds");

        std::fs::remove_file(&tmp).ok();

        let eth = selected.get("ETH").copied().expect("ETH feed");
        assert_eq!(
            format!("{:#x}", eth),
            "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419"
        );
    }

    #[test]
    fn chainlink_loader_accepts_resolved_conflicts_in_strict_mode() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-strict-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5147eA642CAEF7BD9c1265AadcA78f997AbB9649"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, true)
            .expect("loader result")
            .expect("selected feeds");

        std::fs::remove_file(&tmp).ok();

        let eth = selected.get("ETH").copied().expect("ETH feed");
        assert_eq!(
            format!("{:#x}", eth),
            "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419"
        );
    }

    #[test]
    fn chainlink_loader_dedupes_identical_entries() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-dedupe-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"WETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");
        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, false)
            .expect("loader result")
            .expect("selected feeds");
        std::fs::remove_file(&tmp).ok();
        assert_eq!(selected.len(), 1);
        assert!(selected.contains_key("ETH"));
    }

    #[test]
    fn chainlink_loader_rejects_unresolved_conflicts_in_strict_mode() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-strict-unresolved-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"FOO","quote":"USD","chainId":1,"address":"0x1111111111111111111111111111111111111111"},
  {"base":"FOO","quote":"USD","chainId":1,"address":"0x2222222222222222222222222222222222222222"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let err = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, true)
            .expect_err("strict unresolved conflict mode should fail");

        std::fs::remove_file(&tmp).ok();

        assert!(
            matches!(err, AppError::Config(msg) if msg.contains("unresolved conflicting duplicate"))
        );
    }

    #[test]
    fn explicit_config_path_wins_over_active_discovery() {
        let resolved = resolve_config_path(Some("custom-config.toml"));
        assert_eq!(resolved.as_deref(), Some("custom-config.toml"));
    }

    #[test]
    fn env_overrides_selected_profile_file_values() {
        let _env_lock = env_lock_guard();
        let tmp = std::env::temp_dir().join(format!(
            "config-env-override-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let body = r#"
wallet_key = "file_wallet_key"
wallet_address = "0x0000000000000000000000000000000000000001"
"#;
        std::fs::write(&tmp, body).expect("write temp config");
        let old_wallet_key = std::env::var("WALLET_KEY").ok();
        unsafe {
            std::env::set_var("WALLET_KEY", "env_wallet_key");
        }

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.wallet_key, "env_wallet_key");

        std::fs::remove_file(&tmp).ok();
        if let Some(v) = old_wallet_key {
            unsafe { std::env::set_var("WALLET_KEY", v) };
        } else {
            unsafe { std::env::remove_var("WALLET_KEY") };
        }
    }

    #[test]
    fn chains_env_overrides_profile_file_even_when_selected() {
        let _env_lock = env_lock_guard();
        let tmp = std::env::temp_dir().join(format!(
            "config-chains-env-override-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let body = r#"
wallet_key = "file_wallet_key"
wallet_address = "0x0000000000000000000000000000000000000001"
chains = [1]
"#;
        std::fs::write(&tmp, body).expect("write temp config");
        let old_chains = std::env::var("CHAINS").ok();
        unsafe {
            std::env::set_var("CHAINS", "1,137");
        }

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.chains, vec![1, 137]);

        std::fs::remove_file(&tmp).ok();
        if let Some(v) = old_chains {
            unsafe { std::env::set_var("CHAINS", v) };
        } else {
            unsafe { std::env::remove_var("CHAINS") };
        }
    }
}
