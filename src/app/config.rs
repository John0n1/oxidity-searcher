// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::domain::constants;
use crate::domain::error::AppError;
use alloy::primitives::Address;
use config::{Config, Environment, File};
use serde::{Deserialize, Deserializer};
use serde_json;
use std::collections::HashMap;
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
    pub rpc_urls: Option<HashMap<String, String>>,
    pub ws_urls: Option<HashMap<String, String>>,
    pub ipc_urls: Option<HashMap<String, String>>,
    pub chainlink_feeds: Option<HashMap<String, String>>, // Symbol -> aggregator address
    pub chainlink_feeds_path: Option<String>,
    pub aave_pools_by_chain: Option<HashMap<String, String>>,
    pub flashbots_relay_url: Option<String>,
    pub bundle_signer_key: Option<String>,
    #[serde(default = "default_bribe_bps")]
    pub executor_bribe_bps: u64,
    pub executor_bribe_recipient: Option<Address>,
    pub tokenlist_path: Option<String>,
    pub address_registry_path: Option<String>,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    #[serde(default = "default_true")]
    pub strategy_enabled: bool,
    pub strategy_workers: Option<usize>,
    pub metrics_bind: Option<String>,
    pub metrics_token: Option<String>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u64,
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
    0
}
fn default_true() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9000
}
fn default_slippage_bps() -> u64 {
    0
}
fn default_gas_cap_multiplier_bps() -> u64 {
    12_000
}
fn default_skip_log_every() -> u64 {
    500
}
fn default_allow_non_wrapped_swaps() -> bool {
    false
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
    false
}
fn default_router_discovery_max_entries() -> usize {
    2000
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

        let active_config = detect_active_config_file();
        let mut builder = Config::builder();

        match active_config {
            Some(ref active_path) => {
                // Environment is lower priority; active config wins
                builder = builder
                    .add_source(Environment::default())
                    .add_source(File::from(Path::new(active_path)).required(true));
            }
            None => {
                if let Some(path) = path {
                    builder = builder.add_source(File::with_name(path).required(true));
                } else {
                    builder = builder.add_source(File::with_name("config").required(false));
                }
                // Environment (and .env) override non-active configs
                builder = builder.add_source(Environment::default());
            }
        }

        let mut settings: GlobalSettings = builder.build()?.try_deserialize()?;

        // Allow CHAINS env to be comma/space separated string (e.g. "1,137")
        if active_config.is_none() {
            if let Ok(chains_str) = std::env::var("CHAINS") {
                settings.chains = parse_chain_list(&chains_str)?;
            }
        }

        // Basic Validation
        if settings.wallet_key.is_empty() {
            return Err(AppError::Config("WALLET_KEY is missing".to_string()));
        }

        Ok(settings)
    }

    pub fn load() -> Result<Self, AppError> {
        Self::load_with_path(None)
    }

    /// Best-effort primary HTTP RPC URL for chain auto-detection.
    pub fn primary_http_url(&self) -> Option<String> {
        // Prefer explicit map entry with smallest key
        if let Some(map) = &self.rpc_urls {
            if let Some((_, v)) = map.iter().min_by_key(|(k, _)| k.parse::<u64>().ok()) {
                return Some(v.clone());
            }
            if let Some((_, v)) = map.iter().next() {
                return Some(v.clone());
            }
        }
        // Environment fallbacks
        std::env::var("RPC_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("RPC_URL_1").ok().filter(|s| !s.is_empty()))
    }

    /// Helper to get RPC URL for a specific chain
    pub fn get_rpc_url(&self, chain_id: u64) -> Result<String, AppError> {
        // Try looking for explicit map
        if let Some(urls) = &self.rpc_urls {
            if let Some(url) = urls.get(&chain_id.to_string()) {
                return Ok(url.clone());
            }
        }

        // Fallback to env var convention: RPC_URL_1, RPC_URL_137
        let env_key = format!("RPC_URL_{}", chain_id);
        std::env::var(&env_key)
            .map_err(|_| AppError::Config(format!("No RPC URL found for chain {}", chain_id)))
    }

    /// Helper to get WS URL for a specific chain
    pub fn get_ws_url(&self, chain_id: u64) -> Result<String, AppError> {
        if let Some(urls) = &self.ws_urls {
            if let Some(url) = urls.get(&chain_id.to_string()) {
                return Ok(url.clone());
            }
        }

        let candidates = [
            format!("WS_URL_{}", chain_id),
            format!("WEBSOCKET_URL_{}", chain_id),
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

    /// Optional IPC URL for a specific chain, preferring explicit config, then env, then local Nethermind default.
    pub fn get_ipc_url(&self, chain_id: u64) -> Option<String> {
        if let Some(urls) = &self.ipc_urls {
            if let Some(url) = urls.get(&chain_id.to_string()) {
                return Some(url.clone());
            }
        }

        let candidates = [
            format!("IPC_URL_{}", chain_id),
            format!("IPC_PATH_{}", chain_id),
            "IPC_URL".to_string(),
            "IPC_PATH".to_string(),
        ];

        for key in candidates {
            if let Ok(v) = std::env::var(&key) {
                if !v.trim().is_empty() {
                    return Some(v);
                }
            }
        }

        // Local default for mainnet Nethermind.
        let default_ipc = "/mnt/pool/ethereum/nethermind/nethermind.ipc";
        if chain_id == 1 && Path::new(default_ipc).exists() {
            return Some(default_ipc.to_string());
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

    pub fn tokenlist_path(&self) -> String {
        std::env::var("TOKENLIST_PATH")
            .ok()
            .or_else(|| self.tokenlist_path.clone())
            .unwrap_or_else(|| "data/tokenlist.json".to_string())
    }

    pub fn address_registry_path(&self) -> String {
        std::env::var("ADDRESS_REGISTRY_PATH")
            .ok()
            .or_else(|| self.address_registry_path.clone())
            .unwrap_or_else(|| "data/address_registry.json".to_string())
    }

    pub fn database_url(&self) -> String {
        std::env::var("DATABASE_URL")
            .ok()
            .or_else(|| self.database_url.clone())
            .unwrap_or_else(|| "sqlite://oxidity_builder.db".to_string())
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
        if let Ok(v) = std::env::var("STRATEGY_WORKERS") {
            if let Ok(parsed) = v.parse::<usize>() {
                return parsed.max(1);
            }
        }
        self.strategy_workers.unwrap_or(32).max(1)
    }

    pub fn metrics_bind_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("METRICS_BIND") {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        self.metrics_bind.clone()
    }

    pub fn metrics_token_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("METRICS_TOKEN") {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        self.metrics_token.clone()
    }

    pub fn etherscan_api_key_value(&self) -> Option<String> {
        if let Ok(v) = std::env::var("ETHERSCAN_API_KEY") {
            if !v.trim().is_empty() {
                return Some(v);
            }
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

    pub fn skip_log_every_value(&self) -> u64 {
        self.skip_log_every.max(1)
    }

    pub fn aave_pool_for_chain(&self, chain_id: u64) -> Option<Address> {
        if let Some(map) = self
            .aave_pools_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            if let Ok(addr) = Address::from_str(map) {
                return Some(addr);
            }
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

        if out.is_empty() {
            if let Some(map) = &self.chainlink_feeds {
                out.extend(parse_address_map(map, "chainlink_feeds")?);
            }
        }

        if out.is_empty() {
            if let Some(map) =
                load_chainlink_feeds_from_file(&self.chainlink_feeds_path(), chain_id)?
            {
                out.extend(map);
            }
        }

        if out.is_empty() {
            out = constants::default_chainlink_feeds(chain_id);
        }

        Ok(out)
    }

    pub fn chainlink_feeds_path(&self) -> String {
        std::env::var("CHAINLINK_FEEDS_PATH")
            .ok()
            .or_else(|| self.chainlink_feeds_path.clone())
            .unwrap_or_else(|| "data/chainlink_feeds.json".to_string())
    }

    pub fn mev_share_relay_url(&self) -> String {
        if let Ok(v) = std::env::var("MEV_SHARE_RELAY_URL") {
            if !v.trim().is_empty() {
                return v;
            }
        }
        if let Some(v) = &self.mev_share_relay_url {
            if !v.trim().is_empty() {
                return v.clone();
            }
        }
        if let Ok(mut parsed) = Url::parse(&self.mev_share_stream_url) {
            parsed.set_path("");
            parsed.set_query(None);
            parsed.set_fragment(None);
            return parsed.to_string().trim_end_matches('/').to_string();
        }
        self.mev_share_stream_url.clone()
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
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("config.") && name.ends_with(".toml") {
                    if let Some(true) = config_has_active_flag(name) {
                        return Some(name.to_string());
                    }
                }
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

fn load_chainlink_feeds_from_file(
    path: &str,
    chain_id: u64,
) -> Result<Option<HashMap<String, Address>>, AppError> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(file_path)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json read failed: {}", e)))?;
    let entries: Vec<ChainlinkFeedEntry> = serde_json::from_str(&raw)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json parse failed: {}", e)))?;

    let mut selected: HashMap<String, (String, Address)> = HashMap::new();
    for entry in entries {
        if entry.chain_id != chain_id {
            continue;
        }

        let base = alias_base_symbol(&entry.base);
        let quote = entry.quote.to_uppercase();
        let addr = Address::from_str(&entry.address).map_err(|_| {
            AppError::InvalidAddress(format!("chainlink_feeds:{base} -> {}", entry.address))
        })?;

        let new_score = quote_priority(&quote);
        let replace = match selected.get(&base) {
            None => true,
            Some((existing_quote, _)) => new_score < quote_priority(existing_quote),
        };

        if replace {
            selected.insert(base, (quote, addr));
        }
    }

    if selected.is_empty() {
        return Ok(None);
    }

    let out = selected
        .into_iter()
        .map(|(base, (_, addr))| (base, addr))
        .collect();

    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use std::collections::HashMap;

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
            rpc_urls: None,
            ws_urls: None,
            ipc_urls: None,
            chainlink_feeds: None,
            chainlink_feeds_path: None,
            flashbots_relay_url: None,
            bundle_signer_key: None,
            executor_bribe_bps: default_bribe_bps(),
            executor_bribe_recipient: None,
            tokenlist_path: None,
            address_registry_path: None,
            metrics_port: default_metrics_port(),
            strategy_enabled: default_true(),
            strategy_workers: None,
            metrics_bind: None,
            metrics_token: None,
            slippage_bps: default_slippage_bps(),
            gas_cap_multiplier_bps: default_gas_cap_multiplier_bps(),
            skip_log_every: default_skip_log_every(),
            allow_non_wrapped_swaps: default_allow_non_wrapped_swaps(),
            gas_caps_gwei: None,
            mev_share_stream_url: default_mev_share_url(),
            mev_share_relay_url: None,
            mev_share_history_limit: default_mev_share_history_limit(),
            mev_share_enabled: default_true(),
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
    fn ipc_url_prefers_configured_map() {
        let mut settings = base_settings();
        settings.ipc_urls = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/test.ipc".to_string(),
        )]));
        assert_eq!(settings.get_ipc_url(1).as_deref(), Some("/tmp/test.ipc"));
    }

    #[test]
    fn ws_lookup_does_not_use_ipc_entries() {
        let mut settings = base_settings();
        settings.ipc_urls = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/socket.ipc".to_string(),
        )]));
        settings.ws_urls = None;

        let err = settings.get_ws_url(1).unwrap_err();
        match err {
            AppError::Config(msg) => assert!(msg.contains("No WS URL")),
            other => panic!("Unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn mev_share_relay_url_prefers_config_value() {
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
}
