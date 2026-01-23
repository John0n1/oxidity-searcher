// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::domain::constants;
use crate::domain::error::AppError;
use alloy::primitives::Address;
use config::{Config, Environment, File};
use serde::{Deserialize, Deserializer};
use std::fs;
use std::collections::HashMap;
use std::str::FromStr;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct GlobalSettings {
    // General
    #[serde(default = "default_debug")]
    pub debug: bool,
    #[serde(default = "default_chain", deserialize_with = "deserialize_chain_list")]
    pub chains: Vec<u64>,

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
    pub executor_address: Option<Address>,
    #[serde(default = "default_true")]
    pub sandwich_attacks_enabled: bool,
    pub rpc_urls: Option<HashMap<String, String>>,
    pub ws_urls: Option<HashMap<String, String>>,
    pub ipc_urls: Option<HashMap<String, String>>,
    pub chainlink_feeds: Option<HashMap<String, String>>, // Symbol -> aggregator address
    pub flashbots_relay_url: Option<String>,
    pub bundle_signer_key: Option<String>,
    #[serde(default = "default_bribe_bps")]
    pub executor_bribe_bps: u64,
    pub executor_bribe_recipient: Option<Address>,
    pub tokenlist_path: Option<String>,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    #[serde(default = "default_true")]
    pub strategy_enabled: bool,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u64,
    pub gas_caps_gwei: Option<HashMap<String, u64>>,
    #[serde(default = "default_mev_share_url")]
    pub mev_share_stream_url: String,
    #[serde(default = "default_mev_share_history_limit")]
    pub mev_share_history_limit: u32,
    #[serde(default = "default_true")]
    pub mev_share_enabled: bool,

    // Per-chain maps
    pub router_allowlist_by_chain: Option<HashMap<String, HashMap<String, String>>>,
    pub chainlink_feeds_by_chain: Option<HashMap<String, HashMap<String, String>>>,
}

// Defaults
fn default_debug() -> bool {
    false
}
fn default_chain() -> Vec<u64> {
    vec![1]
}
fn default_max_gas() -> u64 {
    200
}
fn default_true() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9000
}
fn default_slippage_bps() -> u64 {
    50
}
fn default_sim_backend() -> String {
    "revm".to_string()
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
            format!("IPC_URL_{}", chain_id),
        ];

        for key in candidates {
            if let Ok(v) = std::env::var(&key) {
                return Ok(v);
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

    pub fn flashbots_relay_url(&self) -> String {
        self.flashbots_relay_url
            .clone()
            .or_else(|| std::env::var("FLASHBOTS_RELAY_URL").ok())
            .unwrap_or_else(|| "https://relay.flashbots.net".to_string())
    }

    pub fn bundle_signer_key(&self) -> String {
        self.bundle_signer_key
            .clone()
            .or_else(|| std::env::var("BUNDLE_SIGNER_KEY").ok())
            .unwrap_or_else(|| self.wallet_key.clone())
    }

    pub fn gas_cap_for_chain(&self, chain_id: u64) -> Option<u64> {
        self.gas_caps_gwei
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()).cloned())
    }

    pub fn routers_for_chain(&self, chain_id: u64) -> Result<HashMap<String, Address>, AppError> {
        if let Some(map) = self
            .router_allowlist_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            return parse_address_map(map, "router_allowlist_by_chain");
        }

        Ok(constants::default_routers_for_chain(chain_id))
    }

    pub fn chainlink_feeds_for_chain(
        &self,
        chain_id: u64,
    ) -> Result<HashMap<String, Address>, AppError> {
        if let Some(map) = self
            .chainlink_feeds_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            return parse_address_map(map, "chainlink_feeds_by_chain");
        }

        if let Some(map) = &self.chainlink_feeds {
            return parse_address_map(map, "chainlink_feeds");
        }

        Ok(constants::default_chainlink_feeds(chain_id))
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
