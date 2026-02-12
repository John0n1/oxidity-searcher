// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::primitives::{Address, U256};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

// =============================================================================
// NETWORK CONSTANTS
// =============================================================================

pub const CHAIN_ETHEREUM: u64 = 1;
pub const CHAIN_OPTIMISM: u64 = 10;
pub const CHAIN_BSC: u64 = 56;
pub const CHAIN_POLYGON: u64 = 137;
pub const CHAIN_ARBITRUM: u64 = 42161;

// Block times in seconds (approximate)
pub fn get_block_time(chain_id: u64) -> u64 {
    match chain_id {
        CHAIN_ETHEREUM => 12,
        CHAIN_BSC => 3,
        CHAIN_POLYGON | CHAIN_OPTIMISM | CHAIN_ARBITRUM => 2,
        _ => 12,
    }
}

// =============================================================================
// GAS & TRANSACTION CONSTANTS
// =============================================================================

pub const DEFAULT_GAS_LIMIT: u64 = 250_000;
pub const MAX_GAS_LIMIT: u64 = 8_000_000;
pub const DEFAULT_PRIORITY_FEE_GWEI: u64 = 2;

// =============================================================================
// MEV CONSTANTS (Using U256 for precise Wei math)
// =============================================================================

lazy_static! {
    // 0.00001 ETH (accept small edges by default)
    pub static ref MIN_PROFIT_THRESHOLD_WEI: U256 = U256::from(10_000_000_000_000u64);

    // 0.00002 ETH
    pub static ref LOW_BALANCE_THRESHOLD_WEI: U256 = U256::from(20_000_000_000_000u64);

    static ref ADDRESS_REGISTRY_DEFAULTS: AddressRegistryDefaults =
        load_address_registry_defaults("data/address_registry.json");

    static ref WRAPPED_NATIVE_BY_CHAIN: HashMap<u64, Address> = {
        let mut merged = load_wrapped_native_from_tokenlist("data/tokenlist.json");
        // If registry provides a wrapped-native address per chain, prefer it.
        for (chain_id, addr) in ADDRESS_REGISTRY_DEFAULTS.wrapped_native_by_chain.iter() {
            merged.insert(*chain_id, *addr);
        }
        merged
    };

    static ref NATIVE_SENTINEL_BY_CHAIN: HashMap<u64, Address> =
        load_native_sentinel_from_tokenlist("data/tokenlist.json");
}

#[derive(Debug, Clone, Default)]
struct AddressRegistryDefaults {
    routers_by_chain: HashMap<u64, HashMap<String, Address>>,
    balancer_vault_by_chain: HashMap<u64, Address>,
    aave_pool_by_chain: HashMap<u64, Address>,
    aave_addresses_provider_by_chain: HashMap<u64, Address>,
    wrapped_native_by_chain: HashMap<u64, Address>,
    chainlink_feeds_by_chain: HashMap<u64, HashMap<String, Address>>,
}

#[derive(Debug, Deserialize, Default)]
struct AddressRegistryFileRaw {
    #[serde(default)]
    chains: HashMap<String, AddressRegistryChainRaw>,
}

#[derive(Debug, Deserialize, Default)]
struct AddressRegistryChainRaw {
    #[serde(default)]
    routers: HashMap<String, String>,
    balancer_vault: Option<String>,
    aave_pool: Option<String>,
    aave_addresses_provider: Option<String>,
    #[serde(default)]
    chainlink_feeds: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct TokenlistEntryRaw {
    symbol: String,
    #[serde(default)]
    addresses: HashMap<String, String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn parse_address(raw: &str) -> Option<Address> {
    Address::from_str(raw).ok()
}

fn load_address_registry_defaults(path: &str) -> AddressRegistryDefaults {
    let p = Path::new(path);
    if !p.exists() {
        return AddressRegistryDefaults::default();
    }

    let raw = match fs::read_to_string(p) {
        Ok(v) => v,
        Err(_) => return AddressRegistryDefaults::default(),
    };
    let parsed: AddressRegistryFileRaw = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return AddressRegistryDefaults::default(),
    };

    let mut out = AddressRegistryDefaults::default();

    for (chain_raw, chain) in parsed.chains {
        let Ok(chain_id) = chain_raw.parse::<u64>() else {
            continue;
        };

        let mut routers = HashMap::new();
        for (name, addr_raw) in chain.routers {
            let Some(addr) = parse_address(&addr_raw) else {
                continue;
            };
            let key = name.trim().to_ascii_lowercase();
            if key == "wrapped_native" || key == "weth" || key == "weth9" || key == "wbnb" {
                out.wrapped_native_by_chain.insert(chain_id, addr);
            }
            routers.insert(key, addr);
        }

        if let Some(vault) = chain.balancer_vault.as_deref().and_then(parse_address) {
            out.balancer_vault_by_chain.insert(chain_id, vault);
            routers.entry("balancer_v2_vault".to_string()).or_insert(vault);
        }

        if let Some(pool) = chain.aave_pool.as_deref().and_then(parse_address) {
            out.aave_pool_by_chain.insert(chain_id, pool);
        }

        if let Some(provider) = chain
            .aave_addresses_provider
            .as_deref()
            .and_then(parse_address)
        {
            out.aave_addresses_provider_by_chain.insert(chain_id, provider);
        }

        if !routers.is_empty() {
            out.routers_by_chain.insert(chain_id, routers);
        }

        let mut feeds = HashMap::new();
        for (symbol, addr_raw) in chain.chainlink_feeds {
            let Some(addr) = parse_address(&addr_raw) else {
                continue;
            };
            feeds.insert(symbol.trim().to_ascii_uppercase(), addr);
        }
        if !feeds.is_empty() {
            out.chainlink_feeds_by_chain.insert(chain_id, feeds);
        }
    }

    out
}

fn wrapped_symbol_match(chain_id: u64, symbol_upper: &str) -> bool {
    match chain_id {
        CHAIN_BSC => symbol_upper == "WBNB",
        CHAIN_POLYGON => symbol_upper == "WMATIC" || symbol_upper == "WETH",
        _ => symbol_upper == "WETH",
    }
}

fn native_symbol_match(chain_id: u64, symbol_upper: &str) -> bool {
    match chain_id {
        CHAIN_BSC => symbol_upper == "BNB",
        CHAIN_POLYGON => symbol_upper == "MATIC",
        _ => symbol_upper == "ETH",
    }
}

fn load_wrapped_native_from_tokenlist(path: &str) -> HashMap<u64, Address> {
    let p = Path::new(path);
    if !p.exists() {
        return HashMap::new();
    }

    let raw = match fs::read_to_string(p) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let entries: Vec<TokenlistEntryRaw> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };

    let mut out = HashMap::new();
    for entry in entries {
        let symbol_upper = entry.symbol.trim().to_ascii_uppercase();
        for (chain_raw, addr_raw) in entry.addresses {
            let Ok(chain_id) = chain_raw.parse::<u64>() else {
                continue;
            };
            if !wrapped_symbol_match(chain_id, &symbol_upper) {
                continue;
            }
            let Some(addr) = parse_address(&addr_raw) else {
                continue;
            };
            out.entry(chain_id).or_insert(addr);
        }
    }

    out
}

fn load_native_sentinel_from_tokenlist(path: &str) -> HashMap<u64, Address> {
    let p = Path::new(path);
    if !p.exists() {
        return HashMap::new();
    }

    let raw = match fs::read_to_string(p) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let entries: Vec<TokenlistEntryRaw> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };

    let mut out = HashMap::new();
    for entry in entries {
        let symbol_upper = entry.symbol.trim().to_ascii_uppercase();
        let has_native_tag = entry
            .tags
            .iter()
            .any(|tag| tag.trim().eq_ignore_ascii_case("native"));

        for (chain_raw, addr_raw) in entry.addresses {
            let Ok(chain_id) = chain_raw.parse::<u64>() else {
                continue;
            };
            if !has_native_tag && !native_symbol_match(chain_id, &symbol_upper) {
                continue;
            }
            let Some(addr) = parse_address(&addr_raw) else {
                continue;
            };
            out.entry(chain_id).or_insert(addr);
        }
    }

    out
}

// =============================================================================
// LOGGING DEFAULTS
// =============================================================================

pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const LOG_FILE_NAME: &str = "oxidity_builder.log";

pub fn default_routers_for_chain(chain_id: u64) -> HashMap<String, Address> {
    ADDRESS_REGISTRY_DEFAULTS
        .routers_by_chain
        .get(&chain_id)
        .cloned()
        .unwrap_or_default()
}

pub fn default_uniswap_v2_router(chain_id: u64) -> Option<Address> {
    let routers = ADDRESS_REGISTRY_DEFAULTS.routers_by_chain.get(&chain_id)?;
    routers
        .get("uniswap_v2_router02")
        .copied()
        .or_else(|| routers.get("uniswap_v2_router").copied())
}

pub fn default_uniswap_v3_router(chain_id: u64) -> Option<Address> {
    let routers = ADDRESS_REGISTRY_DEFAULTS.routers_by_chain.get(&chain_id)?;
    routers
        .get("uniswap_v3_swaprouter02")
        .copied()
        .or_else(|| routers.get("uniswap_v3_router02").copied())
        .or_else(|| routers.get("uniswap_v3_swaprouter").copied())
        .or_else(|| routers.get("uniswap_v3_router").copied())
}

pub fn default_uniswap_universal_router(chain_id: u64) -> Option<Address> {
    let routers = ADDRESS_REGISTRY_DEFAULTS.routers_by_chain.get(&chain_id)?;
    routers
        .get("uniswap_universal_router")
        .copied()
        .or_else(|| routers.get("uniswap_universal_router_v2").copied())
}

pub fn default_uniswap_universal_routers(chain_id: u64) -> Vec<Address> {
    let Some(routers) = ADDRESS_REGISTRY_DEFAULTS.routers_by_chain.get(&chain_id) else {
        return Vec::new();
    };
    let mut out: Vec<Address> = routers
        .iter()
        .filter_map(|(name, addr)| {
            if name.starts_with("uniswap_universal_router") {
                Some(*addr)
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn default_oneinch_routers(chain_id: u64) -> Vec<Address> {
    let Some(routers) = ADDRESS_REGISTRY_DEFAULTS.routers_by_chain.get(&chain_id) else {
        return Vec::new();
    };
    let mut out: Vec<Address> = routers
        .iter()
        .filter_map(|(name, addr)| {
            if name.starts_with("oneinch_aggregation_router") {
                Some(*addr)
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn default_chainlink_feeds(chain_id: u64) -> HashMap<String, Address> {
    ADDRESS_REGISTRY_DEFAULTS
        .chainlink_feeds_by_chain
        .get(&chain_id)
        .cloned()
        .unwrap_or_default()
}

pub fn wrapped_native_for_chain(chain_id: u64) -> Address {
    WRAPPED_NATIVE_BY_CHAIN
        .get(&chain_id)
        .copied()
        .or_else(|| WRAPPED_NATIVE_BY_CHAIN.get(&CHAIN_ETHEREUM).copied())
        .unwrap_or(Address::ZERO)
}

pub fn native_sentinel_for_chain(chain_id: u64) -> Address {
    NATIVE_SENTINEL_BY_CHAIN
        .get(&chain_id)
        .copied()
        .or_else(|| NATIVE_SENTINEL_BY_CHAIN.get(&CHAIN_ETHEREUM).copied())
        .unwrap_or(Address::ZERO)
}

pub fn native_symbol_for_chain(chain_id: u64) -> &'static str {
    match chain_id {
        CHAIN_BSC => "BNB",
        CHAIN_POLYGON => "MATIC",
        _ => "ETH",
    }
}

pub fn default_balancer_vault_for_chain(chain_id: u64) -> Option<Address> {
    ADDRESS_REGISTRY_DEFAULTS
        .balancer_vault_by_chain
        .get(&chain_id)
        .copied()
        .or_else(|| {
            ADDRESS_REGISTRY_DEFAULTS
                .routers_by_chain
                .get(&chain_id)
                .and_then(|m| m.get("balancer_v2_vault").copied())
        })
}

pub fn default_aave_pool(chain_id: u64) -> Option<Address> {
    ADDRESS_REGISTRY_DEFAULTS
        .aave_pool_by_chain
        .get(&chain_id)
        .copied()
}

pub fn default_aave_addresses_provider(chain_id: u64) -> Option<Address> {
    ADDRESS_REGISTRY_DEFAULTS
        .aave_addresses_provider_by_chain
        .get(&chain_id)
        .copied()
}

pub fn default_aave_weth_gateway(_chain_id: u64) -> Option<Address> {
    None
}

pub fn default_aave_oracle(_chain_id: u64) -> Option<Address> {
    None
}

pub fn default_aave_data_provider(_chain_id: u64) -> Option<Address> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_symbol_map() {
        assert_eq!(native_symbol_for_chain(CHAIN_ETHEREUM), "ETH");
        assert_eq!(native_symbol_for_chain(CHAIN_BSC), "BNB");
        assert_eq!(native_symbol_for_chain(CHAIN_POLYGON), "MATIC");
    }
}
