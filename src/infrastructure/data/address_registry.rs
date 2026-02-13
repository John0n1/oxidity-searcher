// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::providers::Provider;
use serde::Deserialize;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ChainRegistry {
    pub routers: HashMap<String, Address>,
    pub balancer_vault: Option<Address>,
    pub curve_registries: Vec<Address>,
    pub curve_meta_registries: Vec<Address>,
    pub curve_crypto_registries: Vec<Address>,
    pub aave_pool: Option<Address>,
    pub aave_addresses_provider: Option<Address>,
    pub chainlink_feeds: HashMap<String, Address>,
}

impl ChainRegistry {
    pub fn empty() -> Self {
        Self {
            routers: HashMap::new(),
            balancer_vault: None,
            curve_registries: Vec::new(),
            curve_meta_registries: Vec::new(),
            curve_crypto_registries: Vec::new(),
            aave_pool: None,
            aave_addresses_provider: None,
            chainlink_feeds: HashMap::new(),
        }
    }

    pub async fn validate_with_provider(mut self, provider: &HttpProvider) -> Self {
        self.routers = validate_address_map(provider, self.routers, "registry.routers").await;
        self.chainlink_feeds =
            validate_address_map(provider, self.chainlink_feeds, "registry.chainlink_feeds").await;

        self.balancer_vault =
            validate_optional(provider, self.balancer_vault, "balancer_vault").await;
        self.aave_pool = validate_optional(provider, self.aave_pool, "aave_pool").await;
        self.aave_addresses_provider = validate_optional(
            provider,
            self.aave_addresses_provider,
            "aave_addresses_provider",
        )
        .await;

        self.curve_registries =
            validate_address_list(provider, self.curve_registries, "curve_registries").await;
        self.curve_meta_registries = validate_address_list(
            provider,
            self.curve_meta_registries,
            "curve_meta_registries",
        )
        .await;
        self.curve_crypto_registries = validate_address_list(
            provider,
            self.curve_crypto_registries,
            "curve_crypto_registries",
        )
        .await;

        self
    }
}

#[derive(Deserialize, Debug)]
struct AddressRegistryFile {
    chains: HashMap<String, ChainRegistryFile>,
}

#[derive(Deserialize, Debug)]
struct ChainRegistryFile {
    #[serde(default)]
    routers: HashMap<String, String>,
    #[serde(default)]
    balancer_vault: Option<String>,
    #[serde(default)]
    curve_registries: Vec<String>,
    #[serde(default)]
    curve_meta_registries: Vec<String>,
    #[serde(default)]
    curve_crypto_registries: Vec<String>,
    #[serde(default)]
    aave_pool: Option<String>,
    #[serde(default)]
    aave_addresses_provider: Option<String>,
    #[serde(default)]
    chainlink_feeds: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct AddressRegistry {
    chains: HashMap<u64, ChainRegistry>,
}

impl AddressRegistry {
    pub fn load_from_file(path: &str) -> Result<Self, AppError> {
        let p = Path::new(path);
        if !p.exists() {
            return Err(AppError::Config(format!(
                "Address registry not found: {}",
                path
            )));
        }
        let raw = fs::read_to_string(p)
            .map_err(|e| AppError::Config(format!("Failed to read registry {}: {e}", path)))?;
        let file: AddressRegistryFile = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("Failed to parse registry {}: {e}", path)))?;

        let mut chains: HashMap<u64, ChainRegistry> = HashMap::new();
        for (chain_str, c) in file.chains {
            let Ok(chain_id) = chain_str.parse::<u64>() else {
                continue;
            };
            let mut reg = ChainRegistry::empty();
            reg.routers = parse_address_map(&c.routers);
            reg.balancer_vault = parse_address_opt(c.balancer_vault);
            reg.curve_registries = parse_address_list(&c.curve_registries);
            reg.curve_meta_registries = parse_address_list(&c.curve_meta_registries);
            reg.curve_crypto_registries = parse_address_list(&c.curve_crypto_registries);
            reg.aave_pool = parse_address_opt(c.aave_pool);
            reg.aave_addresses_provider = parse_address_opt(c.aave_addresses_provider);
            reg.chainlink_feeds = parse_address_map(&c.chainlink_feeds);
            chains.insert(chain_id, reg);
        }

        Ok(Self { chains })
    }

    pub fn chain(&self, chain_id: u64) -> Option<ChainRegistry> {
        self.chains.get(&chain_id).cloned()
    }
}

fn parse_address_opt(raw: Option<String>) -> Option<Address> {
    raw.and_then(|s| Address::from_str(&s).ok())
}

fn parse_address_list(raw: &[String]) -> Vec<Address> {
    raw.iter()
        .filter_map(|s| Address::from_str(s).ok())
        .collect()
}

fn parse_address_map(raw: &HashMap<String, String>) -> HashMap<String, Address> {
    let mut out = HashMap::new();
    for (k, v) in raw {
        if let Ok(addr) = Address::from_str(v) {
            out.insert(k.clone(), addr);
        }
    }
    out
}

async fn validate_optional(
    provider: &HttpProvider,
    addr: Option<Address>,
    label: &str,
) -> Option<Address> {
    let a = addr?;
    if has_code(provider, a).await {
        Some(a)
    } else {
        tracing::warn!(
            target: "registry",
            address = %format!("{:#x}", a),
            label,
            "Address has no code; dropping"
        );
        None
    }
}

async fn validate_address_list(
    provider: &HttpProvider,
    addrs: Vec<Address>,
    label: &str,
) -> Vec<Address> {
    let mut out = Vec::new();
    for a in addrs {
        if has_code(provider, a).await {
            out.push(a);
        } else {
            tracing::warn!(
                target: "registry",
                address = %format!("{:#x}", a),
                label,
                "Address has no code; dropping"
            );
        }
    }
    out
}

pub async fn validate_address_map(
    provider: &HttpProvider,
    addrs: HashMap<String, Address>,
    label: &str,
) -> HashMap<String, Address> {
    let mut out = HashMap::new();
    for (k, v) in addrs {
        if has_code(provider, v).await {
            out.insert(k, v);
        } else {
            tracing::warn!(
                target: "registry",
                address = %format!("{:#x}", v),
                key = %k,
                label,
                "Address has no code; dropping"
            );
        }
    }
    out
}

async fn has_code(provider: &HttpProvider, addr: Address) -> bool {
    match provider.get_code_at(addr).await {
        Ok(code) => !code.is_empty(),
        Err(e) => {
            tracing::warn!(
                target: "registry",
                address = %format!("{:#x}", addr),
                error = %e,
                "Failed to fetch code; treating as invalid"
            );
            false
        }
    }
}
