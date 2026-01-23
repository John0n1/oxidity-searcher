// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use std::collections::HashMap;
use std::fs;

use alloy::primitives::Address;
use serde::Deserialize;

use crate::domain::error::AppError;

/// Minimal token metadata used for decimal-aware profit checks and logging.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TokenManager {
    tokens_by_chain: HashMap<u64, HashMap<Address, TokenInfo>>,
}

#[derive(Deserialize)]
struct TokenEntry {
    symbol: String,
    #[serde(default)]
    tags: Vec<String>,
    decimals: u8,
    #[serde(default)]
    addresses: HashMap<String, String>,
}

impl TokenManager {
    pub fn load_from_file(path: &str) -> Result<Self, AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("Failed to read tokenlist {path}: {e}")))?;
        let entries: Vec<TokenEntry> = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("Invalid tokenlist JSON {path}: {e}")))?;

        let mut tokens_by_chain: HashMap<u64, HashMap<Address, TokenInfo>> = HashMap::new();

        for entry in entries {
            for (chain_str, addr_str) in entry.addresses {
                if let Ok(chain_id) = chain_str.parse::<u64>() {
                    if let Ok(addr) = addr_str.parse::<Address>() {
                        tokens_by_chain.entry(chain_id).or_default().insert(
                            addr,
                            TokenInfo {
                                symbol: entry.symbol.clone(),
                                decimals: entry.decimals,
                                tags: entry.tags.clone(),
                            },
                        );
                    }
                }
            }
        }

        Ok(Self { tokens_by_chain })
    }

    pub fn decimals(&self, chain_id: u64, address: Address) -> Option<u8> {
        self.tokens_by_chain
            .get(&chain_id)
            .and_then(|m| m.get(&address))
            .map(|t| t.decimals)
    }

    pub fn info(&self, chain_id: u64, address: Address) -> Option<&TokenInfo> {
        self.tokens_by_chain
            .get(&chain_id)
            .and_then(|m| m.get(&address))
    }

    pub fn is_empty(&self) -> bool {
        self.tokens_by_chain.is_empty()
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self {
            tokens_by_chain: HashMap::new(),
        }
    }
}
