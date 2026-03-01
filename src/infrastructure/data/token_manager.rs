// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use std::collections::HashMap;
use std::fs;

use alloy::primitives::Address;
use alloy::providers::Provider;
use dashmap::DashSet;
use serde::Deserialize;

use crate::domain::error::AppError;
use crate::network::provider::HttpProvider;

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
    invalid_tokens: DashSet<(u64, Address)>,
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

#[derive(Deserialize)]
struct GlobalDataTokenSources {
    #[serde(default)]
    tokenlist: Vec<TokenEntry>,
}

impl TokenManager {
    fn is_native_token(info: &TokenInfo) -> bool {
        info.tags
            .iter()
            .any(|tag| tag.trim().eq_ignore_ascii_case("native"))
    }

    pub fn load_from_file(path: &str) -> Result<Self, AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("Failed to read global_data {path}: {e}")))?;
        let sources: GlobalDataTokenSources = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("Invalid global_data JSON {path}: {e}")))?;
        let entries = sources.tokenlist;

        let mut tokens_by_chain: HashMap<u64, HashMap<Address, TokenInfo>> = HashMap::new();

        for entry in entries {
            for (chain_str, addr_str) in entry.addresses {
                if let Ok(chain_id) = chain_str.parse::<u64>()
                    && let Ok(addr) = addr_str.parse::<Address>()
                {
                    tokens_by_chain
                        .entry(chain_id)
                        .or_default()
                        .entry(addr)
                        .or_insert(TokenInfo {
                            symbol: entry.symbol.clone(),
                            decimals: entry.decimals,
                            tags: entry.tags.clone(),
                        });
                }
            }
        }

        Ok(Self {
            tokens_by_chain,
            invalid_tokens: DashSet::new(),
        })
    }

    pub fn decimals(&self, chain_id: u64, address: Address) -> Option<u8> {
        if self.invalid_tokens.contains(&(chain_id, address)) {
            return None;
        }
        self.tokens_by_chain
            .get(&chain_id)
            .and_then(|m| m.get(&address))
            .map(|t| t.decimals)
    }

    pub fn info(&self, chain_id: u64, address: Address) -> Option<&TokenInfo> {
        if self.invalid_tokens.contains(&(chain_id, address)) {
            return None;
        }
        self.tokens_by_chain
            .get(&chain_id)
            .and_then(|m| m.get(&address))
    }

    pub fn is_empty(&self) -> bool {
        self.tokens_by_chain.is_empty()
    }

    pub async fn validate_chain_addresses(&self, provider: &HttpProvider, chain_id: u64) -> usize {
        let Some(tokens) = self.tokens_by_chain.get(&chain_id) else {
            return 0;
        };
        let mut invalid = 0usize;
        for (addr, info) in tokens {
            // Native sentinel entries (for example 0xeeee...) intentionally have no bytecode.
            if Self::is_native_token(info) {
                self.invalid_tokens.remove(&(chain_id, *addr));
                continue;
            }
            match provider.get_code_at(*addr).await {
                Ok(code) => {
                    if code.is_empty() {
                        self.invalid_tokens.insert((chain_id, *addr));
                        invalid += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "token_manager",
                        address = %format!("{:#x}", addr),
                        error = %e,
                        "Failed to validate token code; marking invalid"
                    );
                    self.invalid_tokens.insert((chain_id, *addr));
                    invalid += 1;
                }
            }
        }
        invalid
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self {
            tokens_by_chain: HashMap::new(),
            invalid_tokens: DashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TokenInfo;
    use super::TokenManager;

    #[test]
    fn native_tag_is_detected_case_insensitive() {
        let info = TokenInfo {
            symbol: "ETH".to_string(),
            decimals: 18,
            tags: vec!["Tier1".to_string(), "NATIVE".to_string()],
        };
        assert!(TokenManager::is_native_token(&info));
    }

    #[test]
    fn non_native_token_is_not_flagged() {
        let info = TokenInfo {
            symbol: "USDC".to_string(),
            decimals: 6,
            tags: vec!["tier1".to_string(), "stablecoin".to_string()],
        };
        assert!(!TokenManager::is_native_token(&info));
    }

    #[test]
    fn load_from_file_uses_merged_tokenlist_without_overriding_first_entry() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "token-manager-merge-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&base).expect("tmp dir");
        let global_data = base.join("global_data.json");
        let global_data_body = r#"
{
  "tokenlist": [
    {
      "symbol": "MAIN",
      "decimals": 8,
      "tags": ["core"],
      "addresses": {"1": "0x0000000000000000000000000000000000000001"}
    }
    ,
    {
      "symbol": "MM_NEW",
      "decimals": 18,
      "tags": ["supplemental", "metamask_uniswap"],
      "addresses": {"1": "0x0000000000000000000000000000000000000002"}
    },
    {
      "symbol": "CM_NEW",
      "decimals": 6,
      "tags": ["supplemental", "contract_map"],
      "addresses": {"1": "0x0000000000000000000000000000000000000003"}
    },
    {
      "symbol": "DUP_IGNORED",
      "decimals": 18,
      "tags": ["supplemental"],
      "addresses": {"1": "0x0000000000000000000000000000000000000001"}
    }
  ]
}
"#;
        fs::write(&global_data, global_data_body).expect("global data write");

        let mgr =
            TokenManager::load_from_file(global_data.to_str().expect("utf8 path")).expect("load");

        let info_primary = mgr
            .info(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .expect("addr"),
            )
            .expect("primary token");
        assert_eq!(info_primary.symbol, "MAIN");
        assert_eq!(info_primary.decimals, 8);

        let info_metamask = mgr
            .info(
                1,
                "0x0000000000000000000000000000000000000002"
                    .parse()
                    .expect("addr"),
            )
            .expect("metamask token");
        assert_eq!(info_metamask.symbol, "MM_NEW");
        assert_eq!(info_metamask.decimals, 18);

        let info_contract = mgr
            .info(
                1,
                "0x0000000000000000000000000000000000000003"
                    .parse()
                    .expect("addr"),
            )
            .expect("contract-map token");
        assert_eq!(info_contract.symbol, "CM_NEW");
        assert_eq!(info_contract.decimals, 6);

        let _ = fs::remove_file(global_data);
        let _ = fs::remove_dir(base);
    }
}
