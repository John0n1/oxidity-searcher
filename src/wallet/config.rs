// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct WalletServiceConfig {
    pub bind: String,
    pub port: u16,
    pub product_name: String,
    pub support_email: String,
    pub public_site_url: String,
    pub business_contact_url: String,
    pub docs_url: String,
    pub status_url: String,
    pub extension_download_url: String,
    pub android_download_url: String,
    pub default_chain_id: u64,
    pub chains: Vec<WalletChainConfig>,
}

#[derive(Debug, Clone)]
pub struct WalletChainConfig {
    pub id: u64,
    pub slug: String,
    pub name: String,
    pub rpc_label: String,
    pub native_currency: String,
    pub http_url: String,
    pub ws_url: Option<String>,
    pub explorer_address_url: String,
    pub source_label: String,
}

impl WalletServiceConfig {
    pub fn from_env() -> Self {
        let default_chain_id = env_or("WALLET_SERVICE_DEFAULT_CHAIN_ID", "1")
            .parse::<u64>()
            .unwrap_or(1);

        Self {
            bind: env_or("WALLET_SERVICE_BIND", "127.0.0.1"),
            port: env_or("WALLET_SERVICE_PORT", "9555")
                .parse::<u16>()
                .unwrap_or(9555),
            product_name: env_or("WALLET_SERVICE_PRODUCT_NAME", "Oxidity Wallet"),
            support_email: env_or("WALLET_SERVICE_SUPPORT_EMAIL", "support@oxidity.io"),
            public_site_url: env_or(
                "WALLET_SERVICE_PUBLIC_SITE_URL",
                "https://wallet.oxidity.io",
            ),
            business_contact_url: env_or(
                "WALLET_SERVICE_BUSINESS_CONTACT_URL",
                "https://oxidity.io/partners?requested=wallet",
            ),
            docs_url: env_or("WALLET_SERVICE_DOCS_URL", "https://oxidity.io/developers"),
            status_url: env_or("WALLET_SERVICE_STATUS_URL", "https://oxidity.io/status"),
            extension_download_url: env_or(
                "WALLET_SERVICE_EXTENSION_DOWNLOAD_URL",
                "https://wallet.oxidity.io/downloads/oxidity-wallet-extension.zip",
            ),
            android_download_url: env_or(
                "WALLET_SERVICE_ANDROID_DOWNLOAD_URL",
                "https://wallet.oxidity.io/downloads/oxidity-wallet-debug.apk",
            ),
            default_chain_id,
            chains: default_wallet_chains(),
        }
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, String> {
        format!("{}:{}", self.bind.trim(), self.port)
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid wallet service bind address: {error}"))
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn env_first(keys: &[&str], fallback: &str) -> String {
    keys.iter()
        .find_map(|key| {
            env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn env_first_optional(keys: &[&str], fallback: Option<&str>) -> Option<String> {
    keys.iter()
        .find_map(|key| {
            env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| fallback.map(ToString::to_string))
}

fn wallet_chain(
    id: u64,
    slug: &str,
    name: &str,
    native_currency: &str,
    source_label: &str,
    explorer_address_url: &str,
    http_keys: &[&str],
    http_fallback: &str,
    ws_keys: &[&str],
    ws_fallback: Option<&str>,
) -> WalletChainConfig {
    WalletChainConfig {
        id,
        slug: slug.to_string(),
        name: name.to_string(),
        rpc_label: if source_label == "local-node" {
            "Local node".to_string()
        } else {
            "PublicNode".to_string()
        },
        native_currency: native_currency.to_string(),
        http_url: env_first(http_keys, http_fallback),
        ws_url: env_first_optional(ws_keys, ws_fallback),
        explorer_address_url: explorer_address_url.to_string(),
        source_label: source_label.to_string(),
    }
}

fn default_wallet_chains() -> Vec<WalletChainConfig> {
    vec![
        wallet_chain(
            1,
            "ethereum",
            "Ethereum",
            "ETH",
            "local-node",
            "https://etherscan.io/address/",
            &["WALLET_RPC_ETHEREUM_HTTP", "HTTP_PROVIDER_1"],
            "http://127.0.0.1:8545",
            &["WALLET_RPC_ETHEREUM_WS", "WEBSOCKET_PROVIDER_1"],
            Some("ws://127.0.0.1:8546"),
        ),
        wallet_chain(
            42161,
            "arbitrum",
            "Arbitrum One",
            "ETH",
            "publicnode",
            "https://arbiscan.io/address/",
            &["WALLET_RPC_ARBITRUM_HTTP"],
            "https://arbitrum-one-rpc.publicnode.com",
            &["WALLET_RPC_ARBITRUM_WS"],
            Some("wss://arbitrum-one-rpc.publicnode.com"),
        ),
        wallet_chain(
            8453,
            "base",
            "Base",
            "ETH",
            "publicnode",
            "https://basescan.org/address/",
            &["WALLET_RPC_BASE_HTTP"],
            "https://base-rpc.publicnode.com",
            &["WALLET_RPC_BASE_WS"],
            Some("wss://base-rpc.publicnode.com"),
        ),
        wallet_chain(
            10,
            "optimism",
            "Optimism",
            "ETH",
            "publicnode",
            "https://optimistic.etherscan.io/address/",
            &["WALLET_RPC_OPTIMISM_HTTP"],
            "https://optimism-rpc.publicnode.com",
            &["WALLET_RPC_OPTIMISM_WS"],
            Some("wss://optimism-rpc.publicnode.com"),
        ),
        wallet_chain(
            137,
            "polygon",
            "Polygon",
            "POL",
            "publicnode",
            "https://polygonscan.com/address/",
            &["WALLET_RPC_POLYGON_HTTP"],
            "https://polygon-bor-rpc.publicnode.com",
            &["WALLET_RPC_POLYGON_WS"],
            Some("wss://polygon-bor-rpc.publicnode.com"),
        ),
        wallet_chain(
            56,
            "bsc",
            "BNB Smart Chain",
            "BNB",
            "publicnode",
            "https://bscscan.com/address/",
            &["WALLET_RPC_BSC_HTTP"],
            "https://bsc-rpc.publicnode.com",
            &["WALLET_RPC_BSC_WS"],
            Some("wss://bsc-rpc.publicnode.com"),
        ),
        wallet_chain(
            43114,
            "avalanche",
            "Avalanche C-Chain",
            "AVAX",
            "publicnode",
            "https://snowtrace.io/address/",
            &["WALLET_RPC_AVALANCHE_HTTP"],
            "https://avalanche-c-chain-rpc.publicnode.com",
            &["WALLET_RPC_AVALANCHE_WS"],
            Some("wss://avalanche-c-chain-rpc.publicnode.com"),
        ),
    ]
}
