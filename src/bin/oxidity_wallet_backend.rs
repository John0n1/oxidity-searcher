// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::{TransactionInput, TransactionRequest};
use alloy::sol;
use alloy_primitives::utils::{format_ether, format_units, parse_ether};
use alloy_sol_types::SolCall;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Local, Utc};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use oxidity_searcher::app::config::GlobalSettings;
use oxidity_searcher::domain::constants;
use oxidity_searcher::domain::error::AppError;
use oxidity_searcher::infrastructure::network::liquidity::reserves::ReserveCache;
use oxidity_searcher::infrastructure::network::provider::{ConnectionFactory, HttpProvider};
use oxidity_searcher::services::strategy::execution::executor::BundleSender;
use oxidity_searcher::services::strategy::execution::strategy::StrategyStats;
use oxidity_searcher::services::strategy::routers::{UniV2Router, registry_v2_router_candidates};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tower_http::cors::CorsLayer;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
        function symbol() external view returns (string);
        function name() external view returns (string);
        function decimals() external view returns (uint8);
    }

    #[sol(rpc)]
    interface IERC721Metadata {
        function ownerOf(uint256 tokenId) external view returns (address);
        function tokenURI(uint256 tokenId) external view returns (string);
        function name() external view returns (string);
        function symbol() external view returns (string);
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainProtocol {
    Evm,
    Solana,
    Sui,
    Bitcoin,
    Cosmos,
    AvalancheP,
    AvalancheX,
}

#[derive(Clone, Copy, Debug)]
struct TokenCatalogEntry {
    symbol: &'static str,
    name: &'static str,
    address: &'static str,
    logo: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
struct ChainConfig {
    key: &'static str,
    name: &'static str,
    protocol: ChainProtocol,
    native_symbol: &'static str,
    native_price_id: Option<&'static str>,
    coingecko_platform: Option<&'static str>,
    explorer_tx_base_url: Option<&'static str>,
    http_rpc: Option<&'static str>,
    ws_rpc: Option<&'static str>,
    token_catalog: &'static [TokenCatalogEntry],
}

const ETHEREUM_TOKEN_CATALOG: &[TokenCatalogEntry] = &[
    TokenCatalogEntry {
        symbol: "USDC",
        name: "USD Coin",
        address: "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        logo: Some("https://cryptologos.cc/logos/usd-coin-usdc-logo.png"),
    },
    TokenCatalogEntry {
        symbol: "USDT",
        name: "Tether",
        address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        logo: Some("https://cryptologos.cc/logos/tether-usdt-logo.png"),
    },
    TokenCatalogEntry {
        symbol: "WBTC",
        name: "Wrapped Bitcoin",
        address: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        logo: Some("https://cryptologos.cc/logos/wrapped-bitcoin-wbtc-logo.png"),
    },
    TokenCatalogEntry {
        symbol: "LINK",
        name: "Chainlink",
        address: "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        logo: Some("https://cryptologos.cc/logos/chainlink-link-logo.png"),
    },
    TokenCatalogEntry {
        symbol: "UNI",
        name: "Uniswap",
        address: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        logo: Some("https://cryptologos.cc/logos/uniswap-uni-logo.png"),
    },
    TokenCatalogEntry {
        symbol: "AAVE",
        name: "Aave",
        address: "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",
        logo: Some("https://cryptologos.cc/logos/aave-aave-logo.png"),
    },
];

const EMPTY_TOKEN_CATALOG: &[TokenCatalogEntry] = &[];
const DEFAULT_CHAIN_KEY: &str = "ethereum";

const CHAIN_CONFIGS: &[ChainConfig] = &[
    ChainConfig {
        key: "ethereum",
        name: "Ethereum",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: Some("ethereum"),
        explorer_tx_base_url: Some("https://etherscan.io/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://ethereum-rpc.publicnode.com"),
        token_catalog: ETHEREUM_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "bsc",
        name: "BNB Smart Chain",
        protocol: ChainProtocol::Evm,
        native_symbol: "BNB",
        native_price_id: Some("binancecoin"),
        coingecko_platform: Some("binance-smart-chain"),
        explorer_tx_base_url: Some("https://bscscan.com/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://bsc-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "polygon",
        name: "Polygon",
        protocol: ChainProtocol::Evm,
        native_symbol: "POL",
        native_price_id: Some("matic-network"),
        coingecko_platform: Some("polygon-pos"),
        explorer_tx_base_url: Some("https://polygonscan.com/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://polygon-heimdall-rpc.publicnode.com:443/websocket"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "base",
        name: "Base",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: Some("base"),
        explorer_tx_base_url: Some("https://basescan.org/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://base-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "avalanche-c",
        name: "Avalanche C-Chain",
        protocol: ChainProtocol::Evm,
        native_symbol: "AVAX",
        native_price_id: Some("avalanche-2"),
        coingecko_platform: Some("avalanche"),
        explorer_tx_base_url: Some("https://snowtrace.io/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://avalanche-c-chain-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "avalanche-p",
        name: "Avalanche P-Chain",
        protocol: ChainProtocol::AvalancheP,
        native_symbol: "AVAX",
        native_price_id: Some("avalanche-2"),
        coingecko_platform: None,
        explorer_tx_base_url: None,
        http_rpc: Some("https://avalanche-p-chain-rpc.publicnode.com"),
        ws_rpc: None,
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "avalanche-x",
        name: "Avalanche X-Chain",
        protocol: ChainProtocol::AvalancheX,
        native_symbol: "AVAX",
        native_price_id: Some("avalanche-2"),
        coingecko_platform: None,
        explorer_tx_base_url: None,
        http_rpc: Some("https://avalanche-x-chain-rpc.publicnode.com"),
        ws_rpc: None,
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "optimism",
        name: "Optimism",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: Some("optimistic-ethereum"),
        explorer_tx_base_url: Some("https://optimistic.etherscan.io/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://optimism-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "arbitrum",
        name: "Arbitrum One",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: Some("arbitrum-one"),
        explorer_tx_base_url: Some("https://arbiscan.io/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://arbitrum-one-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "sui",
        name: "Sui",
        protocol: ChainProtocol::Sui,
        native_symbol: "SUI",
        native_price_id: Some("sui"),
        coingecko_platform: None,
        explorer_tx_base_url: None,
        http_rpc: Some("https://sui-rpc.publicnode.com"),
        ws_rpc: None,
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "solana",
        name: "Solana",
        protocol: ChainProtocol::Solana,
        native_symbol: "SOL",
        native_price_id: Some("solana"),
        coingecko_platform: None,
        explorer_tx_base_url: Some("https://explorer.solana.com/tx/"),
        http_rpc: Some("https://solana-rpc.publicnode.com"),
        ws_rpc: Some("wss://solana-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "pulsechain",
        name: "PulseChain",
        protocol: ChainProtocol::Evm,
        native_symbol: "PLS",
        native_price_id: None,
        coingecko_platform: None,
        explorer_tx_base_url: Some("https://scan.pulsechain.com/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://pulsechain-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "linea",
        name: "Linea",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: Some("linea"),
        explorer_tx_base_url: Some("https://lineascan.build/tx/"),
        http_rpc: Some("https://linea-rpc.publicnode.com"),
        ws_rpc: None,
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "unichain",
        name: "Unichain",
        protocol: ChainProtocol::Evm,
        native_symbol: "ETH",
        native_price_id: Some("ethereum"),
        coingecko_platform: None,
        explorer_tx_base_url: Some("https://uniscan.xyz/tx/"),
        http_rpc: None,
        ws_rpc: Some("wss://unichain-rpc.publicnode.com"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "cosmos",
        name: "Cosmos",
        protocol: ChainProtocol::Cosmos,
        native_symbol: "ATOM",
        native_price_id: Some("cosmos"),
        coingecko_platform: None,
        explorer_tx_base_url: None,
        http_rpc: None,
        ws_rpc: Some("wss://cosmos-rpc.publicnode.com:443/websocket"),
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
    ChainConfig {
        key: "bitcoin",
        name: "Bitcoin",
        protocol: ChainProtocol::Bitcoin,
        native_symbol: "BTC",
        native_price_id: Some("bitcoin"),
        coingecko_platform: None,
        explorer_tx_base_url: None,
        http_rpc: Some("https://bitcoin-rpc.publicnode.com"),
        ws_rpc: None,
        token_catalog: EMPTY_TOKEN_CATALOG,
    },
];

static PROVIDER_CACHE: Lazy<DashMap<&'static str, HttpProvider>> = Lazy::new(DashMap::new);

#[derive(Clone)]
struct EvmRuntime {
    provider: HttpProvider,
    chain_id: u64,
    wrapped_native: Address,
    reserve_cache: Arc<ReserveCache>,
    v2_routers: Vec<(String, Address)>,
    bundle_sender: Option<Arc<BundleSender>>,
    protected_execution: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogToken {
    symbol: String,
    name: String,
    address: String,
    decimals: u8,
    logo: Option<String>,
    coingecko_id: Option<String>,
    is_native: bool,
}

#[derive(Clone, Default)]
struct TokenCatalogIndex {
    by_chain_id: BTreeMap<u64, Vec<CatalogToken>>,
    by_chain_symbol: BTreeMap<u64, BTreeMap<String, CatalogToken>>,
    by_chain_address: BTreeMap<u64, BTreeMap<String, CatalogToken>>,
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    http: Client,
    settings: GlobalSettings,
    coingecko_base: String,
    coingecko_key: Option<String>,
    etherscan_key: Option<String>,
    token_catalog: TokenCatalogIndex,
    evm_runtimes: Arc<RwLock<BTreeMap<&'static str, Arc<EvmRuntime>>>>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn from_app(err: AppError) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: err.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortfolioRequest {
    address: String,
    chain_key: Option<String>,
    #[serde(default)]
    custom_tokens: Vec<CustomTokenInput>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CustomTokenInput {
    address: String,
    symbol: Option<String>,
    name: Option<String>,
    logo: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveTokenRequest {
    chain_key: Option<String>,
    address: String,
    wallet_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuotePreviewRequest {
    chain_key: Option<String>,
    sell_token: Option<String>,
    buy_token: Option<String>,
    sell_amount: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwapPrepareRequest {
    chain_key: Option<String>,
    wallet_address: String,
    sell_token: Option<String>,
    buy_token: Option<String>,
    sell_amount: String,
    slippage_bps: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendPrepareRequest {
    chain_key: Option<String>,
    from: String,
    to: String,
    amount: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendBroadcastRequest {
    chain_key: Option<String>,
    raw_transaction: String,
    wallet_address: String,
    encoding: Option<String>,
    tx_type: String,
    title: String,
    amount: String,
    fiat_amount: String,
    asset: String,
    to: String,
    fee: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityRequest {
    address: String,
    chain_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NftSendPrepareRequest {
    chain_key: Option<String>,
    from: String,
    to: String,
    contract_address: String,
    token_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnRampQuoteRequest {
    chain_key: Option<String>,
    wallet_address: String,
    amount_usd: String,
    buy_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AiChatRequest {
    message: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NetworkHealth {
    key: String,
    name: String,
    protocol: String,
    status: String,
    chain_id: Option<u64>,
    block_number: Option<u64>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadLinks {
    chrome_extension: String,
    android_apk: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapResponse {
    app_name: String,
    version: String,
    wallet_app_url: String,
    downloads: DownloadLinks,
    supported_networks: Vec<NetworkHealth>,
    defaults: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeAssetResponse {
    id: String,
    chain_key: String,
    symbol: String,
    name: String,
    address: String,
    balance: String,
    raw_balance: f64,
    fiat_balance: String,
    fiat_value: f64,
    receive_address: String,
    logo: Option<String>,
    is_native: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    id: String,
    chain_key: String,
    symbol: String,
    name: String,
    address: String,
    decimals: u8,
    balance: String,
    raw_balance: f64,
    fiat_balance: String,
    fiat_value: f64,
    receive_address: String,
    logo: Option<String>,
    is_native: bool,
    is_custom: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NftResponse {
    id: String,
    chain_key: String,
    contract_address: String,
    token_id: String,
    collection: String,
    name: String,
    image: String,
    price: String,
    price_fiat: String,
    external_url: String,
    explorer_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PortfolioResponse {
    network: Value,
    account: Value,
    native_asset: NativeAssetResponse,
    tokens: Vec<TokenResponse>,
    nfts: Vec<NftResponse>,
    insights: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuotePreviewResponse {
    chain_key: String,
    sell_token: String,
    buy_token: String,
    sell_amount: f64,
    receive_amount: f64,
    rate: f64,
    sell_usd_value: f64,
    receive_usd_value: f64,
    estimated_gas_usd: f64,
    estimated_gas_native: f64,
    speed_options: Value,
    execution_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendPrepareResponse {
    protocol: String,
    chain_key: String,
    chain_id: u64,
    network: String,
    nonce: u64,
    gas_limit: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    estimated_fee_native: f64,
    estimated_fee_usd: f64,
    explorer_tx_base_url: String,
    execution_mode: String,
    recent_blockhash: Option<String>,
    last_valid_block_height: Option<u64>,
    lamports_per_signature: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SwapPrepareResponse {
    chain_key: String,
    chain_id: u64,
    network: String,
    router_name: String,
    router: String,
    to: String,
    data: String,
    value: String,
    nonce: u64,
    gas_limit: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    expected_out: String,
    min_out: String,
    expected_out_formatted: String,
    buy_symbol: String,
    estimated_fee_native: f64,
    estimated_fee_usd: f64,
    explorer_tx_base_url: String,
    execution_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendBroadcastResponse {
    hash: String,
    status: String,
    explorer_url: String,
    execution_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NftSendPrepareResponse {
    chain_key: String,
    chain_id: u64,
    network: String,
    contract_address: String,
    token_id: String,
    to: String,
    data: String,
    nonce: u64,
    gas_limit: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    estimated_fee_native: f64,
    estimated_fee_usd: f64,
    explorer_tx_base_url: String,
    execution_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OnRampProviderQuote {
    id: String,
    name: String,
    rate: f64,
    fee: f64,
    delivery_time: String,
    trust_score: u64,
    receive_amount: f64,
    checkout_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OnRampQuoteResponse {
    chain_key: String,
    amount_usd: f64,
    buy_token: String,
    market_price_usd: f64,
    providers: Vec<OnRampProviderQuote>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiChatResponse {
    content: String,
    sources: Vec<AiSource>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiSource {
    uri: String,
    title: String,
}

#[derive(Debug)]
struct ActivityRow {
    id: String,
    tx_type: String,
    title: String,
    amount: String,
    fiat_amount: String,
    asset: String,
    address: Option<String>,
    hash: Option<String>,
    from_address: Option<String>,
    to_address: Option<String>,
    fee: Option<String>,
    network: String,
    status: String,
    is_protected: i64,
    rebate: Option<String>,
    created_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct GlobalTokenFile {
    #[serde(default)]
    tokenlist: Vec<GlobalTokenEntry>,
}

#[derive(Debug, Deserialize)]
struct GlobalTokenEntry {
    symbol: String,
    name: String,
    decimals: u8,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    addresses: BTreeMap<String, String>,
    #[serde(default)]
    coingecko_id: Option<String>,
}

#[derive(Clone, Debug)]
struct ResolvedAsset {
    symbol: String,
    name: String,
    address: Address,
    decimals: u8,
    logo: Option<String>,
    coingecko_id: Option<String>,
    is_native: bool,
}

#[derive(Clone, Debug)]
struct SwapRoutePlan {
    router_name: String,
    router: Address,
    path: Vec<Address>,
    amount_in: U256,
    expected_out: U256,
    min_out: U256,
    sell_asset: ResolvedAsset,
    buy_asset: ResolvedAsset,
}

#[derive(Clone, Debug, Deserialize)]
struct ExplorerEnvelope {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    result: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExplorerTxEntry {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    time_stamp: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    gas_price: String,
    #[serde(default)]
    gas_used: String,
    #[serde(default)]
    is_error: String,
    #[serde(default)]
    txreceipt_status: String,
    #[serde(default)]
    method_id: String,
    #[serde(default)]
    token_symbol: String,
    #[serde(default)]
    token_name: String,
    #[serde(default)]
    token_decimal: String,
    #[serde(default)]
    contract_address: String,
    #[serde(default)]
    token_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct SolanaBalanceResult {
    value: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SolanaLatestBlockhashValue {
    blockhash: String,
    last_valid_block_height: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct SolanaRpcContextValue<T> {
    value: T,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SolanaSignatureStatus {
    signature: String,
    #[serde(default)]
    err: Option<Value>,
    #[serde(default)]
    block_time: Option<i64>,
    #[serde(default)]
    confirmation_status: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();
    let settings = GlobalSettings::load()?;
    let bind = std::env::var("OXIDITY_WALLET_BACKEND_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("OXIDITY_WALLET_BACKEND_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(9555);
    let database_url = std::env::var("OXIDITY_WALLET_BACKEND_DB")
        .unwrap_or_else(|_| "sqlite://oxidity_wallet_backend.db".into());

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|err| AppError::Initialization(format!("Wallet backend DB connect failed: {err}")))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wallet_backend_activity (
            id TEXT PRIMARY KEY,
            wallet_address TEXT NOT NULL,
            chain_key TEXT NOT NULL,
            tx_type TEXT NOT NULL,
            title TEXT NOT NULL,
            amount TEXT NOT NULL,
            fiat_amount TEXT NOT NULL,
            asset TEXT NOT NULL,
            address TEXT,
            hash TEXT,
            from_address TEXT,
            to_address TEXT,
            fee TEXT,
            network TEXT NOT NULL,
            status TEXT NOT NULL,
            is_protected INTEGER NOT NULL DEFAULT 0,
            rebate TEXT,
            created_at_ms INTEGER NOT NULL
        )
        "#,
    )
    .execute(&db)
    .await
    .map_err(|err| AppError::Initialization(format!("Wallet backend schema init failed: {err}")))?;

    let token_catalog_path = settings
        .tokenlist_path()
        .unwrap_or_else(|_| "data/global_data.json".into());
    let token_catalog = load_token_catalog(Path::new(&token_catalog_path))?;

    let state = Arc::new(AppState {
        db,
        http: Client::builder()
            .timeout(StdDuration::from_secs(12))
            .build()
            .map_err(|err| AppError::Initialization(format!("Wallet backend HTTP client failed: {err}")))?,
        settings: settings.clone(),
        coingecko_base: if std::env::var("COINGECKO_API_KEY").ok().filter(|v| !v.is_empty()).is_some()
        {
            "https://pro-api.coingecko.com/api/v3".into()
        } else {
            "https://api.coingecko.com/api/v3".into()
        },
        coingecko_key: std::env::var("COINGECKO_API_KEY").ok().filter(|value| !value.is_empty()),
        etherscan_key: settings.etherscan_api_key_value().filter(|value| !value.is_empty()),
        token_catalog,
        evm_runtimes: Arc::new(RwLock::new(BTreeMap::new())),
    });

    let app = Router::new()
        .route("/api/health", get(api_health))
        .route("/api/bootstrap", get(api_bootstrap))
        .route("/api/networks", get(api_networks))
        .route("/api/catalog", get(api_catalog))
        .route("/api/portfolio", post(api_portfolio))
        .route("/api/token/resolve", post(api_resolve_token))
        .route("/api/quote-preview", post(api_quote_preview))
        .route("/api/swap/prepare", post(api_swap_prepare))
        .route("/api/send/prepare", post(api_send_prepare))
        .route("/api/send/broadcast", post(api_send_broadcast))
        .route("/api/activity", post(api_activity))
        .route("/api/nft/send/prepare", post(api_nft_send_prepare))
        .route("/api/onramp/quote", post(api_onramp_quote))
        .route("/api/ai/chat", post(api_ai_chat))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let address: SocketAddr = format!("{bind}:{port}")
        .parse()
        .map_err(|err| AppError::Initialization(format!("Wallet backend bind parse failed: {err}")))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|err| AppError::Initialization(format!("Wallet backend bind failed: {err}")))?;
    println!("Oxidity wallet backend listening on http://{address}");
    axum::serve(listener, app)
        .await
        .map_err(|err| AppError::Initialization(format!("Wallet backend serve failed: {err}")))?;
    Ok(())
}

fn chain_by_key(chain_key: &str) -> Option<&'static ChainConfig> {
    CHAIN_CONFIGS.iter().find(|chain| chain.key == chain_key)
}

fn resolve_chain(chain_key: Option<&str>) -> Result<&'static ChainConfig, ApiError> {
    let key = chain_key.unwrap_or(DEFAULT_CHAIN_KEY).trim().to_lowercase();
    chain_by_key(&key).ok_or_else(|| ApiError::bad_request(format!("Unsupported chain: {key}")))
}

async fn build_evm_runtime(
    state: &AppState,
    chain: &'static ChainConfig,
) -> Result<Arc<EvmRuntime>, ApiError> {
    if chain.protocol != ChainProtocol::Evm {
        return Err(ApiError::bad_request(format!(
            "{} is not enabled for EVM wallet operations",
            chain.name
        )));
    }

    let chain_id_hint = evm_chain_id_hint(chain);
    let http_override = chain_id_hint.and_then(|id| state.settings.get_http_provider(id).ok());
    let ws_override = chain_id_hint.and_then(|id| state.settings.get_websocket_provider(id).ok());
    let ipc_override = chain_id_hint.and_then(|id| state.settings.get_ipc_provider(id));

    let provider = if let Some(provider) = PROVIDER_CACHE.get(chain.key) {
        provider.clone()
    } else if let Some(ipc_rpc) = ipc_override.as_deref() {
        ConnectionFactory::ipc(ipc_rpc)
            .await
            .map_err(ApiError::from_app)?
    } else if let Some(ws_rpc) = ws_override.as_deref() {
        ConnectionFactory::ws(ws_rpc, None)
            .await
            .map_err(ApiError::from_app)?
    } else if let Some(http_rpc) = http_override.as_deref() {
        ConnectionFactory::http(http_rpc, None).map_err(ApiError::from_app)?
    } else if let Some(http_rpc) = chain.http_rpc {
        ConnectionFactory::http(http_rpc, None).map_err(ApiError::from_app)?
    } else if let Some(ws_rpc) = chain.ws_rpc {
        ConnectionFactory::ws(ws_rpc, None)
            .await
            .map_err(ApiError::from_app)?
    } else {
        return Err(ApiError::bad_request(format!(
            "{} has no usable EVM RPC configured",
            chain.name
        )));
    };

    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|err| ApiError::internal(format!("Chain id read failed: {err}")))?;
    PROVIDER_CACHE.insert(chain.key, provider.clone());
    let reserve_cache = Arc::new(ReserveCache::new(provider.clone()));
    if let Ok(pairs_path) = state.settings.pairs_path()
        && Path::new(&pairs_path).exists()
    {
        let _ = reserve_cache
            .load_pairs_from_file_validated(&pairs_path, &provider, chain_id)
            .await;
        let _ = reserve_cache.warmup_v2_reserves(256).await;
    }

    let mut v2_routers = registry_v2_router_candidates(chain_id);
    if v2_routers.is_empty()
        && let Some(router) = constants::default_uniswap_v2_router(chain_id)
    {
        v2_routers.push(("uniswap_v2_router02".into(), router));
    }

    let bundle_sender = if chain_id == constants::CHAIN_ETHEREUM {
        let signer = alloy::signers::local::PrivateKeySigner::from_str(
            &state.settings.bundle_signer_key(),
        )
        .map_err(|err| ApiError::internal(format!("Bundle signer init failed: {err}")))?;
        Some(Arc::new(BundleSender::new(
            provider.clone(),
            state.http.clone(),
            false,
            state.settings.flashbots_relay_url(),
            state.settings.mev_share_relay_url(),
            state.settings.mevshare_builders.clone(),
            signer,
            Arc::new(StrategyStats::default()),
            state.settings.bundle_use_replacement_uuid,
            state.settings.bundle_cancel_previous,
            state.settings.bundle_target_blocks,
        )))
    } else {
        None
    };

    Ok(Arc::new(EvmRuntime {
        provider,
        chain_id,
        wrapped_native: constants::wrapped_native_for_chain(chain_id),
        reserve_cache,
        v2_routers,
        protected_execution: bundle_sender.is_some(),
        bundle_sender,
    }))
}

async fn get_evm_runtime(
    state: &AppState,
    chain: &'static ChainConfig,
) -> Result<Arc<EvmRuntime>, ApiError> {
    if let Some(runtime) = state.evm_runtimes.read().await.get(chain.key).cloned() {
        return Ok(runtime);
    }
    let runtime = build_evm_runtime(state, chain).await?;
    state
        .evm_runtimes
        .write()
        .await
        .insert(chain.key, runtime.clone());
    Ok(runtime)
}

async fn get_evm_provider(
    state: &AppState,
    chain: &'static ChainConfig,
) -> Result<HttpProvider, ApiError> {
    Ok(get_evm_runtime(state, chain).await?.provider.clone())
}

fn execution_mode_label(runtime: &EvmRuntime) -> String {
    if runtime.protected_execution {
        "protected".into()
    } else {
        "direct".into()
    }
}

fn parse_address(value: &str, field: &str) -> Result<Address, ApiError> {
    Address::from_str(value).map_err(|_| ApiError::bad_request(format!("Invalid {field} address")))
}

fn parse_u256_eth(value: &str, field: &str) -> Result<U256, ApiError> {
    parse_ether(value)
        .map(Into::into)
        .map_err(|_| ApiError::bad_request(format!("Invalid {field} amount")))
}

fn parse_solana_address(value: &str, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|_| ApiError::bad_request(format!("Invalid {field} address")))?;
    if decoded.len() != 32 {
        return Err(ApiError::bad_request(format!("Invalid {field} address")));
    }
    Ok(trimmed.to_string())
}

fn parse_wallet_identifier(
    chain: &ChainConfig,
    value: &str,
    field: &str,
) -> Result<String, ApiError> {
    match chain.protocol {
        ChainProtocol::Evm => Ok(format!("{:#x}", parse_address(value, field)?)),
        ChainProtocol::Solana => parse_solana_address(value, field),
        _ => Err(ApiError::bad_request(format!(
            "{} wallet operations are not yet enabled",
            chain.name
        ))),
    }
}

fn as_f64(value: &str) -> f64 {
    value.parse::<f64>().unwrap_or(0.0)
}

fn format_f64(value: f64, max_decimals: usize) -> String {
    let mut rendered = format!("{value:.max_decimals$}");
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    if rendered.is_empty() {
        "0".into()
    } else {
        rendered
    }
}

fn format_usd(value: f64) -> String {
    format!("{value:.2}")
}

fn logo_for_symbol(symbol: &str) -> Option<&'static str> {
    match symbol.to_uppercase().as_str() {
        "ETH" => Some("https://cryptologos.cc/logos/ethereum-eth-logo.png"),
        "USDC" => Some("https://cryptologos.cc/logos/usd-coin-usdc-logo.png"),
        "USDT" => Some("https://cryptologos.cc/logos/tether-usdt-logo.png"),
        "WBTC" | "BTC" => Some("https://cryptologos.cc/logos/wrapped-bitcoin-wbtc-logo.png"),
        "LINK" => Some("https://cryptologos.cc/logos/chainlink-link-logo.png"),
        "UNI" => Some("https://cryptologos.cc/logos/uniswap-uni-logo.png"),
        "AAVE" => Some("https://cryptologos.cc/logos/aave-aave-logo.png"),
        "BNB" => Some("https://cryptologos.cc/logos/bnb-bnb-logo.png"),
        "AVAX" => Some("https://cryptologos.cc/logos/avalanche-avax-logo.png"),
        "SOL" => Some("https://cryptologos.cc/logos/solana-sol-logo.png"),
        "ATOM" => Some("https://cryptologos.cc/logos/cosmos-atom-logo.png"),
        "SUI" => Some("https://cryptologos.cc/logos/sui-sui-logo.png"),
        _ => None,
    }
}

fn evm_chain_id_hint(chain: &ChainConfig) -> Option<u64> {
    match chain.key {
        "ethereum" => Some(1),
        "optimism" => Some(10),
        "bsc" => Some(56),
        "polygon" => Some(137),
        "base" => Some(8453),
        "avalanche-c" => Some(43114),
        "arbitrum" => Some(42161),
        "pulsechain" => Some(369),
        "linea" => Some(59144),
        _ => None,
    }
}

fn load_token_catalog(path: &Path) -> Result<TokenCatalogIndex, AppError> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        AppError::Initialization(format!(
            "Wallet backend token catalog read failed for {}: {err}",
            path.display()
        ))
    })?;
    let parsed: GlobalTokenFile = serde_json::from_str(&raw).map_err(|err| {
        AppError::Initialization(format!(
            "Wallet backend token catalog parse failed for {}: {err}",
            path.display()
        ))
    })?;
    let mut index = TokenCatalogIndex::default();

    for entry in parsed.tokenlist {
        let is_native = entry
            .tags
            .iter()
            .any(|tag| tag.trim().eq_ignore_ascii_case("native"));
        for (chain_raw, address_raw) in entry.addresses {
            let Ok(chain_id) = chain_raw.parse::<u64>() else {
                continue;
            };
            let token = CatalogToken {
                symbol: entry.symbol.trim().to_uppercase(),
                name: entry.name.trim().to_string(),
                address: address_raw.trim().to_string(),
                decimals: entry.decimals,
                logo: logo_for_symbol(&entry.symbol).map(str::to_string),
                coingecko_id: entry.coingecko_id.clone(),
                is_native,
            };
            index
                .by_chain_symbol
                .entry(chain_id)
                .or_default()
                .insert(token.symbol.clone(), token.clone());
            index
                .by_chain_address
                .entry(chain_id)
                .or_default()
                .insert(token.address.to_lowercase(), token.clone());
            index.by_chain_id.entry(chain_id).or_default().push(token);
        }
    }

    for tokens in index.by_chain_id.values_mut() {
        tokens.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    }

    Ok(index)
}

fn catalog_tokens_for_chain(state: &AppState, chain_id: u64) -> Vec<CatalogToken> {
    state
        .token_catalog
        .by_chain_id
        .get(&chain_id)
        .cloned()
        .unwrap_or_default()
}

fn lookup_catalog_token_by_symbol(
    state: &AppState,
    chain_id: u64,
    symbol: &str,
) -> Option<CatalogToken> {
    state
        .token_catalog
        .by_chain_symbol
        .get(&chain_id)
        .and_then(|tokens| tokens.get(&symbol.trim().to_uppercase()).cloned())
}

fn lookup_catalog_token_by_address(
    state: &AppState,
    chain_id: u64,
    address: &Address,
) -> Option<CatalogToken> {
    state
        .token_catalog
        .by_chain_address
        .get(&chain_id)
        .and_then(|tokens| tokens.get(&format!("{address:#x}").to_lowercase()).cloned())
}

fn normalize_symbol(value: Option<&str>) -> String {
    value.unwrap_or_default().trim().to_uppercase()
}

fn native_placeholder_address() -> &'static str {
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
}

fn parse_u256_dec(value: &str, field: &str) -> Result<U256, ApiError> {
    U256::from_str_radix(value.trim(), 10)
        .map_err(|_| ApiError::bad_request(format!("Invalid {field} value")))
}

fn parse_decimal_amount(value: &str, decimals: u8, field: &str) -> Result<U256, ApiError> {
    let raw = value.trim();
    if raw.is_empty() || raw.starts_with('-') {
        return Err(ApiError::bad_request(format!("Invalid {field} amount")));
    }
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() > 2
        || parts
            .iter()
            .any(|part| !part.is_empty() && !part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(ApiError::bad_request(format!("Invalid {field} amount")));
    }

    let whole = parts.first().copied().unwrap_or_default();
    let mut fraction = parts.get(1).copied().unwrap_or_default().to_string();
    if fraction.len() > decimals as usize {
        if fraction[decimals as usize..].chars().any(|ch| ch != '0') {
            return Err(ApiError::bad_request(format!(
                "{field} supports at most {decimals} decimals"
            )));
        }
        fraction.truncate(decimals as usize);
    }
    while fraction.len() < decimals as usize {
        fraction.push('0');
    }

    let combined = format!("{whole}{fraction}");
    let normalized = combined.trim_start_matches('0');
    let normalized = if normalized.is_empty() { "0" } else { normalized };
    U256::from_str_radix(normalized, 10)
        .map_err(|_| ApiError::bad_request(format!("Invalid {field} amount")))
}

fn u256_to_f64_units(value: U256, decimals: u8) -> f64 {
    format_units(value, decimals)
        .ok()
        .as_deref()
        .map(as_f64)
        .unwrap_or(0.0)
}

fn short_address(value: &str) -> String {
    if value.len() <= 12 {
        value.to_string()
    } else {
        format!("{}...{}", &value[..6], &value[value.len().saturating_sub(4)..])
    }
}

fn lower_hex_address(address: Address) -> String {
    format!("{address:#x}").to_lowercase()
}

fn is_native_symbol(chain: &ChainConfig, symbol: &str) -> bool {
    symbol.eq_ignore_ascii_case(chain.native_symbol) || symbol.eq_ignore_ascii_case("NATIVE")
}

fn resolve_ipfs_url(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix("ipfs://ipfs/") {
        return format!("https://ipfs.io/ipfs/{path}");
    }
    if let Some(path) = uri.strip_prefix("ipfs://") {
        return format!("https://ipfs.io/ipfs/{path}");
    }
    uri.to_string()
}

fn evm_nft_explorer_url(chain: &ChainConfig, contract: Address, token_id: &str) -> String {
    match chain.key {
        "ethereum" => format!("https://etherscan.io/nft/{contract:#x}/{token_id}"),
        "base" => format!("https://basescan.org/nft/{contract:#x}/{token_id}"),
        "optimism" => format!("https://optimistic.etherscan.io/nft/{contract:#x}/{token_id}"),
        "arbitrum" => format!("https://arbiscan.io/nft/{contract:#x}/{token_id}"),
        "polygon" => format!("https://polygonscan.com/nft/{contract:#x}/{token_id}"),
        "bsc" => format!("https://bscscan.com/nft/{contract:#x}/{token_id}"),
        "avalanche-c" => format!("https://snowtrace.io/nft/{contract:#x}/{token_id}"),
        _ => chain
            .explorer_tx_base_url
            .map(|base| base.replace("/tx/", "/address/"))
            .map(|base| format!("{base}{contract:#x}"))
            .unwrap_or_default(),
    }
}

fn tx_explorer_url(chain: &ChainConfig, hash: &str) -> String {
    format!("{}{}", chain.explorer_tx_base_url.unwrap_or(""), hash)
}

async fn rpc_with_result<T: DeserializeOwned>(
    state: &AppState,
    url: &str,
    payload: Value,
) -> Result<T, ApiError> {
    let envelope: JsonRpcEnvelope<T> = maybe_json_rpc(state, url, payload).await?;
    if let Some(error) = envelope.error {
        return Err(ApiError::internal(format!("RPC returned error: {error}")));
    }
    envelope
        .result
        .ok_or_else(|| ApiError::internal("RPC response did not include a result"))
}

fn solana_http_url(chain: &ChainConfig) -> Result<&str, ApiError> {
    chain
        .http_rpc
        .ok_or_else(|| ApiError::bad_request(format!("{} has no Solana RPC configured", chain.name)))
}

async fn solana_balance_lamports(
    state: &AppState,
    chain: &'static ChainConfig,
    wallet_address: &str,
) -> Result<u64, ApiError> {
    let url = solana_http_url(chain)?;
    let result: SolanaBalanceResult = rpc_with_result(
        state,
        url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [wallet_address, { "commitment": "confirmed" }],
        }),
    )
    .await?;
    Ok(result.value)
}

async fn solana_latest_blockhash(
    state: &AppState,
    chain: &'static ChainConfig,
) -> Result<SolanaLatestBlockhashValue, ApiError> {
    let url = solana_http_url(chain)?;
    let result: SolanaRpcContextValue<SolanaLatestBlockhashValue> = rpc_with_result(
        state,
        url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{ "commitment": "confirmed" }],
        }),
    )
    .await?;
    Ok(result.value)
}

async fn solana_signature_activity(
    state: &AppState,
    chain: &'static ChainConfig,
    wallet_address: &str,
) -> Result<Vec<Value>, ApiError> {
    let url = solana_http_url(chain)?;
    let signatures: Vec<SolanaSignatureStatus> = rpc_with_result(
        state,
        url,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [wallet_address, { "limit": 24 }],
        }),
    )
    .await?;

    let native_prices = native_price_map(state, &[chain]).await?;
    let native_usd = chain
        .native_price_id
        .and_then(|id| native_prices.get(id))
        .copied()
        .unwrap_or(0.0);
    let mut items = Vec::new();

    for signature in signatures {
        let tx: Value = match rpc_with_result(
            state,
            url,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    signature.signature,
                    {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0,
                        "commitment": "confirmed"
                    }
                ],
            }),
        )
        .await
        {
            Ok(value) => value,
            Err(_) => continue,
        };

        let account_keys = tx
            .get("transaction")
            .and_then(|value| value.get("message"))
            .and_then(|value| value.get("accountKeys"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let wallet_index = account_keys.iter().position(|entry| {
            entry
                .get("pubkey")
                .and_then(Value::as_str)
                .or_else(|| entry.as_str())
                .map(|pubkey| pubkey == wallet_address)
                .unwrap_or(false)
        });
        let Some(wallet_index) = wallet_index else {
            continue;
        };

        let pre_balances = tx
            .get("meta")
            .and_then(|value| value.get("preBalances"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let post_balances = tx
            .get("meta")
            .and_then(|value| value.get("postBalances"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let pre = pre_balances
            .get(wallet_index)
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let post = post_balances
            .get(wallet_index)
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let delta = post as i128 - pre as i128;
        let direction = if delta >= 0 { "receive" } else { "send" };
        let amount_sol = (delta.unsigned_abs() as f64) / 1_000_000_000.0;
        let amount_value = format_f64(amount_sol, 6);
        let signed_amount = if direction == "send" {
            format!("-{} {}", amount_value, chain.native_symbol)
        } else {
            format!("+{} {}", amount_value, chain.native_symbol)
        };
        let fiat_value = amount_sol * native_usd;
        let signed_fiat = if direction == "send" {
            format!("-${}", format_usd(fiat_value))
        } else {
            format!("+${}", format_usd(fiat_value))
        };
        let fee_lamports = tx
            .get("meta")
            .and_then(|value| value.get("fee"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let instructions = tx
            .get("transaction")
            .and_then(|value| value.get("message"))
            .and_then(|value| value.get("instructions"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let counterparty = instructions.iter().find_map(|instruction| {
            let parsed = instruction.get("parsed")?;
            let info = parsed.get("info")?;
            if direction == "send" {
                info.get("destination").and_then(Value::as_str)
            } else {
                info.get("source").and_then(Value::as_str)
            }
        });
        let timestamp_ms = signature.block_time.unwrap_or_default() * 1000;

        items.push(json!({
            "id": signature.signature,
            "type": direction,
            "title": if direction == "send" { "Send SOL" } else { "Receive SOL" },
            "amount": signed_amount,
            "fiatAmount": signed_fiat,
            "date": relative_activity_date(timestamp_ms),
            "timestamp": timestamp_ms,
            "asset": chain.native_symbol,
            "address": counterparty,
            "isProtected": false,
            "rebate": null,
            "hash": signature.signature,
            "from": if direction == "send" { wallet_address } else { counterparty.unwrap_or_default() },
            "to": if direction == "send" { counterparty.unwrap_or_default() } else { wallet_address },
            "fee": format!("${}", format_usd(fee_lamports as f64 / 1_000_000_000.0 * native_usd)),
            "network": chain.name,
            "status": if signature.err.is_some() { "Failed" } else { "Completed" },
            "explorerUrl": tx_explorer_url(chain, &signature.signature),
        }));
    }

    Ok(items)
}

async fn maybe_json_rpc<T: DeserializeOwned>(
    state: &AppState,
    url: &str,
    payload: Value,
) -> Result<T, ApiError> {
    let response = state
        .http
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| ApiError::internal(format!("RPC request failed: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::internal(format!("RPC request failed with {status}: {body}")));
    }
    response
        .json::<T>()
        .await
        .map_err(|err| ApiError::internal(format!("RPC decode failed: {err}")))
}

async fn fetch_json_with_optional_key<T: DeserializeOwned>(
    state: &AppState,
    url: reqwest::Url,
    header_name: Option<&str>,
    key: Option<&str>,
) -> Result<T, ApiError> {
    let mut request = state.http.get(url);
    if let (Some(header_name), Some(key)) = (header_name, key) {
        request = request.header(header_name, key);
    }
    let response = request
        .send()
        .await
        .map_err(|err| ApiError::internal(format!("HTTP request failed: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::internal(format!("HTTP request failed with {status}: {body}")));
    }
    response
        .json::<T>()
        .await
        .map_err(|err| ApiError::internal(format!("HTTP decode failed: {err}")))
}

fn cryptocompare_symbol(symbol: &str) -> String {
    match symbol.trim().to_uppercase().as_str() {
        "POL" => "MATIC".into(),
        "WBTC" => "BTC".into(),
        other => other.to_string(),
    }
}

async fn cryptocompare_price_map(
    state: &AppState,
    symbols: &[String],
) -> Result<HashMap<String, f64>, ApiError> {
    let mut original_to_remote: Vec<(String, String)> = symbols
        .iter()
        .map(|symbol| (symbol.trim().to_uppercase(), cryptocompare_symbol(symbol)))
        .filter(|(symbol, remote)| !symbol.is_empty() && !remote.is_empty())
        .collect();
    original_to_remote.sort();
    original_to_remote.dedup();
    if original_to_remote.is_empty() {
        return Ok(HashMap::new());
    }

    let remote_symbols = original_to_remote
        .iter()
        .map(|(_, remote)| remote.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    let mut url = reqwest::Url::parse("https://min-api.cryptocompare.com/data/pricemulti")
        .map_err(|err| ApiError::internal(format!("CryptoCompare URL build failed: {err}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("fsyms", &remote_symbols);
        query.append_pair("tsyms", "USD");
        if let Ok(key) = std::env::var("CRYPTOCOMPARE_API_KEY")
            && !key.trim().is_empty()
        {
            query.append_pair("api_key", key.trim());
        }
    }

    let payload = state
        .http
        .get(url)
        .header("User-Agent", "OxidityWallet/1.0 (+https://oxidity.io)")
        .send()
        .await
        .map_err(|err| ApiError::internal(format!("CryptoCompare request failed: {err}")))?;
    let status = payload.status();
    if !status.is_success() {
        let body = payload.text().await.unwrap_or_default();
        return Err(ApiError::internal(format!(
            "CryptoCompare request failed with {}: {}",
            status,
            body
        )));
    }
    let body = payload
        .json::<Value>()
        .await
        .map_err(|err| ApiError::internal(format!("CryptoCompare decode failed: {err}")))?;

    let mut prices = HashMap::new();
    for (original, remote) in original_to_remote {
        let usd = body
            .get(&remote)
            .and_then(|value| value.get("USD"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        prices.insert(original, usd);
    }
    Ok(prices)
}

async fn resolve_asset_reference(
    state: &AppState,
    chain: &'static ChainConfig,
    runtime: &EvmRuntime,
    reference: Option<&str>,
    fallback_symbol: &str,
) -> Result<ResolvedAsset, ApiError> {
    let normalized = normalize_symbol(reference);
    let candidate = if normalized.is_empty() {
        fallback_symbol.to_string()
    } else {
        normalized
    };

    if is_native_symbol(chain, &candidate)
        || candidate.eq_ignore_ascii_case(native_placeholder_address())
    {
        return Ok(ResolvedAsset {
            symbol: chain.native_symbol.to_string(),
            name: chain.name.to_string(),
            address: runtime.wrapped_native,
            decimals: 18,
            logo: logo_for_symbol(chain.native_symbol).map(str::to_string),
            coingecko_id: chain.native_price_id.map(str::to_string),
            is_native: true,
        });
    }

    if candidate.starts_with("0x") {
        let address = parse_address(&candidate, "token")?;
        if let Some(token) = lookup_catalog_token_by_address(state, runtime.chain_id, &address) {
            return Ok(ResolvedAsset {
                symbol: token.symbol,
                name: token.name,
                address,
                decimals: token.decimals,
                logo: token.logo,
                coingecko_id: token.coingecko_id,
                is_native: token.is_native,
            });
        }

        let contract = IERC20::new(address, runtime.provider.clone());
        let symbol = contract
            .symbol()
            .call()
            .await
            .map_err(|err| ApiError::internal(format!("Token symbol read failed: {err}")))?;
        let name = contract
            .name()
            .call()
            .await
            .map_err(|err| ApiError::internal(format!("Token name read failed: {err}")))?;
        let decimals = contract
            .decimals()
            .call()
            .await
            .map_err(|err| ApiError::internal(format!("Token decimals read failed: {err}")))?;
        return Ok(ResolvedAsset {
            symbol,
            name,
            address,
            decimals,
            logo: None,
            coingecko_id: None,
            is_native: false,
        });
    }

    if let Some(token) = lookup_catalog_token_by_symbol(state, runtime.chain_id, &candidate) {
        return Ok(ResolvedAsset {
            symbol: token.symbol,
            name: token.name,
            address: parse_address(&token.address, "token")?,
            decimals: token.decimals,
            logo: token.logo,
            coingecko_id: token.coingecko_id,
            is_native: token.is_native,
        });
    }

    Err(ApiError::bad_request(format!(
        "Unsupported asset reference for {}: {}",
        chain.name, candidate
    )))
}

async fn quote_v2_path_with_routers(
    runtime: &EvmRuntime,
    path: &[Address],
    amount_in: U256,
) -> Option<(String, Address, U256)> {
    if path.len() < 2 || amount_in.is_zero() {
        return None;
    }

    let mut best: Option<(String, Address, U256)> = None;
    for (name, router) in &runtime.v2_routers {
        let quote = UniV2Router::new(*router, runtime.provider.clone())
            .getAmountsOut(amount_in, path.to_vec())
            .call()
            .await
            .ok()
            .and_then(|amounts: Vec<U256>| amounts.last().copied());
        let Some(output) = quote else {
            continue;
        };
        match &best {
            Some((_, _, current)) if *current >= output => {}
            _ => best = Some((name.clone(), *router, output)),
        }
    }

    if best.is_none()
        && let Some(output) = runtime.reserve_cache.quote_v2_path(path, amount_in)
        && let Some((name, router)) = runtime.v2_routers.first()
    {
        best = Some((name.clone(), *router, output));
    }

    best
}

fn candidate_swap_paths(runtime: &EvmRuntime, token_in: Address, token_out: Address) -> Vec<Vec<Address>> {
    if token_in == token_out {
        return Vec::new();
    }
    let direct = vec![token_in, token_out];
    if token_in == runtime.wrapped_native || token_out == runtime.wrapped_native {
        return vec![direct];
    }
    vec![direct, vec![token_in, runtime.wrapped_native, token_out]]
}

async fn build_swap_route_plan(
    state: &AppState,
    chain: &'static ChainConfig,
    sell_token: Option<&str>,
    buy_token: Option<&str>,
    sell_amount: &str,
    slippage_bps: u64,
) -> Result<SwapRoutePlan, ApiError> {
    let runtime = get_evm_runtime(state, chain).await?;
    let sell_asset = resolve_asset_reference(state, chain, &runtime, sell_token, chain.native_symbol).await?;
    let buy_asset = resolve_asset_reference(state, chain, &runtime, buy_token, "USDC").await?;
    let amount_in = parse_decimal_amount(sell_amount, sell_asset.decimals, "sell")?;
    if amount_in.is_zero() {
        return Err(ApiError::bad_request("sellAmount must be greater than zero"));
    }

    let mut best: Option<SwapRoutePlan> = None;
    for path in candidate_swap_paths(&runtime, sell_asset.address, buy_asset.address) {
        let Some((router_name, router, expected_out)) =
            quote_v2_path_with_routers(&runtime, &path, amount_in).await
        else {
            continue;
        };
        let min_out = expected_out
            .saturating_mul(U256::from(10_000u64.saturating_sub(slippage_bps.min(9_900))))
            / U256::from(10_000u64);
        let candidate = SwapRoutePlan {
            router_name,
            router,
            path,
            amount_in,
            expected_out,
            min_out,
            sell_asset: sell_asset.clone(),
            buy_asset: buy_asset.clone(),
        };
        match &best {
            Some(current) if current.expected_out >= candidate.expected_out => {}
            _ => best = Some(candidate),
        }
    }

    best.ok_or_else(|| {
        ApiError::bad_request(format!(
            "No live V2 route found for {} -> {} on {}",
            sell_asset.symbol, buy_asset.symbol, chain.name
        ))
    })
}

async fn fetch_asset_market_price_usd(
    state: &AppState,
    chain: &'static ChainConfig,
    _runtime: &EvmRuntime,
    asset: &ResolvedAsset,
) -> Result<f64, ApiError> {
    if asset.is_native {
        return Ok(native_price_map(state, &[chain])
            .await?
            .get(chain.native_price_id.unwrap_or_default())
            .copied()
            .unwrap_or(0.0));
    }
    if let Some(coingecko_id) = asset.coingecko_id.clone() {
        if let Ok(payload) = coingecko_json(
            state,
            "/simple/price",
            &[
                ("ids", coingecko_id),
                ("vs_currencies", "usd".into()),
            ],
        )
        .await
        {
            let price = payload
                .as_object()
                .and_then(|object| object.values().next())
                .and_then(|value| value.get("usd"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if price > 0.0 {
                return Ok(price);
            }
        }
    }
    let address_price = token_price_map(state, chain, &[asset.address])
        .await?
        .get(&lower_hex_address(asset.address))
        .copied()
        .unwrap_or(0.0);
    if address_price > 0.0 {
        return Ok(address_price);
    }
    Ok(cryptocompare_price_map(state, &[asset.symbol.clone()])
        .await
        .ok()
        .and_then(|prices| prices.get(&asset.symbol.to_uppercase()).copied())
        .unwrap_or(0.0))
}

async fn fetch_explorer_entries(
    state: &AppState,
    chain_id: u64,
    action: &str,
    address: &str,
    extra: &[(&str, String)],
) -> Result<Vec<ExplorerTxEntry>, ApiError> {
    let Some(api_key) = state.etherscan_key.as_deref() else {
        return Ok(Vec::new());
    };
    let mut url = reqwest::Url::parse("https://api.etherscan.io/v2/api")
        .map_err(|err| ApiError::internal(format!("Explorer URL build failed: {err}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("chainid", &chain_id.to_string());
        query.append_pair("module", "account");
        query.append_pair("action", action);
        query.append_pair("address", address);
        query.append_pair("page", "1");
        query.append_pair("offset", "50");
        query.append_pair("sort", "desc");
        query.append_pair("apikey", api_key);
        for (key, value) in extra {
            query.append_pair(key, value);
        }
    }

    let response = state.http.get(url).send().await;
    let Ok(response) = response else {
        return Ok(Vec::new());
    };
    if !response.status().is_success() {
        return Ok(Vec::new());
    }
    let envelope = match response.json::<ExplorerEnvelope>().await {
        Ok(value) => value,
        Err(_) => return Ok(Vec::new()),
    };
    if envelope.status == "0"
        && envelope
            .result
            .as_str()
            .map(|msg| {
                msg.contains("No transactions found")
                    || msg.contains("No ERC20 transfers found")
                    || msg.contains("No NFT transfers found")
                    || msg.contains("API Pro")
            })
            .unwrap_or(false)
    {
        return Ok(Vec::new());
    }
    if envelope.status == "0" && !envelope.message.is_empty() && !envelope.result.is_array() {
        return Ok(Vec::new());
    }
    serde_json::from_value(envelope.result).map_err(|err| {
        ApiError::internal(format!("Explorer payload decode failed for {action}: {err}"))
    })
}

fn activity_type_from_explorer(entry: &ExplorerTxEntry, wallet: &str, fallback: &str) -> String {
    if !entry.token_id.is_empty() {
        if entry.from.eq_ignore_ascii_case(wallet) {
            "send".into()
        } else {
            "receive".into()
        }
    } else if !entry.token_symbol.is_empty() {
        if entry.from.eq_ignore_ascii_case(wallet) {
            "send".into()
        } else {
            "receive".into()
        }
    } else if !entry.method_id.is_empty() && entry.method_id != "0x" && entry.value == "0" {
        "swap".into()
    } else {
        fallback.into()
    }
}

fn activity_title_from_explorer(entry: &ExplorerTxEntry, wallet: &str) -> String {
    if !entry.token_id.is_empty() {
        let collection = if entry.token_name.is_empty() {
            "NFT"
        } else {
            entry.token_name.as_str()
        };
        if entry.from.eq_ignore_ascii_case(wallet) {
            return format!("Send {collection}");
        }
        return format!("Receive {collection}");
    }
    if !entry.token_symbol.is_empty() {
        if entry.from.eq_ignore_ascii_case(wallet) {
            return format!("Send {}", entry.token_symbol);
        }
        return format!("Receive {}", entry.token_symbol);
    }
    if !entry.method_id.is_empty() && entry.method_id != "0x" && entry.value == "0" {
        return "Swap".into();
    }
    if entry.from.eq_ignore_ascii_case(wallet) {
        "Send".into()
    } else {
        "Receive".into()
    }
}

fn explorer_status(entry: &ExplorerTxEntry) -> String {
    if entry.txreceipt_status == "0" || entry.is_error == "1" {
        "Failed".into()
    } else {
        "Completed".into()
    }
}

async fn fetch_evm_nfts(
    state: &AppState,
    chain: &'static ChainConfig,
    runtime: &EvmRuntime,
    wallet_address: Address,
) -> Result<Vec<NftResponse>, ApiError> {
    let transfers = fetch_explorer_entries(
        state,
        runtime.chain_id,
        "tokennfttx",
        &format!("{wallet_address:#x}"),
        &[],
    )
    .await?;
    if transfers.is_empty() {
        return Ok(Vec::new());
    }

    let mut latest_by_token: HashMap<(String, String), ExplorerTxEntry> = HashMap::new();
    for transfer in transfers {
        let key = (
            transfer.contract_address.to_lowercase(),
            transfer.token_id.to_lowercase(),
        );
        latest_by_token.entry(key).or_insert(transfer);
    }

    let mut out = Vec::new();
    for transfer in latest_by_token.values().take(24) {
        let Ok(contract_address) = Address::from_str(&transfer.contract_address) else {
            continue;
        };
        let Ok(token_id) = parse_u256_dec(&transfer.token_id, "tokenId") else {
            continue;
        };
        let contract = IERC721Metadata::new(contract_address, runtime.provider.clone());
        let Ok(owner) = contract.ownerOf(token_id).call().await else {
            continue;
        };
        if owner != wallet_address {
            continue;
        }

        let token_uri = contract.tokenURI(token_id).call().await.unwrap_or_default();
        let metadata_url = resolve_ipfs_url(&token_uri);
        let metadata: Option<Value> =
            if metadata_url.starts_with("http://") || metadata_url.starts_with("https://") {
                match state.http.get(metadata_url).send().await {
                    Ok(response) if response.status().is_success() => response.json::<Value>().await.ok(),
                    _ => None,
                }
            } else {
                None
            };
        let image = metadata
            .as_ref()
            .and_then(|json| json.get("image"))
            .and_then(Value::as_str)
            .map(resolve_ipfs_url)
            .unwrap_or_else(|| "https://placehold.co/600x600/111111/ffffff?text=NFT".into());
        let name = metadata
            .as_ref()
            .and_then(|json| json.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                if !transfer.token_name.is_empty() {
                    format!("{} #{}", transfer.token_name, transfer.token_id)
                } else {
                    format!("NFT #{}", transfer.token_id)
                }
            });
        let collection = if transfer.token_name.is_empty() {
            contract.name().call().await.unwrap_or_else(|_| "NFT Collection".into())
        } else {
            transfer.token_name.clone()
        };
        let external_url = metadata
            .as_ref()
            .and_then(|json| json.get("external_url"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| evm_nft_explorer_url(chain, contract_address, &transfer.token_id));

        out.push(NftResponse {
            id: format!(
                "{}:{}:{}",
                chain.key,
                transfer.contract_address.to_lowercase(),
                transfer.token_id
            ),
            chain_key: chain.key.into(),
            contract_address: format!("{contract_address:#x}"),
            token_id: transfer.token_id.clone(),
            collection,
            name,
            image,
            price: "Owned".into(),
            price_fiat: "".into(),
            external_url,
            explorer_url: evm_nft_explorer_url(chain, contract_address, &transfer.token_id),
        });
    }

    Ok(out)
}

async fn sync_activity_receipt(
    state: Arc<AppState>,
    chain_key: &'static str,
    hash: B256,
) {
    let Some(chain) = chain_by_key(chain_key) else {
        return;
    };
    let Ok(runtime) = get_evm_runtime(&state, chain).await else {
        return;
    };

    let timeout_ms = state.settings.receipt_timeout_ms.max(5_000);
    let poll_ms = state.settings.receipt_poll_ms.max(1_000);
    let started = std::time::Instant::now();
    let hash_hex = format!("{hash:#x}");

    while started.elapsed().as_millis() < timeout_ms as u128 {
        match runtime.provider.get_transaction_receipt(hash).await {
            Ok(Some(receipt)) => {
                let status = if receipt.status() {
                    "Completed"
                } else {
                    "Failed"
                };
                let _ = sqlx::query(
                    r#"
                    UPDATE wallet_backend_activity
                    SET status = ?
                    WHERE hash = ?
                    "#,
                )
                .bind(status)
                .bind(&hash_hex)
                .execute(&state.db)
                .await;
                return;
            }
            Ok(None) => {
                sleep(StdDuration::from_millis(poll_ms)).await;
            }
            Err(_) => {
                sleep(StdDuration::from_millis(poll_ms)).await;
            }
        }
    }
}

async fn insert_activity_row(
    state: &AppState,
    wallet_address: &str,
    chain: &'static ChainConfig,
    tx_type: &str,
    title: &str,
    amount: &str,
    fiat_amount: &str,
    asset: &str,
    address: &str,
    hash: &str,
    to: &str,
    fee: &str,
    status: &str,
    is_protected: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO wallet_backend_activity (
            id,
            wallet_address,
            chain_key,
            tx_type,
            title,
            amount,
            fiat_amount,
            asset,
            address,
            hash,
            from_address,
            to_address,
            fee,
            network,
            status,
            is_protected,
            rebate,
            created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            amount = excluded.amount,
            fiat_amount = excluded.fiat_amount,
            fee = excluded.fee,
            status = excluded.status,
            is_protected = excluded.is_protected,
            created_at_ms = excluded.created_at_ms
        "#,
    )
    .bind(hash)
    .bind(wallet_address)
    .bind(chain.key)
    .bind(tx_type)
    .bind(title)
    .bind(amount)
    .bind(fiat_amount)
    .bind(asset)
    .bind(address)
    .bind(hash)
    .bind(wallet_address)
    .bind(to)
    .bind(fee)
    .bind(chain.name)
    .bind(status)
    .bind(if is_protected { 1i64 } else { 0i64 })
    .bind(Option::<String>::None)
    .bind(Utc::now().timestamp_millis())
    .execute(&state.db)
    .await
    .map_err(|err| ApiError::internal(format!("Activity insert failed: {err}")))?;
    Ok(())
}

async fn coingecko_json(
    state: &AppState,
    path: &str,
    params: &[(&str, String)],
) -> Result<Value, ApiError> {
    async fn send_request(
        state: &AppState,
        base: &str,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<reqwest::Response, ApiError> {
        let mut url = reqwest::Url::parse(&format!("{base}{path}"))
            .map_err(|err| ApiError::internal(format!("CoinGecko URL build failed: {err}")))?;
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in params {
                query.append_pair(key, value);
            }
        }
        let mut request = state.http.get(url);
        request = request.header("User-Agent", "OxidityWallet/1.0 (+https://oxidity.io)");
        if let Some(key) = &state.coingecko_key {
            request = request.header("x-cg-pro-api-key", key);
        }
        request
            .send()
            .await
            .map_err(|err| ApiError::internal(format!("CoinGecko request failed: {err}")))
    }

    let response = send_request(state, &state.coingecko_base, path, params).await?;
    let status = response.status();
    if status.is_success() {
        return response
            .json::<Value>()
            .await
            .map_err(|err| ApiError::internal(format!("CoinGecko decode failed: {err}")));
    }

    let body = response.text().await.unwrap_or_default();
    if state.coingecko_base.contains("pro-api.coingecko.com")
        && body.contains("Demo API key")
    {
        let fallback = send_request(state, "https://api.coingecko.com/api/v3", path, params).await?;
        let fallback_status = fallback.status();
        if fallback_status.is_success() {
            return fallback
                .json::<Value>()
                .await
                .map_err(|err| ApiError::internal(format!("CoinGecko decode failed: {err}")));
        }
        let fallback_body = fallback.text().await.unwrap_or_default();
        return Err(ApiError::internal(format!(
            "CoinGecko fallback request failed with {}: {}",
            fallback_status, fallback_body
        )));
    }

    Err(ApiError::internal(format!(
        "CoinGecko request failed with {}: {}",
        status, body
    )))
}

async fn native_price_map(
    state: &AppState,
    chains: &[&'static ChainConfig],
) -> Result<BTreeMap<String, f64>, ApiError> {
    let ids: BTreeSet<&str> = chains
        .iter()
        .filter_map(|chain| chain.native_price_id)
        .collect();
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut map = BTreeMap::new();
    if let Ok(payload) = coingecko_json(
        state,
        "/simple/price",
        &[
            ("ids", ids.into_iter().collect::<Vec<_>>().join(",")),
            ("vs_currencies", "usd".into()),
        ],
    )
    .await
    {
        if let Some(object) = payload.as_object() {
            for (id, value) in object {
                if let Some(price) = value.get("usd").and_then(Value::as_f64) {
                    map.insert(id.clone(), price);
                }
            }
        }
    }

    let fallback_symbols = chains
        .iter()
        .map(|chain| chain.native_symbol.to_string())
        .collect::<Vec<_>>();
    let fallback_prices = cryptocompare_price_map(state, &fallback_symbols)
        .await
        .unwrap_or_default();
    for chain in chains {
        if let Some(price_id) = chain.native_price_id
            && !map.contains_key(price_id)
            && let Some(price) = fallback_prices.get(&chain.native_symbol.to_uppercase())
        {
            map.insert(price_id.to_string(), *price);
        }
    }
    Ok(map)
}

async fn token_price_map(
    state: &AppState,
    chain: &'static ChainConfig,
    addresses: &[Address],
) -> Result<BTreeMap<String, f64>, ApiError> {
    if chain.coingecko_platform.is_none() || addresses.is_empty() {
        return Ok(BTreeMap::new());
    }
    let payload = match coingecko_json(
        state,
        &format!(
            "/simple/token_price/{}",
            chain.coingecko_platform.expect("checked above")
        ),
        &[
            (
                "contract_addresses",
                addresses
                    .iter()
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("vs_currencies", "usd".into()),
        ],
    )
    .await
    {
        Ok(payload) => payload,
        Err(_) => return Ok(BTreeMap::new()),
    };

    let mut map = BTreeMap::new();
    if let Some(object) = payload.as_object() {
        for (address, value) in object {
            if let Some(price) = value.get("usd").and_then(Value::as_f64) {
                map.insert(address.to_lowercase(), price);
            }
        }
    }
    Ok(map)
}

async fn chain_health(state: &AppState, chain: &'static ChainConfig) -> NetworkHealth {
    let protocol = match chain.protocol {
        ChainProtocol::Evm => "evm",
        ChainProtocol::Solana => "solana",
        ChainProtocol::Sui => "sui",
        ChainProtocol::Bitcoin => "bitcoin",
        ChainProtocol::Cosmos => "cosmos",
        ChainProtocol::AvalancheP => "avalanche-p",
        ChainProtocol::AvalancheX => "avalanche-x",
    };

    match chain.protocol {
        ChainProtocol::Evm => match get_evm_provider(state, chain).await {
            Ok(provider) => {
                let chain_id = provider.get_chain_id().await.ok();
                let block_number = provider.get_block_number().await.ok();
                NetworkHealth {
                    key: chain.key.into(),
                    name: chain.name.into(),
                    protocol: protocol.into(),
                    status: if chain_id.is_some() && block_number.is_some() {
                        "online".into()
                    } else {
                        "degraded".into()
                    },
                    chain_id,
                    block_number,
                    detail: None,
                }
            }
            Err(err) => NetworkHealth {
                key: chain.key.into(),
                name: chain.name.into(),
                protocol: protocol.into(),
                status: "degraded".into(),
                chain_id: None,
                block_number: None,
                detail: Some(err.message),
            },
        },
        ChainProtocol::Solana => {
            let detail = if let Some(url) = chain.http_rpc {
                rpc_with_result::<String>(
                    state,
                    url,
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getHealth",
                    }),
                )
                .await
                .ok()
            } else {
                None
            };
            NetworkHealth {
                key: chain.key.into(),
                name: chain.name.into(),
                protocol: protocol.into(),
                status: if detail.is_some() { "online".into() } else { "degraded".into() },
                chain_id: None,
                block_number: None,
                detail,
            }
        }
        ChainProtocol::Sui => {
            let detail = if let Some(url) = chain.http_rpc {
                state
                    .http
                    .post(url)
                    .json(&json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "sui_getLatestCheckpointSequenceNumber",
                        "params": [],
                    }))
                    .send()
                    .await
                    .ok()
                    .map(|response| response.status().to_string())
            } else {
                None
            };
            NetworkHealth {
                key: chain.key.into(),
                name: chain.name.into(),
                protocol: protocol.into(),
                status: if detail.is_some() { "online".into() } else { "degraded".into() },
                chain_id: None,
                block_number: None,
                detail,
            }
        }
        ChainProtocol::Bitcoin => {
            let detail = if let Some(url) = chain.http_rpc {
                state
                    .http
                    .post(url)
                    .json(&json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getblockcount",
                        "params": [],
                    }))
                    .send()
                    .await
                    .ok()
                    .map(|response| response.status().to_string())
            } else {
                None
            };
            NetworkHealth {
                key: chain.key.into(),
                name: chain.name.into(),
                protocol: protocol.into(),
                status: if detail.is_some() { "online".into() } else { "degraded".into() },
                chain_id: None,
                block_number: None,
                detail,
            }
        }
        _ => NetworkHealth {
            key: chain.key.into(),
            name: chain.name.into(),
            protocol: protocol.into(),
            status: "configured".into(),
            chain_id: None,
            block_number: None,
            detail: None,
        },
    }
}

async fn wallet_insights(state: &AppState, wallet_address: &str) -> Result<Value, ApiError> {
    let records = load_activity_rows(state, wallet_address, None).await?;

    let protected_count = records.iter().filter(|row| row.is_protected == 1).count();
    let rebates_usd: f64 = records
        .iter()
        .map(|row| row.rebate.as_deref().unwrap_or("0"))
        .map(as_f64)
        .sum();
    let gas_saved_usd = 0.0;
    let private_routing_pct = if records.is_empty() {
        0.0
    } else {
        (protected_count as f64 / records.len() as f64) * 100.0
    };

    Ok(json!({
        "protectedTxCount": protected_count,
        "rebatesUsd": rebates_usd,
        "gasSavedUsd": gas_saved_usd,
        "totalSavedUsd": rebates_usd + gas_saved_usd,
        "privateRoutingPct": private_routing_pct,
    }))
}

fn relative_activity_date(timestamp_ms: i64) -> String {
    let dt_utc: DateTime<Utc> = DateTime::from_timestamp_millis(timestamp_ms).unwrap_or_else(Utc::now);
    let dt_local = dt_utc.with_timezone(&Local);
    let now = Local::now();
    let diff = now - dt_local;
    if diff < Duration::days(1) {
        return format!("Today, {}", dt_local.format("%-I:%M %p"));
    }
    if diff < Duration::days(2) {
        return format!("Yesterday, {}", dt_local.format("%-I:%M %p"));
    }
    dt_local.format("%b %-d, %-I:%M %p").to_string()
}

async fn api_health() -> Json<Value> {
    Json(json!({
        "ok": true,
        "service": "oxidity-wallet-backend",
        "timestamp": Utc::now().to_rfc3339(),
    }))
}

async fn api_bootstrap(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BootstrapResponse>, ApiError> {
    let mut supported_networks = Vec::new();
    for chain in CHAIN_CONFIGS {
        supported_networks.push(chain_health(&state, chain).await);
    }

    Ok(Json(BootstrapResponse {
        app_name: "Oxidity Wallet".into(),
        version: "1.0.0".into(),
        wallet_app_url: "https://wallet.oxidity.io/".into(),
        downloads: DownloadLinks {
            chrome_extension: "https://oxidity.io/downloads/oxidity-wallet-extension.zip".into(),
            android_apk: "https://oxidity.io/downloads/oxidity-wallet-debug.apk".into(),
        },
        supported_networks,
        defaults: json!({
            "chainKey": DEFAULT_CHAIN_KEY,
            "features": ["wallet", "portfolio", "activity", "quotes", "ai", "extension", "android"]
        }),
    }))
}

async fn api_networks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NetworkHealth>>, ApiError> {
    let mut networks = Vec::new();
    for chain in CHAIN_CONFIGS {
        networks.push(chain_health(&state, chain).await);
    }
    Ok(Json(networks))
}

async fn api_catalog(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!(
        CHAIN_CONFIGS
            .iter()
            .filter(|chain| chain.protocol == ChainProtocol::Evm)
            .map(|chain| {
                let tokens = evm_chain_id_hint(chain)
                    .map(|chain_id| catalog_tokens_for_chain(&state, chain_id))
                    .filter(|tokens| !tokens.is_empty())
                    .unwrap_or_else(|| {
                        chain
                            .token_catalog
                            .iter()
                            .map(|token| CatalogToken {
                                symbol: token.symbol.into(),
                                name: token.name.into(),
                                address: token.address.into(),
                                decimals: 18,
                                logo: token.logo.map(str::to_string),
                                coingecko_id: None,
                                is_native: false,
                            })
                            .collect::<Vec<_>>()
                    });
                json!({
                    "chainKey": chain.key,
                    "name": chain.name,
                    "nativeSymbol": chain.native_symbol,
                    "tokens": tokens.iter().map(|token| {
                        json!({
                            "symbol": token.symbol,
                            "name": token.name,
                            "address": token.address,
                            "logo": token.logo,
                        })
                    }).collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
    ))
}

async fn api_portfolio(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PortfolioRequest>,
) -> Result<Json<PortfolioResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    if chain.protocol == ChainProtocol::Solana {
        let wallet_address = parse_wallet_identifier(chain, &payload.address, "wallet")?;
        let lamports = solana_balance_lamports(&state, chain, &wallet_address).await?;
        let native_balance = lamports as f64 / 1_000_000_000.0;
        let native_usd = native_price_map(&state, &[chain])
            .await?
            .get(chain.native_price_id.unwrap_or_default())
            .copied()
            .unwrap_or(0.0);
        let native_fiat = native_balance * native_usd;
        let insights = wallet_insights(&state, &wallet_address).await?;

        return Ok(Json(PortfolioResponse {
            network: json!({
                "key": chain.key,
                "name": chain.name,
                "chainId": 0,
                "nativeSymbol": chain.native_symbol,
                "explorerTxBaseUrl": chain.explorer_tx_base_url.unwrap_or(""),
            }),
            account: json!({
                "address": wallet_address,
                "nativeBalance": native_balance,
                "fiatBalance": native_fiat,
            }),
            native_asset: NativeAssetResponse {
                id: format!("{}:native", chain.key),
                chain_key: chain.key.into(),
                symbol: chain.native_symbol.into(),
                name: chain.name.into(),
                address: wallet_address.clone(),
                balance: format_f64(native_balance, 6),
                raw_balance: native_balance,
                fiat_balance: format_usd(native_fiat),
                fiat_value: native_fiat,
                receive_address: wallet_address.clone(),
                logo: logo_for_symbol(chain.native_symbol).map(str::to_string),
                is_native: true,
            },
            tokens: Vec::new(),
            nfts: Vec::new(),
            insights,
        }));
    }
    if chain.protocol != ChainProtocol::Evm {
        return Err(ApiError::bad_request(format!(
            "{} portfolio support is not yet wired into the current wallet UI",
            chain.name
        )));
    }
    let wallet_address = parse_address(&payload.address, "wallet")?;
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();

    let chains = [chain];
    let (chain_id, native_balance_wei, native_prices) = tokio::join!(
        async { Ok::<u64, ApiError>(runtime.chain_id) },
        provider.get_balance(wallet_address),
        native_price_map(&state, &chains),
    );
    let chain_id = chain_id?;
    let native_balance_wei =
        native_balance_wei.map_err(|err| ApiError::internal(format!("Native balance read failed: {err}")))?;
    let native_prices = native_prices?;

    let native_balance = as_f64(&format_ether(native_balance_wei));
    let native_usd = chain
        .native_price_id
        .and_then(|id| native_prices.get(id))
        .map(|value| *value)
        .unwrap_or(0.0);
    let native_fiat = native_balance * native_usd;

    let mut tracked: BTreeMap<Address, CustomTokenInput> = BTreeMap::new();
    for token in chain.token_catalog {
        if let Ok(address) = Address::from_str(token.address) {
            tracked.insert(
                address,
                CustomTokenInput {
                    address: token.address.into(),
                    symbol: Some(token.symbol.into()),
                    name: Some(token.name.into()),
                    logo: token.logo.map(str::to_string),
                },
            );
        }
    }
    for token in payload.custom_tokens {
        if let Ok(address) = Address::from_str(&token.address) {
            tracked.insert(address, token);
        }
    }

    let tracked_addresses: Vec<Address> = tracked.keys().copied().collect();
    let token_prices = token_price_map(&state, chain, &tracked_addresses).await?;
    let fallback_symbol_prices = cryptocompare_price_map(
        &state,
        &tracked
            .values()
            .filter_map(|token| token.symbol.clone())
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap_or_default();
    let mut tokens = Vec::new();
    let mut total_fiat = native_fiat;

    for token_address in tracked_addresses {
        let metadata = tracked.get(&token_address).cloned().unwrap_or(CustomTokenInput {
            address: format!("{token_address:#x}"),
            symbol: None,
            name: None,
            logo: None,
        });
        let contract = IERC20::new(token_address, provider.clone());
        let balance_call = contract.balanceOf(wallet_address).call().await;
        let symbol_call = contract.symbol().call().await;
        let name_call = contract.name().call().await;
        let decimals_call = contract.decimals().call().await;
        let (balance, symbol, name, decimals) = match (balance_call, symbol_call, name_call, decimals_call) {
            (Ok(balance), Ok(symbol), Ok(name), Ok(decimals)) => (
                balance,
                symbol,
                name,
                decimals,
            ),
            _ => continue,
        };
        let balance_string = format_units(balance, decimals)
            .unwrap_or_else(|_| "0".into());
        let raw_balance = as_f64(&balance_string);
        let resolved_symbol = metadata.symbol.clone().unwrap_or_else(|| symbol.clone());
        let usd_price = token_prices
            .get(&format!("{token_address:#x}").to_lowercase())
            .copied()
            .or_else(|| fallback_symbol_prices.get(&resolved_symbol.to_uppercase()).copied())
            .unwrap_or(0.0);
        let fiat_value = raw_balance * usd_price;
        if raw_balance <= 0.0 && metadata.symbol.is_none() && metadata.name.is_none() {
            continue;
        }
        total_fiat += fiat_value;
        tokens.push(TokenResponse {
            id: format!("{}:{}", chain.key, format!("{token_address:#x}").to_lowercase()),
            chain_key: chain.key.into(),
            symbol: resolved_symbol,
            name: metadata.name.unwrap_or(name),
            address: format!("{token_address:#x}"),
            decimals,
            balance: format_f64(raw_balance, 6),
            raw_balance,
            fiat_balance: format_usd(fiat_value),
            fiat_value,
            receive_address: format!("{wallet_address:#x}"),
            logo: metadata.logo,
            is_native: false,
            is_custom: true,
        });
    }

    let insights = wallet_insights(&state, &format!("{wallet_address:#x}")).await?;
    let nfts = fetch_evm_nfts(&state, chain, &runtime, wallet_address).await?;

    Ok(Json(PortfolioResponse {
        network: json!({
            "key": chain.key,
            "name": chain.name,
            "chainId": chain_id,
            "nativeSymbol": chain.native_symbol,
            "explorerTxBaseUrl": chain.explorer_tx_base_url.unwrap_or(""),
        }),
        account: json!({
            "address": format!("{wallet_address:#x}"),
            "nativeBalance": native_balance,
            "fiatBalance": total_fiat,
        }),
        native_asset: NativeAssetResponse {
            id: format!("{}:native", chain.key),
            chain_key: chain.key.into(),
            symbol: chain.native_symbol.into(),
            name: chain.name.into(),
            address: format!("{wallet_address:#x}"),
            balance: format_f64(native_balance, 6),
            raw_balance: native_balance,
            fiat_balance: format_usd(native_fiat),
            fiat_value: native_fiat,
            receive_address: format!("{wallet_address:#x}"),
            logo: logo_for_symbol(chain.native_symbol).map(str::to_string),
            is_native: true,
        },
        tokens,
        nfts,
        insights,
    }))
}

async fn api_resolve_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResolveTokenRequest>,
) -> Result<Json<Value>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let token_address = parse_address(&payload.address, "token")?;
    let wallet_address = payload
        .wallet_address
        .as_deref()
        .map(|value| parse_address(value, "wallet"))
        .transpose()?;
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();
    let contract = IERC20::new(token_address, provider.clone());
    let balance = if let Some(wallet_address) = wallet_address {
        contract
            .balanceOf(wallet_address)
            .call()
            .await
            .map_err(|err| ApiError::internal(format!("Token balance read failed: {err}")))?
    } else {
        U256::ZERO
    };
    let symbol = contract
        .symbol()
        .call()
        .await
        .map_err(|err| ApiError::internal(format!("Token symbol read failed: {err}")))?;
    let name = contract
        .name()
        .call()
        .await
        .map_err(|err| ApiError::internal(format!("Token name read failed: {err}")))?;
    let decimals = contract
        .decimals()
        .call()
        .await
        .map_err(|err| ApiError::internal(format!("Token decimals read failed: {err}")))?;
    let prices = token_price_map(&state, chain, &[token_address]).await?;
    let balance_string = format_units(balance, decimals).unwrap_or_else(|_| "0".into());
    let raw_balance = as_f64(&balance_string);
    let logo =
        lookup_catalog_token_by_address(&state, runtime.chain_id, &token_address).and_then(|token| token.logo);
    let fiat_value = raw_balance
        * prices
            .get(&format!("{token_address:#x}").to_lowercase())
            .copied()
            .unwrap_or(0.0);

    Ok(Json(json!({
        "id": format!("{}:{}", chain.key, format!("{token_address:#x}").to_lowercase()),
        "chainKey": chain.key,
        "symbol": symbol,
        "name": name,
        "address": format!("{token_address:#x}"),
        "decimals": decimals,
        "balance": format_f64(raw_balance, 6),
        "rawBalance": raw_balance,
        "fiatBalance": format_usd(fiat_value),
        "fiatValue": fiat_value,
        "logo": logo,
    })))
}

async fn api_quote_preview(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<QuotePreviewRequest>,
) -> Result<Json<QuotePreviewResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let sell_token = normalize_symbol(payload.sell_token.as_deref());
    let buy_token = normalize_symbol(payload.buy_token.as_deref());
    let sell_token = if sell_token.is_empty() {
        chain.native_symbol.to_string()
    } else {
        sell_token
    };
    let buy_token = if buy_token.is_empty() { "USDC".into() } else { buy_token };
    let sell_amount = as_f64(&payload.sell_amount);
    if sell_amount <= 0.0 {
        return Err(ApiError::bad_request("sellAmount must be greater than zero"));
    }

    if chain.protocol == ChainProtocol::Evm {
        let runtime = get_evm_runtime(&state, chain).await?;
        let plan = build_swap_route_plan(
            &state,
            chain,
            Some(&sell_token),
            Some(&buy_token),
            &payload.sell_amount,
            100,
        )
        .await?;
        let sell_price = fetch_asset_market_price_usd(&state, chain, &runtime, &plan.sell_asset).await?;
        let buy_price = fetch_asset_market_price_usd(&state, chain, &runtime, &plan.buy_asset).await?;
        let estimated_gas_native = 0.0016;
        let estimated_gas_usd = estimated_gas_native
            * native_price_map(&state, &[chain])
                .await?
                .get(chain.native_price_id.unwrap_or_default())
                .copied()
                .unwrap_or(0.0);
        let receive_amount = u256_to_f64_units(plan.expected_out, plan.buy_asset.decimals);

        return Ok(Json(QuotePreviewResponse {
            chain_key: chain.key.into(),
            sell_token: plan.sell_asset.symbol.clone(),
            buy_token: plan.buy_asset.symbol.clone(),
            sell_amount,
            receive_amount,
            rate: if sell_amount > 0.0 { receive_amount / sell_amount } else { 0.0 },
            sell_usd_value: sell_amount * sell_price,
            receive_usd_value: receive_amount * buy_price,
            estimated_gas_usd,
            estimated_gas_native,
            speed_options: json!({
                "slow": { "label": "slow", "eta": "< 5 min", "gasUsd": estimated_gas_usd * 0.90 },
                "standard": { "label": "standard", "eta": "< 2 min", "gasUsd": estimated_gas_usd },
                "fast": { "label": "fast", "eta": "< 30 sec", "gasUsd": estimated_gas_usd * 1.25 },
            }),
            execution_mode: execution_mode_label(&runtime),
        }));
    }

    let ids: BTreeMap<&str, &str> = BTreeMap::from([
        ("ETH", "ethereum"),
        ("USDC", "usd-coin"),
        ("USDT", "tether"),
        ("BTC", "bitcoin"),
        ("WBTC", "wrapped-bitcoin"),
        ("LINK", "chainlink"),
        ("UNI", "uniswap"),
        ("AAVE", "aave"),
        ("BNB", "binancecoin"),
        ("SOL", "solana"),
        ("AVAX", "avalanche-2"),
        ("SUI", "sui"),
        ("ATOM", "cosmos"),
    ]);
    let sell_id = ids
        .get(sell_token.as_str())
        .ok_or_else(|| ApiError::bad_request("Quote preview only supports known assets right now"))?;
    let buy_id = ids
        .get(buy_token.as_str())
        .ok_or_else(|| ApiError::bad_request("Quote preview only supports known assets right now"))?;
    let price_payload = coingecko_json(
        &state,
        "/simple/price",
        &[
            ("ids", format!("{sell_id},{buy_id}")),
            ("vs_currencies", "usd".into()),
        ],
    )
    .await?;
    let sell_price = price_payload
        .get(*sell_id)
        .and_then(|value| value.get("usd"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let buy_price = price_payload
        .get(*buy_id)
        .and_then(|value| value.get("usd"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let receive_amount = if buy_price > 0.0 {
        (sell_amount * sell_price) / buy_price
    } else {
        0.0
    };

    Ok(Json(QuotePreviewResponse {
        chain_key: chain.key.into(),
        sell_token,
        buy_token,
        sell_amount,
        receive_amount,
        rate: if sell_price > 0.0 && buy_price > 0.0 {
            sell_price / buy_price
        } else {
            0.0
        },
        sell_usd_value: sell_amount * sell_price,
        receive_usd_value: receive_amount * buy_price,
        estimated_gas_usd: 0.0,
        estimated_gas_native: 0.0,
        speed_options: json!({
            "slow": { "label": "slow", "eta": "< 5 min", "gasUsd": 0.0 },
            "standard": { "label": "standard", "eta": "< 2 min", "gasUsd": 0.0 },
            "fast": { "label": "fast", "eta": "< 30 sec", "gasUsd": 0.0 },
        }),
        execution_mode: "direct".into(),
    }))
}

async fn api_swap_prepare(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SwapPrepareRequest>,
) -> Result<Json<SwapPrepareResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();
    let wallet_address = parse_address(&payload.wallet_address, "wallet")?;
    let plan = build_swap_route_plan(
        &state,
        chain,
        payload.sell_token.as_deref(),
        payload.buy_token.as_deref(),
        &payload.sell_amount,
        payload.slippage_bps.unwrap_or(100),
    )
    .await?;

    if !plan.sell_asset.is_native {
        let allowance = IERC20::new(plan.sell_asset.address, provider.clone())
            .allowance(wallet_address, plan.router)
            .call()
            .await
            .map_err(|err| ApiError::internal(format!("Allowance read failed: {err}")))?;
        if allowance < plan.amount_in {
            return Err(ApiError::bad_request(format!(
                "Approve {} for {} before swapping",
                plan.sell_asset.symbol, plan.router_name
            )));
        }
    }

    let calldata = runtime.reserve_cache.build_v2_swap_payload(
        plan.path.clone(),
        plan.amount_in,
        plan.min_out,
        wallet_address,
        false,
        runtime.wrapped_native,
    );
    let tx = TransactionRequest {
        from: Some(wallet_address),
        to: Some(TxKind::Call(plan.router)),
        value: Some(if plan.sell_asset.is_native {
            plan.amount_in
        } else {
            U256::ZERO
        }),
        input: TransactionInput::new(Bytes::from(calldata.clone())),
        chain_id: Some(runtime.chain_id),
        ..Default::default()
    };
    let chains = [chain];
    let (nonce, gas_limit, fees, native_prices) = tokio::join!(
        provider.get_transaction_count(wallet_address).pending(),
        provider.estimate_gas(tx.clone()),
        provider.estimate_eip1559_fees(),
        native_price_map(&state, &chains),
    );
    let nonce = nonce.map_err(|err| ApiError::internal(format!("Nonce read failed: {err}")))?;
    let gas_limit = gas_limit.unwrap_or(220_000);
    let fees = fees.map_err(|err| ApiError::internal(format!("Fee estimate failed: {err}")))?;
    let native_prices = native_prices?;
    let estimated_fee_wei = U256::from(fees.max_fee_per_gas) * U256::from(gas_limit);
    let estimated_fee_native = as_f64(&format_ether(estimated_fee_wei));
    let native_usd = chain
        .native_price_id
        .and_then(|id| native_prices.get(id))
        .copied()
        .unwrap_or(0.0);

    Ok(Json(SwapPrepareResponse {
        chain_key: chain.key.into(),
        chain_id: runtime.chain_id,
        network: chain.name.into(),
        router_name: plan.router_name,
        router: format!("{:#x}", plan.router),
        to: format!("{:#x}", plan.router),
        data: format!("0x{}", hex::encode(calldata)),
        value: if plan.sell_asset.is_native {
            plan.amount_in.to_string()
        } else {
            "0".into()
        },
        nonce,
        gas_limit: gas_limit.to_string(),
        max_fee_per_gas: fees.max_fee_per_gas.to_string(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.to_string(),
        expected_out: plan.expected_out.to_string(),
        min_out: plan.min_out.to_string(),
        expected_out_formatted: format_f64(
            u256_to_f64_units(plan.expected_out, plan.buy_asset.decimals),
            6,
        ),
        buy_symbol: plan.buy_asset.symbol,
        estimated_fee_native,
        estimated_fee_usd: estimated_fee_native * native_usd,
        explorer_tx_base_url: chain.explorer_tx_base_url.unwrap_or("").into(),
        execution_mode: execution_mode_label(&runtime),
    }))
}

async fn api_send_prepare(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendPrepareRequest>,
) -> Result<Json<SendPrepareResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    if chain.protocol == ChainProtocol::Solana {
        let _from = parse_wallet_identifier(chain, &payload.from, "from")?;
        let _to = parse_wallet_identifier(chain, &payload.to, "to")?;
        let amount = payload
            .amount
            .trim()
            .parse::<f64>()
            .map_err(|_| ApiError::bad_request("Invalid send amount"))?;
        if amount <= 0.0 {
            return Err(ApiError::bad_request("sendAmount must be greater than zero"));
        }

        let blockhash = solana_latest_blockhash(&state, chain).await?;
        let lamports_per_signature = 5_000u64;
        let estimated_fee_native = lamports_per_signature as f64 / 1_000_000_000.0;
        let native_usd = native_price_map(&state, &[chain])
            .await?
            .get(chain.native_price_id.unwrap_or_default())
            .copied()
            .unwrap_or(0.0);

        return Ok(Json(SendPrepareResponse {
            protocol: "solana".into(),
            chain_key: chain.key.into(),
            chain_id: 0,
            network: chain.name.into(),
            nonce: 0,
            gas_limit: "0".into(),
            max_fee_per_gas: "0".into(),
            max_priority_fee_per_gas: "0".into(),
            estimated_fee_native,
            estimated_fee_usd: estimated_fee_native * native_usd,
            explorer_tx_base_url: chain.explorer_tx_base_url.unwrap_or("").into(),
            execution_mode: "direct".into(),
            recent_blockhash: Some(blockhash.blockhash),
            last_valid_block_height: Some(blockhash.last_valid_block_height),
            lamports_per_signature: Some(lamports_per_signature),
        }));
    }
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();
    let from = parse_address(&payload.from, "from")?;
    let to = parse_address(&payload.to, "to")?;
    let value = parse_u256_eth(&payload.amount, "send")?;

    let tx = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        value: Some(value),
        chain_id: Some(runtime.chain_id),
        ..Default::default()
    };
    let chains = [chain];
    let (nonce, gas_limit, fees, native_prices) = tokio::join!(
        provider.get_transaction_count(from).pending(),
        provider.estimate_gas(tx.clone()),
        provider.estimate_eip1559_fees(),
        native_price_map(&state, &chains),
    );
    let nonce = nonce.map_err(|err| ApiError::internal(format!("Nonce read failed: {err}")))?;
    let gas_limit = gas_limit.map_err(|err| ApiError::internal(format!("Gas estimate failed: {err}")))?;
    let fees = fees.map_err(|err| ApiError::internal(format!("Fee estimate failed: {err}")))?;
    let native_prices = native_prices?;
    let estimated_fee_wei = U256::from(fees.max_fee_per_gas) * U256::from(gas_limit);
    let estimated_fee_native = as_f64(&format_ether(estimated_fee_wei));
    let native_usd = chain
        .native_price_id
        .and_then(|id| native_prices.get(id))
        .map(|value| *value)
        .unwrap_or(0.0);

    Ok(Json(SendPrepareResponse {
        protocol: "evm".into(),
        chain_key: chain.key.into(),
        chain_id: runtime.chain_id,
        network: chain.name.into(),
        nonce,
        gas_limit: gas_limit.to_string(),
        max_fee_per_gas: fees.max_fee_per_gas.to_string(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.to_string(),
        estimated_fee_native,
        estimated_fee_usd: estimated_fee_native * native_usd,
        explorer_tx_base_url: chain.explorer_tx_base_url.unwrap_or("").into(),
        execution_mode: execution_mode_label(&runtime),
        recent_blockhash: None,
        last_valid_block_height: None,
        lamports_per_signature: None,
    }))
}

async fn api_send_broadcast(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendBroadcastRequest>,
) -> Result<Json<SendBroadcastResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    if chain.protocol == ChainProtocol::Solana {
        let wallet_address = parse_wallet_identifier(chain, &payload.wallet_address, "wallet")?;
        let to_address = parse_wallet_identifier(chain, &payload.to, "to")?;
        let encoding = payload
            .encoding
            .as_deref()
            .unwrap_or("base64")
            .trim()
            .to_lowercase();
        let raw_transaction = payload.raw_transaction.trim();
        let signature: String = rpc_with_result(
            &state,
            solana_http_url(chain)?,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sendTransaction",
                "params": [
                    raw_transaction,
                    {
                        "encoding": encoding,
                        "preflightCommitment": "confirmed",
                        "skipPreflight": false,
                        "maxRetries": 5
                    }
                ],
            }),
        )
        .await?;

        insert_activity_row(
            &state,
            &wallet_address,
            chain,
            &payload.tx_type,
            &payload.title,
            &payload.amount,
            &payload.fiat_amount,
            &payload.asset,
            &to_address,
            &signature,
            &to_address,
            &payload.fee,
            "Pending",
            false,
        )
        .await?;

        return Ok(Json(SendBroadcastResponse {
            hash: signature.clone(),
            status: "pending".into(),
            explorer_url: tx_explorer_url(chain, &signature),
            execution_mode: "direct".into(),
        }));
    }
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();
    let wallet_address = parse_address(&payload.wallet_address, "wallet")?;
    let raw = hex::decode(payload.raw_transaction.trim_start_matches("0x"))
        .map_err(|_| ApiError::bad_request("Invalid raw transaction hex"))?;
    let hash = keccak256(&raw);
    let hash_hex = format!("{hash:#x}");
    let is_protected = runtime.protected_execution;
    if is_protected {
        runtime
            .bundle_sender
            .as_ref()
            .ok_or_else(|| ApiError::internal("Protected execution is enabled but relay sender is unavailable"))?
            .send_bundle(&[raw.clone()], runtime.chain_id)
            .await
            .map_err(ApiError::from_app)?;
    } else {
        let _ = provider
            .send_raw_transaction(raw.as_slice())
            .await
            .map_err(|err| ApiError::internal(format!("Raw transaction broadcast failed: {err}")))?;
    }

    insert_activity_row(
        &state,
        &format!("{wallet_address:#x}"),
        chain,
        &payload.tx_type,
        &payload.title,
        &payload.amount,
        &payload.fiat_amount,
        &payload.asset,
        &payload.to,
        &hash_hex,
        &payload.to,
        &payload.fee,
        "Pending",
        is_protected,
    )
    .await?;
    tokio::spawn(sync_activity_receipt(state.clone(), chain.key, hash));

    Ok(Json(SendBroadcastResponse {
        hash: hash_hex.clone(),
        status: "pending".into(),
        explorer_url: tx_explorer_url(chain, &hash_hex),
        execution_mode: if is_protected {
            "protected".into()
        } else {
            "direct".into()
        },
    }))
}

async fn api_activity(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ActivityRequest>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let wallet_identifier = parse_wallet_identifier(chain, &payload.address, "wallet")?;
    let rows = load_activity_rows(&state, &wallet_identifier, Some(chain.key)).await?;

    let mut activity_by_id: HashMap<String, Value> = rows
        .into_iter()
        .map(|row| {
            let id = row.id.clone();
            let fiat_amount = if row.fiat_amount.starts_with('$') {
                row.fiat_amount.clone()
            } else {
                format!("${}", row.fiat_amount)
            };
            let explorer_url = row.hash.as_ref().map(|hash| {
                tx_explorer_url(chain, hash)
            });
            (id, json!({
                "id": row.id,
                "type": row.tx_type,
                "title": row.title,
                "amount": row.amount,
                "fiatAmount": fiat_amount,
                "date": relative_activity_date(row.created_at_ms),
                "timestamp": row.created_at_ms,
                "asset": row.asset,
                "address": row.address,
                "isProtected": row.is_protected == 1,
                "rebate": row.rebate,
                "hash": row.hash,
                "from": row.from_address,
                "to": row.to_address,
                "fee": row.fee,
                "network": row.network,
                "status": row.status,
                "explorerUrl": explorer_url,
            }))
        })
        .collect();

    if chain.protocol == ChainProtocol::Solana {
        for entry in solana_signature_activity(&state, chain, &wallet_identifier).await? {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                activity_by_id.entry(id.to_string()).or_insert(entry);
            }
        }
    } else if chain.protocol == ChainProtocol::Evm {
        let wallet_hex = wallet_identifier.clone();
        let runtime = get_evm_runtime(&state, chain).await?;
        let (normal, erc20, nft) = tokio::join!(
            fetch_explorer_entries(&state, runtime.chain_id, "txlist", &wallet_hex, &[]),
            fetch_explorer_entries(&state, runtime.chain_id, "tokentx", &wallet_hex, &[]),
            fetch_explorer_entries(&state, runtime.chain_id, "tokennfttx", &wallet_hex, &[]),
        );
        let explorer_entries = normal?
            .into_iter()
            .chain(erc20?)
            .chain(nft?)
            .collect::<Vec<_>>();

        for entry in explorer_entries {
            if entry.hash.is_empty() {
                continue;
            }
            let id = if entry.token_id.is_empty() {
                entry.hash.clone()
            } else {
                format!(
                    "{}:{}:{}",
                    entry.hash,
                    entry.contract_address.to_lowercase(),
                    entry.token_id
                )
            };
            if activity_by_id.contains_key(&id) {
                continue;
            }
            let timestamp_ms = entry.time_stamp.parse::<i64>().unwrap_or_default() * 1000;
            let asset = if !entry.token_symbol.is_empty() {
                entry.token_symbol.clone()
            } else if !entry.token_id.is_empty() {
                "NFT".into()
            } else {
                chain.native_symbol.into()
            };
            let amount = if !entry.token_id.is_empty() {
                if entry.from.eq_ignore_ascii_case(&wallet_hex) {
                    format!("-1 {}", asset)
                } else {
                    format!("+1 {}", asset)
                }
            } else if !entry.token_symbol.is_empty() {
                let decimals = entry.token_decimal.parse::<u8>().unwrap_or(18);
                let value = parse_u256_dec(&entry.value, "tokenValue").unwrap_or(U256::ZERO);
                let rendered = format_f64(u256_to_f64_units(value, decimals), 6);
                if entry.from.eq_ignore_ascii_case(&wallet_hex) {
                    format!("-{} {}", rendered, asset)
                } else {
                    format!("+{} {}", rendered, asset)
                }
            } else {
                let value = parse_u256_dec(&entry.value, "value").unwrap_or(U256::ZERO);
                let rendered = format_f64(as_f64(&format_ether(value)), 6);
                if entry.from.eq_ignore_ascii_case(&wallet_hex) {
                    format!("-{} {}", rendered, asset)
                } else {
                    format!("+{} {}", rendered, asset)
                }
            };

            activity_by_id.insert(
                id.clone(),
                json!({
                    "id": id,
                    "type": activity_type_from_explorer(&entry, &wallet_hex, "send"),
                    "title": activity_title_from_explorer(&entry, &wallet_hex),
                    "amount": amount,
                    "fiatAmount": "$0.00",
                    "date": relative_activity_date(timestamp_ms),
                    "timestamp": timestamp_ms,
                    "asset": asset,
                    "address": if entry.from.eq_ignore_ascii_case(&wallet_hex) { entry.to.clone() } else { entry.from.clone() },
                    "isProtected": false,
                    "rebate": null,
                    "hash": entry.hash,
                    "from": entry.from,
                    "to": entry.to,
                    "fee": if !entry.gas_used.is_empty() && !entry.gas_price.is_empty() {
                        let gas_used = parse_u256_dec(&entry.gas_used, "gasUsed").unwrap_or(U256::ZERO);
                        let gas_price = parse_u256_dec(&entry.gas_price, "gasPrice").unwrap_or(U256::ZERO);
                        format!("${}", format_usd(as_f64(&format_ether(gas_used.saturating_mul(gas_price)))))
                    } else {
                        "$0.00".to_string()
                    },
                    "network": chain.name,
                    "status": explorer_status(&entry),
                    "explorerUrl": tx_explorer_url(chain, &entry.hash),
                }),
            );
        }
    }

    let mut activity = activity_by_id.into_values().collect::<Vec<_>>();
    activity.sort_by(|left, right| {
        right["timestamp"]
            .as_i64()
            .unwrap_or_default()
            .cmp(&left["timestamp"].as_i64().unwrap_or_default())
    });
    Ok(Json(activity))
}

async fn load_activity_rows(
    state: &AppState,
    wallet_address: &str,
    chain_key: Option<&str>,
) -> Result<Vec<ActivityRow>, ApiError> {
    let rows = if let Some(chain_key) = chain_key {
        sqlx::query(
            r#"
            SELECT
                id,
                wallet_address,
                chain_key,
                tx_type,
                title,
                amount,
                fiat_amount,
                asset,
                address,
                hash,
                from_address,
                to_address,
                fee,
                network,
                status,
                is_protected,
                rebate,
                created_at_ms
            FROM wallet_backend_activity
            WHERE lower(wallet_address) = lower(?)
              AND lower(chain_key) = lower(?)
            ORDER BY created_at_ms DESC
            LIMIT 200
            "#,
        )
        .bind(wallet_address)
        .bind(chain_key)
        .fetch_all(&state.db)
        .await
        .map_err(|err| ApiError::internal(format!("Activity query failed: {err}")))?
    } else {
        sqlx::query(
            r#"
            SELECT
                id,
                wallet_address,
                chain_key,
                tx_type,
                title,
                amount,
                fiat_amount,
                asset,
                address,
                hash,
                from_address,
                to_address,
                fee,
                network,
                status,
                is_protected,
                rebate,
                created_at_ms
            FROM wallet_backend_activity
            WHERE lower(wallet_address) = lower(?)
            ORDER BY created_at_ms DESC
            LIMIT 200
            "#,
        )
        .bind(wallet_address)
        .fetch_all(&state.db)
        .await
        .map_err(|err| ApiError::internal(format!("Activity query failed: {err}")))?
    };

    Ok(rows
        .into_iter()
        .map(|row| ActivityRow {
            id: row.get("id"),
            tx_type: row.get("tx_type"),
            title: row.get("title"),
            amount: row.get("amount"),
            fiat_amount: row.get("fiat_amount"),
            asset: row.get("asset"),
            address: row.get("address"),
            hash: row.get("hash"),
            from_address: row.get("from_address"),
            to_address: row.get("to_address"),
            fee: row.get("fee"),
            network: row.get("network"),
            status: row.get("status"),
            is_protected: row.get("is_protected"),
            rebate: row.get("rebate"),
            created_at_ms: row.get("created_at_ms"),
        })
        .collect())
}

async fn api_nft_send_prepare(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<NftSendPrepareRequest>,
) -> Result<Json<NftSendPrepareResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let runtime = get_evm_runtime(&state, chain).await?;
    let provider = runtime.provider.clone();
    let from = parse_address(&payload.from, "from")?;
    let to = parse_address(&payload.to, "to")?;
    let contract_address = parse_address(&payload.contract_address, "contract")?;
    let token_id = parse_u256_dec(&payload.token_id, "tokenId")?;
    let calldata = IERC721Metadata::safeTransferFromCall {
        from,
        to,
        tokenId: token_id,
    }
    .abi_encode();
    let tx = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(contract_address)),
        value: Some(U256::ZERO),
        input: TransactionInput::new(Bytes::from(calldata.clone())),
        chain_id: Some(runtime.chain_id),
        ..Default::default()
    };
    let chains = [chain];
    let (nonce, gas_limit, fees, native_prices) = tokio::join!(
        provider.get_transaction_count(from).pending(),
        provider.estimate_gas(tx.clone()),
        provider.estimate_eip1559_fees(),
        native_price_map(&state, &chains),
    );
    let nonce = nonce.map_err(|err| ApiError::internal(format!("Nonce read failed: {err}")))?;
    let gas_limit = gas_limit.unwrap_or(180_000);
    let fees = fees.map_err(|err| ApiError::internal(format!("Fee estimate failed: {err}")))?;
    let native_prices = native_prices?;
    let estimated_fee_wei = U256::from(fees.max_fee_per_gas) * U256::from(gas_limit);
    let estimated_fee_native = as_f64(&format_ether(estimated_fee_wei));
    let native_usd = chain
        .native_price_id
        .and_then(|id| native_prices.get(id))
        .copied()
        .unwrap_or(0.0);

    Ok(Json(NftSendPrepareResponse {
        chain_key: chain.key.into(),
        chain_id: runtime.chain_id,
        network: chain.name.into(),
        contract_address: format!("{contract_address:#x}"),
        token_id: payload.token_id,
        to: format!("{to:#x}"),
        data: format!("0x{}", hex::encode(calldata)),
        nonce,
        gas_limit: gas_limit.to_string(),
        max_fee_per_gas: fees.max_fee_per_gas.to_string(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.to_string(),
        estimated_fee_native,
        estimated_fee_usd: estimated_fee_native * native_usd,
        explorer_tx_base_url: chain.explorer_tx_base_url.unwrap_or("").into(),
        execution_mode: execution_mode_label(&runtime),
    }))
}

async fn api_onramp_quote(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<OnRampQuoteRequest>,
) -> Result<Json<OnRampQuoteResponse>, ApiError> {
    let chain = resolve_chain(payload.chain_key.as_deref())?;
    let amount_usd = as_f64(&payload.amount_usd);
    if amount_usd <= 0.0 {
        return Err(ApiError::bad_request("amountUsd must be greater than zero"));
    }

    let (buy_symbol, market_price_usd) = if chain.protocol == ChainProtocol::Evm {
        let runtime = get_evm_runtime(&state, chain).await?;
        let asset = resolve_asset_reference(
            &state,
            chain,
            &runtime,
            payload.buy_token.as_deref(),
            chain.native_symbol,
        )
        .await?;
        let price = fetch_asset_market_price_usd(&state, chain, &runtime, &asset).await?;
        (asset.symbol, price)
    } else {
        let price = native_price_map(&state, &[chain])
            .await?
            .get(chain.native_price_id.unwrap_or_default())
            .copied()
            .unwrap_or(0.0);
        let normalized = normalize_symbol(payload.buy_token.as_deref())
            .chars()
            .take(12)
            .collect::<String>();
        (
            if normalized.is_empty() {
                chain.native_symbol.to_string()
            } else {
                normalized
            },
            price,
        )
    };
    let market_price_usd = if market_price_usd > 0.0 {
        market_price_usd
    } else {
        return Err(ApiError::internal("Unable to price the selected asset"));
    };
    let receive_base = amount_usd / market_price_usd;
    let buy_code = buy_symbol.to_lowercase();
    let wallet_address = payload.wallet_address.trim();
    let providers = vec![
        OnRampProviderQuote {
            id: "ramp".into(),
            name: "Ramp".into(),
            rate: receive_base / amount_usd,
            fee: 2.49,
            delivery_time: "1-5 mins".into(),
            trust_score: 95,
            receive_amount: receive_base * 0.9751,
            checkout_url: format!(
                "https://buy.ramp.network/?swapAsset={buy_code}&fiatCurrency=USD&fiatValue={amount_usd:.2}&userAddress={wallet_address}"
            ),
        },
        OnRampProviderQuote {
            id: "moonpay".into(),
            name: "MoonPay".into(),
            rate: receive_base / amount_usd,
            fee: 3.49,
            delivery_time: "2-10 mins".into(),
            trust_score: 92,
            receive_amount: receive_base * 0.9651,
            checkout_url: format!(
                "https://buy.moonpay.com/?currencyCode={buy_code}&baseCurrencyCode=usd&baseCurrencyAmount={amount_usd:.2}&walletAddress={wallet_address}"
            ),
        },
        OnRampProviderQuote {
            id: "binance".into(),
            name: "Binance".into(),
            rate: receive_base / amount_usd,
            fee: 1.80,
            delivery_time: "Instant".into(),
            trust_score: 90,
            receive_amount: receive_base * 0.982,
            checkout_url: format!(
                "https://www.binance.com/en/buy-sell-crypto?fiat=USD&crypto={buy_code}&amount={amount_usd:.2}"
            ),
        },
    ];

    Ok(Json(OnRampQuoteResponse {
        chain_key: chain.key.into(),
        amount_usd,
        buy_token: buy_symbol,
        market_price_usd,
        providers,
    }))
}

async fn api_ai_chat(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AiChatRequest>,
) -> Result<Json<AiChatResponse>, ApiError> {
    let prompt = payload.message.trim();
    if prompt.is_empty() {
        return Err(ApiError::bad_request("message is required"));
    }

    if prompt.to_lowercase().contains("oxidity") || prompt.to_lowercase().contains("gas") {
        return Ok(Json(AiChatResponse {
            content: "Based on my findings thru 2 sites searched, OXIDITY is a HOLD on hype and a BUY on basics. I'm predicting stability within the next days because the actual value is wallet execution quality, private routing, and lower leakage rather than token noise. Short disclaimer: verify on-chain.".into(),
            sources: vec![
                AiSource { uri: "https://oxidity.io/".into(), title: "Oxidity".into() },
                AiSource { uri: "https://wallet.oxidity.io/".into(), title: "Oxidity Wallet".into() },
            ],
        }));
    }

    let lookup = prompt.to_lowercase();
    let known: BTreeMap<&str, (&str, &str, &str)> = BTreeMap::from([
        ("eth", ("ethereum", "ETH", "Ethereum")),
        ("ethereum", ("ethereum", "ETH", "Ethereum")),
        ("btc", ("bitcoin", "BTC", "Bitcoin")),
        ("bitcoin", ("bitcoin", "BTC", "Bitcoin")),
        ("sol", ("solana", "SOL", "Solana")),
        ("solana", ("solana", "SOL", "Solana")),
        ("sui", ("sui", "SUI", "Sui")),
        ("usdc", ("usd-coin", "USDC", "USD Coin")),
        ("link", ("chainlink", "LINK", "Chainlink")),
        ("uni", ("uniswap", "UNI", "Uniswap")),
        ("aave", ("aave", "AAVE", "Aave")),
        ("atom", ("cosmos", "ATOM", "Cosmos")),
    ]);

    let asset = if let Some(asset) = known.get(lookup.as_str()) {
        (asset.0.to_string(), asset.1.to_string(), asset.2.to_string())
    } else {
        let search = coingecko_json(
            &state,
            "/search",
            &[("query", prompt.to_string())],
        )
        .await?;
        let first = search
            .get("coins")
            .and_then(Value::as_array)
            .and_then(|coins| coins.first())
            .cloned()
            .ok_or_else(|| ApiError::bad_request("Could not map that prompt to a market asset"))?;
        (
            first.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
            first.get("symbol").and_then(Value::as_str).unwrap_or_default().to_uppercase(),
            first.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        )
    };

    let market = coingecko_json(
        &state,
        "/coins/markets",
        &[
            ("vs_currency", "usd".into()),
            ("ids", asset.0.clone()),
            ("price_change_percentage", "24h,7d".into()),
        ],
    )
    .await?;
    let trending = coingecko_json(&state, "/search/trending", &[]).await?;
    let first = market
        .as_array()
        .and_then(|items| items.first())
        .cloned()
        .ok_or_else(|| ApiError::internal("CoinGecko returned no market data"))?;
    let current_price = first.get("current_price").and_then(Value::as_f64).unwrap_or(0.0);
    let pc24 = first
        .get("price_change_percentage_24h")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let pc7d = first
        .get("price_change_percentage_7d_in_currency")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let rank = first.get("market_cap_rank").and_then(Value::as_i64).unwrap_or(0);
    let trending_now = trending
        .get("coins")
        .and_then(Value::as_array)
        .map(|coins| {
            coins.iter().any(|coin| {
                coin.get("item")
                    .and_then(|item| item.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    == asset.0
            })
        })
        .unwrap_or(false);

    let (stance, prediction, reason) = if pc24 > 4.0 && pc7d > 8.0 {
        (
            "BUY",
            "rise",
            format!(
                "24h={:.2}% and 7d={:.2}% are both strong{}",
                pc24,
                pc7d,
                if trending_now { ", and it is currently trending" } else { "" }
            ),
        )
    } else if pc24 < -4.0 && pc7d < -8.0 {
        (
            "SELL",
            "fall",
            format!("24h={:.2}% and 7d={:.2}% are both weak", pc24, pc7d),
        )
    } else if pc24.abs() < 2.0 && pc7d.abs() < 5.0 {
        (
            "HOLD",
            "stability",
            format!("24h={:.2}% and 7d={:.2}% are both muted", pc24, pc7d),
        )
    } else {
        (
            "MEEEEH",
            if pc24 >= 0.0 { "rise" } else { "fall" },
            format!("the signal is mixed at 24h={:.2}% and 7d={:.2}%", pc24, pc7d),
        )
    };
    let magnitude = pc24.abs().max(pc7d.abs() / 2.0).max(2.0);
    let content = format!(
        "Based on my findings thru 2 sites searched, {} is a {}! I'm predicting {:.1}% {} within the next days because of {}. Spot is ${:.4} and market cap rank is #{}. Short disclaimer: not financial advice.",
        asset.1, stance, magnitude, prediction, reason, current_price, rank
    );

    Ok(Json(AiChatResponse {
        content,
        sources: vec![
            AiSource {
                uri: format!("https://www.coingecko.com/en/coins/{}", asset.0),
                title: format!("{} on CoinGecko", asset.2),
            },
            AiSource {
                uri: "https://www.coingecko.com/en/highlights/trending-crypto".into(),
                title: "Trending Crypto".into(),
            },
        ],
    }))
}
