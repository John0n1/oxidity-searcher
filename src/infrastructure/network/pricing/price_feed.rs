// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::sol;
use reqwest::Client;
use reqwest::header;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: u64 = 60; // Cache prices for 60 seconds
const CHAINLINK_STALENESS_SECS: u64 = 600;
const CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_ETH: u64 = 3_600;
const CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_BTC: u64 = 3_600;
const CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_STABLE: u64 = 86_400;
const STALE_CACHE_GRACE_SECS: u64 = 900; // Accept up to 15m old cache on failures
const PROVIDER_WINDOW_SECS: u64 = 60; // per-provider RPM window
const SOURCE_CRYPTOCOMPARE: &str = "cryptocompare";
const SOURCE_CRYPTOCOMPARE_PUBLIC_BTC: &str = "cryptocompare_public_btc";
const MAINNET_CHAIN_ID: u64 = 1;

fn is_mainnet_critical_symbol(symbol: &str) -> bool {
    matches!(
        symbol.to_uppercase().as_str(),
        "ETH" | "BTC" | "USDC" | "USDT"
    )
}

fn chainlink_staleness_threshold_secs(chain_id: u64, symbol: &str) -> u64 {
    if chain_id != MAINNET_CHAIN_ID {
        return CHAINLINK_STALENESS_SECS;
    }
    match symbol.to_uppercase().as_str() {
        "ETH" => CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_ETH,
        "BTC" => CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_BTC,
        "USDC" | "USDT" => CHAINLINK_STALENESS_SECS_MAINNET_CRITICAL_STABLE,
        _ => CHAINLINK_STALENESS_SECS,
    }
}

#[derive(Deserialize, Debug)]
struct BinanceTicker {
    #[allow(dead_code)]
    symbol: String,
    price: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedSymbols {
    cache_key: String,
    chainlink_symbol: String,
    binance_symbols: Vec<String>,
}

#[derive(Clone)]
struct RateState {
    window_start: Instant,
    count: u32,
}

impl RateState {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
        }
    }
}

#[derive(Clone)]
pub struct PriceFeed {
    client: Client,
    chain_id: u64,
    // Map: Symbol -> (Price, Timestamp)
    cache: Arc<RwLock<HashMap<String, (PriceQuote, Instant)>>>,
    volatility_cache: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
    last_price: Arc<Mutex<HashMap<String, (f64, Instant)>>>,
    chainlink_feeds: HashMap<String, Address>,
    provider: HttpProvider,
    decimals_cache: Arc<Mutex<HashMap<Address, u8>>>,
    api_keys: PriceApiKeys,
    rate: Arc<Mutex<HashMap<&'static str, RateState>>>,
}

#[derive(Clone, Debug)]
pub struct PriceQuote {
    pub price: f64,
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct PriceApiKeys {
    pub binance: Option<String>,
    pub coingecko: Option<String>,
    pub coinmarketcap: Option<String>,
    pub cryptocompare: Option<String>,
    pub coindesk: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChainlinkFeedAuditOptions {
    pub strict: bool,
    pub allow_stale_critical: bool,
}

impl PriceFeed {
    pub fn new(
        provider: HttpProvider,
        chain_id: u64,
        chainlink_feeds: HashMap<String, Address>,
        api_keys: PriceApiKeys,
    ) -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| {
                AppError::Initialization(format!("price feed HTTP client init failed: {e}"))
            })?;

        Ok(Self {
            client,
            chain_id,
            cache: Arc::new(RwLock::new(HashMap::new())),
            volatility_cache: Arc::new(Mutex::new(HashMap::new())),
            last_price: Arc::new(Mutex::new(HashMap::new())),
            chainlink_feeds,
            provider,
            decimals_cache: Arc::new(Mutex::new(HashMap::new())),
            api_keys,
            rate: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn audit_chainlink_feeds(&self, strict: bool) -> Result<(), AppError> {
        self.audit_chainlink_feeds_with_options(ChainlinkFeedAuditOptions {
            strict,
            allow_stale_critical: false,
        })
        .await
    }

    pub async fn audit_chainlink_feeds_with_options(
        &self,
        options: ChainlinkFeedAuditOptions,
    ) -> Result<(), AppError> {
        let strict = options.strict;
        if self.chainlink_feeds.is_empty() {
            tracing::warn!(
                target: "price_feed",
                "No Chainlink feeds configured; startup feed audit skipped"
            );
            return Ok(());
        }

        sol! {
            #[derive(Debug, PartialEq, Eq)]
            #[sol(rpc)]
            contract AggregatorV3Audit {
                function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
            }
        }

        let mut feeds: Vec<(String, Address)> = self
            .chainlink_feeds
            .iter()
            .map(|(symbol, addr)| (symbol.clone(), *addr))
            .collect();
        feeds.sort_by(|a, b| a.0.cmp(&b.0));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut stale: Vec<String> = Vec::new();
        let mut stale_critical: Vec<String> = Vec::new();
        let mut invalid: Vec<String> = Vec::new();

        for (symbol, addr) in feeds {
            let contract = AggregatorV3Audit::new(addr, self.provider.clone());
            let latest = retry_async(
                move |_| {
                    let c = contract.clone();
                    async move { c.latestRoundData().call().await }
                },
                2,
                Duration::from_millis(75),
            )
            .await;

            let latest = match latest {
                Ok(v) => v,
                Err(e) => {
                    invalid.push(format!("{symbol}@{:#x}:rpc_error={e}", addr));
                    continue;
                }
            };
            if latest.answer.is_negative() {
                invalid.push(format!("{symbol}@{:#x}:negative_answer", addr));
                continue;
            }

            let updated_at_secs: u64 = latest
                .updatedAt
                .try_into()
                .ok()
                .or_else(|| latest.updatedAt.to_string().parse().ok())
                .unwrap_or(0u64);
            if updated_at_secs == 0 {
                invalid.push(format!("{symbol}@{:#x}:updated_at_zero", addr));
                continue;
            }
            let age = now.saturating_sub(updated_at_secs);
            let is_critical_mainnet =
                self.chain_id == MAINNET_CHAIN_ID && is_mainnet_critical_symbol(&symbol);
            let threshold = chainlink_staleness_threshold_secs(self.chain_id, &symbol);
            if age > threshold {
                let row = format!(
                    "{symbol}@{:#x}:age={}s threshold={}s critical_mainnet={}",
                    addr, age, threshold, is_critical_mainnet
                );
                if is_critical_mainnet {
                    stale_critical.push(row);
                } else {
                    stale.push(row);
                }
            }
        }

        if !invalid.is_empty() {
            for row in invalid.iter().take(12) {
                tracing::warn!(
                    target: "price_feed",
                    strict,
                    issue = %row,
                    "Chainlink feed audit invalid feed"
                );
            }
        }
        if !stale.is_empty() {
            for row in stale.iter().take(12) {
                tracing::debug!(
                    target: "price_feed",
                    strict,
                    issue = %row,
                    stale_threshold_secs = CHAINLINK_STALENESS_SECS,
                    "Chainlink feed audit stale feed"
                );
            }
        }
        if !stale_critical.is_empty() {
            for row in stale_critical.iter().take(12) {
                if options.allow_stale_critical {
                    tracing::warn!(
                        target: "price_feed",
                        strict,
                        allow_stale_critical = options.allow_stale_critical,
                        chain_id = self.chain_id,
                        issue = %row,
                        "Chainlink feed audit stale critical feed (sync-lag override active)"
                    );
                } else {
                    tracing::warn!(
                        target: "price_feed",
                        strict,
                        allow_stale_critical = options.allow_stale_critical,
                        chain_id = self.chain_id,
                        issue = %row,
                        "Chainlink feed audit stale critical feed"
                    );
                }
            }
        }

        let stale_critical_blocking = !options.allow_stale_critical && !stale_critical.is_empty();
        if !invalid.is_empty() || stale_critical_blocking || (strict && !stale.is_empty()) {
            return Err(AppError::Config(format!(
                "Chainlink feed audit failed (invalid={}, stale_critical={}, stale={}, strict={}, allow_stale_critical={})",
                invalid.len(),
                stale_critical.len(),
                stale.len(),
                strict,
                options.allow_stale_critical
            )));
        }

        tracing::info!(
            target: "price_feed",
            strict,
            allow_stale_critical = options.allow_stale_critical,
            chain_id = self.chain_id,
            stale_critical = stale_critical.len(),
            stale = stale.len(),
            invalid = invalid.len(),
            "✔ Chainlink feed audit completed"
        );
        Ok(())
    }

    /// Get price from Binance (e.g., symbol = "ETHUSDT")
    pub async fn get_price(&self, symbol: &str) -> Result<PriceQuote, AppError> {
        let normalized = normalize_symbol(symbol);

        // 1. Check fresh cache
        if let Some(quote) = self.cached_if_fresh(&normalized.cache_key).await {
            return Ok(quote);
        }

        // 2. Try Chainlink on-chain feed
        if let Some(price) = self.try_chainlink(&normalized.chainlink_symbol).await? {
            self.store_cache(&normalized.cache_key, price.clone()).await;
            return Ok(price);
        }

        // 2b. Etherscan stats fallback for ETHUSD
        if let Some(price) = self.try_etherscan(&normalized.chainlink_symbol).await? {
            self.store_cache(&normalized.cache_key, price.clone()).await;
            return Ok(price);
        }

        // 3. Binance (with API key if provided; then anonymous)
        if let Some(q) = self.try_binance(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 3b. OKX public ticker
        if let Some(q) = self.try_okx(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 4. CoinMarketCap (API key)
        if let Some(q) = self.try_coinmarketcap(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 5. CoinGecko (API key or keyless)
        if let Some(q) = self.try_coingecko(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 6. CryptoCompare (API key)
        if let Some(q) = self.try_cryptocompare(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 7. CoinPaprika (keyless)
        if let Some(q) = self.try_coinpaprika(&normalized).await? {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 8. CryptoCompare public BTC fallback (legacy COINDESK_API_KEY alias supported)
        if normalized.chainlink_symbol == "BTC"
            && let Some(q) = self.try_cryptocompare_btc_public().await?
        {
            self.store_cache(&normalized.cache_key, q.clone()).await;
            return Ok(q);
        }

        // 9. Soft-fail: serve stale cache if available instead of hard error
        if let Some((quote, age)) = self.cached_any(&normalized.cache_key).await {
            let mut stale = quote.clone();
            stale.source = format!("cache_stale_{}s", age.as_secs());
            return Ok(stale);
        }

        Err(AppError::ApiCall {
            provider: "Binance".into(),
            status: 429,
        })
    }

    async fn try_binance(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        for binance_symbol in &normalized.binance_symbols {
            let url = format!(
                "https://api.binance.com/api/v3/ticker/price?symbol={}",
                binance_symbol
            );

            // Try with API key header if provided
            if let Some(key) = &self.api_keys.binance
                && self.allow("binance", 120).await
            {
                let resp = self
                    .client
                    .get(&url)
                    .header("X-MBX-APIKEY", key)
                    .send()
                    .await;
                if let Ok(ok_resp) = resp
                    && ok_resp.status().is_success()
                {
                    return Self::parse_binance(ok_resp).await;
                }
            }

            // Fallback without API key
            if self.allow("binance_anon", 60).await
                && let Ok(resp) = self.client.get(&url).send().await
                && resp.status().is_success()
            {
                return Self::parse_binance(resp).await;
            }
        }
        Ok(None)
    }

    async fn try_okx(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        if normalized.chainlink_symbol.len() > 8 {
            return Ok(None);
        }
        let inst = format!("{}-USDT", normalized.chainlink_symbol);
        let url = format!("https://www.okx.com/api/v5/market/ticker?instId={}", inst);
        if !self.allow("okx", 60).await {
            return Ok(None);
        }
        let resp = self.client.get(&url).send().await;
        let resp = match resp {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct OkxResp {
            data: Vec<OkxTicker>,
        }
        #[derive(Deserialize)]
        struct OkxTicker {
            #[serde(rename = "last")]
            last: String,
        }
        let parsed: OkxResp = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("OKX decode failed: {}", e)))?;
        let price = parsed.data.first().and_then(|d| d.last.parse::<f64>().ok());
        if let Some(p) = price {
            return Ok(Some(PriceQuote {
                price: p,
                source: "okx".into(),
            }));
        }
        Ok(None)
    }

    async fn parse_binance(resp: reqwest::Response) -> Result<Option<PriceQuote>, AppError> {
        let ticker: BinanceTicker = resp.json().await.map_err(|_| AppError::ApiCall {
            provider: "Binance JSON".into(),
            status: 0,
        })?;

        let price = ticker.price.parse().unwrap_or(0.0);
        Ok(Some(PriceQuote {
            price,
            source: "binance".into(),
        }))
    }

    async fn try_coinmarketcap(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        let Some(key) = &self.api_keys.coinmarketcap else {
            return Ok(None);
        };
        if !self.allow("cmc", 30).await {
            return Ok(None);
        }
        let url = format!(
            "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest?symbol={}&convert=USD",
            normalized.chainlink_symbol
        );
        let resp = self
            .client
            .get(&url)
            .header("X-CMC_PRO_API_KEY", key)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("CMC request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct Quote {
            price: f64,
        }
        #[derive(Deserialize)]
        struct DataQuote {
            #[serde(rename = "quote")]
            quote: HashMap<String, Quote>,
        }
        #[derive(Deserialize)]
        struct CmcResp {
            data: HashMap<String, DataQuote>,
        }
        let parsed: CmcResp = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("CMC decode failed: {}", e)))?;
        if let Some(entry) = parsed.data.get(&normalized.chainlink_symbol)
            && let Some(usd) = entry.quote.get("USD")
        {
            return Ok(Some(PriceQuote {
                price: usd.price,
                source: "coinmarketcap".into(),
            }));
        }
        Ok(None)
    }

    async fn try_coingecko(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        let id = match normalized.chainlink_symbol.as_str() {
            "ETH" => "ethereum",
            "BTC" => "bitcoin",
            "BNB" => "binancecoin",
            "ARB" => "arbitrum",
            "OP" => "optimism",
            _ => return Ok(None),
        };
        let url =
            format!("https://api.coingecko.com/api/v3/simple/price?ids={id}&vs_currencies=usd");
        if !self.allow("coingecko", 30).await {
            return Ok(None);
        }
        let mut req = self.client.get(&url);
        if let Some(key) = &self.api_keys.coingecko {
            req = req.header("x-cg-pro-api-key", key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("CoinGecko request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("CoinGecko decode failed: {}", e)))?;
        if let Some(price) = parsed
            .get(id)
            .and_then(|v| v.get("usd"))
            .and_then(|v| v.as_f64())
        {
            return Ok(Some(PriceQuote {
                price,
                source: "coingecko".into(),
            }));
        }
        Ok(None)
    }

    async fn try_cryptocompare(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        let Some(key) = &self.api_keys.cryptocompare else {
            return Ok(None);
        };
        if !self.allow("cryptocompare", 20).await {
            return Ok(None);
        }
        let url = format!(
            "https://min-api.cryptocompare.com/data/price?fsym={}&tsyms=USD&api_key={}",
            normalized.chainlink_symbol, key
        );
        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                AppError::Connection(format!("CryptoCompare request failed: {}", e))
            })?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("CryptoCompare decode failed: {}", e)))?;
        if let Some(price) = parsed.get("USD").and_then(|v| v.as_f64()) {
            return Ok(Some(PriceQuote {
                price,
                source: SOURCE_CRYPTOCOMPARE.into(),
            }));
        }
        Ok(None)
    }

    async fn try_coinpaprika(
        &self,
        normalized: &NormalizedSymbols,
    ) -> Result<Option<PriceQuote>, AppError> {
        if !self.allow("coinpaprika", 600).await {
            return Ok(None);
        }
        let id = match normalized.chainlink_symbol.as_str() {
            "BTC" => "btc-bitcoin",
            "ETH" => "eth-ethereum",
            "BNB" => "bnb-binance-coin",
            _ => return Ok(None),
        };
        let url = format!("https://api.coinpaprika.com/v1/tickers/{id}");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("CoinPaprika request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("CoinPaprika decode failed: {}", e)))?;
        if let Some(price) = parsed
            .get("quotes")
            .and_then(|q| q.get("USD"))
            .and_then(|u| u.get("price"))
            .and_then(|p| p.as_f64())
        {
            return Ok(Some(PriceQuote {
                price,
                source: "coinpaprika".into(),
            }));
        }
        Ok(None)
    }

    async fn try_cryptocompare_btc_public(&self) -> Result<Option<PriceQuote>, AppError> {
        if !self.allow("cryptocompare_public", 30).await {
            return Ok(None);
        }
        let key = self
            .api_keys
            .cryptocompare
            .as_ref()
            .or(self.api_keys.coindesk.as_ref());
        let url = if let Some(key) = key {
            format!(
                "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD,JPY,EUR&api_key={key}"
            )
        } else {
            "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD,JPY,EUR".to_string()
        };
        let resp = self.client.get(&url).send().await.map_err(|e| {
            AppError::Connection(format!("CryptoCompare public request failed: {}", e))
        })?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let parsed: serde_json::Value = resp.json().await.map_err(|e| {
            AppError::Initialization(format!("CryptoCompare public decode failed: {}", e))
        })?;
        if let Some(price) = parsed.get("USD").and_then(|v| v.as_f64()) {
            return Ok(Some(PriceQuote {
                price,
                source: SOURCE_CRYPTOCOMPARE_PUBLIC_BTC.into(),
            }));
        }
        Ok(None)
    }

    async fn allow(&self, provider: &'static str, rpm: u32) -> bool {
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let state = guard.entry(provider).or_insert_with(RateState::new);
        let now = Instant::now();
        if now.duration_since(state.window_start).as_secs() >= PROVIDER_WINDOW_SECS {
            state.window_start = now;
            state.count = 0;
        }
        if state.count >= rpm {
            return false;
        }
        state.count += 1;
        true
    }
    async fn try_chainlink(&self, symbol: &str) -> Result<Option<PriceQuote>, AppError> {
        let key = symbol.to_uppercase();
        let fallback_keys = [
            key.clone(),
            format!("{key}_USD"),
            format!("{key}_USDT"),
            format!("{key}_USDC"),
            format!("{key}_ETH"),
            format!("{key}_BTC"),
        ];
        let Some(addr) = fallback_keys
            .iter()
            .find_map(|k| self.chainlink_feeds.get(k))
        else {
            return Ok(None);
        };

        sol! {
            #[derive(Debug, PartialEq, Eq)]
            #[sol(rpc)]
            contract AggregatorV3Interface {
                function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
                function decimals() external view returns (uint8);
            }
        }

        let contract = AggregatorV3Interface::new(*addr, self.provider.clone());
        let contract_for_latest = contract.clone();
        let decimals_resp: u8 = {
            let cached = self
                .decimals_cache
                .lock()
                .ok()
                .and_then(|m| m.get(addr).copied());
            if let Some(dec) = cached {
                dec
            } else {
                let contract_for_decimals = contract.clone();
                let d: u8 = retry_async(
                    move |_| {
                        let c = contract_for_decimals.clone();
                        async move { c.decimals().call().await }
                    },
                    3,
                    Duration::from_millis(100),
                )
                .await
                .map_err(|e| AppError::Connection(format!("Chainlink decimals failed: {}", e)))?;
                if let Ok(mut guard) = self.decimals_cache.lock() {
                    guard.insert(*addr, d);
                }
                d
            }
        };
        let latest = retry_async(
            move |_| {
                let c = contract_for_latest.clone();
                async move { c.latestRoundData().call().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Connection(format!("Chainlink price failed: {}", e)))?;

        // Chainlink answers are int256; negative indicates invalid.
        if latest.answer.is_negative() {
            return Ok(None);
        }

        let decimals = decimals_resp as i32;
        let updated_at_secs: Option<u64> = latest
            .updatedAt
            .try_into()
            .ok()
            .or_else(|| latest.updatedAt.to_string().parse().ok());
        let mut stale = false;
        let mut critical_stale = false;
        if let Some(ts) = updated_at_secs {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now.saturating_sub(ts);
            let is_critical_mainnet =
                self.chain_id == MAINNET_CHAIN_ID && is_mainnet_critical_symbol(&key);
            let threshold = chainlink_staleness_threshold_secs(self.chain_id, &key);
            if age > threshold {
                stale = true;
                critical_stale = is_critical_mainnet;
                tracing::warn!(
                    target: "price_feed",
                    age,
                    threshold,
                    chain_id = self.chain_id,
                    critical_mainnet = is_critical_mainnet,
                    "Chainlink price stale for {}",
                    symbol
                );
            }
        }
        let raw: i128 = latest
            .answer
            .try_into()
            .map_err(|e| AppError::Connection(format!("Chainlink answer convert failed: {}", e)))?;
        let price = (raw as f64) / 10f64.powi(decimals);
        if critical_stale {
            return Ok(None);
        }
        let source = if stale {
            "chainlink_stale".into()
        } else {
            "chainlink".into()
        };
        Ok(Some(PriceQuote { price, source }))
    }

    async fn try_etherscan(&self, symbol: &str) -> Result<Option<PriceQuote>, AppError> {
        // Only ETH price is available via etherscan stats; gate accordingly.
        if symbol.to_uppercase() != "ETH" {
            return Ok(None);
        }
        let api_key = match env::var("ETHERSCAN_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => return Ok(None),
        };
        let url =
            format!("https://api.etherscan.io/api?module=stats&action=ethprice&apikey={api_key}");
        let resp = match self
            .client
            .get(&url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(
                    target: "price_feed",
                    error = %e,
                    "Etherscan price request failed; falling back"
                );
                return Ok(None);
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(
                target: "price_feed",
                status = resp.status().as_u16(),
                "Etherscan price returned non-200; falling back"
            );
            return Ok(None);
        }
        let parsed: EtherscanPriceResponse = match resp.json().await {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(
                    target: "price_feed",
                    error = %e,
                    "Etherscan price decode failed; falling back"
                );
                return Ok(None);
            }
        };

        let result = match parsed.result {
            Some(result) => result,
            None => {
                tracing::warn!(target: "price_feed", "Etherscan price missing result; falling back");
                return Ok(None);
            }
        };

        let price: f64 = match result.ethusd.parse() {
            Ok(price) => price,
            Err(_) => {
                tracing::warn!(
                    target: "price_feed",
                    "Invalid ethusd from Etherscan; falling back"
                );
                return Ok(None);
            }
        };

        Ok(Some(PriceQuote {
            price,
            source: "etherscan".into(),
        }))
    }

    pub fn volatility_bps_cached(&self, symbol: &str) -> Option<u64> {
        let upper = symbol.to_uppercase();
        let mut guard = self.volatility_cache.lock().ok()?;
        let (bps, ts) = guard.get(&upper).copied()?;
        if ts.elapsed().as_secs() > STALE_CACHE_GRACE_SECS {
            guard.remove(&upper);
            return None;
        }
        Some(bps)
    }

    async fn store_cache(&self, symbol: &str, price: PriceQuote) {
        let price_value = price.price;
        let mut write_guard = self.cache.write().await;
        write_guard.insert(symbol.to_string(), (price, Instant::now()));
        drop(write_guard);
        self.update_volatility(symbol, price_value);
    }

    fn update_volatility(&self, symbol: &str, price: f64) {
        if price <= 0.0 {
            return;
        }
        let upper = symbol.to_uppercase();
        let now = Instant::now();
        if let Ok(mut last_guard) = self.last_price.lock() {
            if let Some((prev_price, prev_ts)) = last_guard.get(&upper).copied() {
                let elapsed = now.duration_since(prev_ts).as_secs().max(1);
                let delta = (price - prev_price).abs();
                if prev_price > 0.0 {
                    let raw_bps = (delta / prev_price) * 10_000.0;
                    let scaled = raw_bps * (60.0 / elapsed as f64);
                    let vol_bps = scaled.round().clamp(0.0, 2_000.0) as u64;
                    if let Ok(mut vol_guard) = self.volatility_cache.lock() {
                        vol_guard.insert(upper.clone(), (vol_bps, now));
                    }
                }
            }
            last_guard.insert(upper, (price, now));
        }
    }

    async fn cached_if_fresh(&self, key: &str) -> Option<PriceQuote> {
        let read_guard = self.cache.read().await;
        read_guard
            .get(key)
            .and_then(|(quote, ts)| (ts.elapsed().as_secs() < CACHE_TTL).then(|| quote.clone()))
    }

    async fn cached_any(&self, key: &str) -> Option<(PriceQuote, std::time::Duration)> {
        let read_guard = self.cache.read().await;
        read_guard
            .get(key)
            .map(|(quote, ts)| (quote.clone(), ts.elapsed()))
            .filter(|(_, age)| age.as_secs() < STALE_CACHE_GRACE_SECS)
    }
}

#[derive(Debug, Deserialize)]
struct EtherscanPriceResponse {
    result: Option<EtherscanPriceResult>,
}

#[derive(Debug, Deserialize)]
struct EtherscanPriceResult {
    ethusd: String,
}

fn normalize_symbol(symbol: &str) -> NormalizedSymbols {
    let cleaned: String = symbol
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    let (base, explicit_quote) = strip_quote(&cleaned);
    let chainlink_symbol = alias_base(&base);

    let mut binance_symbols = Vec::new();
    if let Some(q) = explicit_quote {
        binance_symbols.push(format!("{}{}", chainlink_symbol, q));
    }

    // Prefer USDT/USDC, then USD/BUSD for breadth.
    for quote in ["USDT", "USDC", "USD", "BUSD"] {
        binance_symbols.push(format!("{}{}", chainlink_symbol, quote));
    }

    let mut seen = HashSet::new();
    binance_symbols.retain(|s| seen.insert(s.clone()));

    NormalizedSymbols {
        cache_key: chainlink_symbol.clone(),
        chainlink_symbol,
        binance_symbols,
    }
}

fn strip_quote(symbol: &str) -> (String, Option<&'static str>) {
    const QUOTES: [&str; 4] = ["USDT", "USDC", "USD", "BUSD"];
    for quote in QUOTES {
        if let Some(base) = symbol.strip_suffix(quote) {
            return (base.to_string(), Some(quote));
        }
    }
    (symbol.to_string(), None)
}

fn alias_base(base: &str) -> String {
    match base {
        "WETH" => "ETH".into(),
        "WBTC" => "BTC".into(),
        _ => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ethusd() {
        let normalized = normalize_symbol("ethusd");
        assert_eq!(normalized.cache_key, "ETH");
        assert_eq!(normalized.chainlink_symbol, "ETH");
        assert!(normalized.binance_symbols.contains(&"ETHUSDT".to_string()));
    }

    #[test]
    fn normalizes_plain_symbol() {
        let normalized = normalize_symbol("eth");
        assert_eq!(normalized.cache_key, "ETH");
        assert!(normalized.binance_symbols.contains(&"ETHUSDT".to_string()));
    }

    #[test]
    fn normalizes_with_alias_and_separator() {
        let normalized = normalize_symbol("weth-usdc");
        assert_eq!(normalized.chainlink_symbol, "ETH");
        assert!(normalized.binance_symbols.contains(&"ETHUSDC".to_string()));
        assert!(normalized.binance_symbols.contains(&"ETHUSDT".to_string()));
    }

    #[test]
    fn pricing_source_labels_match_adapter_names() {
        assert_eq!(SOURCE_CRYPTOCOMPARE, "cryptocompare");
        assert_eq!(SOURCE_CRYPTOCOMPARE_PUBLIC_BTC, "cryptocompare_public_btc");
    }
}
