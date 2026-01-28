// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::network::provider::HttpProvider;
use alloy::primitives::Address;
use alloy::sol;
use reqwest::Client;
use reqwest::header;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: u64 = 60; // Cache prices for 60 seconds
const CHAINLINK_STALENESS_SECS: u64 = 600;
const STALE_CACHE_GRACE_SECS: u64 = 900; // Accept up to 15m old cache on failures

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
pub struct PriceFeed {
    client: Client,
    // Map: Symbol -> (Price, Timestamp)
    cache: Arc<RwLock<HashMap<String, (PriceQuote, Instant)>>>,
    chainlink_feeds: HashMap<String, Address>,
    provider: HttpProvider,
    decimals_cache: Arc<Mutex<HashMap<Address, u8>>>,
}

#[derive(Clone, Debug)]
pub struct PriceQuote {
    pub price: f64,
    pub source: String,
}

impl PriceFeed {
    pub fn new(provider: HttpProvider, chainlink_feeds: HashMap<String, Address>) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            chainlink_feeds,
            provider,
            decimals_cache: Arc::new(Mutex::new(HashMap::new())),
        }
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

        // 3. Fallback to Binance API
        let mut last_status = 0u16;
        for binance_symbol in &normalized.binance_symbols {
            let url = format!(
                "https://api.binance.com/api/v3/ticker/price?symbol={}",
                binance_symbol
            );
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if !resp.status().is_success() {
                last_status = resp.status().as_u16();
                continue;
            }

            let ticker: BinanceTicker = resp.json().await.map_err(|_| AppError::ApiCall {
                provider: "Binance JSON".into(),
                status: 0,
            })?;

            let price = ticker.price.parse().unwrap_or(0.0);
            let quote = PriceQuote {
                price,
                source: "binance".into(),
            };

            self.store_cache(&normalized.cache_key, quote.clone()).await;

            return Ok(quote);
        }

        // 4. Soft-fail: serve stale cache if available instead of hard error
        if let Some((quote, age)) = self.cached_any(&normalized.cache_key).await {
            let mut stale = quote.clone();
            stale.source = format!("cache_stale_{}s", age.as_secs());
            return Ok(stale);
        }

        Err(AppError::ApiCall {
            provider: "Binance".into(),
            status: last_status,
        })
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
        if let Some(ts) = updated_at_secs {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now.saturating_sub(ts);
            if age > CHAINLINK_STALENESS_SECS {
                stale = true;
                tracing::warn!(target: "price_feed", age, "Chainlink price stale for {}", symbol);
            }
        }
        let raw: i128 = latest
            .answer
            .try_into()
            .map_err(|e| AppError::Connection(format!("Chainlink answer convert failed: {}", e)))?;
        let price = (raw as f64) / 10f64.powi(decimals);
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
        let resp = self
            .client
            .get(&url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("Etherscan price failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(AppError::ApiCall {
                provider: "Etherscan price".into(),
                status: resp.status().as_u16(),
            });
        }
        let parsed: EtherscanPriceResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("Etherscan price decode failed: {e}")))?;

        let result = parsed
            .result
            .ok_or_else(|| AppError::Initialization("Etherscan price missing result".into()))?;

        let price: f64 = result
            .ethusd
            .parse()
            .map_err(|_| AppError::Initialization("Invalid ethusd from Etherscan".into()))?;

        Ok(Some(PriceQuote {
            price,
            source: "etherscan".into(),
        }))
    }

    async fn store_cache(&self, symbol: &str, price: PriceQuote) {
        let mut write_guard = self.cache.write().await;
        write_guard.insert(symbol.to_string(), (price, Instant::now()));
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
            .and_then(|(quote, ts)| Some((quote.clone(), ts.elapsed())))
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

    binance_symbols.sort();
    binance_symbols.dedup();

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
}
