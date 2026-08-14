// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use futures::{StreamExt, TryStreamExt, stream};
use oxidity_searcher::infrastructure::data::pool_index::{
    CuratedPoolRecord, PoolCurationPolicy, PoolMetrics, PoolProtocol,
};
use reqwest::Client;
use serde_json::{Value, json};

const DEFAULT_DISCOVERY_BLOCKS: u64 = 250_000;
const DEFAULT_VOLUME_BLOCKS: u64 = 7_200;
const DEFAULT_LOG_CHUNK: u64 = 25_000;

#[derive(Debug, Parser)]
#[command(about = "Build a curated V3/V4/Balancer/Curve pool index")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// Probe configured httpRpcs and use history-capable endpoints for event discovery.
    #[arg(long)]
    auto_history_rpc: bool,
    /// Number of history-capable endpoints retained for per-request failover.
    #[arg(long, default_value_t = 3)]
    history_rpc_count: usize,
    #[arg(long, default_value_t = 1)]
    chain_id: u64,
    /// Comma-separated: uniswap_v3,uniswap_v4,balancer_v2,curve.
    #[arg(long, default_value = "uniswap_v3,uniswap_v4,balancer_v2,curve")]
    protocols: String,
    #[arg(long, default_value = "data/global_data.json")]
    global_data: PathBuf,
    #[arg(long)]
    from_block: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_DISCOVERY_BLOCKS)]
    discovery_blocks: u64,
    #[arg(long, default_value_t = DEFAULT_VOLUME_BLOCKS)]
    volume_blocks: u64,
    #[arg(long, default_value_t = DEFAULT_LOG_CHUNK)]
    log_chunk: u64,
    /// Refresh already indexed records without scanning creation/registration history.
    #[arg(long)]
    skip_discovery: bool,
    #[arg(long, default_value_t = 500)]
    max_candidates: usize,
    #[arg(long, default_value_t = 50_400)]
    min_age_blocks: u64,
    #[arg(long, default_value_t = 100_000)]
    min_liquidity_usd: u64,
    #[arg(long, default_value_t = 10_000)]
    min_volume_usd: u64,
    #[arg(long, default_value_t = 5)]
    min_swaps: u64,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_usd_metrics: bool,
    #[arg(long, default_value_t = 1)]
    min_v4_liquidity: u128,
    #[arg(long, default_value_t = 86_400)]
    max_feed_age_secs: u64,
    #[arg(long)]
    update_global_data: bool,
    #[arg(long, default_value = "data/pool_index.generated.json")]
    output: PathBuf,
}

#[derive(Clone)]
struct Rpc {
    urls: Arc<Vec<String>>,
    next_url: Arc<AtomicUsize>,
    client: Client,
}

impl Rpc {
    fn new(url: String) -> Self {
        Self::from_urls(vec![url])
    }

    fn from_urls(urls: Vec<String>) -> Self {
        Self::from_urls_with_timeout(urls, Duration::from_secs(45))
    }

    fn from_urls_with_timeout(urls: Vec<String>, timeout: Duration) -> Self {
        assert!(!urls.is_empty(), "RPC endpoint set must not be empty");
        Self {
            urls: Arc::new(urls),
            next_url: Arc::new(AtomicUsize::new(0)),
            client: Client::builder()
                .timeout(timeout)
                .build()
                .expect("valid HTTP client configuration"),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let start = self.next_url.fetch_add(1, Ordering::Relaxed);
        let mut failures = Vec::with_capacity(self.urls.len());
        for offset in 0..self.urls.len() {
            let endpoint = &self.urls[(start + offset) % self.urls.len()];
            let response = self
                .client
                .post(endpoint)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params.clone()}))
                .send()
                .await;
            let response: Value = match response {
                Ok(response) => match response.error_for_status() {
                    Ok(response) => match response.json().await {
                        Ok(value) => value,
                        Err(_) => {
                            failures.push("invalid JSON".to_string());
                            continue;
                        }
                    },
                    Err(_) => {
                        failures.push("HTTP error".to_string());
                        continue;
                    }
                },
                Err(_) => {
                    failures.push("transport error".to_string());
                    continue;
                }
            };
            if let Some(error) = response.get("error") {
                failures.push(format!("RPC error: {error}"));
                continue;
            }
            if let Some(result) = response.get("result") {
                return Ok(result.clone());
            }
            failures.push("missing result".to_string());
        }
        bail!(
            "RPC {method} failed on all {} configured endpoints: {}",
            self.urls.len(),
            failures.join("; ")
        )
    }

    async fn block_number(&self) -> Result<u64> {
        parse_hex_u64(&self.call("eth_blockNumber", json!([])).await?)
    }

    async fn eth_call(&self, to: Address, data: String, block: &str) -> Result<String> {
        let value = self
            .call(
                "eth_call",
                json!([{"to": format!("{to:#x}"), "data": data}, block]),
            )
            .await?;
        value
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("eth_call result was not hex"))
    }

    async fn logs(
        &self,
        address: Address,
        topics: Vec<Option<String>>,
        from_block: u64,
        to_block: u64,
        chunk_size: u64,
    ) -> Result<Vec<Value>> {
        if self.urls.len() > 1 {
            let chunk = chunk_size.max(1);
            let mut ranges = Vec::new();
            let mut start = from_block;
            while start <= to_block {
                let end = start.saturating_add(chunk - 1).min(to_block);
                ranges.push((start, end));
                start = end.saturating_add(1);
            }
            let parallelism = self.urls.len();
            let chunks: Vec<Vec<Value>> = stream::iter(ranges)
                .map(|(start, end)| {
                    let topics = topics.clone();
                    async move {
                        let filter = json!({
                            "address": format!("{address:#x}"),
                            "fromBlock": hex_u64(start),
                            "toBlock": hex_u64(end),
                            "topics": topics,
                        });
                        match self.call("eth_getLogs", json!([filter])).await? {
                            Value::Array(logs) => Ok(logs),
                            _ => bail!("eth_getLogs returned a non-array result"),
                        }
                    }
                })
                .buffer_unordered(parallelism)
                .try_collect()
                .await?;
            let mut all: Vec<Value> = chunks.into_iter().flatten().collect();
            all.sort_by_key(|log| {
                (
                    log.get("blockNumber")
                        .and_then(|value| parse_hex_u64(value).ok())
                        .unwrap_or_default(),
                    log.get("logIndex")
                        .and_then(|value| parse_hex_u64(value).ok())
                        .unwrap_or_default(),
                )
            });
            return Ok(all);
        }
        let mut all = Vec::new();
        let mut start = from_block;
        let mut chunk = chunk_size.max(1);
        while start <= to_block {
            let end = start.saturating_add(chunk - 1).min(to_block);
            let filter = json!({
                "address": format!("{address:#x}"),
                "fromBlock": hex_u64(start),
                "toBlock": hex_u64(end),
                "topics": topics,
            });
            match self.call("eth_getLogs", json!([filter])).await {
                Ok(Value::Array(mut logs)) => {
                    all.append(&mut logs);
                    start = end.saturating_add(1);
                    if chunk < chunk_size {
                        chunk = (chunk.saturating_mul(2)).min(chunk_size);
                    }
                }
                Ok(_) => bail!("eth_getLogs returned a non-array result"),
                Err(error) if error.to_string().contains("pruned history unavailable") => {
                    bail!(
                        "requested log history starts at block {start}, but the RPC has pruned it; use an archive RPC for initial backfill or a shorter incremental range"
                    );
                }
                Err(error) if chunk > 128 => {
                    eprintln!(
                        "log range {start}..={end} rejected ({error}); retrying smaller chunks"
                    );
                    chunk = (chunk / 2).max(128);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(all)
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    protocol: PoolProtocol,
    pool: Address,
    pool_id: Option<B256>,
    tokens: Vec<Address>,
    canonical_source: Address,
    created_block: u64,
    creation_block_exact: bool,
    fee: Option<u32>,
    tick_spacing: Option<i32>,
}

#[derive(Clone, Debug)]
struct TokenMeta {
    decimals: u8,
    feed: Option<Address>,
}

struct MetricsContext<'a> {
    rpc: &'a Rpc,
    latest: u64,
    latest_timestamp: u64,
    max_feed_age_secs: u64,
    volume_from: u64,
    log_chunk: u64,
    token_meta: HashMap<Address, TokenMeta>,
    price_cache: HashMap<Address, Option<(U256, u8)>>,
    v4_state_view: Option<Address>,
    v4_swap_logs: Option<HashMap<B256, Vec<Value>>>,
    v4_swap_logs_available: Option<bool>,
}

impl<'a> MetricsContext<'a> {
    async fn token_price(&mut self, token: Address) -> Option<(U256, u8, u8)> {
        let meta = self.token_meta.get(&token)?.clone();
        let feed = meta.feed?;
        if let Some(price) = self.price_cache.get(&feed) {
            return price.map(|(value, feed_decimals)| (value, feed_decimals, meta.decimals));
        }
        let feed_decimals = call_u256(self.rpc, feed, "decimals()", "latest")
            .await
            .ok()
            .and_then(u256_to_u8);
        let round = self
            .rpc
            .eth_call(feed, selector_data("latestRoundData()"), "latest")
            .await
            .ok();
        let answer = round
            .as_deref()
            .and_then(|hex| word(hex, 1))
            .and_then(|bytes| u256_from_word(&bytes));
        let updated_at = round
            .as_deref()
            .and_then(|hex| word(hex, 3))
            .and_then(|bytes| u256_from_word(&bytes))
            .map(|value| value.to::<u64>());
        let fresh = updated_at.is_some_and(|timestamp| {
            timestamp <= self.latest_timestamp
                && self.latest_timestamp.saturating_sub(timestamp) <= self.max_feed_age_secs
        });
        let price = match (answer, feed_decimals, fresh) {
            (Some(answer), Some(decimals), true) if !answer.is_zero() => Some((answer, decimals)),
            _ => None,
        };
        self.price_cache.insert(feed, price);
        price.map(|(value, feed_decimals)| (value, feed_decimals, meta.decimals))
    }

    async fn amount_usd_e6(&mut self, token: Address, amount: U256) -> Option<U256> {
        let (price, feed_decimals, token_decimals) = self.token_price(token).await?;
        let denominator = pow10(token_decimals)?.saturating_mul(pow10(feed_decimals)?);
        Some(
            amount
                .saturating_mul(price)
                .saturating_mul(U256::from(1_000_000u64))
                / denominator,
        )
    }

    async fn balances_liquidity_usd(
        &mut self,
        holder: Address,
        tokens: &[Address],
    ) -> Option<U256> {
        let mut total = U256::ZERO;
        for token in tokens {
            let balance = call_u256_with_address(self.rpc, *token, "balanceOf(address)", holder)
                .await
                .ok()?;
            total = total.saturating_add(self.amount_usd_e6(*token, balance).await?);
        }
        Some(total)
    }

    async fn volume_for(&mut self, candidate: &Candidate) -> (u64, Option<U256>) {
        if candidate.protocol == PoolProtocol::UniswapV4 {
            return self.v4_volume(candidate).await;
        }
        let (address, topic0, topic1) = match candidate.protocol {
            PoolProtocol::UniswapV3 => (
                candidate.pool,
                event_topic("Swap(address,address,int256,int256,uint160,uint128,int24)"),
                None,
            ),
            PoolProtocol::UniswapV4 => unreachable!(),
            PoolProtocol::BalancerV2 => (
                candidate.canonical_source,
                event_topic("Swap(bytes32,address,address,uint256,uint256)"),
                candidate.pool_id.map(|id| format!("{id:#x}")),
            ),
            PoolProtocol::Curve => {
                return self.curve_volume(candidate).await;
            }
        };
        let logs = match self
            .rpc
            .logs(
                address,
                vec![Some(topic0), topic1],
                self.volume_from,
                self.latest,
                self.log_chunk,
            )
            .await
        {
            Ok(logs) => logs,
            Err(_) => return (0, None),
        };
        let mut total = U256::ZERO;
        let mut priced = true;
        for log in &logs {
            let data = log.get("data").and_then(Value::as_str).unwrap_or("0x");
            match candidate.protocol {
                PoolProtocol::UniswapV3 | PoolProtocol::UniswapV4 => {
                    let amount0 = signed_abs_word(data, 0).unwrap_or(U256::ZERO);
                    let amount1 = signed_abs_word(data, 1).unwrap_or(U256::ZERO);
                    let usd0 = self.amount_usd_e6(candidate.tokens[0], amount0).await;
                    let usd1 = self.amount_usd_e6(candidate.tokens[1], amount1).await;
                    if let (Some(a), Some(b)) = (usd0, usd1) {
                        total = total.saturating_add(a.saturating_add(b) / U256::from(2u8));
                    } else {
                        priced = false;
                    }
                }
                PoolProtocol::BalancerV2 => {
                    let topics = log.get("topics").and_then(Value::as_array);
                    let token_in = topics
                        .and_then(|v| v.get(2))
                        .and_then(Value::as_str)
                        .and_then(parse_topic_address);
                    let token_out = topics
                        .and_then(|v| v.get(3))
                        .and_then(Value::as_str)
                        .and_then(parse_topic_address);
                    let amount_in = word(data, 0).and_then(|v| u256_from_word(&v));
                    let amount_out = word(data, 1).and_then(|v| u256_from_word(&v));
                    match (token_in, token_out, amount_in, amount_out) {
                        (Some(t0), Some(t1), Some(a0), Some(a1)) => {
                            if let (Some(v0), Some(v1)) = (
                                self.amount_usd_e6(t0, a0).await,
                                self.amount_usd_e6(t1, a1).await,
                            ) {
                                total =
                                    total.saturating_add(v0.saturating_add(v1) / U256::from(2u8));
                            } else {
                                priced = false;
                            }
                        }
                        _ => priced = false,
                    }
                }
                PoolProtocol::Curve => unreachable!(),
            }
        }
        (logs.len() as u64, priced.then_some(total))
    }

    async fn v4_volume(&mut self, candidate: &Candidate) -> (u64, Option<U256>) {
        if self.v4_swap_logs_available == Some(false) {
            return (0, None);
        }
        if self.v4_swap_logs.is_none() {
            let topic =
                event_topic("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)");
            let logs = match self
                .rpc
                .logs(
                    candidate.canonical_source,
                    vec![Some(topic)],
                    self.volume_from,
                    self.latest,
                    self.log_chunk,
                )
                .await
            {
                Ok(logs) => logs,
                Err(_) => {
                    self.v4_swap_logs_available = Some(false);
                    return (0, None);
                }
            };
            let mut grouped: HashMap<B256, Vec<Value>> = HashMap::new();
            for log in logs {
                if let Some(pool_id) = log
                    .get("topics")
                    .and_then(Value::as_array)
                    .and_then(|topics| topics.get(1))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse().ok())
                {
                    grouped.entry(pool_id).or_default().push(log);
                }
            }
            self.v4_swap_logs = Some(grouped);
            self.v4_swap_logs_available = Some(true);
        }
        let Some(pool_id) = candidate.pool_id else {
            return (0, None);
        };
        let logs = self
            .v4_swap_logs
            .as_ref()
            .and_then(|grouped| grouped.get(&pool_id))
            .cloned()
            .unwrap_or_default();
        let mut total = U256::ZERO;
        let mut priced = true;
        for log in &logs {
            let data = log.get("data").and_then(Value::as_str).unwrap_or("0x");
            let amount0 = signed_abs_word(data, 0).unwrap_or(U256::ZERO);
            let amount1 = signed_abs_word(data, 1).unwrap_or(U256::ZERO);
            match (
                self.amount_usd_e6(candidate.tokens[0], amount0).await,
                self.amount_usd_e6(candidate.tokens[1], amount1).await,
            ) {
                (Some(value0), Some(value1)) => {
                    total = total.saturating_add(value0.saturating_add(value1) / U256::from(2u8));
                }
                _ => priced = false,
            }
        }
        (logs.len() as u64, priced.then_some(total))
    }

    async fn curve_volume(&mut self, candidate: &Candidate) -> (u64, Option<U256>) {
        let topics = [
            event_topic("TokenExchange(address,int128,uint256,int128,uint256)"),
            event_topic("TokenExchangeUnderlying(address,int128,uint256,int128,uint256)"),
        ];
        let mut count = 0u64;
        let mut total = U256::ZERO;
        let mut priced = true;
        for topic in topics {
            let logs = match self
                .rpc
                .logs(
                    candidate.pool,
                    vec![Some(topic)],
                    self.volume_from,
                    self.latest,
                    self.log_chunk,
                )
                .await
            {
                Ok(logs) => logs,
                Err(_) => continue,
            };
            count = count.saturating_add(logs.len() as u64);
            for log in logs {
                let data = log.get("data").and_then(Value::as_str).unwrap_or("0x");
                let sold_id = word(data, 0).and_then(|v| u256_from_word(&v));
                let sold = word(data, 1).and_then(|v| u256_from_word(&v));
                let bought_id = word(data, 2).and_then(|v| u256_from_word(&v));
                let bought = word(data, 3).and_then(|v| u256_from_word(&v));
                let indexes = sold_id
                    .zip(bought_id)
                    .map(|(a, b)| (a.to::<usize>(), b.to::<usize>()));
                match (indexes, sold, bought) {
                    (Some((i, j)), Some(a), Some(b))
                        if i < candidate.tokens.len() && j < candidate.tokens.len() =>
                    {
                        if let (Some(v0), Some(v1)) = (
                            self.amount_usd_e6(candidate.tokens[i], a).await,
                            self.amount_usd_e6(candidate.tokens[j], b).await,
                        ) {
                            total = total.saturating_add(v0.saturating_add(v1) / U256::from(2u8));
                        } else {
                            priced = false;
                        }
                    }
                    _ => priced = false,
                }
            }
        }
        (count, priced.then_some(total))
    }

    async fn metrics(
        &mut self,
        candidate: &Candidate,
        min_liquidity_usd_e6: u128,
        min_v4_protocol_liquidity: u128,
    ) -> PoolMetrics {
        let (liquidity, protocol_liquidity) = match candidate.protocol {
            PoolProtocol::UniswapV3 | PoolProtocol::Curve => (
                self.balances_liquidity_usd(candidate.pool, &candidate.tokens)
                    .await,
                None,
            ),
            PoolProtocol::BalancerV2 => (self.balancer_liquidity_usd(candidate).await, None),
            PoolProtocol::UniswapV4 => {
                let raw = match (self.v4_state_view, candidate.pool_id) {
                    (Some(view), Some(pool_id)) => {
                        call_u256_with_b256(self.rpc, view, "getLiquidity(bytes32)", pool_id)
                            .await
                            .ok()
                    }
                    _ => None,
                };
                (None, raw)
            }
        };
        let sufficiently_liquid = match candidate.protocol {
            PoolProtocol::UniswapV4 => protocol_liquidity
                .is_some_and(|value| value >= U256::from(min_v4_protocol_liquidity)),
            _ => liquidity.is_some_and(|value| value >= U256::from(min_liquidity_usd_e6)),
        };
        let (swap_count, volume) = if sufficiently_liquid {
            self.volume_for(candidate).await
        } else {
            (0, Some(U256::ZERO))
        };
        PoolMetrics {
            measured_at_block: self.latest,
            volume_window_blocks: self.latest.saturating_sub(self.volume_from),
            swap_count,
            liquidity_usd_e6: liquidity.map(|v| v.to_string()),
            volume_usd_e6: volume.map(|v| v.to_string()),
            protocol_liquidity: protocol_liquidity.map(|v| v.to_string()),
        }
    }

    async fn balancer_liquidity_usd(&mut self, candidate: &Candidate) -> Option<U256> {
        let pool_id = candidate.pool_id?;
        let output = self
            .rpc
            .eth_call(
                candidate.canonical_source,
                calldata_b256("getPoolTokens(bytes32)", pool_id),
                "latest",
            )
            .await
            .ok()?;
        let balances_offset = word(&output, 1)
            .and_then(|v| u256_from_word(&v))?
            .to::<usize>();
        let balances = decode_u256_array(&output, balances_offset)?;
        if balances.len() != candidate.tokens.len() {
            return None;
        }
        let mut total = U256::ZERO;
        for (token, balance) in candidate.tokens.iter().zip(balances) {
            total = total.saturating_add(self.amount_usd_e6(*token, balance).await?);
        }
        Some(total)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut global: Value = serde_json::from_slice(
        &tokio::fs::read(&cli.global_data)
            .await
            .with_context(|| format!("read {}", cli.global_data.display()))?,
    )?;
    let rpc = Rpc::new(cli.rpc_url.clone());
    let latest = rpc.block_number().await?;
    let latest_timestamp = block_timestamp(&rpc, latest).await?;
    let from_block = cli
        .from_block
        .unwrap_or_else(|| latest.saturating_sub(cli.discovery_blocks));
    let registry = chain_registry(&global, cli.chain_id)?;
    let mut sources = canonical_sources(registry)?;
    let discovery_rpc = if cli.auto_history_rpc && !cli.skip_discovery {
        let probe_address = first_source(&sources, PoolProtocol::UniswapV3)
            .or_else(|| first_source(&sources, PoolProtocol::UniswapV4))
            .ok_or_else(|| anyhow!("no canonical source is available for RPC history probing"))?;
        select_history_rpcs(
            configured_http_rpcs(&global),
            probe_address,
            from_block,
            latest,
            cli.history_rpc_count,
        )
        .await?
    } else {
        rpc.clone()
    };
    let token_meta = token_metadata(&global, registry, cli.chain_id)?;
    let v4_state_view = router_address(registry, "UNISWAP_V4_STATE_VIEW");

    eprintln!(
        "discovering chain={} blocks={}..={} volume_window={} max_candidates={}",
        cli.chain_id, from_block, latest, cli.volume_blocks, cli.max_candidates
    );
    let enabled_protocols = parse_protocols(&cli.protocols)?;
    let mut candidates: Vec<Candidate> = existing_candidates(&global, cli.chain_id)
        .into_iter()
        .filter(|candidate| enabled_protocols.contains(&candidate.protocol))
        .collect();
    if !cli.skip_discovery
        && enabled_protocols.contains(&PoolProtocol::UniswapV3)
        && let Some(factory) = first_source(&sources, PoolProtocol::UniswapV3)
    {
        candidates
            .extend(discover_v3(&discovery_rpc, factory, from_block, latest, cli.log_chunk).await?);
    }
    if !cli.skip_discovery
        && enabled_protocols.contains(&PoolProtocol::UniswapV4)
        && let Some(manager) = first_source(&sources, PoolProtocol::UniswapV4)
    {
        candidates
            .extend(discover_v4(&discovery_rpc, manager, from_block, latest, cli.log_chunk).await?);
    }
    if !cli.skip_discovery
        && enabled_protocols.contains(&PoolProtocol::BalancerV2)
        && let Some(vault) = first_source(&sources, PoolProtocol::BalancerV2)
    {
        candidates.extend(
            discover_balancer(
                &discovery_rpc,
                &rpc,
                vault,
                from_block,
                latest,
                cli.log_chunk,
            )
            .await?,
        );
    }
    if !cli.skip_discovery
        && enabled_protocols.contains(&PoolProtocol::Curve)
        && let Some(registries) = sources.get(&PoolProtocol::Curve)
    {
        for registry in registries.clone() {
            candidates.extend(
                discover_curve(&rpc, registry, from_block, latest, cli.max_candidates).await?,
            );
        }
    }
    // Curve address providers resolve to concrete registries. Since the provider itself came from
    // the configured canonical registry set, its resolved targets retain that provenance.
    sources.entry(PoolProtocol::Curve).or_default().extend(
        candidates
            .iter()
            .filter(|candidate| candidate.protocol == PoolProtocol::Curve)
            .map(|candidate| candidate.canonical_source),
    );
    let mut unique = HashMap::new();
    for candidate in candidates {
        let identity = (candidate.protocol, candidate.pool, candidate.pool_id);
        unique
            .entry(identity)
            .and_modify(|existing: &mut Candidate| {
                let candidate_is_better = (candidate.creation_block_exact
                    && !existing.creation_block_exact)
                    || (candidate.creation_block_exact == existing.creation_block_exact
                        && candidate.created_block < existing.created_block);
                if candidate_is_better {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    let discovered_count = unique.len();
    let mut candidates: Vec<Candidate> = unique
        .into_values()
        .filter(|candidate| {
            candidate.tokens.len() >= 2
                && candidate
                    .tokens
                    .iter()
                    .all(|token| token_meta.contains_key(token))
                && candidate
                    .tokens
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .len()
                    == candidate.tokens.len()
        })
        .collect();
    candidates.sort_by_key(|candidate| (candidate.protocol as u8, candidate.created_block));
    eprintln!(
        "discovered {discovered_count} unique candidates; {} use distinct listed tokens",
        candidates.len()
    );

    let policy = PoolCurationPolicy {
        min_age_blocks: cli.min_age_blocks,
        min_liquidity_usd_e6: u128::from(cli.min_liquidity_usd) * 1_000_000,
        min_volume_usd_e6: u128::from(cli.min_volume_usd) * 1_000_000,
        min_swap_count: cli.min_swaps,
        require_usd_metrics: cli.require_usd_metrics,
        min_v4_protocol_liquidity: cli.min_v4_liquidity,
    };
    let mut metrics = MetricsContext {
        rpc: &rpc,
        latest,
        latest_timestamp,
        max_feed_age_secs: cli.max_feed_age_secs,
        volume_from: latest.saturating_sub(cli.volume_blocks),
        log_chunk: cli.log_chunk,
        token_meta,
        price_cache: HashMap::new(),
        v4_state_view,
        v4_swap_logs: None,
        v4_swap_logs_available: None,
    };
    let mut records = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        if index.is_multiple_of(25) {
            eprintln!("measuring candidate {}/{}", index + 1, candidates.len());
        }
        let old_enough = latest.saturating_sub(candidate.created_block) >= policy.min_age_blocks;
        let measured = if old_enough {
            metrics
                .metrics(
                    candidate,
                    policy.min_liquidity_usd_e6,
                    policy.min_v4_protocol_liquidity,
                )
                .await
        } else {
            PoolMetrics {
                measured_at_block: latest,
                volume_window_blocks: cli.volume_blocks,
                swap_count: 0,
                liquidity_usd_e6: None,
                volume_usd_e6: None,
                protocol_liquidity: None,
            }
        };
        let mut record = CuratedPoolRecord {
            chain_id: cli.chain_id,
            protocol: candidate.protocol,
            pool: candidate.pool,
            pool_id: candidate.pool_id,
            tokens: candidate.tokens.clone(),
            canonical_source: candidate.canonical_source,
            created_block: candidate.created_block,
            creation_block_exact: candidate.creation_block_exact,
            fee: candidate.fee,
            tick_spacing: candidate.tick_spacing,
            metrics: measured,
            eligible: false,
            rejection_reasons: Vec::new(),
        };
        policy.curate(&mut record, &sources);
        records.push(record);
    }
    if cli.max_candidates > 0 && records.len() > cli.max_candidates {
        records.sort_by_key(|record| std::cmp::Reverse(pool_record_rank(record)));
        records.truncate(cli.max_candidates);
        eprintln!(
            "retained the best {} measured candidates after curation",
            records.len()
        );
    }
    records.sort_by_key(|record| (record.protocol as u8, record.pool, record.pool_id));
    let eligible = records.iter().filter(|record| record.eligible).count();
    let summary = summary(&records);
    eprintln!("eligible {eligible}/{}; {summary}", records.len());
    let mut discovery_from_blocks = global
        .pointer("/pool_index_meta/discovery_from_blocks")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if !cli.skip_discovery {
        for protocol in &enabled_protocols {
            let key = serde_json::to_value(protocol)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| format!("{protocol:?}"));
            discovery_from_blocks.insert(key, json!(from_block));
        }
    }

    if cli.update_global_data {
        merge_global_pool_index(
            &mut global,
            cli.chain_id,
            &enabled_protocols,
            records.clone(),
        )?;
        let mut refreshed: Vec<String> = enabled_protocols
            .iter()
            .map(|protocol| {
                serde_json::to_value(protocol)
                    .ok()
                    .and_then(|value| value.as_str().map(ToOwned::to_owned))
                    .unwrap_or_else(|| format!("{protocol:?}"))
            })
            .collect();
        refreshed.sort();
        global["pool_index_meta"] = json!({
            "schema_version": 1,
            "chain_id": cli.chain_id,
            "generated_at_block": latest,
            "discovery_from_block": from_block,
            "discovery_from_blocks": discovery_from_blocks,
            "volume_window_blocks": cli.volume_blocks,
            "protocols_refreshed": refreshed,
            "skip_discovery": cli.skip_discovery,
            "policy": policy_value(&policy, cli.max_feed_age_secs),
        });
        atomic_write_json(&cli.global_data, &global).await?;
    }
    let artifact = json!({
        "schema_version": 1,
        "chain_id": cli.chain_id,
        "generated_at_block": latest,
        "discovery_from_block": from_block,
        "discovery_from_blocks": discovery_from_blocks,
        "policy": policy_value(&policy, cli.max_feed_age_secs),
        "summary": summary,
        "pool_index": records,
    });
    atomic_write_json(&cli.output, &artifact).await?;
    println!("wrote {}", cli.output.display());
    Ok(())
}

fn configured_http_rpcs(global: &Value) -> Vec<String> {
    fn visit(value: &Value, urls: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                if let Some(Value::Array(values)) = object.get("httpRpcs") {
                    urls.extend(
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned),
                    );
                }
                for child in object.values() {
                    visit(child, urls);
                }
            }
            Value::Array(values) => {
                for child in values {
                    visit(child, urls);
                }
            }
            _ => {}
        }
    }

    let mut urls = Vec::new();
    visit(global, &mut urls);
    let mut seen = HashSet::new();
    urls.retain(|url| url.starts_with("https://") && seen.insert(url.clone()));
    urls
}

async fn select_history_rpcs(
    endpoints: Vec<String>,
    probe_address: Address,
    from_block: u64,
    latest: u64,
    wanted: usize,
) -> Result<Rpc> {
    if wanted == 0 {
        bail!("--history-rpc-count must be at least one");
    }
    let probe_end = from_block.saturating_add(100).min(latest);
    let mut accepted = Vec::new();
    let total = endpoints.len();
    for endpoint in endpoints {
        let candidate = Rpc::from_urls_with_timeout(vec![endpoint.clone()], Duration::from_secs(8));
        if candidate
            .logs(probe_address, Vec::new(), from_block, probe_end, 101)
            .await
            .is_ok()
        {
            accepted.push(endpoint);
            if accepted.len() == wanted {
                break;
            }
        }
    }
    if accepted.is_empty() {
        bail!(
            "none of the {total} configured HTTP RPC endpoints served logs at block {from_block}"
        );
    }
    eprintln!(
        "selected {} history-capable RPC endpoint(s) from {} configured candidates",
        accepted.len(),
        total
    );
    Ok(Rpc::from_urls(accepted))
}

fn chain_registry(global: &Value, chain_id: u64) -> Result<&Value> {
    global
        .pointer(&format!("/address_registry/chains/{chain_id}"))
        .ok_or_else(|| anyhow!("address_registry missing chain {chain_id}"))
}

fn existing_candidates(global: &Value, chain_id: u64) -> Vec<Candidate> {
    global
        .get("pool_index")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value::<CuratedPoolRecord>(value.clone()).ok())
        .filter(|record| record.chain_id == chain_id)
        .map(|record| {
            let protocol = record.protocol;
            Candidate {
                protocol,
                pool: record.pool,
                pool_id: record.pool_id,
                tokens: record.tokens,
                canonical_source: record.canonical_source,
                created_block: record.created_block,
                // Curve registry enumeration provides an auditable conservative bound, but not
                // deployment-event proof. Normalize legacy records that predate this distinction.
                creation_block_exact: record.creation_block_exact
                    && protocol != PoolProtocol::Curve,
                fee: record.fee,
                tick_spacing: record.tick_spacing,
            }
        })
        .collect()
}

fn router_address(registry: &Value, key: &str) -> Option<Address> {
    registry
        .pointer(&format!("/routers/{key}"))
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
}

fn canonical_sources(registry: &Value) -> Result<HashMap<PoolProtocol, HashSet<Address>>> {
    let mut sources = HashMap::new();
    if let Some(factory) = router_address(registry, "UNISWAP_V3_FACTORY") {
        sources.insert(PoolProtocol::UniswapV3, HashSet::from([factory]));
    }
    if let Some(manager) = router_address(registry, "UNISWAP_V4_POOL_MANAGER") {
        sources.insert(PoolProtocol::UniswapV4, HashSet::from([manager]));
    }
    if let Some(vault) = registry
        .get("balancer_vault")
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
    {
        sources.insert(PoolProtocol::BalancerV2, HashSet::from([vault]));
    }
    let curve: HashSet<Address> = [
        "curve_registries",
        "curve_meta_registries",
        "curve_crypto_registries",
    ]
    .into_iter()
    .flat_map(|key| {
        registry
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    })
    .filter_map(Value::as_str)
    .filter_map(|value| value.parse().ok())
    .collect();
    if !curve.is_empty() {
        sources.insert(PoolProtocol::Curve, curve);
    }
    Ok(sources)
}

fn first_source(
    sources: &HashMap<PoolProtocol, HashSet<Address>>,
    protocol: PoolProtocol,
) -> Option<Address> {
    sources
        .get(&protocol)
        .and_then(|values| values.iter().copied().min())
}

fn parse_protocols(raw: &str) -> Result<HashSet<PoolProtocol>> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "uniswap_v3" | "univ3" | "v3" => Ok(PoolProtocol::UniswapV3),
            "uniswap_v4" | "univ4" | "v4" => Ok(PoolProtocol::UniswapV4),
            "balancer_v2" | "balancer" => Ok(PoolProtocol::BalancerV2),
            "curve" => Ok(PoolProtocol::Curve),
            other => bail!("unsupported protocol: {other}"),
        })
        .collect()
}

fn token_metadata(
    global: &Value,
    registry: &Value,
    chain_id: u64,
) -> Result<HashMap<Address, TokenMeta>> {
    let feeds = registry
        .get("chainlink_feeds")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut out = HashMap::new();
    for token in global
        .get("tokenlist")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(address) = token
            .pointer(&format!("/addresses/{chain_id}"))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<Address>().ok())
        else {
            continue;
        };
        let Some(decimals) = token
            .get("decimals")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
        else {
            continue;
        };
        let symbol = token
            .get("symbol")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_uppercase();
        let feed_symbol = match symbol.as_str() {
            "WETH" | "STETH" | "WSTETH" | "RETH" | "WEETH" => "ETH",
            "WBTC" | "TBTC" | "CBBTC" | "LBTC" | "EBTC" | "FBTC" => "BTC",
            other => other,
        };
        let feed = feeds
            .get(&format!("{feed_symbol}_USD"))
            .or_else(|| feeds.get(feed_symbol))
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok());
        out.insert(address, TokenMeta { decimals, feed });
    }
    if let Some(wrapped) = router_address(registry, "WRAPPED_NATIVE")
        && let Some(meta) = out.get(&wrapped).cloned()
    {
        out.insert(Address::ZERO, meta);
    }
    Ok(out)
}

async fn discover_v3(
    rpc: &Rpc,
    factory: Address,
    from: u64,
    latest: u64,
    chunk: u64,
) -> Result<Vec<Candidate>> {
    let topic = event_topic("PoolCreated(address,address,uint24,int24,address)");
    let logs = rpc
        .logs(factory, vec![Some(topic)], from, latest, chunk)
        .await?;
    let mut out = Vec::new();
    for log in logs {
        let topics = log.get("topics").and_then(Value::as_array);
        let token0 = topics
            .and_then(|v| v.get(1))
            .and_then(Value::as_str)
            .and_then(parse_topic_address);
        let token1 = topics
            .and_then(|v| v.get(2))
            .and_then(Value::as_str)
            .and_then(parse_topic_address);
        let fee = topics
            .and_then(|v| v.get(3))
            .and_then(Value::as_str)
            .and_then(parse_hex_u32_str);
        let data = log.get("data").and_then(Value::as_str).unwrap_or("0x");
        let tick_spacing = word(data, 0).and_then(|value| signed_i32_word(&value));
        let pool = word(data, 1).and_then(|value| parse_word_address(&value));
        let created_block = log
            .get("blockNumber")
            .and_then(|value| parse_hex_u64(value).ok());
        if let (
            Some(token0),
            Some(token1),
            Some(fee),
            Some(tick_spacing),
            Some(pool),
            Some(created_block),
        ) = (token0, token1, fee, tick_spacing, pool, created_block)
        {
            out.push(Candidate {
                protocol: PoolProtocol::UniswapV3,
                pool,
                pool_id: None,
                tokens: vec![token0, token1],
                canonical_source: factory,
                created_block,
                creation_block_exact: true,
                fee: Some(fee),
                tick_spacing: Some(tick_spacing),
            });
        }
    }
    Ok(out)
}

async fn discover_v4(
    rpc: &Rpc,
    manager: Address,
    from: u64,
    latest: u64,
    chunk: u64,
) -> Result<Vec<Candidate>> {
    let topic =
        event_topic("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)");
    let logs = rpc
        .logs(manager, vec![Some(topic)], from, latest, chunk)
        .await?;
    let mut out = Vec::new();
    for log in logs {
        let topics = log.get("topics").and_then(Value::as_array);
        let pool_id = topics
            .and_then(|v| v.get(1))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<B256>().ok());
        let token0 = topics
            .and_then(|v| v.get(2))
            .and_then(Value::as_str)
            .and_then(parse_topic_address);
        let token1 = topics
            .and_then(|v| v.get(3))
            .and_then(Value::as_str)
            .and_then(parse_topic_address);
        let data = log.get("data").and_then(Value::as_str).unwrap_or("0x");
        let fee = word(data, 0)
            .and_then(|value| u256_from_word(&value))
            .map(|v| v.to::<u32>());
        let tick_spacing = word(data, 1).and_then(|value| signed_i32_word(&value));
        let created_block = log
            .get("blockNumber")
            .and_then(|value| parse_hex_u64(value).ok());
        if let (
            Some(pool_id),
            Some(token0),
            Some(token1),
            Some(fee),
            Some(tick_spacing),
            Some(created_block),
        ) = (pool_id, token0, token1, fee, tick_spacing, created_block)
        {
            out.push(Candidate {
                protocol: PoolProtocol::UniswapV4,
                pool: manager,
                pool_id: Some(pool_id),
                tokens: vec![token0, token1],
                canonical_source: manager,
                created_block,
                creation_block_exact: true,
                fee: Some(fee),
                tick_spacing: Some(tick_spacing),
            });
        }
    }
    Ok(out)
}

async fn discover_balancer(
    history_rpc: &Rpc,
    state_rpc: &Rpc,
    vault: Address,
    from: u64,
    latest: u64,
    chunk: u64,
) -> Result<Vec<Candidate>> {
    let topic = event_topic("PoolRegistered(bytes32,address,uint8)");
    let logs = history_rpc
        .logs(vault, vec![Some(topic)], from, latest, chunk)
        .await?;
    let mut out = Vec::new();
    for log in logs {
        let topics = log.get("topics").and_then(Value::as_array);
        let pool_id = topics
            .and_then(|v| v.get(1))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<B256>().ok());
        let pool = topics
            .and_then(|v| v.get(2))
            .and_then(Value::as_str)
            .and_then(parse_topic_address);
        let created_block = log
            .get("blockNumber")
            .and_then(|value| parse_hex_u64(value).ok());
        if let (Some(pool_id), Some(pool), Some(created_block)) = (pool_id, pool, created_block)
            && let Some(tokens) = balancer_tokens(state_rpc, vault, pool_id).await
            && tokens.len() >= 2
        {
            out.push(Candidate {
                protocol: PoolProtocol::BalancerV2,
                pool,
                pool_id: Some(pool_id),
                tokens,
                canonical_source: vault,
                created_block,
                creation_block_exact: true,
                fee: None,
                tick_spacing: None,
            });
        }
    }
    Ok(out)
}

async fn balancer_tokens(rpc: &Rpc, vault: Address, pool_id: B256) -> Option<Vec<Address>> {
    let output = rpc
        .eth_call(
            vault,
            calldata_b256("getPoolTokens(bytes32)", pool_id),
            "latest",
        )
        .await
        .ok()?;
    let offset = word(&output, 0)
        .and_then(|value| u256_from_word(&value))?
        .to::<usize>();
    decode_address_array(&output, offset)
}

async fn discover_curve(
    rpc: &Rpc,
    configured_registry: Address,
    from: u64,
    latest: u64,
    limit: usize,
) -> Result<Vec<Candidate>> {
    let registry = match call_u256(rpc, configured_registry, "pool_count()", "latest").await {
        Ok(_) => configured_registry,
        Err(_) => call_address(rpc, configured_registry, "get_registry()")
            .await
            .with_context(|| {
                format!(
                    "Curve source {configured_registry:#x} is neither a registry nor a resolvable address provider"
                )
            })?,
    };
    let count = call_u256(rpc, registry, "pool_count()", "latest")
        .await?
        .to::<usize>();
    let mut out = Vec::new();
    for index in (0..count).rev().take(limit) {
        let pool = call_address_with_u256(rpc, registry, "pool_list(uint256)", U256::from(index))
            .await
            .ok();
        let Some(pool) = pool.filter(|address| *address != Address::ZERO) else {
            continue;
        };
        let mut tokens = Vec::new();
        for coin in 0..8usize {
            let token = call_address_with_u256(rpc, pool, "coins(uint256)", U256::from(coin))
                .await
                .ok();
            match token {
                Some(token) if token != Address::ZERO && !tokens.contains(&token) => {
                    tokens.push(token)
                }
                _ => break,
            }
        }
        if tokens.len() < 2 {
            continue;
        }
        let (created_block, _) = first_code_block(rpc, pool, from, latest)
            .await
            .unwrap_or((from, false));
        out.push(Candidate {
            protocol: PoolProtocol::Curve,
            pool,
            pool_id: None,
            tokens,
            canonical_source: registry,
            created_block,
            // Registry enumeration has no deployment event proof. On pruned state providers the
            // code-search boundary is a conservative upper bound, not an exact creation block.
            creation_block_exact: false,
            fee: None,
            tick_spacing: None,
        });
    }
    Ok(out)
}

async fn first_code_block(
    rpc: &Rpc,
    address: Address,
    floor: u64,
    latest: u64,
) -> Option<(u64, bool)> {
    let mut low = floor;
    let mut high = latest;
    let code_at_floor = rpc
        .call(
            "eth_getCode",
            json!([format!("{address:#x}"), hex_u64(floor)]),
        )
        .await
        .ok()?
        .as_str()?
        .to_string();
    if code_at_floor != "0x" && code_at_floor != "0x0" {
        return Some((floor, false));
    }
    while low < high {
        let mid = low + (high - low) / 2;
        let code = rpc
            .call(
                "eth_getCode",
                json!([format!("{address:#x}"), hex_u64(mid)]),
            )
            .await
            .ok()?
            .as_str()?
            .to_string();
        if code == "0x" || code == "0x0" {
            low = mid.saturating_add(1);
        } else {
            high = mid;
        }
    }
    Some((low, true))
}

fn merge_global_pool_index(
    global: &mut Value,
    chain_id: u64,
    refreshed_protocols: &HashSet<PoolProtocol>,
    records: Vec<CuratedPoolRecord>,
) -> Result<()> {
    let mut retained: Vec<Value> = global
        .get("pool_index")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            if entry.get("chain_id").and_then(Value::as_u64) != Some(chain_id) {
                return true;
            }
            entry
                .get("protocol")
                .cloned()
                .and_then(|value| serde_json::from_value::<PoolProtocol>(value).ok())
                .is_none_or(|protocol| !refreshed_protocols.contains(&protocol))
        })
        .cloned()
        .collect();
    retained.extend(
        records
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
    );
    global["pool_index"] = Value::Array(retained);
    Ok(())
}

async fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("pool-index"),
        std::process::id()
    ));
    let bytes = serde_json::to_vec_pretty(value)?;
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn summary(records: &[CuratedPoolRecord]) -> String {
    let mut counts: HashMap<PoolProtocol, (usize, usize)> = HashMap::new();
    for record in records {
        let count = counts.entry(record.protocol).or_default();
        count.0 += 1;
        count.1 += usize::from(record.eligible);
    }
    let mut parts: Vec<String> = counts
        .into_iter()
        .map(|(protocol, (total, eligible))| format!("{protocol:?}={eligible}/{total}"))
        .collect();
    parts.sort();
    parts.join(",")
}

fn pool_record_rank(record: &CuratedPoolRecord) -> (bool, U256, U256, u64) {
    let liquidity = record
        .metrics
        .liquidity_usd_e6
        .as_deref()
        .or(record.metrics.protocol_liquidity.as_deref())
        .and_then(|value| value.parse().ok())
        .unwrap_or(U256::ZERO);
    let volume = record
        .metrics
        .volume_usd_e6
        .as_deref()
        .and_then(|value| value.parse().ok())
        .unwrap_or(U256::ZERO);
    (
        record.eligible,
        liquidity,
        volume,
        record.metrics.swap_count,
    )
}

fn policy_value(policy: &PoolCurationPolicy, max_feed_age_secs: u64) -> Value {
    json!({
        "min_age_blocks": policy.min_age_blocks,
        "min_liquidity_usd_e6": policy.min_liquidity_usd_e6.to_string(),
        "min_volume_usd_e6": policy.min_volume_usd_e6.to_string(),
        "min_swap_count": policy.min_swap_count,
        "require_usd_metrics": policy.require_usd_metrics,
        "min_v4_protocol_liquidity": policy.min_v4_protocol_liquidity.to_string(),
        "max_feed_age_secs": max_feed_age_secs,
    })
}

fn event_topic(signature: &str) -> String {
    format!("{:#x}", keccak256(signature.as_bytes()))
}

fn selector_data(signature: &str) -> String {
    format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
}

fn calldata_b256(signature: &str, value: B256) -> String {
    format!("{}{}", selector_data(signature), hex::encode(value))
}

fn calldata_u256(signature: &str, value: U256) -> String {
    format!("{}{:064x}", selector_data(signature), value)
}

fn calldata_address(signature: &str, value: Address) -> String {
    format!("{}{:0>64}", selector_data(signature), hex::encode(value))
}

async fn call_u256(rpc: &Rpc, to: Address, signature: &str, block: &str) -> Result<U256> {
    let output = rpc.eth_call(to, selector_data(signature), block).await?;
    word(&output, 0)
        .and_then(|value| u256_from_word(&value))
        .ok_or_else(|| anyhow!("invalid uint256 response from {signature}"))
}

async fn block_timestamp(rpc: &Rpc, block: u64) -> Result<u64> {
    let value = rpc
        .call("eth_getBlockByNumber", json!([hex_u64(block), false]))
        .await?;
    let timestamp = value
        .get("timestamp")
        .ok_or_else(|| anyhow!("latest block missing timestamp"))?;
    parse_hex_u64(timestamp)
}

async fn call_address(rpc: &Rpc, to: Address, signature: &str) -> Result<Address> {
    let output = rpc.eth_call(to, selector_data(signature), "latest").await?;
    word(&output, 0)
        .and_then(|value| parse_word_address(&value))
        .ok_or_else(|| anyhow!("invalid address response from {signature}"))
}

async fn call_u256_with_address(
    rpc: &Rpc,
    to: Address,
    signature: &str,
    value: Address,
) -> Result<U256> {
    let output = rpc
        .eth_call(to, calldata_address(signature, value), "latest")
        .await?;
    word(&output, 0)
        .and_then(|value| u256_from_word(&value))
        .ok_or_else(|| anyhow!("invalid uint256 response from {signature}"))
}

async fn call_u256_with_b256(rpc: &Rpc, to: Address, signature: &str, value: B256) -> Result<U256> {
    let output = rpc
        .eth_call(to, calldata_b256(signature, value), "latest")
        .await?;
    word(&output, 0)
        .and_then(|value| u256_from_word(&value))
        .ok_or_else(|| anyhow!("invalid uint256 response from {signature}"))
}

async fn call_address_with_u256(
    rpc: &Rpc,
    to: Address,
    signature: &str,
    value: U256,
) -> Result<Address> {
    let output = rpc
        .eth_call(to, calldata_u256(signature, value), "latest")
        .await?;
    word(&output, 0)
        .and_then(|value| parse_word_address(&value))
        .ok_or_else(|| anyhow!("invalid address response from {signature}"))
}

fn word(data: &str, index: usize) -> Option<Vec<u8>> {
    let bytes = hex::decode(data.trim_start_matches("0x")).ok()?;
    let start = index.checked_mul(32)?;
    bytes.get(start..start + 32).map(ToOwned::to_owned)
}

fn u256_from_word(word: &[u8]) -> Option<U256> {
    (word.len() == 32).then(|| U256::from_be_slice(word))
}

fn signed_abs_word(data: &str, index: usize) -> Option<U256> {
    let value = word(data, index)?;
    let negative = value.first().is_some_and(|byte| byte & 0x80 != 0);
    let unsigned = U256::from_be_slice(&value);
    if negative {
        Some((!unsigned).saturating_add(U256::from(1u8)))
    } else {
        Some(unsigned)
    }
}

fn signed_i32_word(word: &[u8]) -> Option<i32> {
    let tail: [u8; 4] = word.get(28..32)?.try_into().ok()?;
    Some(i32::from_be_bytes(tail))
}

fn parse_word_address(word: &[u8]) -> Option<Address> {
    Address::try_from(word.get(12..32)?).ok()
}

fn parse_topic_address(value: &str) -> Option<Address> {
    let bytes = hex::decode(value.trim_start_matches("0x")).ok()?;
    parse_word_address(&bytes)
}

fn parse_hex_u32_str(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn parse_hex_u64(value: &Value) -> Result<u64> {
    let value = value
        .as_str()
        .ok_or_else(|| anyhow!("expected hex string"))?;
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(Into::into)
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn pow10(decimals: u8) -> Option<U256> {
    if decimals > 77 {
        return None;
    }
    let mut value = U256::from(1u8);
    for _ in 0..decimals {
        value = value.saturating_mul(U256::from(10u8));
    }
    Some(value)
}

fn u256_to_u8(value: U256) -> Option<u8> {
    (value <= U256::from(u8::MAX)).then(|| value.to::<u8>())
}

fn decode_address_array(data: &str, byte_offset: usize) -> Option<Vec<Address>> {
    let bytes = hex::decode(data.trim_start_matches("0x")).ok()?;
    let length = U256::from_be_slice(bytes.get(byte_offset..byte_offset + 32)?).to::<usize>();
    (0..length)
        .map(|index| {
            let start = byte_offset + 32 + index * 32;
            Address::try_from(bytes.get(start + 12..start + 32)?).ok()
        })
        .collect()
}

fn decode_u256_array(data: &str, byte_offset: usize) -> Option<Vec<U256>> {
    let bytes = hex::decode(data.trim_start_matches("0x")).ok()?;
    let length = U256::from_be_slice(bytes.get(byte_offset..byte_offset + 32)?).to::<usize>();
    (0..length)
        .map(|index| {
            let start = byte_offset + 32 + index * 32;
            Some(U256::from_be_slice(bytes.get(start..start + 32)?))
        })
        .collect()
}
