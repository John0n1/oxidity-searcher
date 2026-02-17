// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::primitives::{Address, U256};
use clap::Parser;
use oxidity_searcher::app::config::GlobalSettings;
use oxidity_searcher::app::logging::setup_logging;
use oxidity_searcher::domain::error::AppError;
use oxidity_searcher::infrastructure::data::db::Database;
use oxidity_searcher::services::strategy::decode::{RouterKind, decode_swap_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(author, version, about = "Historical block-window replay harness")]
struct Cli {
    /// Path to config file (default: config.* detection)
    #[arg(long)]
    config: Option<String>,

    /// Chain id to replay (defaults to first configured chain)
    #[arg(long)]
    chain_id: Option<u64>,

    /// Inclusive start block. If unset, start is derived from latest-lookback_blocks+1.
    #[arg(long)]
    start_block: Option<u64>,

    /// Inclusive end block. If unset, end defaults to latest.
    #[arg(long)]
    end_block: Option<u64>,

    /// Lookback blocks when start_block is omitted.
    #[arg(long, default_value_t = 20_000)]
    lookback_blocks: u64,

    /// Number of blocks per replay window.
    #[arg(long, default_value_t = 250)]
    window_size: u64,

    /// Include unknown router addresses in decode attempts.
    #[arg(long, default_value_t = false)]
    include_unknown_routers: bool,

    /// Enable historical trace simulation (debug_traceCall at block-1).
    #[arg(long, default_value_t = false)]
    trace_sim: bool,

    /// Max decoded transactions to trace-simulate per window.
    #[arg(long, default_value_t = 24)]
    trace_sim_sample_per_window: usize,

    /// Fallback to eth_call(block-1) when debug_traceCall is unavailable.
    #[arg(long, default_value_t = true)]
    trace_sim_fallback_eth_call: bool,

    /// Output path for full JSON replay report.
    #[arg(long, default_value = "historical-replay-report.json")]
    out: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplayStressProfile {
    UltraLow,
    Low,
    Normal,
    Elevated,
    High,
}

impl ReplayStressProfile {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UltraLow => "ultra_low",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CalibrationSuggestion {
    stress_profile: String,
    slippage_bps_default: u64,
    gas_cap_multiplier_bps: u64,
    profit_guard_base_floor_multiplier_bps: u64,
    profit_guard_cost_multiplier_bps: u64,
    profit_guard_min_margin_bps: u64,
    liquidity_ratio_floor_ppm: u64,
}

#[derive(Clone, Debug, Serialize)]
struct WindowReport {
    window_index: usize,
    start_block: u64,
    end_block: u64,
    blocks: usize,
    tx_total: u64,
    tx_candidate: u64,
    tx_decoded: u64,
    decode_rate: f64,
    decoded_v2: u64,
    decoded_v3: u64,
    unique_candidate_routers: usize,
    base_fee_gwei_p50: f64,
    base_fee_gwei_p95: f64,
    gas_used_ratio_avg: f64,
    trace_sim_enabled: bool,
    trace_attempted: u64,
    trace_success: u64,
    trace_revert: u64,
    trace_error: u64,
    trace_unavailable: u64,
    trace_success_rate: f64,
    trace_gas_used_p50: Option<u64>,
    trace_gas_used_p95: Option<u64>,
    trace_source_debug: u64,
    trace_source_eth_call: u64,
    stress_profile: String,
    suggestion: CalibrationSuggestion,
}

struct ReplayWindowInput<'a> {
    window_index: usize,
    start_block: u64,
    end_block: u64,
    known_routers: &'a HashSet<Address>,
    include_unknown_routers: bool,
    trace_cfg: TraceConfig,
    trace_available: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ReplaySummary {
    chain_id: u64,
    http_provider: String,
    start_block: u64,
    end_block: u64,
    window_size: u64,
    windows: usize,
    tx_total: u64,
    tx_candidate: u64,
    tx_decoded: u64,
    decode_rate: f64,
    decoded_v2: u64,
    decoded_v3: u64,
    trace_sim_enabled: bool,
    trace_attempted: u64,
    trace_success: u64,
    trace_revert: u64,
    trace_error: u64,
    trace_unavailable: u64,
    trace_success_rate: f64,
    trace_source_debug: u64,
    trace_source_eth_call: u64,
    stress_profile_counts: HashMap<String, u64>,
}

#[derive(Clone, Debug, Serialize)]
struct ReplayReport {
    generated_at_unix: i64,
    summary: ReplaySummary,
    windows: Vec<WindowReport>,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    result: Option<serde_json::Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcBlock {
    number: String,
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: Option<String>,
    #[serde(rename = "gasUsed")]
    gas_used: String,
    #[serde(rename = "gasLimit")]
    gas_limit: String,
    transactions: Vec<RpcTx>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcTx {
    from: Option<String>,
    to: Option<String>,
    gas: Option<String>,
    #[serde(rename = "gasPrice")]
    gas_price: Option<String>,
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: Option<String>,
    nonce: Option<String>,
    input: String,
    value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceSource {
    DebugTraceCall,
    EthCall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceKind {
    Success,
    Revert,
    Error,
    Unavailable,
}

#[derive(Clone, Debug)]
struct TraceSimSample {
    kind: TraceKind,
    source: TraceSource,
    gas_used: Option<u64>,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
struct TraceWorkItem {
    block_number: u64,
    tx: RpcTx,
}

#[derive(Clone, Copy, Debug)]
struct TraceConfig {
    enabled: bool,
    sample_per_window: usize,
    fallback_eth_call: bool,
}

#[derive(Clone)]
struct JsonRpcClient {
    client: Client,
    http_provider: String,
}

impl JsonRpcClient {
    fn new(http_provider: String) -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Initialization(format!("RPC client init failed: {e}")))?;
        Ok(Self {
            client,
            http_provider,
        })
    }

    async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let resp = self
            .client
            .post(&self.http_provider)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("RPC request failed ({method}): {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::ApiCall {
                provider: "historical_replay_rpc".into(),
                status: resp.status().as_u16(),
            });
        }
        let body: RpcEnvelope = resp
            .json()
            .await
            .map_err(|e| AppError::Initialization(format!("RPC decode failed ({method}): {e}")))?;
        if let Some(err) = body.error {
            return Err(AppError::Initialization(format!(
                "RPC returned error for {method}: code={} message={}",
                err.code, err.message
            )));
        }
        Ok(body.result.unwrap_or(serde_json::Value::Null))
    }

    async fn block_number(&self) -> Result<u64, AppError> {
        let result = self.request("eth_blockNumber", json!([])).await?;
        let hex = result.as_str().ok_or_else(|| {
            AppError::Initialization("eth_blockNumber result was not string".into())
        })?;
        parse_u64_hex(hex).ok_or_else(|| {
            AppError::Initialization(format!("Invalid eth_blockNumber hex value: {hex}"))
        })
    }

    async fn block_with_txs(&self, block_number: u64) -> Result<RpcBlock, AppError> {
        let tag = format!("0x{block_number:x}");
        let result = self
            .request("eth_getBlockByNumber", json!([tag, true]))
            .await?;
        serde_json::from_value(result).map_err(|e| {
            AppError::Initialization(format!(
                "eth_getBlockByNumber decode failed for block {block_number}: {e}"
            ))
        })
    }

    async fn trace_call(
        &self,
        tx: &RpcTx,
        block_number: u64,
        fallback_eth_call: bool,
    ) -> Result<TraceSimSample, AppError> {
        let call = tx_to_call_object(tx);
        let block_tag = format!("0x{block_number:x}");
        match self
            .request("debug_traceCall", json!([call, block_tag, {}]))
            .await
        {
            Ok(result) => Ok(parse_debug_trace_result(&result)),
            Err(e) => {
                if rpc_method_unavailable(&e) {
                    if fallback_eth_call {
                        return self.eth_call_fallback(tx, block_number).await;
                    }
                    return Ok(TraceSimSample {
                        kind: TraceKind::Unavailable,
                        source: TraceSource::DebugTraceCall,
                        gas_used: None,
                        reason: Some("debug_traceCall unavailable".into()),
                    });
                }
                Ok(TraceSimSample {
                    kind: TraceKind::Error,
                    source: TraceSource::DebugTraceCall,
                    gas_used: None,
                    reason: Some(e.to_string()),
                })
            }
        }
    }

    async fn eth_call_fallback(
        &self,
        tx: &RpcTx,
        block_number: u64,
    ) -> Result<TraceSimSample, AppError> {
        let call = tx_to_call_object(tx);
        let block_tag = format!("0x{block_number:x}");
        match self.request("eth_call", json!([call, block_tag])).await {
            Ok(result) => {
                if let Some(ret) = result.as_str() {
                    return Ok(TraceSimSample {
                        kind: TraceKind::Success,
                        source: TraceSource::EthCall,
                        gas_used: None,
                        reason: Some(format!("eth_call_return_len={}", ret.len())),
                    });
                }
                Ok(TraceSimSample {
                    kind: TraceKind::Success,
                    source: TraceSource::EthCall,
                    gas_used: None,
                    reason: None,
                })
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                let kind = if msg.contains("revert")
                    || msg.contains("execution reverted")
                    || msg.contains("vm execution error")
                {
                    TraceKind::Revert
                } else if rpc_method_unavailable(&e) {
                    TraceKind::Unavailable
                } else {
                    TraceKind::Error
                };
                Ok(TraceSimSample {
                    kind,
                    source: TraceSource::EthCall,
                    gas_used: None,
                    reason: Some(e.to_string()),
                })
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let settings = GlobalSettings::load_with_path(cli.config.as_deref())?;
    setup_logging(if settings.debug { "debug" } else { "info" }, false);

    let chain_id = resolve_chain_id(&settings, cli.chain_id)?;
    let http_provider = settings.get_http_provider(chain_id)?;
    let rpc = JsonRpcClient::new(http_provider.clone())?;

    let latest = rpc.block_number().await?;
    let (start_block, end_block) = resolve_range(&cli, latest)?;
    let windows = build_windows(start_block, end_block, cli.window_size.max(1));
    let trace_cfg = TraceConfig {
        enabled: cli.trace_sim,
        sample_per_window: cli.trace_sim_sample_per_window.max(1),
        fallback_eth_call: cli.trace_sim_fallback_eth_call,
    };
    let mut trace_available = trace_cfg.enabled;

    let mut routers: HashSet<Address> = settings
        .routers_for_chain(chain_id)?
        .values()
        .copied()
        .collect();
    let db = Database::new(&settings.database_url()).await?;
    if let Ok(dynamic_approved) = db.approved_routers(chain_id).await {
        for addr in dynamic_approved {
            routers.insert(addr);
        }
    }

    tracing::info!(
        target: "replay",
        chain_id,
        start_block,
        end_block,
        windows = windows.len(),
        window_size = cli.window_size,
        known_routers = routers.len(),
        include_unknown = cli.include_unknown_routers,
        trace_sim = trace_cfg.enabled,
        trace_sample_per_window = trace_cfg.sample_per_window,
        trace_fallback_eth_call = trace_cfg.fallback_eth_call,
        "Starting historical block-window replay"
    );

    let mut reports = Vec::with_capacity(windows.len());
    for (idx, (w_start, w_end)) in windows.iter().copied().enumerate() {
        let input = ReplayWindowInput {
            window_index: idx + 1,
            start_block: w_start,
            end_block: w_end,
            known_routers: &routers,
            include_unknown_routers: cli.include_unknown_routers,
            trace_cfg,
            trace_available,
        };
        let report = replay_window(&rpc, input).await?;
        if report.trace_unavailable > 0 {
            trace_available = false;
            tracing::warn!(
                target: "replay",
                window = idx + 1,
                "Trace simulation became unavailable; disabling for remaining windows"
            );
        }
        print_window_line(&report);
        reports.push(report);
    }

    let summary = summarize(
        chain_id,
        &http_provider,
        start_block,
        end_block,
        cli.window_size,
        &reports,
    );
    let report = ReplayReport {
        generated_at_unix: chrono::Utc::now().timestamp(),
        summary,
        windows: reports,
    };

    let json_out = serde_json::to_string_pretty(&report)
        .map_err(|e| AppError::Initialization(format!("Replay report encode failed: {e}")))?;
    std::fs::write(&cli.out, json_out)
        .map_err(|e| AppError::Initialization(format!("Replay report write failed: {e}")))?;

    println!(
        "Replay completed: chain={} range=[{}..{}] windows={} report={}",
        report.summary.chain_id,
        report.summary.start_block,
        report.summary.end_block,
        report.summary.windows,
        cli.out.display()
    );
    println!(
        "Decoded {}/{} candidate txs ({:.2}%)",
        report.summary.tx_decoded,
        report.summary.tx_candidate,
        report.summary.decode_rate * 100.0
    );
    if report.summary.trace_sim_enabled {
        println!(
            "Trace sim {}/{} success ({:.2}%) [revert={}, error={}, unavailable={}, source_debug={}, source_eth_call={}]",
            report.summary.trace_success,
            report.summary.trace_attempted,
            report.summary.trace_success_rate * 100.0,
            report.summary.trace_revert,
            report.summary.trace_error,
            report.summary.trace_unavailable,
            report.summary.trace_source_debug,
            report.summary.trace_source_eth_call
        );
    }
    Ok(())
}

fn resolve_chain_id(
    settings: &GlobalSettings,
    override_chain: Option<u64>,
) -> Result<u64, AppError> {
    if let Some(chain) = override_chain {
        return Ok(chain);
    }
    if let Some(chain) = settings.chains.first().copied() {
        return Ok(chain);
    }
    Err(AppError::Config(
        "No chain configured. Set CHAINS or pass --chain-id".into(),
    ))
}

fn resolve_range(cli: &Cli, latest: u64) -> Result<(u64, u64), AppError> {
    if let Some(start) = cli.start_block {
        let end = cli.end_block.unwrap_or(latest);
        return if start <= end {
            Ok((start, end))
        } else {
            Ok((end, start))
        };
    }
    let end = cli.end_block.unwrap_or(latest);
    let lookback = cli.lookback_blocks.max(1);
    let start = end.saturating_sub(lookback.saturating_sub(1));
    Ok((start, end))
}

fn build_windows(start_block: u64, end_block: u64, window_size: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut cursor = start_block;
    while cursor <= end_block {
        let end = cursor
            .saturating_add(window_size.saturating_sub(1))
            .min(end_block);
        out.push((cursor, end));
        if end == u64::MAX {
            break;
        }
        cursor = end.saturating_add(1);
    }
    out
}

async fn replay_window(
    rpc: &JsonRpcClient,
    input: ReplayWindowInput<'_>,
) -> Result<WindowReport, AppError> {
    let ReplayWindowInput {
        window_index,
        start_block,
        end_block,
        known_routers,
        include_unknown_routers,
        trace_cfg,
        trace_available,
    } = input;

    let mut tx_total = 0u64;
    let mut tx_candidate = 0u64;
    let mut tx_decoded = 0u64;
    let mut decoded_v2 = 0u64;
    let mut decoded_v3 = 0u64;
    let mut candidate_routers = HashSet::new();
    let mut base_fees_gwei = Vec::new();
    let mut gas_ratios = Vec::new();
    let mut trace_items: Vec<TraceWorkItem> = Vec::new();

    for block_number in start_block..=end_block {
        let block = rpc.block_with_txs(block_number).await?;
        let _bn = parse_u64_hex(&block.number).unwrap_or(block_number);
        if let Some(base) = block.base_fee_per_gas.as_deref().and_then(parse_u128_hex) {
            base_fees_gwei.push((base as f64) / 1e9f64);
        }
        if let (Some(gas_used), Some(gas_limit)) = (
            parse_u128_hex(&block.gas_used),
            parse_u128_hex(&block.gas_limit),
        ) && gas_limit > 0
        {
            gas_ratios.push(gas_used as f64 / gas_limit as f64);
        }

        tx_total = tx_total.saturating_add(block.transactions.len() as u64);
        for tx in block.transactions {
            let Some(to) = tx.to.as_deref().and_then(parse_address) else {
                continue;
            };
            if !include_unknown_routers && !known_routers.contains(&to) {
                continue;
            }

            let input = decode_hex_bytes(&tx.input);
            if input.len() < 4 {
                continue;
            }
            tx_candidate = tx_candidate.saturating_add(1);
            candidate_routers.insert(to);
            let value = parse_u256_hex(&tx.value).unwrap_or(U256::ZERO);
            if let Some(observed) = decode_swap_input(to, &input, value) {
                tx_decoded = tx_decoded.saturating_add(1);
                match observed.router_kind {
                    RouterKind::V2Like => decoded_v2 = decoded_v2.saturating_add(1),
                    RouterKind::V3Like => decoded_v3 = decoded_v3.saturating_add(1),
                }
                if trace_cfg.enabled
                    && trace_available
                    && trace_items.len() < trace_cfg.sample_per_window
                {
                    trace_items.push(TraceWorkItem {
                        block_number,
                        tx: tx.clone(),
                    });
                }
            }
        }
    }

    let mut trace_attempted = 0u64;
    let mut trace_success = 0u64;
    let mut trace_revert = 0u64;
    let mut trace_error = 0u64;
    let mut trace_unavailable = 0u64;
    let mut trace_source_debug = 0u64;
    let mut trace_source_eth_call = 0u64;
    let mut trace_gas_used = Vec::new();

    if trace_cfg.enabled && trace_available {
        for item in trace_items {
            trace_attempted = trace_attempted.saturating_add(1);
            let at_block = item.block_number.saturating_sub(1);
            let sim = rpc
                .trace_call(&item.tx, at_block, trace_cfg.fallback_eth_call)
                .await?;
            if let Some(gas) = sim.gas_used {
                trace_gas_used.push(gas);
            }
            match sim.source {
                TraceSource::DebugTraceCall => {
                    trace_source_debug = trace_source_debug.saturating_add(1);
                }
                TraceSource::EthCall => {
                    trace_source_eth_call = trace_source_eth_call.saturating_add(1);
                }
            }
            match sim.kind {
                TraceKind::Success => trace_success = trace_success.saturating_add(1),
                TraceKind::Revert => trace_revert = trace_revert.saturating_add(1),
                TraceKind::Error => trace_error = trace_error.saturating_add(1),
                TraceKind::Unavailable => trace_unavailable = trace_unavailable.saturating_add(1),
            }
            if let Some(reason) = sim.reason {
                tracing::debug!(
                    target: "replay_trace",
                    window = window_index,
                    at_block,
                    kind = ?sim.kind,
                    source = ?sim.source,
                    reason = %reason,
                    "Trace replay sample result"
                );
            }
        }
    }

    let decode_rate = if tx_candidate == 0 {
        0.0
    } else {
        tx_decoded as f64 / tx_candidate as f64
    };
    let base_fee_p50 = percentile(&base_fees_gwei, 0.50).unwrap_or(0.0);
    let base_fee_p95 = percentile(&base_fees_gwei, 0.95).unwrap_or(0.0);
    let gas_ratio_avg = mean(&gas_ratios).unwrap_or(0.0);
    let trace_success_rate = if trace_attempted == 0 {
        0.0
    } else {
        trace_success as f64 / trace_attempted as f64
    };
    let trace_gas_used_p50 = percentile_u64(&trace_gas_used, 0.50);
    let trace_gas_used_p95 = percentile_u64(&trace_gas_used, 0.95);
    let stress = classify_stress(base_fee_p50, gas_ratio_avg);
    let suggestion = suggestion_for_stress(&stress);

    Ok(WindowReport {
        window_index,
        start_block,
        end_block,
        blocks: (end_block.saturating_sub(start_block).saturating_add(1)) as usize,
        tx_total,
        tx_candidate,
        tx_decoded,
        decode_rate,
        decoded_v2,
        decoded_v3,
        unique_candidate_routers: candidate_routers.len(),
        base_fee_gwei_p50: base_fee_p50,
        base_fee_gwei_p95: base_fee_p95,
        gas_used_ratio_avg: gas_ratio_avg,
        trace_sim_enabled: trace_cfg.enabled && trace_available,
        trace_attempted,
        trace_success,
        trace_revert,
        trace_error,
        trace_unavailable,
        trace_success_rate,
        trace_gas_used_p50,
        trace_gas_used_p95,
        trace_source_debug,
        trace_source_eth_call,
        stress_profile: stress.as_str().to_string(),
        suggestion,
    })
}

fn summarize(
    chain_id: u64,
    http_provider: &str,
    start_block: u64,
    end_block: u64,
    window_size: u64,
    windows: &[WindowReport],
) -> ReplaySummary {
    let mut tx_total = 0u64;
    let mut tx_candidate = 0u64;
    let mut tx_decoded = 0u64;
    let mut decoded_v2 = 0u64;
    let mut decoded_v3 = 0u64;
    let mut trace_attempted = 0u64;
    let mut trace_success = 0u64;
    let mut trace_revert = 0u64;
    let mut trace_error = 0u64;
    let mut trace_unavailable = 0u64;
    let mut trace_source_debug = 0u64;
    let mut trace_source_eth_call = 0u64;
    let mut trace_sim_enabled = false;
    let mut stress_profile_counts: HashMap<String, u64> = HashMap::new();
    for w in windows {
        tx_total = tx_total.saturating_add(w.tx_total);
        tx_candidate = tx_candidate.saturating_add(w.tx_candidate);
        tx_decoded = tx_decoded.saturating_add(w.tx_decoded);
        decoded_v2 = decoded_v2.saturating_add(w.decoded_v2);
        decoded_v3 = decoded_v3.saturating_add(w.decoded_v3);
        trace_attempted = trace_attempted.saturating_add(w.trace_attempted);
        trace_success = trace_success.saturating_add(w.trace_success);
        trace_revert = trace_revert.saturating_add(w.trace_revert);
        trace_error = trace_error.saturating_add(w.trace_error);
        trace_unavailable = trace_unavailable.saturating_add(w.trace_unavailable);
        trace_source_debug = trace_source_debug.saturating_add(w.trace_source_debug);
        trace_source_eth_call = trace_source_eth_call.saturating_add(w.trace_source_eth_call);
        if w.trace_sim_enabled {
            trace_sim_enabled = true;
        }
        stress_profile_counts
            .entry(w.stress_profile.clone())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }
    let decode_rate = if tx_candidate == 0 {
        0.0
    } else {
        tx_decoded as f64 / tx_candidate as f64
    };
    let trace_success_rate = if trace_attempted == 0 {
        0.0
    } else {
        trace_success as f64 / trace_attempted as f64
    };

    ReplaySummary {
        chain_id,
        http_provider: http_provider.to_string(),
        start_block,
        end_block,
        window_size,
        windows: windows.len(),
        tx_total,
        tx_candidate,
        tx_decoded,
        decode_rate,
        decoded_v2,
        decoded_v3,
        trace_sim_enabled,
        trace_attempted,
        trace_success,
        trace_revert,
        trace_error,
        trace_unavailable,
        trace_success_rate,
        trace_source_debug,
        trace_source_eth_call,
        stress_profile_counts,
    }
}

fn classify_stress(base_fee_p50_gwei: f64, gas_ratio_avg: f64) -> ReplayStressProfile {
    let mut score: i32 = if base_fee_p50_gwei <= 0.15 {
        0
    } else if base_fee_p50_gwei <= 2.0 {
        1
    } else if base_fee_p50_gwei <= 20.0 {
        2
    } else if base_fee_p50_gwei <= 60.0 {
        3
    } else {
        4
    };

    if gas_ratio_avg > 1.12 {
        score += 2;
    } else if gas_ratio_avg > 0.98 {
        score += 1;
    } else if gas_ratio_avg < 0.55 {
        score -= 1;
    }

    match score.clamp(0, 4) {
        0 => ReplayStressProfile::UltraLow,
        1 => ReplayStressProfile::Low,
        2 => ReplayStressProfile::Normal,
        3 => ReplayStressProfile::Elevated,
        _ => ReplayStressProfile::High,
    }
}

fn suggestion_for_stress(profile: &ReplayStressProfile) -> CalibrationSuggestion {
    match profile {
        ReplayStressProfile::UltraLow => CalibrationSuggestion {
            stress_profile: profile.as_str().to_string(),
            slippage_bps_default: 45,
            gas_cap_multiplier_bps: 10_000,
            profit_guard_base_floor_multiplier_bps: 9_500,
            profit_guard_cost_multiplier_bps: 10_000,
            profit_guard_min_margin_bps: 600,
            liquidity_ratio_floor_ppm: 650,
        },
        ReplayStressProfile::Low => CalibrationSuggestion {
            stress_profile: profile.as_str().to_string(),
            slippage_bps_default: 55,
            gas_cap_multiplier_bps: 10_500,
            profit_guard_base_floor_multiplier_bps: 10_000,
            profit_guard_cost_multiplier_bps: 10_100,
            profit_guard_min_margin_bps: 700,
            liquidity_ratio_floor_ppm: 700,
        },
        ReplayStressProfile::Normal => CalibrationSuggestion {
            stress_profile: profile.as_str().to_string(),
            slippage_bps_default: 70,
            gas_cap_multiplier_bps: 11_000,
            profit_guard_base_floor_multiplier_bps: 10_500,
            profit_guard_cost_multiplier_bps: 10_300,
            profit_guard_min_margin_bps: 900,
            liquidity_ratio_floor_ppm: 850,
        },
        ReplayStressProfile::Elevated => CalibrationSuggestion {
            stress_profile: profile.as_str().to_string(),
            slippage_bps_default: 90,
            gas_cap_multiplier_bps: 11_750,
            profit_guard_base_floor_multiplier_bps: 11_250,
            profit_guard_cost_multiplier_bps: 10_700,
            profit_guard_min_margin_bps: 1_100,
            liquidity_ratio_floor_ppm: 1_000,
        },
        ReplayStressProfile::High => CalibrationSuggestion {
            stress_profile: profile.as_str().to_string(),
            slippage_bps_default: 120,
            gas_cap_multiplier_bps: 12_500,
            profit_guard_base_floor_multiplier_bps: 12_000,
            profit_guard_cost_multiplier_bps: 11_000,
            profit_guard_min_margin_bps: 1_300,
            liquidity_ratio_floor_ppm: 1_150,
        },
    }
}

fn print_window_line(report: &WindowReport) {
    if report.trace_attempted > 0 {
        println!(
            "[window {:>3}] blocks {}..{} tx={} cand={} dec={} ({:.2}%) trace={}/{} ({:.2}%) base_p50={:.4}gwei util={:.3} stress={}",
            report.window_index,
            report.start_block,
            report.end_block,
            report.tx_total,
            report.tx_candidate,
            report.tx_decoded,
            report.decode_rate * 100.0,
            report.trace_success,
            report.trace_attempted,
            report.trace_success_rate * 100.0,
            report.base_fee_gwei_p50,
            report.gas_used_ratio_avg,
            report.stress_profile
        );
    } else {
        println!(
            "[window {:>3}] blocks {}..{} tx={} cand={} dec={} ({:.2}%) base_p50={:.4}gwei util={:.3} stress={}",
            report.window_index,
            report.start_block,
            report.end_block,
            report.tx_total,
            report.tx_candidate,
            report.tx_decoded,
            report.decode_rate * 100.0,
            report.base_fee_gwei_p50,
            report.gas_used_ratio_avg,
            report.stress_profile
        );
    }
}

fn parse_address(s: &str) -> Option<Address> {
    Address::from_str(s).ok()
}

fn tx_to_call_object(tx: &RpcTx) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(from) = tx.from.as_deref() {
        obj.insert("from".into(), serde_json::Value::String(from.to_string()));
    }
    if let Some(to) = tx.to.as_deref() {
        obj.insert("to".into(), serde_json::Value::String(to.to_string()));
    }
    if let Some(gas) = tx.gas.as_deref() {
        obj.insert("gas".into(), serde_json::Value::String(gas.to_string()));
    }
    if let Some(gas_price) = tx.gas_price.as_deref() {
        obj.insert(
            "gasPrice".into(),
            serde_json::Value::String(gas_price.to_string()),
        );
    }
    if let Some(max_fee) = tx.max_fee_per_gas.as_deref() {
        obj.insert(
            "maxFeePerGas".into(),
            serde_json::Value::String(max_fee.to_string()),
        );
    }
    if let Some(max_priority) = tx.max_priority_fee_per_gas.as_deref() {
        obj.insert(
            "maxPriorityFeePerGas".into(),
            serde_json::Value::String(max_priority.to_string()),
        );
    }
    if let Some(nonce) = tx.nonce.as_deref() {
        obj.insert("nonce".into(), serde_json::Value::String(nonce.to_string()));
    }
    obj.insert(
        "value".into(),
        serde_json::Value::String(tx.value.to_string()),
    );
    obj.insert(
        "data".into(),
        serde_json::Value::String(tx.input.to_string()),
    );
    serde_json::Value::Object(obj)
}

fn parse_debug_trace_result(value: &serde_json::Value) -> TraceSimSample {
    let failed = value
        .get("failed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let gas_used = value
        .get("gas")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_u64_hex)
        .or_else(|| value.get("gasUsed").and_then(serde_json::Value::as_u64));
    let reason = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("output")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        });
    let kind = if value.get("error").is_some() {
        TraceKind::Error
    } else if failed {
        TraceKind::Revert
    } else {
        TraceKind::Success
    };
    TraceSimSample {
        kind,
        source: TraceSource::DebugTraceCall,
        gas_used,
        reason,
    }
}

fn rpc_error_code(err: &AppError) -> Option<i64> {
    let AppError::Initialization(msg) = err else {
        return None;
    };
    let marker = "code=";
    let start = msg.find(marker)?;
    let tail = &msg[start + marker.len()..];
    let code_token = tail
        .split(|c: char| !(c.is_ascii_digit() || c == '-'))
        .next()
        .unwrap_or_default();
    code_token.parse::<i64>().ok()
}

fn rpc_method_unavailable(err: &AppError) -> bool {
    if matches!(rpc_error_code(err), Some(-32601)) {
        return true;
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("method not found")
        || msg.contains("does not exist/is not available")
        || msg.contains("unsupported")
        || msg.contains("missing value for required argument")
        || msg.contains("the method debug_tracecall does not exist")
        || (msg.contains("namespace") && msg.contains("disabled"))
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(strip_0x(s), 16).ok()
}

fn parse_u128_hex(s: &str) -> Option<u128> {
    u128::from_str_radix(strip_0x(s), 16).ok()
}

fn parse_u256_hex(s: &str) -> Option<U256> {
    U256::from_str_radix(strip_0x(s), 16).ok()
}

fn decode_hex_bytes(raw: &str) -> Vec<u8> {
    hex::decode(strip_0x(raw)).unwrap_or_default()
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn percentile(values: &[f64], pct: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let idx = ((sorted.len() as f64 - 1.0) * pct.clamp(0.0, 1.0)).round() as usize;
    sorted.get(idx).copied()
}

fn percentile_u64(values: &[u64], pct: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64 - 1.0) * pct.clamp(0.0, 1.0)).round() as usize;
    sorted.get(idx).copied()
}

fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let sum: f64 = values.iter().sum();
    Some(sum / values.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_cover_full_range_without_overlap() {
        let windows = build_windows(10, 20, 4);
        assert_eq!(windows, vec![(10, 13), (14, 17), (18, 20)]);
    }

    #[test]
    fn stress_classification_moves_with_fee_and_util() {
        assert_eq!(classify_stress(0.03, 0.45), ReplayStressProfile::UltraLow);
        assert_eq!(classify_stress(4.2, 0.88), ReplayStressProfile::Normal);
        assert_eq!(classify_stress(120.0, 1.2), ReplayStressProfile::High);
    }

    #[test]
    fn hex_parsers_handle_prefixed_and_plain_values() {
        assert_eq!(parse_u64_hex("0x2a"), Some(42));
        assert_eq!(parse_u64_hex("2a"), Some(42));
        assert_eq!(parse_u128_hex("0x64"), Some(100));
        assert_eq!(parse_u256_hex("0x0"), Some(U256::ZERO));
    }

    #[test]
    fn parse_debug_trace_result_detects_success_and_revert() {
        let success = json!({
            "gas": "0x5208",
            "failed": false,
            "returnValue": "0x"
        });
        let parsed_ok = parse_debug_trace_result(&success);
        assert_eq!(parsed_ok.kind, TraceKind::Success);
        assert_eq!(parsed_ok.gas_used, Some(21_000));

        let reverted = json!({
            "gas": "0x7530",
            "failed": true,
            "returnValue": "0x08c379a0"
        });
        let parsed_revert = parse_debug_trace_result(&reverted);
        assert_eq!(parsed_revert.kind, TraceKind::Revert);
        assert_eq!(parsed_revert.gas_used, Some(30_000));
    }

    #[test]
    fn tx_to_call_object_includes_expected_fields() {
        let tx = RpcTx {
            from: Some("0x1111111111111111111111111111111111111111".into()),
            to: Some("0x2222222222222222222222222222222222222222".into()),
            gas: Some("0x5208".into()),
            gas_price: Some("0x3b9aca00".into()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some("0x1".into()),
            input: "0xabcdef01".into(),
            value: "0x0".into(),
        };
        let call = tx_to_call_object(&tx);
        assert_eq!(
            call.get("from").and_then(|v| v.as_str()),
            tx.from.as_deref()
        );
        assert_eq!(call.get("to").and_then(|v| v.as_str()), tx.to.as_deref());
        assert_eq!(call.get("gas").and_then(|v| v.as_str()), tx.gas.as_deref());
        assert_eq!(
            call.get("nonce").and_then(|v| v.as_str()),
            tx.nonce.as_deref()
        );
        assert_eq!(
            call.get("data").and_then(|v| v.as_str()),
            Some("0xabcdef01")
        );
    }
}
