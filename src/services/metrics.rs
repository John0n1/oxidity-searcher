// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::core::portfolio::PortfolioManager;
use crate::core::strategy::StrategyStats;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

const METRICS_MAX_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct PublicSummaryPolicy {
    pub retained_bps: u64,
    pub per_tx_gas_cap_eth: f64,
    pub per_day_gas_cap_eth: f64,
}

impl Default for PublicSummaryPolicy {
    fn default() -> Self {
        Self {
            retained_bps: 1_000,
            per_tx_gas_cap_eth: 0.05,
            per_day_gas_cap_eth: 0.5,
        }
    }
}

pub async fn spawn_metrics_server(
    port: u16,
    chain_id: u64,
    shutdown: CancellationToken,
    stats: Arc<StrategyStats>,
    portfolio: Arc<PortfolioManager>,
    public_summary_policy: PublicSummaryPolicy,
    metrics_bind: Option<String>,
    metrics_token: Option<String>,
    enable_shutdown: bool,
) -> Option<SocketAddr> {
    let token = match metrics_token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(t) => t.to_string(),
        _ => {
            tracing::warn!(
                target: "metrics",
                "metrics token missing/empty; metrics server disabled (strategy continues)"
            );
            return None;
        }
    };
    let bind_addr = metrics_bind
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("127.0.0.1")
        .to_string();
    let addr: SocketAddr = match format!("{}:{}", bind_addr, port).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                "Invalid METRICS_BIND '{}': {}. Falling back to 127.0.0.1:{}",
                bind_addr,
                e,
                port
            );
            SocketAddr::from(([127, 0, 0, 1], port))
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Metrics server failed to bind: {}", e);
            return None;
        }
    };

    let local = listener.local_addr().ok();
    if let Some(addr) = local {
        tracing::info!("✔ Metrics server online - listening on {}", addr);
    }

    let token = token.clone();
    let limiter = Arc::new(TokioMutex::new(RateLimiter::default()));
    tokio::spawn(async move {
        loop {
            let accept_result = tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(target: "metrics", "Shutdown requested; stopping metrics server");
                    break;
                }
                accept = listener.accept() => accept,
            };

            match accept_result {
                Ok((mut socket, _)) => {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let mut too_large = false;
                    loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        if buf.len().saturating_add(n) > METRICS_MAX_REQUEST_BYTES {
                            too_large = true;
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if header_end_offset(&buf).is_some() {
                            break;
                        }
                    }
                    if too_large {
                        let body = r#"{"status":"error","error":"request too large"}"#;
                        let response = format!(
                            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        continue;
                    }
                    let Some(header_end) = header_end_offset(&buf) else {
                        if !buf.is_empty() {
                            let body = r#"{"status":"error","error":"malformed request"}"#;
                            let response = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                        }
                        continue;
                    };

                    let req = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let mut lines = req.lines();
                    let request_line = lines.next().unwrap_or_default();
                    {
                        let mut guard = limiter.lock().await;
                        if !guard.allow(60) {
                            let body = r#"{"status":"error","error":"rate_limited"}"#;
                            let response = format!(
                                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            continue;
                        }
                    }
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    if method != "GET" && method != "HEAD" {
                        let body = r#"{"status":"error","error":"method not allowed"}"#;
                        let response = format!(
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        continue;
                    }

                    let path = parts.next().unwrap_or("/");
                    let path = path.lines().next().unwrap_or("/");
                    let headers: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();
                    let route = path.split('?').next().unwrap_or(path);
                    let is_public_route = route == "/public/summary";
                    let auth_header = headers.iter().find_map(|l| {
                        let (key, val) = l.split_once(':')?;
                        if key.eq_ignore_ascii_case("authorization") {
                            Some(val.trim())
                        } else {
                            None
                        }
                    });
                    let ok = if is_public_route {
                        true
                    } else {
                        auth_header
                            .and_then(|v| v.strip_prefix("Bearer "))
                            .map(|v| v.trim() == token)
                            .unwrap_or(false)
                    };
                    if !ok {
                        let body = r#"{"status":"error","error":"unauthorized"}"#;
                        let response = format!(
                            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        continue;
                    }

                    if route == "/health" {
                        let body = json!({"status":"ok","chainId":chain_id}).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route == "/shutdown" {
                        if enable_shutdown {
                            shutdown.cancel();
                            let body =
                                json!({"status":"ok","message":"shutdown_requested"}).to_string();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                        } else {
                            let body = r#"{"status":"error","error":"shutdown route disabled"}"#;
                            let response = format!(
                                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                        }
                    } else if route == "/" {
                        let body = render_metrics(&stats, &portfolio);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route == "/public/summary" {
                        let body = render_public_summary(
                            chain_id,
                            &stats,
                            &portfolio,
                            public_summary_policy,
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route == "/partner/summary" {
                        let body = render_public_summary(
                            chain_id,
                            &stats,
                            &portfolio,
                            public_summary_policy,
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let body = r#"{"status":"error","error":"not found"}"#;
                        let response = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
                Err(e) => {
                    tracing::warn!("Metrics accept error: {}", e);
                    continue;
                }
            }
        }
    });

    local
}

fn header_end_offset(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|idx| idx + 2))
}

fn render_metrics(stats: &Arc<StrategyStats>, portfolio: &Arc<PortfolioManager>) -> String {
    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    let submitted = stats.submitted.load(std::sync::atomic::Ordering::Relaxed);
    let skipped = stats.skipped.load(std::sync::atomic::Ordering::Relaxed);
    let failed = stats.failed.load(std::sync::atomic::Ordering::Relaxed);
    let skip_decode = stats
        .skip_decode_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_unknown = stats
        .skip_unknown_router
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_missing_wrapped = stats
        .skip_missing_wrapped
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_non_wrapped_balance = stats
        .skip_non_wrapped_balance
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_gas_cap = stats
        .skip_gas_cap
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_sim_failed = stats
        .skip_sim_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_profit_guard = stats
        .skip_profit_guard
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_unsupported_router = stats
        .skip_unsupported_router
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_token_call = stats
        .skip_token_call
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_toxic_token = stats
        .skip_toxic_token
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_insufficient_balance = stats
        .skip_insufficient_balance
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_router_revert_rate = stats
        .skip_router_revert_rate
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_liquidity_depth = stats
        .skip_liquidity_depth
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_sandwich_risk = stats
        .skip_sandwich_risk
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_front_run_build_failed = stats
        .skip_front_run_build_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_backrun_build_failed = stats
        .skip_backrun_build_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_attempts_router = stats
        .decode_attempts_router
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_success_router = stats
        .decode_success_router
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_attempts_wrapper = stats
        .decode_attempts_wrapper
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_success_wrapper = stats
        .decode_success_wrapper
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_attempts_infra = stats
        .decode_attempts_infra
        .load(std::sync::atomic::Ordering::Relaxed);
    let decode_success_infra = stats
        .decode_success_infra
        .load(std::sync::atomic::Ordering::Relaxed);
    let nonce_loads = stats
        .nonce_state_loads
        .load(std::sync::atomic::Ordering::Relaxed);
    let nonce_load_fail = stats
        .nonce_state_load_fail
        .load(std::sync::atomic::Ordering::Relaxed);
    let nonce_persist = stats
        .nonce_state_persist
        .load(std::sync::atomic::Ordering::Relaxed);
    let nonce_persist_fail = stats
        .nonce_state_persist_fail
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_sum = stats
        .sim_latency_ms_sum
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_count = stats
        .sim_latency_ms_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_sum_mem = stats
        .sim_latency_ms_sum_mempool
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_count_mem = stats
        .sim_latency_ms_count_mempool
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_sum_mev = stats
        .sim_latency_ms_sum_mevshare
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_count_mev = stats
        .sim_latency_ms_count_mevshare
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_depth = stats
        .ingest_queue_depth
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_dropped = stats
        .ingest_queue_dropped
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_full = stats
        .ingest_queue_full
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_backpressure = stats
        .ingest_backpressure
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_success_ratio = if processed == 0 {
        1.0
    } else {
        ((processed.saturating_sub(skip_sim_failed)) as f64) / (processed as f64)
    };
    let nonce_total = nonce_loads
        .saturating_add(nonce_persist)
        .saturating_add(nonce_load_fail)
        .saturating_add(nonce_persist_fail);
    let nonce_error_ratio = if nonce_total == 0 {
        0.0
    } else {
        ((nonce_load_fail.saturating_add(nonce_persist_fail)) as f64) / (nonce_total as f64)
    };
    let bundle_reject_total = skip_profit_guard
        .saturating_add(skip_sim_failed)
        .saturating_add(skip_gas_cap)
        .saturating_add(skip_router_revert_rate)
        .saturating_add(skip_liquidity_depth)
        .saturating_add(skip_sandwich_risk)
        .saturating_add(skip_front_run_build_failed)
        .saturating_add(skip_backrun_build_failed);
    let decode_success_rate_router = if decode_attempts_router == 0 {
        0.0
    } else {
        decode_success_router as f64 / decode_attempts_router as f64
    };
    let decode_success_rate_wrapper = if decode_attempts_wrapper == 0 {
        0.0
    } else {
        decode_success_wrapper as f64 / decode_attempts_wrapper as f64
    };
    let decode_success_rate_infra = if decode_attempts_infra == 0 {
        0.0
    } else {
        decode_success_infra as f64 / decode_attempts_infra as f64
    };
    let bundles_snapshot: Vec<crate::core::strategy::BundleTelemetry> = {
        let guard = stats.bundles.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    };
    let bundle_samples = bundles_snapshot.len() as u64;
    let bundle_profit_eth_sum: f64 = bundles_snapshot.iter().map(|b| b.profit_eth).sum();
    let bundle_gas_eth_sum: f64 = bundles_snapshot.iter().map(|b| b.gas_cost_eth).sum();
    let bundle_net_eth_sum: f64 = bundles_snapshot.iter().map(|b| b.net_eth).sum();
    let mut body = format!(
        concat!(
            "# TYPE strategy_processed counter\nstrategy_processed {}\n",
            "# TYPE strategy_submitted counter\nstrategy_submitted {}\n",
            "# TYPE strategy_skipped counter\nstrategy_skipped {}\n",
            "# TYPE strategy_failed counter\nstrategy_failed {}\n",
            "# TYPE strategy_skip_decode counter\nstrategy_skip_decode {}\n",
            "# TYPE strategy_skip_unknown_router counter\nstrategy_skip_unknown_router {}\n",
            "# TYPE strategy_skip_missing_wrapped counter\nstrategy_skip_missing_wrapped {}\n",
            "# TYPE strategy_skip_non_wrapped_balance counter\nstrategy_skip_non_wrapped_balance {}\n",
            "# TYPE strategy_skip_gas_cap counter\nstrategy_skip_gas_cap {}\n",
            "# TYPE strategy_skip_sim_failed counter\nstrategy_skip_sim_failed {}\n",
            "# TYPE strategy_skip_profit_guard counter\nstrategy_skip_profit_guard {}\n",
            "# TYPE strategy_skip_unsupported_router counter\nstrategy_skip_unsupported_router {}\n",
            "# TYPE strategy_skip_token_call counter\nstrategy_skip_token_call {}\n",
            "# TYPE strategy_skip_toxic_token counter\nstrategy_skip_toxic_token {}\n",
            "# TYPE strategy_skip_insufficient_balance counter\nstrategy_skip_insufficient_balance {}\n",
            "# TYPE strategy_skip_router_revert_rate counter\nstrategy_skip_router_revert_rate {}\n",
            "# TYPE strategy_skip_liquidity_depth counter\nstrategy_skip_liquidity_depth {}\n",
            "# TYPE strategy_skip_sandwich_risk counter\nstrategy_skip_sandwich_risk {}\n",
            "# TYPE strategy_skip_front_run_build_failed counter\nstrategy_skip_front_run_build_failed {}\n",
            "# TYPE strategy_skip_backrun_build_failed counter\nstrategy_skip_backrun_build_failed {}\n",
            "# TYPE decode_attempts_by_category counter\ndecode_attempts_by_category{{category=\"routers\"}} {}\n",
            "decode_attempts_by_category{{category=\"wrappers\"}} {}\n",
            "decode_attempts_by_category{{category=\"infra\"}} {}\n",
            "# TYPE decode_success_by_category counter\ndecode_success_by_category{{category=\"routers\"}} {}\n",
            "decode_success_by_category{{category=\"wrappers\"}} {}\n",
            "decode_success_by_category{{category=\"infra\"}} {}\n",
            "# TYPE decode_success_rate_by_category gauge\ndecode_success_rate_by_category{{category=\"routers\"}} {:.6}\n",
            "decode_success_rate_by_category{{category=\"wrappers\"}} {:.6}\n",
            "decode_success_rate_by_category{{category=\"infra\"}} {:.6}\n",
            "# TYPE nonce_state_loads counter\nnonce_state_loads {}\n",
            "# TYPE nonce_state_load_fail counter\nnonce_state_load_fail {}\n",
            "# TYPE nonce_state_persist counter\nnonce_state_persist {}\n",
            "# TYPE nonce_state_persist_fail counter\nnonce_state_persist_fail {}\n",
            "# TYPE sim_latency_ms_sum counter\nsim_latency_ms_sum {}\n",
            "# TYPE sim_latency_ms_count counter\nsim_latency_ms_count {}\n",
            "# TYPE sim_latency_ms_sum_mempool counter\nsim_latency_ms_sum_mempool {}\n",
            "# TYPE sim_latency_ms_count_mempool counter\nsim_latency_ms_count_mempool {}\n",
            "# TYPE sim_latency_ms_sum_mevshare counter\nsim_latency_ms_sum_mevshare {}\n",
            "# TYPE sim_latency_ms_count_mevshare counter\nsim_latency_ms_count_mevshare {}\n",
            "# TYPE ingest_queue_depth gauge\ningest_queue_depth {}\n",
            "# TYPE ingest_queue_dropped counter\ningest_queue_dropped {}\n",
            "# TYPE ingest_queue_full counter\ningest_queue_full {}\n",
            "# TYPE ingest_queue_backpressure counter\ningest_queue_backpressure {}\n",
            "# TYPE strategy_sim_success_ratio gauge\nstrategy_sim_success_ratio {:.6}\n",
            "# TYPE nonce_state_error_ratio gauge\nnonce_state_error_ratio {:.6}\n",
            "# TYPE bundle_reject_total counter\nbundle_reject_total {}\n",
            "# TYPE bundle_telemetry_samples gauge\nbundle_telemetry_samples {}\n",
            "# TYPE bundle_profit_eth_sum gauge\nbundle_profit_eth_sum {:.12}\n",
            "# TYPE bundle_gas_cost_eth_sum gauge\nbundle_gas_cost_eth_sum {:.12}\n",
            "# TYPE bundle_net_eth_sum gauge\nbundle_net_eth_sum {:.12}\n"
        ),
        processed,
        submitted,
        skipped,
        failed,
        skip_decode,
        skip_unknown,
        skip_missing_wrapped,
        skip_non_wrapped_balance,
        skip_gas_cap,
        skip_sim_failed,
        skip_profit_guard,
        skip_unsupported_router,
        skip_token_call,
        skip_toxic_token,
        skip_insufficient_balance,
        skip_router_revert_rate,
        skip_liquidity_depth,
        skip_sandwich_risk,
        skip_front_run_build_failed,
        skip_backrun_build_failed,
        decode_attempts_router,
        decode_attempts_wrapper,
        decode_attempts_infra,
        decode_success_router,
        decode_success_wrapper,
        decode_success_infra,
        decode_success_rate_router,
        decode_success_rate_wrapper,
        decode_success_rate_infra,
        nonce_loads,
        nonce_load_fail,
        nonce_persist,
        nonce_persist_fail,
        sim_sum,
        sim_count,
        sim_sum_mem,
        sim_count_mem,
        sim_sum_mev,
        sim_count_mev,
        queue_depth,
        queue_dropped,
        queue_full,
        queue_backpressure,
        sim_success_ratio,
        nonce_error_ratio,
        bundle_reject_total,
        bundle_samples,
        bundle_profit_eth_sum,
        bundle_gas_eth_sum,
        bundle_net_eth_sum
    );

    let rejection_snapshot: Vec<(String, u64)> = {
        let guard = stats
            .opportunity_rejections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .map(|(reason, count)| (reason.clone(), *count))
            .collect()
    };
    for (reason, count) in rejection_snapshot {
        let reason = reason.replace('"', "_");
        body.push_str(&format!(
            "# TYPE opportunity_rejected_total counter\nopportunity_rejected_total{{reason=\"{}\"}} {}\n",
            reason, count
        ));
    }

    for (chain, profit) in portfolio.net_profit_all() {
        body.push_str(&format!(
            "# TYPE net_profit_eth gauge\nnet_profit_eth{{chain=\"{}\"}} {}\n",
            chain, profit
        ));
    }

    for (chain, token, profit, decimals) in portfolio.token_profit_all() {
        body.push_str(&format!(
            "# TYPE token_profit gauge\ntoken_profit{{chain=\"{}\",token=\"{:#x}\",decimals=\"{}\"}} {}\n",
            chain, token, decimals, profit
        ));
    }

    let relay_outcomes: Vec<(String, crate::core::strategy::RelayOutcomeStats)> = {
        let guard = stats
            .relay_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .map(|(name, outcome)| (name.clone(), outcome.clone()))
            .collect()
    };
    let relay_bundle_status: Vec<(String, crate::core::strategy::RelayBundleStatus)> = {
        let guard = stats
            .relay_bundle_status
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .map(|(name, status)| (name.clone(), status.clone()))
            .collect()
    };
    for (relay, outcome) in relay_outcomes {
        let relay = relay.replace('"', "_");
        body.push_str(&format!(
            "# TYPE relay_attempts_total counter\nrelay_attempts_total{{relay=\"{}\"}} {}\n",
            relay, outcome.attempts
        ));
        body.push_str(&format!(
            "# TYPE relay_successes_total counter\nrelay_successes_total{{relay=\"{}\"}} {}\n",
            relay, outcome.successes
        ));
        body.push_str(&format!(
            "# TYPE relay_failures_total counter\nrelay_failures_total{{relay=\"{}\"}} {}\n",
            relay, outcome.failures
        ));
        body.push_str(&format!(
            "# TYPE relay_timeouts_total counter\nrelay_timeouts_total{{relay=\"{}\"}} {}\n",
            relay, outcome.timeouts
        ));
        body.push_str(&format!(
            "# TYPE relay_retries_total counter\nrelay_retries_total{{relay=\"{}\"}} {}\n",
            relay, outcome.retries
        ));
    }
    for (relay, status) in relay_bundle_status {
        let relay = relay.replace('"', "_");
        let state = status.status.replace('"', "_");
        body.push_str(&format!(
            "# TYPE relay_last_submission_status gauge\nrelay_last_submission_status{{relay=\"{}\",status=\"{}\"}} 1\n",
            relay, state
        ));
        body.push_str(&format!(
            "# TYPE relay_last_submission_timestamp_ms gauge\nrelay_last_submission_timestamp_ms{{relay=\"{}\"}} {}\n",
            relay, status.updated_at_ms
        ));
        let replacement_uuid = status
            .replacement_uuid
            .as_deref()
            .unwrap_or("")
            .replace('"', "_");
        let bundle_id = status.bundle_id.as_deref().unwrap_or("").replace('"', "_");
        body.push_str(&format!(
            "# TYPE relay_last_submission_info gauge\nrelay_last_submission_info{{relay=\"{}\",replacement_uuid=\"{}\",bundle_id=\"{}\"}} 1\n",
            relay, replacement_uuid, bundle_id
        ));
    }

    body
}

fn timestamp_ms_to_iso(timestamp_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

fn clamp_non_negative(value: f64) -> f64 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn render_public_summary(
    chain_id: u64,
    stats: &Arc<StrategyStats>,
    portfolio: &Arc<PortfolioManager>,
    policy: PublicSummaryPolicy,
) -> String {
    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    let submitted = stats.submitted.load(std::sync::atomic::Ordering::Relaxed);
    let skipped = stats.skipped.load(std::sync::atomic::Ordering::Relaxed);
    let failed = stats.failed.load(std::sync::atomic::Ordering::Relaxed);
    let sim_count = stats
        .sim_latency_ms_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let sim_sum = stats
        .sim_latency_ms_sum
        .load(std::sync::atomic::Ordering::Relaxed);

    let mut bundles: Vec<crate::core::strategy::BundleTelemetry> = {
        let guard = stats.bundles.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().cloned().collect()
    };
    bundles.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));

    let fallback_native_usd_price = bundles
        .iter()
        .find_map(|b| {
            if b.native_usd_price.is_finite() && b.native_usd_price > 0.0 {
                Some(b.native_usd_price)
            } else {
                None
            }
        })
        .unwrap_or(0.0);
    let bundle_price = |bundle: &crate::core::strategy::BundleTelemetry| {
        if bundle.native_usd_price.is_finite() && bundle.native_usd_price > 0.0 {
            bundle.native_usd_price
        } else {
            fallback_native_usd_price
        }
    };
    let decision_label = |decision_path: &str| match decision_path {
        "sponsored" => "Sponsored",
        "pass_through" => "Pass-through",
        _ => "Private only",
    };

    let sponsored_tx_count = bundles
        .iter()
        .filter(|b| b.decision_path == "sponsored")
        .count() as u64;
    let gas_covered_eth_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.gas_covered_eth))
        .sum();
    let gas_refunded_eth_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.gas_refunded_eth))
        .sum();
    let retained_eth_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.retained_eth))
        .sum();
    let rebate_eth_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.rebate_eth))
        .sum();
    let gas_covered_usd_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.gas_covered_eth) * bundle_price(b))
        .sum();
    let gas_refunded_usd_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.gas_refunded_eth) * bundle_price(b))
        .sum();
    let retained_usd_total: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.retained_eth) * bundle_price(b))
        .sum();
    let mev_returned_usd: f64 = bundles
        .iter()
        .map(|b| clamp_non_negative(b.rebate_eth) * bundle_price(b))
        .sum();
    let net_profit_eth_total: f64 = portfolio.net_profit_all().iter().map(|(_, v)| *v).sum();
    let avg_inclusion_seconds = if sim_count > 0 {
        (sim_sum as f64) / (sim_count as f64) / 1000.0
    } else {
        1.2
    };

    let activity: Vec<serde_json::Value> = bundles
        .iter()
        .take(10)
        .enumerate()
        .map(|(idx, bundle)| {
            let path = decision_label(&bundle.decision_path);
            let price = bundle_price(bundle);
            let net_to_user_usd = (clamp_non_negative(bundle.gas_refunded_eth)
                + clamp_non_negative(bundle.rebate_eth))
                * price;
            json!({
                "id": format!("bundle-{}", idx + 1),
                "txHash": bundle.tx_hash,
                "path": path,
                "decisionPath": bundle.decision_path.clone(),
                "netToUserUsd": net_to_user_usd,
                "status": bundle.status.clone(),
                "timestamp": timestamp_ms_to_iso(bundle.timestamp_ms),
            })
        })
        .collect();

    let transactions: Vec<serde_json::Value> = bundles
        .iter()
        .take(50)
        .enumerate()
        .map(|(idx, bundle)| {
            let path = decision_label(&bundle.decision_path);
            let price = bundle_price(bundle);
            let gas_covered_usd = clamp_non_negative(bundle.gas_covered_eth) * price;
            let gas_refunded_usd = clamp_non_negative(bundle.gas_refunded_eth) * price;
            let retained_usd = clamp_non_negative(bundle.retained_eth) * price;
            let rebate_usd = clamp_non_negative(bundle.rebate_eth) * price;
            let net_usd = gas_refunded_usd + rebate_usd;
            json!({
                "id": format!("tx-{}", idx + 1),
                "txHash": bundle.tx_hash,
                "submittedAt": timestamp_ms_to_iso(bundle.timestamp_ms),
                "status": bundle.status.clone(),
                "path": path,
                "decisionPath": bundle.decision_path.clone(),
                "reason": format!(
                    "Execution source: {} ({})",
                    bundle.source,
                    bundle.decision_path.as_str()
                ),
                "gasCoveredUsd": gas_covered_usd,
                "gasRefundedUsd": gas_refunded_usd,
                "retainedUsd": retained_usd,
                "mevRebateUsd": rebate_usd,
                "netToUserUsd": net_usd,
                "ledger": {
                    "gasCoveredEth": clamp_non_negative(bundle.gas_covered_eth),
                    "gasRefundedEth": clamp_non_negative(bundle.gas_refunded_eth),
                    "retainedEth": clamp_non_negative(bundle.retained_eth),
                    "rebateEth": clamp_non_negative(bundle.rebate_eth),
                    "gasCoveredUsd": gas_covered_usd,
                    "gasRefundedUsd": gas_refunded_usd,
                    "retainedUsd": retained_usd,
                    "rebateUsd": rebate_usd
                },
                "timeline": [
                    {"step": "Received", "status": "done", "time": timestamp_ms_to_iso(bundle.timestamp_ms)},
                    {"step": "Simulated", "status": "done", "time": timestamp_ms_to_iso(bundle.timestamp_ms)},
                    {"step": "Submitted", "status": "done", "time": timestamp_ms_to_iso(bundle.timestamp_ms)},
                    {"step": "Included", "status": "done", "time": timestamp_ms_to_iso(bundle.timestamp_ms)}
                ]
            })
        })
        .collect();

    let pipeline_ok = if processed == 0 {
        100.0
    } else {
        100.0 * (1.0 - (failed as f64 / processed as f64))
    };
    let services = vec![
        json!({
            "name": "Pipeline Health",
            "status": if pipeline_ok >= 99.0 { "operational" } else { "degraded" },
            "uptimePct": pipeline_ok,
            "latencyMs": (avg_inclusion_seconds * 1000.0)
        }),
        json!({
            "name": "Bundle Submission",
            "status": if submitted > 0 || processed == 0 { "operational" } else { "degraded" },
            "uptimePct": if processed > 0 { 100.0 * (submitted as f64 / processed as f64) } else { 100.0 },
            "latencyMs": (avg_inclusion_seconds * 1000.0)
        }),
        json!({
            "name": "Risk Filtering",
            "status": "operational",
            "uptimePct": 100.0,
            "latencyMs": 90.0
        }),
    ];

    json!({
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "chainId": chain_id,
        "source": "strategy-metrics",
        "stats": {
            "sponsoredTxCount": sponsored_tx_count,
            "gasRefundedEth": gas_refunded_eth_total + gas_covered_eth_total,
            "gasCoveredEth": gas_covered_eth_total,
            "retainedEth": retained_eth_total,
            "rebateEth": rebate_eth_total,
            "gasCoveredUsd": gas_covered_usd_total,
            "gasRefundedUsd": gas_refunded_usd_total,
            "retainedUsd": retained_usd_total,
            "rebateUsd": mev_returned_usd,
            "mevReturnedUsd": mev_returned_usd,
            "avgInclusionSeconds": avg_inclusion_seconds,
            "portfolioNetProfitEth": net_profit_eth_total
        },
        "activity": activity,
        "transactions": transactions,
        "services": services,
        "incidents": [],
        "policy": {
            "retainedBps": policy.retained_bps,
            "perTxGasCapEth": policy.per_tx_gas_cap_eth,
            "perDayGasCapEth": policy.per_day_gas_cap_eth
        },
        "counters": {
            "processed": processed,
            "submitted": submitted,
            "skipped": skipped,
            "failed": failed
        }
    })
    .to_string()
}

struct RateLimiter {
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
        }
    }

    fn allow(&mut self, max_per_second: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs_f64().ge(&1.0) {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= max_per_second {
            return false;
        }
        self.count += 1;
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::portfolio::PortfolioManager;
    use crate::core::strategy::StrategyStats;
    use crate::network::provider::HttpProvider;
    use alloy::primitives::Address;
    use tokio::net::TcpStream;
    use url::Url;

    #[tokio::test]
    async fn metrics_endpoint_serves() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            1,
            shutdown,
            stats.clone(),
            portfolio.clone(),
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            Some("testtoken".to_string()),
            false,
        )
        .await
        .expect("bind metrics");

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}", addr))
            .bearer_auth("testtoken")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();

        assert!(body.contains("strategy_processed"));
    }

    #[tokio::test]
    async fn health_endpoint_includes_chain_id() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            137,
            shutdown,
            stats.clone(),
            portfolio.clone(),
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            Some("testtoken".to_string()),
            false,
        )
        .await
        .expect("bind metrics");

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/health", addr))
            .bearer_auth("testtoken")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();

        assert!(body.contains("\"chainId\":137"));
    }

    #[tokio::test]
    async fn public_summary_endpoint_serves_without_auth() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            1,
            shutdown,
            stats,
            portfolio,
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            Some("testtoken".to_string()),
            false,
        )
        .await
        .expect("bind metrics");

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/public/summary", addr))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();

        assert!(body.contains("\"stats\""));
        assert!(body.contains("\"policy\""));
    }

    #[tokio::test]
    async fn shutdown_endpoint_stops_server() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            1,
            shutdown,
            stats.clone(),
            portfolio.clone(),
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            Some("testtoken".to_string()),
            true,
        )
        .await
        .expect("bind metrics");

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/shutdown", addr))
            .bearer_auth("testtoken")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Server should stop shortly after shutdown request.
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let probe = client
                .get(format!("http://{}/health", addr))
                .bearer_auth("testtoken")
                .send()
                .await;
            if probe.is_err() {
                return;
            }
        }

        panic!("metrics server still accepted requests after shutdown");
    }

    #[tokio::test]
    async fn missing_metrics_token_disables_server_without_exiting() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            1,
            shutdown,
            stats,
            portfolio,
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            None,
            false,
        )
        .await;
        assert!(addr.is_none());
    }

    #[test]
    fn header_end_offset_detects_crlf_and_lf_delimiters() {
        let crlf = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let lf = b"GET / HTTP/1.1\nHost: localhost\n\n";
        assert_eq!(header_end_offset(crlf), Some(crlf.len()));
        assert_eq!(header_end_offset(lf), Some(lf.len()));
        assert_eq!(header_end_offset(b"GET / HTTP/1.1\r\nHost: x"), None);
    }

    #[tokio::test]
    async fn split_header_reads_are_parsed_correctly() {
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(
            0,
            1,
            shutdown,
            stats,
            portfolio,
            PublicSummaryPolicy::default(),
            Some("127.0.0.1".to_string()),
            Some("testtoken".to_string()),
            false,
        )
        .await
        .expect("bind metrics");

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ")
            .await
            .expect("write first segment");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        stream
            .write_all(b"testtoken\r\n\r\n")
            .await
            .expect("write second segment");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("\"chainId\":1"));
    }
}
