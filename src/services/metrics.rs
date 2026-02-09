// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::app::logging::{recent_logs_since, set_log_level};
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

pub async fn spawn_metrics_server(
    port: u16,
    chain_id: u64,
    shutdown: CancellationToken,
    stats: Arc<StrategyStats>,
    portfolio: Arc<PortfolioManager>,
) -> Option<SocketAddr> {
    let token = match std::env::var("METRICS_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            // Fail fast: metrics are required for observability / health.
            tracing::error!("METRICS_TOKEN missing or empty; aborting startup.");
            std::process::exit(1);
        }
    };
    let bind_addr = std::env::var("METRICS_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
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
        tracing::info!("Metrics server listening on {}", addr);
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
                    const MAX_READ: usize = 2048;
                    let mut buf = vec![0u8; MAX_READ];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == MAX_READ {
                        let body = r#"{"status":"error","error":"request too large"}"#;
                        let response = format!(
                            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        continue;
                    }

                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
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
                    let auth_header = headers.iter().find_map(|l| {
                        let (key, val) = l.split_once(':')?;
                        if key.eq_ignore_ascii_case("authorization") {
                            Some(val.trim())
                        } else {
                            None
                        }
                    });
                    let ok = auth_header
                        .and_then(|v| v.strip_prefix("Bearer ").or(Some(v)))
                        .map(|v| v.trim() == token)
                        .unwrap_or(false);
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

                    let (route, query) = path.split_once('?').unwrap_or((path, ""));

                    if route == "/health" {
                        let body = json!({"status":"ok","chainId":chain_id}).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route == "/shutdown" {
                        shutdown.cancel();
                        let body = json!({"status":"ok","message":"shutdown_requested"}).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/dashboard") {
                        let body = render_dashboard_json(&stats, &portfolio, chain_id);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/bundles") {
                        let body = render_bundles_json(&stats);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/logs") {
                        let after = query
                            .split('&')
                            .find_map(|kv| {
                                let mut parts = kv.split('=');
                                match (parts.next(), parts.next()) {
                                    (Some("after"), Some(v)) => Some(v),
                                    _ => None,
                                }
                            })
                            .and_then(|v| v.parse::<u64>().ok());
                        let limit = query
                            .split('&')
                            .find_map(|kv| {
                                let mut parts = kv.split('=');
                                match (parts.next(), parts.next()) {
                                    (Some("limit"), Some(v)) => Some(v),
                                    _ => None,
                                }
                            })
                            .and_then(|v| v.parse::<usize>().ok())
                            .map(|v| v.clamp(1, 500))
                            .unwrap_or(200);
                        let logs = recent_logs_since(after, limit);
                        let body =
                            serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string());
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/log_level") {
                        let level = query.split('&').find_map(|kv| {
                            let mut parts = kv.split('=');
                            match (parts.next(), parts.next()) {
                                (Some("level"), Some(v)) => Some(v),
                                _ => None,
                            }
                        });

                        let (status, body) = match level {
                            Some(lvl) => match set_log_level(lvl) {
                                Ok(_) => {
                                    ("200 OK", json!({"status": "ok", "level": lvl}).to_string())
                                }
                                Err(e) => (
                                    "400 Bad Request",
                                    json!({"status": "error", "error": e}).to_string(),
                                ),
                            },
                            None => (
                                "400 Bad Request",
                                json!({"status": "error", "error": "missing level"}).to_string(),
                            ),
                        };

                        let response = format!(
                            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            status,
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route == "/" {
                        let body = render_metrics(&stats, &portfolio);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
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
    let skip_gas_cap = stats
        .skip_gas_cap
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_sim_failed = stats
        .skip_sim_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_profit_guard = stats
        .skip_profit_guard
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
    let mut body = format!(
        concat!(
            "# TYPE strategy_processed counter\nstrategy_processed {}\n",
            "# TYPE strategy_submitted counter\nstrategy_submitted {}\n",
            "# TYPE strategy_skipped counter\nstrategy_skipped {}\n",
            "# TYPE strategy_failed counter\nstrategy_failed {}\n",
            "# TYPE strategy_skip_decode counter\nstrategy_skip_decode {}\n",
            "# TYPE strategy_skip_unknown_router counter\nstrategy_skip_unknown_router {}\n",
            "# TYPE strategy_skip_gas_cap counter\nstrategy_skip_gas_cap {}\n",
            "# TYPE strategy_skip_sim_failed counter\nstrategy_skip_sim_failed {}\n",
            "# TYPE strategy_skip_profit_guard counter\nstrategy_skip_profit_guard {}\n",
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
            "# TYPE ingest_queue_backpressure counter\ningest_queue_backpressure {}\n"
        ),
        processed,
        submitted,
        skipped,
        failed,
        skip_decode,
        skip_unknown,
        skip_gas_cap,
        skip_sim_failed,
        skip_profit_guard,
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
        queue_backpressure
    );

    for (chain, profit) in portfolio.net_profit_all() {
        body.push_str(&format!(
            "# TYPE net_profit_eth gauge\nnet_profit_eth{{chain=\"{}\"}} {}\n",
            chain, profit
        ));
    }

    for (chain, token, profit) in portfolio.token_profit_all() {
        body.push_str(&format!(
            "# TYPE token_profit gauge\ntoken_profit{{chain=\"{}\",token=\"{:#x}\"}} {}\n",
            chain, token, profit
        ));
    }

    body
}

fn render_dashboard_json(
    stats: &Arc<StrategyStats>,
    portfolio: &Arc<PortfolioManager>,
    chain_id: u64,
) -> String {
    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    let submitted = stats.submitted.load(std::sync::atomic::Ordering::Relaxed);
    let skipped = stats.skipped.load(std::sync::atomic::Ordering::Relaxed);
    let failed = stats.failed.load(std::sync::atomic::Ordering::Relaxed);
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
    let skip_decode = stats
        .skip_decode_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    let skip_unknown = stats
        .skip_unknown_router
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
    let success_rate = if submitted > 0 {
        ((submitted.saturating_sub(failed)) as f64) / (submitted as f64) * 100.0
    } else {
        0.0
    };

    let mut net_profit_by_chain = serde_json::Map::new();
    let mut total_profit = 0.0;
    for (chain, profit) in portfolio.net_profit_all() {
        total_profit += profit;
        net_profit_by_chain.insert(chain.to_string(), serde_json::json!(profit));
    }

    let mut token_profit = Vec::new();
    for (chain, token, profit) in portfolio.token_profit_all() {
        token_profit.push(serde_json::json!({
            "chain": chain.to_string(),
            "token": format!("{:#x}", token),
            "profit": profit
        }));
    }

    let payload = serde_json::json!({
        "chainId": chain_id,
        "processed": processed,
        "submitted": submitted,
        "skipped": skipped,
        "failed": failed,
        "successRate": success_rate,
        "queueDepth": queue_depth,
        "queueDropped": queue_dropped,
        "queueFull": queue_full,
        "queueBackpressure": queue_backpressure,
        "skipDecode": skip_decode,
        "skipUnknownRouter": skip_unknown,
        "skipGasCap": skip_gas_cap,
        "skipSimulation": skip_sim_failed,
        "skipProfitGuard": skip_profit_guard,
        "nonceStateLoads": nonce_loads,
        "nonceStateLoadFail": nonce_load_fail,
        "nonceStatePersist": nonce_persist,
        "nonceStatePersistFail": nonce_persist_fail,
        "simLatencyMsSum": sim_sum,
        "simLatencyMsCount": sim_count,
        "simLatencyMsSumMempool": sim_sum_mem,
        "simLatencyMsCountMempool": sim_count_mem,
        "simLatencyMsSumMevShare": sim_sum_mev,
        "simLatencyMsCountMevShare": sim_count_mev,
        "netProfitEth": total_profit,
        "netProfitByChain": net_profit_by_chain,
        "tokenProfit": token_profit,
        "history": render_bundle_history(stats),
        "table": render_bundle_history(stats)
    });

    payload.to_string()
}

fn render_bundle_history(stats: &Arc<StrategyStats>) -> serde_json::Value {
    let guard = stats
        .bundles
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let rows: Vec<serde_json::Value> = guard
        .iter()
        .rev()
        .map(|b| {
            json!({
                "tx": b.tx_hash,
                "source": b.source,
                "profitEth": b.profit_eth,
                "gasEth": b.gas_cost_eth,
                "netEth": b.net_eth,
                "timestampMs": b.timestamp_ms,
            })
        })
        .collect();
    serde_json::Value::Array(rows)
}

fn render_bundles_json(stats: &Arc<StrategyStats>) -> String {
    let history = render_bundle_history(stats);
    json!({ "history": history }).to_string()
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
    use url::Url;

    #[tokio::test]
    async fn metrics_endpoint_serves() {
        unsafe { std::env::set_var("METRICS_TOKEN", "testtoken") };
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(0, 1, shutdown, stats.clone(), portfolio.clone())
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
        unsafe { std::env::set_var("METRICS_TOKEN", "testtoken") };
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(0, 137, shutdown, stats.clone(), portfolio.clone())
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
    async fn shutdown_endpoint_stops_server() {
        unsafe { std::env::set_var("METRICS_TOKEN", "testtoken") };
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();

        let addr = spawn_metrics_server(0, 1, shutdown, stats.clone(), portfolio.clone())
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
}
