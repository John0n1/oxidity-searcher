// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

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

                    let route = path.split('?').next().unwrap_or(path);

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
                        let body =
                            json!({"status":"ok","message":"shutdown_requested"}).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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

    body
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
