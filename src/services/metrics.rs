// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::app::logging::{recent_logs, set_log_level};
use crate::core::portfolio::PortfolioManager;
use crate::core::strategy::StrategyStats;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn spawn_metrics_server(
    port: u16,
    stats: Arc<StrategyStats>,
    portfolio: Arc<PortfolioManager>,
) -> Option<SocketAddr> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
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

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    // Very small HTTP parser to switch between Prometheus text and JSON dashboard payloads.
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (route, query) = path.split_once('?').unwrap_or((path, ""));

                    if route.starts_with("/dashboard") {
                        let body = render_dashboard_json(&stats, &portfolio);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/bundles") {
                        // Placeholder bundle payload; extend when bundle history is persisted.
                        let body = r#"{"history":[],"table":[]}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if route.starts_with("/logs") {
                        let logs = recent_logs(200);
                        let body = serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string());
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
                                Ok(_) => ("200 OK", json!({"status": "ok", "level": lvl}).to_string()),
                                Err(e) => ("400 Bad Request", json!({"status": "error", "error": e}).to_string()),
                            },
                            None => ("400 Bad Request", json!({"status": "error", "error": "missing level"}).to_string()),
                        };

                        let response = format!(
                            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            status,
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let body = render_metrics(&stats, &portfolio);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
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
    let mut body = format!(
        concat!(
            "# TYPE strategy_processed counter\nstrategy_processed {}\n",
            "# TYPE strategy_submitted counter\nstrategy_submitted {}\n",
            "# TYPE strategy_skipped counter\nstrategy_skipped {}\n",
            "# TYPE strategy_failed counter\nstrategy_failed {}\n"
        ),
        processed, submitted, skipped, failed
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

fn render_dashboard_json(stats: &Arc<StrategyStats>, portfolio: &Arc<PortfolioManager>) -> String {
    let processed = stats.processed.load(std::sync::atomic::Ordering::Relaxed);
    let submitted = stats.submitted.load(std::sync::atomic::Ordering::Relaxed);
    let skipped = stats.skipped.load(std::sync::atomic::Ordering::Relaxed);
    let failed = stats.failed.load(std::sync::atomic::Ordering::Relaxed);
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
        "processed": processed,
        "submitted": submitted,
        "skipped": skipped,
        "failed": failed,
        "successRate": success_rate,
        "netProfitEth": total_profit,
        "netProfitByChain": net_profit_by_chain,
        "tokenProfit": token_profit,
        "history": [], // reserved for future bundle history wiring
        "table": []    // reserved for future bundle table wiring
    });

    payload.to_string()
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
        let provider = HttpProvider::new_http(Url::parse("http://localhost:8545").unwrap());
        let portfolio = Arc::new(PortfolioManager::new(provider, Address::ZERO));
        let stats = Arc::new(StrategyStats::default());

        let addr = spawn_metrics_server(0, stats.clone(), portfolio.clone())
            .await
            .expect("bind metrics");

        let body = reqwest::get(format!("http://{}", addr))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert!(body.contains("strategy_processed"));
    }
}
