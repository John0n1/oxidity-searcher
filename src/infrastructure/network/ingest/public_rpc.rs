// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::core::executor::SharedBundleSender;
use crate::core::strategy::{BundleTelemetry, StrategyStats};
use alloy::primitives::keccak256;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const PUBLIC_RPC_MAX_REQUEST_BYTES: usize = 256 * 1024;
const PUBLIC_RPC_ALLOWED_METHODS: [&str; 4] = [
    "eth_sendRawTransaction",
    "eth_chainId",
    "net_version",
    "web3_clientVersion",
];
const PUBLIC_RPC_BLOCKED_PREFIXES: [&str; 11] = [
    "admin_",
    "debug_",
    "txpool_",
    "trace_",
    "personal_",
    "engine_",
    "miner_",
    "parity_",
    "rpc_",
    "ots_",
    "wallet_",
];
const PUBLIC_RPC_BLOCKED_EXACT_METHODS: [&str; 7] = [
    "eth_sendtransaction",
    "eth_sign",
    "eth_signtypeddata",
    "eth_signtypeddata_v3",
    "eth_signtypeddata_v4",
    "eth_accounts",
    "eth_requestaccounts",
];

pub async fn spawn_public_rpc_ingress(
    port: u16,
    chain_id: u64,
    shutdown: CancellationToken,
    bind: Option<String>,
    bundle_sender: SharedBundleSender,
    stats: Arc<StrategyStats>,
) -> Option<SocketAddr> {
    let bind_addr = bind
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("127.0.0.1")
        .to_string();
    let addr: SocketAddr = match format!("{}:{}", bind_addr, port).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                target: "public_rpc",
                bind = %bind_addr,
                port,
                error = %e,
                "Invalid public RPC bind address; falling back to 127.0.0.1"
            );
            SocketAddr::from(([127, 0, 0, 1], port))
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                target: "public_rpc",
                bind = %addr,
                error = %e,
                "Public RPC ingress failed to bind"
            );
            return None;
        }
    };

    let local = listener.local_addr().ok();
    if let Some(addr) = local {
        tracing::info!(
            target: "public_rpc",
            listen = %addr,
            "Public RPC ingress online"
        );
    }

    tokio::spawn(async move {
        loop {
            let accept_result = tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!(target: "public_rpc", "Shutdown requested; stopping public RPC ingress");
                    break;
                }
                accept = listener.accept() => accept,
            };

            match accept_result {
                Ok((mut socket, _)) => {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let mut too_large = false;
                    loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        if buf.len().saturating_add(n) > PUBLIC_RPC_MAX_REQUEST_BYTES {
                            too_large = true;
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if header_end_offset(&buf).is_some() {
                            break;
                        }
                    }

                    if too_large {
                        let _ = write_http_json(
                            &mut socket,
                            "413 Payload Too Large",
                            json!({"status":"error","error":"request too large"}),
                        )
                        .await;
                        continue;
                    }

                    let Some(header_end) = header_end_offset(&buf) else {
                        if !buf.is_empty() {
                            let _ = write_http_json(
                                &mut socket,
                                "400 Bad Request",
                                json!({"status":"error","error":"malformed request"}),
                            )
                            .await;
                        }
                        continue;
                    };

                    let req_head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let mut lines = req_head.lines();
                    let request_line = lines.next().unwrap_or_default();
                    let mut req_parts = request_line.split_whitespace();
                    let method = req_parts.next().unwrap_or("");
                    let path = req_parts.next().unwrap_or("/");
                    let route = path.split('?').next().unwrap_or(path);
                    let headers: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();

                    if method == "GET" && route == "/health" {
                        let _ = write_http_json(
                            &mut socket,
                            "200 OK",
                            json!({"status":"ok","chainId":chain_id}),
                        )
                        .await;
                        continue;
                    }

                    if method != "POST" || route != "/" {
                        let _ = write_http_json(
                            &mut socket,
                            "404 Not Found",
                            json!({"status":"error","error":"not found"}),
                        )
                        .await;
                        continue;
                    }

                    let content_length = headers
                        .iter()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);

                    if content_length > PUBLIC_RPC_MAX_REQUEST_BYTES {
                        let _ = write_http_json(
                            &mut socket,
                            "413 Payload Too Large",
                            json!({"status":"error","error":"request too large"}),
                        )
                        .await;
                        continue;
                    }

                    let mut body = buf[header_end..].to_vec();
                    while body.len() < content_length {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        if body.len().saturating_add(n) > PUBLIC_RPC_MAX_REQUEST_BYTES {
                            too_large = true;
                            break;
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    if too_large {
                        let _ = write_http_json(
                            &mut socket,
                            "413 Payload Too Large",
                            json!({"status":"error","error":"request too large"}),
                        )
                        .await;
                        continue;
                    }

                    if content_length > 0 {
                        if body.len() < content_length {
                            let _ = write_http_json(
                                &mut socket,
                                "400 Bad Request",
                                json!({"status":"error","error":"short request body"}),
                            )
                            .await;
                            continue;
                        }
                        body.truncate(content_length);
                    }

                    let parsed: Value = match serde_json::from_slice(&body) {
                        Ok(v) => v,
                        Err(_) => {
                            let payload = jsonrpc_error(Value::Null, -32700, "parse error");
                            let _ = write_http_json(&mut socket, "200 OK", payload).await;
                            continue;
                        }
                    };

                    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
                    let method = parsed
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or_default();

                    let response_payload = if is_public_method_allowed(method) {
                        match method {
                            "eth_sendRawTransaction" => {
                                let raw = match raw_tx_from_params(parsed.get("params")) {
                                    Ok(bytes) => bytes,
                                    Err(msg) => {
                                        let payload = jsonrpc_error(id.clone(), -32602, msg);
                                        let _ = write_http_json(&mut socket, "200 OK", payload).await;
                                        continue;
                                    }
                                };

                                let tx_hash = format!("{:#x}", keccak256(&raw));
                                let bundle = vec![raw];
                                match bundle_sender.send_bundle(&bundle, chain_id).await {
                                    Ok(_) => {
                                        stats.record_bundle(BundleTelemetry {
                                            tx_hash: tx_hash.clone(),
                                            source: "public_rpc".to_string(),
                                            decision_path: "pass_through".to_string(),
                                            status: "Submitted".to_string(),
                                            profit_eth: 0.0,
                                            gas_cost_eth: 0.0,
                                            net_eth: 0.0,
                                            gas_covered_eth: 0.0,
                                            gas_refunded_eth: 0.0,
                                            retained_eth: 0.0,
                                            rebate_eth: 0.0,
                                            native_usd_price: 0.0,
                                            timestamp_ms: chrono::Utc::now().timestamp_millis(),
                                        });
                                        jsonrpc_result(id, Value::String(tx_hash))
                                    }
                                    Err(e) => jsonrpc_error(
                                        id,
                                        -32000,
                                        &format!("private submission failed: {e}"),
                                    ),
                                }
                            }
                            "eth_chainId" => {
                                jsonrpc_result(id, Value::String(format!("0x{chain_id:x}")))
                            }
                            "net_version" => jsonrpc_result(id, Value::String(chain_id.to_string())),
                            "web3_clientVersion" => jsonrpc_result(
                                id,
                                Value::String("oxidity-searcher/private-gateway".to_string()),
                            ),
                            _ => jsonrpc_error(id, -32601, "method not found"),
                        }
                    } else if is_public_method_blocked(method) {
                        tracing::warn!(
                            target: "public_rpc",
                            method = method,
                            "Blocked dangerous JSON-RPC method on public ingress"
                        );
                        jsonrpc_error(id, -32601, "method disabled on public gateway")
                    } else {
                        jsonrpc_error(id, -32601, "method not found")
                    };

                    let _ = write_http_json(&mut socket, "200 OK", response_payload).await;
                }
                Err(e) => {
                    tracing::warn!(target: "public_rpc", error = %e, "Public RPC accept error");
                    continue;
                }
            }
        }
    });

    local
}

fn is_public_method_allowed(method: &str) -> bool {
    PUBLIC_RPC_ALLOWED_METHODS.contains(&method)
}

fn is_public_method_blocked(method: &str) -> bool {
    let lower = method.to_ascii_lowercase();
    PUBLIC_RPC_BLOCKED_EXACT_METHODS.contains(&lower.as_str())
        || PUBLIC_RPC_BLOCKED_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

fn raw_tx_from_params(params: Option<&Value>) -> Result<Vec<u8>, &'static str> {
    let raw_hex = params
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .ok_or("invalid params")?;
    let compact = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
    if compact.is_empty() {
        return Err("raw transaction payload is empty");
    }
    hex::decode(compact).map_err(|_| "raw transaction must be hex")
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

fn header_end_offset(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|idx| idx + 2))
}

async fn write_http_json(
    socket: &mut tokio::net::TcpStream,
    status: &str,
    body: Value,
) -> Result<(), std::io::Error> {
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_tx_param_accepts_prefixed_hex() {
        let params = json!(["0x1234abcd"]);
        let parsed = raw_tx_from_params(Some(&params)).expect("parse tx hex");
        assert_eq!(parsed, vec![0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn raw_tx_param_rejects_invalid_values() {
        let params = json!([123]);
        assert!(raw_tx_from_params(Some(&params)).is_err());
    }

    #[test]
    fn allowlist_accepts_expected_methods_only() {
        assert!(is_public_method_allowed("eth_sendRawTransaction"));
        assert!(is_public_method_allowed("eth_chainId"));
        assert!(is_public_method_allowed("net_version"));
        assert!(is_public_method_allowed("web3_clientVersion"));
        assert!(!is_public_method_allowed("eth_getBalance"));
    }

    #[test]
    fn blocked_method_detection_catches_dangerous_namespaces() {
        assert!(is_public_method_blocked("admin_nodeInfo"));
        assert!(is_public_method_blocked("debug_traceCall"));
        assert!(is_public_method_blocked("txpool_content"));
        assert!(is_public_method_blocked("engine_exchangeCapabilities"));
        assert!(is_public_method_blocked("eth_sendTransaction"));
        assert!(is_public_method_blocked("ETH_SENDTRANSACTION"));
        assert!(!is_public_method_blocked("eth_chainId"));
    }
}
