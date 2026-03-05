// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::core::executor::SharedBundleSender;
use crate::core::strategy::{BundleTelemetry, StrategyStats};
use alloy::eips::eip2718::Decodable2718;
use alloy_consensus::{Transaction, TxEnvelope};
use reqwest::Client;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

const PUBLIC_RPC_MAX_REQUEST_BYTES: usize = 256 * 1024;
const PUBLIC_RPC_READ_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLIC_RPC_LOCAL_METHODS: [&str; 4] = [
    "eth_sendRawTransaction",
    "eth_chainId",
    "net_version",
    "web3_clientVersion",
];
const PUBLIC_RPC_PASSTHROUGH_READ_METHODS: [&str; 20] = [
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_call",
    "eth_estimateGas",
    "eth_gasPrice",
    "eth_feeHistory",
    "eth_maxPriorityFeePerGas",
    "eth_getLogs",
    "eth_syncing",
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
    upstream_rpc_url: Option<String>,
    http_client: Client,
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
                Ok((socket, _)) => {
                    let stats = stats.clone();
                    let bundle_sender = bundle_sender.clone();
                    let upstream_rpc_url = upstream_rpc_url.clone();
                    let http_client = http_client.clone();
                    tokio::spawn(async move {
                        handle_public_rpc_connection(
                            socket,
                            chain_id,
                            bundle_sender,
                            stats,
                            upstream_rpc_url,
                            http_client,
                        )
                        .await;
                    });
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

async fn handle_public_rpc_connection(
    mut socket: TcpStream,
    chain_id: u64,
    bundle_sender: SharedBundleSender,
    stats: Arc<StrategyStats>,
    upstream_rpc_url: Option<String>,
    http_client: Client,
) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut too_large = false;
    loop {
        let n = match timeout(PUBLIC_RPC_READ_TIMEOUT, socket.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return,
            Err(_) => {
                let _ = write_http_json(
                    &mut socket,
                    "408 Request Timeout",
                    json!({"status":"error","error":"request timeout"}),
                )
                .await;
                return;
            }
        };
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
        return;
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
        return;
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
        return;
    }

    if method != "POST" || route != "/" {
        let _ = write_http_json(
            &mut socket,
            "404 Not Found",
            json!({"status":"error","error":"not found"}),
        )
        .await;
        return;
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
        return;
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = match timeout(PUBLIC_RPC_READ_TIMEOUT, socket.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return,
            Err(_) => {
                let _ = write_http_json(
                    &mut socket,
                    "408 Request Timeout",
                    json!({"status":"error","error":"request timeout"}),
                )
                .await;
                return;
            }
        };
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
        return;
    }

    if content_length > 0 {
        if body.len() < content_length {
            let _ = write_http_json(
                &mut socket,
                "400 Bad Request",
                json!({"status":"error","error":"short request body"}),
            )
            .await;
            return;
        }
        body.truncate(content_length);
    }

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let payload = jsonrpc_error(Value::Null, -32700, "parse error");
            let _ = write_http_json(&mut socket, "200 OK", payload).await;
            return;
        }
    };

    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let method = parsed
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let response_payload = if is_public_local_method_allowed(method) {
        match method {
            "eth_sendRawTransaction" => {
                let raw = match raw_tx_from_params(parsed.get("params")) {
                    Ok(bytes) => bytes,
                    Err(msg) => {
                        let payload = jsonrpc_error(id.clone(), -32602, msg);
                        let _ = write_http_json(&mut socket, "200 OK", payload).await;
                        return;
                    }
                };

                let tx_hash = match validate_raw_transaction_payload(&raw, chain_id) {
                    Ok(hash) => hash,
                    Err(msg) => {
                        let payload = jsonrpc_error(id.clone(), -32602, msg);
                        let _ = write_http_json(&mut socket, "200 OK", payload).await;
                        return;
                    }
                };
                let bundle = vec![raw];
                match bundle_sender.send_bundle(&bundle, chain_id).await {
                    Ok(_) => {
                        stats.record_bundle(BundleTelemetry {
                            tx_hash: tx_hash.clone(),
                            source: "public_rpc".to_string(),
                            decision_path: "private_only".to_string(),
                            status: "Pending".to_string(),
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
                    Err(e) => {
                        stats.record_bundle(BundleTelemetry {
                            tx_hash: tx_hash.clone(),
                            source: "public_rpc".to_string(),
                            decision_path: "private_only".to_string(),
                            status: "Failed".to_string(),
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
                        jsonrpc_error(id, -32000, &format!("private submission failed: {e}"))
                    }
                }
            }
            "eth_chainId" => jsonrpc_result(id, Value::String(format!("0x{chain_id:x}"))),
            "net_version" => jsonrpc_result(id, Value::String(chain_id.to_string())),
            "web3_clientVersion" => jsonrpc_result(
                id,
                Value::String("oxidity-searcher/private-gateway".to_string()),
            ),
            _ => jsonrpc_error(id, -32601, "method not found"),
        }
    } else if is_public_passthrough_read_method(method) {
        let params = parsed.get("params").cloned();
        forward_read_rpc_method(
            upstream_rpc_url.as_deref(),
            &http_client,
            method,
            id,
            params,
        )
        .await
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

fn is_public_local_method_allowed(method: &str) -> bool {
    PUBLIC_RPC_LOCAL_METHODS.contains(&method)
}

fn is_public_passthrough_read_method(method: &str) -> bool {
    PUBLIC_RPC_PASSTHROUGH_READ_METHODS.contains(&method)
}

fn is_public_method_blocked(method: &str) -> bool {
    let lower = method.to_ascii_lowercase();
    PUBLIC_RPC_BLOCKED_EXACT_METHODS.contains(&lower.as_str())
        || PUBLIC_RPC_BLOCKED_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

async fn forward_read_rpc_method(
    upstream_rpc_url: Option<&str>,
    http_client: &Client,
    method: &str,
    id: Value,
    params: Option<Value>,
) -> Value {
    let Some(upstream) = upstream_rpc_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
    else {
        return jsonrpc_error(id, -32000, "upstream RPC unavailable");
    };

    let payload = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "method": method,
        "params": params.unwrap_or_else(|| Value::Array(Vec::new())),
    });
    let response = match http_client.post(upstream).json(&payload).send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(
                target: "public_rpc",
                method,
                upstream = %upstream,
                error = %e,
                "Read passthrough request failed"
            );
            return jsonrpc_error(id, -32000, "upstream read request failed");
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            target: "public_rpc",
            method,
            upstream = %upstream,
            status = %response.status(),
            "Read passthrough returned non-success status"
        );
        return jsonrpc_error(
            id,
            -32000,
            &format!("upstream RPC status {}", response.status().as_u16()),
        );
    }

    match response.json::<Value>().await {
        Ok(mut value) => {
            if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return jsonrpc_error(id, -32000, "upstream RPC returned invalid JSON-RPC payload");
            }
            if value.get("id").is_none()
                && let Some(obj) = value.as_object_mut()
            {
                obj.insert("id".to_string(), id);
            }
            value
        }
        Err(e) => {
            tracing::warn!(
                target: "public_rpc",
                method,
                upstream = %upstream,
                error = %e,
                "Read passthrough response decode failed"
            );
            jsonrpc_error(id, -32000, "upstream RPC decode failed")
        }
    }
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

fn validate_raw_transaction_payload(
    raw: &[u8],
    expected_chain_id: u64,
) -> Result<String, &'static str> {
    let envelope = TxEnvelope::decode_2718_exact(raw)
        .map_err(|_| "raw transaction is not valid EIP-2718 encoded transaction")?;
    let tx_chain_id = envelope
        .chain_id()
        .ok_or("raw transaction missing chain_id")?;
    if tx_chain_id != expected_chain_id {
        return Err("raw transaction chain_id mismatch");
    }
    Ok(format!("{:#x}", envelope.tx_hash()))
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
    use alloy::eips::eip2718::Encodable2718;
    use alloy::network::TxSignerSync;
    use alloy::primitives::{Address, Bytes, TxKind, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};

    fn signed_test_raw_tx(chain_id: u64) -> Vec<u8> {
        let signer: PrivateKeySigner =
            "59c6995e998f97a5a0044966f0945382d8ad7f7f6d0f7f6f4c6f9d5cb66f17d1"
                .parse()
                .expect("private key");
        let mut tx = TxEip1559 {
            chain_id,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::from([0x11u8; 20])),
            value: U256::from(1u64),
            access_list: Default::default(),
            input: Bytes::new(),
        };
        let sig = TxSignerSync::sign_transaction_sync(&signer, &mut tx).expect("sign tx");
        let signed: TxEnvelope = tx.into_signed(sig).into();
        signed.encoded_2718()
    }

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
    fn raw_tx_payload_validation_rejects_invalid_envelope() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(validate_raw_transaction_payload(&raw, 1).is_err());
    }

    #[test]
    fn raw_tx_payload_validation_enforces_chain_id() {
        let raw = signed_test_raw_tx(1);
        assert!(validate_raw_transaction_payload(&raw, 137).is_err());
    }

    #[test]
    fn raw_tx_payload_validation_accepts_valid_transaction() {
        let raw = signed_test_raw_tx(1);
        let hash = validate_raw_transaction_payload(&raw, 1).expect("valid raw tx");
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66);
    }

    #[test]
    fn allowlist_accepts_expected_methods_only() {
        assert!(is_public_local_method_allowed("eth_sendRawTransaction"));
        assert!(is_public_local_method_allowed("eth_chainId"));
        assert!(is_public_local_method_allowed("net_version"));
        assert!(is_public_local_method_allowed("web3_clientVersion"));
        assert!(!is_public_local_method_allowed("eth_getBalance"));
    }

    #[test]
    fn passthrough_allowlist_includes_wallet_read_methods() {
        assert!(is_public_passthrough_read_method("eth_getBalance"));
        assert!(is_public_passthrough_read_method("eth_getTransactionCount"));
        assert!(is_public_passthrough_read_method("eth_call"));
        assert!(is_public_passthrough_read_method("eth_estimateGas"));
        assert!(is_public_passthrough_read_method("eth_feeHistory"));
        assert!(!is_public_passthrough_read_method("eth_sendTransaction"));
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
