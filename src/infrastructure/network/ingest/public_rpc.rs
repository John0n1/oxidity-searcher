// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use crate::core::executor::SharedBundleSender;
use crate::core::strategy::{BundleTelemetry, StrategyStats};
use alloy::eips::eip2718::Decodable2718;
use alloy_consensus::{Transaction, TxEnvelope};
use ipnet::IpNet;
use reqwest::Client;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as TokioMutex, Semaphore};
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

const PUBLIC_RPC_MAX_REQUEST_BYTES: usize = 256 * 1024;
const PUBLIC_RPC_READ_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLIC_RPC_BUDGET_WINDOW: Duration = Duration::from_secs(60);
const PUBLIC_RPC_BUDGET_TTL: Duration = Duration::from_secs(5 * 60);
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

#[derive(Clone, Debug)]
pub struct PublicRpcIngressPolicyConfig {
    pub auth_token: Option<String>,
    pub allowed_cidrs: Vec<String>,
    pub max_concurrent_requests: usize,
    pub requests_per_minute: u32,
    pub send_raw_per_minute: u32,
    pub eth_call_per_minute: u32,
    pub eth_estimate_gas_per_minute: u32,
    pub eth_get_logs_per_minute: u32,
}

#[derive(Clone, Debug)]
struct PublicRpcIngressPolicy {
    auth_token: String,
    allowed_cidrs: Vec<IpNet>,
    max_concurrent_requests: usize,
    requests_per_minute: u32,
    send_raw_per_minute: u32,
    eth_call_per_minute: u32,
    eth_estimate_gas_per_minute: u32,
    eth_get_logs_per_minute: u32,
}

impl PublicRpcIngressPolicy {
    fn from_config(config: PublicRpcIngressPolicyConfig) -> Result<Self, String> {
        let auth_token = config
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "missing public RPC auth token".to_string())?
            .to_string();
        let mut allowed_cidrs = Vec::new();
        for entry in config.allowed_cidrs {
            let parsed = entry
                .trim()
                .parse::<IpNet>()
                .map_err(|err| format!("invalid CIDR '{entry}': {err}"))?;
            allowed_cidrs.push(parsed);
        }
        if allowed_cidrs.is_empty() {
            return Err("public RPC allowlist cannot be empty".to_string());
        }
        Ok(Self {
            auth_token,
            allowed_cidrs,
            max_concurrent_requests: config.max_concurrent_requests.max(1),
            requests_per_minute: config.requests_per_minute.max(1),
            send_raw_per_minute: config.send_raw_per_minute.max(1),
            eth_call_per_minute: config.eth_call_per_minute.max(1),
            eth_estimate_gas_per_minute: config.eth_estimate_gas_per_minute.max(1),
            eth_get_logs_per_minute: config.eth_get_logs_per_minute.max(1),
        })
    }

    fn is_authorized(&self, header: Option<&str>) -> bool {
        header
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .is_some_and(|token| token == self.auth_token)
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.allowed_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }

    fn method_budget(&self, method: &str) -> u32 {
        match method {
            "eth_sendRawTransaction" => self.send_raw_per_minute,
            "eth_call" => self.eth_call_per_minute,
            "eth_estimateGas" => self.eth_estimate_gas_per_minute,
            "eth_getLogs" => self.eth_get_logs_per_minute,
            _ => self.requests_per_minute,
        }
    }
}

#[derive(Default)]
struct PublicRpcRateLimiter {
    clients: HashMap<String, ClientBudgetWindow>,
}

struct ClientBudgetWindow {
    window_started_at: Instant,
    last_seen_at: Instant,
    total_count: u32,
    method_counts: HashMap<&'static str, u32>,
}

impl Default for ClientBudgetWindow {
    fn default() -> Self {
        Self {
            window_started_at: Instant::now(),
            last_seen_at: Instant::now(),
            total_count: 0,
            method_counts: HashMap::new(),
        }
    }
}

impl PublicRpcRateLimiter {
    fn allow(&mut self, client_key: &str, method: &str, policy: &PublicRpcIngressPolicy) -> bool {
        let now = Instant::now();
        self.clients
            .retain(|_, window| now.duration_since(window.last_seen_at) <= PUBLIC_RPC_BUDGET_TTL);

        let entry = self.clients.entry(client_key.to_string()).or_default();

        if now.duration_since(entry.window_started_at) >= PUBLIC_RPC_BUDGET_WINDOW {
            entry.window_started_at = now;
            entry.total_count = 0;
            entry.method_counts.clear();
        }
        entry.last_seen_at = now;

        if entry.total_count >= policy.requests_per_minute {
            return false;
        }
        let key = rate_limit_bucket(method);
        let method_budget = policy.method_budget(method);
        let current_method_count = entry.method_counts.get(key).copied().unwrap_or(0);
        if current_method_count >= method_budget {
            return false;
        }

        entry.total_count = entry.total_count.saturating_add(1);
        entry
            .method_counts
            .entry(key)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        true
    }
}

pub async fn spawn_public_rpc_ingress(
    port: u16,
    chain_id: u64,
    shutdown: CancellationToken,
    bind: Option<String>,
    bundle_sender: SharedBundleSender,
    stats: Arc<StrategyStats>,
    upstream_rpc_url: Option<String>,
    http_client: Client,
    policy_config: PublicRpcIngressPolicyConfig,
) -> Option<SocketAddr> {
    let policy = match PublicRpcIngressPolicy::from_config(policy_config) {
        Ok(policy) => Arc::new(policy),
        Err(error) => {
            tracing::warn!(
                target: "public_rpc",
                error = %error,
                "Public RPC ingress disabled"
            );
            return None;
        }
    };
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

    let limiter = Arc::new(TokioMutex::new(PublicRpcRateLimiter::default()));
    let semaphore = Arc::new(Semaphore::new(policy.max_concurrent_requests));
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
                Ok((socket, peer_addr)) => {
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tokio::spawn(async move {
                                let mut socket = socket;
                                let _ = write_http_json(
                                    &mut socket,
                                    "503 Service Unavailable",
                                    json!({"status":"error","error":"ingress busy"}),
                                )
                                .await;
                            });
                            continue;
                        }
                    };
                    let stats = stats.clone();
                    let bundle_sender = bundle_sender.clone();
                    let upstream_rpc_url = upstream_rpc_url.clone();
                    let http_client = http_client.clone();
                    let policy = policy.clone();
                    let limiter = limiter.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle_public_rpc_connection(
                            socket,
                            peer_addr,
                            chain_id,
                            bundle_sender,
                            stats,
                            upstream_rpc_url,
                            http_client,
                            policy,
                            limiter,
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
    peer_addr: SocketAddr,
    chain_id: u64,
    bundle_sender: SharedBundleSender,
    stats: Arc<StrategyStats>,
    upstream_rpc_url: Option<String>,
    http_client: Client,
    policy: Arc<PublicRpcIngressPolicy>,
    limiter: Arc<TokioMutex<PublicRpcRateLimiter>>,
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
    let client_ip = resolve_client_ip(peer_addr, &headers);

    if !policy.allows_ip(client_ip) {
        tracing::warn!(
            target: "public_rpc",
            client_ip = %client_ip,
            route,
            "Rejected public RPC request from disallowed network"
        );
        let _ = write_http_json(
            &mut socket,
            "403 Forbidden",
            json!({"status":"error","error":"forbidden"}),
        )
        .await;
        return;
    }

    if (method == "GET" || method == "HEAD") && route == "/health" {
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

    let auth_header = header_value(&headers, "authorization");
    if !policy.is_authorized(auth_header) {
        tracing::warn!(
            target: "public_rpc",
            client_ip = %client_ip,
            route,
            "Rejected public RPC request with missing or invalid auth"
        );
        let _ = write_http_json(
            &mut socket,
            "401 Unauthorized",
            json!({"status":"error","error":"unauthorized"}),
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

    {
        let mut guard = limiter.lock().await;
        if !guard.allow(&client_ip.to_string(), method, &policy) {
            tracing::warn!(
                target: "public_rpc",
                client_ip = %client_ip,
                method,
                "Rejected public RPC request due to rate limit"
            );
            let _ = write_http_json(
                &mut socket,
                "429 Too Many Requests",
                json!({"status":"error","error":"rate_limited"}),
            )
            .await;
            return;
        }
    }

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

fn header_value<'a>(headers: &'a [&'a str], key: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case(key) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn resolve_client_ip(peer_addr: SocketAddr, headers: &[&str]) -> IpAddr {
    if peer_addr.ip().is_loopback() {
        if let Some(forwarded) = header_value(headers, "x-forwarded-for")
            && let Some(ip) = forwarded
                .split(',')
                .find_map(|entry| entry.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
        if let Some(real_ip) = header_value(headers, "x-real-ip")
            && let Ok(ip) = real_ip.parse::<IpAddr>()
        {
            return ip;
        }
    }
    peer_addr.ip()
}

fn rate_limit_bucket(method: &str) -> &'static str {
    match method {
        "eth_sendRawTransaction" => "eth_sendRawTransaction",
        "eth_call" => "eth_call",
        "eth_estimateGas" => "eth_estimateGas",
        "eth_getLogs" => "eth_getLogs",
        _ => "default",
    }
}

async fn write_http_json(
    socket: &mut tokio::net::TcpStream,
    status: &str,
    body: Value,
) -> Result<(), std::io::Error> {
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::executor::BundleSender;
    use crate::core::strategy::StrategyStats;
    use crate::network::provider::HttpProvider;
    use alloy::eips::eip2718::Encodable2718;
    use alloy::network::TxSignerSync;
    use alloy::primitives::{Address, Bytes, TxKind, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use std::str::FromStr;
    use tokio_util::sync::CancellationToken;
    use url::Url;

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

    fn test_policy_config() -> PublicRpcIngressPolicyConfig {
        PublicRpcIngressPolicyConfig {
            auth_token: Some("test-rpc-token".to_string()),
            allowed_cidrs: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            max_concurrent_requests: 4,
            requests_per_minute: 16,
            send_raw_per_minute: 2,
            eth_call_per_minute: 2,
            eth_estimate_gas_per_minute: 2,
            eth_get_logs_per_minute: 1,
        }
    }

    fn test_bundle_sender(stats: Arc<StrategyStats>) -> SharedBundleSender {
        let signer: PrivateKeySigner =
            "59c6995e998f97a5a0044966f0945382d8ad7f7f6d0f7f6f4c6f9d5cb66f17d1"
                .parse()
                .expect("private key");
        Arc::new(BundleSender::new(
            HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").expect("rpc url")),
            Client::new(),
            true,
            "https://relay.flashbots.net".to_string(),
            "https://mev-share.flashbots.net".to_string(),
            Vec::new(),
            signer,
            stats,
            true,
            false,
            1,
        ))
    }

    async fn spawn_test_public_rpc(policy_config: PublicRpcIngressPolicyConfig) -> SocketAddr {
        let stats = Arc::new(StrategyStats::default());
        let shutdown = CancellationToken::new();
        spawn_public_rpc_ingress(
            0,
            1,
            shutdown,
            Some("127.0.0.1".to_string()),
            test_bundle_sender(stats.clone()),
            stats,
            Some("http://127.0.0.1:8545".to_string()),
            Client::new(),
            policy_config,
        )
        .await
        .expect("bind public rpc")
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

    #[test]
    fn policy_requires_non_empty_auth_token() {
        let mut config = test_policy_config();
        config.auth_token = None;
        assert!(PublicRpcIngressPolicy::from_config(config).is_err());
    }

    #[test]
    fn resolve_client_ip_prefers_forwarded_header_from_loopback_proxy() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 9545));
        let headers = vec!["X-Forwarded-For: 198.51.100.7, 127.0.0.1"];
        let resolved = resolve_client_ip(peer, &headers);
        assert_eq!(resolved, IpAddr::from_str("198.51.100.7").unwrap());
    }

    #[test]
    fn rate_limiter_enforces_total_and_method_budgets() {
        let policy = PublicRpcIngressPolicy::from_config(test_policy_config()).expect("policy");
        let mut limiter = PublicRpcRateLimiter::default();
        assert!(limiter.allow("127.0.0.1", "eth_getLogs", &policy));
        assert!(!limiter.allow("127.0.0.1", "eth_getLogs", &policy));
        assert!(limiter.allow("127.0.0.1", "eth_chainId", &policy));
    }

    #[tokio::test]
    async fn public_rpc_rejects_missing_auth_and_no_cors_header() {
        let addr = spawn_test_public_rpc(test_policy_config()).await;
        let response = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_chainId",
                "params": []
            }))
            .send()
            .await
            .expect("send request");

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[tokio::test]
    async fn public_rpc_rejects_disallowed_forwarded_ip() {
        let mut config = test_policy_config();
        config.allowed_cidrs = vec!["203.0.113.0/24".to_string()];
        let addr = spawn_test_public_rpc(config).await;
        let response = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .header("Authorization", "Bearer test-rpc-token")
            .header("X-Forwarded-For", "198.51.100.7")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_chainId",
                "params": []
            }))
            .send()
            .await
            .expect("send request");

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn public_rpc_enforces_per_method_budget() {
        let mut config = test_policy_config();
        config.requests_per_minute = 10;
        config.eth_get_logs_per_minute = 1;
        let addr = spawn_test_public_rpc(config).await;
        let client = reqwest::Client::new();
        let request = || {
            client
                .post(format!("http://{addr}"))
                .header("Authorization", "Bearer test-rpc-token")
                .json(&json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getLogs",
                    "params": [{}]
                }))
        };

        let first = request().send().await.expect("first request");
        assert_eq!(first.status(), reqwest::StatusCode::OK);
        let second = request().send().await.expect("second request");
        assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }
}
