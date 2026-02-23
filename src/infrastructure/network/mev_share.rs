// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use crate::common::parsing::{
    parse_address_hex, parse_b256_hex, parse_hex_bytes, parse_u64_hex, parse_u128_hex,
    parse_u256_hex,
};
use crate::common::seen_cache::remember_with_bounded_order;
use alloy::primitives::{Address, B256, U256};
use dashmap::DashSet;
use futures::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use crate::core::strategy::{StrategyStats, StrategyWork};
use crate::services::strategy::execution::work_queue::SharedWorkQueue;

#[derive(Debug, Clone)]
pub struct MevShareHint {
    pub tx_hash: B256,
    pub router: Address,
    pub from: Option<Address>,
    pub call_data: Vec<u8>,
    pub value: U256,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    #[allow(dead_code)]
    hash: Option<String>,
    #[serde(default)]
    txs: Option<Vec<RawTx>>,
}

#[derive(Debug, Deserialize)]
struct RawTx {
    #[serde(rename = "hash")]
    hash: Option<String>,
    #[serde(rename = "to")]
    to: Option<String>,
    #[serde(rename = "from")]
    from: Option<String>,
    #[serde(rename = "callData")]
    call_data: Option<String>,
    #[serde(rename = "value")]
    value: Option<String>,
    #[serde(rename = "gas")]
    gas: Option<String>,
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: Option<String>,
    #[serde(rename = "chainId")]
    chain_id: Option<String>,
}

/// Very small SSE client for MEV-Share streams. Converts events into StrategyWork hints.
pub struct MevShareClient {
    base_url: String,
    history_url: String,
    client: Client,
    chain_id: u64,
    seen: Arc<DashSet<B256>>,
    seen_order: Arc<Mutex<VecDeque<B256>>>,
    work_queue: SharedWorkQueue,
    stats: Arc<StrategyStats>,
    capacity: usize,
    history_limit: u32,
    shutdown: CancellationToken,
}

const SEEN_MAX: usize = 50_000;

impl MevShareClient {
    pub fn new(
        base_url: String,
        chain_id: u64,
        work_queue: SharedWorkQueue,
        stats: Arc<StrategyStats>,
        capacity: usize,
        history_limit: u32,
        shutdown: CancellationToken,
    ) -> Result<Self, AppError> {
        let history_url = format!("{}/api/v1/history", base_url.trim_end_matches('/'));
        let client = Client::builder()
            // Use a connect timeout, but keep the stream alive beyond 15s SSE pings.
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AppError::Initialization(format!("MEV-Share HTTP client init failed: {e}"))
            })?;

        Ok(Self {
            base_url,
            history_url,
            client,
            chain_id,
            seen: Arc::new(DashSet::new()),
            seen_order: Arc::new(Mutex::new(VecDeque::new())),
            work_queue,
            stats,
            capacity,
            history_limit,
            shutdown,
        })
    }

    pub async fn run(mut self) -> Result<(), AppError> {
        self.backfill_history().await?;
        let mut reconnect_backoff_secs: u64 = 2;
        loop {
            if self.shutdown.is_cancelled() {
                tracing::info!(target: "mev_share", "Shutdown requested; stopping MEV-Share client");
                return Ok(());
            }
            match self.stream_once().await {
                Ok(_) => {
                    reconnect_backoff_secs = 2;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let lower = msg.to_ascii_lowercase();
                    let is_transient = lower.contains("sse chunk error")
                        || lower.contains("sse stream ended unexpectedly");

                    if is_transient {
                        tracing::info!(
                            target: "mev_share",
                            error = %msg,
                            backoff_secs = reconnect_backoff_secs,
                            "Transient SSE disconnect; reconnecting"
                        );
                    } else {
                        tracing::warn!(
                            target: "mev_share",
                            error = %msg,
                            backoff_secs = reconnect_backoff_secs,
                            "Stream error, reconnecting"
                        );
                    }

                    // Best-effort gap fill after disconnect so we don't lose hints during reconnects.
                    if let Err(history_err) = self.backfill_history().await {
                        tracing::warn!(
                            target: "mev_share",
                            error = %history_err,
                            "History backfill during reconnect failed"
                        );
                    }

                    tokio::select! {
                        _ = self.shutdown.cancelled() => {
                            tracing::info!(target: "mev_share", "Shutdown requested during reconnect backoff");
                            return Ok(());
                        }
                        _ = sleep(Duration::from_secs(reconnect_backoff_secs)) => {}
                    }
                    reconnect_backoff_secs = (reconnect_backoff_secs.saturating_mul(2)).min(30);
                }
            }
        }
    }

    async fn backfill_history(&mut self) -> Result<(), AppError> {
        if self.history_limit == 0 {
            return Ok(());
        }
        if self.shutdown.is_cancelled() {
            return Ok(());
        }
        let url = format!("{}?limit={}", self.history_url, self.history_limit);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("History request failed: {}", e)))?;
        if !resp.status().is_success() {
            tracing::warn!(
                target: "mev_share",
                status = %resp.status(),
                "History endpoint returned non-success"
            );
            return Ok(());
        }

        let raw: Vec<HistoricalRecord> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "mev_share", error=%e, "Failed to decode history response");
                return Ok(());
            }
        };

        for rec in raw {
            if let Some(evt) = rec.hint {
                self.handle_event(evt).await;
            }
        }
        Ok(())
    }

    async fn stream_once(&mut self) -> Result<(), AppError> {
        if self.shutdown.is_cancelled() {
            return Ok(());
        }
        tracing::info!(target: "mev_share", url=%self.base_url, "Connecting to MEV-Share SSE");
        let resp = self
            .client
            .get(&self.base_url)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("SSE connect failed: {}", e)))?;
        if !resp.status().is_success() {
            if let Some(delay) = retry_after_delay(&resp) {
                tracing::warn!(
                    target: "mev_share",
                    delay_secs = %delay.as_secs(),
                    status = %resp.status(),
                    "SSE returned non-success; honoring Retry-After"
                );
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        return Ok(());
                    }
                    _ = sleep(delay) => {}
                }
            }
            return Err(AppError::Connection(format!(
                "SSE returned status {}",
                resp.status()
            )));
        }

        let mut stream = resp.bytes_stream();
        let mut buffer = String::new();

        loop {
            let maybe_chunk = tokio::select! {
                _ = self.shutdown.cancelled() => {
                    tracing::info!(target: "mev_share", "Shutdown requested; exiting SSE stream");
                    return Ok(());
                }
                chunk = stream.next() => chunk,
            };

            let Some(chunk) = maybe_chunk else {
                break;
            };
            let chunk =
                chunk.map_err(|e| AppError::Connection(format!("SSE chunk error: {}", e)))?;

            // Append chunk to buffer, being lossy with UTF-8 to prevent crashes on garbage data
            let chunk_str = String::from_utf8_lossy(&chunk);
            buffer.push_str(&chunk_str);

            while let Some((idx, delimiter_len)) = next_sse_event_boundary(&buffer) {
                let event_str = buffer[..idx].to_string();
                // Advance buffer past the event boundary (LF-LF or CRLF-CRLF).
                buffer.drain(..idx + delimiter_len);

                let mut data_lines = Vec::new();
                for line in event_str.lines() {
                    let line = line.trim();
                    if line.starts_with(':') {
                        continue;
                    }
                    if let Some(data) = line.strip_prefix("data:") {
                        data_lines.push(data.trim());
                    }
                }

                if data_lines.is_empty() {
                    continue;
                }

                let data = data_lines.join("\n");
                match serde_json::from_str::<Option<RawEvent>>(&data) {
                    Ok(Some(evt)) => self.handle_event(evt).await,
                    Ok(None) => {
                        // null or empty payloads are valid keep-alives from the service
                        tracing::debug!(target: "mev_share", "Ignored null SSE payload");
                    }
                    Err(e) => {
                        tracing::warn!(target: "mev_share", error=%e, "Failed to parse SSE data");
                    }
                }
            }

            // Safety cap: if buffer grows too large without finding \n\n, clear it to prevent OOM.
            if buffer.len() > 1024 * 1024 {
                tracing::warn!(target: "mev_share", len=buffer.len(), "Buffer too large without delimiter; clearing");
                buffer.clear();
            }
        }

        Err(AppError::Connection("SSE stream ended unexpectedly".into()))
    }

    async fn handle_event(&self, evt: RawEvent) {
        let Some(txs) = evt.txs else { return };

        for tx in txs {
            if let Some(hint) = self.convert_hint(tx) {
                let key = hint.tx_hash;
                if remember_with_bounded_order(&self.seen, &self.seen_order, key, SEEN_MAX).await {
                    self.enqueue(StrategyWork::MevShareHint {
                        hint: Box::new(hint),
                        received_at: std::time::Instant::now(),
                    })
                    .await;
                }
            }
        }
    }

    async fn enqueue(&self, work: StrategyWork) {
        let pushed = self.work_queue.push(work).await;
        self.stats.record_ingest_enqueue(pushed.dropped_oldest);
        if pushed.dropped_oldest {
            tracing::warn!(
                target: "mev_share",
                capacity = self.capacity,
                "ingest queue full; dropped oldest hint"
            );
        }
    }

    fn convert_hint(&self, raw: RawTx) -> Option<MevShareHint> {
        let tx_hash = raw.hash.as_deref().and_then(parse_b256_hex)?;
        let router = raw.to.as_deref().and_then(parse_address_hex)?;

        // Missing chainId is accepted, but malformed/invalid chainId is rejected.
        let chain_ok = match raw.chain_id.as_deref() {
            Some(raw_chain_id) => parse_u64_hex(raw_chain_id)
                .map(|cid| cid == self.chain_id)
                .unwrap_or(false),
            None => true,
        };

        if !chain_ok {
            return None;
        }

        let call_data = raw
            .call_data
            .as_deref()
            .and_then(parse_hex_bytes)
            .filter(|v| !v.is_empty())?;

        let value = raw
            .value
            .as_deref()
            .and_then(parse_u256_hex)
            .unwrap_or(U256::ZERO);
        let gas_limit = raw.gas.as_deref().and_then(parse_u64_hex);
        let max_fee_per_gas = raw.max_fee_per_gas.as_deref().and_then(parse_u128_hex);
        let max_priority_fee_per_gas = raw
            .max_priority_fee_per_gas
            .as_deref()
            .and_then(parse_u128_hex);
        let from = raw.from.as_deref().and_then(parse_address_hex);

        Some(MevShareHint {
            tx_hash,
            router,
            from,
            call_data,
            value,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }
}

#[derive(Debug, Deserialize)]
struct HistoricalRecord {
    #[serde(rename = "hint")]
    hint: Option<RawEvent>,
}

fn retry_after_delay(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn next_sse_event_boundary(buffer: &str) -> Option<(usize, usize)> {
    let lf = buffer.find("\n\n").map(|idx| (idx, 2usize));
    let crlf = buffer.find("\r\n\r\n").map(|idx| (idx, 4usize));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::strategy::execution::work_queue::WorkQueue;

    #[test]
    fn parses_null_txs_hint() {
        let json = r#"{"hash":"0xabc","txs":null}"#;
        let evt: RawEvent = serde_json::from_str(json).expect("parse");
        assert!(evt.txs.is_none());
    }

    #[test]
    fn parses_null_event_payload() {
        let evt: Option<RawEvent> = serde_json::from_str("null").expect("parse");
        assert!(evt.is_none());
    }

    fn test_client(chain_id: u64) -> MevShareClient {
        MevShareClient::new(
            "http://localhost:9000".to_string(),
            chain_id,
            Arc::new(WorkQueue::new(8)),
            Arc::new(StrategyStats::default()),
            8,
            0,
            CancellationToken::new(),
        )
        .expect("client")
    }

    fn base_raw_tx() -> RawTx {
        RawTx {
            hash: Some(
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            to: Some("0x2222222222222222222222222222222222222222".to_string()),
            from: Some("0x3333333333333333333333333333333333333333".to_string()),
            call_data: Some("0xaabbcc".to_string()),
            value: Some("0x2a".to_string()),
            gas: Some("0x5208".to_string()),
            max_fee_per_gas: Some("0x3b9aca00".to_string()),
            max_priority_fee_per_gas: Some("0x77359400".to_string()),
            chain_id: Some("0x1".to_string()),
        }
    }

    #[test]
    fn convert_hint_rejects_malformed_chain_id() {
        let client = test_client(1);
        let mut raw = base_raw_tx();
        raw.chain_id = Some("not-hex".to_string());
        assert!(client.convert_hint(raw).is_none());
    }

    #[test]
    fn convert_hint_accepts_uppercase_hex_prefixes() {
        let client = test_client(1);
        let mut raw = base_raw_tx();
        raw.hash =
            Some("0Xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        raw.to = Some("0X4444444444444444444444444444444444444444".to_string());
        raw.call_data = Some("0Xdeadbeef".to_string());
        raw.chain_id = Some("0X1".to_string());
        raw.value = Some("0X2A".to_string());

        let hint = client.convert_hint(raw).expect("hint");
        assert_eq!(hint.call_data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hint.value, U256::from(42u64));
    }

    #[test]
    fn sse_boundary_detects_lf_and_crlf_events() {
        let lf = next_sse_event_boundary("data: {}\n\nnext");
        assert_eq!(lf, Some((8, 2)));

        let crlf = next_sse_event_boundary("data: {}\r\n\r\nnext");
        assert_eq!(crlf, Some((8, 4)));
    }

    #[test]
    fn sse_boundary_picks_earliest_delimiter() {
        let boundary = next_sse_event_boundary("a\r\n\r\nb\n\n");
        assert_eq!(boundary, Some((1, 4)));
    }
}
