// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use alloy::primitives::{Address, B256, U256};
use dashmap::DashSet;
use futures::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Sender, error::TrySendError};
use tokio::time::{Duration, sleep};

use crate::core::strategy::{StrategyStats, StrategyWork};

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
    tx_sender: Sender<StrategyWork>,
    stats: Arc<StrategyStats>,
    capacity: usize,
    history_limit: u32,
}

const SEEN_MAX: usize = 50_000;

impl MevShareClient {
    pub fn new(
        base_url: String,
        chain_id: u64,
        tx_sender: Sender<StrategyWork>,
        stats: Arc<StrategyStats>,
        capacity: usize,
        history_limit: u32,
    ) -> Self {
        let history_url = format!("{}/api/v1/history", base_url.trim_end_matches('/'));
        Self {
            base_url,
            history_url,
            client: Client::builder()
                // Use a connect timeout, but keep the stream alive beyond 15s SSE pings.
                .connect_timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            chain_id,
            seen: Arc::new(DashSet::new()),
            seen_order: Arc::new(Mutex::new(VecDeque::new())),
            tx_sender,
            stats,
            capacity,
            history_limit,
        }
    }

    pub async fn run(mut self) -> Result<(), AppError> {
        self.backfill_history().await?;
        loop {
            match self.stream_once().await {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(target: "mev_share", error=%e, "Stream error, reconnecting");
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn backfill_history(&mut self) -> Result<(), AppError> {
        if self.history_limit == 0 {
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
                sleep(delay).await;
            }
            return Err(AppError::Connection(format!(
                "SSE returned status {}",
                resp.status()
            )));
        }

        let mut stream = resp.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| AppError::Connection(format!("SSE chunk error: {}", e)))?;
            let normalized = String::from_utf8_lossy(&chunk);
            buffer.push_str(&normalized.replace("\r\n", "\n"));

            while let Some(idx) = buffer.find("\n\n") {
                let event = buffer[..idx].to_string();
                buffer = buffer[idx + 2..].to_string();

                let mut data_lines = Vec::new();
                for line in event.lines() {
                    let line = line.trim_end_matches('\r');
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
        }

        Err(AppError::Connection("SSE stream ended unexpectedly".into()))
    }

    async fn record_seen(&self, key: B256) {
        let mut order = self.seen_order.lock().await;
        order.push_back(key);
        if order.len() > SEEN_MAX {
            if let Some(oldest) = order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    async fn handle_event(&self, evt: RawEvent) {
        let Some(txs) = evt.txs else { return };

        for tx in txs {
            if let Some(hint) = self.convert_hint(tx) {
                let key = hint.tx_hash;
                if self.seen.insert(key) {
                    self.record_seen(key).await;
                    self.enqueue(StrategyWork::MevShareHint {
                        hint,
                        received_at: std::time::Instant::now(),
                    });
                }
            }
        }
    }

    fn enqueue(&self, work: StrategyWork) {
        match self.tx_sender.try_send(work) {
            Ok(()) => {
                self.stats
                    .ingest_queue_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.stats
                    .ingest_queue_full
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats
                    .ingest_queue_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats
                    .ingest_backpressure
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    target: "mev_share",
                    capacity = self.capacity,
                    "ingest channel full; dropped hint"
                );
            }
            Err(TrySendError::Closed(_)) => {
                tracing::warn!(target: "mev_share", "ingest channel closed; dropping hint");
            }
        }
    }

    fn convert_hint(&self, raw: RawTx) -> Option<MevShareHint> {
        let tx_hash = raw.hash.as_deref().and_then(parse_b256)?;
        let router = raw.to.as_deref().and_then(parse_address)?;
        let chain_ok = raw
            .chain_id
            .as_deref()
            .and_then(parse_u64_hex)
            .map(|cid| cid == self.chain_id)
            .unwrap_or(true);
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
        let from = raw.from.as_deref().and_then(parse_address);

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

#[cfg(test)]
mod tests {
    use super::*;

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
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(strip_0x(s)).ok()
}

fn parse_b256(s: &str) -> Option<B256> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

fn parse_address(s: &str) -> Option<Address> {
    Address::from_str(strip_0x(s)).ok()
}

fn parse_u256_hex(s: &str) -> Option<U256> {
    U256::from_str_radix(strip_0x(s), 16).ok()
}

fn parse_u128_hex(s: &str) -> Option<u128> {
    u128::from_str_radix(strip_0x(s), 16).ok()
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(strip_0x(s), 16).ok()
}

fn retry_after_delay(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}
