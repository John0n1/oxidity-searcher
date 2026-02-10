// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use crate::services::strategy::strategy::StrategyStats;
use crate::services::strategy::time_utils::current_unix;
use alloy::primitives::keccak256;
use alloy::providers::Provider;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum BundleItem {
    Hash {
        hash: String,
    },
    Tx {
        tx: String,
        #[serde(rename = "canRevert")]
        can_revert: bool,
    },
}

/// Sends bundles or raw transactions to the network/relays.
pub struct BundleSender {
    provider: HttpProvider,
    dry_run: bool,
    relay_url: String,
    mev_share_relay_url: String,
    mevshare_builders: Vec<String>,
    signer: PrivateKeySigner,
    stats: Arc<StrategyStats>,
}

const FLASHBOTS_MAX_TXS: usize = 100;
const FLASHBOTS_MAX_BYTES: usize = 300_000;
const RELAY_TIMEOUT_MS: u64 = 2_500;
const RELAY_MAX_ATTEMPTS: u64 = 2;
const DEFAULT_MEVSHARE_BUILDERS: [&str; 4] = ["flashbots", "beaverbuild.org", "rsync", "Titan"];

impl BundleSender {
    pub fn new(
        provider: HttpProvider,
        dry_run: bool,
        relay_url: String,
        mev_share_relay_url: String,
        mevshare_builders: Vec<String>,
        signer: PrivateKeySigner,
        stats: Arc<StrategyStats>,
    ) -> Self {
        let mut builders: Vec<String> = mevshare_builders
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if builders.is_empty() {
            builders = DEFAULT_MEVSHARE_BUILDERS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }
        Self {
            provider,
            dry_run,
            relay_url,
            mev_share_relay_url,
            mevshare_builders: builders,
            signer,
            stats,
        }
    }

    /// Send a MEV-Share bundle that references tx hashes (instead of raw bytes).
    pub async fn send_mev_share_bundle(&self, body: &[BundleItem]) -> Result<(), AppError> {
        let hash_count = body
            .iter()
            .filter(|item| matches!(item, BundleItem::Hash { .. }))
            .count();
        let tx_count = body
            .iter()
            .filter(|item| matches!(item, BundleItem::Tx { .. }))
            .count();
        if body.len() != 2 || hash_count != 1 || tx_count != 1 {
            return Err(AppError::Strategy(
                "MEV-Share requires exactly one victim hash and one backrun tx".into(),
            ));
        }

        if self.dry_run {
            tracing::info!(target: "executor", "Dry-run: would send mev_sendBundle with {} legs", body.len());
            self.stats
                .record_relay_attempt("mev_share_dry_run", true, false, 0);
            return Ok(());
        }

        let block_number =
            self.provider.get_block_number().await.map_err(|e| {
                AppError::Connection(format!("Failed to fetch block number: {}", e))
            })?;
        let params = json!({
            "version": "v0.1",
            "inclusion": {
                "block": format!("0x{:x}", block_number + 1),
                "maxBlock": format!("0x{:x}", block_number + 4),
            },
            "body": body,
            "privacy": {
                "builders": self.mevshare_builders
            }
        });

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "mev_sendBundle",
            "params": [params]
        });

        let body_bytes =
            serde_json::to_vec(&payload).map_err(|e| AppError::Initialization(e.to_string()))?;
        let sig_header = self.sign_request(&body_bytes)?;

        let client = reqwest::Client::new();
        let mut attempts = 0u64;
        let mut saw_timeout = false;
        loop {
            attempts += 1;
            let resp = client
                .post(&self.mev_share_relay_url)
                .header("Content-Type", "application/json")
                .header(
                    "X-Flashbots-Signature",
                    HeaderValue::from_str(&sig_header).map_err(|e| {
                        AppError::Connection(format!("Signature header invalid: {}", e))
                    })?,
                )
                .body(body_bytes.clone())
                .timeout(Duration::from_millis(RELAY_TIMEOUT_MS))
                .send()
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    saw_timeout |= e.is_timeout();
                    if attempts < RELAY_MAX_ATTEMPTS {
                        tracing::warn!(
                            target: "executor",
                            relay=%self.mev_share_relay_url,
                            error=%e,
                            attempt=attempts,
                            "Relay POST failed for mev_sendBundle, retrying"
                        );
                        continue;
                    }
                    self.stats.record_relay_attempt(
                        "mev_share",
                        false,
                        saw_timeout,
                        attempts.saturating_sub(1),
                    );
                    return Err(AppError::Connection(format!("Relay POST failed: {}", e)));
                }
            };

            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                tracing::info!(target: "executor", relay=%self.mev_share_relay_url, block=block_number + 1, legs=body.len(), body=%body_text, "MEV-Share bundle submitted");
                self.stats.record_relay_attempt(
                    "mev_share",
                    true,
                    false,
                    attempts.saturating_sub(1),
                );
                break;
            } else if attempts < RELAY_MAX_ATTEMPTS {
                tracing::warn!(target: "executor", status=%status, body=%body_text, attempt=attempts, "Relay rejected mev_sendBundle, retrying");
                continue;
            } else {
                self.stats.record_relay_attempt(
                    "mev_share",
                    false,
                    false,
                    attempts.saturating_sub(1),
                );
                return Err(AppError::Connection(format!(
                    "Relay rejected mev_sendBundle: {} body={}",
                    status, body_text
                )));
            }
        }

        Ok(())
    }

    /// Broadcast a list of raw transaction payloads (RLP encoded).
    /// In dry-run mode this only logs.
    pub async fn send_bundle(&self, raw_txs: &[Vec<u8>], chain_id: u64) -> Result<(), AppError> {
        let bundle_bytes: usize = raw_txs.iter().map(|r| r.len()).sum();
        if raw_txs.len() > FLASHBOTS_MAX_TXS || bundle_bytes > FLASHBOTS_MAX_BYTES {
            return Err(AppError::Strategy(format!(
                "Bundle exceeds Flashbots limits: {} txs, {} bytes (max {} tx / {} bytes)",
                raw_txs.len(),
                bundle_bytes,
                FLASHBOTS_MAX_TXS,
                FLASHBOTS_MAX_BYTES
            )));
        }

        if self.dry_run {
            tracing::info!("Dry-run: would send bundle with {} txs", raw_txs.len());
            return Ok(());
        }

        if chain_id == 1 {
            self.send_mainnet_builders(raw_txs).await
        } else {
            self.send_direct(raw_txs).await
        }
    }

    /// Broadcast a raw transaction directly to the public mempool.
    pub async fn send_public_tx(&self, raw_tx: &[u8]) -> Result<(), AppError> {
        if self.dry_run {
            tracing::info!(target: "executor", "Dry-run: would send public tx");
            return Ok(());
        }
        let res = self.provider.send_raw_transaction(raw_tx).await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(AppError::Connection(format!(
                "Public tx send failed: {}",
                e
            ))),
        }
    }

    async fn send_direct(&self, raw_txs: &[Vec<u8>]) -> Result<(), AppError> {
        for raw in raw_txs {
            let mut attempts = 0;
            loop {
                attempts += 1;
                let res = self.provider.send_raw_transaction(raw.as_slice()).await;
                match res {
                    Ok(_) => break,
                    Err(e) if attempts < 2 => {
                        tracing::warn!(target: "executor", error=%e, attempt=attempts, "Retrying raw tx send");
                        continue;
                    }
                    Err(e) => {
                        return Err(AppError::Connection(format!("Bundle send failed: {}", e)));
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_mainnet_builders(&self, raw_txs: &[Vec<u8>]) -> Result<(), AppError> {
        let block_number =
            self.provider.get_block_number().await.map_err(|e| {
                AppError::Connection(format!("Failed to fetch block number: {}", e))
            })?;
        let target_block = block_number + 1;
        let params = json!({
            "txs": raw_txs.iter().map(|r| format!("0x{}", hex::encode(r))).collect::<Vec<_>>(),
            "blockNumber": format!("0x{:x}", target_block),
            "minTimestamp": current_unix(),
        });

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendBundle",
            "params": [params]
        });

        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| AppError::Initialization(e.to_string()))?;

        let relays = [
            (self.relay_url.as_str(), true, "flashbots"),
            ("https://rpc.beaverbuild.org", false, "beaver"),
            ("https://rpc.titanbuilder.xyz", true, "titan"),
            ("https://rpc.ultrasound.money", true, "ultrasound"),
            ("https://builder0x69.io", true, "agnostic"),
            ("https://rpc.blxrbdn.com", true, "bloxroute"),
        ];
        let mut accepted = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for (url, with_sig, name) in relays {
            let result = self
                .post_bundle_optional(url, &body_bytes, with_sig, name, target_block, raw_txs.len())
                .await;
            match result {
                Ok(()) => {
                    accepted = accepted.saturating_add(1);
                }
                Err(e) => {
                    failures.push(format!("{name}@{url}: {e}"));
                }
            }
        }

        if accepted == 0 {
            return Err(AppError::Connection(format!(
                "All relays rejected bundle: {}",
                failures.join(" | ")
            )));
        }
        if !failures.is_empty() {
            tracing::warn!(
                target: "executor",
                accepted,
                failures = %failures.join(" | "),
                "Bundle accepted by subset of relays"
            );
        }
        Ok(())
    }

    async fn post_bundle_with_sig(
        &self,
        url: &str,
        body_bytes: &[u8],
        name: &str,
        target_block: u64,
        txs: usize,
    ) -> Result<(), AppError> {
        let sig_header = self.sign_request(body_bytes)?;
        let client = reqwest::Client::new();
        let mut attempts = 0u64;
        let mut saw_timeout = false;
        loop {
            attempts += 1;
            let resp = client
                .post(url)
                .header("Content-Type", "application/json")
                .header(
                    "X-Flashbots-Signature",
                    HeaderValue::from_str(&sig_header).map_err(|e| {
                        AppError::Connection(format!("Signature header invalid: {}", e))
                    })?,
                )
                .body(body_bytes.to_vec())
                .timeout(Duration::from_millis(RELAY_TIMEOUT_MS))
                .send()
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    saw_timeout |= e.is_timeout();
                    if attempts < RELAY_MAX_ATTEMPTS {
                        tracing::warn!(
                            target: "executor",
                            relay=%url,
                            name=%name,
                            error=%e,
                            attempt=attempts,
                            "Relay POST failed, retrying"
                        );
                        continue;
                    }
                    self.stats.record_relay_attempt(
                        name,
                        false,
                        saw_timeout,
                        attempts.saturating_sub(1),
                    );
                    return Err(AppError::Connection(format!("Relay POST failed: {}", e)));
                }
            };

            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                tracing::info!(target: "executor", relay=%url, name=%name, block=target_block, txs=txs, body=%body_text, "Bundle submitted");
                self.stats.record_relay_attempt(
                    name,
                    true,
                    false,
                    attempts.saturating_sub(1),
                );
                return Ok(());
            } else if attempts < RELAY_MAX_ATTEMPTS {
                tracing::warn!(target: "executor", relay=%url, status=%status, body=%body_text, attempt=attempts, "Relay rejected bundle, retrying");
                continue;
            } else {
                self.stats.record_relay_attempt(
                    name,
                    false,
                    false,
                    attempts.saturating_sub(1),
                );
                return Err(AppError::Connection(format!(
                    "Relay {} rejected bundle: {} body={}",
                    name, status, body_text
                )));
            }
        }
    }

    async fn post_bundle_optional(
        &self,
        url: &str,
        body_bytes: &[u8],
        with_sig: bool,
        name: &str,
        target_block: u64,
        txs: usize,
    ) -> Result<(), AppError> {
        if with_sig {
            return self
                .post_bundle_with_sig(url, body_bytes, name, target_block, txs)
                .await;
        }

        let client = reqwest::Client::new();
        let mut attempts = 0u64;
        let mut saw_timeout = false;
        loop {
            attempts += 1;
            let resp = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(body_bytes.to_vec())
                .timeout(Duration::from_millis(RELAY_TIMEOUT_MS))
                .send()
                .await;
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    saw_timeout |= e.is_timeout();
                    if attempts < RELAY_MAX_ATTEMPTS {
                        tracing::warn!(
                            target: "executor",
                            relay=%url,
                            name=%name,
                            error=%e,
                            attempt=attempts,
                            "Best-effort relay POST failed, retrying"
                        );
                        continue;
                    }
                    self.stats.record_relay_attempt(
                        name,
                        false,
                        saw_timeout,
                        attempts.saturating_sub(1),
                    );
                    return Err(AppError::Connection(format!("Relay POST failed: {}", e)));
                }
            };

            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                tracing::info!(target: "executor", relay=%url, name=%name, block=target_block, txs=txs, body=%body_text, "Bundle submitted (best-effort)");
                self.stats.record_relay_attempt(
                    name,
                    true,
                    false,
                    attempts.saturating_sub(1),
                );
                return Ok(());
            }
            if attempts < RELAY_MAX_ATTEMPTS {
                tracing::warn!(
                    target: "executor",
                    relay=%url,
                    name=%name,
                    status=%status,
                    body=%body_text,
                    attempt=attempts,
                    "Best-effort relay rejected bundle, retrying"
                );
                continue;
            }
            self.stats.record_relay_attempt(
                name,
                false,
                false,
                attempts.saturating_sub(1),
            );
            return Err(AppError::Connection(format!(
                "Relay {} rejected bundle: {} body={}",
                name, status, body_text
            )));
        }
    }

    pub async fn canonicalize_mevshare_builders(builders: Vec<String>) -> Vec<String> {
        let mut requested: Vec<String> = builders
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if requested.is_empty() {
            requested = DEFAULT_MEVSHARE_BUILDERS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(3_000))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "executor", error = %e, "Failed to construct HTTP client for builder validation");
                return requested;
            }
        };

        let resp = client
            .get("https://raw.githubusercontent.com/flashbots/dowg/main/builder-registrations.json")
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target: "executor", error = %e, "Builder registration fetch failed; skipping canonical validation");
                return requested;
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(
                target: "executor",
                status = %resp.status(),
                "Builder registration fetch non-success; skipping canonical validation"
            );
            return requested;
        }

        #[derive(Debug, Deserialize)]
        struct BuilderRegistration {
            name: String,
        }
        let parsed: Vec<BuilderRegistration> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "executor", error = %e, "Builder registration parse failed; skipping canonical validation");
                return requested;
            }
        };
        let mut canonical_by_lower: HashMap<String, String> = HashMap::new();
        for entry in parsed {
            canonical_by_lower.insert(entry.name.to_lowercase(), entry.name);
        }
        Self::normalize_mevshare_builders_with_registry(requested, &canonical_by_lower)
    }

    fn normalize_mevshare_builders_with_registry(
        requested: Vec<String>,
        canonical_by_lower: &HashMap<String, String>,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for requested_name in requested {
            let lower = requested_name.to_lowercase();
            let canonical = canonical_by_lower
                .get(&lower)
                .cloned()
                .unwrap_or_else(|| requested_name.clone());
            if !canonical_by_lower.contains_key(&lower) {
                tracing::warn!(
                    target: "executor",
                    builder = %requested_name,
                    "MEV-Share builder not found in canonical registrations"
                );
            } else if canonical != requested_name {
                tracing::info!(
                    target: "executor",
                    from = %requested_name,
                    to = %canonical,
                    "Normalized MEV-Share builder to canonical registration name"
                );
            }
            let dedupe_key = canonical.to_lowercase();
            if seen.insert(dedupe_key) {
                out.push(canonical);
            }
        }
        out
    }

    fn sign_request(&self, body_bytes: &[u8]) -> Result<String, AppError> {
        let hash = keccak256(body_bytes);
        let sig = self
            .signer
            .sign_hash_sync(&hash)
            .map_err(|e| AppError::Connection(format!("Bundle signing failed: {}", e)))?;
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        Ok(format!("{:#x}:{}", self.signer.address(), sig_hex))
    }
}

pub type SharedBundleSender = Arc<BundleSender>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::provider::HttpProvider;
    use url::Url;

    fn dry_run_sender() -> BundleSender {
        let provider =
            HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").expect("valid url"));
        let signer = PrivateKeySigner::random();
        let stats = Arc::new(StrategyStats::default());
        BundleSender::new(
            provider,
            true,
            "https://relay.flashbots.net".to_string(),
            "https://mev-share.flashbots.net".to_string(),
            vec![
                "flashbots".to_string(),
                "beaverbuild.org".to_string(),
                "rsync".to_string(),
                "Titan".to_string(),
            ],
            signer,
            stats,
        )
    }

    #[tokio::test]
    async fn mev_share_bundle_rejects_non_compliant_body_shape() {
        let sender = dry_run_sender();
        let invalid = vec![
            BundleItem::Tx {
                tx: "0x02".into(),
                can_revert: false,
            },
            BundleItem::Tx {
                tx: "0x03".into(),
                can_revert: false,
            },
        ];
        let err = sender
            .send_mev_share_bundle(&invalid)
            .await
            .expect_err("should reject invalid mev-share body");
        assert!(
            matches!(err, AppError::Strategy(msg) if msg.contains("exactly one victim hash and one backrun tx"))
        );
    }

    #[tokio::test]
    async fn mev_share_bundle_accepts_single_hash_and_backrun_tx() {
        let sender = dry_run_sender();
        let body = vec![
            BundleItem::Hash {
                hash: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            },
            BundleItem::Tx {
                tx: "0x02".into(),
                can_revert: false,
            },
        ];
        sender
            .send_mev_share_bundle(&body)
            .await
            .expect("valid mev-share body should be accepted in dry-run");
    }

    #[tokio::test]
    async fn send_bundle_rejects_payload_above_flashbots_limit() {
        let sender = dry_run_sender();
        let oversized = vec![vec![0u8; FLASHBOTS_MAX_BYTES + 1]];
        let err = sender
            .send_bundle(&oversized, 1)
            .await
            .expect_err("bundle should exceed max bytes");
        assert!(
            matches!(err, AppError::Strategy(msg) if msg.contains("Bundle exceeds Flashbots limits"))
        );
    }

    #[tokio::test]
    async fn send_bundle_accepts_payload_at_flashbots_limit() {
        let sender = dry_run_sender();
        let boundary = vec![vec![0u8; FLASHBOTS_MAX_BYTES]];
        sender
            .send_bundle(&boundary, 1)
            .await
            .expect("bundle at byte limit should be accepted");
    }

    #[test]
    fn normalize_builders_uses_registry_names_and_dedupes() {
        let requested = vec![
            "FlashBots".to_string(),
            "titan".to_string(),
            "custom".to_string(),
            "CUSTOM".to_string(),
        ];
        let mut registry = HashMap::new();
        registry.insert("flashbots".to_string(), "flashbots".to_string());
        registry.insert("titan".to_string(), "Titan".to_string());

        let out = BundleSender::normalize_mevshare_builders_with_registry(requested, &registry);
        assert_eq!(
            out,
            vec![
                "flashbots".to_string(),
                "Titan".to_string(),
                "custom".to_string()
            ]
        );
    }
}
