// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use alloy::primitives::keccak256;
use alloy::providers::Provider;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use reqwest::header::HeaderValue;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    signer: PrivateKeySigner,
}

impl BundleSender {
    pub fn new(
        provider: HttpProvider,
        dry_run: bool,
        relay_url: String,
        signer: PrivateKeySigner,
    ) -> Self {
        Self {
            provider,
            dry_run,
            relay_url,
            signer,
        }
    }

    /// Send a MEV-Share bundle that references tx hashes (instead of raw bytes).
    pub async fn send_mev_share_bundle(&self, body: &[BundleItem]) -> Result<(), AppError> {
        if self.dry_run {
            tracing::info!(target: "executor", "Dry-run: would send mev_sendBundle with {} legs", body.len());
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
                "builders": ["flashbots", "beaverbuild.org", "rsync", "titan"]
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
        let mut attempts = 0;
        loop {
            attempts += 1;
            let resp = client
                .post(&self.relay_url)
                .header("Content-Type", "application/json")
                .header(
                    "X-Flashbots-Signature",
                    HeaderValue::from_str(&sig_header).map_err(|e| {
                        AppError::Connection(format!("Signature header invalid: {}", e))
                    })?,
                )
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| AppError::Connection(format!("Relay POST failed: {}", e)))?;

            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                tracing::info!(target: "executor", relay=%self.relay_url, block=block_number + 1, legs=body.len(), body=%body_text, "MEV-Share bundle submitted");
                break;
            } else if attempts < 2 {
                tracing::warn!(target: "executor", status=%status, body=%body_text, attempt=attempts, "Relay rejected mev_sendBundle, retrying");
                continue;
            } else {
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

        // Primary: Flashbots relay (signed header)
        self.post_bundle_with_sig(
            &self.relay_url,
            &body_bytes,
            "flashbots",
            target_block,
            raw_txs.len(),
        )
        .await?;

        // Secondary: beaver (no auth) and titan (signed best-effort)
        let secondary = [
            ("https://rpc.beaverbuild.org", false, "beaver"),
            ("https://rpc.titanbuilder.xyz", true, "titan"),
        ];
        for (url, with_sig, name) in secondary {
            if let Err(e) = self
                .post_bundle_optional(
                    url,
                    &body_bytes,
                    with_sig,
                    name,
                    target_block,
                    raw_txs.len(),
                )
                .await
            {
                tracing::warn!(target: "executor", relay=%url, error=%e, "Secondary builder submit failed");
            }
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
        let mut attempts = 0;
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
                .send()
                .await
                .map_err(|e| AppError::Connection(format!("Relay POST failed: {}", e)))?;

            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                tracing::info!(target: "executor", relay=%url, name=%name, block=target_block, txs=txs, body=%body_text, "Bundle submitted");
                return Ok(());
            } else if attempts < 2 {
                tracing::warn!(target: "executor", relay=%url, status=%status, body=%body_text, attempt=attempts, "Relay rejected bundle, retrying");
                continue;
            } else {
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
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body_bytes.to_vec())
            .send()
            .await
            .map_err(|e| AppError::Connection(format!("Relay POST failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            tracing::info!(target: "executor", relay=%url, name=%name, block=target_block, txs=txs, body=%body_text, "Bundle submitted (best-effort)");
            Ok(())
        } else {
            Err(AppError::Connection(format!(
                "Relay {} rejected bundle: {} body={}",
                name, status, body_text
            )))
        }
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

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
