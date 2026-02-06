// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::network::provider::HttpProvider;
use crate::services::strategy::time_utils::current_unix;
use alloy::primitives::keccak256;
use alloy::providers::Provider;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use reqwest::header::HeaderValue;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

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
    signer: PrivateKeySigner,
}

const FLASHBOTS_MAX_TXS: usize = 100;
const FLASHBOTS_MAX_BYTES: usize = 300_000;

impl BundleSender {
    pub fn new(
        provider: HttpProvider,
        dry_run: bool,
        relay_url: String,
        mev_share_relay_url: String,
        signer: PrivateKeySigner,
    ) -> Self {
        Self {
            provider,
            dry_run,
            relay_url,
            mev_share_relay_url,
            signer,
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
                .post(&self.mev_share_relay_url)
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
                tracing::info!(target: "executor", relay=%self.mev_share_relay_url, block=block_number + 1, legs=body.len(), body=%body_text, "MEV-Share bundle submitted");
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

        // Primary: Flashbots relay (signed header)
        self.post_bundle_with_sig(
            &self.relay_url,
            &body_bytes,
            "flashbots",
            target_block,
            raw_txs.len(),
        )
        .await?;

        // Secondary: broader builder set, signed where supported
        let secondary = [
            ("https://rpc.beaverbuild.org", false, "beaver"),
            ("https://rpc.titanbuilder.xyz", true, "titan"),
            ("https://rpc.ultrasound.money", true, "ultrasound"),
            ("https://builder0x69.io", true, "agnostic"),
            ("https://rpc.blxrbdn.com", true, "bloxroute"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::provider::HttpProvider;
    use url::Url;

    fn dry_run_sender() -> BundleSender {
        let provider =
            HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").expect("valid url"));
        let signer = PrivateKeySigner::random();
        BundleSender::new(
            provider,
            true,
            "https://relay.flashbots.net".to_string(),
            "https://mev-share.flashbots.net".to_string(),
            signer,
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
}
