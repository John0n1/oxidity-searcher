// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use alloy::network::Ethereum;
use alloy::providers::RootProvider;
use alloy_rpc_client::BuiltInConnectionString;
use std::path::PathBuf;
use url::Url;

pub type HttpProvider = RootProvider<Ethereum>;
pub type WsProvider = RootProvider<Ethereum>;
pub type IpcProvider = RootProvider<Ethereum>;

pub struct ConnectionFactory;

impl ConnectionFactory {
    /// Try IPC first, then WS, and fall back to HTTP as a last resort.
    pub async fn preferred(
        ipc_url: Option<&str>,
        ws_url: Option<&str>,
        rpc_url: &str,
    ) -> Result<(WsProvider, HttpProvider), AppError> {
        if let Some(ipc_url) = ipc_url {
            match Self::ipc(ipc_url).await {
                Ok(ipc_provider) => {
                    tracing::info!(target: "rpc", %ipc_url, "Using IPC provider (preferred)");
                    return Ok((ipc_provider.clone(), ipc_provider));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "rpc",
                        %ipc_url,
                        error = %e,
                        "IPC connection failed; trying WS next"
                    );
                }
            }
        } else {
            tracing::debug!(target: "rpc", "No IPC URL configured; trying WS");
        }

        if let Some(ws_url) = ws_url {
            match Self::ws(ws_url).await {
                Ok(ws_provider) => {
                    tracing::info!(target: "rpc", %ws_url, "Using WS provider (fallback)");
                    return Ok((ws_provider.clone(), ws_provider));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "rpc",
                        %ws_url,
                        error = %e,
                        "WS connection failed; falling back to HTTP"
                    );
                }
            }
        } else {
            tracing::debug!(target: "rpc", "No WS URL configured; falling back to HTTP");
        }

        let http_provider = Self::http(rpc_url)?;
        tracing::warn!(
            target: "rpc",
            rpc_url,
            "Using HTTP provider only; streaming features may be limited"
        );
        Ok((http_provider.clone(), http_provider))
    }

    pub fn http(rpc_url: &str) -> Result<HttpProvider, AppError> {
        let url =
            Url::parse(rpc_url).map_err(|e| AppError::Config(format!("Invalid RPC URL: {}", e)))?;

        let provider = RootProvider::new_http(url);
        Ok(provider)
    }

    pub async fn ws(ws_url: &str) -> Result<WsProvider, AppError> {
        let provider = RootProvider::connect(ws_url)
            .await
            .map_err(|e| AppError::Connection(format!("WS Connection failed: {}", e)))?;

        Ok(provider)
    }

    pub async fn ipc(ipc_url: &str) -> Result<IpcProvider, AppError> {
        let path = PathBuf::from(ipc_url);
        let conn = BuiltInConnectionString::Ipc(path);
        let provider: IpcProvider = RootProvider::connect_with(conn)
            .await
            .map_err(|e| AppError::Connection(format!("IPC Connection failed: {}", e)))?;

        Ok(provider)
    }
}
