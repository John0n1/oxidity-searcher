// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

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
        ipc_provider: Option<&str>,
        websocket_provider: Option<&str>,
        http_provider: &str,
    ) -> Result<(WsProvider, HttpProvider), AppError> {
        if let Some(ipc_provider) = ipc_provider {
            match Self::ipc(ipc_provider).await {
                Ok(ipc_provider) => {
                    tracing::info!(target: "rpc", "Using IPC provider (preferred)");
                    return Ok((ipc_provider.clone(), ipc_provider));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "rpc",
                        %ipc_provider,
                        error = %e,
                        "IPC connection failed; trying WS next"
                    );
                }
            }
        } else {
            tracing::debug!(target: "rpc", "No IPC URL configured; trying WS");
        }

        if let Some(websocket_provider) = websocket_provider {
            match Self::ws(websocket_provider).await {
                Ok(websocket_provider) => {
                    tracing::info!(target: "rpc", "Using WS provider (fallback)");
                    return Ok((websocket_provider.clone(), websocket_provider));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "rpc",
                        %websocket_provider,
                        error = %e,
                        "WS connection failed; falling back to HTTP"
                    );
                }
            }
        } else {
            tracing::debug!(target: "rpc", "No WS URL configured; falling back to HTTP");
        }

        let http_provider = Self::http(http_provider)?;
        tracing::warn!(
            target: "rpc",
            "Using HTTP provider only; streaming features may be limited"
        );
        Ok((http_provider.clone(), http_provider))
    }

    pub fn http(http_provider: &str) -> Result<HttpProvider, AppError> {
        let url = Url::parse(http_provider)
            .map_err(|e| AppError::Config(format!("Invalid RPC URL: {}", e)))?;

        let provider = RootProvider::new_http(url);
        Ok(provider)
    }

    pub async fn ws(websocket_provider: &str) -> Result<WsProvider, AppError> {
        let provider = RootProvider::connect(websocket_provider)
            .await
            .map_err(|e| AppError::Connection(format!("WS Connection failed: {}", e)))?;

        Ok(provider)
    }

    pub async fn ipc(ipc_provider: &str) -> Result<IpcProvider, AppError> {
        let path = PathBuf::from(ipc_provider);
        let conn = BuiltInConnectionString::Ipc(path);
        let provider: IpcProvider = RootProvider::connect_with(conn)
            .await
            .map_err(|e| AppError::Connection(format!("IPC Connection failed: {}", e)))?;

        Ok(provider)
    }
}
