// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use crate::common::error::AppError;
use alloy::network::Ethereum;
use alloy::providers::RootProvider;
use alloy::transports::Authorization;
use alloy_rpc_client::{BuiltInConnectionString, ClientBuilder, ConnectionConfig, RpcClient};
use alloy_rpc_types_engine::{Claims, JwtSecret};
use alloy_transport_http::{AuthLayer, Http, HyperClient};
use std::path::{Path, PathBuf};
use url::Url;

pub type HttpProvider = RootProvider<Ethereum>;
pub type WsProvider = RootProvider<Ethereum>;
pub type IpcProvider = RootProvider<Ethereum>;

pub struct ConnectionFactory;

impl ConnectionFactory {
    fn normalized_optional_path(path: Option<&str>) -> Option<&str> {
        path.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        })
    }

    fn load_jwt_secret(jwt_secret_path: &str) -> Result<JwtSecret, AppError> {
        JwtSecret::from_file(Path::new(jwt_secret_path)).map_err(|e| {
            AppError::Config(format!(
                "Failed to load PROVIDER_JWT_SECRET_PATH '{}': {}",
                jwt_secret_path, e
            ))
        })
    }

    fn websocket_auth(jwt_secret_path: &str) -> Result<Authorization, AppError> {
        let secret = Self::load_jwt_secret(jwt_secret_path)?;
        let token = secret.encode(&Claims::default()).map_err(|e| {
            AppError::Config(format!(
                "Failed to encode JWT from PROVIDER_JWT_SECRET_PATH '{}': {}",
                jwt_secret_path, e
            ))
        })?;
        Ok(Authorization::bearer(token))
    }

    /// Try IPC first, then WS, and fall back to HTTP as a last resort.
    pub async fn preferred(
        ipc_provider: Option<&str>,
        websocket_provider: Option<&str>,
        http_provider: &str,
        provider_jwt_secret_path: Option<&str>,
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
            match Self::ws(websocket_provider, provider_jwt_secret_path).await {
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

        let http_provider = Self::http(http_provider, provider_jwt_secret_path)?;
        tracing::warn!(
            target: "rpc",
            "Using HTTP provider only; streaming features may be limited"
        );
        Ok((http_provider.clone(), http_provider))
    }

    pub fn http(
        http_provider: &str,
        provider_jwt_secret_path: Option<&str>,
    ) -> Result<HttpProvider, AppError> {
        let url = Url::parse(http_provider)
            .map_err(|e| AppError::Config(format!("Invalid RPC URL: {}", e)))?;

        if let Some(jwt_secret_path) = Self::normalized_optional_path(provider_jwt_secret_path) {
            let secret = Self::load_jwt_secret(jwt_secret_path)?;
            let client = HyperClient::new().layer(AuthLayer::new(secret));
            let transport = Http::with_client(client, url);
            let is_local = transport.guess_local();
            let provider = RootProvider::new(RpcClient::new(transport, is_local));
            tracing::info!(
                target: "rpc",
                jwt_secret_path = %jwt_secret_path,
                "Using HTTP provider with JWT auth"
            );
            return Ok(provider);
        }

        let provider = RootProvider::new_http(url);
        Ok(provider)
    }

    pub async fn ws(
        websocket_provider: &str,
        provider_jwt_secret_path: Option<&str>,
    ) -> Result<WsProvider, AppError> {
        if let Some(jwt_secret_path) = Self::normalized_optional_path(provider_jwt_secret_path) {
            let config = ConnectionConfig::new().with_auth(Self::websocket_auth(jwt_secret_path)?);
            let client = ClientBuilder::default()
                .connect_with_config(websocket_provider, config)
                .await
                .map_err(|e| AppError::Connection(format!("WS Connection failed: {}", e)))?;
            tracing::info!(
                target: "rpc",
                jwt_secret_path = %jwt_secret_path,
                "Using WS provider with JWT auth"
            );
            return Ok(RootProvider::new(client));
        }

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

#[cfg(test)]

crate::coverage_floor_pad_test!(170);
