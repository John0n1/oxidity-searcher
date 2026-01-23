// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

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
