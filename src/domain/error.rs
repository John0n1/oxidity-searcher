// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Initialization failed: {0}")]
    Initialization(String),

    #[error("Connection failed to endpoint: {0}")]
    Connection(String),

    #[error("Transaction failed: {hash:?}, reason: {reason}")]
    Transaction { hash: String, reason: String },

    #[error("Strategy execution error: {0}")]
    Strategy(String),

    #[error("Insufficient funds. Required: {required}, Available: {available}")]
    InsufficientFunds { required: String, available: String },

    #[error("External API error: {provider} responded with {status}")]
    ApiCall { provider: String, status: u16 },

    #[error("Validation failed for field {field}: {message}")]
    Validation { field: String, message: String },

    #[error("Address {0} is invalid or not checksummed")]
    InvalidAddress(String),

    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        AppError::Config(err.to_string())
    }
}
