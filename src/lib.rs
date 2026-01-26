// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

pub mod app;
pub mod common;
pub mod domain;
pub mod infrastructure;
pub mod services;

// Backward-compat re-exports
pub use infrastructure::data;
pub use infrastructure::network;
pub use services::strategy as core;
