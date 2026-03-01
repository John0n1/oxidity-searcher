// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>
#![allow(clippy::too_many_arguments)]

pub mod app;
pub mod common;
pub mod domain;
pub mod infrastructure;
pub mod services;

// Stable module aliases used across internal modules and integration tests.
pub use infrastructure::data;
pub use infrastructure::network;
pub use services::strategy as core;
