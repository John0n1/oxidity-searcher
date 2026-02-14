// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

pub mod execution;
pub use execution::{engine, executor, strategy};

pub mod ingest;
pub use ingest::{decode, handlers};

pub mod planning;
pub use planning::{bundles, swaps};

pub mod risk;
pub use risk::{guards, safety, time_utils};

pub mod state;
pub use state::{inventory, portfolio};

pub mod router_discovery;
pub mod routers;
pub mod simulation;
