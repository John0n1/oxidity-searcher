// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use std::str::FromStr;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn setup_logging(log_level: &str, json_format: bool) {
    let filter = EnvFilter::from_str(log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry().with(filter);

    if json_format {
        let json_layer = fmt::layer()
            .json()
            .with_target(false)
            .with_current_span(false);
        subscriber.with(json_layer).init();
    } else {
        let fmt_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .compact();
        subscriber.with(fmt_layer).init();
    }

    tracing::info!("Logging initialized. Level: {}", log_level);
}
