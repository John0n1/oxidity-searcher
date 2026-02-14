// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use std::str::FromStr;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn setup_logging(log_level: &str, json_format: bool) {
    // If user passes a bare level (e.g. "debug"), apply sane noisy-module defaults.
    // Custom directive strings (with ',' or '=') are respected as-is.
    let normalized = log_level.trim();
    let filter_spec = if normalized.contains(',') || normalized.contains('=') {
        normalized.to_string()
    } else {
        format!(
            "{},h2=info,hyper=info,hyper_util=info,reqwest=info,tokio_tungstenite=info,alloy_transport_http=info",
            normalized
        )
    };
    let filter = EnvFilter::from_str(&filter_spec).unwrap_or_else(|_| EnvFilter::new("info"));
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

    let directives: Vec<&str> = filter_spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let base = directives.first().copied().unwrap_or("info");
    let overrides = directives
        .iter()
        .skip(1)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");

    if overrides.is_empty() {
        tracing::info!(
            "Logging initialized\n  base: {base}\n  format: {}",
            if json_format { "json" } else { "compact" }
        );
    } else {
        tracing::info!(
            "Logging initialized\n  base: {base}\n  overrides: {overrides}\n  format: {}",
            if json_format { "json" } else { "compact" }
        );
    }
}
