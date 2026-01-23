// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use chrono::Utc;
use serde::Serialize;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter, Registry};

#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

const LOG_BUFFER_MAX: usize = 500;

static LOG_BUFFER: OnceLock<Arc<Mutex<Vec<LogRecord>>>> = OnceLock::new();
static LOG_RELOAD: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

struct LogCaptureLayer {
    buffer: Arc<Mutex<Vec<LogRecord>>>,
}

impl<S> tracing_subscriber::Layer<S> for LogCaptureLayer
where
    S: tracing::Subscriber,
    for<'span> S: tracing_subscriber::registry::LookupSpan<'span>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let record = LogRecord {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: visitor.message.unwrap_or_default(),
        };

        let mut buf = self.buffer.lock().unwrap();
        buf.push(record);
        if buf.len() > LOG_BUFFER_MAX {
            let drop = buf.len() - LOG_BUFFER_MAX;
            buf.drain(0..drop);
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

pub fn setup_logging(log_level: &str, json_format: bool) {
    let filter = EnvFilter::from_str(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let (filter_layer, handle) = reload::Layer::new(filter);
    let _ = LOG_RELOAD.set(handle);

    let buffer = LOG_BUFFER
        .get_or_init(|| Arc::new(Mutex::new(Vec::with_capacity(LOG_BUFFER_MAX))));

    let capture_layer = LogCaptureLayer {
        buffer: buffer.clone(),
    };

    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(capture_layer);

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

pub fn set_log_level(level: &str) -> Result<(), String> {
    let handle = LOG_RELOAD
        .get()
        .ok_or_else(|| "Log level handle not initialized".to_string())?;
    let filter = EnvFilter::from_str(level).map_err(|e| e.to_string())?;
    handle.reload(filter).map_err(|e| e.to_string())
}

pub fn recent_logs(limit: usize) -> Vec<LogRecord> {
    let buf = LOG_BUFFER
        .get()
        .map(|b| b.lock().unwrap().clone())
        .unwrap_or_default();
    let len = buf.len();
    let take = limit.min(len);
    buf.into_iter().skip(len.saturating_sub(take)).collect()
}
