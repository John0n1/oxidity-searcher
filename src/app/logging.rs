// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use std::str::FromStr;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const ANSI_TITLE_BLUEISH: &str = "\x1b[38;5;75m";
const ANSI_RESET: &str = "\x1b[0m";

fn ansi_enabled() -> bool {
    use std::io::IsTerminal;

    std::env::var("NO_COLOR").is_err()
        && std::env::var("TERM")
            .map(|v| !v.eq_ignore_ascii_case("dumb"))
            .unwrap_or(true)
        && std::io::stderr().is_terminal()
}

fn visible_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut len = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() && bytes[i] != b'm' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            continue;
        }
        len += 1;
        i += 1;
    }
    len
}

fn wrap_line(line: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || line.chars().count() <= max_width {
        return vec![line.to_string()];
    }

    let mut out = Vec::new();
    let mut remaining = line.trim();

    while remaining.chars().count() > max_width {
        let mut cut_byte = 0usize;
        let mut last_break = None::<usize>;
        let mut chars_seen = 0usize;

        for (idx, ch) in remaining.char_indices() {
            if chars_seen >= max_width {
                break;
            }
            chars_seen += 1;
            cut_byte = idx + ch.len_utf8();
            if ch == ',' || ch == ' ' || ch == ';' || ch == '|' {
                last_break = Some(idx + ch.len_utf8());
            }
        }

        let min_acceptable = max_width / 2;
        let break_at = match last_break {
            Some(pos) if remaining[..pos].chars().count() >= min_acceptable => pos,
            _ => cut_byte.max(1),
        };

        let chunk = remaining[..break_at].trim();
        if !chunk.is_empty() {
            out.push(chunk.to_string());
        }
        remaining = remaining[break_at..].trim_start();
    }

    if !remaining.is_empty() {
        out.push(remaining.to_string());
    }

    if out.is_empty() {
        out.push(String::new());
    }
    out
}

pub fn format_framed_table<I, S>(lines: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let max_content_width = std::env::var("LOG_TABLE_MAX_WIDTH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(110)
        .clamp(60, 180);

    let lines = collect_wrapped_lines(lines, max_content_width);
    if lines.is_empty() {
        return String::new();
    }
    let width = lines
        .iter()
        .map(|line| visible_len(line))
        .max()
        .unwrap_or(0);
    let border = format!("+{}+", "-".repeat(width + 2));
    let mut framed = String::new();
    framed.push_str(&border);
    for line in lines {
        let line_len = visible_len(&line);
        let pad = width.saturating_sub(line_len);
        framed.push('\n');
        framed.push_str(&format!("| {}{} |", line, " ".repeat(pad)));
    }
    framed.push('\n');
    framed.push_str(&border);
    framed
}

fn collect_wrapped_lines<I, S>(lines: I, max_content_width: usize) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let raw_lines = lines
        .into_iter()
        .map(|line| line.as_ref().to_string())
        .collect::<Vec<_>>();
    if raw_lines.is_empty() {
        return Vec::new();
    }

    let mut wrapped_lines = Vec::new();
    for line in raw_lines {
        wrapped_lines.extend(wrap_line(&line, max_content_width));
    }
    wrapped_lines
}

pub fn format_framed_table_with_blue_title<I, S>(lines: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let max_content_width = std::env::var("LOG_TABLE_MAX_WIDTH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(110)
        .clamp(60, 180);

    let mut wrapped_lines = collect_wrapped_lines(lines, max_content_width);
    if wrapped_lines.is_empty() {
        return String::new();
    }
    if let Some(first_line) = wrapped_lines.first_mut() {
        *first_line = format!("{ANSI_TITLE_BLUEISH}{first_line}{ANSI_RESET}");
    }

    let width = wrapped_lines
        .iter()
        .map(|line| visible_len(line))
        .max()
        .unwrap_or(0);
    let border = format!("+{}+", "-".repeat(width + 2));
    let mut framed = String::new();
    framed.push_str(&border);
    for line in wrapped_lines {
        let line_len = visible_len(&line);
        let pad = width.saturating_sub(line_len);
        framed.push('\n');
        framed.push_str(&format!("| {}{} |", line, " ".repeat(pad)));
    }
    framed.push('\n');
    framed.push_str(&border);
    framed
}

pub fn ansi_tables_enabled() -> bool {
    ansi_enabled()
}

pub fn setup_logging(log_level: &str, json_format: bool) {
    // If user passes a bare level (e.g. "debug"), apply sane noisy-module defaults.
    // Custom directive strings (with ',' or '=') are respected as-is.
    let normalized = log_level.trim();
    let filter_spec = if normalized.contains(',') || normalized.contains('=') {
        normalized.to_string()
    } else {
        format!(
            "{},h2=info,hyper=info,hyper_util=info,reqwest=info,tokio_tungstenite=info,alloy_transport_http=info,alloy_pubsub=info,alloy_transport_ipc=info,alloy_rpc_client=info,request=info,sqlx=info",
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

    let mut panel_lines = vec!["Logging initialized".to_string(), format!("base: {base}")];
    if !overrides.is_empty() {
        panel_lines.push(format!("overrides: {overrides}"));
    }
    panel_lines.push(format!(
        "format: {}",
        if json_format { "json" } else { "compact" }
    ));
    if ansi_tables_enabled() {
        let framed = format_framed_table_with_blue_title(panel_lines.iter().map(String::as_str));
        eprintln!("{framed}");
    } else {
        let framed = format_framed_table(panel_lines.iter().map(String::as_str));
        tracing::info!(target: "oxidity_searcher::app::logging", "\n{framed}");
    }
}
