// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

use crate::wallet::config::WalletServiceConfig;
use crate::wallet::state::WalletServiceState;
use crate::wallet::types::{WalletPortfolioRequest, WalletQuotePreviewRequest};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(config: WalletServiceConfig) -> std::io::Result<()> {
    let addr = config
        .socket_addr()
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let listener = TcpListener::bind(addr).await?;
    let state = Arc::new(
        WalletServiceState::new(config.clone())
            .await
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?,
    );

    tracing::info!(
        target: "wallet",
        listen = %addr,
        product = %config.product_name,
        "Wallet service online"
    );

    loop {
        let (socket, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            handle_connection(socket, state).await;
        });
    }
}

async fn handle_connection(mut socket: TcpStream, state: Arc<WalletServiceState>) {
    let request = match read_request(&mut socket).await {
        Ok(request) => request,
        Err((status, body)) => {
            let _ = write_json(&mut socket, status, &body).await;
            return;
        }
    };

    let (method, path, headers, body) = request;
    let route = path.split('?').next().unwrap_or(path.as_str());

    if method == "OPTIONS" {
        let _ = write_response(
            &mut socket,
            "204 No Content",
            "text/plain",
            cors_headers(),
            "",
        )
        .await;
        return;
    }

    match (method.as_str(), route) {
        ("GET", "/health") => {
            let body = match serde_json::to_string(&state.health().await) {
                Ok(value) => value,
                Err(_) => json!({"status":"error","error":"serialization_failed"}).to_string(),
            };
            let _ = write_response(
                &mut socket,
                "200 OK",
                "application/json",
                cors_headers(),
                &body,
            )
            .await;
        }
        ("GET", "/bootstrap") => {
            let body = match serde_json::to_string(&state.bootstrap()) {
                Ok(value) => value,
                Err(_) => json!({"status":"error","error":"serialization_failed"}).to_string(),
            };
            let _ = write_response(
                &mut socket,
                "200 OK",
                "application/json",
                cors_headers(),
                &body,
            )
            .await;
        }
        ("POST", "/quote-preview") => {
            if let Err(response) = ensure_json_request(&headers) {
                let _ = write_json(&mut socket, response.0, &response.1).await;
                return;
            }

            let request: WalletQuotePreviewRequest = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => {
                    let _ = write_json(
                        &mut socket,
                        "400 Bad Request",
                        &json!({"status":"error","error":"invalid quote preview payload"}),
                    )
                    .await;
                    return;
                }
            };

            match state.quote_preview(request).await {
                Ok(preview) => {
                    let body = match serde_json::to_string(&preview) {
                        Ok(value) => value,
                        Err(_) => {
                            json!({"status":"error","error":"serialization_failed"}).to_string()
                        }
                    };
                    let _ = write_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        cors_headers(),
                        &body,
                    )
                    .await;
                }
                Err(error) => {
                    let _ = write_json(
                        &mut socket,
                        "400 Bad Request",
                        &json!({"status":"error","error":"invalid_quote","message":error}),
                    )
                    .await;
                }
            }
        }
        ("POST", "/portfolio") => {
            if let Err(response) = ensure_json_request(&headers) {
                let _ = write_json(&mut socket, response.0, &response.1).await;
                return;
            }

            let request: WalletPortfolioRequest = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => {
                    let _ = write_json(
                        &mut socket,
                        "400 Bad Request",
                        &json!({"status":"error","error":"invalid portfolio payload"}),
                    )
                    .await;
                    return;
                }
            };

            match state.portfolio(request).await {
                Ok(portfolio) => {
                    let body = match serde_json::to_string(&portfolio) {
                        Ok(value) => value,
                        Err(_) => {
                            json!({"status":"error","error":"serialization_failed"}).to_string()
                        }
                    };
                    let _ = write_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        cors_headers(),
                        &body,
                    )
                    .await;
                }
                Err(error) => {
                    let _ = write_json(
                        &mut socket,
                        "400 Bad Request",
                        &json!({"status":"error","error":"invalid_portfolio","message":error}),
                    )
                    .await;
                }
            }
        }
        _ => {
            let _ = write_json(
                &mut socket,
                "404 Not Found",
                &json!({"status":"error","error":"not_found"}),
            )
            .await;
        }
    }
}

type ParsedRequest = (String, String, Vec<String>, Vec<u8>);

async fn read_request(
    socket: &mut TcpStream,
) -> Result<ParsedRequest, (&'static str, serde_json::Value)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut expected_total_bytes: Option<usize> = None;

    loop {
        let read = match timeout(READ_TIMEOUT, socket.read(&mut chunk)).await {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => {
                return Err((
                    "400 Bad Request",
                    json!({"status":"error","error":"request read failed"}),
                ));
            }
            Err(_) => {
                return Err((
                    "408 Request Timeout",
                    json!({"status":"error","error":"request timeout"}),
                ));
            }
        };

        if read == 0 {
            break;
        }

        if buf.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return Err((
                "413 Payload Too Large",
                json!({"status":"error","error":"request too large"}),
            ));
        }

        buf.extend_from_slice(&chunk[..read]);

        if expected_total_bytes.is_none() {
            if let Some(header_end) = header_end_offset(&buf) {
                let request = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = parse_content_length(&request).map_err(|_| {
                    (
                        "400 Bad Request",
                        json!({"status":"error","error":"invalid content-length"}),
                    )
                })?;
                if content_length > MAX_BODY_BYTES {
                    return Err((
                        "413 Payload Too Large",
                        json!({"status":"error","error":"request too large"}),
                    ));
                }
                let total = header_end.saturating_add(content_length);
                expected_total_bytes = Some(total);
                if buf.len() >= total {
                    break;
                }
            }
        } else if let Some(total) = expected_total_bytes
            && buf.len() >= total
        {
            break;
        }
    }

    let header_end = header_end_offset(&buf).ok_or((
        "400 Bad Request",
        json!({"status":"error","error":"malformed request"}),
    ))?;
    let total_bytes = expected_total_bytes.unwrap_or(header_end);
    if buf.len() < total_bytes {
        return Err((
            "400 Bad Request",
            json!({"status":"error","error":"incomplete request body"}),
        ));
    }

    let request_head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let body = buf[header_end..total_bytes].to_vec();

    let mut lines = request_head.lines();
    let request_line = lines.next().unwrap_or_default();
    let headers = lines
        .take_while(|line| !line.trim().is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();

    if !matches!(method.as_str(), "GET" | "POST" | "OPTIONS" | "HEAD") {
        return Err((
            "405 Method Not Allowed",
            json!({"status":"error","error":"method not allowed"}),
        ));
    }

    Ok((method, path, headers, body))
}

fn ensure_json_request(headers: &[String]) -> Result<(), (&'static str, serde_json::Value)> {
    if !header_value(headers, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return Err((
            "415 Unsupported Media Type",
            json!({"status":"error","error":"content type must be application/json"}),
        ));
    }

    Ok(())
}

fn header_end_offset(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_content_length(request: &str) -> Result<usize, ()> {
    for line in request.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().map_err(|_| ());
        }
    }
    Ok(0)
}

fn header_value<'a>(headers: &'a [String], key: &str) -> Option<&'a str> {
    headers.iter().find_map(|header| {
        let (name, value) = header.split_once(':')?;
        if name.eq_ignore_ascii_case(key) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn cors_headers() -> &'static [(&'static str, &'static str)] {
    &[
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Headers", "content-type"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Cache-Control", "no-store"),
    ]
}

async fn write_json(
    socket: &mut TcpStream,
    status: &str,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    write_response(
        socket,
        status,
        "application/json",
        cors_headers(),
        &value.to_string(),
    )
    .await
}

async fn write_response(
    socket: &mut TcpStream,
    status: &str,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> std::io::Result<()> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    socket.write_all(response.as_bytes()).await
}
