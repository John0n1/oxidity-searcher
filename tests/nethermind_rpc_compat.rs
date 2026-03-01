use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

fn nethermind_http_provider() -> Option<String> {
    std::env::var("NETHERMIND_HTTP_PROVIDER")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

async fn rpc_call(client: &Client, url: &str, method: &str, params: Value) -> RpcResponse {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1u64,
        "method": method,
        "params": params,
    });
    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .expect("rpc request");
    assert!(
        resp.status().is_success(),
        "non-success HTTP status for {method}"
    );
    resp.json::<RpcResponse>()
        .await
        .expect("rpc response decode")
}

fn assert_shape_conformant(method: &str, resp: &RpcResponse) {
    if let Some(err) = &resp.error {
        let msg = err.message.to_lowercase();
        assert_ne!(
            err.code, -32601,
            "{method} missing/unavailable on configured Nethermind node: {}",
            err.message
        );
        assert_ne!(
            err.code, -32602,
            "{method} rejected with invalid params: {}",
            err.message
        );
        assert!(
            !msg.contains("invalid params")
                && !msg.contains("missing value for required argument")
                && !msg.contains("cannot unmarshal")
                && !msg.contains("invalid argument"),
            "{method} appears parameter-shape non-conformant: code={} message={}",
            err.code,
            err.message
        );
        return;
    }
    assert!(
        resp.result.is_some(),
        "{method} response missing result/error"
    );
}

#[tokio::test]
async fn eth_simulate_v1_shape_matches_nethermind_expectations() {
    let Some(url) = nethermind_http_provider() else {
        eprintln!("skipping eth_simulateV1 conformance test: NETHERMIND_HTTP_PROVIDER is not set");
        return;
    };
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    let chain = rpc_call(&client, &url, "eth_chainId", json!([])).await;
    let chain_id = chain.result.and_then(|v| v.as_str().map(str::to_string));
    assert_eq!(
        chain_id.as_deref(),
        Some("0x1"),
        "NETHERMIND_HTTP_PROVIDER must point to Ethereum mainnet"
    );

    let params = json!([
        {
            "blockStateCalls": [
                {
                    "calls": [
                        {
                            "from": "0x0000000000000000000000000000000000000000",
                            "to": "0x0000000000000000000000000000000000000000",
                            "value": "0x0"
                        }
                    ]
                }
            ],
            "traceTransfers": false,
            "validation": false,
            "returnFullTransactions": false
        },
        "latest"
    ]);

    let resp = rpc_call(&client, &url, "eth_simulateV1", params).await;
    assert_shape_conformant("eth_simulateV1", &resp);
}

#[tokio::test]
async fn debug_trace_call_many_shape_matches_nethermind_expectations() {
    let Some(url) = nethermind_http_provider() else {
        eprintln!(
            "skipping debug_traceCallMany conformance test: NETHERMIND_HTTP_PROVIDER is not set"
        );
        return;
    };
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    let chain = rpc_call(&client, &url, "eth_chainId", json!([])).await;
    let chain_id = chain.result.and_then(|v| v.as_str().map(str::to_string));
    assert_eq!(
        chain_id.as_deref(),
        Some("0x1"),
        "NETHERMIND_HTTP_PROVIDER must point to Ethereum mainnet"
    );

    let params = json!([
        [
            {
                "transactions": [
                    {
                        "from": "0x0000000000000000000000000000000000000000",
                        "to": "0x0000000000000000000000000000000000000000",
                        "value": "0x0"
                    }
                ]
            }
        ],
        "latest",
        {}
    ]);

    let resp = rpc_call(&client, &url, "debug_traceCallMany", params).await;
    assert_shape_conformant("debug_traceCallMany", &resp);
}
