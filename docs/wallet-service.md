# Wallet Service

The wallet backend is a standalone Rust service under `src/wallet` and `src/bin/wallet_service.rs`.

## Purpose

- serve wallet bootstrap metadata to `wallet.oxidity.io`
- provide an early quote preview API for the shared wallet shell
- stay separate from the production MEV searcher runtime

## Default runtime

- bind: `127.0.0.1`
- port: `9555`

## Endpoints

- `GET /health`
- `GET /bootstrap`
- `POST /quote-preview`

`/quote-preview` currently provides a policy-oriented preview model for a small ETH/stable pair set. It is intentionally not a live executable quote engine yet.

## Example

```bash
curl -s http://127.0.0.1:9555/bootstrap | jq
curl -s http://127.0.0.1:9555/quote-preview \
  -H 'content-type: application/json' \
  -d '{"chainId":1,"sellToken":"ETH","buyToken":"USDC","sellAmount":"0.5"}' | jq
```

## Android and extension artifacts

The wallet frontend writes site-downloadable artifacts into `wallet.oxidity.io/public/downloads/`:

- `oxidity-wallet-extension.zip`
- `oxidity-wallet-debug.apk`

These are preview artifacts. Release signing and store submission should be layered on later.
