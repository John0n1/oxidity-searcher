# Oxidity Wallet

`wallet.oxidity.io` is the public wallet product site and shared wallet shell for:

- the web experience under `/app`
- the Chrome extension popup build
- the Android Capacitor wrapper
- the Rust wallet bootstrap / preview API exposed separately from the searcher

## Local development

1. Install dependencies with `npm install`
2. Copy `.env.example` to `.env.local` if you need non-default API endpoints
3. Run `npm run dev`

## Build targets

- `npm run build:web` builds the wallet product site and `/app` shell
- `npm run build:extension` builds the Chrome extension package and writes `public/downloads/oxidity-wallet-extension.zip`
- `npm run android:sync` syncs the web bundle into the Android Capacitor project

## Android

The Android wrapper is already added in `android/`.

Typical workflow:

1. Ensure `ANDROID_HOME` and `ANDROID_SDK_ROOT` point at a valid SDK root
2. Run `npm run android:sync`
3. Build with `cd android && ./gradlew assembleDebug`

Current generated artifact:

- `android/app/build/outputs/apk/debug/app-debug.apk`
- copied to `public/downloads/oxidity-wallet-debug.apk` for site distribution

## Rust wallet service

The Rust backend lives under `src/wallet` and is started with:

```bash
cargo run --bin wallet_service
```

Default endpoints:

- `GET /health`
- `GET /bootstrap`
- `POST /quote-preview`
