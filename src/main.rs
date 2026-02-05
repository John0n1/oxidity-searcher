// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use dashmap::DashSet;
use futures::future::try_join_all;
use oxidity_builder::app::config::GlobalSettings;
use oxidity_builder::app::logging::setup_logging;
use oxidity_builder::domain::error::AppError;
use oxidity_builder::infrastructure::data::db::Database;
use oxidity_builder::infrastructure::data::address_registry::validate_address_map;
use oxidity_builder::infrastructure::data::token_manager::TokenManager;
use oxidity_builder::infrastructure::network::gas::GasOracle;
use oxidity_builder::infrastructure::network::nonce::NonceManager;
use oxidity_builder::infrastructure::network::price_feed::PriceFeed;
use oxidity_builder::infrastructure::network::provider::ConnectionFactory;
use oxidity_builder::services::strategy::engine::Engine;
use oxidity_builder::services::strategy::portfolio::PortfolioManager;
use oxidity_builder::services::strategy::safety::SafetyGuard;
use oxidity_builder::services::strategy::simulation::{SimulationBackend, Simulator};
use std::str::FromStr;
use std::sync::Arc;
use alloy::providers::Provider;

#[derive(Parser, Debug)]
#[command(author, version, about = "Oxidity Builder")]
struct Cli {
    /// Path to config file (default: config.{toml,yaml,...})
    #[arg(long)]
    config: Option<String>,

    /// Do not submit transactions/bundles, only simulate/log
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Metrics port (overrides config/env)
    #[arg(long)]
    metrics_port: Option<u16>,

    /// Enable strategies (ingest + execute)
    #[arg(long, default_value_t = true)]
    strategy_enabled: bool,

    /// Disable strategies (ingest only)
    #[arg(long, default_value_t = false)]
    no_strategy: bool,

    /// Slippage basis points for crafted bundles
    #[arg(long)]
    slippage_bps: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    let settings = GlobalSettings::load_with_path(cli.config.as_deref())?;
    setup_logging(if settings.debug { "debug" } else { "info" }, false);

    if let Some(bind) = settings.metrics_bind_value() {
        unsafe { std::env::set_var("METRICS_BIND", bind) };
    }
    if let Some(token) = settings.metrics_token_value() {
        unsafe { std::env::set_var("METRICS_TOKEN", token) };
    }
    if let Some(key) = settings.etherscan_api_key_value() {
        if std::env::var("ETHERSCAN_API_KEY").is_err() {
            unsafe { std::env::set_var("ETHERSCAN_API_KEY", key) };
        }
    }

    let database_url = settings.database_url();
    let db = Database::new(&database_url).await?;

    let wallet_signer = PrivateKeySigner::from_str(&settings.wallet_key)
        .map_err(|e| AppError::Config(format!("Invalid wallet key: {}", e)))?;
    let wallet_address = wallet_signer.address();
    if wallet_address != settings.wallet_address {
        return Err(AppError::Config(format!(
            "wallet_address {} does not match wallet_key address {}",
            settings.wallet_address, wallet_address
        )));
    }

    // Auto-detect chain if not explicitly configured
    let chains: Vec<u64> = if settings.chains.is_empty() {
        if let Some(url) = settings.primary_http_url() {
            let http = ConnectionFactory::http(&url)?;
            let cid_u64: u64 = http
                .get_chain_id()
                .await
                .map_err(|e| AppError::Connection(format!("chain_id detect failed: {e}")))?;
            tracing::info!(target: "config", detected_chain = cid_u64, rpc = %url, "Auto-detected chain_id from RPC");
            vec![cid_u64]
        } else {
            return Err(AppError::Config(
                "No chains configured and no RPC_URL available to auto-detect".into(),
            ));
        }
    } else {
        settings.chains.clone()
    };

    let relay_url = settings.flashbots_relay_url();
    let bundle_signer = PrivateKeySigner::from_str(&settings.bundle_signer_key())
        .map_err(|e| AppError::Config(format!("Invalid bundle signer key: {}", e)))?;
    let metrics_base: u16 = cli
        .metrics_port
        .or_else(|| {
            std::env::var("METRICS_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(settings.metrics_port);
    let slippage_bps = cli.slippage_bps.unwrap_or(settings.slippage_bps);
    let strategy_enabled_flag =
        !cli.no_strategy && cli.strategy_enabled && settings.strategy_enabled;
    let worker_limit = settings.strategy_worker_limit();
    let tokenlist_path = settings.tokenlist_path();
    let token_manager = Arc::new(
        TokenManager::load_from_file(&tokenlist_path).unwrap_or_else(|e| {
            tracing::warn!(
                "TokenManager: failed to load {}; defaulting to empty list: {}",
                tokenlist_path,
                e
            );
            TokenManager::default()
        }),
    );
    let profit_receiver = settings.profit_receiver_or_wallet();

    let mut engine_tasks = Vec::new();

    for (idx, chain_id) in chains.iter().copied().enumerate() {
        let ipc_url = settings.get_ipc_url(chain_id);
        let (ws_provider, http_provider) = if let Some(ipc_path) = ipc_url {
            let ipc = ConnectionFactory::ipc(&ipc_path).await.map_err(|e| {
                AppError::Connection(format!(
                    "IPC required for chain {chain_id} at {ipc_path} but failed: {e}"
                ))
            })?;
            let ws_provider = match settings.get_ws_url(chain_id) {
                Ok(url) => ConnectionFactory::ws(&url).await.unwrap_or_else(|e| {
                    tracing::warn!(target: "rpc", chain_id, error=%e, "WS unavailable, using IPC for streaming");
                    ipc.clone()
                }),
                Err(_) => ipc.clone(),
            };
            (ws_provider, ipc)
        } else {
            let ws_url = match settings.get_ws_url(chain_id) {
                Ok(url) => Some(url),
                Err(e) => {
                    tracing::warn!(
                        target: "rpc",
                        chain_id,
                        error = %e,
                        "WS URL unavailable; continuing without WS fallback"
                    );
                    None
                }
            };
            let rpc_url = settings.get_rpc_url(chain_id)?;
            ConnectionFactory::preferred(None, ws_url.as_deref(), &rpc_url).await?
        };

        let portfolio = Arc::new(PortfolioManager::new(http_provider.clone(), wallet_address));
        let nonce_manager = NonceManager::new(http_provider.clone(), wallet_address);
        let safety_guard = Arc::new(SafetyGuard::new());
        let gas_oracle = GasOracle::new(http_provider.clone(), chain_id);

        let chainlink_feeds_raw = settings.chainlink_feeds_for_chain(chain_id)?;
        let chainlink_feeds =
            validate_address_map(&http_provider, chainlink_feeds_raw, "chainlink_feeds").await;
        if chainlink_feeds.is_empty() {
            tracing::warn!("No Chainlink feeds configured for chain {}", chain_id);
        }
        let wrapped_native = oxidity_builder::common::constants::wrapped_native_for_chain(chain_id);
        let price_feed = PriceFeed::new(
            http_provider.clone(),
            chainlink_feeds,
            settings.price_api_keys(),
        );
        let simulator = Simulator::new(
            http_provider.clone(),
            SimulationBackend::new(settings.simulation_backend.clone()),
        );

        let strategy_enabled = strategy_enabled_flag;
        let router_allowlist = Arc::new(DashSet::new());
        for addr in settings.routers_for_chain(chain_id)?.values().copied() {
            router_allowlist.insert(addr);
        }
        if let Ok(approved) = db.approved_routers(chain_id).await {
            for addr in approved {
                router_allowlist.insert(addr);
            }
        }
        if router_allowlist.is_empty() {
            tracing::warn!(target: "router", chain_id, "Router allowlist is empty");
        }

        let router_discovery = if settings.router_discovery_enabled {
            Some(Arc::new(
                oxidity_builder::services::strategy::router_discovery::RouterDiscovery::new(
                    chain_id,
                    router_allowlist.clone(),
                    db.clone(),
                    settings.etherscan_api_key_value(),
                    settings.router_discovery_enabled,
                    settings.router_discovery_auto_allow,
                    settings.router_discovery_min_hits,
                    settings.router_discovery_flush_every,
                    settings.router_discovery_check_interval(),
                    settings.router_discovery_max_entries,
                ),
            ))
        } else {
            None
        };

        let metrics_port = if chains.len() > 1 {
            metrics_base.saturating_add(idx as u16)
        } else {
            metrics_base
        };

        let engine = Engine::new(
            http_provider,
            ws_provider,
            db.clone(),
            nonce_manager,
            portfolio,
            safety_guard,
            cli.dry_run,
            gas_oracle,
            price_feed,
            chain_id,
            relay_url.clone(),
            settings.mev_share_relay_url(),
            wallet_signer.clone(),
            bundle_signer.clone(),
            settings.executor_address,
            settings.executor_bribe_bps,
            settings.executor_bribe_recipient.or(Some(profit_receiver)),
            settings.flashloan_enabled,
            settings.flashloan_providers(),
            settings.aave_pool_for_chain(chain_id),
            settings
                .gas_cap_for_chain(chain_id)
                .unwrap_or(settings.max_gas_price_gwei),
            settings.gas_cap_multiplier_bps_value(),
            simulator,
            token_manager.clone(),
            metrics_port,
            strategy_enabled,
            slippage_bps,
            router_allowlist,
            router_discovery,
            settings.skip_log_every_value(),
            wrapped_native,
            settings.allow_non_wrapped_swaps,
            settings.mev_share_stream_url.clone(),
            settings.mev_share_history_limit,
            settings.mev_share_enabled,
            settings.sandwich_attacks_enabled,
            settings.simulation_backend.clone(),
            worker_limit,
            settings.address_registry_path(),
        );

        engine_tasks.push(tokio::spawn(async move { engine.run().await }));
    }

    let results = try_join_all(engine_tasks)
        .await
        .map_err(|e| AppError::Strategy(format!("Engine task join failed: {e}")))?;
    for res in results {
        res?;
    }
    Ok(())
}
