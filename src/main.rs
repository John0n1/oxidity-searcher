// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use dashmap::DashSet;
use futures::future::try_join_all;
use mitander_search::app::config::GlobalSettings;
use mitander_search::app::logging::setup_logging;
use mitander_search::domain::error::AppError;
use mitander_search::infrastructure::data::address_registry::validate_address_map;
use mitander_search::infrastructure::data::db::Database;
use mitander_search::infrastructure::data::token_manager::TokenManager;
use mitander_search::infrastructure::network::gas::GasOracle;
use mitander_search::infrastructure::network::nonce::NonceManager;
use mitander_search::infrastructure::network::price_feed::PriceFeed;
use mitander_search::infrastructure::network::provider::ConnectionFactory;
use mitander_search::services::strategy::engine::Engine;
use mitander_search::services::strategy::portfolio::PortfolioManager;
use mitander_search::services::strategy::safety::SafetyGuard;
use mitander_search::services::strategy::simulation::{SimulationBackend, Simulator};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about = "mitander search")]
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

fn log_chainlink_feed_summary(chain_id: u64, feeds: &HashMap<String, alloy::primitives::Address>) {
    let mut entries: Vec<(String, alloy::primitives::Address)> =
        feeds.iter().map(|(k, v)| (k.to_uppercase(), *v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let feed_count = entries.len();
    let sample = entries
        .iter()
        .take(12)
        .map(|(symbol, addr)| format!("{symbol}={addr:#x}"))
        .collect::<Vec<_>>()
        .join(",");

    let critical_symbols = ["ETH", "BTC", "USDC", "USDT"];
    let missing_critical: Vec<&str> = critical_symbols
        .iter()
        .copied()
        .filter(|symbol| !feeds.contains_key(*symbol))
        .collect();
    let critical_summary = critical_symbols
        .iter()
        .filter_map(|symbol| feeds.get(*symbol).map(|addr| format!("{symbol}={addr:#x}")))
        .collect::<Vec<_>>()
        .join(",");

    tracing::info!(
        target: "config",
        chain_id,
        feed_count,
        critical = %critical_summary,
        sample = %sample,
        "Selected canonical Chainlink feeds"
    );
    if !missing_critical.is_empty() {
        tracing::warn!(
            target: "config",
            chain_id,
            missing = %missing_critical.join(","),
            "Critical Chainlink symbols missing from selected feed set"
        );
    }
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
    if let Some(key) = settings.etherscan_api_key_value()
        && std::env::var("ETHERSCAN_API_KEY").is_err()
    {
        unsafe { std::env::set_var("ETHERSCAN_API_KEY", key) };
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
        if let Some(url) = settings.primary_http_provider() {
            let http = ConnectionFactory::http(&url)?;
            let cid_u64: u64 = http
                .get_chain_id()
                .await
                .map_err(|e| AppError::Connection(format!("chain_id detect failed: {e}")))?;
            tracing::info!(target: "config", detected_chain = cid_u64, rpc = %url, "Auto-detected chain_id from RPC");
            vec![cid_u64]
        } else {
            return Err(AppError::Config(
                "No chains configured and no http_provider available to auto-detect".into(),
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
    let mut engine_tasks = Vec::new();

    for (idx, chain_id) in chains.iter().copied().enumerate() {
        let http_provider_url = settings.get_http_provider(chain_id)?;
        let ipc_provider = settings.get_ipc_provider(chain_id);
        let (websocket_provider, http_provider) = if let Some(ipc_provider) = ipc_provider {
            let ipc = ConnectionFactory::ipc(&ipc_provider).await.map_err(|e| {
                AppError::Connection(format!(
                    "IPC required for chain {chain_id} at {ipc_provider} but failed: {e}"
                ))
            })?;
            let websocket_provider = match settings.get_websocket_provider(chain_id) {
                Ok(url) => ConnectionFactory::ws(&url).await.unwrap_or_else(|e| {
                    tracing::warn!(target: "rpc", chain_id, error=%e, "WS unavailable, using IPC for streaming");
                    ipc.clone()
                }),
                Err(_) => ipc.clone(),
            };
            (websocket_provider, ipc)
        } else {
            let websocket_provider_url = match settings.get_websocket_provider(chain_id) {
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
            ConnectionFactory::preferred(
                None,
                websocket_provider_url.as_deref(),
                &http_provider_url,
            )
            .await?
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
        } else {
            log_chainlink_feed_summary(chain_id, &chainlink_feeds);
        }
        let wrapped_native = mitander_search::common::constants::wrapped_native_for_chain(chain_id);
        let price_feed = PriceFeed::new(
            http_provider.clone(),
            chain_id,
            chainlink_feeds,
            settings.price_api_keys(),
        )?;
        let simulation_backend = if chain_id == 1 {
            SimulationBackend::mainnet_priority()
        } else {
            SimulationBackend::new(settings.simulation_backend.clone())
        };
        let simulator = Simulator::new(http_provider.clone(), simulation_backend);

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
            match mitander_search::services::strategy::router_discovery::RouterDiscovery::new(
                chain_id,
                router_allowlist.clone(),
                db.clone(),
                Some(http_provider_url.clone()),
                settings.etherscan_api_key_value(),
                settings.router_discovery_enabled,
                settings.router_discovery_auto_allow,
                settings.router_discovery_min_hits,
                settings.router_discovery_flush_every,
                settings.router_discovery_check_interval(),
                settings.router_discovery_max_entries,
            ) {
                Ok(discovery) => {
                    let discovery = Arc::new(discovery);
                    discovery.spawn_bootstrap_top_unknown(1000, 512);
                    Some(discovery)
                }
                Err(e) => {
                    tracing::warn!(
                        target: "router_discovery",
                        chain_id,
                        error = %e,
                        "Router discovery init failed; continuing with static allowlist"
                    );
                    None
                }
            }
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
            websocket_provider,
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
            settings.executor_bribe_recipient,
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
            settings.profit_guard_base_floor_multiplier_bps_value(),
            settings.profit_guard_cost_multiplier_bps_value(),
            settings.profit_guard_min_margin_bps_value(),
            settings.liquidity_ratio_floor_ppm_value(),
            settings.sell_min_native_out_wei_value(),
            router_allowlist,
            router_discovery,
            settings.skip_log_every_value(),
            wrapped_native,
            settings.allow_non_wrapped_swaps,
            settings.mev_share_stream_url.clone(),
            settings.mev_share_history_limit,
            settings.mev_share_enabled,
            settings.mevshare_builders_value(),
            settings.sandwich_attacks_enabled,
            settings.simulation_backend.clone(),
            settings.chainlink_feed_audit_strict_for_chain(chain_id),
            settings.bundle_use_replacement_uuid_for_chain(chain_id),
            settings.bundle_cancel_previous_for_chain(chain_id),
            worker_limit,
            settings.address_registry_path(),
            settings.receipt_poll_ms_value(),
            settings.receipt_timeout_ms_value(),
            settings.receipt_confirm_blocks_value(),
            settings.emergency_exit_on_unknown_receipt,
            settings.rpc_capability_strict_for_chain(chain_id),
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
