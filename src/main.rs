// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use dashmap::DashSet;
use futures::future::try_join_all;
use oxidity_searcher::app::config::GlobalSettings;
use oxidity_searcher::app::logging::{
    ansi_tables_enabled, format_framed_table, format_framed_table_with_blue_title, setup_logging,
};
use oxidity_searcher::domain::error::AppError;
use oxidity_searcher::infrastructure::data::address_registry::validate_address_map;
use oxidity_searcher::infrastructure::data::db::Database;
use oxidity_searcher::infrastructure::data::token_manager::TokenManager;
use oxidity_searcher::infrastructure::network::gas::GasOracle;
use oxidity_searcher::infrastructure::network::nonce::NonceManager;
use oxidity_searcher::infrastructure::network::price_feed::PriceFeed;
use oxidity_searcher::infrastructure::network::provider::ConnectionFactory;
use oxidity_searcher::services::strategy::engine::{Engine, EngineConfig};
use oxidity_searcher::services::strategy::portfolio::PortfolioManager;
use oxidity_searcher::services::strategy::router_discovery::{
    RouterDiscovery, RouterDiscoveryBudget, RouterDiscoveryConfig,
};
use oxidity_searcher::services::strategy::safety::SafetyGuard;
use oxidity_searcher::services::strategy::simulation::{SimulationBackend, Simulator};
use oxidity_searcher::services::strategy::strategy::{AllowlistCategory, classify_allowlist_entry};
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about = "oxidity searcher")]
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

    /// Base directory for data files (tokenlist, address registry, feeds, pairs)
    #[arg(long)]
    data_dir: Option<String>,

    /// Print redacted effective configuration and exit
    #[arg(long, default_value_t = false)]
    print_effective_config: bool,
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

    let panel_lines = [
        "Selected canonical Chainlink feeds".to_string(),
        format!("chain_id={chain_id}"),
        format!("feed_count={feed_count}"),
        format!("critical={critical_summary}"),
        format!("sample={sample}"),
    ];
    if ansi_tables_enabled() {
        let framed = format_framed_table_with_blue_title(panel_lines.iter().map(String::as_str));
        eprintln!("{framed}");
    } else {
        let framed = format_framed_table(panel_lines.iter().map(String::as_str));
        tracing::info!(target: "config", "\n{framed}");
    }
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
    let loaded = GlobalSettings::load_with_report(cli.config.as_deref())?;
    let effective_config = loaded.effective_config_json();
    let config_debug = loaded.config_debug;
    let config_hash = loaded.report.effective_config_hash.clone();
    let config_warnings = loaded.report.warnings.clone();
    let field_sources = loaded.report.field_sources.clone();
    let config_report = json!({
        "effective_config_hash": config_hash,
        "warnings": config_warnings.clone(),
        "field_sources": field_sources.clone(),
        "effective_config": effective_config,
    });
    if cli.print_effective_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&config_report)
                .map_err(|e| AppError::Initialization(format!("config print failed: {e}")))?
        );
        return Ok(());
    }

    let mut settings = loaded.settings;
    if let Some(data_dir) = cli.data_dir.as_deref()
        && !data_dir.trim().is_empty()
    {
        settings.data_dir = Some(data_dir.trim().to_string());
    }

    setup_logging(&settings.log_level, false);
    tracing::info!(
        target: "config",
        effective_config_hash = %config_hash,
        "Effective config hash"
    );
    if !config_warnings.is_empty() {
        for warning in &config_warnings {
            tracing::warn!(target: "config", warning = %warning, "Config resolver warning");
        }
    }
    if config_debug {
        tracing::info!(
            target: "config",
            effective_config_hash = %config_hash,
            "Effective config debug enabled"
        );
        tracing::info!(target: "config", report = %config_report, "Redacted effective configuration");
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
    let metrics_base: u16 = cli.metrics_port.unwrap_or(settings.metrics_port);
    let slippage_bps = cli.slippage_bps.unwrap_or(settings.slippage_bps);
    let strategy_enabled_flag =
        !cli.no_strategy && cli.strategy_enabled && settings.strategy_enabled;
    let worker_limit = settings.strategy_worker_limit();
    let tokenlist_path = settings.tokenlist_path()?;
    let pairs_path = settings.pairs_path()?;
    let address_registry_path = settings.address_registry_path()?;
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
    let relay_http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2_500))
        .build()
        .map_err(|e| AppError::Initialization(format!("relay HTTP client init failed: {e}")))?;

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
        let wrapped_native =
            oxidity_searcher::common::constants::wrapped_native_for_chain(chain_id);
        let price_feed = PriceFeed::new(
            http_provider.clone(),
            chain_id,
            chainlink_feeds,
            settings.price_api_keys(),
        )?;
        let simulation_backend = {
            let configured = settings.simulation_backend.trim().to_lowercase();
            let explicit = !configured.is_empty()
                && configured != "auto"
                && configured != "mainnet_priority"
                && configured != "mainnet-priority";
            if chain_id == 1 && !explicit {
                SimulationBackend::mainnet_priority()
            } else {
                SimulationBackend::new(settings.simulation_backend.clone())
            }
        };
        let simulator = Simulator::new(http_provider.clone(), simulation_backend);

        let strategy_enabled = strategy_enabled_flag;
        let router_allowlist = Arc::new(DashSet::new());
        let wrapper_allowlist = Arc::new(DashSet::new());
        let infra_allowlist = Arc::new(DashSet::new());
        for (name, addr) in settings.routers_for_chain(chain_id)? {
            match classify_allowlist_entry(&name) {
                AllowlistCategory::Routers => {
                    router_allowlist.insert(addr);
                }
                AllowlistCategory::Wrappers => {
                    wrapper_allowlist.insert(addr);
                }
                AllowlistCategory::Infra => {
                    infra_allowlist.insert(addr);
                }
            }
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
            let discovery_budget = RouterDiscoveryBudget {
                max_blocks_per_cycle: settings.router_discovery_bootstrap_lookback_blocks_value(),
                max_rpc_calls_per_cycle: settings.router_discovery_max_rpc_calls_per_cycle_value(),
                cycle_timeout: settings.router_discovery_cycle_timeout(),
                failure_budget: settings.router_discovery_failure_budget_value(),
                cooldown: settings.router_discovery_cooldown(),
            };
            let discovery_config = RouterDiscoveryConfig {
                chain_id,
                allowlist: router_allowlist.clone(),
                db: db.clone(),
                http_provider: Some(http_provider_url.clone()),
                etherscan_api_key: settings.etherscan_api_key_value(),
                enabled: settings.router_discovery_enabled,
                auto_allow: settings.router_discovery_auto_allow,
                min_hits: settings.router_discovery_min_hits,
                flush_every: settings.router_discovery_flush_every,
                check_interval: settings.router_discovery_check_interval(),
                max_entries: settings.router_discovery_max_entries,
                budget: discovery_budget,
                cache_path: settings.router_discovery_cache_path().ok(),
                force_full_rescan: settings.router_discovery_force_full_rescan,
            };
            match RouterDiscovery::new(discovery_config) {
                Ok(discovery) => {
                    let discovery = Arc::new(discovery);
                    discovery.spawn_bootstrap_top_unknown(
                        settings.router_discovery_bootstrap_limit_value(),
                        settings.router_discovery_bootstrap_lookback_blocks_value(),
                    );
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
            let idx_u16 = u16::try_from(idx).map_err(|_| {
                AppError::Config(format!(
                    "Too many chains configured for metrics port indexing: idx={idx}"
                ))
            })?;
            metrics_base.checked_add(idx_u16).ok_or_else(|| {
                AppError::Config(format!(
                    "Metrics port overflow: base={metrics_base} idx={idx}"
                ))
            })?
        } else {
            metrics_base
        };

        let engine = Engine::new(EngineConfig {
            http_provider,
            websocket_provider,
            db: db.clone(),
            nonce_manager,
            portfolio,
            safety_guard,
            dry_run: cli.dry_run,
            gas_oracle,
            price_feed,
            chain_id,
            relay_url: relay_url.clone(),
            mev_share_relay_url: settings.mev_share_relay_url(),
            wallet_signer: wallet_signer.clone(),
            bundle_signer: bundle_signer.clone(),
            executor: settings.executor_address,
            executor_bribe_bps: settings.executor_bribe_bps,
            executor_bribe_recipient: settings.executor_bribe_recipient,
            flashloan_enabled: settings.flashloan_enabled,
            flashloan_providers: settings.flashloan_providers(),
            aave_pool: settings.aave_pool_for_chain(chain_id),
            max_gas_price_gwei: settings
                .gas_cap_for_chain(chain_id)
                .unwrap_or(settings.max_gas_price_gwei),
            gas_cap_multiplier_bps: settings.gas_cap_multiplier_bps_value(),
            simulator,
            token_manager: token_manager.clone(),
            metrics_port,
            metrics_bind: settings.metrics_bind_value(),
            metrics_token: settings.metrics_token_value(),
            metrics_enable_shutdown: settings.metrics_enable_shutdown_value(),
            strategy_enabled,
            slippage_bps,
            profit_guard_base_floor_multiplier_bps: settings
                .profit_guard_base_floor_multiplier_bps_value(),
            profit_guard_cost_multiplier_bps: settings.profit_guard_cost_multiplier_bps_value(),
            profit_guard_min_margin_bps: settings.profit_guard_min_margin_bps_value(),
            liquidity_ratio_floor_ppm: settings.liquidity_ratio_floor_ppm_value(),
            sell_min_native_out_wei: settings.sell_min_native_out_wei_value(),
            router_allowlist,
            wrapper_allowlist,
            infra_allowlist,
            router_discovery,
            skip_log_every: settings.skip_log_every_value(),
            wrapped_native,
            allow_non_wrapped_swaps: settings.allow_non_wrapped_swaps,
            mev_share_stream_url: settings.mev_share_stream_url.clone(),
            mev_share_history_limit: settings.mev_share_history_limit,
            mev_share_enabled: settings.mev_share_enabled,
            mevshare_builders: settings.mevshare_builders_value(),
            sandwich_attacks_enabled: settings.sandwich_attacks_enabled,
            simulation_backend: settings.simulation_backend.clone(),
            chainlink_feed_strict: settings.chainlink_feed_audit_strict_for_chain(chain_id),
            bundle_use_replacement_uuid: settings.bundle_use_replacement_uuid_for_chain(chain_id),
            bundle_cancel_previous: settings.bundle_cancel_previous_for_chain(chain_id),
            worker_limit,
            address_registry_path: address_registry_path.clone(),
            pairs_path: pairs_path.clone(),
            receipt_poll_ms: settings.receipt_poll_ms_value(),
            receipt_timeout_ms: settings.receipt_timeout_ms_value(),
            receipt_confirm_blocks: settings.receipt_confirm_blocks_value(),
            emergency_exit_on_unknown_receipt: settings.emergency_exit_on_unknown_receipt,
            runtime_settings: settings.strategy_runtime_settings(),
            rpc_capability_strict: settings.rpc_capability_strict_for_chain(chain_id),
            feed_audit_max_lag_blocks: settings.feed_audit_max_lag_blocks_value(),
            feed_audit_recheck_secs: settings.feed_audit_recheck_secs_value(),
            feed_audit_public_rpc_url: settings.feed_audit_public_rpc_url_value(),
            feed_audit_public_tip_lag_blocks: settings.feed_audit_public_tip_lag_blocks_value(),
            bundle_target_blocks: settings.bundle_target_blocks_value(),
            relay_http_client: relay_http_client.clone(),
        });

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
