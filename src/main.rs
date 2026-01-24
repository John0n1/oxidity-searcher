// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use oxidity_builder::app::config::GlobalSettings;
use oxidity_builder::app::logging::setup_logging;
use oxidity_builder::domain::error::AppError;
use oxidity_builder::infrastructure::data::db::Database;
use oxidity_builder::infrastructure::data::token_manager::TokenManager;
use oxidity_builder::infrastructure::network::gas::GasOracle;
use oxidity_builder::infrastructure::network::price_feed::PriceFeed;
use oxidity_builder::infrastructure::network::provider::ConnectionFactory;
use oxidity_builder::services::strategy::engine::Engine;
use oxidity_builder::services::strategy::nonce::NonceManager;
use oxidity_builder::services::strategy::portfolio::PortfolioManager;
use oxidity_builder::services::strategy::safety::SafetyGuard;
use oxidity_builder::services::strategy::simulation::Simulator;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

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

    /// Disable strategies (ingest only)
    #[arg(long, default_value_t = true)]
    strategy_enabled: bool,

    /// Slippage basis points for crafted bundles
    #[arg(long)]
    slippage_bps: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    let settings = GlobalSettings::load_with_path(cli.config.as_deref())?;
    setup_logging(if settings.debug { "debug" } else { "info" }, false);

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://oxidity_builder.db".to_string());
    let db = Database::new(&database_url).await?;

    let chain_id = *settings.chains.get(0).unwrap_or(&1);

    let ipc_url = settings.get_ipc_url(chain_id);
    let ws_url = match settings.get_ws_url(chain_id) {
        Ok(url) => Some(url),
        Err(e) => {
            tracing::warn!(
                target: "rpc",
                error = %e,
                "WS URL unavailable; continuing without WS fallback"
            );
            None
        }
    };
    let rpc_url = settings.get_rpc_url(chain_id)?;
    let (ws_provider, http_provider) =
        ConnectionFactory::preferred(ipc_url.as_deref(), ws_url.as_deref(), &rpc_url).await?;

    let wallet_address = settings.wallet_address;
    let portfolio = Arc::new(PortfolioManager::new(http_provider.clone(), wallet_address));
    let nonce_manager = NonceManager::new(http_provider.clone(), wallet_address);
    let safety_guard = Arc::new(SafetyGuard::new());
    let gas_oracle = GasOracle::new(http_provider.clone());

    let chainlink_feeds = settings.chainlink_feeds_for_chain(chain_id)?;
    if chainlink_feeds.is_empty() {
        tracing::warn!("No Chainlink feeds configured for chain {}", chain_id);
    }
    let wrapped_native = oxidity_builder::common::constants::wrapped_native_for_chain(chain_id);
    let price_feed = PriceFeed::new(http_provider.clone(), chainlink_feeds);
    let simulator = Simulator::new(http_provider.clone());
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

    let relay_url = settings.flashbots_relay_url();
    let bundle_signer = PrivateKeySigner::from_str(&settings.bundle_signer_key())
        .map_err(|e| AppError::Config(format!("Invalid bundle signer key: {}", e)))?;
    let metrics_port: u16 = cli
        .metrics_port
        .or_else(|| {
            std::env::var("METRICS_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(settings.metrics_port);
    let slippage_bps = cli.slippage_bps.unwrap_or(settings.slippage_bps);
    let strategy_enabled = cli.strategy_enabled && settings.strategy_enabled;
    let router_allowlist: HashSet<Address> = settings
        .routers_for_chain(chain_id)?
        .values()
        .copied()
        .collect();
    if router_allowlist.is_empty() {
        tracing::warn!("Router allowlist is empty for chain {}", chain_id);
    }

    let engine = Engine::new(
        http_provider,
        ws_provider,
        db,
        nonce_manager,
        portfolio,
        safety_guard,
        cli.dry_run,
        gas_oracle,
        price_feed,
        chain_id,
        relay_url,
        bundle_signer,
        settings.executor_address,
        settings.executor_bribe_bps,
        settings.executor_bribe_recipient,
        settings.flashloan_enabled,
        settings
            .gas_cap_for_chain(chain_id)
            .unwrap_or(settings.max_gas_price_gwei),
        simulator,
        token_manager,
        metrics_port,
        strategy_enabled,
        slippage_bps,
        router_allowlist,
        wrapped_native,
        settings.mev_share_stream_url.clone(),
        settings.mev_share_history_limit,
        settings.mev_share_enabled,
    );

    engine.run().await
}
