// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use crate::common::error::AppError;
use crate::core::executor::{BundleSender, SharedBundleSender};
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::Simulator;
use crate::core::strategy::{StrategyExecutor, StrategyStats, StrategyWork};
use crate::common::constants::default_balancer_vault_for_chain;
use crate::data::db::Database;
use crate::infrastructure::data::address_registry::AddressRegistry;
use crate::infrastructure::data::token_manager::TokenManager;
use crate::network::block_listener::BlockListener;
use crate::network::gas::GasOracle;
use crate::network::mempool::MempoolScanner;
use crate::network::mev_share::MevShareClient;
use crate::network::nonce::NonceManager;
use crate::network::price_feed::PriceFeed;
use crate::network::provider::{HttpProvider, WsProvider};
use crate::network::reserves::ReserveCache;
use crate::services::strategy::router_discovery::RouterDiscovery;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use dashmap::DashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

const INGEST_QUEUE_BOUND: usize = 2048;

pub struct Engine {
    http_provider: HttpProvider,
    ws_provider: WsProvider,
    db: Database,
    nonce_manager: NonceManager,
    portfolio: Arc<PortfolioManager>,
    safety_guard: Arc<SafetyGuard>,
    dry_run: bool,
    gas_oracle: GasOracle,
    price_feed: PriceFeed,
    chain_id: u64,
    relay_url: String,
    mev_share_relay_url: String,
    wallet_signer: PrivateKeySigner,
    bundle_signer: PrivateKeySigner,
    executor: Option<Address>,
    executor_bribe_bps: u64,
    executor_bribe_recipient: Option<Address>,
    flashloan_enabled: bool,
    flashloan_providers: Vec<crate::services::strategy::strategy::FlashloanProvider>,
    aave_pool: Option<Address>,
    max_gas_price_gwei: u64,
    gas_cap_multiplier_bps: u64,
    simulator: Simulator,
    token_manager: Arc<TokenManager>,
    metrics_port: u16,
    strategy_enabled: bool,
    slippage_bps: u64,
    router_allowlist: Arc<DashSet<Address>>,
    router_discovery: Option<Arc<RouterDiscovery>>,
    skip_log_every: u64,
    wrapped_native: Address,
    allow_non_wrapped_swaps: bool,
    mev_share_stream_url: String,
    mev_share_history_limit: u32,
    mev_share_enabled: bool,
    sandwich_attacks_enabled: bool,
    simulation_backend: String,
    worker_limit: usize,
    address_registry_path: String,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http_provider: HttpProvider,
        ws_provider: WsProvider,
        db: Database,
        nonce_manager: NonceManager,
        portfolio: Arc<PortfolioManager>,
        safety_guard: Arc<SafetyGuard>,
        dry_run: bool,
        gas_oracle: GasOracle,
        price_feed: PriceFeed,
        chain_id: u64,
        relay_url: String,
        mev_share_relay_url: String,
        wallet_signer: PrivateKeySigner,
        bundle_signer: PrivateKeySigner,
        executor: Option<Address>,
        executor_bribe_bps: u64,
        executor_bribe_recipient: Option<Address>,
        flashloan_enabled: bool,
        flashloan_providers: Vec<crate::services::strategy::strategy::FlashloanProvider>,
        aave_pool: Option<Address>,
        max_gas_price_gwei: u64,
        gas_cap_multiplier_bps: u64,
        simulator: Simulator,
        token_manager: Arc<TokenManager>,
        metrics_port: u16,
        strategy_enabled: bool,
        slippage_bps: u64,
        router_allowlist: Arc<DashSet<Address>>,
        router_discovery: Option<Arc<RouterDiscovery>>,
        skip_log_every: u64,
        wrapped_native: Address,
        allow_non_wrapped_swaps: bool,
        mev_share_stream_url: String,
        mev_share_history_limit: u32,
        mev_share_enabled: bool,
        sandwich_attacks_enabled: bool,
        simulation_backend: String,
        worker_limit: usize,
        address_registry_path: String,
    ) -> Self {
        Self {
            http_provider,
            ws_provider,
            db,
            nonce_manager,
            portfolio,
            safety_guard,
            dry_run,
            gas_oracle,
            price_feed,
            chain_id,
            relay_url,
            mev_share_relay_url,
            wallet_signer,
            bundle_signer,
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            flashloan_providers,
            aave_pool,
            max_gas_price_gwei,
            gas_cap_multiplier_bps,
            simulator,
            token_manager,
            metrics_port,
            strategy_enabled,
            slippage_bps,
            router_allowlist,
            router_discovery,
            skip_log_every,
            wrapped_native,
            allow_non_wrapped_swaps,
            mev_share_stream_url,
            mev_share_history_limit,
            mev_share_enabled,
            sandwich_attacks_enabled,
            simulation_backend,
            worker_limit,
            address_registry_path,
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        if self.flashloan_enabled && self.executor.is_none() {
            return Err(AppError::Config(
                "flashloan_enabled requires executor_address".into(),
            ));
        }
        if let Some(exec) = self.executor {
            let code = self.http_provider.get_code_at(exec).await.map_err(|e| {
                AppError::Initialization(format!("Executor code check failed: {e}"))
            })?;
            if code.is_empty() {
                return Err(AppError::Config(format!(
                    "executor_address {:#x} has no code deployed",
                    exec
                )));
            }
        }

        let stats = Arc::new(StrategyStats::default());
        let (tx_sender, tx_receiver) = mpsc::channel::<StrategyWork>(INGEST_QUEUE_BOUND);
        let (block_sender, block_receiver) = broadcast::channel(32);

        let mempool = MempoolScanner::new(
            self.ws_provider.clone(),
            tx_sender.clone(),
            stats.clone(),
            INGEST_QUEUE_BOUND,
        );
        let block_listener = BlockListener::new(
            self.ws_provider.clone(),
            block_sender.clone(),
            self.nonce_manager.clone(),
        );
        let bundle_sender: SharedBundleSender = Arc::new(BundleSender::new(
            self.http_provider.clone(),
            self.dry_run,
            self.relay_url.clone(),
            self.mev_share_relay_url.clone(),
            self.bundle_signer.clone(),
        ));
        let reserve_cache = Arc::new(ReserveCache::new(self.http_provider.clone()));
        if Path::new("data/pairs.json").exists() {
            if let Err(e) = reserve_cache
                .load_pairs_from_file_validated("data/pairs.json", &self.http_provider)
                .await
            {
                tracing::warn!(target: "reserves", error=%e, "Failed to preload pairs.json");
            }
        }

        let mut aave_pool = self.aave_pool;
        // Address registry: validate and apply optional protocol addresses.
        if let Ok(registry) = AddressRegistry::load_from_file(&self.address_registry_path) {
            if let Some(chain_reg) = registry.chain(self.chain_id) {
                let chain_reg = chain_reg.validate_with_provider(&self.http_provider).await;
                for addr in chain_reg.routers.values().copied() {
                    self.router_allowlist.insert(addr);
                }
                if let Some(vault) = chain_reg.balancer_vault {
                    reserve_cache.set_balancer_vault(vault).await;
                }
                for addr in chain_reg.curve_registries {
                    reserve_cache.add_curve_registry(addr);
                }
                for addr in chain_reg.curve_meta_registries {
                    reserve_cache.add_curve_meta_registry(addr);
                }
                for addr in chain_reg.curve_crypto_registries {
                    reserve_cache.add_curve_crypto_registry(addr);
                }
                if let Some(aave_pool_reg) = chain_reg.aave_pool {
                    if aave_pool.is_none() {
                        tracing::info!(
                            target: "registry",
                            chain_id = self.chain_id,
                            pool = %format!("{:#x}", aave_pool_reg),
                            "Using Aave pool from registry"
                        );
                        aave_pool = Some(aave_pool_reg);
                    }
                }
            }
        } else {
            tracing::warn!(
                target: "registry",
                path = %self.address_registry_path,
                "Address registry not loaded; proceeding with defaults"
            );
        }

        if let Some(vault) = default_balancer_vault_for_chain(self.chain_id) {
            reserve_cache.set_balancer_vault(vault).await;
        }

        if let Some(pool) = aave_pool {
            match self.http_provider.get_code_at(pool).await {
                Ok(code) => {
                    if code.is_empty() {
                        tracing::warn!(
                            target: "registry",
                            pool = %format!("{:#x}", pool),
                            "Aave pool has no code; disabling"
                        );
                        aave_pool = None;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "registry",
                        pool = %format!("{:#x}", pool),
                        error = %e,
                        "Failed to validate Aave pool; disabling"
                    );
                    aave_pool = None;
                }
            }
        }

        // Validate router allowlist against on-chain code.
        let mut invalid_routers = Vec::new();
        for addr in self.router_allowlist.iter() {
            match self.http_provider.get_code_at(*addr).await {
                Ok(code) => {
                    if code.is_empty() {
                        invalid_routers.push(*addr);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "router",
                        address = %format!("{:#x}", *addr),
                        error = %e,
                        "Failed to validate router; dropping"
                    );
                    invalid_routers.push(*addr);
                }
            }
        }
        for addr in invalid_routers.iter() {
            self.router_allowlist.remove(addr);
        }
        if !invalid_routers.is_empty() {
            tracing::warn!(
                target: "router",
                count = invalid_routers.len(),
                "Dropped routers with missing code"
            );
        }
        {
            let cache = reserve_cache.clone();
            let ws_for_cache = self.ws_provider.clone();
            tokio::spawn(async move {
                cache.run_v2_log_listener(ws_for_cache).await;
            });
        }
        let _metrics_addr = crate::common::metrics::spawn_metrics_server(
            self.metrics_port,
            stats.clone(),
            self.portfolio.clone(),
        )
        .await;
        if self.strategy_enabled {
            // Validate tokenlist addresses for this chain before strategy uses them.
            let invalid = self
                .token_manager
                .validate_chain_addresses(&self.http_provider, self.chain_id)
                .await;
            if invalid > 0 {
                tracing::warn!(
                    target: "token_manager",
                    chain_id = self.chain_id,
                    invalid,
                    "Tokenlist contains addresses without code; filtered"
                );
            }

            let strategy = StrategyExecutor::new(
                tx_receiver,
                block_receiver,
                self.safety_guard.clone(),
                bundle_sender.clone(),
                self.db.clone(),
                self.portfolio.clone(),
                self.gas_oracle.clone(),
                self.price_feed,
                self.chain_id,
                self.max_gas_price_gwei,
                self.gas_cap_multiplier_bps,
                self.simulator,
                self.token_manager.clone(),
                stats.clone(),
                self.wallet_signer.clone(),
                self.nonce_manager.clone(),
                self.slippage_bps,
                self.http_provider.clone(),
                self.dry_run,
                self.router_allowlist.clone(),
                self.router_discovery.clone(),
                self.skip_log_every,
                self.wrapped_native,
                self.allow_non_wrapped_swaps,
                self.executor,
                self.executor_bribe_bps,
                self.executor_bribe_recipient,
                self.flashloan_enabled,
                self.flashloan_providers.clone(),
                aave_pool,
                reserve_cache.clone(),
                self.sandwich_attacks_enabled,
                self.simulation_backend.clone(),
                self.worker_limit,
            );

            if self.mev_share_enabled {
                let mev_share = MevShareClient::new(
                    self.mev_share_stream_url.clone(),
                    self.chain_id,
                    tx_sender.clone(),
                    stats.clone(),
                    INGEST_QUEUE_BOUND,
                    self.mev_share_history_limit,
                );
                tokio::try_join!(
                    mempool.run(),
                    block_listener.run(),
                    strategy.run(),
                    mev_share.run()
                )
                .map(|_| ())
                .map_err(|e| AppError::Unknown(e.into()))
            } else {
                tokio::try_join!(mempool.run(), block_listener.run(), strategy.run())
                    .map(|_| ())
                    .map_err(|e| AppError::Unknown(e.into()))
            }
        } else {
            tokio::try_join!(mempool.run(), block_listener.run())
                .map(|_| ())
                .map_err(|e| AppError::Unknown(e.into()))
        }
    }
}
