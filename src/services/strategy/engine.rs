// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use crate::core::block_listener::BlockListener;
use crate::core::executor::{BundleSender, SharedBundleSender};
use crate::core::mempool::MempoolScanner;
use crate::core::nonce::NonceManager;
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::Simulator;
use crate::core::strategy::{StrategyExecutor, StrategyStats};
use crate::data::db::Database;
use crate::infrastructure::data::token_manager::TokenManager;
use crate::network::gas::GasOracle;
use crate::network::mev_share::MevShareClient;
use crate::network::price_feed::PriceFeed;
use crate::network::provider::{HttpProvider, WsProvider};
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

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
    bundle_signer: PrivateKeySigner,
    executor: Option<Address>,
    executor_bribe_bps: u64,
    executor_bribe_recipient: Option<Address>,
    flashloan_enabled: bool,
    max_gas_price_gwei: u64,
    simulator: Simulator,
    token_manager: Arc<TokenManager>,
    metrics_port: u16,
    strategy_enabled: bool,
    slippage_bps: u64,
    router_allowlist: HashSet<Address>,
    wrapped_native: Address,
    mev_share_stream_url: String,
    mev_share_history_limit: u32,
    mev_share_enabled: bool,
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
        bundle_signer: PrivateKeySigner,
        executor: Option<Address>,
        executor_bribe_bps: u64,
        executor_bribe_recipient: Option<Address>,
        flashloan_enabled: bool,
        max_gas_price_gwei: u64,
        simulator: Simulator,
        token_manager: Arc<TokenManager>,
        metrics_port: u16,
        strategy_enabled: bool,
        slippage_bps: u64,
        router_allowlist: HashSet<Address>,
        wrapped_native: Address,
        mev_share_stream_url: String,
        mev_share_history_limit: u32,
        mev_share_enabled: bool,
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
            bundle_signer,
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            max_gas_price_gwei,
            simulator,
            token_manager,
            metrics_port,
            strategy_enabled,
            slippage_bps,
            router_allowlist,
            wrapped_native,
            mev_share_stream_url,
            mev_share_history_limit,
            mev_share_enabled,
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        let (tx_sender, tx_receiver) = mpsc::unbounded_channel();
        let (block_sender, block_receiver) = broadcast::channel(32);

        let mempool = MempoolScanner::new(self.ws_provider.clone(), tx_sender.clone());
        let block_listener = BlockListener::new(
            self.ws_provider.clone(),
            block_sender.clone(),
            self.nonce_manager.clone(),
        );
        let bundle_sender: SharedBundleSender = Arc::new(BundleSender::new(
            self.http_provider.clone(),
            self.dry_run,
            self.relay_url.clone(),
            self.bundle_signer.clone(),
        ));
        let stats = Arc::new(StrategyStats::default());
        let _metrics_addr = crate::common::metrics::spawn_metrics_server(
            self.metrics_port,
            stats.clone(),
            self.portfolio.clone(),
        )
        .await;
        if self.strategy_enabled {
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
                self.simulator,
                self.token_manager.clone(),
                stats,
                self.bundle_signer.clone(),
                self.nonce_manager.clone(),
                self.slippage_bps,
                self.http_provider.clone(),
                self.dry_run,
                self.router_allowlist.clone(),
                self.wrapped_native,
                self.executor,
                self.executor_bribe_bps,
                self.executor_bribe_recipient,
                self.flashloan_enabled,
            );

            if self.mev_share_enabled {
                let mev_share = MevShareClient::new(
                    self.mev_share_stream_url.clone(),
                    self.chain_id,
                    tx_sender.clone(),
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
