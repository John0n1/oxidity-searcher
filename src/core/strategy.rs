// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::constants::{
    CHAIN_ARBITRUM, CHAIN_ETHEREUM, CHAIN_OPTIMISM, CHAIN_POLYGON, MIN_PROFIT_THRESHOLD_WEI,
};
use crate::common::error::AppError;
use crate::core::executor::{BundleItem, SharedBundleSender};
use crate::core::nonce::NonceManager;
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::Simulator;
use crate::data::db::Database;
use crate::network::gas::{GasFees, GasOracle};
use crate::network::price_feed::PriceFeed;
use crate::network::provider::HttpProvider;
use crate::network::mev_share::MevShareHint;
use alloy::consensus::{SignableTransaction, Transaction as ConsensusTxTrait, TxEip1559};
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{TransactionResponse, TxSignerSync};
use alloy::primitives::{address, Address, Bytes, TxKind, B256, U256, I256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::state::StateOverridesBuilder;
use alloy::rpc::types::eth::Transaction;
use alloy::rpc::types::eth::TransactionInput;
use alloy::rpc::types::eth::TransactionRequest;
use alloy::rpc::types::Header;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy_consensus::TxEnvelope;
use dashmap::DashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::HashSet;
use tokio::sync::{broadcast::Receiver, mpsc::UnboundedReceiver};
use crate::common::retry::retry_async;
use std::time::Duration;
use std::time::Instant;
use std::ops::Neg;

#[derive(Debug)]
pub enum StrategyWork {
    Mempool(Transaction),
    MevShareHint(MevShareHint),
}

const VICTIM_FEE_BUMP_BPS: u64 = 11_000;
const TAX_TOLERANCE_BPS: u64 = 500;
const PROBE_GAS_LIMIT: u64 = 220_000;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV2Router {
        function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) payable returns (uint256[] memory amounts);
        function swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV3Router {
        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }
        struct ExactInputParams {
            bytes path;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
        }
        function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
        function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV3Quoter {
        function quoteExactInputSingle(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint160 sqrtPriceLimitX96) external returns (uint256 amountOut);
        function quoteExactInput(bytes path, uint256 amountIn) external returns (uint256 amountOut);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract ERC20 {
        function balanceOf(address) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

use UniV2Router::{swapExactETHForTokensCall, swapExactTokensForETHCall, swapExactTokensForTokensCall};

#[derive(Default)]
pub struct StrategyStats {
    pub processed: AtomicU64,
    pub submitted: AtomicU64,
    pub skipped: AtomicU64,
    pub failed: AtomicU64,
    pub skip_unknown_router: AtomicU64,
    pub skip_decode_failed: AtomicU64,
    pub skip_missing_wrapped: AtomicU64,
    pub skip_gas_cap: AtomicU64,
    pub skip_sim_failed: AtomicU64,
    pub skip_profit_guard: AtomicU64,
    pub skip_unsupported_router: AtomicU64,
    pub skip_token_call: AtomicU64,
    pub skip_toxic_token: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouterKind {
    V2Like,
    V3Like,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwapDirection {
    BuyWithEth,
    SellForEth,
    Other,
}

pub struct StrategyExecutor {
    tx_rx: UnboundedReceiver<StrategyWork>,
    mut_block_rx: Receiver<Header>,
    safety_guard: Arc<SafetyGuard>,
    bundle_sender: SharedBundleSender,
    db: Database,
    portfolio: Arc<PortfolioManager>,
    gas_oracle: GasOracle,
    price_feed: PriceFeed,
    chain_id: u64,
    stats: Arc<StrategyStats>,
    max_gas_price_gwei: u64,
    simulator: Simulator,
    signer: PrivateKeySigner,
    nonce_manager: NonceManager,
    slippage_bps: u64,
    http_provider: HttpProvider,
    dry_run: bool,
    router_allowlist: HashSet<Address>,
    wrapped_native: Address,
    inventory_tokens: DashSet<Address>,
    last_rebalance: Mutex<Instant>,
    toxic_tokens: DashSet<Address>,
}

#[derive(Clone, Debug)]
struct ObservedSwap {
    router: Address,
    path: Vec<Address>,
    v3_fees: Vec<u32>,
    v3_path: Option<Vec<u8>>,
    amount_in: U256,
    min_out: U256,
    recipient: Address,
    router_kind: RouterKind,
}

#[derive(Clone, Debug)]
struct ParsedV3Path {
    tokens: Vec<Address>,
    fees: Vec<u32>,
}

struct BackrunTx {
    raw: Vec<u8>,
    hash: B256,
    to: Address,
    value: U256,
    request: TransactionRequest,
    expected_out: U256,
}

struct FrontRunTx {
    raw: Vec<u8>,
    hash: B256,
    to: Address,
    value: U256,
    request: TransactionRequest,
    expected_tokens: U256,
}

struct ApproveTx {
    raw: Vec<u8>,
    request: TransactionRequest,
}

impl StrategyExecutor {
    fn price_ratio_ppm(amount_out: U256, amount_in: U256) -> U256 {
        if amount_in.is_zero() {
            return U256::ZERO;
        }
        amount_out.saturating_mul(U256::from(1_000_000u64)) / amount_in
    }

    fn log_skip(&self, reason: &str, detail: &str) {
        if self.dry_run {
            tracing::info!(target: "strategy_skip", %reason, %detail, "Dry-run skip");
        } else {
            tracing::debug!(target: "strategy_skip", %reason, %detail);
        }

        match reason {
            "unknown_router" => { self.stats.skip_unknown_router.fetch_add(1, Ordering::Relaxed); }
            "decode_failed" => { self.stats.skip_decode_failed.fetch_add(1, Ordering::Relaxed); }
            "zero_amount_or_no_wrapped_native" => { self.stats.skip_missing_wrapped.fetch_add(1, Ordering::Relaxed); }
            "gas_price_cap" => { self.stats.skip_gas_cap.fetch_add(1, Ordering::Relaxed); }
            "simulation_failed" => { self.stats.skip_sim_failed.fetch_add(1, Ordering::Relaxed); }
            "profit_or_gas_guard" => { self.stats.skip_profit_guard.fetch_add(1, Ordering::Relaxed); }
            "unsupported_router_type" => { self.stats.skip_unsupported_router.fetch_add(1, Ordering::Relaxed); }
            "token_call" => { self.stats.skip_token_call.fetch_add(1, Ordering::Relaxed); }
            "toxic_token" => { self.stats.skip_toxic_token.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn new(
        tx_rx: UnboundedReceiver<StrategyWork>,
        block_rx: Receiver<Header>,
        safety_guard: Arc<SafetyGuard>,
        bundle_sender: SharedBundleSender,
        db: Database,
        portfolio: Arc<PortfolioManager>,
        gas_oracle: GasOracle,
        price_feed: PriceFeed,
        chain_id: u64,
        max_gas_price_gwei: u64,
        simulator: Simulator,
        stats: Arc<StrategyStats>,
        signer: PrivateKeySigner,
        nonce_manager: NonceManager,
        slippage_bps: u64,
        http_provider: HttpProvider,
        dry_run: bool,
        router_allowlist: HashSet<Address>,
        wrapped_native: Address,
    ) -> Self {
        Self {
            tx_rx,
            mut_block_rx: block_rx,
            safety_guard,
            bundle_sender,
            db,
            portfolio,
            gas_oracle,
            price_feed,
            chain_id,
            stats,
            max_gas_price_gwei,
            simulator,
            signer,
            nonce_manager,
            slippage_bps,
            http_provider,
            dry_run,
            router_allowlist,
            wrapped_native,
            inventory_tokens: DashSet::new(),
            last_rebalance: Mutex::new(Instant::now()),
            toxic_tokens: DashSet::new(),
        }
    }

    pub async fn run(mut self) -> Result<(), AppError> {
        tracing::info!("StrategyExecutor: waiting for pending transactions");
        while let Some(work) = self.tx_rx.recv().await {
            while let Ok(header) = self.mut_block_rx.try_recv() {
                tracing::debug!("StrategyExecutor: observed new block {:?}", header.hash);
                let _ = self.maybe_rebalance_inventory().await;
            }

            self.safety_guard.check()?;

            let outcome = match work {
                StrategyWork::Mempool(tx) => {
                    let from = tx.from();
                    let res = self.evaluate_mempool_tx(&tx).await;
                    (res, Some(from), Some(tx.tx_hash()))
                }
                StrategyWork::MevShareHint(hint) => {
                    let res = self.evaluate_mev_share_hint(&hint).await;
                    (res, hint.from, Some(hint.tx_hash))
                }
            };

            match outcome {
                (Ok(Some(tx_hash)), from, _) => {
                    tracing::info!(
                        target: "strategy",
                        from = ?from,
                        tx_hash = %tx_hash,
                        "Bundle submitted"
                    );
                    self.safety_guard.report_success();
                    self.stats.submitted.fetch_add(1, Ordering::Relaxed);
                }
                (Ok(None), from, tx_hash) => {
                    tracing::debug!(
                        target: "strategy",
                        from=?from,
                        tx_hash=?tx_hash,
                        "Skipped item"
                    );
                    self.stats.skipped.fetch_add(1, Ordering::Relaxed);
                }
                (Err(e), _, _) => {
                    self.safety_guard.report_failure();
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(target: "strategy", error=%e, "Strategy failed");
                }
            };

            let processed = self.stats.processed.fetch_add(1, Ordering::Relaxed) + 1;
            if processed % 50 == 0 {
                tracing::info!(
                    target: "strategy_summary",
                    processed,
                    submitted = self.stats.submitted.load(Ordering::Relaxed),
                    skipped = self.stats.skipped.load(Ordering::Relaxed),
                    failed = self.stats.failed.load(Ordering::Relaxed),
                    skip_unknown_router = self.stats.skip_unknown_router.load(Ordering::Relaxed),
                    skip_decode = self.stats.skip_decode_failed.load(Ordering::Relaxed),
                    skip_missing_wrapped = self.stats.skip_missing_wrapped.load(Ordering::Relaxed),
                    skip_gas_cap = self.stats.skip_gas_cap.load(Ordering::Relaxed),
                    skip_sim_failed = self.stats.skip_sim_failed.load(Ordering::Relaxed),
                    skip_profit_guard = self.stats.skip_profit_guard.load(Ordering::Relaxed),
                    skip_unsupported_router = self.stats.skip_unsupported_router.load(Ordering::Relaxed),
                    skip_token_call = self.stats.skip_token_call.load(Ordering::Relaxed),
                    "Strategy loop summary"
                );
            }
        }

        Ok(())
    }

    async fn evaluate_mempool_tx(&self, tx: &Transaction) -> Result<Option<String>, AppError> {
        let to_addr = match tx.kind() {
            TxKind::Call(addr) => addr,
            TxKind::Create => return Ok(None),
        };

        if !self.router_allowlist.contains(&to_addr) {
            if Self::is_common_token_call(tx.input()) {
                self.log_skip("token_call", "erc20 transfer/approve");
                return Ok(None);
            }
            self.log_skip("unknown_router", &format!("to={to_addr:#x}"));
            return Ok(None);
        }

        let Some(observed_swap) = Self::decode_swap(tx) else {
            self.log_skip("decode_failed", "unable to decode swap input");
            return Ok(None);
        };
        if observed_swap.amount_in.is_zero() || !observed_swap.path.contains(&self.wrapped_native) {
            self.log_skip(
                "zero_amount_or_no_wrapped_native",
                "path missing wrapped native or zero amount",
            );
            return Ok(None);
        }
        let direction = Self::direction(&observed_swap, self.wrapped_native);
        let target_token = match Self::target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip("decode_failed", "no target token");
                return Ok(None);
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip("toxic_token", &format!("token={:#x}", target_token));
            return Ok(None);
        }
        self.inventory_tokens.insert(target_token);
        let tx_value = tx.value();

        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(&mut gas_fees, None, None);
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            self.log_skip(
                "gas_price_cap",
                &format!(
                    "max_fee_per_gas={} cap_gwei={}",
                    gas_fees.max_fee_per_gas, self.max_gas_price_gwei
                ),
            );
            return Ok(None);
        }

        let real_balance = self
            .portfolio
            .update_eth_balance(self.chain_id)
            .await?;
        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom =
                U256::from(tx.gas_limit()) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = tx.value().saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };
        let base_gas_budget = U256::from(tx.gas_limit()) * U256::from(gas_fees.max_fee_per_gas);
        if !self.dry_run {
            self.portfolio
                .ensure_funding(self.chain_id, base_gas_budget)?;
        }

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let mut raw_bundle: Vec<Vec<u8>> = Vec::new();

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth {
            let nonce_front = self.nonce_manager.get_next_nonce().await?;
            match self
                .build_front_run_tx(
                    &observed_swap,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    wallet_chain_balance,
                    tx.gas_limit(),
                    nonce_front,
                )
                .await
            {
                Ok(Some(f)) => {
                    attack_value_eth = f.value;
                    bundle_requests.push(f.request.clone());
                    raw_bundle.push(f.raw.clone());
                    front_run = Some(f);
                }
                Ok(None) => {}
                Err(e) => {
                    self.log_skip("front_run_build_failed", &e.to_string());
                    return Ok(None);
                }
            }
        }

        if let Some(f) = &front_run {
            if self
                .needs_approval(target_token, observed_swap.router, f.expected_tokens)
                .await?
            {
                let needed_nonce = self.nonce_manager.get_next_nonce().await?;
                approval = Some(
                    self.build_approval_tx(
                        target_token,
                        observed_swap.router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        needed_nonce,
                    )
                    .await?,
                );
            }
        }

        let nonce_backrun = self.nonce_manager.get_next_nonce().await?;

        let backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                wallet_chain_balance,
                tx.gas_limit(),
                front_run.as_ref().map(|f| f.expected_tokens),
                nonce_backrun,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };
        let backrun_raw = backrun.raw.clone();
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), wallet_chain_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        if let Some(app) = &approval {
            bundle_requests.push(app.request.clone());
        }
        bundle_requests.push(tx.clone().into_request());
        bundle_requests.push(backrun.request.clone());

        if let Some(app) = &approval {
            raw_bundle.push(app.raw.clone());
        }
        raw_bundle.push(tx.inner.encoded_2718());
        raw_bundle.push(backrun_raw.clone());
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let reqs = bundle_requests.clone();
                let overrides = overrides.clone();
                async move { simulator.simulate_bundle_requests(&reqs, Some(overrides)).await }
            },
            2,
            Duration::from_millis(100),
        )
        .await?;
        if bundle_sims.iter().any(|o| !o.success) {
            self.log_skip("simulation_failed", "bundle sim returned failure");
            return Ok(None);
        }

        let mut gas_used_total = 0u64;
        for sim in &bundle_sims {
            gas_used_total = gas_used_total.saturating_add(sim.gas_used);
        }
        let bundle_gas_limit = gas_used_total.max(tx.gas_limit());
        let gas_cost_wei =
            U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        if !self.dry_run {
            let spend = backrun.value.saturating_add(attack_value_eth);
            self.portfolio
                .ensure_funding(self.chain_id, spend + gas_cost_wei)?;
        }

        let total_eth_in = backrun.value.saturating_add(attack_value_eth);
        let gross_profit_wei = backrun.expected_out.saturating_sub(total_eth_in);

        // --- PROFIT CHECK (U256 Safe) ---
        if gas_cost_wei > gross_profit_wei {
            self.log_skip("profit_or_gas_guard", "Gas > Gross Profit");
            return Ok(None);
        }

        let net_profit_wei = gross_profit_wei.saturating_sub(gas_cost_wei);
        let profit_floor = StrategyExecutor::dynamic_profit_floor(wallet_chain_balance);
        
        if net_profit_wei < profit_floor {
            self.log_skip("profit_or_gas_guard", &format!("Net {} < Floor {}", net_profit_wei, profit_floor));
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        // --- Logging/Persistence (Safe to use f64 here for display) ---
        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = wei_to_eth_f64(gross_profit_wei);
        let gas_cost_eth_f64 = wei_to_eth_f64(gas_cost_wei);
        let net_profit_eth_f64 = wei_to_eth_f64(net_profit_wei);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_wei = %gas_cost_wei,
            net_profit_wei = %net_profit_wei,
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = wei_to_eth_f64(wallet_chain_balance),
            price_source = %eth_quote.source,
            price = eth_quote.price,
            victim_min_out = ?observed_swap.min_out,
            victim_recipient = ?observed_swap.recipient,
            path_len = observed_swap.path.len(),
            path = ?observed_swap.path,
            router = ?observed_swap.router,
            used_mock_balance = self.dry_run,
            sandwich = front_run.is_some(),
            "Strategy evaluation"
        );

        let tx_hash = tx.tx_hash();

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %format!("{:#x}", tx_hash),
                net_profit_eth = net_profit_eth_f64,
                gross_profit_eth = profit_eth_f64,
                gas_cost_eth = gas_cost_eth_f64,
                front_run_value_eth = wei_to_eth_f64(attack_value_eth),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable bundle (not sent)"
            );
            return Ok(Some(format!("{tx_hash:#x}")));
        }

        let _ = self
            .db
            .update_status(&format!("{:#x}", backrun.hash), None, Some(false))
            .await;

        self.bundle_sender
            .send_bundle(&raw_bundle, self.chain_id)
            .await?;

        let to_addr = match tx.kind() {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };

        self.db
            .save_transaction(
                &format!("{tx_hash:#x}"),
                self.chain_id,
                &format!("{:#x}", tx.from()),
                to_addr.as_ref().map(|a| format!("{:#x}", a)).as_deref(),
                tx_value.to_string().as_str(),
                Some("strategy_v1"),
            )
            .await?;

        self.db
            .save_transaction(
                &format!("{:#x}", backrun.hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                Some(format!("{:#x}", backrun.to)).as_deref(),
                backrun.value.to_string().as_str(),
                Some("strategy_backrun"),
            )
            .await?;
        if let Some(f) = &front_run {
            self.db
                .save_transaction(
                    &format!("{:#x}", f.hash),
                    self.chain_id,
                    &format!("{:#x}", self.signer.address()),
                    Some(format!("{:#x}", f.to)).as_deref(),
                    f.value.to_string().as_str(),
                    Some("strategy_front_run"),
                )
                .await?;
        }

        self.db
            .save_profit_record(
                &format!("{tx_hash:#x}"),
                self.chain_id,
                "strategy_v1",
                profit_eth_f64,
                gas_cost_eth_f64,
                net_profit_eth_f64,
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, gross_profit_wei, gas_cost_wei);

        let _ = self
            .db
            .save_market_price(self.chain_id, "ETHUSD", eth_quote.price, &eth_quote.source)
            .await;

        let _ = self.await_receipt(&backrun.hash).await;

        Ok(Some(format!("{tx_hash:#x}")))
    }

    async fn evaluate_mev_share_hint(
        &self,
        hint: &MevShareHint,
    ) -> Result<Option<String>, AppError> {
        if !self.router_allowlist.contains(&hint.router) {
            self.log_skip("unknown_router", &format!("to={:#x}", hint.router));
            return Ok(None);
        }

        let Some(observed_swap) =
            Self::decode_swap_input(hint.router, &hint.call_data, hint.value)
        else {
            self.log_skip("decode_failed", "unable to decode swap input");
            return Ok(None);
        };

        if observed_swap.router_kind == RouterKind::V3Like {
            self.log_skip(
                "unsupported_router_type",
                "uniswap_v3 not yet implemented for backrun",
            );
            return Ok(None);
        }

        if observed_swap.amount_in.is_zero() || !observed_swap.path.contains(&self.wrapped_native) {
            self.log_skip(
                "zero_amount_or_no_wrapped_native",
                "path missing wrapped native or zero amount",
            );
            return Ok(None);
        }

        let direction = Self::direction(&observed_swap, self.wrapped_native);
        let target_token = match Self::target_token(&observed_swap.path, self.wrapped_native) {
            Some(t) => t,
            None => {
                self.log_skip("decode_failed", "no target token");
                return Ok(None);
            }
        };
        if self.toxic_tokens.contains(&target_token) {
            self.log_skip("toxic_token", &format!("token={:#x}", target_token));
            return Ok(None);
        }
        self.inventory_tokens.insert(target_token);
        let gas_limit_hint = hint.gas_limit.unwrap_or(220_000);

        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(
            &mut gas_fees,
            hint.max_fee_per_gas,
            hint.max_priority_fee_per_gas,
        );
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            self.log_skip(
                "gas_price_cap",
                &format!(
                    "max_fee_per_gas={} cap_gwei={}",
                    gas_fees.max_fee_per_gas, self.max_gas_price_gwei
                ),
            );
            return Ok(None);
        }

        let real_balance = self.portfolio.update_eth_balance(self.chain_id).await?;
        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom =
                U256::from(gas_limit_hint) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = hint.value.saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };
        let base_gas_budget = U256::from(gas_limit_hint) * U256::from(gas_fees.max_fee_per_gas);
        if !self.dry_run {
            self.portfolio
                .ensure_funding(self.chain_id, base_gas_budget)?;
        }

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let mut bundle_body: Vec<BundleItem> = Vec::new();

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth {
            let nonce_front = self.nonce_manager.get_next_nonce().await?;
            match self
                .build_front_run_tx(
                    &observed_swap,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    wallet_chain_balance,
                    gas_limit_hint,
                    nonce_front,
                )
                .await
            {
                Ok(Some(f)) => {
                    attack_value_eth = f.value;
                    bundle_requests.push(f.request.clone());
                    front_run = Some(f);
                }
                Ok(None) => {}
                Err(e) => {
                    self.log_skip("front_run_build_failed", &e.to_string());
                    return Ok(None);
                }
            }
        }

        if let Some(f) = &front_run {
            if self
                .needs_approval(target_token, observed_swap.router, f.expected_tokens)
                .await?
            {
                let needed_nonce = self.nonce_manager.get_next_nonce().await?;
                approval = Some(
                    self.build_approval_tx(
                        target_token,
                        observed_swap.router,
                        gas_fees.max_fee_per_gas,
                        gas_fees.max_priority_fee_per_gas,
                        needed_nonce,
                    )
                    .await?,
                );
            }
        }

        let nonce_backrun = self.nonce_manager.get_next_nonce().await?;
        let backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                wallet_chain_balance,
                gas_limit_hint,
                front_run.as_ref().map(|f| f.expected_tokens),
                nonce_backrun,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };
        let backrun_raw = backrun.raw.clone();
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), wallet_chain_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        let max_fee_hint = hint
            .max_fee_per_gas
            .unwrap_or(gas_fees.max_fee_per_gas);
        let max_prio_hint = hint
            .max_priority_fee_per_gas
            .unwrap_or(gas_fees.max_priority_fee_per_gas);
        let victim_request = TransactionRequest {
            from: hint.from,
            to: Some(TxKind::Call(hint.router)),
            max_fee_per_gas: Some(max_fee_hint),
            max_priority_fee_per_gas: Some(max_prio_hint),
            gas: Some(gas_limit_hint),
            value: Some(hint.value),
            input: TransactionInput::new(hint.call_data.clone().into()),
            nonce: None,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        if let Some(app) = &approval {
            bundle_requests.push(app.request.clone());
        }
        bundle_requests.push(victim_request);
        bundle_requests.push(backrun.request.clone());
        if let Some(f) = &front_run {
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&f.raw)),
                can_revert: false,
            });
        }
        if let Some(app) = &approval {
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&app.raw)),
                can_revert: false,
            });
        }
        bundle_body.push(BundleItem::Hash {
            hash: format!("{:#x}", hint.tx_hash),
        });
        bundle_body.push(BundleItem::Tx {
            tx: format!("0x{}", hex::encode(&backrun_raw)),
            can_revert: false,
        });

        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let reqs = bundle_requests.clone();
                let overrides = overrides.clone();
                async move { simulator.simulate_bundle_requests(&reqs, Some(overrides)).await }
            },
            2,
            Duration::from_millis(100),
        )
        .await?;
        if bundle_sims.iter().any(|o| !o.success) {
            self.log_skip("simulation_failed", "bundle sim returned failure");
            return Ok(None);
        }

        let mut gas_used_total = 0u64;
        for sim in &bundle_sims {
            gas_used_total = gas_used_total.saturating_add(sim.gas_used);
        }
        let bundle_gas_limit = gas_used_total.max(gas_limit_hint);
        let gas_cost_wei =
            U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        if !self.dry_run {
            let spend = backrun.value.saturating_add(attack_value_eth);
            self.portfolio
                .ensure_funding(self.chain_id, spend + gas_cost_wei)?;
        }

        let total_eth_in = backrun.value.saturating_add(attack_value_eth);
        let gross_profit_wei = backrun.expected_out.saturating_sub(total_eth_in);

        // --- PROFIT CHECK (MEV Share - U256 Safe) ---
        if gas_cost_wei > gross_profit_wei {
            self.log_skip("profit_or_gas_guard", "Gas > Gross Profit");
            return Ok(None);
        }

        let net_profit_wei = gross_profit_wei.saturating_sub(gas_cost_wei);
        let profit_floor = StrategyExecutor::dynamic_profit_floor(wallet_chain_balance);

        if net_profit_wei < profit_floor {
            self.log_skip("profit_or_gas_guard", &format!("Net {} < Floor {}", net_profit_wei, profit_floor));
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = wei_to_eth_f64(gross_profit_wei);
        let gas_cost_eth_f64 = wei_to_eth_f64(gas_cost_wei);
        let net_profit_eth_f64 = wei_to_eth_f64(net_profit_wei);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_eth = gas_cost_eth_f64,
            backrun_value_eth = wei_to_eth_f64(backrun.value),
            expected_out_eth = wei_to_eth_f64(backrun.expected_out),
            front_run_value_eth = wei_to_eth_f64(attack_value_eth),
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = wei_to_eth_f64(wallet_chain_balance),
            price_source = %eth_quote.source,
            price = eth_quote.price,
            victim_min_out = ?observed_swap.min_out,
            victim_recipient = ?observed_swap.recipient,
            path_len = observed_swap.path.len(),
            path = ?observed_swap.path,
            router = ?observed_swap.router,
            used_mock_balance = self.dry_run,
            profit_floor_wei = %profit_floor,
            sandwich = front_run.is_some(),
            "MEV-Share strategy evaluation"
        );

        let tx_hash = format!("{:#x}", hint.tx_hash);

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %tx_hash,
                net_profit_eth = net_profit_eth_f64,
                gross_profit_eth = profit_eth_f64,
                gas_cost_eth = gas_cost_eth_f64,
                front_run_value_eth = wei_to_eth_f64(attack_value_eth),
                wallet_eth = wei_to_eth_f64(wallet_chain_balance),
                path_len = observed_swap.path.len(),
                router = ?observed_swap.router,
                used_mock_balance = self.dry_run,
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable MEV-Share bundle (not sent)"
            );
            return Ok(Some(tx_hash));
        }

        let _ = self
            .db
            .update_status(&tx_hash, None, Some(false))
            .await;

        self.bundle_sender
            .send_mev_share_bundle(&bundle_body)
            .await?;

        let from_addr = hint.from.unwrap_or(Address::ZERO);
        self.db
            .save_transaction(
                &tx_hash,
                self.chain_id,
                &format!("{:#x}", from_addr),
                Some(format!("{:#x}", hint.router)).as_deref(),
                hint.value.to_string().as_str(),
                Some("strategy_mev_share"),
            )
            .await?;

        self.db
            .save_transaction(
                &format!("{:#x}", backrun.hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                Some(format!("{:#x}", backrun.to)).as_deref(),
                backrun.value.to_string().as_str(),
                Some("strategy_backrun"),
            )
            .await?;
        if let Some(f) = &front_run {
            self.db
                .save_transaction(
                    &format!("{:#x}", f.hash),
                    self.chain_id,
                    &format!("{:#x}", self.signer.address()),
                    Some(format!("{:#x}", f.to)).as_deref(),
                    f.value.to_string().as_str(),
                    Some("strategy_front_run"),
                )
                .await?;
        }

        self.db
            .save_profit_record(
                &tx_hash,
                self.chain_id,
                "strategy_mev_share",
                profit_eth_f64,
                gas_cost_eth_f64,
                net_profit_eth_f64,
            )
            .await?;

        self.portfolio
            .record_profit(self.chain_id, gross_profit_wei, gas_cost_wei);

        let _ = self
            .db
            .save_market_price(self.chain_id, "ETHUSD", eth_quote.price, &eth_quote.source)
            .await;

        let _ = self.await_receipt(&backrun.hash).await;

        Ok(Some(tx_hash))
    }

    fn dynamic_profit_floor(wallet_balance: U256) -> U256 {
        let abs_floor = *MIN_PROFIT_THRESHOLD_WEI;
        let scaled = wallet_balance
            .checked_div(U256::from(100_000u64))
            .unwrap_or(U256::ZERO);
        if scaled > abs_floor {
            scaled
        } else {
            abs_floor
        }
    }

    fn boost_fees(&self, fees: &mut GasFees, victim_max_fee: Option<u128>, victim_tip: Option<u128>) {
        let base_gwei = fees.base_fee_per_gas / 1_000_000_000u128;
        let mut boost_bps: u64 = if base_gwei > 80 {
            13000 // +30%
        } else if base_gwei > 40 {
            12000 // +20%
        } else {
            11000 // +10%
        };
        
        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        // -0.1 ETH threshold approx in I256
        let neg_threshold = I256::from_raw(U256::from(100_000_000_000_000_000u128)).neg(); 
        
        if pnl < neg_threshold {
             boost_bps = (boost_bps as f64 * 0.8) as u64; 
        } else if pnl.is_positive() {
             boost_bps = (boost_bps as f64 * 1.05) as u64;
        }
        boost_bps = boost_bps.max(10200).min(14500);

        let boost = |val: u128| -> u128 {
            (val.saturating_mul(boost_bps as u128) / 10_000u128).max(val)
        };
        fees.max_fee_per_gas = boost(fees.max_fee_per_gas);
        fees.max_priority_fee_per_gas = boost(fees.max_priority_fee_per_gas);
        
        let one_gwei: u128 = 1_000_000_000;
        let tip_floor = ((fees.base_fee_per_gas / 10).max(2 * one_gwei)).min(30 * one_gwei);
        if fees.max_priority_fee_per_gas < tip_floor {
            fees.max_priority_fee_per_gas = tip_floor;
        }
        let min_fee = fees.base_fee_per_gas.saturating_add(fees.max_priority_fee_per_gas);
        if fees.max_fee_per_gas < min_fee {
            fees.max_fee_per_gas = min_fee;
        }

        if let Some(v_fee) = victim_max_fee {
            let fee_target = v_fee
                .saturating_mul(VICTIM_FEE_BUMP_BPS as u128)
                / 10_000u128;
            fees.max_fee_per_gas = fees.max_fee_per_gas.max(fee_target);
        }
        if let Some(v_tip) = victim_tip {
            let tip_target = v_tip
                .saturating_mul(VICTIM_FEE_BUMP_BPS as u128)
                / 10_000u128;
            fees.max_priority_fee_per_gas = fees.max_priority_fee_per_gas.max(tip_target);
        }
    }

    fn gas_ratio_ok(&self, gas_cost_wei: U256, gross_profit_wei: U256, wallet_balance: U256) -> bool {
        if gross_profit_wei.is_zero() {
            return false;
        }
        let limit = self.dynamic_gas_ratio_limit(wallet_balance);
        gas_cost_wei.saturating_mul(U256::from(10_000u64))
            <= gross_profit_wei.saturating_mul(U256::from(limit))
    }

    fn dynamic_backrun_value(
        observed_in: U256,
        wallet_balance: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        max_fee_per_gas: u128,
    ) -> Result<U256, AppError> {
        let mut value =
            observed_in.saturating_mul(U256::from(slippage_bps)) / U256::from(10_000u64);

        let min_backrun = U256::from(100_000_000_000_000u64);
        if value < min_backrun {
            value = min_backrun;
        }

        let (max_divisor, gas_buffer_divisor) = Self::backrun_divisors(wallet_balance);
        let mut max_value = wallet_balance
            .checked_div(U256::from(max_divisor))
            .unwrap_or(wallet_balance);
        let gas_buffer =
            U256::from(max_fee_per_gas).saturating_mul(U256::from(gas_limit_hint.max(210_000)));
        if gas_buffer > wallet_balance / U256::from(gas_buffer_divisor) {
            max_value = wallet_balance
                .checked_div(U256::from(gas_buffer_divisor))
                .unwrap_or(wallet_balance);
        }
        if value > max_value {
            value = max_value;
        }
        if value.is_zero() {
            return Err(AppError::Strategy(
                "Backrun value is zero after caps".into(),
            ));
        }
        Ok(value)
    }

    fn backrun_divisors(wallet_balance: U256) -> (u64, u64) {
        let thresholds = [
            (U256::from(100_000_000_000_000_000u128), (4u64, 6u64)), // <0.1 ETH
            (U256::from(500_000_000_000_000_000u128), (3u64, 5u64)), // <0.5 ETH
            (U256::from(2_000_000_000_000_000_000u128), (2u64, 4u64)), // <2 ETH
        ];
        for (limit, divisors) in thresholds {
            if wallet_balance < limit {
                return divisors;
            }
        }
        (2, 3) 
    }

    fn dynamic_gas_ratio_limit(&self, wallet_balance: U256) -> u64 {
        let pnl = self.portfolio.get_net_profit_i256(self.chain_id);
        let base = if wallet_balance < U256::from(100_000_000_000_000_000u128) {
            5000 
        } else if wallet_balance < U256::from(500_000_000_000_000_000u128) {
            6500
        } else if wallet_balance < U256::from(2_000_000_000_000_000_000u128) {
            8000
        } else {
            9000
        };

        // Convert U256 PnL thresholds to I256 for comparison
        let neg_0_05 = I256::from_raw(U256::from(50_000_000_000_000_000u128)).neg();
        let pos_0_2 = I256::from_raw(U256::from(200_000_000_000_000_000u128));

        if pnl < neg_0_05 {
            (base * 85 / 100).max(3500) // tighten 15%
        } else if pnl.is_negative() {
            (base * 92 / 100).max(4000) // tighten 8%
        } else if pnl > pos_0_2 {
            (base * 105 / 100).min(9500)
        } else {
            base
        }
    }

    async fn quote_v3_path(&self, path: &[u8], amount_in: U256) -> Result<U256, AppError> {
        let quoter_addr = Self::v3_quoter_for_chain(self.chain_id)
            .ok_or_else(|| AppError::Strategy("No V3 quoter configured for chain".into()))?;
        let quoter = UniV3Quoter::new(quoter_addr, self.http_provider.clone());
        let amount_in_cloned = amount_in;
        let path_vec = path.to_vec();
        let out: U256 = retry_async(
            move |_| {
                let q = quoter.clone();
                let p = path_vec.clone();
                async move { q.quoteExactInput(p.into(), amount_in_cloned).call().await }
            },
            3,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Strategy(format!("V3 path quote failed: {}", e)))?;
        Ok(out)
    }

    fn v3_quoter_for_chain(chain_id: u64) -> Option<Address> {
        match chain_id {
            CHAIN_ETHEREUM => Some(address!("b27308f9F90D607463bb33eA1BeBb41C27CE5AB6")),
            CHAIN_OPTIMISM | CHAIN_ARBITRUM | CHAIN_POLYGON => {
                Some(address!("61fFE014bA17989E743c5F6cB21bF9697530B21e"))
            }
            _ => None,
        }
    }

    fn decode_swap(tx: &Transaction) -> Option<ObservedSwap> {
        let router = match tx.kind() {
            TxKind::Call(addr) => addr,
            TxKind::Create => return None,
        };
        Self::decode_swap_input(router, tx.input(), tx.value())
    }

    fn decode_swap_input(router: Address, input: &[u8], eth_value: U256) -> Option<ObservedSwap> {
        if input.len() < 4 {
            return None;
        }

        if let Ok(decoded) = swapExactETHForTokensCall::abi_decode(input) {
            return Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                amount_in: eth_value,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            });
        }

        if let Ok(decoded) = swapExactTokensForETHCall::abi_decode(input) {
            return Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            });
        }

        if let Ok(decoded) = swapExactTokensForTokensCall::abi_decode(input) {
            return Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            });
        }

        if let Ok(decoded) = UniV3Router::exactInputSingleCall::abi_decode(input) {
            let params = decoded.params;
            let path_bytes = Self::encode_v3_path(&[params.tokenIn, params.tokenOut], &[params.fee.to()]);
            let fee_u32: u32 = params.fee.to::<u32>();
            if !Self::v3_fee_sane(fee_u32) {
                return None;
            }
            if !Self::validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                return None;
            }
            return Some(ObservedSwap {
                router,
                path: vec![params.tokenIn, params.tokenOut],
                v3_fees: vec![fee_u32],
                v3_path: path_bytes,
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            });
        }

        if let Ok(decoded) = UniV3Router::exactInputCall::abi_decode(input) {
            let params = decoded.params;
            if let Some(path) = Self::parse_v3_path(&params.path) {
                if path.fees.iter().any(|f| !Self::v3_fee_sane(*f)) {
                    return None;
                }
                if !Self::validate_v3_tokens(&path.tokens) {
                    return None;
                }
                return Some(ObservedSwap {
                    router,
                    path: path.tokens.clone(),
                    v3_fees: path.fees.clone(),
                    v3_path: Some(params.path.to_vec()),
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            });
            }
        }

        None
    }

    fn target_token(path: &[Address], wrapped_native: Address) -> Option<Address> {
        path.iter().copied().find(|addr| addr != &wrapped_native)
    }

    fn direction(observed: &ObservedSwap, wrapped_native: Address) -> SwapDirection {
        let starts_with_native = observed.path.first().copied() == Some(wrapped_native);
        let ends_with_native = observed.path.last().copied() == Some(wrapped_native);
        if starts_with_native {
            SwapDirection::BuyWithEth
        } else if ends_with_native {
            SwapDirection::SellForEth
        } else {
            SwapDirection::Other
        }
    }

    fn parse_v3_path(path: &[u8]) -> Option<ParsedV3Path> {
        // Expected layout: token (20) + [fee (3) + token (20)]*
        if path.len() < 43 {
            return None;
        }
        if (path.len() - 20) % 23 != 0 {
            return None;
        }
        let mut tokens = Vec::new();
        let mut fees = Vec::new();
        let mut offset = 0;
        tokens.push(Address::from_slice(&path[offset..offset + 20]));
        offset += 20;
        while offset < path.len() {
            if path.len() < offset + 3 + 20 {
                return None;
            }
            let fee_bytes = &path[offset..offset + 3];
            let fee = ((fee_bytes[0] as u32) << 16) | ((fee_bytes[1] as u32) << 8) | fee_bytes[2] as u32;
            fees.push(fee);
            offset += 3; // skip fee
            tokens.push(Address::from_slice(&path[offset..offset + 20]));
            offset += 20;
        }
        Some(ParsedV3Path { tokens, fees })
    }

    fn encode_v3_path(tokens: &[Address], fees: &[u32]) -> Option<Vec<u8>> {
        if tokens.len() < 2 || fees.len() + 1 != tokens.len() {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(tokens.len() * 23);
        out.extend_from_slice(tokens[0].as_slice());
        for (i, fee) in fees.iter().enumerate() {
            out.extend_from_slice(&fee.to_be_bytes()[1..]); // take last 3 bytes
            out.extend_from_slice(tokens[i + 1].as_slice());
        }
        Some(out)
    }

    fn reverse_v3_path(tokens: &[Address], fees: &[u32]) -> Option<Vec<u8>> {
        if tokens.len() < 2 || fees.len() + 1 != tokens.len() {
            return None;
        }
        let rev_tokens: Vec<Address> = tokens.iter().rev().copied().collect();
        let rev_fees: Vec<u32> = fees.iter().rev().copied().collect();
        // When reversing path, token count stays same, fees reversed.
        Self::encode_v3_path(&rev_tokens, &rev_fees)
    }

    fn v3_fee_sane(fee: u32) -> bool {
        matches!(fee, 500 | 3000 | 10_000)
    }

    fn build_access_list(router: Address, tokens: &[Address]) -> AccessList {
        let mut seen = HashSet::new();
        let mut items: Vec<AccessListItem> = Vec::new();
        let push = |addr: Address, seen: &mut HashSet<Address>, items: &mut Vec<AccessListItem>| {
            if seen.insert(addr) {
                items.push(AccessListItem {
                    address: addr,
                    storage_keys: Vec::new(),
                });
            }
        };
        push(router, &mut seen, &mut items);
        for t in tokens {
            push(*t, &mut seen, &mut items);
        }
        AccessList(items)
    }

    fn validate_v3_tokens(tokens: &[Address]) -> bool {
        let max_hops = 4; // up to 4 tokens (3 hops) to bound complexity
        if tokens.len() < 2 || tokens.len() > max_hops {
            return false;
        }
        true
    }

    async fn maybe_rebalance_inventory(&self) -> Result<(), AppError> {
        let mut guard = self
            .last_rebalance
            .lock()
            .map_err(|_| AppError::Strategy("Rebalance lock poisoned".into()))?;
        if guard.elapsed().as_secs() < 60 {
            return Ok(());
        }
        *guard = Instant::now();
        drop(guard);

        let routers: Vec<Address> = self.router_allowlist.iter().copied().collect();
        if routers.is_empty() {
            return Ok(());
        }

        let tokens: Vec<Address> = self.inventory_tokens.iter().map(|t| *t).collect();
        for token in tokens.into_iter().take(2) {
            for router in routers.iter().copied().take(3) {
                if self.rebalance_token(token, router).await.is_ok() {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn rebalance_token(&self, token: Address, router: Address) -> Result<(), AppError> {
        if token == self.wrapped_native {
            return Ok(());
        }
        if self.toxic_tokens.contains(&token) {
            return Ok(());
        }
        // Check balance
        let erc20 = ERC20::new(token, self.http_provider.clone());
        let bal: U256 = retry_async(
            move |_| {
                let c = erc20.clone();
                async move { c.balanceOf(self.signer.address()).call().await }
            },
            2,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Strategy(format!("Inventory balance failed: {}", e)))?;
        if bal.is_zero() {
            return Ok(());
        }

        let mut gas_fees: GasFees = self.gas_oracle.estimate_eip1559_fees().await?;
        self.boost_fees(&mut gas_fees, None, None);
        let gas_cap_wei = U256::from(self.max_gas_price_gwei) * U256::from(1_000_000_000u64);
        if U256::from(gas_fees.max_fee_per_gas) > gas_cap_wei {
            return Ok(());
        }

        // Quote token -> wrapped_native on V2 (liquidity check)
        let router_contract = UniV2Router::new(router, self.http_provider.clone());
        let sell_path = vec![token, self.wrapped_native];
        let quote_path = sell_path.clone();
        let quote_contract = router_contract.clone();
        let sell_amount = bal;
        let quote: Vec<U256> = match retry_async(
            move |_| {
                let c = quote_contract.clone();
                let p = quote_path.clone();
                async move { c.getAmountsOut(sell_amount, p.clone()).call().await }
            },
            2,
            Duration::from_millis(100),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => return Ok(()), // skip silently
        };
        let Some(expected_out) = quote.last().copied() else {
            return Ok(());
        };
        // Quick liquidity sanity: ensure intermediate amount scales roughly linearly
        if quote.len() >= 2 {
            let first_hop = quote[1];
            if first_hop.is_zero() || expected_out.is_zero() {
                return Ok(());
            }
        }
        // Skip tiny balances (<0.01 ETH)
        let min_eth = U256::from(10_000_000_000_000_000u128);
        if expected_out < min_eth {
            return Ok(());
        }
        // Avoid sweeping illiquid tokens where price impact is extreme (expected_out << sell_amount)
        if sell_amount > U256::ZERO {
            let ratio = expected_out.saturating_mul(U256::from(1_000_000u64)) / sell_amount;
            // Require at least 0.1% of notional back (ratio >= 1000 in ppm terms)
            if ratio < U256::from(1_000u64) {
                return Ok(());
            }
        }
        // Probe execution to avoid fee-on-transfer/honeypot tokens
        if !self
            .probe_v2_sell_for_toxicity(token, router, sell_amount, expected_out)
            .await?
        {
            return Ok(());
        }
        let min_out = expected_out
            .saturating_mul(U256::from(10_000u64 - self.slippage_bps))
            / U256::from(10_000u64);
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);

        // Allowance
        if self
            .needs_approval(token, router, sell_amount)
            .await
            .unwrap_or(true)
        {
            let nonce = self.nonce_manager.get_next_nonce().await?;
            let approval = self
                .build_approval_tx(
                    token,
                    router,
                    gas_fees.max_fee_per_gas,
                    gas_fees.max_priority_fee_per_gas,
                    nonce,
                )
                .await?;
            let _ = self
                .bundle_sender
                .send_bundle(&[approval.raw.clone()], self.chain_id)
                .await;
        }

        let nonce_sell = self.nonce_manager.get_next_nonce().await?;
        let gas_limit = 180_000u64;
        let calldata = router_contract
            .swapExactTokensForETH(
                sell_amount,
                min_out,
                sell_path,
                self.signer.address(),
                deadline,
            )
            .calldata()
            .to_vec();
                let mut tx = TxEip1559 {
                    chain_id: self.chain_id,
                    nonce: nonce_sell,
                    max_priority_fee_per_gas: gas_fees.max_priority_fee_per_gas,
                    max_fee_per_gas: gas_fees.max_fee_per_gas,
                    gas_limit,
                    to: TxKind::Call(router),
                    value: U256::ZERO,
                    access_list: Self::build_access_list(router, &[token]),
                    input: calldata.clone().into(),
                };
        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign inventory sell failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();
        let _ = self
            .bundle_sender
            .send_bundle(&[raw], self.chain_id)
            .await;

        Ok(())
    }

    fn mark_toxic_token(&self, token: Address, reason: &str) {
        if self.toxic_tokens.insert(token) {
            tracing::warn!(
                target: "strategy",
                token = %format!("{:#x}", token),
                %reason,
                "Token marked toxic; skipping sweeps"
            );
        }
    }

    async fn probe_v2_sell_for_toxicity(
        &self,
        token: Address,
        router: Address,
        sell_amount: U256,
        expected_out: U256,
    ) -> Result<bool, AppError> {
        if sell_amount.is_zero() || expected_out.is_zero() {
            return Ok(false);
        }
        if self.toxic_tokens.contains(&token) {
            return Ok(false);
        }
        // Build a simulated approval + sell to detect fee-on-transfer / honeypots.
        let approve_calldata = ERC20::new(token, self.http_provider.clone())
            .approve(router, U256::MAX)
            .calldata()
            .to_vec();
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 60);
        let sell_calldata = UniV2Router::new(router, self.http_provider.clone())
            .swapExactTokensForETH(
                sell_amount,
                U256::ZERO, // allow any out for probe
                vec![token, self.wrapped_native],
                self.signer.address(),
                deadline,
            )
            .calldata()
            .to_vec();

        let approve_req = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(token)),
            gas: Some(70_000),
            value: Some(U256::ZERO),
            input: TransactionInput::new(approve_calldata.into()),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let sell_req = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            gas: Some(PROBE_GAS_LIMIT),
            value: Some(U256::ZERO),
            input: TransactionInput::new(sell_calldata.into()),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        let sims = self
            .simulator
            .simulate_bundle_requests(&[approve_req, sell_req], None)
            .await?;
        if sims.len() < 2 {
            tracing::debug!(
                target: "strategy",
                token = %format!("{:#x}", token),
                "Probe simulation missing results; skipping toxicity mark"
            );
            return Ok(true);
        }
        let outcome = &sims[1];
        if !outcome.success {
            self.mark_toxic_token(token, "probe_revert");
            return Ok(false);
        }

        if outcome.return_data.is_empty() {
            return Ok(true);
        }

        match swapExactTokensForETHCall::abi_decode_returns(&outcome.return_data) {
            Ok(amounts) => {
                let Some(actual_out) = amounts.last() else {
                    return Ok(true);
                };
                let tolerance_bps = U256::from(10_000u64 - TAX_TOLERANCE_BPS);
                let ok = actual_out.saturating_mul(U256::from(10_000u64))
                    >= expected_out.saturating_mul(tolerance_bps);
                if !ok {
                    self.mark_toxic_token(token, "probe_output_too_low");
                }
                Ok(ok)
            }
            Err(_) => Ok(true),
        }
    }

    async fn probe_v3_sell_for_toxicity(
        &self,
        router: Address,
        path: Vec<u8>,
        amount_in: U256,
        expected_out: U256,
    ) -> Result<bool, AppError> {
        if amount_in.is_zero() || expected_out.is_zero() {
            return Ok(false);
        }
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 60);
        let calldata = UniV3Router::new(router, self.http_provider.clone())
            .exactInput(UniV3Router::ExactInputParams {
                path: path.clone().into(),
                recipient: self.signer.address(),
                deadline,
                amountIn: amount_in,
                amountOutMinimum: U256::ZERO,
            })
            .calldata()
            .to_vec();
        let req = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            gas: Some(PROBE_GAS_LIMIT.saturating_mul(2)),
            value: Some(U256::ZERO),
            input: TransactionInput::new(Bytes::from(calldata)),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let outcome = self.simulator.simulate_request(req, None).await?;
        if !outcome.success {
            tracing::debug!(target: "strategy", "V3 probe revert; marking toxic");
            return Ok(false);
        }
        if outcome.return_data.is_empty() {
            return Ok(true);
        }
        match UniV3Router::exactInputCall::abi_decode_returns(&outcome.return_data) {
            Ok(amount_out) => {
                let tolerance_bps = U256::from(10_000u64 - TAX_TOLERANCE_BPS);
                let ok = amount_out.saturating_mul(U256::from(10_000u64))
                    >= expected_out.saturating_mul(tolerance_bps);
                Ok(ok)
            }
            Err(_) => Ok(true),
        }
    }

    async fn needs_approval(&self, token: Address, spender: Address, required: U256) -> Result<bool, AppError> {
        let erc20 = ERC20::new(token, self.http_provider.clone());
        let allowance: U256 = retry_async(
            move |_| {
                let c = erc20.clone();
                async move { c.allowance(self.signer.address(), spender).call().await }
            },
            2,
            Duration::from_millis(100),
        )
        .await
        .map_err(|e| AppError::Strategy(format!("Allowance check failed: {}", e)))?;
        Ok(allowance < required)
    }

    async fn build_approval_tx(
        &self,
        token: Address,
        spender: Address,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        nonce: u64,
    ) -> Result<ApproveTx, AppError> {
        let calldata = ERC20::new(token, self.http_provider.clone())
            .approve(spender, U256::MAX)
            .calldata()
            .to_vec();
        let gas_limit = 70_000u64;
        let mut tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: TxKind::Call(token),
            value: U256::ZERO,
            access_list: Self::build_access_list(spender, &[token]),
            input: calldata.clone().into(),
        };
        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign approval failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();
        let request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(token)),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(U256::ZERO),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        Ok(ApproveTx { raw, request })
    }

    fn is_common_token_call(input: &[u8]) -> bool {
        if input.len() < 4 {
            return false;
        }
        let selector = &input[..4];
        const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
        const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
        const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
        const PERMIT: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf]; // EIP-2612
        selector == TRANSFER
            || selector == TRANSFER_FROM
            || selector == APPROVE
            || selector == PERMIT
    }

    async fn build_front_run_tx(
        &self,
        observed: &ObservedSwap,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        wallet_balance: U256,
        gas_limit_hint: u64,
        nonce: u64,
    ) -> Result<Option<FrontRunTx>, AppError> {
        if wallet_balance.is_zero() {
            return Ok(None);
        }
        let target_token = Self::target_token(&observed.path, self.wrapped_native)
            .ok_or_else(|| AppError::Strategy("Unable to derive target token".into()))?;

        let value = StrategyExecutor::dynamic_backrun_value(
            observed.amount_in,
            wallet_balance,
            self.slippage_bps,
            gas_limit_hint,
            max_fee_per_gas,
        )?;

        let (expected_tokens, calldata, value, gas_limit, access_list) = match observed.router_kind {
            RouterKind::V2Like => {
                let router_contract = UniV2Router::new(observed.router, self.http_provider.clone());
                let path = vec![self.wrapped_native, target_token];
                let access_list = Self::build_access_list(observed.router, &path);
                let quote_path = path.clone();
                let quote_contract = router_contract.clone();
                let quote_value = value;
                let quote: Vec<U256> = retry_async(
                    move |_| {
                        let c = quote_contract.clone();
                        let p = quote_path.clone();
                        async move { c.getAmountsOut(quote_value, p.clone()).call().await }
                    },
                    3,
                    Duration::from_millis(100),
                )
                .await
                .map_err(|e| AppError::Strategy(format!("Front-run quote failed: {}", e)))?;
                let expected_tokens = *quote
                    .last()
                    .ok_or_else(|| AppError::Strategy("Front-run quote missing amounts".into()))?;
                let ratio_ppm = Self::price_ratio_ppm(expected_tokens, value);
                if ratio_ppm < U256::from(1_000u64) {
                    return Ok(None); // skip illiquid paths quietly
                }
                let min_out = expected_tokens
                    .saturating_mul(U256::from(10_000u64 - self.slippage_bps))
                    / U256::from(10_000u64);
                let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);
                let calldata = router_contract
                    .swapExactETHForTokens(min_out, path, self.signer.address(), deadline)
                    .calldata()
                    .to_vec();
                let mut gas_limit = gas_limit_hint
                    .saturating_mul(11)
                    .checked_div(10)
                    .unwrap_or(300_000);
                if gas_limit < 160_000 {
                    gas_limit = 160_000;
                }
                (expected_tokens, calldata, value, gas_limit, access_list)
            }
            RouterKind::V3Like => {
                if observed.path.len() < 2 {
                    return Err(AppError::Strategy("V3 path too short".into()));
                }
                let path_bytes = if let Some(p) = observed.v3_path.clone() {
                    p
                } else {
                    Self::encode_v3_path(&observed.path, &observed.v3_fees)
                        .ok_or_else(|| AppError::Strategy("Encode V3 path failed".into()))?
                };
                if observed.path.first().copied() != Some(self.wrapped_native) {
                    return Ok(None);
                }
                let expected_tokens = self.quote_v3_path(&path_bytes, value).await?;
                let ratio_ppm = Self::price_ratio_ppm(expected_tokens, value);
                if ratio_ppm < U256::from(1_000u64) {
                    return Ok(None);
                }
                let min_out = expected_tokens
                    .saturating_mul(U256::from(10_000u64 - self.slippage_bps))
                    / U256::from(10_000u64);
                let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);
                let access_list = Self::build_access_list(observed.router, &observed.path);
                let calldata = UniV3Router::new(observed.router, self.http_provider.clone())
                        .exactInput(UniV3Router::ExactInputParams {
                            path: path_bytes.clone().into(),
                            recipient: self.signer.address(),
                            deadline,
                            amountIn: value,
                            amountOutMinimum: min_out,
                        })
                    .calldata()
                    .to_vec();
                let mut gas_limit = gas_limit_hint
                    .saturating_mul(12)
                    .checked_div(10)
                    .unwrap_or(320_000);
                if gas_limit < 200_000 {
                    gas_limit = 200_000;
                }
                (expected_tokens, calldata, value, gas_limit, access_list)
            }
        };

        let mut tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: TxKind::Call(observed.router),
            value,
            access_list,
            input: Bytes::from(calldata.clone()),
        };

        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign front-run failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();

        let request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(observed.router)),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(value),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        Ok(Some(FrontRunTx {
            raw,
            hash: *signed.tx_hash(),
            to: observed.router,
            value,
            request,
            expected_tokens,
        }))
    }

    async fn build_backrun_tx(
        &self,
        observed: &ObservedSwap,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        wallet_balance: U256,
        gas_limit_hint: u64,
        token_in_override: Option<U256>,
        nonce: u64,
    ) -> Result<BackrunTx, AppError> {
        let target_token = Self::target_token(&observed.path, self.wrapped_native)
            .ok_or_else(|| AppError::Strategy("Unable to derive target token".into()))?;

        if wallet_balance.is_zero() {
            return Err(AppError::Strategy(
                "No balance available for backrun".into(),
            ));
        }

        let (value, expected_out, calldata, access_list) = if let Some(tokens_in) = token_in_override {
            match observed.router_kind {
                RouterKind::V2Like => {
                    let router_contract =
                        UniV2Router::new(observed.router, self.http_provider.clone());
                    let sell_path = vec![target_token, self.wrapped_native];
                    let quote_path = sell_path.clone();
                    let quote_contract = router_contract.clone();
                    let sell_amount = tokens_in;
                    let quote: Vec<U256> = retry_async(
                        move |_| {
                            let c = quote_contract.clone();
                            let p = quote_path.clone();
                            async move { c.getAmountsOut(sell_amount, p.clone()).call().await }
                        },
                        3,
                        Duration::from_millis(100),
                    )
                    .await
                    .map_err(|e| AppError::Strategy(format!("Sell quote failed: {}", e)))?;
                    let expected_out = *quote
                        .last()
                        .ok_or_else(|| AppError::Strategy("Sell quote missing amounts".into()))?;
                    // Liquidity sanity: require minimal return relative to notional (avoid >99.9% impact)
                    let ratio_ppm = Self::price_ratio_ppm(expected_out, sell_amount);
                    if ratio_ppm < U256::from(1_000u64) {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run {
                        // Probe toxicity before trusting expected_out
                        if !self
                            .probe_v2_sell_for_toxicity(target_token, observed.router, sell_amount, expected_out)
                            .await?
                        {
                            return Err(AppError::Strategy("toxic token detected on backrun".into()));
                        }
                    }
                    let min_out = expected_out
                        .saturating_mul(U256::from(10_000u64 - self.slippage_bps))
                        / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);
                    let calldata = router_contract
                        .swapExactTokensForETH(
                            sell_amount,
                            min_out,
                            sell_path.clone(),
                            self.signer.address(),
                            deadline,
                        )
                        .calldata()
                        .to_vec();
                    let access_list = Self::build_access_list(observed.router, &sell_path);
                    (U256::ZERO, expected_out, calldata, access_list)
                }
                RouterKind::V3Like => {
                    let rev_path = Self::reverse_v3_path(&observed.path, &observed.v3_fees)
                        .ok_or_else(|| AppError::Strategy("Reverse V3 path failed".into()))?;
                    let expected_out = self.quote_v3_path(&rev_path, tokens_in).await?;
                    let ratio_ppm = Self::price_ratio_ppm(expected_out, tokens_in);
                    if ratio_ppm < U256::from(1_000u64) {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run {
                        if !self
                            .probe_v3_sell_for_toxicity(observed.router, rev_path.clone(), tokens_in, expected_out)
                            .await?
                        {
                            self.mark_toxic_token(target_token, "v3_probe_shortfall");
                            return Err(AppError::Strategy("toxic token detected on backrun".into()));
                        }
                    }
                    let min_out = expected_out
                        .saturating_mul(U256::from(10_000u64 - self.slippage_bps))
                        / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);
                    let calldata = UniV3Router::new(observed.router, self.http_provider.clone())
                        .exactInput(UniV3Router::ExactInputParams {
                            path: rev_path.clone().into(),
                            recipient: self.signer.address(),
                            deadline,
                            amountIn: tokens_in,
                            amountOutMinimum: min_out,
                        })
                        .calldata()
                        .to_vec();
                    let access_list = Self::build_access_list(observed.router, &observed.path);
                    (U256::ZERO, expected_out, calldata, access_list)
                }
            }
        } else {
            match observed.router_kind {
                RouterKind::V2Like => {
                    let router_contract =
                        UniV2Router::new(observed.router, self.http_provider.clone());
                    let value = StrategyExecutor::dynamic_backrun_value(
                        observed.amount_in,
                        wallet_balance,
                        self.slippage_bps,
                        gas_limit_hint,
                        max_fee_per_gas,
                    )?;

                    let buy_path = vec![self.wrapped_native, target_token, self.wrapped_native];
                    let quote_path = buy_path.clone();
                    let quote_contract = router_contract.clone();
                    let quote_value = value;
                    let quote: Vec<U256> = retry_async(
                        move |_| {
                            let c = quote_contract.clone();
                            let p = quote_path.clone();
                            async move { c.getAmountsOut(quote_value, p.clone()).call().await }
                        },
                        3,
                        Duration::from_millis(100),
                    )
                    .await
                    .map_err(|e| AppError::Strategy(format!("Quote failed: {}", e)))?;
                    let expected_out = *quote
                        .last()
                        .ok_or_else(|| AppError::Strategy("Quote missing amounts".into()))?;
                    let ratio_ppm = Self::price_ratio_ppm(expected_out, value);
                    if ratio_ppm < U256::from(1_000u64) {
                        return Err(AppError::Strategy("Double-swap liquidity too low".into()));
                    }

                    let re_quote_contract = router_contract.clone();
                    let re_quote_path = buy_path.clone();
                    let second_quote: Vec<U256> = retry_async(
                        move |_| {
                            let c = re_quote_contract.clone();
                            let p = re_quote_path.clone();
                            async move { c.getAmountsOut(value, p.clone()).call().await }
                        },
                        3,
                        Duration::from_millis(100),
                    )
                    .await
                    .map_err(|e| AppError::Strategy(format!("Re-quote failed: {}", e)))?;
                    let second_out = *second_quote
                        .last()
                        .ok_or_else(|| AppError::Strategy("Re-quote missing amounts".into()))?;
                    let drift = if expected_out > second_out {
                        expected_out - second_out
                    } else {
                        second_out - expected_out
                    };
                    let tolerance = expected_out
                        .saturating_mul(U256::from(self.slippage_bps * 2))
                        / U256::from(10_000u64);
                    if drift > tolerance {
                        return Err(AppError::Strategy("Quote drift too high, skip".into()));
                    }

                    let min_out =
                        expected_out.saturating_mul(U256::from(10_000u64 - self.slippage_bps))
                            / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);
                    let calldata = router_contract
                        .swapExactETHForTokens(
                            min_out,
                            buy_path.clone(),
                            self.signer.address(),
                            deadline,
                        )
                        .calldata()
                        .to_vec();
                    let access_list = Self::build_access_list(observed.router, &buy_path);
                    (value, expected_out, calldata, access_list)
                }
                RouterKind::V3Like => {
                    return Err(AppError::Strategy(
                        "V3 double swap without owned tokens not supported".into(),
                    ))
                }
            }
        };

        let mut gas_limit = gas_limit_hint
            .saturating_mul(12)
            .checked_div(10)
            .unwrap_or(350_000);
        if gas_limit < 200_000 {
            gas_limit = 200_000;
        }
        let mut tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: TxKind::Call(observed.router),
            value,
            access_list,
            input: Bytes::from(calldata.clone()),
        };

        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign backrun failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();

        let request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(observed.router)),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(value),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        Ok(BackrunTx {
            raw,
            hash: *signed.tx_hash(),
            to: observed.router,
            value,
            request,
            expected_out,
        })
    }

    async fn await_receipt(&self, hash: &B256) -> Result<(), AppError> {
        for _ in 0..3 {
            if let Ok(Some(rcpt)) = self.http_provider.get_transaction_receipt(*hash).await {
                let block_num = rcpt.block_number;
                let status = rcpt.status();
                let _ = self.db.update_status(
                    &format!("{:#x}", hash),
                    block_num.map(|b| b as i64),
                    Some(status),
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(())
    }
}

fn wei_to_eth_f64(value: U256) -> f64 {
    let wei_in_eth = 1_000_000_000_000_000_000u128;
    let num: u128 = value.try_into().unwrap_or(u128::MAX);
    (num as f64) / (wei_in_eth as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::WETH_MAINNET;

    #[test]
    fn decodes_eth_swap() {
        let router = WETH_MAINNET;
        let call = swapExactETHForTokensCall {
            amountOutMin: U256::from(5u64),
            path: vec![WETH_MAINNET, Address::from([2u8; 20])],
            to: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
        };
        let data = call.abi_encode();
        let decoded = StrategyExecutor::decode_swap_input(
            router,
            &data,
            U256::from(1_000_000_000_000_000_000u128),
        )
        .expect("decode");
        assert_eq!(decoded.path.len(), 2);
        assert_eq!(decoded.min_out, U256::from(5u64));
    }

    #[test]
    fn wei_to_eth_conversion() {
        let two_eth = U256::from(2_000_000_000_000_000_000u128);
        let eth = wei_to_eth_f64(two_eth);
        assert!((eth - 2.0).abs() < 1e-9);
    }

    #[test]
    fn decodes_uniswap_v3_exact_input_single() {
        use alloy::primitives::{U160, aliases::U24};
        let params = UniV3Router::ExactInputSingleParams {
            tokenIn: WETH_MAINNET,
            tokenOut: Address::from([2u8; 20]),
            fee: U24::from(500u32),
            recipient: Address::from([3u8; 20]),
            deadline: U256::from(100u64),
            amountIn: U256::from(1_000_000_000_000_000_000u128),
            amountOutMinimum: U256::from(5u64),
            sqrtPriceLimitX96: U160::ZERO,
        };
        let call = UniV3Router::exactInputSingleCall { params };
        let data = call.abi_encode();
        let decoded = StrategyExecutor::decode_swap_input(
            WETH_MAINNET,
            &data,
            U256::from(0u64),
        )
        .expect("decode v3 single");
        assert_eq!(decoded.router_kind, RouterKind::V3Like);
        assert_eq!(decoded.path.len(), 2);
    }

    #[test]
    fn parses_uniswap_v3_path() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 1u8, 244u8]); // fee 500
        let out = Address::from([9u8; 20]);
        path.extend_from_slice(out.as_slice());
        let parsed = StrategyExecutor::parse_v3_path(&path).expect("parse path");
        assert_eq!(parsed.tokens.len(), 2);
        assert_eq!(parsed.tokens[1], out);
        assert_eq!(parsed.fees, vec![500]);
    }

    #[test]
    fn detects_token_calls() {
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb, 0u8];
        assert!(StrategyExecutor::is_common_token_call(&transfer_selector));
        let random = [0x12, 0x34, 0x56, 0x78];
        assert!(!StrategyExecutor::is_common_token_call(&random));
    }

    #[test]
    fn classifies_swap_direction() {
        let buy = ObservedSwap {
            router: Address::ZERO,
            path: vec![WETH_MAINNET, Address::from([2u8; 20])],
            v3_fees: Vec::new(),
            v3_path: None,
            amount_in: U256::from(1u64),
            min_out: U256::ZERO,
            recipient: Address::ZERO,
            router_kind: RouterKind::V2Like,
        };
        assert_eq!(
            StrategyExecutor::direction(&buy, WETH_MAINNET),
            SwapDirection::BuyWithEth
        );
        let sell = ObservedSwap {
            path: vec![Address::from([2u8; 20]), WETH_MAINNET],
            ..buy
        };
        assert_eq!(
            StrategyExecutor::direction(&sell, WETH_MAINNET),
            SwapDirection::SellForEth
        );
    }
}