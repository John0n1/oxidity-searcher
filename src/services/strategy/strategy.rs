// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::constants::{
    CHAIN_ARBITRUM, CHAIN_ETHEREUM, CHAIN_OPTIMISM, CHAIN_POLYGON, MIN_PROFIT_THRESHOLD_WEI,
};
use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::core::executor::{BundleItem, SharedBundleSender};
use crate::core::nonce::NonceManager;
use crate::core::portfolio::PortfolioManager;
use crate::core::safety::SafetyGuard;
use crate::core::simulation::Simulator;
use crate::data::db::Database;
use crate::data::executor::{FlashCallbackData, UnifiedHardenedExecutor};
use crate::infrastructure::data::token_manager::TokenManager;
use crate::network::gas::{GasFees, GasOracle};
use crate::network::mev_share::MevShareHint;
use crate::network::price_feed::PriceFeed;
use crate::network::provider::{HttpProvider, WsProvider};
use alloy::consensus::{SignableTransaction, Transaction as ConsensusTxTrait, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::network::{TransactionResponse, TxSignerSync};
use alloy::primitives::{
    Address, B256, Bytes, I256, TxKind, U256, address, aliases::U24, keccak256,
};
use alloy::providers::Provider;
use alloy::rpc::types::Header;
use alloy::rpc::types::eth::Transaction;
use alloy::rpc::types::eth::TransactionInput;
use alloy::rpc::types::eth::TransactionRequest;
use alloy::rpc::types::eth::state::StateOverridesBuilder;
use alloy::rpc::types::eth::{Filter, Log};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy_consensus::TxEnvelope;
use alloy_sol_types::SolValue;
use dashmap::{DashMap, DashSet};
use futures::StreamExt;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::ops::Neg;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, broadcast::Receiver, mpsc::UnboundedReceiver};
use tokio::time::sleep;

#[derive(Debug)]
pub enum StrategyWork {
    Mempool(Transaction),
    MevShareHint(MevShareHint),
}

const VICTIM_FEE_BUMP_BPS: u64 = 11_000;
const TAX_TOLERANCE_BPS: u64 = 500;
const PROBE_GAS_LIMIT: u64 = 220_000;
const V2_SYNC_EVENT: &str = "Sync(uint112,uint112)";
const BUNDLE_DEBOUNCE_MS: u64 = 5;
const V3_QUOTE_CACHE_TTL_MS: u64 = 250;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct V2Reserves {
    token0: Address,
    token1: Address,
    reserve0: U256,
    reserve1: U256,
}

#[derive(Clone)]
pub struct ReserveCache {
    http_provider: HttpProvider,
    v2_reserves: DashSet<(Address, V2Reserves)>,
    v2_pairs_by_tokens: DashSet<((Address, Address), Address)>,
    inflight_pairs: DashSet<Address>,
}

impl ReserveCache {
    pub fn new(http_provider: HttpProvider) -> Self {
        Self {
            http_provider,
            v2_reserves: DashSet::new(),
            v2_pairs_by_tokens: DashSet::new(),
            inflight_pairs: DashSet::new(),
        }
    }

    /// Optional preload from a JSON file: [{"pair":"0x...","token0":"0x...","token1":"0x..."}]
    pub fn load_pairs_from_file(&self, path: &str) -> Result<(), AppError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("pairs.json read failed: {}", e)))?;
        #[derive(Deserialize)]
        struct PairEntry {
            pair: String,
            token0: String,
            token1: String,
        }
        let entries: Vec<PairEntry> = serde_json::from_str(&raw)
            .map_err(|e| AppError::Config(format!("pairs.json parse failed: {}", e)))?;

        for entry in entries {
            let pair = Address::from_str(&entry.pair)
                .map_err(|_| AppError::Config("Invalid pair address in pairs.json".into()))?;
            let token0 = Address::from_str(&entry.token0)
                .map_err(|_| AppError::Config("Invalid token0 in pairs.json".into()))?;
            let token1 = Address::from_str(&entry.token1)
                .map_err(|_| AppError::Config("Invalid token1 in pairs.json".into()))?;
            let key = Self::token_pair_key(token0, token1);
            self.v2_pairs_by_tokens.insert((key, pair));
            self.v2_reserves.insert((
                pair,
                V2Reserves {
                    token0,
                    token1,
                    reserve0: U256::ZERO,
                    reserve1: U256::ZERO,
                },
            ));
        }
        Ok(())
    }

    pub async fn run_v2_log_listener(self: Arc<Self>, ws: WsProvider) {
        let filter = Filter::new().event(V2_SYNC_EVENT);
        loop {
            match ws.subscribe_logs(&filter).await {
                Ok(sub) => {
                    let mut stream = sub.into_stream();
                    tracing::info!(target: "reserves", "Subscribed to V2 Sync logs");
                    while let Some(log) = stream.next().await {
                        if let Err(e) = self.handle_v2_log(log).await {
                            tracing::debug!(target: "reserves", error=%e, "Failed to process Sync log");
                        }
                    }
                    tracing::warn!(target: "reserves", "Sync subscription ended, retrying");
                }
                Err(e) => {
                    tracing::warn!(target: "reserves", error=%e, "Sync subscribe failed, retrying");
                }
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    async fn handle_v2_log(&self, log: Log) -> Result<(), AppError> {
        let Some(topic0) = log.topic0() else {
            return Ok(());
        };
        if topic0 != &keccak256(V2_SYNC_EVENT.as_bytes()) {
            return Ok(());
        }

        let data = log.data().data.as_ref();
        if data.len() < 64 {
            return Ok(());
        }

        let reserve0 = U256::from_be_slice(&data[0..32]);
        let reserve1 = U256::from_be_slice(&data[32..64]);
        let pair = log.address();

        let cached_tokens = self.v2_reserves.iter().find_map(|entry| {
            let key = entry.key();
            if key.0 == pair {
                Some((key.1.token0, key.1.token1))
            } else {
                None
            }
        });

        let (token0, token1) = if let Some(tokens) = cached_tokens {
            tokens
        } else {
            // Avoid blocking hot path; schedule lookup and skip this log.
            self.schedule_pair_lookup(pair);
            return Ok(());
        };

        self.v2_reserves.insert((
            pair,
            V2Reserves {
                token0,
                token1,
                reserve0,
                reserve1,
            },
        ));
        let key = Self::token_pair_key(token0, token1);
        self.v2_pairs_by_tokens.insert((key, pair));
        Ok(())
    }

    fn token_pair_key(a: Address, b: Address) -> (Address, Address) {
        if a < b { (a, b) } else { (b, a) }
    }

    fn quote_v2_path(&self, path: &[Address], amount_in: U256) -> Option<U256> {
        if path.len() < 2 {
            return None;
        }
        let mut amount = amount_in;
        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];
            let key = Self::token_pair_key(from, to);
            let pair = self.v2_pairs_by_tokens.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == key { Some(k.1) } else { None }
            })?;
            let reserves = self.v2_reserves.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == pair { Some(k.1.clone()) } else { None }
            })?;
            let (reserve_in, reserve_out) = if from == reserves.token0 {
                (reserves.reserve0, reserves.reserve1)
            } else if from == reserves.token1 {
                (reserves.reserve1, reserves.reserve0)
            } else {
                return None;
            };
            if reserve_in.is_zero() || reserve_out.is_zero() {
                return None;
            }
            let amount_in_with_fee = amount.saturating_mul(U256::from(997u64));
            let numerator = amount_in_with_fee.saturating_mul(reserve_out);
            let denominator = reserve_in
                .saturating_mul(U256::from(1000u64))
                .saturating_add(amount_in_with_fee);
            amount = if denominator.is_zero() {
                return None;
            } else {
                numerator / denominator
            };
        }
        Some(amount)
    }

    fn pairs_for_v2_path(&self, path: &[Address]) -> Vec<Address> {
        if path.len() < 2 {
            return Vec::new();
        }
        let mut pairs = Vec::new();
        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];
            let key = Self::token_pair_key(from, to);
            if let Some(pair) = self.v2_pairs_by_tokens.iter().find_map(|entry| {
                let k = entry.key();
                if k.0 == key { Some(k.1) } else { None }
            }) {
                pairs.push(pair);
            }
        }
        pairs
    }

    fn schedule_pair_lookup(&self, pair: Address) {
        if !self.inflight_pairs.insert(pair) {
            return;
        }
        let provider = self.http_provider.clone();
        let pairs_map = self.v2_pairs_by_tokens.clone();
        let reserves_map = self.v2_reserves.clone();
        let inflight = self.inflight_pairs.clone();
        tokio::spawn(async move {
            sol! {
                #[derive(Debug, PartialEq, Eq)]
                #[sol(rpc)]
                contract UniswapV2Pair {
                    function token0() external view returns (address);
                    function token1() external view returns (address);
                }
            }
            let contract = UniswapV2Pair::new(pair, provider.clone());
            let token0: Result<Address, _> = contract.token0().call().await;
            let contract = UniswapV2Pair::new(pair, provider.clone());
            let token1: Result<Address, _> = contract.token1().call().await;
            if let (Ok(t0), Ok(t1)) = (token0, token1) {
                let key = if t0 < t1 { (t0, t1) } else { (t1, t0) };
                pairs_map.insert((key, pair));
                reserves_map.insert((
                    pair,
                    V2Reserves {
                        token0: t0,
                        token1: t1,
                        reserve0: U256::ZERO,
                        reserve1: U256::ZERO,
                    },
                ));
            }
            inflight.remove(&pair);
        });
    }
}

#[derive(Clone)]
struct BundlePlan {
    front_run: Option<TransactionRequest>,
    approval: Option<TransactionRequest>,
    main: TransactionRequest,
    victims: Vec<Vec<u8>>,
}

#[derive(Default)]
struct PlanHashes {
    front_run: Option<B256>,
    approval: Option<B256>,
    main: B256,
}

struct BundleState {
    block: u64,
    next_nonce: u64,
    raw: Vec<Vec<u8>>,
    touched_pools: HashSet<Address>,
    send_pending: bool,
}

#[derive(Clone)]
struct V3QuoteCacheEntry {
    amount_out: U256,
    expires_at: Instant,
}

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

use UniV2Router::{
    swapExactETHForTokensCall, swapExactTokensForETHCall, swapExactTokensForTokensCall,
};

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
    tx_rx: Mutex<UnboundedReceiver<StrategyWork>>,
    mut_block_rx: Mutex<Receiver<Header>>,
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
    token_manager: Arc<TokenManager>,
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
    executor: Option<Address>,
    executor_bribe_bps: u64,
    executor_bribe_recipient: Option<Address>,
    flashloan_enabled: bool,
    reserve_cache: Arc<ReserveCache>,
    bundle_state: Arc<Mutex<Option<BundleState>>>,
    v3_quote_cache: DashMap<B256, V3QuoteCacheEntry>,
    current_block: AtomicU64,
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
    expected_out_token: Address,
    unwrap_to_native: bool,
    uses_flashloan: bool,
    router_kind: RouterKind,
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

struct V2SwapBuild {
    expected_out: U256,
    calldata: Vec<u8>,
    access_list: AccessList,
    gas_limit: u64,
    tx_value: U256,
}

impl StrategyExecutor {
    fn price_ratio_ppm(amount_out: U256, amount_in: U256) -> U256 {
        if amount_in.is_zero() {
            return U256::ZERO;
        }
        amount_out.saturating_mul(U256::from(1_000_000u64)) / amount_in
    }

    fn is_nonce_gap_error(err: &AppError) -> bool {
        let msg = err.to_string().to_lowercase();
        msg.contains("nonce too high")
            || msg.contains("nonce too low")
            || msg.contains("nonce gap")
            || msg.contains("missing nonce")
    }

    #[cfg(test)]
    fn test_backrun_divisors_public(wallet_balance: U256) -> (u64, u64) {
        Self::backrun_divisors(wallet_balance)
    }

    fn log_skip(&self, reason: &str, detail: &str) {
        if self.dry_run {
            tracing::info!(target: "strategy_skip", %reason, %detail, "Dry-run skip");
        } else {
            tracing::debug!(target: "strategy_skip", %reason, %detail);
        }

        match reason {
            "unknown_router" => {
                self.stats
                    .skip_unknown_router
                    .fetch_add(1, Ordering::Relaxed);
            }
            "decode_failed" => {
                self.stats
                    .skip_decode_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            "zero_amount_or_no_wrapped_native" => {
                self.stats
                    .skip_missing_wrapped
                    .fetch_add(1, Ordering::Relaxed);
            }
            "gas_price_cap" => {
                self.stats.skip_gas_cap.fetch_add(1, Ordering::Relaxed);
            }
            "simulation_failed" => {
                self.stats.skip_sim_failed.fetch_add(1, Ordering::Relaxed);
            }
            "profit_or_gas_guard" => {
                self.stats.skip_profit_guard.fetch_add(1, Ordering::Relaxed);
            }
            "unsupported_router_type" => {
                self.stats
                    .skip_unsupported_router
                    .fetch_add(1, Ordering::Relaxed);
            }
            "token_call" => {
                self.stats.skip_token_call.fetch_add(1, Ordering::Relaxed);
            }
            "toxic_token" => {
                self.stats.skip_toxic_token.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn amount_to_display(&self, amount: U256, token: Address) -> f64 {
        let decimals = self
            .token_manager
            .decimals(self.chain_id, token)
            .unwrap_or(18);
        units_to_float(amount, decimals)
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
        token_manager: Arc<TokenManager>,
        stats: Arc<StrategyStats>,
        signer: PrivateKeySigner,
        nonce_manager: NonceManager,
        slippage_bps: u64,
        http_provider: HttpProvider,
        dry_run: bool,
        router_allowlist: HashSet<Address>,
        wrapped_native: Address,
        executor: Option<Address>,
        executor_bribe_bps: u64,
        executor_bribe_recipient: Option<Address>,
        flashloan_enabled: bool,
        reserve_cache: Arc<ReserveCache>,
    ) -> Self {
        Self {
            tx_rx: Mutex::new(tx_rx),
            mut_block_rx: Mutex::new(block_rx),
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
            token_manager,
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
            executor,
            executor_bribe_bps,
            executor_bribe_recipient,
            flashloan_enabled,
            reserve_cache,
            bundle_state: Arc::new(Mutex::new(None)),
            v3_quote_cache: DashMap::new(),
            current_block: AtomicU64::new(0),
        }
    }

    pub async fn run(self) -> Result<(), AppError> {
        tracing::info!("StrategyExecutor: waiting for pending transactions");

        let executor = Arc::new(self);

        // Spawn a lightweight block watcher so work processing never waits on block stream.
        let block_exec = executor.clone();
        tokio::spawn(async move {
            block_exec.block_watcher().await;
        });

        loop {
            let work_opt = {
                let mut rx = executor.tx_rx.lock().await;
                rx.recv().await
            };

            match work_opt {
                Some(work) => {
                    let exec = executor.clone();
                    tokio::spawn(async move {
                        exec.process_work(work).await;
                    });
                }
                None => break,
            }
        }

        Ok(())
    }

    async fn block_watcher(self: Arc<Self>) {
        loop {
            let msg = {
                let mut rx = self.mut_block_rx.lock().await;
                rx.recv().await
            };

            match msg {
                Ok(header) => {
                    tracing::debug!("StrategyExecutor: observed new block {:?}", header.hash);
                    let number = header.inner.number;
                    let prev = self.current_block.swap(number as u64, Ordering::Relaxed);
                    if prev != number as u64 {
                        let mut guard = self.bundle_state.lock().await;
                        *guard = None;
                    }
                    let _ = self.maybe_rebalance_inventory().await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    }

    async fn process_work(self: Arc<Self>, work: StrategyWork) {
        if let Err(e) = self.handle_work(work).await {
            tracing::error!(target: "strategy", error=%e, "Strategy task failed");
        }
    }

    async fn populate_access_list(&self, req: &mut TransactionRequest) {
        match self.http_provider.create_access_list(&req.clone()).await {
            Ok(res) => {
                let list = res.ensure_ok().map(|r| r.access_list).unwrap_or_default();
                if !list.0.is_empty() {
                    req.access_list = Some(list);
                }
            }
            Err(e) => {
                tracing::debug!(
                    target: "access_list",
                    error=%e,
                    "eth_createAccessList failed; continuing without access list"
                );
            }
        }
    }

    async fn apply_access_list(
        &self,
        req: &mut TransactionRequest,
        fallback: AccessList,
    ) -> AccessList {
        self.populate_access_list(req).await;
        req.access_list.clone().unwrap_or(fallback)
    }

    async fn sign_with_access_list(
        &self,
        mut request: TransactionRequest,
        fallback: AccessList,
    ) -> Result<(Vec<u8>, TransactionRequest, B256), AppError> {
        let access_list = self.apply_access_list(&mut request, fallback).await;

        let to = request
            .to
            .ok_or_else(|| AppError::Strategy("Missing `to` in tx request".into()))?;
        let gas = request
            .gas
            .ok_or_else(|| AppError::Strategy("Missing `gas` in tx request".into()))?;
        let value = request.value.unwrap_or_default();
        let max_fee_per_gas = request
            .max_fee_per_gas
            .ok_or_else(|| AppError::Strategy("Missing max_fee_per_gas in tx request".into()))?;
        let max_priority_fee_per_gas = request.max_priority_fee_per_gas.ok_or_else(|| {
            AppError::Strategy("Missing max_priority_fee_per_gas in tx request".into())
        })?;
        let nonce = request
            .nonce
            .ok_or_else(|| AppError::Strategy("Missing nonce in tx request".into()))?;
        let chain_id = request.chain_id.unwrap_or(self.chain_id);
        let input_bytes = request
            .input
            .clone()
            .into_input()
            .map(Bytes::from)
            .unwrap_or_default();

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: gas,
            to,
            value,
            access_list,
            input: input_bytes,
        };

        let sig = TxSignerSync::sign_transaction_sync(&self.signer, &mut tx)
            .map_err(|e| AppError::Strategy(format!("Sign tx failed: {}", e)))?;
        let signed: TxEnvelope = tx.into_signed(sig).into();
        let raw = signed.encoded_2718();
        Ok((raw, request, *signed.tx_hash()))
    }

    async fn sign_swap_request(
        &self,
        to: Address,
        gas_limit: u64,
        value: U256,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        nonce: u64,
        calldata: Vec<u8>,
        access_list: AccessList,
    ) -> Result<(Vec<u8>, TransactionRequest, B256), AppError> {
        let request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(to)),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(value),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        self.sign_with_access_list(request, access_list).await
    }

    async fn merge_and_send_bundle(
        &self,
        plan: BundlePlan,
        touched_pools: Vec<Address>,
    ) -> Result<Option<PlanHashes>, AppError> {
        let mut state_guard = self.bundle_state.lock().await;
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .map_err(|e| AppError::Connection(format!("Failed to fetch block: {}", e)))?;
        }

        if state_guard
            .as_ref()
            .map(|s| s.block != block)
            .unwrap_or(true)
        {
            let base_nonce = self.nonce_manager.get_base_nonce(block).await?;
            *state_guard = Some(BundleState {
                block,
                next_nonce: base_nonce,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }

        let state = state_guard.as_mut().unwrap();

        // Conflict guard: skip if any pool already touched in this bundle.
        for pool in &touched_pools {
            if state.touched_pools.contains(pool) {
                tracing::warn!(target: "bundle_merge", pool=%format!("{:#x}", pool), "Pool conflict; skipping merge");
                return Ok(None);
            }
        }

        let mut nonce = state.next_nonce;
        let mut hashes = PlanHashes::default();
        let mut new_raw: Vec<Vec<u8>> = Vec::new();

        if let Some(mut fr) = plan.front_run {
            fr.nonce = Some(nonce);
            let fallback = fr.access_list.clone().unwrap_or_default();
            let (raw, _, hash) = self.sign_with_access_list(fr, fallback).await?;
            hashes.front_run = Some(hash);
            nonce = nonce.saturating_add(1);
            new_raw.push(raw);
        }

        for victim in plan.victims {
            new_raw.push(victim);
        }

        if let Some(mut approval) = plan.approval {
            approval.nonce = Some(nonce);
            let fallback = approval.access_list.clone().unwrap_or_default();
            let (raw, _, hash) = self.sign_with_access_list(approval, fallback).await?;
            hashes.approval = Some(hash);
            nonce = nonce.saturating_add(1);
            new_raw.push(raw);
        }

        let mut main = plan.main;
        main.nonce = Some(nonce);
        let fallback = main.access_list.clone().unwrap_or_default();
        let (raw, _, hash) = self.sign_with_access_list(main, fallback).await?;
        hashes.main = hash;
        nonce = nonce.saturating_add(1);
        new_raw.push(raw);

        state.next_nonce = nonce;
        state.raw.extend(new_raw);
        for pool in touched_pools {
            state.touched_pools.insert(pool);
        }
        let bundle_len = state.raw.len();
        drop(state_guard);

        if self.dry_run {
            tracing::info!(
                target: "executor",
                "Dry-run: would send merged bundle with {} txs",
                bundle_len
            );
            return Ok(Some(hashes));
        }

        self.schedule_bundle_send().await;

        Ok(Some(hashes))
    }

    async fn schedule_bundle_send(&self) {
        let mut guard = self.bundle_state.lock().await;
        let Some(state) = guard.as_mut() else {
            return;
        };
        if state.send_pending {
            return;
        }
        state.send_pending = true;

        let bundle_state = self.bundle_state.clone();
        let sender = self.bundle_sender.clone();
        let chain_id = self.chain_id;
        let dry_run = self.dry_run;

        tokio::spawn(async move {
            sleep(Duration::from_millis(BUNDLE_DEBOUNCE_MS)).await;
            let maybe_bundle = {
                let mut guard = bundle_state.lock().await;
                if let Some(state) = guard.as_mut() {
                    state.send_pending = false;
                    Some((state.block, state.raw.clone()))
                } else {
                    None
                }
            };

            if dry_run {
                if let Some((_, bundle)) = maybe_bundle {
                    tracing::info!(
                        target: "executor",
                        "Dry-run: would send merged bundle with {} txs",
                        bundle.len()
                    );
                }
                return;
            }

            if let Some((block, bundle)) = maybe_bundle {
                if bundle.is_empty() {
                    return;
                }
                if let Err(e) = sender.send_bundle(&bundle, chain_id).await {
                    tracing::error!(
                        target: "bundle_merge",
                        block,
                        error = %e,
                        "Deferred bundle send failed"
                    );
                }
            }
        });
    }

    async fn peek_nonce_for_sim(&self) -> Result<u64, AppError> {
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .unwrap_or_default();
        }
        if let Some(state) = self.bundle_state.lock().await.as_ref() {
            return Ok(state.next_nonce);
        }
        self.nonce_manager.get_base_nonce(block).await
    }

    async fn lease_nonces(&self, count: u64) -> Result<u64, AppError> {
        if count == 0 {
            return self.peek_nonce_for_sim().await;
        }
        let mut block = self.current_block.load(Ordering::Relaxed);
        if block == 0 {
            block = self
                .http_provider
                .get_block_number()
                .await
                .unwrap_or_default();
        }
        let mut guard = self.bundle_state.lock().await;
        if guard.as_ref().map(|s| s.block != block).unwrap_or(true) {
            let base_nonce = self.nonce_manager.get_base_nonce(block).await?;
            *guard = Some(BundleState {
                block,
                next_nonce: base_nonce,
                raw: Vec::new(),
                touched_pools: HashSet::new(),
                send_pending: false,
            });
        }
        let state = guard.as_mut().unwrap();
        let start = state.next_nonce;
        state.next_nonce = state.next_nonce.saturating_add(count);
        Ok(start)
    }

    async fn handle_work(&self, work: StrategyWork) -> Result<(), AppError> {
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
                let nonce_gap = Self::is_nonce_gap_error(&e);
                if nonce_gap {
                    tracing::warn!(
                        target: "strategy",
                        error=%e,
                        "Nonce gap detected; suppressing safety guard trip"
                    );
                    self.safety_guard.report_success();
                } else {
                    self.safety_guard.report_failure();
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(target: "strategy", error=%e, "Strategy failed");
                }
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

        let real_balance = self.portfolio.update_eth_balance(self.chain_id).await?;
        let (wallet_chain_balance, _) = if self.dry_run {
            let gas_headroom = U256::from(tx.gas_limit()) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = tx.value().saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };
        // Do not gate locally on wallet balance; we simulate with a fat override and let the builder/validator decide.

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let executor_tx: Option<(Vec<u8>, TransactionRequest, B256)>;
        let main_request: TransactionRequest;

        // Capture a simulation nonce snapshot; execution nonces are assigned in merge_and_send_bundle.
        let mut nonce_cursor = self.peek_nonce_for_sim().await?;

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth {
            let nonce_front = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
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
                let needed_nonce = nonce_cursor;
                nonce_cursor = nonce_cursor.saturating_add(1);
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

        let use_flashloan =
            self.should_use_flashloan(observed_swap.amount_in, wallet_chain_balance, &gas_fees)
                && front_run.is_none();

        let sim_balance =
            U256::from_str("10000000000000000000000").unwrap_or_else(|_| U256::from(u128::MAX));
        let trade_balance = if use_flashloan {
            sim_balance
        } else {
            wallet_chain_balance
        };

        let nonce_backrun = nonce_cursor;

        let backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                trade_balance,
                tx.gas_limit(),
                front_run.as_ref().map(|f| f.expected_tokens),
                use_flashloan,
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
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), sim_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        // Build optional executor wrapper for approval + backrun legs.
        executor_tx = self
            .build_executor_wrapper(
                approval.as_ref(),
                &backrun,
                &gas_fees,
                tx.gas_limit(),
                nonce_backrun,
            )
            .await?;
        if let Some(f) = &front_run {
            bundle_requests.push(f.request.clone());
        }
        bundle_requests.push(tx.clone().into_request());

        if let Some((_, req, _)) = &executor_tx {
            bundle_requests.push(req.clone());
            main_request = req.clone();
        } else {
            if let Some(app) = &approval {
                bundle_requests.push(app.request.clone());
            }
            bundle_requests.push(backrun.request.clone());
            main_request = backrun.request.clone();
        }
        let mut bundle_reqs_for_sim = bundle_requests.clone();
        for req in bundle_reqs_for_sim.iter_mut() {
            self.populate_access_list(req).await;
        }
        let overrides_for_sim = overrides.clone();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let overrides = overrides_for_sim.clone();
                let reqs = bundle_reqs_for_sim.clone();
                async move {
                    simulator
                        .simulate_bundle_requests(&reqs, Some(overrides))
                        .await
                }
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
        let gas_cost_wei = U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        // No local balance gating here; avoid blocking concurrent bundles. The builder/validator will enforce real balances.

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
            self.log_skip(
                "profit_or_gas_guard",
                &format!("Net {} < Floor {}", net_profit_wei, profit_floor),
            );
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        // --- Logging/Persistence (Safe to use f64 here for display) ---
        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = self.amount_to_display(gross_profit_wei, self.wrapped_native);
        let gas_cost_eth_f64 = self.amount_to_display(gas_cost_wei, self.wrapped_native);
        let net_profit_eth_f64 = self.amount_to_display(net_profit_wei, self.wrapped_native);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_wei = %gas_cost_wei,
            net_profit_wei = %net_profit_wei,
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
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
                front_run_value_eth = self.amount_to_display(attack_value_eth, self.wrapped_native),
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable bundle (not sent)"
            );
            return Ok(Some(format!("{tx_hash:#x}")));
        }

        // Merge bundle with any other pending plans for this block to avoid nonce collisions.
        let plan = BundlePlan {
            front_run: front_run.as_ref().map(|f| f.request.clone()),
            approval: approval.as_ref().map(|a| a.request.clone()),
            main: main_request.clone(),
            victims: vec![tx.inner.encoded_2718()],
        };
        let touched_pools = self.reserve_cache.pairs_for_v2_path(&observed_swap.path);
        let plan_hashes = match self.merge_and_send_bundle(plan, touched_pools).await {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.emergency_exit_inventory("bundle send failed").await;
                return Err(e);
            }
        };

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
        let recorded_hash = plan_hashes.main;
        let recorded_to = main_request
            .to
            .clone()
            .or_else(|| Some(TxKind::Call(backrun.to)));
        let recorded_value = main_request.value.unwrap_or(backrun.value);
        self.db
            .save_transaction(
                &format!("{:#x}", recorded_hash),
                self.chain_id,
                &format!("{:#x}", self.signer.address()),
                recorded_to
                    .as_ref()
                    .and_then(|k| match k {
                        TxKind::Call(a) => Some(format!("{:#x}", a)),
                        _ => None,
                    })
                    .as_deref(),
                recorded_value.to_string().as_str(),
                Some("strategy_backrun"),
            )
            .await?;
        if let Some(f) = &front_run {
            self.db
                .save_transaction(
                    &format!("{:#x}", plan_hashes.front_run.unwrap_or_else(|| f.hash)),
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

        let receipt_target = plan_hashes.main;
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("bundle receipt missing/failed")
                .await;
        }

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

        let Some(observed_swap) = Self::decode_swap_input(hint.router, &hint.call_data, hint.value)
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
            let gas_headroom = U256::from(gas_limit_hint) * U256::from(gas_fees.max_fee_per_gas);
            let value_headroom = hint.value.saturating_mul(U256::from(2u64));
            let mock = gas_headroom
                .saturating_add(value_headroom)
                .max(U256::from(500_000_000_000_000_000u128)); // floor 0.5 ETH
            (mock, true)
        } else {
            (real_balance, false)
        };
        // Skip local balance gating for concurrent bundles; rely on simulation override and builder validation.

        let mut attack_value_eth = U256::ZERO;
        let mut bundle_requests: Vec<TransactionRequest> = Vec::new();
        let mut bundle_body: Vec<BundleItem> = Vec::new();
        let mut executor_request: Option<TransactionRequest> = None;
        let mut executor_hash: Option<B256> = None;

        // Capture a simulation nonce snapshot; execution nonces are assigned in merge_and_send_bundle.
        let mut nonce_cursor = self.peek_nonce_for_sim().await?;

        let mut front_run: Option<FrontRunTx> = None;
        let mut approval: Option<ApproveTx> = None;
        if direction == SwapDirection::BuyWithEth {
            let nonce_front = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
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
                let needed_nonce = nonce_cursor;
                nonce_cursor = nonce_cursor.saturating_add(1);
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

        let use_flashloan =
            self.should_use_flashloan(observed_swap.amount_in, wallet_chain_balance, &gas_fees)
                && front_run.is_none();
        let sim_balance =
            U256::from_str("10000000000000000000000").unwrap_or_else(|_| U256::from(u128::MAX));
        let trade_balance = if use_flashloan {
            sim_balance
        } else {
            wallet_chain_balance
        };
        let nonce_backrun = nonce_cursor;
        nonce_cursor = nonce_cursor.saturating_add(1);
        let mut backrun = match self
            .build_backrun_tx(
                &observed_swap,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                trade_balance,
                gas_limit_hint,
                front_run.as_ref().map(|f| f.expected_tokens),
                use_flashloan,
                nonce_cursor,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.log_skip("backrun_build_failed", &e.to_string());
                return Ok(None);
            }
        };
        let sim_nonce = front_run
            .as_ref()
            .and_then(|f| f.request.nonce)
            .or_else(|| backrun.request.nonce)
            .unwrap_or_default();

        let overrides = StateOverridesBuilder::default()
            .with_balance(self.signer.address(), sim_balance)
            .with_nonce(self.signer.address(), sim_nonce)
            .build();

        let max_fee_hint = hint.max_fee_per_gas.unwrap_or(gas_fees.max_fee_per_gas);
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

        // If we can avoid a front-run, wrap our legs in the on-chain executor for atomicity.
        if self.executor.is_some() && front_run.is_none() {
            if let Some(exec_addr) = self.executor {
                let mut targets = Vec::new();
                let mut payloads = Vec::new();
                let mut values = Vec::new();

                if let Some(app) = &approval {
                    if let Some(TxKind::Call(addr)) = app.request.to {
                        targets.push(addr);
                        let bytes = app.request.input.clone().into_input().unwrap_or_default();
                        payloads.push(bytes);
                        values.push(U256::ZERO);
                    }
                }
                if let Some(TxKind::Call(addr)) = backrun.request.to {
                    targets.push(addr);
                    let bytes = backrun
                        .request
                        .input
                        .clone()
                        .into_input()
                        .unwrap_or_default();
                    payloads.push(bytes);
                    values.push(backrun.value);
                }

                if !targets.is_empty() {
                    let total_value = values
                        .iter()
                        .copied()
                        .fold(U256::ZERO, |acc, v| acc.saturating_add(v));
                    let exec_call = UnifiedHardenedExecutor::executeBundleCall {
                        targets,
                        payloads,
                        values,
                        bribeRecipient: Address::ZERO,
                        bribeAmount: U256::ZERO,
                        allowPartial: true,
                        balanceCheckToken: self.wrapped_native,
                    };
                    let calldata = exec_call.abi_encode();
                    let gas_limit = backrun
                        .request
                        .gas
                        .unwrap_or(gas_limit_hint)
                        .saturating_add(approval.as_ref().and_then(|a| a.request.gas).unwrap_or(0))
                        .saturating_add(80_000);

                    let (_raw, request, hash) = self
                        .sign_swap_request(
                            exec_addr,
                            gas_limit,
                            total_value,
                            gas_fees.max_fee_per_gas,
                            gas_fees.max_priority_fee_per_gas,
                            nonce_backrun,
                            calldata,
                            AccessList::default(),
                        )
                        .await?;
                    executor_hash = Some(hash);
                    executor_request = Some(request);
                }
            }
        }

        let exec_req_for_sim = executor_request.clone();
        let mut bundle_reqs_for_sim = bundle_requests.clone();
        for req in bundle_reqs_for_sim.iter_mut() {
            self.populate_access_list(req).await;
        }
        let overrides_for_sim = overrides.clone();
        let bundle_sims = retry_async(
            move |_| {
                let simulator = self.simulator.clone();
                let reqs = if let Some(r) = exec_req_for_sim.clone() {
                    vec![r]
                } else {
                    bundle_reqs_for_sim.clone()
                };
                let overrides = overrides_for_sim.clone();
                async move {
                    simulator
                        .simulate_bundle_requests(&reqs, Some(overrides))
                        .await
                }
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
        let gas_cost_wei = U256::from(bundle_gas_limit) * U256::from(gas_fees.max_fee_per_gas);

        // Likewise, do not block based on local balance; validator will enforce account state.

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
            self.log_skip(
                "profit_or_gas_guard",
                &format!("Net {} < Floor {}", net_profit_wei, profit_floor),
            );
            return Ok(None);
        }

        if !self.gas_ratio_ok(gas_cost_wei, gross_profit_wei, wallet_chain_balance) {
            self.log_skip("profit_or_gas_guard", "Bad Risk/Reward");
            return Ok(None);
        }

        let eth_quote = self.price_feed.get_price("ETHUSD").await?;
        let profit_eth_f64 = self.amount_to_display(gross_profit_wei, self.wrapped_native);
        let gas_cost_eth_f64 = self.amount_to_display(gas_cost_wei, self.wrapped_native);
        let net_profit_eth_f64 = self.amount_to_display(net_profit_wei, self.wrapped_native);

        tracing::info!(
            target: "strategy",
            gas_limit = bundle_gas_limit,
            max_fee_per_gas = gas_fees.max_fee_per_gas,
            gas_cost_eth = gas_cost_eth_f64,
            backrun_value_eth = self.amount_to_display(backrun.value, self.wrapped_native),
            expected_out_eth = self.amount_to_display(backrun.expected_out, self.wrapped_native),
            front_run_value_eth = self.amount_to_display(attack_value_eth, self.wrapped_native),
            net_profit_eth = net_profit_eth_f64,
            wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
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

        let used_nonces = 1 + front_run.is_some() as u64 + approval.is_some() as u64;
        let base_nonce = self.lease_nonces(used_nonces).await?;
        let mut nonce_cursor = base_nonce;

        bundle_body.clear();
        bundle_body.push(BundleItem::Hash {
            hash: tx_hash.clone(),
        });

        if let Some(f) = front_run.as_mut() {
            let fallback = f.request.access_list.clone().unwrap_or_default();
            let mut req = f.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            f.raw = raw.clone();
            f.request = signed_req;
            f.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
            nonce_cursor = nonce_cursor.saturating_add(1);
        }

        if let Some(app) = approval.as_mut() {
            let fallback = app.request.access_list.clone().unwrap_or_default();
            let mut req = app.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, _) = self.sign_with_access_list(req, fallback).await?;
            app.raw = raw.clone();
            app.request = signed_req;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
            nonce_cursor = nonce_cursor.saturating_add(1);
        }

        if let Some(mut req) = executor_request.take() {
            let fallback = req.access_list.clone().unwrap_or_default();
            req.nonce = Some(nonce_cursor);
            let (raw, _signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            executor_hash = Some(hash);
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        } else {
            let fallback = backrun.request.access_list.clone().unwrap_or_default();
            let mut req = backrun.request.clone();
            req.nonce = Some(nonce_cursor);
            let (raw, signed_req, hash) = self.sign_with_access_list(req, fallback).await?;
            backrun.raw = raw.clone();
            backrun.request = signed_req;
            backrun.hash = hash;
            bundle_body.push(BundleItem::Tx {
                tx: format!("0x{}", hex::encode(&raw)),
                can_revert: false,
            });
        }

        if self.dry_run {
            tracing::info!(
                target: "strategy_dry_run",
                tx_hash = %tx_hash,
                net_profit_eth = net_profit_eth_f64,
                gross_profit_eth = profit_eth_f64,
                gas_cost_eth = gas_cost_eth_f64,
                front_run_value_eth = self.amount_to_display(attack_value_eth, self.wrapped_native),
                wallet_eth = self.amount_to_display(wallet_chain_balance, self.wrapped_native),
                path_len = observed_swap.path.len(),
                router = ?observed_swap.router,
                used_mock_balance = self.dry_run,
                sandwich = front_run.is_some(),
                "Dry-run only: simulated profitable MEV-Share bundle (not sent)"
            );
            return Ok(Some(tx_hash));
        }

        let _ = self.db.update_status(&tx_hash, None, Some(false)).await;

        if let Err(e) = self.bundle_sender.send_mev_share_bundle(&bundle_body).await {
            self.emergency_exit_inventory("mev_share bundle send failed")
                .await;
            return Err(e);
        }

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

        let receipt_target = executor_hash.unwrap_or(backrun.hash);
        if !self.await_receipt(&receipt_target).await? {
            self.emergency_exit_inventory("mev_share receipt missing/failed")
                .await;
        }

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

    #[cfg(test)]
    fn test_dynamic_profit_floor_public(balance: U256) -> U256 {
        Self::dynamic_profit_floor(balance)
    }

    fn boost_fees(
        &self,
        fees: &mut GasFees,
        victim_max_fee: Option<u128>,
        victim_tip: Option<u128>,
    ) {
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

        let boost =
            |val: u128| -> u128 { (val.saturating_mul(boost_bps as u128) / 10_000u128).max(val) };
        fees.max_fee_per_gas = boost(fees.max_fee_per_gas);
        fees.max_priority_fee_per_gas = boost(fees.max_priority_fee_per_gas);

        let one_gwei: u128 = 1_000_000_000;
        let tip_floor = ((fees.base_fee_per_gas / 10).max(2 * one_gwei)).min(30 * one_gwei);
        if fees.max_priority_fee_per_gas < tip_floor {
            fees.max_priority_fee_per_gas = tip_floor;
        }
        let min_fee = fees
            .base_fee_per_gas
            .saturating_add(fees.max_priority_fee_per_gas);
        if fees.max_fee_per_gas < min_fee {
            fees.max_fee_per_gas = min_fee;
        }

        if let Some(v_fee) = victim_max_fee {
            let fee_target = v_fee.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            fees.max_fee_per_gas = fees.max_fee_per_gas.max(fee_target);
        }
        if let Some(v_tip) = victim_tip {
            let tip_target = v_tip.saturating_mul(VICTIM_FEE_BUMP_BPS as u128) / 10_000u128;
            fees.max_priority_fee_per_gas = fees.max_priority_fee_per_gas.max(tip_target);
        }
    }

    fn gas_ratio_ok(
        &self,
        gas_cost_wei: U256,
        gross_profit_wei: U256,
        wallet_balance: U256,
    ) -> bool {
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

    fn v3_quote_cache_key(path: &[u8], amount_in: U256) -> B256 {
        let mut key_material = Vec::with_capacity(path.len() + 32);
        key_material.extend_from_slice(path);
        key_material.extend_from_slice(&amount_in.to_be_bytes::<32>());
        keccak256(key_material)
    }

    async fn quote_v3_path(&self, path: &[u8], amount_in: U256) -> Result<U256, AppError> {
        let cache_key = Self::v3_quote_cache_key(path, amount_in);
        let now = Instant::now();
        let expired = if let Some(entry) = self.v3_quote_cache.get(&cache_key) {
            if entry.expires_at > now {
                return Ok(entry.amount_out);
            }
            true
        } else {
            false
        };
        if expired {
            self.v3_quote_cache.remove(&cache_key);
        }

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

        let expiry = now
            .checked_add(Duration::from_millis(V3_QUOTE_CACHE_TTL_MS))
            .unwrap_or(now);
        self.v3_quote_cache.insert(
            cache_key,
            V3QuoteCacheEntry {
                amount_out: out,
                expires_at: expiry,
            },
        );

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

        let selector: [u8; 4] = input[..4].try_into().ok()?;
        match selector {
            swapExactETHForTokensCall::SELECTOR => {
                let decoded = swapExactETHForTokensCall::abi_decode(input).ok()?;
                Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    amount_in: eth_value,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.to,
                    router_kind: RouterKind::V2Like,
                })
            }
            swapExactTokensForETHCall::SELECTOR => {
                let decoded = swapExactTokensForETHCall::abi_decode(input).ok()?;
                Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.to,
                    router_kind: RouterKind::V2Like,
                })
            }
            swapExactTokensForTokensCall::SELECTOR => {
                let decoded = swapExactTokensForTokensCall::abi_decode(input).ok()?;
                Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.to,
                    router_kind: RouterKind::V2Like,
                })
            }
            UniV3Router::exactInputSingleCall::SELECTOR => {
                let decoded = UniV3Router::exactInputSingleCall::abi_decode(input).ok()?;
                let params = decoded.params;
                let path_bytes =
                    Self::encode_v3_path(&[params.tokenIn, params.tokenOut], &[params.fee.to()]);
                let fee_u32: u32 = params.fee.to::<u32>();
                if !Self::v3_fee_sane(fee_u32) {
                    return None;
                }
                if !Self::validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                    return None;
                }
                Some(ObservedSwap {
                    router,
                    path: vec![params.tokenIn, params.tokenOut],
                    v3_fees: vec![fee_u32],
                    v3_path: path_bytes,
                    amount_in: params.amountIn,
                    min_out: params.amountOutMinimum,
                    recipient: params.recipient,
                    router_kind: RouterKind::V3Like,
                })
            }
            UniV3Router::exactInputCall::SELECTOR => {
                let decoded = UniV3Router::exactInputCall::abi_decode(input).ok()?;
                let params = decoded.params;
                let Some(path) = Self::parse_v3_path(&params.path) else {
                    return None;
                };
                Some(ObservedSwap {
                    router,
                    path: path.tokens.clone(),
                    v3_fees: path.fees.clone(),
                    v3_path: Some(params.path.to_vec()),
                    amount_in: params.amountIn,
                    min_out: params.amountOutMinimum,
                    recipient: params.recipient,
                    router_kind: RouterKind::V3Like,
                })
            }
            _ => None,
        }
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

    #[cfg(test)]
    fn test_price_ratio_ppm_public(out: U256, inn: U256) -> U256 {
        Self::price_ratio_ppm(out, inn)
    }

    #[cfg(test)]
    fn test_dynamic_backrun_value_public(
        observed_in: U256,
        wallet_balance: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        max_fee_per_gas: u128,
    ) -> Result<U256, AppError> {
        Self::dynamic_backrun_value(
            observed_in,
            wallet_balance,
            slippage_bps,
            gas_limit_hint,
            max_fee_per_gas,
        )
    }

    fn parse_v3_path(path: &[u8]) -> Option<ParsedV3Path> {
        const ADDRESS_BYTES: usize = 20;
        const FEE_BYTES: usize = 3;
        const HOP_BYTES: usize = ADDRESS_BYTES + FEE_BYTES;

        // Need at least two tokens (one hop).
        if path.len() < ADDRESS_BYTES + HOP_BYTES {
            return None;
        }

        let mut tokens = Vec::new();
        let mut fees = Vec::new();

        // First token
        let first = path.get(..ADDRESS_BYTES)?;
        tokens.push(Address::from_slice(first));

        let mut cursor = ADDRESS_BYTES;
        while cursor + HOP_BYTES <= path.len() {
            let fee_bytes = path.get(cursor..cursor + FEE_BYTES)?;
            let token_bytes = path.get(cursor + FEE_BYTES..cursor + HOP_BYTES)?;

            let fee = U24::try_from_be_slice(fee_bytes).map(|v| v.to::<u32>())?;
            if !Self::v3_fee_sane(fee) {
                return None;
            }

            tokens.push(Address::from_slice(token_bytes));
            fees.push(fee);

            cursor += HOP_BYTES;

            // Bound hop explosion early.
            if tokens.len() > 4 {
                return None;
            }
        }

        // Cursor must land exactly at the end (no trailing junk) and have at least one hop.
        if cursor != path.len() || tokens.len() < 2 {
            return None;
        }
        if !Self::validate_v3_tokens(&tokens) {
            return None;
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

    fn build_v3_swap_payload(
        &self,
        router: Address,
        path: Vec<u8>,
        amount_in: U256,
        amount_out_min: U256,
        recipient: Address,
    ) -> Vec<u8> {
        let deadline = current_unix().saturating_add(60);
        UniV3Router::new(router, self.http_provider.clone())
            .exactInput(UniV3Router::ExactInputParams {
                path: path.into(),
                recipient,
                deadline: U256::from(deadline),
                amountIn: amount_in,
                amountOutMinimum: amount_out_min,
            })
            .calldata()
            .to_vec()
    }

    fn build_v2_swap_payload(
        &self,
        path: Vec<Address>,
        amount_in: U256,
        amount_out_min: U256,
        recipient: Address,
        use_flashloan: bool,
    ) -> Vec<u8> {
        let deadline = U256::from(current_unix().saturating_add(60));

        // Buy path: wrapped_native -> token (or multi-hop starting with wrapped)
        if path.first().copied() == Some(self.wrapped_native) {
            if use_flashloan {
                // We hold wrapped native as ERC20; use token-for-token swap.
                UniV2Router::swapExactTokensForTokensCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            } else {
                // We pay native ETH; value is set on tx, calldata uses ETH entrypoint.
                UniV2Router::swapExactETHForTokensCall {
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            }
        } else {
            // Sell path: token -> wrapped_native (potentially multi-hop)
            if use_flashloan {
                UniV2Router::swapExactTokensForTokensCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            } else {
                UniV2Router::swapExactTokensForETHCall {
                    amountIn: amount_in,
                    amountOutMin: amount_out_min,
                    path,
                    to: recipient,
                    deadline,
                }
                .abi_encode()
            }
        }
    }

    async fn build_v2_swap(
        &self,
        router: Address,
        path: Vec<Address>,
        amount_in: U256,
        slippage_bps: u64,
        gas_limit_hint: u64,
        gas_multiplier_num: u64,
        gas_multiplier_den: u64,
        gas_floor: u64,
        use_flashloan: bool,
        recipient: Address,
        strict_liquidity: bool,
    ) -> Result<Option<V2SwapBuild>, AppError> {
        let router_contract = UniV2Router::new(router, self.http_provider.clone());
        let access_list = Self::build_access_list(router, &path);

        let expected_out = if let Some(q) = self.reserve_cache.quote_v2_path(&path, amount_in) {
            q
        } else {
            let quote_path = path.clone();
            let quote_contract = router_contract.clone();
            let quote_value = amount_in;
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
            .map_err(|e| AppError::Strategy(format!("V2 quote failed: {}", e)))?;
            *quote
                .last()
                .ok_or_else(|| AppError::Strategy("V2 quote missing amounts".into()))?
        };

        let ratio_ppm = Self::price_ratio_ppm(expected_out, amount_in);
        if ratio_ppm < U256::from(1_000u64) {
            if strict_liquidity {
                return Err(AppError::Strategy("V2 liquidity too low".into()));
            } else {
                return Ok(None);
            }
        }

        let min_out = expected_out.saturating_mul(U256::from(10_000u64 - slippage_bps))
            / U256::from(10_000u64);
        let calldata =
            self.build_v2_swap_payload(path.clone(), amount_in, min_out, recipient, use_flashloan);

        let mut gas_limit = gas_limit_hint
            .saturating_mul(gas_multiplier_num)
            .checked_div(gas_multiplier_den)
            .unwrap_or(gas_floor);
        if gas_limit < gas_floor {
            gas_limit = gas_floor;
        }

        let tx_value = if path.first().copied() == Some(self.wrapped_native) && !use_flashloan {
            amount_in
        } else {
            U256::ZERO
        };

        Ok(Some(V2SwapBuild {
            expected_out,
            calldata,
            access_list,
            gas_limit,
            tx_value,
        }))
    }

    async fn maybe_rebalance_inventory(&self) -> Result<(), AppError> {
        let mut guard = self.last_rebalance.lock().await;
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

        // Use a single nonce snapshot for this maintenance flow.
        let mut nonce_cursor = self.nonce_manager.get_next_nonce().await?;

        // Quote token -> wrapped_native on V2 (liquidity check)
        let router_contract = UniV2Router::new(router, self.http_provider.clone());
        let sell_path = vec![token, self.wrapped_native];
        let sell_amount = bal;
        let expected_out =
            if let Some(q) = self.reserve_cache.quote_v2_path(&sell_path, sell_amount) {
                q
            } else {
                let quote_path = sell_path.clone();
                let quote_contract = router_contract.clone();
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
                expected_out
            };
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
        let min_out = expected_out.saturating_mul(U256::from(10_000u64 - self.slippage_bps))
            / U256::from(10_000u64);
        let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 300);

        // Allowance
        if self
            .needs_approval(token, router, sell_amount)
            .await
            .unwrap_or(true)
        {
            let nonce = nonce_cursor;
            nonce_cursor = nonce_cursor.saturating_add(1);
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

        let nonce_sell = nonce_cursor;
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
        let mut request = TransactionRequest {
            from: Some(self.signer.address()),
            to: Some(TxKind::Call(router)),
            max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
            max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(U256::ZERO),
            input: TransactionInput::new(calldata.clone().into()),
            nonce: Some(nonce_sell),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let access_list = self
            .apply_access_list(&mut request, Self::build_access_list(router, &[token]))
            .await;
        let (raw, _, _) = self.sign_with_access_list(request, access_list).await?;
        let _ = self.bundle_sender.send_bundle(&[raw], self.chain_id).await;

        Ok(())
    }

    async fn emergency_exit_inventory(&self, reason: &str) {
        let routers: Vec<Address> = self.router_allowlist.iter().copied().collect();
        if routers.is_empty() {
            tracing::warn!(target: "inventory", reason=%reason, "No routers available for emergency exit");
            return;
        }

        let tokens: Vec<Address> = self.inventory_tokens.iter().map(|t| *t).collect();
        for token in tokens {
            for router in routers.iter().copied() {
                match self.rebalance_token(token, router).await {
                    Ok(_) => {
                        tracing::warn!(
                            target: "inventory",
                            reason=%reason,
                            token=%format!("{:#x}", token),
                            router=%format!("{:#x}", router),
                            "Emergency exit attempted"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "inventory",
                            reason=%reason,
                            token=%format!("{:#x}", token),
                            router=%format!("{:#x}", router),
                            error=%e,
                            "Emergency exit failed, trying next router"
                        );
                        continue;
                    }
                }
            }
        }
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

    async fn needs_approval(
        &self,
        token: Address,
        spender: Address,
        required: U256,
    ) -> Result<bool, AppError> {
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
        let fallback = Self::build_access_list(spender, &[token]);
        let (raw, request, _) = self
            .sign_swap_request(
                token,
                gas_limit,
                U256::ZERO,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                calldata,
                fallback,
            )
            .await?;

        Ok(ApproveTx { raw, request })
    }

    async fn build_executor_wrapper(
        &self,
        approval: Option<&ApproveTx>,
        backrun: &BackrunTx,
        gas_fees: &GasFees,
        gas_limit_hint: u64,
        nonce: u64,
    ) -> Result<Option<(Vec<u8>, TransactionRequest, B256)>, AppError> {
        let exec_addr = match self.executor {
            Some(addr) => addr,
            None => return Ok(None),
        };

        // Guard: avoid wrapping flashloan legs in the executor wrapper until repay/allowance handling is explicit.
        if backrun.uses_flashloan {
            return Ok(None);
        }

        let mut targets = Vec::new();
        let mut payloads = Vec::new();
        let mut values = Vec::new();
        if let Some(app) = approval {
            if let Some(TxKind::Call(addr)) = app.request.to {
                targets.push(addr);
                let bytes = app.request.input.clone().into_input().unwrap_or_default();
                payloads.push(bytes);
                values.push(U256::ZERO);
            }
        }
        if let Some(TxKind::Call(addr)) = backrun.request.to {
            targets.push(addr);
            let bytes = backrun
                .request
                .input
                .clone()
                .into_input()
                .unwrap_or_default();
            payloads.push(bytes);
            values.push(backrun.value);
        }

        // If the backrun leaves the executor holding WETH (e.g., V3 exactInput),
        // unwrap it to native ETH so the bribe check passes.
        let unwrap_weth = (backrun.unwrap_to_native
            || (backrun.router_kind == RouterKind::V3Like
                && backrun.expected_out_token == self.wrapped_native))
            && backrun.expected_out > U256::ZERO;
        if unwrap_weth {
            targets.push(self.wrapped_native);
            let mut withdraw_calldata = Vec::with_capacity(4 + 32);
            withdraw_calldata.extend_from_slice(&[0x2e, 0x1a, 0x7d, 0x4d]); // withdraw(uint256)
            withdraw_calldata.extend_from_slice(&backrun.expected_out.to_be_bytes::<32>());
            payloads.push(Bytes::from(withdraw_calldata));
            values.push(U256::ZERO);
        }

        if targets.is_empty() {
            return Ok(None);
        }

        let mut gas_limit = backrun
            .request
            .gas
            .unwrap_or(gas_limit_hint)
            .saturating_add(approval.and_then(|a| a.request.gas).unwrap_or(0))
            .saturating_add(80_000);

        if unwrap_weth {
            gas_limit = gas_limit.saturating_add(30_000);
        }

        if gas_limit < 150_000 {
            gas_limit = 150_000;
        }

        let mut bribe = U256::ZERO;
        if self.executor_bribe_bps > 0 {
            let base = U256::from(gas_limit).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
            bribe =
                base.saturating_mul(U256::from(self.executor_bribe_bps)) / U256::from(10_000u64);
        }
        let bribe_recipient = self.executor_bribe_recipient.unwrap_or(Address::ZERO);

        let total_value = values
            .iter()
            .copied()
            .fold(U256::ZERO, |acc, v| acc.saturating_add(v))
            .saturating_add(bribe);

        let exec_call = UnifiedHardenedExecutor::executeBundleCall {
            targets,
            payloads,
            values,
            bribeRecipient: bribe_recipient,
            bribeAmount: bribe,
            allowPartial: true,
            balanceCheckToken: self.wrapped_native,
        };
        let calldata = exec_call.abi_encode();

        let (raw, request, hash) = self
            .sign_swap_request(
                exec_addr,
                gas_limit,
                total_value,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                nonce,
                calldata,
                AccessList::default(),
            )
            .await?;

        Ok(Some((raw, request, hash)))
    }

    fn should_use_flashloan(
        &self,
        required_value: U256,
        wallet_balance: U256,
        gas_fees: &GasFees,
    ) -> bool {
        if !self.flashloan_enabled || self.executor.is_none() || self.dry_run {
            return false;
        }
        // If balance can't cover notional + small buffer, flashloan.
        let safety_buffer = U256::from(2_000_000_000_000_000u128); // 0.002 ETH
        if wallet_balance < required_value.saturating_add(safety_buffer) {
            return true;
        }
        // Estimate extra gas overhead for flashloan path; if remaining balance after trade is below this, prefer flashloan.
        let overhead_gas = U256::from(180_000u64);
        let overhead_cost = overhead_gas.saturating_mul(U256::from(gas_fees.max_fee_per_gas));
        let remaining = wallet_balance.saturating_sub(required_value);
        remaining < overhead_cost
    }

    async fn build_flashloan_transaction(
        &self,
        executor: Address,
        asset: Address,
        amount: U256,
        router: Address,
        swap_payload: Vec<u8>,
        approve_token: Option<Address>,
        gas_limit_hint: u64,
        gas_fees: &GasFees,
        nonce: u64,
    ) -> Result<(Vec<u8>, TransactionRequest, B256), AppError> {
        let mut targets = Vec::new();
        let mut values = Vec::new();
        let mut payloads = Vec::new();

        if let Some(tok) = approve_token {
            let approve = ERC20::approveCall {
                spender: router,
                amount: U256::MAX,
            };
            targets.push(tok);
            values.push(U256::ZERO);
            payloads.push(Bytes::from(approve.abi_encode()));
        }

        targets.push(router);
        values.push(U256::ZERO);
        payloads.push(Bytes::from(swap_payload));

        let callback = FlashCallbackData {
            targets,
            values,
            payloads,
        };
        let params = callback.abi_encode();

        let exec_call = UnifiedHardenedExecutor::executeFlashLoanCall {
            assets: vec![asset],
            amounts: vec![amount],
            params: Bytes::from(params),
        };
        let calldata = exec_call.abi_encode();

        let mut gas_limit = gas_limit_hint.saturating_add(150_000);
        if gas_limit < 220_000 {
            gas_limit = 220_000;
        }

        let request = Self::flashloan_request_template(
            self.signer.address(),
            executor,
            gas_fees,
            gas_limit,
            nonce,
            calldata,
            self.chain_id,
        );

        self.sign_with_access_list(request, AccessList::default())
            .await
    }

    fn flashloan_request_template(
        from: Address,
        executor: Address,
        gas_fees: &GasFees,
        gas_limit: u64,
        nonce: u64,
        calldata: Vec<u8>,
        chain_id: u64,
    ) -> TransactionRequest {
        TransactionRequest {
            from: Some(from),
            to: Some(TxKind::Call(executor)),
            max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
            max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
            gas: Some(gas_limit),
            value: Some(U256::ZERO),
            input: TransactionInput::new(calldata.into()),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            ..Default::default()
        }
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

        let (expected_tokens, calldata, value, gas_limit, access_list) = match observed.router_kind
        {
            RouterKind::V2Like => {
                let path = vec![self.wrapped_native, target_token];
                let swap = self
                    .build_v2_swap(
                        observed.router,
                        path,
                        value,
                        self.slippage_bps,
                        gas_limit_hint,
                        11,
                        10,
                        160_000,
                        false,
                        self.signer.address(),
                        false,
                    )
                    .await?;
                let Some(swap) = swap else {
                    return Ok(None);
                };
                (
                    swap.expected_out,
                    swap.calldata,
                    swap.tx_value,
                    swap.gas_limit,
                    swap.access_list,
                )
            }
            RouterKind::V3Like => {
                if observed.path.len() < 2 {
                    return Err(AppError::Strategy("V3 path too short".into()));
                }
                let recipient = self.signer.address();
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
                let access_list = Self::build_access_list(observed.router, &observed.path);
                let calldata = self.build_v3_swap_payload(
                    observed.router,
                    path_bytes.clone(),
                    value,
                    min_out,
                    recipient,
                );
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

        let (raw, request, hash) = self
            .sign_swap_request(
                observed.router,
                gas_limit,
                value,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                calldata,
                access_list,
            )
            .await?;

        Ok(Some(FrontRunTx {
            raw,
            hash,
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
        use_flashloan: bool,
        nonce: u64,
    ) -> Result<BackrunTx, AppError> {
        let target_token = Self::target_token(&observed.path, self.wrapped_native)
            .ok_or_else(|| AppError::Strategy("Unable to derive target token".into()))?;

        if wallet_balance.is_zero() {
            return Err(AppError::Strategy(
                "No balance available for backrun".into(),
            ));
        }

        let expected_out_token;
        let mut unwrap_to_native = false;
        let (value, expected_out, calldata, access_list) = if let Some(tokens_in) =
            token_in_override
        {
            match observed.router_kind {
                RouterKind::V2Like => {
                    expected_out_token = self.wrapped_native;
                    let router_contract =
                        UniV2Router::new(observed.router, self.http_provider.clone());
                    let sell_path = vec![target_token, self.wrapped_native];
                    let sell_amount = tokens_in;
                    let expected_out = if let Some(q) =
                        self.reserve_cache.quote_v2_path(&sell_path, sell_amount)
                    {
                        q
                    } else {
                        let quote_path = sell_path.clone();
                        let quote_contract = router_contract.clone();
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
                        *quote.last().ok_or_else(|| {
                            AppError::Strategy("Sell quote missing amounts".into())
                        })?
                    };
                    // Liquidity sanity: require minimal return relative to notional (avoid >99.9% impact)
                    let ratio_ppm = Self::price_ratio_ppm(expected_out, sell_amount);
                    if ratio_ppm < U256::from(1_000u64) {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run {
                        // Probe toxicity before trusting expected_out
                        if !self
                            .probe_v2_sell_for_toxicity(
                                target_token,
                                observed.router,
                                sell_amount,
                                expected_out,
                            )
                            .await?
                        {
                            return Err(AppError::Strategy(
                                "toxic token detected on backrun".into(),
                            ));
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
                    expected_out_token = self.wrapped_native;
                    unwrap_to_native = true;
                    let rev_path = Self::reverse_v3_path(&observed.path, &observed.v3_fees)
                        .ok_or_else(|| AppError::Strategy("Reverse V3 path failed".into()))?;
                    let expected_out = self.quote_v3_path(&rev_path, tokens_in).await?;
                    let ratio_ppm = Self::price_ratio_ppm(expected_out, tokens_in);
                    if ratio_ppm < U256::from(1_000u64) {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run {
                        if !self
                            .probe_v3_sell_for_toxicity(
                                observed.router,
                                rev_path.clone(),
                                tokens_in,
                                expected_out,
                            )
                            .await?
                        {
                            self.mark_toxic_token(target_token, "v3_probe_shortfall");
                            return Err(AppError::Strategy(
                                "toxic token detected on backrun".into(),
                            ));
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
                    let value = StrategyExecutor::dynamic_backrun_value(
                        observed.amount_in,
                        wallet_balance,
                        self.slippage_bps,
                        gas_limit_hint,
                        max_fee_per_gas,
                    )?;

                    let path = vec![self.wrapped_native, target_token];
                    let recipient = if use_flashloan {
                        self.executor.unwrap_or(self.signer.address())
                    } else {
                        self.signer.address()
                    };
                    let swap = self
                        .build_v2_swap(
                            observed.router,
                            path.clone(),
                            value,
                            self.slippage_bps,
                            gas_limit_hint,
                            12,
                            10,
                            200_000,
                            use_flashloan,
                            recipient,
                            true,
                        )
                        .await?;
                    let Some(swap) = swap else {
                        return Err(AppError::Strategy("V2 liquidity too low".into()));
                    };
                    expected_out_token = target_token;
                    (
                        swap.tx_value,
                        swap.expected_out,
                        swap.calldata,
                        swap.access_list,
                    )
                }
                RouterKind::V3Like => {
                    return Err(AppError::Strategy(
                        "V3 double swap without owned tokens not supported".into(),
                    ));
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

        let flashloan_ok = use_flashloan && self.executor.is_some() && token_in_override.is_none();
        if flashloan_ok {
            let exec_addr = self
                .executor
                .ok_or_else(|| AppError::Strategy("Missing flashloan executor".into()))?;
            let gas = GasFees {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                base_fee_per_gas: 0,
            };
            let (raw, request, hash) = self
                .build_flashloan_transaction(
                    exec_addr,
                    self.wrapped_native,
                    value,
                    observed.router,
                    calldata.clone(),
                    Some(self.wrapped_native),
                    gas_limit,
                    &gas,
                    nonce,
                )
                .await?;
            return Ok(BackrunTx {
                raw,
                hash,
                to: exec_addr,
                value: U256::ZERO,
                request,
                expected_out,
                expected_out_token,
                unwrap_to_native,
                uses_flashloan: true,
                router_kind: observed.router_kind,
            });
        }

        let (raw, request, hash) = self
            .sign_swap_request(
                observed.router,
                gas_limit,
                value,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                calldata,
                access_list,
            )
            .await?;

        Ok(BackrunTx {
            raw,
            hash,
            to: observed.router,
            value,
            request,
            expected_out,
            expected_out_token,
            unwrap_to_native,
            uses_flashloan: false,
            router_kind: observed.router_kind,
        })
    }

    async fn await_receipt(&self, hash: &B256) -> Result<bool, AppError> {
        for _ in 0..3 {
            if let Ok(Some(rcpt)) = self.http_provider.get_transaction_receipt(*hash).await {
                let block_num = rcpt.block_number;
                let status = rcpt.status();
                let _ = self.db.update_status(
                    &format!("{:#x}", hash),
                    block_num.map(|b| b as i64),
                    Some(status),
                );
                return Ok(status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(false)
    }
}

#[allow(dead_code)]
fn wei_to_eth_f64(value: U256) -> f64 {
    units_to_float(value, 18)
}

#[allow(dead_code)]
fn units_to_float(value: U256, decimals: u8) -> f64 {
    let scale = 10f64.powi(decimals as i32);
    let num = value.to_string().parse::<f64>().unwrap_or(0.0);
    num / scale
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
        let decoded = StrategyExecutor::decode_swap_input(WETH_MAINNET, &data, U256::from(0u64))
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
    fn rejects_invalid_v3_path_length() {
        // Missing last token bytes.
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 1u8, 244u8]); // fee 500
        path.extend_from_slice(&[1u8; 10]); // truncated address
        assert!(StrategyExecutor::parse_v3_path(&path).is_none());
    }

    #[test]
    fn rejects_invalid_v3_fee() {
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(WETH_MAINNET.as_slice());
        path.extend_from_slice(&[0u8, 0u8, 1u8]); // fee 1 (not standard)
        path.extend_from_slice([2u8; 20].as_slice());
        assert!(StrategyExecutor::parse_v3_path(&path).is_none());
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

    #[test]
    fn price_ratio_handles_zero_and_scales() {
        assert_eq!(StrategyExecutor::test_price_ratio_ppm_public(U256::from(10u64), U256::ZERO), U256::ZERO);
        let ratio = StrategyExecutor::test_price_ratio_ppm_public(U256::from(2u64), U256::from(1u64));
        assert_eq!(ratio, U256::from(2_000_000u64));
    }

    #[test]
    fn backrun_divisors_change_with_balance() {
        assert_eq!(
            StrategyExecutor::test_backrun_divisors_public(U256::from(50_000_000_000_000_000u128)),
            (4, 6)
        );
        assert_eq!(
            StrategyExecutor::test_backrun_divisors_public(U256::from(300_000_000_000_000_000u128)),
            (3, 5)
        );
        assert_eq!(
            StrategyExecutor::test_backrun_divisors_public(U256::from(1_000_000_000_000_000_000u128)),
            (2, 4)
        );
        assert_eq!(
            StrategyExecutor::test_backrun_divisors_public(U256::from(3_000_000_000_000_000_000u128)),
            (2, 3)
        );
    }

    #[test]
    fn dynamic_profit_floor_scales_up() {
        let floor_small = StrategyExecutor::test_dynamic_profit_floor_public(U256::from(10_000_000_000_000_000u128));
        let floor_large = StrategyExecutor::test_dynamic_profit_floor_public(U256::from(20_000_000_000_000_000_000u128));
        assert!(floor_large > floor_small, "profit floor should scale with balance");
        assert!(floor_small >= *MIN_PROFIT_THRESHOLD_WEI, "floor should never drop below constant");
    }

    #[test]
    fn dynamic_backrun_value_respects_minimum() {
        let value = StrategyExecutor::test_dynamic_backrun_value_public(
            U256::from(1u64),
            U256::from(10_000_000_000_000_000_000u128),
            500,
            220_000,
            50_000_000_000,
        )
        .expect("backrun value");
        assert!(
            value >= U256::from(100_000_000_000_000u64),
            "should enforce minimum backrun size"
        );
    }

    #[test]
    fn dynamic_backrun_value_caps_by_wallet_and_gas_buffer() {
        let wallet = U256::from(50_000_000_000_000_000u128); // 0.05 ETH
        let value = StrategyExecutor::test_dynamic_backrun_value_public(
            U256::from(10_000_000_000_000_000u128),
            wallet,
            500,
            220_000,
            100_000_000_000, // 100 gwei
        )
        .expect("backrun value");
        // With wallet <0.1 ETH, max divisor (4,6) applies; gas buffer will cap to wallet/6.
        assert!(
            value <= wallet / U256::from(6u64),
            "value should be capped by wallet/gas buffer"
        );
    }

    #[test]
    fn flashloan_request_template_sets_fields() {
        let gas_fees = GasFees {
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 5,
            base_fee_per_gas: 0,
        };
        let calldata = vec![0x01, 0x02];
        let req = StrategyExecutor::flashloan_request_template(
            Address::from([1u8; 20]),
            Address::from([2u8; 20]),
            &gas_fees,
            300_000,
            7,
            calldata.clone(),
            1,
        );
        assert_eq!(req.nonce, Some(7));
        assert_eq!(req.gas, Some(300_000));
        assert_eq!(req.max_fee_per_gas, Some(100));
        assert_eq!(req.max_priority_fee_per_gas, Some(5));
        assert_eq!(req.to, Some(TxKind::Call(Address::from([2u8; 20]))));
        assert_eq!(req.from, Some(Address::from([1u8; 20])));
        assert_eq!(req.chain_id, Some(1));
        assert_eq!(
            req.input.clone().into_input().unwrap_or_default(),
            calldata
        );
    }

    #[test]
    fn detects_nonce_gap_errors() {
        let gap_errs = [
            AppError::Strategy("nonce too high".into()),
            AppError::Strategy("Nonce gap detected".into()),
            AppError::Strategy("missing nonce".into()),
        ];
        for e in gap_errs {
            assert!(StrategyExecutor::is_nonce_gap_error(&e));
        }

        let other = AppError::Strategy("insufficient funds".into());
        assert!(!StrategyExecutor::is_nonce_gap_error(&other));
    }
}
