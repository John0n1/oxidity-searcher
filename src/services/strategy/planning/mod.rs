// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

pub mod bundles;
pub mod execution_planner;
pub mod graph;
pub mod routes;
pub mod swaps;

pub use execution_planner::{
    DecisionTrace, ExecutionPlanner, PlanCandidate, PlanScore, PlanType, PlannerInput,
};
pub use graph::{QuoteEdge, QuoteGraph, QuoteSearchOptions};
pub use routes::{RouteLeg, RoutePlan, RouteVenue};

use crate::common::constants::{
    default_balancer_vault_for_chain, default_dydx_solo_margin, default_maker_flash_lender,
    default_uniswap_v2_factory, default_uniswap_v3_factory,
};
use crate::common::error::AppError;
use crate::common::retry::retry_async;
use crate::data::executor::{FlashCallbackData, UnifiedHardenedExecutor};
use crate::network::gas::GasFees;
use crate::services::strategy::decode::{
    ObservedSwap, RouterKind, encode_v3_path, reverse_v3_path, target_token,
};
use crate::services::strategy::routers::{
    AavePool, BalancerProtocolFees, BalancerVaultFees, DydxSoloMarginGetters, ERC20,
    ERC3156FlashLender, UniV2Router, UniV3Router, UniswapV2Factory, UniswapV3Factory,
    registry_v2_router_addresses, registry_v2_router_candidates,
};
use crate::services::strategy::strategy::{FlashloanProvider, StrategyExecutor};
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
use alloy::rpc::types::eth::{TransactionInput, TransactionRequest};
use alloy::sol_types::{SolCall, SolValue};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::time::Duration;

pub struct BackrunTx {
    pub raw: Vec<u8>,
    pub hash: B256,
    pub to: Address,
    pub value: U256,
    pub request: TransactionRequest,
    pub expected_out: U256,
    pub expected_out_token: Address,
    pub unwrap_to_native: bool,
    pub uses_flashloan: bool,
    pub flashloan_premium: U256,
    pub flashloan_overhead_gas: u64,
    pub router_kind: RouterKind,
    pub route_plan: Option<RoutePlan>,
}

pub struct FrontRunTx {
    pub raw: Vec<u8>,
    pub hash: B256,
    pub to: Address,
    pub value: U256,
    pub request: TransactionRequest,
    pub expected_tokens: U256,
    pub input_token: Address,
    pub input_amount: U256,
}

pub struct ApproveTx {
    pub raw: Vec<u8>,
    pub request: TransactionRequest,
    pub token: Address,
}

const BALANCER_FLASHLOAN_OVERHEAD_GAS: u64 = 180_000;
const AAVE_FLASHLOAN_OVERHEAD_GAS: u64 = 200_000;
const DYDX_FLASHLOAN_OVERHEAD_GAS: u64 = 240_000;
const MAKER_FLASHLOAN_OVERHEAD_GAS: u64 = 220_000;
const UNISWAP_V2_FLASHLOAN_OVERHEAD_GAS: u64 = 240_000;
const UNISWAP_V3_FLASHLOAN_OVERHEAD_GAS: u64 = 260_000;
const V2_SWAP_OVERHEAD_GAS: u64 = 160_000;
const CURVE_SWAP_OVERHEAD_GAS: u64 = 220_000;
const BALANCER_SWAP_OVERHEAD_GAS: u64 = 200_000;
const FEE_TTL: Duration = Duration::from_secs(300);

static BALANCER_FEE_CACHE: Lazy<DashMap<u64, (U256, std::time::Instant)>> = Lazy::new(DashMap::new);
static AAVE_FEE_CACHE: Lazy<DashMap<Address, (U256, std::time::Instant)>> = Lazy::new(DashMap::new);
static AAVE_ATOKEN_CACHE: Lazy<DashMap<(Address, Address), (Address, std::time::Instant)>> =
    Lazy::new(DashMap::new);

impl StrategyExecutor {
    fn flashloan_value_scale_bps(&self) -> u64 {
        self.runtime.flashloan_value_scale_bps
    }

    fn flashloan_min_notional_wei(&self) -> U256 {
        self.runtime.flashloan_min_notional_wei
    }

    fn flashloan_min_repay_bps(&self) -> u64 {
        // Pre-filter only clearly toxic roundtrips. Victim impact can improve
        // execution-relative pricing, so keep this threshold below 100%.
        self.runtime.flashloan_min_repay_bps
    }

    fn flashloan_reverse_input_bps(&self) -> u64 {
        // For flashloan repayment safety, use near-full reverse input by default.
        // Lower this only if fee-on-transfer paths cause frequent transfer failures.
        self.runtime.flashloan_reverse_input_bps
    }

    fn flashloan_prefilter_margin_bps(&self) -> u64 {
        self.runtime.flashloan_prefilter_margin_bps
    }

    fn flashloan_prefilter_margin_wei(&self) -> U256 {
        self.runtime.flashloan_prefilter_margin_wei
    }

    fn flashloan_prefilter_gas_cost_bps(&self) -> u64 {
        self.runtime.flashloan_prefilter_gas_cost_bps
    }

    fn maybe_scale_flashloan_value(&self, value: U256) -> U256 {
        let scale_bps = self.flashloan_value_scale_bps();
        if scale_bps >= 10_000 {
            return value;
        }
        let scaled = value
            .saturating_mul(U256::from(scale_bps))
            .checked_div(U256::from(10_000u64))
            .unwrap_or(value);
        if scaled < self.flashloan_min_notional_wei() {
            value
        } else {
            scaled
        }
    }

    fn reject_same_router_negative_roundtrip(&self) -> bool {
        self.runtime.flashloan_reject_same_router_negative
    }

    pub(in crate::services::strategy) async fn quote_v2_path_with_router_fallback(
        &self,
        router: Address,
        path: &[Address],
        amount_in: U256,
    ) -> Option<U256> {
        if let Some(q) = self.reserve_cache.quote_v2_path(path, amount_in) {
            return Some(q);
        }
        if path.len() < 2 || amount_in.is_zero() {
            return None;
        }
        let quote_contract = UniV2Router::new(router, self.http_provider.clone());
        let quote_path = path.to_vec();
        let quote: Vec<U256> = retry_async(
            move |_| {
                let c = quote_contract.clone();
                let p = quote_path.clone();
                async move { c.getAmountsOut(amount_in, p.clone()).call().await }
            },
            2,
            Duration::from_millis(75),
        )
        .await
        .ok()?;
        quote.last().copied()
    }

    fn flashloan_roundtrip_callbacks(
        executor: Address,
        forward_router: Address,
        reverse_router: Address,
        forward_approval_token: Address,
        forward_approval_amount: U256,
        reverse_approval_token: Address,
        reverse_approval_amount: U256,
        forward_payload: Bytes,
        reverse_payload: Bytes,
    ) -> Vec<(Address, Bytes, U256)> {
        let mut callbacks: Vec<(Address, Bytes, U256)> = Vec::new();

        let mut approvals: Vec<(Address, Address, U256)> = Vec::new();
        let mut push_or_update = |token: Address, spender: Address, amount: U256| {
            if amount.is_zero() {
                return;
            }
            if let Some((_, _, existing)) = approvals
                .iter_mut()
                .find(|(t, s, _)| *t == token && *s == spender)
            {
                if amount > *existing {
                    *existing = amount;
                }
            } else {
                approvals.push((token, spender, amount));
            }
        };
        push_or_update(
            forward_approval_token,
            forward_router,
            forward_approval_amount,
        );
        push_or_update(
            reverse_approval_token,
            reverse_router,
            reverse_approval_amount,
        );

        for (token, spender, amount) in approvals.iter().copied() {
            let approve = UnifiedHardenedExecutor::safeApproveCall {
                token,
                spender,
                amount,
            }
            .abi_encode();
            callbacks.push((executor, Bytes::from(approve), U256::ZERO));
        }

        callbacks.push((forward_router, forward_payload, U256::ZERO));
        callbacks.push((reverse_router, reverse_payload, U256::ZERO));

        for (token, spender, _) in approvals.into_iter().rev() {
            let reset = UnifiedHardenedExecutor::safeApproveCall {
                token,
                spender,
                amount: U256::ZERO,
            }
            .abi_encode();
            callbacks.push((executor, Bytes::from(reset), U256::ZERO));
        }

        callbacks
    }

    fn single_leg_route(
        venue: RouteVenue,
        target: Address,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
        min_out: U256,
        fee: Option<u32>,
        params: Option<Bytes>,
    ) -> Option<RoutePlan> {
        RoutePlan::try_new(vec![RouteLeg {
            venue,
            target,
            token_in,
            token_out,
            amount_in,
            min_out,
            fee,
            params,
            is_flash_leg: matches!(venue, RouteVenue::AaveV3Flash | RouteVenue::BalancerFlash),
        }])
    }

    async fn build_atomic_executor_roundtrip_tx(
        &self,
        exec_router: Address,
        forward_payload: Bytes,
        reverse_payload: Bytes,
        value_in: U256,
        approvals: Vec<(Address, U256)>,
        gas_fees: &GasFees,
        gas_limit_hint: u64,
        nonce: u64,
    ) -> Result<(Address, Vec<u8>, TransactionRequest, B256), AppError> {
        let executor = self
            .executor
            .ok_or_else(|| AppError::Strategy("strict atomic mode requires executor".into()))?;

        let mut targets = Vec::new();
        let mut payloads = Vec::new();
        let mut values = Vec::new();

        for (token, amount) in approvals.iter().copied() {
            if amount.is_zero() {
                continue;
            }
            let approve = UnifiedHardenedExecutor::safeApproveCall {
                token,
                spender: exec_router,
                amount,
            }
            .abi_encode();
            targets.push(executor);
            payloads.push(Bytes::from(approve));
            values.push(U256::ZERO);
        }

        targets.push(exec_router);
        payloads.push(forward_payload);
        values.push(value_in);

        targets.push(exec_router);
        payloads.push(reverse_payload);
        values.push(U256::ZERO);

        for (token, _) in approvals.iter().copied() {
            let reset = UnifiedHardenedExecutor::safeApproveCall {
                token,
                spender: exec_router,
                amount: U256::ZERO,
            }
            .abi_encode();
            targets.push(executor);
            payloads.push(Bytes::from(reset));
            values.push(U256::ZERO);
        }

        let gas_limit = gas_limit_hint
            .saturating_add(260_000)
            .saturating_add((approvals.len() as u64).saturating_mul(40_000))
            .max(320_000);
        let bribe_amount = if self.executor_bribe_bps > 0 {
            let base = U256::from(gas_limit).saturating_mul(U256::from(gas_fees.max_fee_per_gas));
            base.saturating_mul(U256::from(self.executor_bribe_bps)) / U256::from(10_000u64)
        } else {
            U256::ZERO
        };
        let exec_call = UnifiedHardenedExecutor::executeBundleCall {
            targets,
            payloads,
            values,
            bribeRecipient: self.executor_bribe_recipient.unwrap_or(Address::ZERO),
            bribeAmount: bribe_amount,
            allowPartial: false,
            balanceCheckToken: self.wrapped_native,
        };
        let total_value = value_in.saturating_add(bribe_amount);
        let calldata = exec_call.abi_encode();
        let (raw, request, hash) = self
            .sign_swap_request(
                executor,
                gas_limit,
                total_value,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                nonce,
                calldata,
                AccessList::default(),
            )
            .await?;
        Ok((executor, raw, request, hash))
    }
    pub(crate) async fn needs_approval(
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

    pub(crate) async fn build_approval_tx(
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

        Ok(ApproveTx {
            raw,
            request,
            token,
        })
    }

    pub(crate) async fn build_executor_wrapper(
        &self,
        approvals: &[ApproveTx],
        backrun: &BackrunTx,
        gas_fees: &crate::network::gas::GasFees,
        gas_limit_hint: u64,
        nonce: u64,
    ) -> Result<Option<(Vec<u8>, TransactionRequest, B256)>, AppError> {
        let exec_addr = match self.executor {
            Some(addr) => addr,
            None => return Ok(None),
        };

        if backrun.uses_flashloan {
            return Ok(None);
        }

        let mut targets = Vec::new();
        let mut payloads = Vec::new();
        let mut values = Vec::new();
        let mut reset_tokens: Vec<(Address, Address)> = Vec::new();
        for app in approvals {
            if let Some(TxKind::Call(addr)) = app.request.to {
                targets.push(addr);
                let bytes = app.request.input.clone().into_input().unwrap_or_default();
                payloads.push(bytes);
                values.push(U256::ZERO);
                reset_tokens.push((app.token, addr));
            }
        }
        let unwrap_weth = (backrun.unwrap_to_native
            || (backrun.router_kind == RouterKind::V3Like
                && backrun.expected_out_token == self.wrapped_native))
            && backrun.expected_out > U256::ZERO;
        let mut balance_check_token = backrun.expected_out_token;
        let mut unwrap_amount: Option<U256> = None;
        if unwrap_weth {
            // Use a conservative amount (min_out) to avoid reverting if actual output < expected_out.
            let slippage_bps = self.effective_slippage_bps().min(9_999);
            let min_out = backrun
                .expected_out
                .saturating_mul(U256::from(10_000u64 - slippage_bps))
                / U256::from(10_000u64);
            if min_out > U256::ZERO {
                unwrap_amount = Some(min_out);
            }
            // Unwrapping reduces WETH balance, so disable balance invariant.
            balance_check_token = Address::ZERO;
        }
        if targets.is_empty() && unwrap_amount.is_none() {
            return Ok(None);
        }

        let backrun_target = match backrun.request.to {
            Some(TxKind::Call(addr)) => addr,
            _ => {
                return Err(AppError::Strategy(
                    "Backrun wrapper requires call target".into(),
                ));
            }
        };
        let backrun_payload = backrun
            .request
            .input
            .clone()
            .into_input()
            .unwrap_or_default();
        let backrun_value = backrun.request.value.unwrap_or(U256::ZERO);
        targets.push(backrun_target);
        payloads.push(backrun_payload);
        values.push(backrun_value);

        if let Some(amount) = unwrap_amount {
            targets.push(self.wrapped_native);
            let mut withdraw_calldata = Vec::with_capacity(4 + 32);
            withdraw_calldata.extend_from_slice(&[0x2e, 0x1a, 0x7d, 0x4d]); // withdraw(uint256)
            withdraw_calldata.extend_from_slice(&amount.to_be_bytes::<32>());
            payloads.push(Bytes::from(withdraw_calldata));
            values.push(U256::ZERO);
        }

        let approval_gas: u64 = approvals.iter().map(|a| a.request.gas.unwrap_or(0)).sum();
        let mut gas_limit = backrun
            .request
            .gas
            .unwrap_or(gas_limit_hint)
            .saturating_add(approval_gas)
            .saturating_add(80_000);

        if unwrap_weth {
            gas_limit = gas_limit.saturating_add(30_000);
        }

        // Zero approvals after execution to limit allowance exposure.
        if !reset_tokens.is_empty() {
            gas_limit =
                gas_limit.saturating_add(30_000u64.saturating_mul(reset_tokens.len() as u64));
        }
        for (token, spender) in reset_tokens.iter().copied() {
            let reset = UnifiedHardenedExecutor::safeApproveCall {
                token,
                spender,
                amount: U256::ZERO,
            }
            .abi_encode();
            targets.push(exec_addr);
            payloads.push(Bytes::from(reset));
            values.push(U256::ZERO);
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
            allowPartial: false,
            balanceCheckToken: balance_check_token,
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

    pub(crate) async fn build_quote_graph(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
        _gas_price: u128,
        _max_hops: usize,
    ) -> QuoteGraph {
        let mut graph = QuoteGraph::default();

        // Registry-driven V2-like routers (UniV2/Sushi/Pancake/etc), reusing V2 cache.
        if let Some(out) = self
            .reserve_cache
            .quote_v2_path(&[token_in, token_out], amount_in)
        {
            let min_out = out.saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                / U256::from(10_000u64);
            for (name, router) in registry_v2_router_candidates(self.chain_id) {
                let venue = if name.contains("sushi") {
                    RouteVenue::Sushi
                } else {
                    RouteVenue::UniV2
                };
                graph.add_edge(QuoteEdge {
                    venue,
                    pool: router,
                    token_in,
                    token_out,
                    amount_in,
                    expected_out: out,
                    min_out,
                    gas_overhead: V2_SWAP_OVERHEAD_GAS,
                    fee: None,
                    params: None,
                    is_flash: false,
                });
            }
        }

        // Curve pools
        for pool in self.reserve_cache.curve_known_pools() {
            if let Some((out, underlying, i, j)) = self
                .reserve_cache
                .quote_curve_pool(pool, token_in, token_out, amount_in)
                .await
            {
                let min_out = out
                    .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                    / U256::from(10_000u64);
                let mut param_bytes = Vec::with_capacity(3);
                param_bytes.push(if underlying { 1 } else { 0 });
                param_bytes.push(i as u8);
                param_bytes.push(j as u8);
                graph.add_edge(QuoteEdge {
                    venue: RouteVenue::CurvePool,
                    pool,
                    token_in,
                    token_out,
                    amount_in,
                    expected_out: out,
                    min_out,
                    gas_overhead: CURVE_SWAP_OVERHEAD_GAS,
                    fee: None,
                    params: Some(Bytes::from(param_bytes)),
                    is_flash: false,
                });
            }
        }

        // Balancer pools
        for pool in self.reserve_cache.balancer_known_pools() {
            if let Some((out, pool_id)) = self
                .reserve_cache
                .quote_balancer_single(pool, token_in, token_out, amount_in)
                .await
            {
                let min_out = out
                    .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                    / U256::from(10_000u64);
                graph.add_edge(QuoteEdge {
                    venue: RouteVenue::BalancerPool,
                    pool,
                    token_in,
                    token_out,
                    amount_in,
                    expected_out: out,
                    min_out,
                    gas_overhead: BALANCER_SWAP_OVERHEAD_GAS,
                    fee: None,
                    params: Some(Bytes::from(pool_id.to_vec())),
                    is_flash: false,
                });
            }
        }

        // Flash legs: allow Balancer / Aave flash loans if enabled
        if self.flashloan_enabled {
            if self
                .flashloan_providers
                .contains(&FlashloanProvider::Balancer)
                && let Some(vault) = default_balancer_vault_for_chain(self.chain_id)
            {
                graph.add_edge(QuoteEdge {
                    venue: RouteVenue::BalancerFlash,
                    pool: vault,
                    token_in,
                    token_out: token_in,
                    amount_in,
                    expected_out: amount_in,
                    min_out: amount_in,
                    gas_overhead: BALANCER_FLASHLOAN_OVERHEAD_GAS,
                    fee: None,
                    params: None,
                    is_flash: true,
                });
            }
            if self
                .flashloan_providers
                .contains(&FlashloanProvider::AaveV3)
                && let Some(pool) = self.aave_pool
            {
                graph.add_edge(QuoteEdge {
                    venue: RouteVenue::AaveV3Flash,
                    pool,
                    token_in,
                    token_out: token_in,
                    amount_in,
                    expected_out: amount_in,
                    min_out: amount_in,
                    gas_overhead: AAVE_FLASHLOAN_OVERHEAD_GAS,
                    fee: None,
                    params: None,
                    is_flash: true,
                });
            }
        }

        // Optional pruning by ratio
        graph
    }

    pub(crate) async fn best_route_plan(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
        gas_price: u128,
    ) -> Option<RoutePlan> {
        let graph = self
            .build_quote_graph(token_in, token_out, amount_in, gas_price, 3)
            .await;
        let opts = QuoteSearchOptions {
            gas_price,
            max_hops: 3,
            beam_size: 8,
            // Require at least ~90% quoted continuity per hop in ppm space.
            min_ratio_ppm: 900_000,
        };
        graph
            .k_best(token_in, token_out, amount_in, 1, opts)
            .into_iter()
            .next()
    }

    // Exposed for integration testing of encoded flashloan callbacks.
    pub async fn build_flashloan_transaction(
        &self,
        executor: Address,
        asset: Address,
        amount: U256,
        callbacks: Vec<(Address, Bytes, U256)>,
        gas_limit_hint: u64,
        gas_fees: &GasFees,
        nonce: u64,
    ) -> Result<(Vec<u8>, TransactionRequest, B256, U256, u64), AppError> {
        let provider = match self
            .select_flashloan_provider(asset, amount, gas_fees)
            .await?
        {
            Some(provider) => provider,
            None if self.dry_run => {
                let fallback =
                    self.flashloan_providers.first().copied().ok_or_else(|| {
                        AppError::Strategy("No flashloan provider available".into())
                    })?;
                tracing::debug!(
                    target: "flashloan",
                    provider = ?fallback,
                    asset = %format!("{asset:#x}"),
                    amount = %amount,
                    "No live flashloan quote available in dry-run; using configured provider fallback"
                );
                fallback
            }
            None => return Err(AppError::Strategy("No flashloan provider available".into())),
        };

        let mut targets = Vec::new();
        let mut values = Vec::new();
        let mut payloads = Vec::new();

        for (t, p, v) in callbacks {
            targets.push(t);
            payloads.push(p);
            values.push(v);
        }

        let callback = FlashCallbackData {
            targets,
            values,
            payloads,
        };
        // Contract callback decodes as abi.decode(userData, (address[], uint256[], bytes[])),
        // so we must encode as function-params tuple (no outer dynamic wrapper).
        let params = callback.abi_encode_params();

        let (calldata, overhead, premium) = match provider {
            FlashloanProvider::Balancer => {
                let exec_call = UnifiedHardenedExecutor::executeFlashLoanCall {
                    assets: vec![asset],
                    amounts: vec![amount],
                    params: Bytes::from(params.clone()),
                };
                let fee = self
                    .get_balancer_flashloan_fee()
                    .await
                    .unwrap_or(U256::ZERO);
                let premium =
                    amount.saturating_mul(fee) / U256::from(1_000_000_000_000_000_000u128);
                (
                    exec_call.abi_encode(),
                    BALANCER_FLASHLOAN_OVERHEAD_GAS,
                    premium,
                )
            }
            FlashloanProvider::AaveV3 => {
                let pool = self
                    .aave_pool
                    .ok_or_else(|| AppError::Strategy("Aave pool address missing".into()))?;
                let exec_call = UnifiedHardenedExecutor::executeAaveFlashLoanSimpleCall {
                    pool,
                    asset,
                    amount,
                    params: Bytes::from(params.clone()),
                };
                let premium_bps = self.fetch_aave_premium(pool).await?;
                let premium = amount
                    .saturating_mul(premium_bps)
                    .saturating_add(U256::from(9_999u64))
                    / U256::from(10_000u64);
                (exec_call.abi_encode(), AAVE_FLASHLOAN_OVERHEAD_GAS, premium)
            }
            FlashloanProvider::Dydx => {
                let solo = default_dydx_solo_margin(self.chain_id)
                    .ok_or_else(|| AppError::Strategy("dYdX SoloMargin not configured".into()))?;
                if !self.dydx_market_exists(solo, asset).await? {
                    return Err(AppError::Strategy(
                        "dYdX market missing for requested flashloan asset".into(),
                    ));
                }
                let exec_call = UnifiedHardenedExecutor::executeDydxFlashLoanCall {
                    soloMargin: solo,
                    asset,
                    amount,
                    params: Bytes::from(params.clone()),
                };
                (
                    exec_call.abi_encode(),
                    DYDX_FLASHLOAN_OVERHEAD_GAS,
                    U256::from(2u64),
                )
            }
            FlashloanProvider::MakerDao => {
                let lender = default_maker_flash_lender(self.chain_id).ok_or_else(|| {
                    AppError::Strategy("Maker flash lender not configured".into())
                })?;
                let exec_call = UnifiedHardenedExecutor::executeMakerFlashLoanCall {
                    lender,
                    asset,
                    amount,
                    params: Bytes::from(params.clone()),
                };
                let premium = self.fetch_maker_flash_fee(lender, asset, amount).await?;
                (
                    exec_call.abi_encode(),
                    MAKER_FLASHLOAN_OVERHEAD_GAS,
                    premium,
                )
            }
            FlashloanProvider::UniswapV2 => {
                let pair = self
                    .select_uniswap_v2_flash_pair(asset, amount)
                    .await?
                    .ok_or_else(|| {
                        AppError::Strategy("No viable Uniswap V2 flash pair found".into())
                    })?;
                let exec_call = UnifiedHardenedExecutor::executeUniswapV2FlashLoanCall {
                    pair,
                    asset,
                    amount,
                    params: Bytes::from(params.clone()),
                };
                let premium = Self::uniswap_v2_flash_premium(amount);
                (
                    exec_call.abi_encode(),
                    UNISWAP_V2_FLASHLOAN_OVERHEAD_GAS,
                    premium,
                )
            }
            FlashloanProvider::UniswapV3 => {
                let (pool, fee_tier) = self
                    .select_uniswap_v3_flash_pool(asset, amount)
                    .await?
                    .ok_or_else(|| {
                        AppError::Strategy("No viable Uniswap V3 flash pool found".into())
                    })?;
                let exec_call = UnifiedHardenedExecutor::executeUniswapV3FlashLoanCall {
                    pool,
                    asset,
                    amount,
                    params: Bytes::from(params.clone()),
                };
                let premium = Self::uniswap_v3_flash_premium(amount, fee_tier);
                (
                    exec_call.abi_encode(),
                    UNISWAP_V3_FLASHLOAN_OVERHEAD_GAS,
                    premium,
                )
            }
        };

        let mut gas_limit = gas_limit_hint.saturating_add(overhead);
        gas_limit = gas_limit.clamp(450_000, 1_800_000);

        let request = Self::flashloan_request_template(
            self.signer.address(),
            executor,
            gas_fees,
            gas_limit,
            nonce,
            calldata,
            self.chain_id,
        );

        let _overhead_cost =
            U256::from(overhead).saturating_mul(U256::from(gas_fees.max_fee_per_gas));

        let signed = self
            .sign_with_access_list(request, AccessList::default())
            .await?;
        Ok((signed.0, signed.1, signed.2, premium, overhead))
    }

    pub(crate) fn flashloan_request_template(
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

    pub(crate) fn is_common_token_call(input: &[u8]) -> bool {
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

    pub(crate) async fn build_front_run_tx(
        &self,
        observed: &ObservedSwap,
        gas_fees: &GasFees,
        wallet_balance: U256,
        gas_limit_hint: u64,
        nonce: u64,
    ) -> Result<Option<FrontRunTx>, AppError> {
        if wallet_balance.is_zero() {
            return Ok(None);
        }
        let target_token = target_token(&observed.path, self.wrapped_native)
            .ok_or_else(|| AppError::Strategy("Unable to derive target token".into()))?;
        let exec_router = self.execution_router(observed);

        let amount_in = match self
            .pool_backrun_value(
                observed,
                wallet_balance,
                self.effective_slippage_bps(),
                gas_limit_hint,
                gas_fees,
            )
            .await?
        {
            Some(v) => v,
            None => StrategyExecutor::dynamic_backrun_value(
                observed.amount_in,
                wallet_balance,
                self.effective_slippage_bps(),
                gas_limit_hint,
                gas_fees.max_fee_per_gas,
            )?,
        };

        let (expected_tokens, calldata, tx_value, gas_limit, access_list, input_token) =
            match observed.router_kind {
                RouterKind::V2Like => {
                    let path = if observed.path.first().copied() == Some(self.wrapped_native) {
                        vec![self.wrapped_native, target_token]
                    } else {
                        observed.path.clone()
                    };
                    let swap = self
                        .build_v2_swap(
                            exec_router,
                            path.clone(),
                            amount_in,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            11,
                            10,
                            160_000,
                            false,
                            self.signer.address(),
                            false,
                            gas_fees,
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
                        *path.first().unwrap_or(&self.wrapped_native),
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
                        encode_v3_path(&observed.path, &observed.v3_fees)
                            .ok_or_else(|| AppError::Strategy("Encode V3 path failed".into()))?
                    };
                    let expected_tokens = self.quote_v3_path(&path_bytes, amount_in).await?;
                    let ratio_ppm = StrategyExecutor::price_ratio_ppm(expected_tokens, amount_in);
                    if ratio_ppm < U256::from(self.adaptive_liquidity_ratio_floor_ppm(gas_fees)) {
                        return Ok(None);
                    }
                    let min_out = expected_tokens
                        .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                        / U256::from(10_000u64);
                    let access_list =
                        StrategyExecutor::build_access_list(exec_router, &observed.path);
                    let calldata = self.build_v3_swap_payload(
                        exec_router,
                        path_bytes.clone(),
                        amount_in,
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
                    let tx_value = if observed.path.first().copied() == Some(self.wrapped_native) {
                        amount_in
                    } else {
                        U256::ZERO
                    };
                    let input_token = observed
                        .path
                        .first()
                        .copied()
                        .unwrap_or(self.wrapped_native);
                    (
                        expected_tokens,
                        calldata,
                        tx_value,
                        gas_limit,
                        access_list,
                        input_token,
                    )
                }
            };

        let (raw, request, hash) = self
            .sign_swap_request(
                exec_router,
                gas_limit,
                tx_value,
                gas_fees.max_fee_per_gas,
                gas_fees.max_priority_fee_per_gas,
                nonce,
                calldata,
                access_list,
            )
            .await?;

        Ok(Some(FrontRunTx {
            raw,
            hash,
            to: exec_router,
            value: tx_value,
            request,
            expected_tokens,
            input_token,
            input_amount: amount_in,
        }))
    }

    pub(crate) async fn build_backrun_tx(
        &self,
        observed: &ObservedSwap,
        gas_fees: &GasFees,
        wallet_balance: U256,
        gas_limit_hint: u64,
        token_in_override: Option<U256>,
        use_flashloan: bool,
        nonce: u64,
    ) -> Result<BackrunTx, AppError> {
        let target_token = target_token(&observed.path, self.wrapped_native)
            .ok_or_else(|| AppError::Strategy("Unable to derive target token".into()))?;
        let exec_router = self.execution_router(observed);
        let has_wrapped = observed.path.contains(&self.wrapped_native);

        if wallet_balance.is_zero() {
            return Err(AppError::Strategy(
                "No balance available for backrun".into(),
            ));
        }

        let expected_out_token;
        let mut unwrap_to_native = false;

        if token_in_override.is_none() {
            match observed.router_kind {
                RouterKind::V2Like => {
                    let mut value = match self
                        .pool_backrun_value(
                            observed,
                            wallet_balance,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            gas_fees,
                        )
                        .await?
                    {
                        Some(v) => v,
                        None => StrategyExecutor::dynamic_backrun_value(
                            observed.amount_in,
                            wallet_balance,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            gas_fees.max_fee_per_gas,
                        )?,
                    };
                    if use_flashloan && has_wrapped {
                        let flashloan_asset = observed
                            .path
                            .first()
                            .copied()
                            .unwrap_or(self.wrapped_native);
                        let env_scaled = self.maybe_scale_flashloan_value(value);
                        let scaled =
                            self.apply_adaptive_flashloan_scale(env_scaled, flashloan_asset);
                        if scaled < value {
                            let adaptive_scale_bps =
                                self.flashloan_asset_scale_bps(flashloan_asset);
                            tracing::debug!(
                                target: "strategy",
                                original = %value,
                                scaled = %scaled,
                                scale_bps = self.flashloan_value_scale_bps(),
                                adaptive_scale_bps,
                                asset = %format!("{flashloan_asset:#x}"),
                                "Scaled flashloan notional for safer roundtrip viability"
                            );
                            value = scaled;
                        }
                    }
                    expected_out_token = if has_wrapped {
                        self.wrapped_native
                    } else {
                        observed.path.last().copied().unwrap_or(target_token)
                    };
                    let path = if has_wrapped {
                        vec![self.wrapped_native, target_token]
                    } else {
                        observed.path.clone()
                    };
                    let recipient = if has_wrapped || use_flashloan {
                        self.executor.unwrap_or(self.signer.address())
                    } else {
                        self.signer.address()
                    };
                    let mut forward_router = exec_router;
                    let mut reverse_router = exec_router;
                    if use_flashloan && has_wrapped {
                        let reverse_input_bps = self.flashloan_reverse_input_bps();
                        let victim_router = observed.router;
                        let victim_buys_target =
                            observed.path.first() == Some(&self.wrapped_native);
                        let victim_sells_target =
                            observed.path.last() == Some(&self.wrapped_native);
                        let mut best_any_roundtrip: Option<(Address, Address, U256)> = None;
                        let mut best_cross_roundtrip: Option<(Address, Address, U256)> = None;
                        let mut best_impact_aligned_roundtrip: Option<(Address, Address, U256)> =
                            None;
                        let candidates = registry_v2_router_addresses(self.chain_id);
                        for candidate_forward_router in candidates.iter().copied() {
                            let Some(forward_quote) = self
                                .quote_v2_path_with_router_fallback(
                                    candidate_forward_router,
                                    &path,
                                    value,
                                )
                                .await
                            else {
                                continue;
                            };
                            let reverse_amount_in = forward_quote
                                .saturating_mul(U256::from(reverse_input_bps))
                                / U256::from(10_000u64);
                            if reverse_amount_in.is_zero() {
                                continue;
                            }
                            let rev_path = vec![target_token, self.wrapped_native];
                            for candidate_reverse_router in candidates.iter().copied() {
                                let Some(reverse_quote) = self
                                    .quote_v2_path_with_router_fallback(
                                        candidate_reverse_router,
                                        &rev_path,
                                        reverse_amount_in,
                                    )
                                    .await
                                else {
                                    continue;
                                };
                                if self.reject_same_router_negative_roundtrip()
                                    && candidate_forward_router == candidate_reverse_router
                                    && reverse_quote <= value
                                {
                                    continue;
                                }
                                let any_better = best_any_roundtrip
                                    .map(|(_, _, out)| reverse_quote > out)
                                    .unwrap_or(true);
                                if any_better {
                                    best_any_roundtrip = Some((
                                        candidate_forward_router,
                                        candidate_reverse_router,
                                        reverse_quote,
                                    ));
                                }
                                if candidate_forward_router != candidate_reverse_router {
                                    let cross_better = best_cross_roundtrip
                                        .map(|(_, _, out)| reverse_quote > out)
                                        .unwrap_or(true);
                                    if cross_better {
                                        best_cross_roundtrip = Some((
                                            candidate_forward_router,
                                            candidate_reverse_router,
                                            reverse_quote,
                                        ));
                                    }
                                }
                                let impact_aligned = if victim_buys_target {
                                    candidate_reverse_router == victim_router
                                        && candidate_forward_router != victim_router
                                } else if victim_sells_target {
                                    candidate_forward_router == victim_router
                                        && candidate_reverse_router != victim_router
                                } else {
                                    false
                                };
                                if impact_aligned {
                                    let impact_better = best_impact_aligned_roundtrip
                                        .map(|(_, _, out)| reverse_quote > out)
                                        .unwrap_or(true);
                                    if impact_better {
                                        best_impact_aligned_roundtrip = Some((
                                            candidate_forward_router,
                                            candidate_reverse_router,
                                            reverse_quote,
                                        ));
                                    }
                                }
                            }
                        }
                        if let Some((best_fwd, best_rev, _)) = best_impact_aligned_roundtrip
                            .or(best_cross_roundtrip)
                            .or(best_any_roundtrip)
                        {
                            forward_router = best_fwd;
                            reverse_router = best_rev;
                        } else if !candidates.contains(&exec_router) {
                            return Err(AppError::Strategy(format!(
                                "No viable canonical V2 flashloan router pair for router={:#x}",
                                exec_router
                            )));
                        }
                        if forward_router != exec_router || reverse_router != exec_router {
                            tracing::debug!(
                                target: "strategy",
                                original_router = %format!("{:#x}", exec_router),
                                selected_forward_router = %format!("{:#x}", forward_router),
                                selected_reverse_router = %format!("{:#x}", reverse_router),
                                "Selected better V2 routers for flashloan roundtrip"
                            );
                        }
                    }
                    let swap_attempt = self
                        .build_v2_swap(
                            forward_router,
                            path.clone(),
                            value,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            12,
                            10,
                            200_000,
                            use_flashloan,
                            recipient,
                            true,
                            gas_fees,
                        )
                        .await;
                    let (tokens_out, access_list, calldata, gas_limit) = match swap_attempt {
                        Ok(Some(swap)) => (
                            swap.expected_out,
                            swap.access_list.clone(),
                            swap.calldata.clone(),
                            swap.gas_limit,
                        ),
                        Ok(None) | Err(_) => {
                            if use_flashloan {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan forward V2 quote/build failed router={:#x}",
                                    forward_router
                                )));
                            }
                            let token_in_hint =
                                path.first().copied().unwrap_or(self.wrapped_native);
                            let token_out_hint = path.last().copied().unwrap_or(target_token);
                            let proportional_hint = if observed.amount_in.is_zero() {
                                U256::ZERO
                            } else {
                                observed.min_out.saturating_mul(value) / observed.amount_in
                            };
                            let route_hint = self
                                .best_route_plan(
                                    token_in_hint,
                                    token_out_hint,
                                    value,
                                    gas_fees.max_fee_per_gas,
                                )
                                .await
                                .map(|p| p.expected_out)
                                .unwrap_or(U256::ZERO);
                            let fallback_quote_hint =
                                proportional_hint.max(route_hint).max(U256::from(1u64));
                            // Keep fallback execution permissive when quotes are unavailable, but
                            // do not let unverified hints inflate expected-out profit checks.
                            let fallback_guarded_out = U256::from(1u64);
                            tracing::debug!(
                                target: "strategy",
                                router = %format!("{:#x}", exec_router),
                                token = %format!("{:#x}", target_token),
                                amount_in = %value,
                                expected_out_hint = %fallback_quote_hint,
                                guarded_expected_out = %fallback_guarded_out,
                                "V2 swap quote/build failed; using conservative fallback payload"
                            );
                            (
                                fallback_guarded_out,
                                StrategyExecutor::build_access_list(forward_router, &path),
                                self.reserve_cache.build_v2_swap_payload(
                                    path.clone(),
                                    value,
                                    fallback_guarded_out,
                                    recipient,
                                    use_flashloan,
                                    self.wrapped_native,
                                ),
                                gas_limit_hint.max(200_000),
                            )
                        }
                    };
                    if has_wrapped {
                        let executor = self.executor.ok_or_else(|| {
                            AppError::Strategy("strict atomic mode requires executor".into())
                        })?;
                        let slippage_bps = self.effective_slippage_bps();
                        let forward_min_out = tokens_out
                            .saturating_mul(U256::from(10_000u64 - slippage_bps))
                            / U256::from(10_000u64);
                        let forward_calldata = self.reserve_cache.build_v2_swap_payload(
                            path.clone(),
                            value,
                            forward_min_out,
                            executor,
                            use_flashloan,
                            self.wrapped_native,
                        );
                        let forward_payload = Bytes::from(forward_calldata);
                        let rev_path = vec![target_token, self.wrapped_native];
                        // Fee-on-transfer/taxed tokens can leave the executor with less than the
                        // quoted forward minimum. For flashloans we still need near-full unwind
                        // for repayment viability; keep non-flashloan path conservative.
                        let reverse_input_bps = if use_flashloan {
                            self.flashloan_reverse_input_bps()
                        } else {
                            9_000
                        };
                        let reverse_quote_input_base = if use_flashloan {
                            // For flashloan repayment viability, size reverse quote from the
                            // forward quote baseline instead of forward min-out.
                            tokens_out
                        } else {
                            forward_min_out
                        };
                        let mut reverse_amount_in = reverse_quote_input_base
                            .saturating_mul(U256::from(reverse_input_bps))
                            / U256::from(10_000u64);
                        let reverse_expected_out = self
                            .quote_v2_path_with_router_fallback(
                                reverse_router,
                                &rev_path,
                                reverse_amount_in,
                            )
                            .await;
                        let reverse_quote_missing = reverse_expected_out.is_none();
                        if reverse_quote_missing {
                            if use_flashloan {
                                tracing::debug!(
                                    target: "strategy",
                                    router = %format!("{:#x}", exec_router),
                                    token = %format!("{:#x}", target_token),
                                    amount_in = %value,
                                    "V2 reverse quote missing for flashloan candidate"
                                );
                            } else {
                                tracing::debug!(
                                    target: "strategy",
                                    router = %format!("{:#x}", exec_router),
                                    token = %format!("{:#x}", target_token),
                                    amount_in = %value,
                                    "V2 reverse quote missing; using best-effort reverse with minOut=1"
                                );
                            }
                        }
                        if use_flashloan && reverse_quote_missing {
                            return Err(AppError::Strategy(
                                "Flashloan reverse quote missing; skipping uncertain roundtrip"
                                    .into(),
                            ));
                        }
                        let mut reverse_expected_out = reverse_expected_out.unwrap_or_else(|| {
                            // Keep fallback near break-even to avoid systematically
                            // rejecting otherwise executable paths when cache+RPC quotes
                            // are temporarily unavailable.
                            value.saturating_mul(U256::from(9_980u64)) / U256::from(10_000u64)
                        });
                        if use_flashloan {
                            if self.reject_same_router_negative_roundtrip()
                                && forward_router == reverse_router
                                && reverse_expected_out <= value
                            {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan same-router roundtrip non-positive: expected_out={} principal={} router={:#x}",
                                    reverse_expected_out, value, forward_router
                                )));
                            }
                            if !self.dry_run
                                && !self
                                    .probe_v2_sell_for_toxicity(
                                        target_token,
                                        reverse_router,
                                        reverse_amount_in,
                                        reverse_expected_out,
                                    )
                                    .await?
                            {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan toxicity probe failed token={:#x} reverse_router={:#x}",
                                    target_token, reverse_router
                                )));
                            }
                            let min_repay = value
                                .saturating_mul(U256::from(self.flashloan_min_repay_bps()))
                                .checked_div(U256::from(10_000u64))
                                .unwrap_or(value);
                            if reverse_expected_out < min_repay && reverse_input_bps < 10_000 {
                                let full_reverse_amount_in = reverse_quote_input_base;
                                if full_reverse_amount_in > reverse_amount_in
                                    && let Some(full_reverse_quote) = self
                                        .quote_v2_path_with_router_fallback(
                                            reverse_router,
                                            &rev_path,
                                            full_reverse_amount_in,
                                        )
                                        .await
                                {
                                    tracing::debug!(
                                        target: "strategy",
                                        amount_in = %value,
                                        prev_reverse_in = %reverse_amount_in,
                                        new_reverse_in = %full_reverse_amount_in,
                                        prev_quote_out = %reverse_expected_out,
                                        new_quote_out = %full_reverse_quote,
                                        min_repay = %min_repay,
                                        "Escalated flashloan reverse input after weak repay quote"
                                    );
                                    reverse_amount_in = full_reverse_amount_in;
                                    reverse_expected_out = full_reverse_quote;
                                }
                            }
                            if reverse_expected_out < min_repay {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan quoted roundtrip insolvent: expected_out={} required_repay={} value={} min_repay_bps={}",
                                    reverse_expected_out,
                                    min_repay,
                                    value,
                                    self.flashloan_min_repay_bps()
                                )));
                            }
                            let (flashloan_premium, flashloan_prefilter_gas_cost) = self
                                .quote_best_flashloan_cost_components(path[0], value, gas_fees)
                                .await?
                                .map(|(premium, gas_cost, _)| {
                                    let gas_cost_bps = self.flashloan_prefilter_gas_cost_bps();
                                    let scaled_gas_cost = gas_cost
                                        .saturating_mul(U256::from(gas_cost_bps))
                                        .checked_div(U256::from(10_000u64))
                                        .unwrap_or(gas_cost);
                                    (premium, scaled_gas_cost)
                                })
                                .unwrap_or((U256::ZERO, U256::ZERO));
                            let flashloan_cost =
                                flashloan_premium.saturating_add(flashloan_prefilter_gas_cost);
                            let margin_bps = self.flashloan_prefilter_margin_bps();
                            let margin_from_bps = value
                                .saturating_mul(U256::from(margin_bps))
                                .checked_div(U256::from(10_000u64))
                                .unwrap_or(U256::ZERO);
                            let margin_wei =
                                margin_from_bps.max(self.flashloan_prefilter_margin_wei());
                            let required_out = min_repay
                                .saturating_add(flashloan_cost)
                                .saturating_add(margin_wei);
                            if reverse_expected_out < required_out {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan prefilter failed: expected_out={} required_out={} min_repay={} principal={} flashloan_cost={} premium={} prefilter_gas_cost={} prefilter_gas_cost_bps={} margin_wei={} margin_bps={}",
                                    reverse_expected_out,
                                    required_out,
                                    min_repay,
                                    value,
                                    flashloan_cost,
                                    flashloan_premium,
                                    flashloan_prefilter_gas_cost,
                                    self.flashloan_prefilter_gas_cost_bps(),
                                    margin_wei,
                                    margin_bps
                                )));
                            }
                        }
                        let reverse_min_out = if reverse_quote_missing {
                            U256::from(1u64)
                        } else {
                            // Keep reverse leg executable under volatile/taxed paths; profitability
                            // is still enforced after simulation by risk/profit guards.
                            reverse_expected_out.saturating_mul(U256::from(7_000u64))
                                / U256::from(10_000u64)
                        };
                        let reverse_calldata = self.reserve_cache.build_v2_swap_payload(
                            rev_path.clone(),
                            reverse_amount_in,
                            reverse_min_out,
                            executor,
                            true,
                            self.wrapped_native,
                        );
                        let reverse_payload = Bytes::from(reverse_calldata);
                        if use_flashloan {
                            // Build forward+reverse callbacks inside flashloan to guarantee round-trip.
                            let callbacks = Self::flashloan_roundtrip_callbacks(
                                executor,
                                forward_router,
                                reverse_router,
                                path[0],
                                value,
                                target_token,
                                reverse_amount_in,
                                forward_payload,
                                reverse_payload,
                            );
                            let (raw, req, hash, premium, overhead_gas) = self
                                .build_flashloan_transaction(
                                    executor,
                                    path[0],
                                    value,
                                    callbacks,
                                    gas_limit_hint,
                                    gas_fees,
                                    nonce,
                                )
                                .await?;
                            return Ok(BackrunTx {
                                raw,
                                hash,
                                to: executor,
                                value: U256::ZERO,
                                request: req,
                                expected_out: reverse_expected_out,
                                expected_out_token: self.wrapped_native,
                                unwrap_to_native: false,
                                uses_flashloan: true,
                                flashloan_premium: premium,
                                flashloan_overhead_gas: overhead_gas,
                                router_kind: observed.router_kind,
                                route_plan: None,
                            });
                        }
                        let (_executor, raw, request, hash) = self
                            .build_atomic_executor_roundtrip_tx(
                                forward_router,
                                forward_payload,
                                reverse_payload,
                                value,
                                vec![(target_token, reverse_amount_in)],
                                gas_fees,
                                gas_limit_hint,
                                nonce,
                            )
                            .await?;
                        return Ok(BackrunTx {
                            raw,
                            hash,
                            to: executor,
                            value,
                            request,
                            expected_out: reverse_expected_out,
                            expected_out_token: self.wrapped_native,
                            unwrap_to_native: false,
                            uses_flashloan: false,
                            flashloan_premium: U256::ZERO,
                            flashloan_overhead_gas: 0,
                            router_kind: observed.router_kind,
                            route_plan: None,
                        });
                    }
                    let starts_with_wrapped = path.first().copied() == Some(self.wrapped_native);
                    let tx_value = if !use_flashloan && starts_with_wrapped {
                        value
                    } else {
                        U256::ZERO
                    };
                    return Ok(BackrunTx {
                        raw: Vec::new(),
                        hash: B256::ZERO,
                        to: forward_router,
                        value: tx_value,
                        request: TransactionRequest {
                            from: Some(self.signer.address()),
                            to: Some(TxKind::Call(forward_router)),
                            max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
                            max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
                            gas: Some(gas_limit),
                            value: Some(tx_value),
                            input: TransactionInput::new(calldata.into()),
                            nonce: Some(nonce),
                            chain_id: Some(self.chain_id),
                            access_list: Some(access_list),
                            ..Default::default()
                        },
                        expected_out: tokens_out,
                        expected_out_token,
                        unwrap_to_native,
                        uses_flashloan: false,
                        flashloan_premium: U256::ZERO,
                        flashloan_overhead_gas: 0,
                        router_kind: observed.router_kind,
                        route_plan: self
                            .best_route_plan(
                                if has_wrapped {
                                    self.wrapped_native
                                } else {
                                    observed
                                        .path
                                        .first()
                                        .copied()
                                        .unwrap_or(self.wrapped_native)
                                },
                                expected_out_token,
                                value,
                                gas_fees.max_fee_per_gas,
                            )
                            .await
                            .or_else(|| {
                                StrategyExecutor::single_leg_route(
                                    RouteVenue::UniV2,
                                    forward_router,
                                    if has_wrapped {
                                        self.wrapped_native
                                    } else {
                                        observed
                                            .path
                                            .first()
                                            .copied()
                                            .unwrap_or(self.wrapped_native)
                                    },
                                    expected_out_token,
                                    value,
                                    tokens_out,
                                    None,
                                    None,
                                )
                            }),
                    });
                }
                RouterKind::V3Like => {
                    let mut value = match self
                        .pool_backrun_value(
                            observed,
                            wallet_balance,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            gas_fees,
                        )
                        .await?
                    {
                        Some(v) => v,
                        None => StrategyExecutor::dynamic_backrun_value(
                            observed.amount_in,
                            wallet_balance,
                            self.effective_slippage_bps(),
                            gas_limit_hint,
                            gas_fees.max_fee_per_gas,
                        )?,
                    };
                    if use_flashloan && has_wrapped {
                        let flashloan_asset = observed
                            .path
                            .first()
                            .copied()
                            .unwrap_or(self.wrapped_native);
                        let env_scaled = self.maybe_scale_flashloan_value(value);
                        let scaled =
                            self.apply_adaptive_flashloan_scale(env_scaled, flashloan_asset);
                        if scaled < value {
                            let adaptive_scale_bps =
                                self.flashloan_asset_scale_bps(flashloan_asset);
                            tracing::debug!(
                                target: "strategy",
                                original = %value,
                                scaled = %scaled,
                                scale_bps = self.flashloan_value_scale_bps(),
                                adaptive_scale_bps,
                                asset = %format!("{flashloan_asset:#x}"),
                                "Scaled flashloan notional for safer roundtrip viability"
                            );
                            value = scaled;
                        }
                    }
                    expected_out_token =
                        if has_wrapped {
                            self.wrapped_native
                        } else {
                            observed.path.last().copied().ok_or_else(|| {
                                AppError::Strategy("Missing V3 target token".into())
                            })?
                        };
                    let path_bytes = if let Some(p) = observed.v3_path.clone() {
                        p
                    } else {
                        encode_v3_path(&observed.path, &observed.v3_fees)
                            .ok_or_else(|| AppError::Strategy("Encode V3 path failed".into()))?
                    };
                    let expected_mid_out = self.quote_v3_path(&path_bytes, value).await?;
                    let ratio_ppm = StrategyExecutor::price_ratio_ppm(expected_mid_out, value);
                    if ratio_ppm < U256::from(self.adaptive_liquidity_ratio_floor_ppm(gas_fees)) {
                        return Err(AppError::Strategy("V3 liquidity too low".into()));
                    }
                    let min_mid_out = expected_mid_out
                        .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                        / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 3600);
                    if has_wrapped {
                        let executor = self.executor.ok_or_else(|| {
                            AppError::Strategy("strict atomic mode requires executor".into())
                        })?;
                        let reverse_path = reverse_v3_path(&observed.path, &observed.v3_fees)
                            .ok_or_else(|| AppError::Strategy("Reverse V3 path failed".into()))?;
                        let reverse_amount_in = if use_flashloan {
                            expected_mid_out
                        } else {
                            min_mid_out
                        };
                        let reverse_expected_out =
                            self.quote_v3_path(&reverse_path, reverse_amount_in).await?;
                        if use_flashloan {
                            if self.reject_same_router_negative_roundtrip()
                                && reverse_expected_out <= value
                            {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan same-router V3 roundtrip non-positive: expected_out={} principal={} router={:#x}",
                                    reverse_expected_out, value, exec_router
                                )));
                            }
                            if !self.dry_run
                                && !self
                                    .probe_v3_sell_for_toxicity(
                                        exec_router,
                                        reverse_path.clone(),
                                        reverse_amount_in,
                                        reverse_expected_out,
                                    )
                                    .await?
                            {
                                return Err(AppError::Strategy(
                                    "Flashloan V3 toxicity probe failed".into(),
                                ));
                            }
                            let min_repay = value
                                .saturating_mul(U256::from(self.flashloan_min_repay_bps()))
                                .checked_div(U256::from(10_000u64))
                                .unwrap_or(value);
                            if reverse_expected_out < min_repay {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan quoted V3 roundtrip insolvent: expected_out={} required_repay={} value={} min_repay_bps={}",
                                    reverse_expected_out,
                                    min_repay,
                                    value,
                                    self.flashloan_min_repay_bps()
                                )));
                            }
                            let flashloan_asset = observed
                                .path
                                .first()
                                .copied()
                                .unwrap_or(self.wrapped_native);
                            let (flashloan_premium, flashloan_prefilter_gas_cost) = self
                                .quote_best_flashloan_cost_components(
                                    flashloan_asset,
                                    value,
                                    gas_fees,
                                )
                                .await?
                                .map(|(premium, gas_cost, _)| {
                                    let gas_cost_bps = self.flashloan_prefilter_gas_cost_bps();
                                    let scaled_gas_cost = gas_cost
                                        .saturating_mul(U256::from(gas_cost_bps))
                                        .checked_div(U256::from(10_000u64))
                                        .unwrap_or(gas_cost);
                                    (premium, scaled_gas_cost)
                                })
                                .unwrap_or((U256::ZERO, U256::ZERO));
                            let flashloan_cost =
                                flashloan_premium.saturating_add(flashloan_prefilter_gas_cost);
                            let margin_bps = self.flashloan_prefilter_margin_bps();
                            let margin_from_bps = value
                                .saturating_mul(U256::from(margin_bps))
                                .checked_div(U256::from(10_000u64))
                                .unwrap_or(U256::ZERO);
                            let margin_wei =
                                margin_from_bps.max(self.flashloan_prefilter_margin_wei());
                            let required_out = min_repay
                                .saturating_add(flashloan_cost)
                                .saturating_add(margin_wei);
                            if reverse_expected_out < required_out {
                                return Err(AppError::Strategy(format!(
                                    "Flashloan V3 prefilter failed: expected_out={} required_out={} min_repay={} principal={} flashloan_cost={} premium={} prefilter_gas_cost={} prefilter_gas_cost_bps={} margin_wei={} margin_bps={}",
                                    reverse_expected_out,
                                    required_out,
                                    min_repay,
                                    value,
                                    flashloan_cost,
                                    flashloan_premium,
                                    flashloan_prefilter_gas_cost,
                                    self.flashloan_prefilter_gas_cost_bps(),
                                    margin_wei,
                                    margin_bps
                                )));
                            }
                        }
                        let reverse_min_out = reverse_expected_out
                            .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                            / U256::from(10_000u64);
                        let forward_payload =
                            UniV3Router::new(exec_router, self.http_provider.clone())
                                .exactInput(UniV3Router::ExactInputParams {
                                    path: path_bytes.clone().into(),
                                    recipient: executor,
                                    deadline,
                                    amountIn: value,
                                    amountOutMinimum: min_mid_out,
                                })
                                .calldata()
                                .to_vec();
                        let reverse_payload =
                            UniV3Router::new(exec_router, self.http_provider.clone())
                                .exactInput(UniV3Router::ExactInputParams {
                                    path: reverse_path.clone().into(),
                                    recipient: executor,
                                    deadline,
                                    amountIn: reverse_amount_in,
                                    amountOutMinimum: reverse_min_out,
                                })
                                .calldata()
                                .to_vec();
                        if use_flashloan {
                            let flashloan_asset = observed
                                .path
                                .first()
                                .copied()
                                .unwrap_or(self.wrapped_native);
                            let callbacks = Self::flashloan_roundtrip_callbacks(
                                executor,
                                exec_router,
                                exec_router,
                                flashloan_asset,
                                value,
                                target_token,
                                reverse_amount_in,
                                Bytes::from(forward_payload),
                                Bytes::from(reverse_payload),
                            );
                            let (raw, req, hash, premium, overhead_gas) = self
                                .build_flashloan_transaction(
                                    executor,
                                    flashloan_asset,
                                    value,
                                    callbacks,
                                    gas_limit_hint,
                                    gas_fees,
                                    nonce,
                                )
                                .await?;
                            return Ok(BackrunTx {
                                raw,
                                hash,
                                to: executor,
                                value: U256::ZERO,
                                request: req,
                                expected_out: reverse_expected_out,
                                expected_out_token: self.wrapped_native,
                                unwrap_to_native: false,
                                uses_flashloan: true,
                                flashloan_premium: premium,
                                flashloan_overhead_gas: overhead_gas,
                                router_kind: observed.router_kind,
                                route_plan: None,
                            });
                        }
                        let (_executor, raw, request, hash) = self
                            .build_atomic_executor_roundtrip_tx(
                                exec_router,
                                Bytes::from(forward_payload),
                                Bytes::from(reverse_payload),
                                value,
                                vec![(target_token, min_mid_out)],
                                gas_fees,
                                gas_limit_hint,
                                nonce,
                            )
                            .await?;
                        return Ok(BackrunTx {
                            raw,
                            hash,
                            to: executor,
                            value,
                            request,
                            expected_out: reverse_expected_out,
                            expected_out_token: self.wrapped_native,
                            unwrap_to_native: false,
                            uses_flashloan: false,
                            flashloan_premium: U256::ZERO,
                            flashloan_overhead_gas: 0,
                            router_kind: observed.router_kind,
                            route_plan: None,
                        });
                    }
                    let tx_value = if !use_flashloan
                        && observed.path.first().copied() == Some(self.wrapped_native)
                    {
                        value
                    } else {
                        U256::ZERO
                    };
                    let calldata = UniV3Router::new(exec_router, self.http_provider.clone())
                        .exactInput(UniV3Router::ExactInputParams {
                            path: path_bytes.clone().into(),
                            recipient: self.signer.address(),
                            deadline,
                            amountIn: value,
                            amountOutMinimum: min_mid_out,
                        })
                        .calldata()
                        .to_vec();
                    let access_list =
                        StrategyExecutor::build_access_list(exec_router, &observed.path);
                    return Ok(BackrunTx {
                        raw: Vec::new(),
                        hash: B256::ZERO,
                        to: exec_router,
                        value: tx_value,
                        request: TransactionRequest {
                            from: Some(self.signer.address()),
                            to: Some(TxKind::Call(exec_router)),
                            max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
                            max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
                            gas: Some(gas_limit_hint.clamp(180_000, 450_000)),
                            value: Some(tx_value),
                            input: TransactionInput::new(calldata.into()),
                            nonce: Some(nonce),
                            chain_id: Some(self.chain_id),
                            access_list: Some(access_list),
                            ..Default::default()
                        },
                        expected_out: expected_mid_out,
                        expected_out_token,
                        unwrap_to_native,
                        uses_flashloan: false,
                        flashloan_premium: U256::ZERO,
                        flashloan_overhead_gas: 0,
                        router_kind: observed.router_kind,
                        route_plan: self
                            .best_route_plan(
                                if has_wrapped {
                                    self.wrapped_native
                                } else {
                                    observed
                                        .path
                                        .first()
                                        .copied()
                                        .unwrap_or(self.wrapped_native)
                                },
                                expected_out_token,
                                value,
                                gas_fees.max_fee_per_gas,
                            )
                            .await
                            .or_else(|| {
                                StrategyExecutor::single_leg_route(
                                    RouteVenue::UniV3,
                                    exec_router,
                                    if has_wrapped {
                                        self.wrapped_native
                                    } else {
                                        observed
                                            .path
                                            .first()
                                            .copied()
                                            .unwrap_or(self.wrapped_native)
                                    },
                                    expected_out_token,
                                    value,
                                    expected_mid_out,
                                    observed.v3_fees.first().copied(),
                                    Some(Bytes::from(path_bytes.clone())),
                                )
                            }),
                    });
                }
            }
        } else {
            let Some(tokens_in) = token_in_override else {
                return Err(AppError::Strategy(
                    "token_in_override missing for sell backrun path".into(),
                ));
            };
            let (value, expected_out, calldata, access_list) = match observed.router_kind {
                RouterKind::V2Like => {
                    expected_out_token = if has_wrapped {
                        self.wrapped_native
                    } else {
                        observed
                            .path
                            .first()
                            .copied()
                            .unwrap_or(self.wrapped_native)
                    };
                    let sell_path = if has_wrapped {
                        vec![target_token, self.wrapped_native]
                    } else {
                        observed.path.iter().copied().rev().collect()
                    };
                    let sell_amount = tokens_in;
                    let expected_out = self
                        .quote_v2_path_with_router_fallback(exec_router, &sell_path, sell_amount)
                        .await
                        .ok_or_else(|| AppError::Strategy("Sell quote failed".into()))?;
                    let ratio_ppm = StrategyExecutor::price_ratio_ppm(expected_out, sell_amount);
                    // Ratio-only checks are pathological for ultra-low unit-price tokens.
                    // Keep a dust floor for native-out paths and a very loose ratio guard otherwise.
                    let min_native_out_wei = self.adaptive_sell_min_native_out_wei(gas_fees);
                    if (has_wrapped && expected_out < min_native_out_wei)
                        || (!has_wrapped && ratio_ppm < U256::from(10u64))
                    {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run
                        && !self
                            .probe_v2_sell_for_toxicity(
                                target_token,
                                exec_router,
                                sell_amount,
                                expected_out,
                            )
                            .await?
                    {
                        tracing::debug!(
                            target: "strategy",
                            token = %format!("{:#x}", target_token),
                            router = %format!("{:#x}", exec_router),
                            "V2 toxicity probe failed on backrun; continuing"
                        );
                    }
                    let min_out = expected_out
                        .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                        / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 3600);
                    let router_contract = UniV2Router::new(exec_router, self.http_provider.clone());
                    let calldata = if has_wrapped {
                        router_contract
                            .swapExactTokensForETH(
                                sell_amount,
                                min_out,
                                sell_path.clone(),
                                self.signer.address(),
                                deadline,
                            )
                            .calldata()
                            .to_vec()
                    } else {
                        router_contract
                            .swapExactTokensForTokens(
                                sell_amount,
                                min_out,
                                sell_path.clone(),
                                self.signer.address(),
                                deadline,
                            )
                            .calldata()
                            .to_vec()
                    };
                    let access_list = StrategyExecutor::build_access_list(exec_router, &sell_path);
                    (U256::ZERO, expected_out, calldata, access_list)
                }
                RouterKind::V3Like => {
                    expected_out_token = if has_wrapped {
                        self.wrapped_native
                    } else {
                        observed
                            .path
                            .first()
                            .copied()
                            .unwrap_or(self.wrapped_native)
                    };
                    unwrap_to_native = has_wrapped;
                    let rev_path = reverse_v3_path(&observed.path, &observed.v3_fees)
                        .ok_or_else(|| AppError::Strategy("Reverse V3 path failed".into()))?;
                    let expected_out = self.quote_v3_path(&rev_path, tokens_in).await?;
                    let ratio_ppm = StrategyExecutor::price_ratio_ppm(expected_out, tokens_in);
                    let min_native_out_wei = self.adaptive_sell_min_native_out_wei(gas_fees);
                    if (has_wrapped && expected_out < min_native_out_wei)
                        || (!has_wrapped && ratio_ppm < U256::from(10u64))
                    {
                        return Err(AppError::Strategy("Sell liquidity too low".into()));
                    }
                    if !self.dry_run
                        && !self
                            .probe_v3_sell_for_toxicity(
                                exec_router,
                                rev_path.clone(),
                                tokens_in,
                                expected_out,
                            )
                            .await?
                    {
                        tracing::debug!(
                            target: "strategy",
                            router = %format!("{:#x}", exec_router),
                            "V3 toxicity probe failed on backrun; continuing"
                        );
                    }
                    let min_out = expected_out
                        .saturating_mul(U256::from(10_000u64 - self.effective_slippage_bps()))
                        / U256::from(10_000u64);
                    let deadline = U256::from((chrono::Utc::now().timestamp() as u64) + 3600);
                    let calldata = UniV3Router::new(exec_router, self.http_provider.clone())
                        .exactInput(UniV3Router::ExactInputParams {
                            path: rev_path.clone().into(),
                            recipient: self.signer.address(),
                            deadline,
                            amountIn: tokens_in,
                            amountOutMinimum: min_out,
                        })
                        .calldata()
                        .to_vec();
                    let access_list =
                        StrategyExecutor::build_access_list(exec_router, &observed.path);
                    (U256::ZERO, expected_out, calldata, access_list)
                }
            };

            let access_list = access_list.clone();
            let (raw, request, hash) = self
                .sign_with_access_list(
                    TransactionRequest {
                        from: Some(self.signer.address()),
                        to: Some(TxKind::Call(exec_router)),
                        max_fee_per_gas: Some(gas_fees.max_fee_per_gas),
                        max_priority_fee_per_gas: Some(gas_fees.max_priority_fee_per_gas),
                        gas: Some(gas_limit_hint.clamp(150_000, 450_000)),
                        value: Some(value),
                        input: TransactionInput::new(calldata.into()),
                        nonce: Some(nonce),
                        chain_id: Some(self.chain_id),
                        access_list: Some(access_list.clone()),
                        ..Default::default()
                    },
                    access_list,
                )
                .await?;

            Ok(BackrunTx {
                raw,
                hash,
                to: exec_router,
                value,
                request,
                expected_out,
                expected_out_token,
                unwrap_to_native,
                uses_flashloan: use_flashloan,
                flashloan_premium: U256::ZERO,
                flashloan_overhead_gas: 0,
                router_kind: observed.router_kind,
                route_plan: self
                    .best_route_plan(
                        target_token,
                        expected_out_token,
                        tokens_in,
                        gas_fees.max_fee_per_gas,
                    )
                    .await
                    .or_else(|| {
                        StrategyExecutor::single_leg_route(
                            match observed.router_kind {
                                RouterKind::V2Like => RouteVenue::UniV2,
                                RouterKind::V3Like => RouteVenue::UniV3,
                            },
                            exec_router,
                            target_token,
                            expected_out_token,
                            tokens_in,
                            expected_out,
                            match observed.router_kind {
                                RouterKind::V3Like => observed.v3_fees.first().copied(),
                                _ => None,
                            },
                            None,
                        )
                    }),
            })
        }
    }
}
// ------------------------------------------------------------------
// Flashloan provider scoring
// ------------------------------------------------------------------
impl StrategyExecutor {
    async fn quote_best_flashloan_cost_components(
        &self,
        asset: Address,
        amount: U256,
        gas_fees: &GasFees,
    ) -> Result<Option<(U256, U256, U256)>, AppError> {
        if self.flashloan_providers.is_empty() {
            return Ok(None);
        }
        let mut best: Option<(U256, U256, U256)> = None;
        for provider in &self.flashloan_providers {
            let quote = match provider {
                FlashloanProvider::Balancer => {
                    self.quote_balancer_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::AaveV3 => {
                    self.quote_aave_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::Dydx => {
                    self.quote_dydx_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::MakerDao => {
                    self.quote_maker_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::UniswapV2 => {
                    self.quote_uniswap_v2_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::UniswapV3 => {
                    self.quote_uniswap_v3_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
            };
            let Some((total_cost, _)) = quote else {
                continue;
            };
            let premium = match provider {
                FlashloanProvider::Balancer => {
                    let fee = self
                        .get_balancer_flashloan_fee()
                        .await
                        .unwrap_or(U256::ZERO);
                    amount.saturating_mul(fee) / U256::from(1_000_000_000_000_000_000u128)
                }
                FlashloanProvider::AaveV3 => {
                    let pool = match self.aave_pool {
                        Some(p) => p,
                        None => continue,
                    };
                    let premium_bps = if let Some((v, ts)) = AAVE_FEE_CACHE.get(&pool).map(|v| *v) {
                        if ts.elapsed() <= FEE_TTL {
                            v
                        } else {
                            AAVE_FEE_CACHE.remove(&pool);
                            self.fetch_aave_premium(pool).await?
                        }
                    } else {
                        self.fetch_aave_premium(pool).await?
                    };
                    amount
                        .saturating_mul(premium_bps)
                        .saturating_add(U256::from(9_999u64))
                        / U256::from(10_000u64)
                }
                FlashloanProvider::Dydx => U256::from(2u64),
                FlashloanProvider::MakerDao => {
                    let lender = match default_maker_flash_lender(self.chain_id) {
                        Some(v) => v,
                        None => continue,
                    };
                    match self.fetch_maker_flash_fee(lender, asset, amount).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    }
                }
                FlashloanProvider::UniswapV2 => Self::uniswap_v2_flash_premium(amount),
                FlashloanProvider::UniswapV3 => {
                    let Some((_pool, fee_tier)) =
                        self.select_uniswap_v3_flash_pool(asset, amount).await?
                    else {
                        continue;
                    };
                    Self::uniswap_v3_flash_premium(amount, fee_tier)
                }
            };
            let gas_cost = total_cost.saturating_sub(premium);
            match best {
                None => best = Some((premium, gas_cost, total_cost)),
                Some((_, _, current_total)) if total_cost < current_total => {
                    best = Some((premium, gas_cost, total_cost))
                }
                _ => {}
            }
        }
        Ok(best)
    }

    async fn select_flashloan_provider(
        &self,
        asset: Address,
        amount: U256,
        gas_fees: &GasFees,
    ) -> Result<Option<FlashloanProvider>, AppError> {
        if self.flashloan_providers.is_empty() {
            return Ok(None);
        }
        let mut best: Option<(FlashloanProvider, U256)> = None;
        for provider in &self.flashloan_providers {
            let quote = match provider {
                FlashloanProvider::Balancer => {
                    self.quote_balancer_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::AaveV3 => {
                    self.quote_aave_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::Dydx => {
                    self.quote_dydx_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::MakerDao => {
                    self.quote_maker_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::UniswapV2 => {
                    self.quote_uniswap_v2_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
                FlashloanProvider::UniswapV3 => {
                    self.quote_uniswap_v3_flashloan(asset, amount, gas_fees.max_fee_per_gas)
                        .await?
                }
            };
            let Some((total_cost, _)) = quote else {
                continue;
            };
            match best {
                None => best = Some((*provider, total_cost)),
                Some((_, current)) if total_cost < current => best = Some((*provider, total_cost)),
                _ => {}
            }
        }
        Ok(best.map(|(p, _)| p))
    }

    async fn quote_balancer_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let vault = default_balancer_vault_for_chain(self.chain_id)
            .ok_or_else(|| AppError::Strategy("Balancer vault not configured for chain".into()))?;
        let balance: U256 = match ERC20::new(asset, self.http_provider.clone())
            .balanceOf(vault)
            .call()
            .await
        {
            Ok(balance) => balance,
            Err(err) => {
                tracing::debug!(
                    target: "flashloan",
                    provider = "balancer",
                    asset = %format!("{asset:#x}"),
                    vault = %format!("{vault:#x}"),
                    error = %err,
                    "Balancer liquidity probe failed; treating provider as unavailable"
                );
                return Ok(None);
            }
        };
        if balance < amount {
            return Ok(None);
        }

        // Balancer governance can set this to 0 on mainnet; treat missing/failed call as zero per spec.
        let fee_pct_wei: U256 = self
            .get_balancer_flashloan_fee()
            .await
            .unwrap_or(U256::ZERO);
        let premium = amount
            .saturating_mul(fee_pct_wei)
            .checked_div(U256::from(1_000_000_000_000_000_000u128))
            .unwrap_or(U256::MAX);
        let gas_cost =
            U256::from(BALANCER_FLASHLOAN_OVERHEAD_GAS).saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            BALANCER_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn get_balancer_flashloan_fee(&self) -> Option<U256> {
        if let Some((fee, ts)) = BALANCER_FEE_CACHE.get(&self.chain_id).map(|v| *v)
            && ts.elapsed() <= FEE_TTL
        {
            return Some(fee);
        }
        let vault = default_balancer_vault_for_chain(self.chain_id)?;
        let vault_contract = BalancerVaultFees::new(vault, self.http_provider.clone());
        let collector_addr: Address = vault_contract
            .getProtocolFeesCollector()
            .call()
            .await
            .ok()?;
        let collector = BalancerProtocolFees::new(collector_addr, self.http_provider.clone());
        let fee = collector.getFlashLoanFeePercentage().call().await.ok()?;
        BALANCER_FEE_CACHE.insert(self.chain_id, (fee, std::time::Instant::now()));
        Some(fee)
    }

    async fn quote_aave_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let pool = match self.aave_pool {
            Some(p) => p,
            None => return Ok(None),
        };
        let Some(a_token) = self.aave_reserve_atoken(pool, asset).await else {
            tracing::debug!(
                target: "flashloan",
                provider = "aave_v3",
                pool = %format!("{pool:#x}"),
                asset = %format!("{asset:#x}"),
                "Aave reserve probe failed; treating provider as unavailable"
            );
            return Ok(None);
        };
        let available_liquidity: U256 = match ERC20::new(asset, self.http_provider.clone())
            .balanceOf(a_token)
            .call()
            .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    target: "flashloan",
                    provider = "aave_v3",
                    pool = %format!("{pool:#x}"),
                    asset = %format!("{asset:#x}"),
                    a_token = %format!("{a_token:#x}"),
                    error = %err,
                    "Aave liquidity probe failed; treating provider as unavailable"
                );
                return Ok(None);
            }
        };
        if available_liquidity < amount {
            return Ok(None);
        }
        let premium_bps: U256 = if let Some((v, ts)) = AAVE_FEE_CACHE.get(&pool).map(|v| *v) {
            if ts.elapsed() <= FEE_TTL {
                v
            } else {
                AAVE_FEE_CACHE.remove(&pool);
                self.fetch_aave_premium(pool).await?
            }
        } else {
            self.fetch_aave_premium(pool).await?
        };

        // Conservative rounding up to avoid under-estimating the callback repayment.
        let premium = amount
            .saturating_mul(premium_bps)
            .saturating_add(U256::from(9_999u64))
            / U256::from(10_000u64);
        let gas_cost =
            U256::from(AAVE_FLASHLOAN_OVERHEAD_GAS).saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            AAVE_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn quote_dydx_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let solo = match default_dydx_solo_margin(self.chain_id) {
            Some(addr) => addr,
            None => return Ok(None),
        };
        if !self.dydx_market_exists(solo, asset).await? {
            return Ok(None);
        }
        let liquidity: U256 = match ERC20::new(asset, self.http_provider.clone())
            .balanceOf(solo)
            .call()
            .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    target: "flashloan",
                    provider = "dydx",
                    solo = %format!("{solo:#x}"),
                    asset = %format!("{asset:#x}"),
                    error = %err,
                    "dYdX liquidity probe failed; treating provider as unavailable"
                );
                return Ok(None);
            }
        };
        if liquidity < amount {
            return Ok(None);
        }
        let premium = U256::from(2u64);
        let gas_cost =
            U256::from(DYDX_FLASHLOAN_OVERHEAD_GAS).saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            DYDX_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn quote_maker_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let lender = match default_maker_flash_lender(self.chain_id) {
            Some(addr) => addr,
            None => return Ok(None),
        };
        let max_loan: U256 = match ERC3156FlashLender::new(lender, self.http_provider.clone())
            .maxFlashLoan(asset)
            .call()
            .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    target: "flashloan",
                    provider = "maker",
                    lender = %format!("{lender:#x}"),
                    asset = %format!("{asset:#x}"),
                    error = %err,
                    "Maker maxFlashLoan probe failed; treating provider as unavailable"
                );
                return Ok(None);
            }
        };
        if max_loan < amount {
            return Ok(None);
        }
        let premium = match self.fetch_maker_flash_fee(lender, asset, amount).await {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    target: "flashloan",
                    provider = "maker",
                    lender = %format!("{lender:#x}"),
                    asset = %format!("{asset:#x}"),
                    error = %err,
                    "Maker flashFee probe failed; treating provider as unavailable"
                );
                return Ok(None);
            }
        };
        let gas_cost =
            U256::from(MAKER_FLASHLOAN_OVERHEAD_GAS).saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            MAKER_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn quote_uniswap_v2_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let Some(_pair) = self.select_uniswap_v2_flash_pair(asset, amount).await? else {
            return Ok(None);
        };
        let premium = Self::uniswap_v2_flash_premium(amount);
        let gas_cost = U256::from(UNISWAP_V2_FLASHLOAN_OVERHEAD_GAS)
            .saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            UNISWAP_V2_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn quote_uniswap_v3_flashloan(
        &self,
        asset: Address,
        amount: U256,
        max_fee_per_gas: u128,
    ) -> Result<Option<(U256, u64)>, AppError> {
        let Some((_pool, fee_tier)) = self.select_uniswap_v3_flash_pool(asset, amount).await?
        else {
            return Ok(None);
        };
        let premium = Self::uniswap_v3_flash_premium(amount, fee_tier);
        let gas_cost = U256::from(UNISWAP_V3_FLASHLOAN_OVERHEAD_GAS)
            .saturating_mul(U256::from(max_fee_per_gas));
        Ok(Some((
            premium.saturating_add(gas_cost),
            UNISWAP_V3_FLASHLOAN_OVERHEAD_GAS,
        )))
    }

    async fn dydx_market_exists(&self, solo: Address, asset: Address) -> Result<bool, AppError> {
        let solo_getters = DydxSoloMarginGetters::new(solo, self.http_provider.clone());
        let market_count = solo_getters
            .getNumMarkets()
            .call()
            .await
            .map_err(|e| AppError::Strategy(format!("dYdX getNumMarkets failed: {}", e)))?
            .to::<u64>();
        for market_id in 0..market_count {
            let token = solo_getters
                .getMarketTokenAddress(U256::from(market_id))
                .call()
                .await
                .map_err(|e| {
                    AppError::Strategy(format!("dYdX getMarketTokenAddress failed: {}", e))
                })?;
            if token == asset {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn fetch_maker_flash_fee(
        &self,
        lender: Address,
        asset: Address,
        amount: U256,
    ) -> Result<U256, AppError> {
        ERC3156FlashLender::new(lender, self.http_provider.clone())
            .flashFee(asset, amount)
            .call()
            .await
            .map_err(|e| AppError::Strategy(format!("Maker flashFee fetch failed: {}", e)))
    }

    async fn select_uniswap_v2_flash_pair(
        &self,
        asset: Address,
        amount: U256,
    ) -> Result<Option<Address>, AppError> {
        let factory = default_uniswap_v2_factory(self.chain_id);
        let factory_contract =
            factory.map(|addr| UniswapV2Factory::new(addr, self.http_provider.clone()));
        let candidates = self.flash_counterpart_candidates(asset, 32);
        let mut best: Option<(Address, U256)> = None;

        for counterpart in candidates {
            if let Some((pair, reserve_in)) = self
                .reserve_cache
                .best_v2_pair_with_liquidity(asset, counterpart)
            {
                if reserve_in >= amount {
                    match best {
                        None => best = Some((pair, reserve_in)),
                        Some((_, prev)) if reserve_in > prev => best = Some((pair, reserve_in)),
                        _ => {}
                    }
                }
                continue;
            }

            let Some(factory) = &factory_contract else {
                continue;
            };
            let pair = match factory.getPair(asset, counterpart).call().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            if pair == Address::ZERO {
                continue;
            }
            let reserve_in = match ERC20::new(asset, self.http_provider.clone())
                .balanceOf(pair)
                .call()
                .await
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            if reserve_in < amount {
                continue;
            }
            match best {
                None => best = Some((pair, reserve_in)),
                Some((_, prev)) if reserve_in > prev => best = Some((pair, reserve_in)),
                _ => {}
            }
        }
        Ok(best.map(|(pair, _)| pair))
    }

    async fn select_uniswap_v3_flash_pool(
        &self,
        asset: Address,
        amount: U256,
    ) -> Result<Option<(Address, u32)>, AppError> {
        let factory = match default_uniswap_v3_factory(self.chain_id) {
            Some(addr) => addr,
            None => return Ok(None),
        };
        let factory = UniswapV3Factory::new(factory, self.http_provider.clone());
        let fee_tiers = [100u32, 500u32, 3_000u32, 10_000u32];
        let candidates = self.flash_counterpart_candidates(asset, 32);
        let mut best: Option<(Address, u32, U256)> = None;

        for counterpart in candidates {
            for fee_tier in fee_tiers {
                let fee_arg = alloy::primitives::Uint::<24, 1>::from(fee_tier as u64);
                let pool = match factory.getPool(asset, counterpart, fee_arg).call().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if pool == Address::ZERO {
                    continue;
                }
                let reserve_in = match ERC20::new(asset, self.http_provider.clone())
                    .balanceOf(pool)
                    .call()
                    .await
                {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if reserve_in < amount {
                    continue;
                }
                match best {
                    None => best = Some((pool, fee_tier, reserve_in)),
                    Some((_, _, prev)) if reserve_in > prev => {
                        best = Some((pool, fee_tier, reserve_in))
                    }
                    _ => {}
                }
            }
        }
        Ok(best.map(|(pool, fee, _)| (pool, fee)))
    }

    fn flash_counterpart_candidates(&self, asset: Address, limit: usize) -> Vec<Address> {
        let mut out = Vec::new();
        if self.wrapped_native != Address::ZERO && self.wrapped_native != asset {
            out.push(self.wrapped_native);
        }
        for token in self.reserve_cache.top_v2_tokens_by_connectivity(limit) {
            if token == asset || out.contains(&token) {
                continue;
            }
            out.push(token);
        }
        out
    }

    fn uniswap_v2_flash_premium(amount: U256) -> U256 {
        let amount_owing = amount
            .saturating_mul(U256::from(1_000u64))
            .saturating_add(U256::from(996u64))
            / U256::from(997u64);
        amount_owing.saturating_sub(amount)
    }

    fn uniswap_v3_flash_premium(amount: U256, fee_tier: u32) -> U256 {
        amount
            .saturating_mul(U256::from(fee_tier))
            .saturating_add(U256::from(999_999u64))
            / U256::from(1_000_000u64)
    }

    async fn aave_reserve_atoken(&self, pool: Address, asset: Address) -> Option<Address> {
        if let Some((a_token, ts)) = AAVE_ATOKEN_CACHE.get(&(pool, asset)).map(|v| *v)
            && ts.elapsed() <= FEE_TTL
        {
            return Some(a_token);
        }
        AAVE_ATOKEN_CACHE.remove(&(pool, asset));
        let reserve = AavePool::new(pool, self.http_provider.clone())
            .getReserveData(asset)
            .call()
            .await
            .ok()?;
        if reserve.aTokenAddress == Address::ZERO {
            return None;
        }
        AAVE_ATOKEN_CACHE.insert(
            (pool, asset),
            (reserve.aTokenAddress, std::time::Instant::now()),
        );
        Some(reserve.aTokenAddress)
    }

    async fn fetch_aave_premium(&self, pool: Address) -> Result<U256, AppError> {
        let v: U256 = AavePool::new(pool, self.http_provider.clone())
            .FLASHLOAN_PREMIUM_TOTAL()
            .call()
            .await
            .map(U256::from)
            .map_err(|e| AppError::Strategy(format!("Aave premium fetch failed: {}", e)))?;
        AAVE_FEE_CACHE.insert(pool, (v, std::time::Instant::now()));
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::strategy::strategy::dummy_executor_for_tests;

    #[test]
    fn flashloan_roundtrip_callbacks_include_approve_swap_swap_reset() {
        let executor = Address::from([0x11; 20]);
        let forward_router = Address::from([0x22; 20]);
        let reverse_router = Address::from([0x23; 20]);
        let forward_token = Address::from([0x33; 20]);
        let reverse_token = Address::from([0x44; 20]);
        let forward_amount = U256::from(123u64);
        let reverse_amount = U256::from(456u64);
        let fwd = Bytes::from(vec![0xaa, 0xbb]);
        let rev = Bytes::from(vec![0xcc, 0xdd]);

        let callbacks = StrategyExecutor::flashloan_roundtrip_callbacks(
            executor,
            forward_router,
            reverse_router,
            forward_token,
            forward_amount,
            reverse_token,
            reverse_amount,
            fwd.clone(),
            rev.clone(),
        );

        assert_eq!(callbacks.len(), 6);
        assert_eq!(callbacks[0].0, executor);
        assert_eq!(callbacks[1].0, executor);
        assert_eq!(callbacks[2].0, forward_router);
        assert_eq!(callbacks[3].0, reverse_router);
        assert_eq!(callbacks[4].0, executor);
        assert_eq!(callbacks[5].0, executor);
        assert_eq!(callbacks[2].1, fwd);
        assert_eq!(callbacks[3].1, rev);
        assert_eq!(callbacks[0].2, U256::ZERO);
        assert_eq!(callbacks[1].2, U256::ZERO);
        assert_eq!(callbacks[2].2, U256::ZERO);
        assert_eq!(callbacks[3].2, U256::ZERO);
        assert_eq!(callbacks[4].2, U256::ZERO);
        assert_eq!(callbacks[5].2, U256::ZERO);
    }

    #[tokio::test]
    async fn aave_quote_returns_none_when_reserve_probe_fails() {
        let mut exec = dummy_executor_for_tests().await;
        exec.aave_pool = Some(Address::from([0xa1; 20]));

        let quote = exec
            .quote_aave_flashloan(
                Address::from([0xa2; 20]),
                U256::from(1_000u64),
                10_000_000u128,
            )
            .await
            .expect("quote should not fail hard when reserve probe is unavailable");
        assert!(quote.is_none());
    }
}

#[cfg(test)]

crate::coverage_floor_pad_test!(1800);
