// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

#![allow(
    clippy::explicit_iter_loop,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::non_std_lazy_statics,
    clippy::redundant_clone,
    clippy::similar_names,
    clippy::too_many_lines
)]

use alloy::consensus::Transaction as ConsensusTxTrait;
use alloy::primitives::{Address, Bytes, TxKind, U256, aliases::U24};
use alloy::rpc::types::eth::Transaction;
use alloy_sol_types::{SolCall, SolType};
use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::common::constants::{
    CHAIN_ARBITRUM, CHAIN_BSC, CHAIN_ETHEREUM, CHAIN_OPTIMISM, CHAIN_POLYGON, CHAIN_SEPOLIA,
    default_routers_for_chain, native_sentinel_for_chain, wrapped_native_for_chain,
};
use crate::services::strategy::routers::{
    BalancerVault, DexRouter, KyberAggregationRouterV2, OneInchAggregationRouter,
    OneInchAggregationRouterV5, ParaSwapAugustusV6, RelayApprovalProxyV3, RelayRouterV3,
    TransitSwapRouterV5, UniV2Router, UniV3Multicall, UniV3MulticallDeadline, UniV3Router,
    UniV3Router02, UniversalRouter, UniversalRouterDeadline, ZeroXExchangeProxy,
};

use alloy::sol;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservedSwap {
    pub router: Address,
    pub path: Vec<Address>,
    pub v3_fees: Vec<u32>,
    pub v3_path: Option<Vec<u8>>,
    /// Exact V4 identities. Native currency remains `Address::ZERO`; `path` contains the
    /// normalized wrapped-native representation used by generic strategy code.
    pub v4_path: Vec<ObservedV4Hop>,
    pub amount_in: U256,
    pub min_out: U256,
    pub recipient: Address,
    pub router_kind: RouterKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservedV4PoolKey {
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservedV4Hop {
    pub pool_key: ObservedV4PoolKey,
    pub zero_for_one: bool,
    pub hook_data: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouterKind {
    V2Like,
    V3Like,
    V4Like,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapDirection {
    BuyWithEth,
    SellForEth,
    Other,
}

#[derive(Clone, Debug)]
pub struct ParsedV3Path {
    pub tokens: Vec<Address>,
    pub fees: Vec<u32>,
}

static ROUTER_CHAIN_LOOKUP: Lazy<HashMap<Address, u64>> = Lazy::new(|| {
    let mut lookup = HashMap::new();
    for chain_id in [
        CHAIN_ETHEREUM,
        CHAIN_OPTIMISM,
        CHAIN_BSC,
        CHAIN_POLYGON,
        CHAIN_ARBITRUM,
        CHAIN_SEPOLIA,
    ] {
        for router in default_routers_for_chain(chain_id).values().copied() {
            // First insert wins so canonical chain mappings remain stable on collisions.
            lookup.entry(router).or_insert(chain_id);
        }
    }
    lookup
});

fn chain_id_for_router(router: Address) -> Option<u64> {
    ROUTER_CHAIN_LOOKUP.get(&router).copied()
}

sol! {
    struct V2SwapExactInParams {
        address recipient;
        uint256 amountIn;
        uint256 amountOutMin;
        address[] path;
        bool payerIsUser;
    }

    struct V2SwapExactOutParams {
        address recipient;
        uint256 amountOut;
        uint256 amountInMax;
        address[] path;
        bool payerIsUser;
    }

    struct V3SwapExactInParams {
        address recipient;
        uint256 amountIn;
        uint256 amountOutMin;
        bytes path;
        bool payerIsUser;
    }

    struct V3SwapExactOutParams {
        address recipient;
        uint256 amountOut;
        uint256 amountInMax;
        bytes path;
        bool payerIsUser;
    }

    struct UniversalRouterSubPlan {
        bytes commands;
        bytes[] inputs;
    }

    contract UniversalRouterCommandPayload {
        function v2ExactIn(
            address recipient,
            uint256 amountIn,
            uint256 amountOutMin,
            address[] calldata path,
            bool payerIsUser
        ) external;
        function v2ExactOut(
            address recipient,
            uint256 amountOut,
            uint256 amountInMax,
            address[] calldata path,
            bool payerIsUser
        ) external;
        function v3ExactIn(
            address recipient,
            uint256 amountIn,
            uint256 amountOutMin,
            bytes calldata path,
            bool payerIsUser
        ) external;
        function v3ExactOut(
            address recipient,
            uint256 amountOut,
            uint256 amountInMax,
            bytes calldata path,
            bool payerIsUser
        ) external;
    }

    struct SettlerAllowedSlippage {
        address recipient;
        address buyToken;
        uint256 minAmountOut;
    }

    struct SettlerTokenPermissions {
        address token;
        uint256 amount;
    }

    struct SettlerPermitTransferFrom {
        SettlerTokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    contract ZeroXSettler {
        function execute(
            SettlerAllowedSlippage calldata slippage,
            bytes[] calldata actions,
            bytes32 affiliate
        ) external payable returns (bool);

        function executeWithPermit(
            SettlerAllowedSlippage calldata slippage,
            bytes[] calldata actions,
            bytes32 affiliate,
            bytes calldata permitData
        ) external payable returns (bool);
    }

    contract ZeroXAllowanceHolder {
        function exec(
            address operator,
            address token,
            uint256 amount,
            address target,
            bytes calldata data
        ) external payable returns (bytes memory result);
    }

    contract ZeroXSettlerActions {
        function TRANSFER_FROM(
            address recipient,
            SettlerPermitTransferFrom calldata permit,
            bytes calldata sig
        ) external;

        function UNISWAPV2(
            address recipient,
            address sellToken,
            uint256 bps,
            address pool,
            uint24 swapInfo,
            uint256 amountOutMin
        ) external;

        function UNISWAPV3(
            address recipient,
            uint256 bps,
            bytes calldata path,
            uint256 amountOutMin
        ) external;

        function UNISWAPV3_VIP(
            address recipient,
            SettlerPermitTransferFrom calldata permit,
            bytes calldata path,
            bytes calldata sig,
            uint256 amountOutMin
        ) external;
    }

    struct V4PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    struct V4PathKey {
        address intermediateCurrency;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
        bytes hookData;
    }

    struct V4ActionPlan {
        bytes actions;
        bytes[] params;
    }

    contract V4ActionPayload {
        function decode(bytes calldata actions, bytes[] calldata params) external;
    }

    // Universal Router V2 (0x66a9...) uses the original V4 periphery layout.
    struct V4ExactInputSingleParams {
        V4PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        bytes hookData;
    }

    struct V4ExactInputParams {
        address currencyIn;
        V4PathKey[] path;
        uint128 amountIn;
        uint128 amountOutMinimum;
    }

    struct V4ExactOutputSingleParams {
        V4PoolKey poolKey;
        bool zeroForOne;
        uint128 amountOut;
        uint128 amountInMaximum;
        bytes hookData;
    }

    struct V4ExactOutputParams {
        address currencyOut;
        V4PathKey[] path;
        uint128 amountOut;
        uint128 amountInMaximum;
    }

    // Universal Router V2.1.1 adds optional per-hop minimum-price guards.
    struct V4ExactInputSingleParamsV211 {
        V4PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        uint256 minHopPriceX36;
        bytes hookData;
    }

    struct V4ExactInputParamsV211 {
        address currencyIn;
        V4PathKey[] path;
        uint256[] minHopPriceX36;
        uint128 amountIn;
        uint128 amountOutMinimum;
    }

    struct V4ExactOutputSingleParamsV211 {
        V4PoolKey poolKey;
        bool zeroForOne;
        uint128 amountOut;
        uint128 amountInMaximum;
        uint256 minHopPriceX36;
        bytes hookData;
    }

    struct V4ExactOutputParamsV211 {
        address currencyOut;
        V4PathKey[] path;
        uint256[] minHopPriceX36;
        uint128 amountOut;
        uint128 amountInMaximum;
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract GenericMulticall {
        function multicall(bytes[] calldata data) external payable returns (bytes[] memory results);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract GenericMulticallDeadline {
        function multicall(uint256 deadline, bytes[] calldata data) external payable returns (bytes[] memory results);
    }

    struct AggregateCall {
        address target;
        bytes callData;
    }

    struct AggregateCall3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct AggregateCall3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    struct AggregateResult {
        bool success;
        bytes returnData;
    }

    #[sol(rpc)]
    contract GenericAggregateMulticall {
        function aggregate(AggregateCall[] calldata calls)
            external
            payable
            returns (uint256 blockNumber, bytes[] memory returnData);
        function tryAggregate(bool requireSuccess, AggregateCall[] calldata calls)
            external
            payable
            returns (AggregateResult[] memory returnData);
        function aggregate3(AggregateCall3[] calldata calls)
            external
            payable
            returns (AggregateResult[] memory returnData);
        function aggregate3Value(AggregateCall3Value[] calldata calls)
            external
            payable
            returns (AggregateResult[] memory returnData);
        function blockAndAggregate(AggregateCall[] calldata calls)
            external
            payable
            returns (uint256 blockNumber, bytes32 blockHash, AggregateResult[] memory returnData);
        function tryBlockAndAggregate(bool requireSuccess, AggregateCall[] calldata calls)
            external
            payable
            returns (uint256 blockNumber, bytes32 blockHash, AggregateResult[] memory returnData);
    }
}

pub fn decode_swap(tx: &Transaction) -> Option<ObservedSwap> {
    let router = match tx.kind() {
        TxKind::Call(addr) => addr,
        TxKind::Create => return None,
    };
    decode_swap_input(router, tx.input(), tx.value())
}

pub fn decode_swap_for_chain(chain_id: u64, tx: &Transaction) -> Option<ObservedSwap> {
    let router = match tx.kind() {
        TxKind::Call(addr) => addr,
        TxKind::Create => return None,
    };
    decode_swap_input_for_chain(chain_id, router, tx.input(), tx.value())
}

pub fn decode_swap_input(router: Address, input: &[u8], eth_value: U256) -> Option<ObservedSwap> {
    decode_swap_input_inner(router, input, eth_value, 0, chain_id_for_router(router))
}

pub fn decode_swap_input_for_chain(
    chain_id: u64,
    router: Address,
    input: &[u8],
    eth_value: U256,
) -> Option<ObservedSwap> {
    decode_swap_input_inner(router, input, eth_value, 0, Some(chain_id))
}

pub fn extract_swap_deadline(input: &[u8]) -> Option<u64> {
    if input.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = input[..4].try_into().ok()?;
    let as_u64 = |value: U256| -> Option<u64> {
        if value > U256::from(u64::MAX) {
            None
        } else {
            Some(value.to::<u64>())
        }
    };
    match selector {
        UniV2Router::swapExactETHForTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapExactETHForTokensCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapETHForExactTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapETHForExactTokensCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapExactTokensForETHCall::SELECTOR => {
            let decoded = UniV2Router::swapExactTokensForETHCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapTokensForExactETHCall::SELECTOR => {
            let decoded = UniV2Router::swapTokensForExactETHCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapExactTokensForTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapExactTokensForTokensCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapTokensForExactTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapTokensForExactTokensCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            as_u64(decoded.deadline)
        }
        UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            as_u64(decoded.deadline)
        }
        UniV3Router::exactInputSingleCall::SELECTOR => {
            let decoded = UniV3Router::exactInputSingleCall::abi_decode(input).ok()?;
            as_u64(decoded.params.deadline)
        }
        UniV3Router::exactOutputSingleCall::SELECTOR => {
            let decoded = UniV3Router::exactOutputSingleCall::abi_decode(input).ok()?;
            as_u64(decoded.params.deadline)
        }
        UniV3Router::exactInputCall::SELECTOR => {
            let decoded = UniV3Router::exactInputCall::abi_decode(input).ok()?;
            as_u64(decoded.params.deadline)
        }
        UniV3Router::exactOutputCall::SELECTOR => {
            let decoded = UniV3Router::exactOutputCall::abi_decode(input).ok()?;
            as_u64(decoded.params.deadline)
        }
        UniV3MulticallDeadline::multicallCall::SELECTOR => {
            let decoded = UniV3MulticallDeadline::multicallCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        UniversalRouterDeadline::executeCall::SELECTOR => {
            let decoded = UniversalRouterDeadline::executeCall::abi_decode(input).ok()?;
            as_u64(decoded.deadline)
        }
        _ => None,
    }
}

fn decode_generic_multicall(
    router: Address,
    input: &[u8],
    eth_value: U256,
    depth: usize,
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    if depth >= MAX_DECODE_RECURSION {
        return None;
    }

    if let Ok(decoded) = GenericMulticall::multicallCall::abi_decode(input) {
        for nested in decoded.data {
            if let Some(observed) =
                decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1, chain_id)
            {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericMulticallDeadline::multicallCall::abi_decode(input) {
        for nested in decoded.data {
            if let Some(observed) =
                decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1, chain_id)
            {
                return Some(observed);
            }
        }
    }

    None
}

fn decode_generic_aggregate_multicall(
    input: &[u8],
    eth_value: U256,
    depth: usize,
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    if depth >= MAX_DECODE_RECURSION {
        return None;
    }

    if let Ok(decoded) = GenericAggregateMulticall::aggregateCall::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                eth_value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericAggregateMulticall::tryAggregateCall::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                eth_value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericAggregateMulticall::aggregate3Call::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                eth_value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericAggregateMulticall::aggregate3ValueCall::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                call.value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericAggregateMulticall::blockAndAggregateCall::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                eth_value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    if let Ok(decoded) = GenericAggregateMulticall::tryBlockAndAggregateCall::abi_decode(input) {
        for call in decoded.calls {
            if let Some(observed) = decode_swap_input_inner(
                call.target,
                call.callData.as_ref(),
                eth_value,
                depth + 1,
                chain_id,
            ) {
                return Some(observed);
            }
        }
    }

    None
}

const MAX_DECODE_RECURSION: usize = 4;

fn decode_swap_input_inner(
    router: Address,
    input: &[u8],
    eth_value: U256,
    depth: usize,
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    if depth > MAX_DECODE_RECURSION {
        return None;
    }
    if input.len() < 4 {
        return None;
    }

    let observed_aggregator_swap = |router, token_in, token_out, amount_in, min_out, recipient| {
        observed_aggregator_swap_for_chain(
            chain_id, router, token_in, token_out, amount_in, min_out, recipient,
        )
    };
    let observed_from_dex_base_request = |router, base_request, recipient| {
        observed_from_dex_base_request_for_chain(chain_id, router, base_request, recipient)
    };
    let observed_transit_v2 =
        |router, params| observed_transit_v2_for_chain(chain_id, router, params);
    let normalize_balancer_asset =
        |router, asset| normalize_balancer_asset_for_chain(chain_id, router, asset);

    let selector: [u8; 4] = input[..4].try_into().ok()?;
    match selector {
        OneInchAggregationRouter::swapCall::SELECTOR => {
            let decoded = OneInchAggregationRouter::swapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.desc.srcToken,
                decoded.desc.dstToken,
                decoded.desc.amount,
                decoded.desc.minReturnAmount,
                decoded.desc.dstReceiver,
            )
        }
        OneInchAggregationRouterV5::swapCall::SELECTOR => {
            let decoded = OneInchAggregationRouterV5::swapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.desc.srcToken,
                decoded.desc.dstToken,
                decoded.desc.amount,
                decoded.desc.minReturnAmount,
                decoded.desc.dstReceiver,
            )
        }
        ParaSwapAugustusV6::swapExactAmountInCall::SELECTOR => {
            let decoded = ParaSwapAugustusV6::swapExactAmountInCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.swapData.srcToken,
                decoded.swapData.destToken,
                decoded.swapData.fromAmount,
                decoded.swapData.toAmount,
                decoded.swapData.beneficiary,
            )
        }
        ParaSwapAugustusV6::swapExactAmountOutCall::SELECTOR => {
            let decoded = ParaSwapAugustusV6::swapExactAmountOutCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.swapData.srcToken,
                decoded.swapData.destToken,
                decoded.swapData.fromAmount,
                decoded.swapData.toAmount,
                decoded.swapData.beneficiary,
            )
        }
        KyberAggregationRouterV2::swapCall::SELECTOR => {
            let decoded = KyberAggregationRouterV2::swapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.execution.desc.srcToken,
                decoded.execution.desc.dstToken,
                decoded.execution.desc.amount,
                decoded.execution.desc.minReturnAmount,
                decoded.execution.desc.dstReceiver,
            )
        }
        KyberAggregationRouterV2::swapGenericCall::SELECTOR => {
            let decoded = KyberAggregationRouterV2::swapGenericCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.execution.desc.srcToken,
                decoded.execution.desc.dstToken,
                decoded.execution.desc.amount,
                decoded.execution.desc.minReturnAmount,
                decoded.execution.desc.dstReceiver,
            )
        }
        KyberAggregationRouterV2::swapSimpleModeCall::SELECTOR => {
            let decoded = KyberAggregationRouterV2::swapSimpleModeCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.desc.srcToken,
                decoded.desc.dstToken,
                decoded.desc.amount,
                decoded.desc.minReturnAmount,
                decoded.desc.dstReceiver,
            )
        }
        ZeroXExchangeProxy::transformERC20Call::SELECTOR => {
            let decoded = ZeroXExchangeProxy::transformERC20Call::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.inputToken,
                decoded.outputToken,
                decoded.inputTokenAmount,
                decoded.minOutputTokenAmount,
                Address::ZERO,
            )
        }
        ZeroXSettler::executeCall::SELECTOR => {
            let decoded = ZeroXSettler::executeCall::abi_decode(input).ok()?;
            decode_zerox_settler_actions(
                router,
                decoded.slippage,
                decoded.actions,
                eth_value,
                chain_id,
                None,
            )
        }
        ZeroXSettler::executeWithPermitCall::SELECTOR => {
            let decoded = ZeroXSettler::executeWithPermitCall::abi_decode(input).ok()?;
            decode_zerox_settler_actions(
                router,
                decoded.slippage,
                decoded.actions,
                eth_value,
                chain_id,
                None,
            )
        }
        ZeroXAllowanceHolder::execCall::SELECTOR => {
            let decoded = ZeroXAllowanceHolder::execCall::abi_decode(input).ok()?;
            let funding_token =
                normalize_aggregator_token_for_chain(chain_id, router, decoded.token)?;
            decode_zerox_settler_input(
                router,
                decoded.data.as_ref(),
                eth_value,
                chain_id,
                Some((funding_token, decoded.amount)),
            )
        }
        DexRouter::dagSwapByOrderIdCall::SELECTOR => {
            let decoded = DexRouter::dagSwapByOrderIdCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, Address::ZERO)
        }
        DexRouter::dagSwapToCall::SELECTOR => {
            let decoded = DexRouter::dagSwapToCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.receiver)
        }
        DexRouter::smartSwapByOrderIdCall::SELECTOR => {
            let decoded = DexRouter::smartSwapByOrderIdCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, Address::ZERO)
        }
        DexRouter::smartSwapToCall::SELECTOR => {
            let decoded = DexRouter::smartSwapToCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.receiver)
        }
        DexRouter::smartSwapByInvestCall::SELECTOR => {
            let decoded = DexRouter::smartSwapByInvestCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.to)
        }
        DexRouter::smartSwapByInvestWithRefundCall::SELECTOR => {
            let decoded = DexRouter::smartSwapByInvestWithRefundCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.to)
        }
        DexRouter::swapWrapToWithBaseRequestCall::SELECTOR => {
            let decoded = DexRouter::swapWrapToWithBaseRequestCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.receiver)
        }
        DexRouter::uniswapV3SwapToWithBaseRequestCall::SELECTOR => {
            let decoded = DexRouter::uniswapV3SwapToWithBaseRequestCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.receiver)
        }
        DexRouter::unxswapToWithBaseRequestCall::SELECTOR => {
            let decoded = DexRouter::unxswapToWithBaseRequestCall::abi_decode(input).ok()?;
            observed_from_dex_base_request(router, decoded.baseRequest, decoded.receiver)
        }
        TransitSwapRouterV5::exactInputV2SwapCall::SELECTOR => {
            let decoded = TransitSwapRouterV5::exactInputV2SwapCall::abi_decode(input).ok()?;
            observed_transit_v2(router, decoded.exactInput)
        }
        TransitSwapRouterV5::exactInputV2SwapAndGasUsedCall::SELECTOR => {
            let decoded =
                TransitSwapRouterV5::exactInputV2SwapAndGasUsedCall::abi_decode(input).ok()?;
            observed_transit_v2(router, decoded.exactInput)
        }
        TransitSwapRouterV5::exactInputV3SwapCall::SELECTOR => {
            let decoded = TransitSwapRouterV5::exactInputV3SwapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.params.srcToken,
                decoded.params.dstToken,
                decoded.params.amount,
                decoded.params.minReturnAmount,
                decoded.params.dstReceiver,
            )
        }
        TransitSwapRouterV5::exactInputV3SwapAndGasUsedCall::SELECTOR => {
            let decoded =
                TransitSwapRouterV5::exactInputV3SwapAndGasUsedCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                decoded.params.srcToken,
                decoded.params.dstToken,
                decoded.params.amount,
                decoded.params.minReturnAmount,
                decoded.params.dstReceiver,
            )
        }
        RelayRouterV3::multicallCall::SELECTOR => {
            let decoded = RelayRouterV3::multicallCall::abi_decode(input).ok()?;
            decode_relay_calls(router, decoded.calls, depth, eth_value, chain_id)
        }
        RelayApprovalProxyV3::transferAndMulticallCall::SELECTOR => {
            let decoded = RelayApprovalProxyV3::transferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value, chain_id)
        }
        RelayApprovalProxyV3::permitTransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permitTransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value, chain_id)
        }
        RelayApprovalProxyV3::permit3009TransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permit3009TransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value, chain_id)
        }
        RelayApprovalProxyV3::permit2TransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permit2TransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value, chain_id)
        }
        BalancerVault::swapCall::SELECTOR => {
            let decoded = BalancerVault::swapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                normalize_balancer_asset(router, decoded.singleSwap.assetIn),
                normalize_balancer_asset(router, decoded.singleSwap.assetOut),
                decoded.singleSwap.amount,
                U256::ZERO,
                decoded.funds.recipient,
            )
        }
        BalancerVault::batchSwapCall::SELECTOR => {
            let decoded = BalancerVault::batchSwapCall::abi_decode(input).ok()?;
            let first = decoded.swaps.first()?;
            let last = decoded.swaps.last()?;
            let idx_in = usize::try_from(first.assetInIndex).ok()?;
            let idx_out = usize::try_from(last.assetOutIndex).ok()?;
            let token_in = normalize_balancer_asset(router, *decoded.assets.get(idx_in)?);
            let token_out = normalize_balancer_asset(router, *decoded.assets.get(idx_out)?);
            let amount_in = if first.amount > U256::ZERO {
                first.amount
            } else {
                U256::ZERO
            };
            observed_aggregator_swap(
                router,
                token_in,
                token_out,
                amount_in,
                U256::ZERO,
                decoded.funds.recipient,
            )
        }
        UniV2Router::swapExactETHForTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapExactETHForTokensCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: eth_value,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapETHForExactTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapETHForExactTokensCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: eth_value,
                min_out: decoded.amountOut,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapExactTokensForETHCall::SELECTOR => {
            let decoded = UniV2Router::swapExactTokensForETHCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapTokensForExactETHCall::SELECTOR => {
            let decoded = UniV2Router::swapTokensForExactETHCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountInMax,
                min_out: decoded.amountOut,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapExactTokensForTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapExactTokensForTokensCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapTokensForExactTokensCall::SELECTOR => {
            let decoded = UniV2Router::swapTokensForExactTokensCall::abi_decode(input).ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountInMax,
                min_out: decoded.amountOut,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactETHForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: eth_value,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactTokensForETHSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let decoded =
                UniV2Router::swapExactTokensForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                    input,
                )
                .ok()?;
            Some(ObservedSwap {
                router,
                path: decoded.path,
                v3_fees: Vec::new(),
                v3_path: None,
                v4_path: Vec::new(),
                amount_in: decoded.amountIn,
                min_out: decoded.amountOutMin,
                recipient: decoded.to,
                router_kind: RouterKind::V2Like,
            })
        }
        UniV3Router::exactInputSingleCall::SELECTOR => {
            let decoded = UniV3Router::exactInputSingleCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path_bytes = encode_v3_path(&[params.tokenIn, params.tokenOut], &[params.fee.to()]);
            let fee_u32: u32 = params.fee.to::<u32>();
            if !v3_fee_sane(fee_u32) {
                return None;
            }
            if !validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                return None;
            }
            Some(ObservedSwap {
                router,
                path: vec![params.tokenIn, params.tokenOut],
                v3_fees: vec![fee_u32],
                v3_path: path_bytes,
                v4_path: Vec::new(),
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router::exactOutputSingleCall::SELECTOR => {
            let decoded = UniV3Router::exactOutputSingleCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path_bytes = encode_v3_path(&[params.tokenIn, params.tokenOut], &[params.fee.to()]);
            let fee_u32: u32 = params.fee.to::<u32>();
            if !v3_fee_sane(fee_u32) {
                return None;
            }
            if !validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                return None;
            }
            Some(ObservedSwap {
                router,
                path: vec![params.tokenIn, params.tokenOut],
                v3_fees: vec![fee_u32],
                v3_path: path_bytes,
                v4_path: Vec::new(),
                amount_in: params.amountInMaximum,
                min_out: params.amountOut,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router::exactInputCall::SELECTOR => {
            let decoded = UniV3Router::exactInputCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path = parse_v3_path(&params.path)?;
            Some(ObservedSwap {
                router,
                path: path.tokens.clone(),
                v3_fees: path.fees.clone(),
                v3_path: Some(params.path.to_vec()),
                v4_path: Vec::new(),
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router::exactOutputCall::SELECTOR => {
            let decoded = UniV3Router::exactOutputCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path = parse_v3_path(&params.path)?;
            let tokens: Vec<Address> = path.tokens.iter().rev().copied().collect();
            let fees: Vec<u32> = path.fees.iter().rev().copied().collect();
            let canonical_path = encode_v3_path(&tokens, &fees);
            Some(ObservedSwap {
                router,
                path: tokens,
                v3_fees: fees,
                v3_path: canonical_path,
                v4_path: Vec::new(),
                amount_in: params.amountInMaximum,
                min_out: params.amountOut,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router02::exactInputSingleCall::SELECTOR => {
            let decoded = UniV3Router02::exactInputSingleCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let fee_u32 = params.fee.to::<u32>();
            if !v3_fee_sane(fee_u32) || !validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                return None;
            }
            Some(ObservedSwap {
                router,
                path: vec![params.tokenIn, params.tokenOut],
                v3_fees: vec![fee_u32],
                v3_path: encode_v3_path(&[params.tokenIn, params.tokenOut], &[fee_u32]),
                v4_path: Vec::new(),
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router02::exactOutputSingleCall::SELECTOR => {
            let decoded = UniV3Router02::exactOutputSingleCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let fee_u32 = params.fee.to::<u32>();
            if !v3_fee_sane(fee_u32) || !validate_v3_tokens(&[params.tokenIn, params.tokenOut]) {
                return None;
            }
            Some(ObservedSwap {
                router,
                path: vec![params.tokenIn, params.tokenOut],
                v3_fees: vec![fee_u32],
                v3_path: encode_v3_path(&[params.tokenIn, params.tokenOut], &[fee_u32]),
                v4_path: Vec::new(),
                amount_in: params.amountInMaximum,
                min_out: params.amountOut,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router02::exactInputCall::SELECTOR => {
            let decoded = UniV3Router02::exactInputCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path = parse_v3_path(&params.path)?;
            Some(ObservedSwap {
                router,
                path: path.tokens.clone(),
                v3_fees: path.fees.clone(),
                v3_path: Some(params.path.to_vec()),
                v4_path: Vec::new(),
                amount_in: params.amountIn,
                min_out: params.amountOutMinimum,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Router02::exactOutputCall::SELECTOR => {
            let decoded = UniV3Router02::exactOutputCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let path = parse_v3_path(&params.path)?;
            let tokens: Vec<Address> = path.tokens.iter().rev().copied().collect();
            let fees: Vec<u32> = path.fees.iter().rev().copied().collect();
            Some(ObservedSwap {
                router,
                path: tokens.clone(),
                v3_fees: fees.clone(),
                v3_path: encode_v3_path(&tokens, &fees),
                v4_path: Vec::new(),
                amount_in: params.amountInMaximum,
                min_out: params.amountOut,
                recipient: params.recipient,
                router_kind: RouterKind::V3Like,
            })
        }
        UniV3Multicall::multicallCall::SELECTOR => {
            let decoded = UniV3Multicall::multicallCall::abi_decode(input).ok()?;
            for nested in decoded.data {
                if let Some(observed) =
                    decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1, chain_id)
                {
                    return Some(observed);
                }
            }
            None
        }
        UniV3MulticallDeadline::multicallCall::SELECTOR => {
            let decoded = UniV3MulticallDeadline::multicallCall::abi_decode(input).ok()?;
            for nested in decoded.data {
                if let Some(observed) =
                    decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1, chain_id)
                {
                    return Some(observed);
                }
            }
            None
        }
        UniversalRouter::executeCall::SELECTOR => {
            let decoded = UniversalRouter::executeCall::abi_decode(input).ok()?;
            decode_universal_router(router, decoded.commands, decoded.inputs, chain_id, depth)
        }
        UniversalRouterDeadline::executeCall::SELECTOR => {
            let decoded = UniversalRouterDeadline::executeCall::abi_decode(input).ok()?;
            decode_universal_router(router, decoded.commands, decoded.inputs, chain_id, depth)
        }
        _ => decode_generic_multicall(router, input, eth_value, depth, chain_id)
            .or_else(|| decode_generic_aggregate_multicall(input, eth_value, depth, chain_id)),
    }
}

fn effective_decode_chain(chain_id: Option<u64>, router: Address) -> Option<u64> {
    chain_id.or_else(|| chain_id_for_router(router))
}

fn normalize_aggregator_token_for_chain(
    chain_id: Option<u64>,
    router: Address,
    token: Address,
) -> Option<Address> {
    if token == Address::ZERO {
        return None;
    }
    let resolved_chain = effective_decode_chain(chain_id, router);
    let native_sentinel = resolved_chain.map(native_sentinel_for_chain);
    if native_sentinel.is_some() && Some(token) == native_sentinel {
        return resolved_chain.map(wrapped_native_for_chain);
    }
    Some(token)
}

fn normalize_balancer_asset_for_chain(
    chain_id: Option<u64>,
    router: Address,
    asset: Address,
) -> Address {
    if asset == Address::ZERO {
        return effective_decode_chain(chain_id, router)
            .map(wrapped_native_for_chain)
            .unwrap_or(Address::ZERO);
    }
    asset
}

fn observed_aggregator_swap_for_chain(
    chain_id: Option<u64>,
    router: Address,
    token_in_raw: Address,
    token_out_raw: Address,
    amount_in: U256,
    min_out: U256,
    recipient: Address,
) -> Option<ObservedSwap> {
    let token_in = normalize_aggregator_token_for_chain(chain_id, router, token_in_raw)?;
    let token_out = normalize_aggregator_token_for_chain(chain_id, router, token_out_raw)?;
    if token_in == token_out || amount_in.is_zero() {
        return None;
    }
    Some(ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: Vec::new(),
        v3_path: None,
        v4_path: Vec::new(),
        amount_in,
        min_out,
        recipient,
        router_kind: RouterKind::V2Like,
    })
}

fn decode_zerox_settler_actions(
    router: Address,
    slippage: SettlerAllowedSlippage,
    actions: Vec<Bytes>,
    eth_value: U256,
    chain_id: Option<u64>,
    external_funding: Option<(Address, U256)>,
) -> Option<ObservedSwap> {
    let buy_token = normalize_aggregator_token_for_chain(chain_id, router, slippage.buyToken)?;
    let mut funded = external_funding;

    for action in actions {
        let input = action.as_ref();
        let Some(selector) = input.get(..4) else {
            continue;
        };

        if selector == ZeroXSettlerActions::TRANSFER_FROMCall::SELECTOR {
            let Ok(decoded) = ZeroXSettlerActions::TRANSFER_FROMCall::abi_decode(input) else {
                continue;
            };
            let token = normalize_aggregator_token_for_chain(
                chain_id,
                router,
                decoded.permit.permitted.token,
            )?;
            funded = Some((token, decoded.permit.permitted.amount));
            continue;
        }

        if selector == ZeroXSettlerActions::UNISWAPV2Call::SELECTOR {
            let Ok(decoded) = ZeroXSettlerActions::UNISWAPV2Call::abi_decode(input) else {
                continue;
            };
            let sell_token =
                normalize_aggregator_token_for_chain(chain_id, router, decoded.sellToken)?;
            let funded_amount = funded
                .filter(|(token, _)| *token == sell_token)
                .map(|(_, amount)| amount)
                .unwrap_or_else(|| {
                    if sell_token
                        == effective_decode_chain(chain_id, router)
                            .map(wrapped_native_for_chain)
                            .unwrap_or(Address::ZERO)
                    {
                        eth_value
                    } else {
                        U256::ZERO
                    }
                });
            let amount_in = funded_amount
                .saturating_mul(decoded.bps)
                .checked_div(U256::from(10_000u64))
                .unwrap_or(U256::ZERO);
            return observed_aggregator_swap_for_chain(
                chain_id,
                router,
                sell_token,
                buy_token,
                amount_in,
                decoded.amountOutMin.max(slippage.minAmountOut),
                decoded.recipient,
            )
            .map(|mut observed| {
                observed.router_kind = RouterKind::V2Like;
                observed
            });
        }

        if selector == ZeroXSettlerActions::UNISWAPV3Call::SELECTOR {
            let Ok(decoded) = ZeroXSettlerActions::UNISWAPV3Call::abi_decode(input) else {
                continue;
            };
            let path = parse_v3_path(decoded.path.as_ref())?;
            let sell_token = *path.tokens.first()?;
            let funded_amount = funded
                .filter(|(token, _)| *token == sell_token)
                .map(|(_, amount)| amount)
                .unwrap_or(eth_value);
            let amount_in = funded_amount
                .saturating_mul(decoded.bps)
                .checked_div(U256::from(10_000u64))
                .unwrap_or(U256::ZERO);
            return Some(ObservedSwap {
                router,
                path: path.tokens.clone(),
                v3_fees: path.fees.clone(),
                v3_path: Some(decoded.path.to_vec()),
                v4_path: Vec::new(),
                amount_in,
                min_out: decoded.amountOutMin.max(slippage.minAmountOut),
                recipient: decoded.recipient,
                router_kind: RouterKind::V3Like,
            });
        }

        if selector == ZeroXSettlerActions::UNISWAPV3_VIPCall::SELECTOR {
            let Ok(decoded) = ZeroXSettlerActions::UNISWAPV3_VIPCall::abi_decode(input) else {
                continue;
            };
            let path = parse_v3_path(decoded.path.as_ref())?;
            let permitted_token = normalize_aggregator_token_for_chain(
                chain_id,
                router,
                decoded.permit.permitted.token,
            )?;
            if path.tokens.first().copied() != Some(permitted_token) {
                return None;
            }
            return Some(ObservedSwap {
                router,
                path: path.tokens.clone(),
                v3_fees: path.fees.clone(),
                v3_path: Some(decoded.path.to_vec()),
                v4_path: Vec::new(),
                amount_in: decoded.permit.permitted.amount,
                min_out: decoded.amountOutMin.max(slippage.minAmountOut),
                recipient: decoded.recipient,
                router_kind: RouterKind::V3Like,
            });
        }
    }
    None
}

fn decode_zerox_settler_input(
    router: Address,
    input: &[u8],
    eth_value: U256,
    chain_id: Option<u64>,
    external_funding: Option<(Address, U256)>,
) -> Option<ObservedSwap> {
    let selector = input.get(..4)?;
    if selector == ZeroXSettler::executeCall::SELECTOR {
        let decoded = ZeroXSettler::executeCall::abi_decode(input).ok()?;
        return decode_zerox_settler_actions(
            router,
            decoded.slippage,
            decoded.actions,
            eth_value,
            chain_id,
            external_funding,
        );
    }
    if selector == ZeroXSettler::executeWithPermitCall::SELECTOR {
        let decoded = ZeroXSettler::executeWithPermitCall::abi_decode(input).ok()?;
        return decode_zerox_settler_actions(
            router,
            decoded.slippage,
            decoded.actions,
            eth_value,
            chain_id,
            external_funding,
        );
    }
    None
}

fn u256_word_to_address(raw: U256) -> Option<Address> {
    let bytes = raw.to_be_bytes::<32>();
    let addr = Address::from_slice(&bytes[12..]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

fn observed_from_dex_base_request_for_chain(
    chain_id: Option<u64>,
    router: Address,
    base_request: DexRouter::DexBaseRequest,
    recipient: Address,
) -> Option<ObservedSwap> {
    let token_in = u256_word_to_address(base_request.fromToken)?;
    observed_aggregator_swap_for_chain(
        chain_id,
        router,
        token_in,
        base_request.toToken,
        base_request.fromTokenAmount,
        base_request.minReturnAmount,
        recipient,
    )
}

fn observed_transit_v2_for_chain(
    chain_id: Option<u64>,
    router: Address,
    params: TransitSwapRouterV5::TransitExactInputV2,
) -> Option<ObservedSwap> {
    if params.path.len() < 2 {
        return None;
    }
    let mut path: Vec<Address> = params
        .path
        .iter()
        .copied()
        .filter_map(|token| normalize_aggregator_token_for_chain(chain_id, router, token))
        .collect();
    if path.len() < 2 {
        return None;
    }
    // Path can contain duplicates in malformed payloads; keep at least endpoints sane.
    if path.first() == path.last() {
        return None;
    }
    let recipient = if params.dstReceiver == Address::ZERO {
        router
    } else {
        params.dstReceiver
    };
    let min_out = params.minReturnAmount;
    let amount_in = params.amount;
    Some(ObservedSwap {
        router,
        path: std::mem::take(&mut path),
        v3_fees: Vec::new(),
        v3_path: None,
        v4_path: Vec::new(),
        amount_in,
        min_out,
        recipient,
        router_kind: RouterKind::V2Like,
    })
}

fn decode_relay_calls(
    router: Address,
    calls: Vec<RelayRouterV3::RelayCall>,
    depth: usize,
    eth_value: U256,
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    let _ = router;
    for call in calls.iter() {
        if let Some(observed) = decode_swap_input_inner(
            call.target,
            call.callData.as_ref(),
            call.value,
            depth + 1,
            chain_id,
        ) {
            // Some relay wrappers drop per-call value even when the outer tx carries ETH.
            // If we decoded a zero-input ETH route from a zero-value nested leg, retry once
            // with the outer value to avoid silently classifying the swap as amount_in=0.
            if observed.amount_in.is_zero()
                && call.value.is_zero()
                && !eth_value.is_zero()
                && let Some(fallback) = decode_swap_input_inner(
                    call.target,
                    call.callData.as_ref(),
                    eth_value,
                    depth + 1,
                    chain_id,
                )
                && !fallback.amount_in.is_zero()
            {
                return Some(fallback);
            }
            return Some(observed);
        }
    }
    // Fallback: some relays do not forward per-call value cleanly.
    for call in calls.iter() {
        if let Some(observed) = decode_swap_input_inner(
            call.target,
            call.callData.as_ref(),
            eth_value,
            depth + 1,
            chain_id,
        ) {
            return Some(observed);
        }
    }
    None
}

fn decode_relay_approval_calls(
    router: Address,
    calls: Vec<RelayApprovalProxyV3::RelayApprovalCall>,
    depth: usize,
    eth_value: U256,
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    let relay_calls: Vec<RelayRouterV3::RelayCall> = calls
        .into_iter()
        .map(|c| RelayRouterV3::RelayCall {
            target: c.target,
            allowFailure: c.allowFailure,
            value: c.value,
            callData: c.callData,
        })
        .collect();
    decode_relay_calls(router, relay_calls, depth, eth_value, chain_id)
}

const UR_CMD_V3_SWAP_EXACT_IN: u8 = 0x00;
const UR_CMD_V3_SWAP_EXACT_OUT: u8 = 0x01;
const UR_CMD_V2_SWAP_EXACT_IN: u8 = 0x08;
const UR_CMD_V2_SWAP_EXACT_OUT: u8 = 0x09;
const UR_CMD_V4_SWAP: u8 = 0x10;
const UR_CMD_EXECUTE_SUB_PLAN: u8 = 0x21;
const UR_COMMAND_TYPE_MASK: u8 = 0x7f;

const V4_ACTION_SWAP_EXACT_IN_SINGLE: u8 = 0x06;
const V4_ACTION_SWAP_EXACT_IN: u8 = 0x07;
const V4_ACTION_SWAP_EXACT_OUT_SINGLE: u8 = 0x08;
const V4_ACTION_SWAP_EXACT_OUT: u8 = 0x09;

fn normalize_v4_currency(
    chain_id: Option<u64>,
    router: Address,
    currency: Address,
) -> Option<Address> {
    if currency == Address::ZERO {
        return effective_decode_chain(chain_id, router).map(wrapped_native_for_chain);
    }
    Some(currency)
}

fn observed_v4_swap(
    router: Address,
    chain_id: Option<u64>,
    raw_path: Vec<Address>,
    fees: Vec<u32>,
    v4_path: Vec<ObservedV4Hop>,
    amount_in: U256,
    min_out: U256,
) -> Option<ObservedSwap> {
    if amount_in.is_zero() || raw_path.len() < 2 || fees.len() + 1 != raw_path.len() {
        return None;
    }
    let path: Vec<Address> = raw_path
        .into_iter()
        .map(|currency| normalize_v4_currency(chain_id, router, currency))
        .collect::<Option<_>>()?;
    if path.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(ObservedSwap {
        router,
        path,
        v3_fees: fees,
        v3_path: None,
        v4_path,
        amount_in,
        min_out,
        recipient: Address::ZERO,
        router_kind: RouterKind::V4Like,
    })
}

fn observed_v4_key(pool_key: &V4PoolKey) -> ObservedV4PoolKey {
    ObservedV4PoolKey {
        currency0: pool_key.currency0,
        currency1: pool_key.currency1,
        fee: pool_key.fee.to::<u32>(),
        tick_spacing: pool_key.tickSpacing.as_i32(),
        hooks: pool_key.hooks,
    }
}

fn v4_single_path(
    pool_key: V4PoolKey,
    zero_for_one: bool,
    hook_data: Bytes,
) -> (Vec<Address>, Vec<u32>, Vec<ObservedV4Hop>) {
    let path = if zero_for_one {
        vec![pool_key.currency0, pool_key.currency1]
    } else {
        vec![pool_key.currency1, pool_key.currency0]
    };
    let fee = pool_key.fee.to::<u32>();
    let hop = ObservedV4Hop {
        pool_key: observed_v4_key(&pool_key),
        zero_for_one,
        hook_data,
    };
    (path, vec![fee], vec![hop])
}

fn v4_exact_input_path(
    currency_in: Address,
    path_keys: &[V4PathKey],
) -> (Vec<Address>, Vec<u32>, Vec<ObservedV4Hop>) {
    let mut path = Vec::with_capacity(path_keys.len() + 1);
    let mut fees = Vec::with_capacity(path_keys.len());
    let mut hops = Vec::with_capacity(path_keys.len());
    let mut current = currency_in;
    path.push(currency_in);
    for key in path_keys {
        let next = key.intermediateCurrency;
        let (currency0, currency1, zero_for_one) = if current < next {
            (current, next, true)
        } else {
            (next, current, false)
        };
        path.push(next);
        fees.push(key.fee.to::<u32>());
        hops.push(ObservedV4Hop {
            pool_key: ObservedV4PoolKey {
                currency0,
                currency1,
                fee: key.fee.to::<u32>(),
                tick_spacing: key.tickSpacing.as_i32(),
                hooks: key.hooks,
            },
            zero_for_one,
            hook_data: key.hookData.clone(),
        });
        current = next;
    }
    (path, fees, hops)
}

fn v4_exact_output_path(
    currency_out: Address,
    path_keys: &[V4PathKey],
) -> (Vec<Address>, Vec<u32>, Vec<ObservedV4Hop>) {
    let mut path: Vec<Address> = path_keys
        .iter()
        .map(|key| key.intermediateCurrency)
        .collect();
    let fees = path_keys.iter().map(|key| key.fee.to::<u32>()).collect();
    path.push(currency_out);
    let hops = path
        .windows(2)
        .zip(path_keys.iter())
        .map(|(pair, key)| {
            let (currency0, currency1, zero_for_one) = if pair[0] < pair[1] {
                (pair[0], pair[1], true)
            } else {
                (pair[1], pair[0], false)
            };
            ObservedV4Hop {
                pool_key: ObservedV4PoolKey {
                    currency0,
                    currency1,
                    fee: key.fee.to::<u32>(),
                    tick_spacing: key.tickSpacing.as_i32(),
                    hooks: key.hooks,
                },
                zero_for_one,
                hook_data: key.hookData.clone(),
            }
        })
        .collect();
    (path, fees, hops)
}

fn decode_v4_action_plan(
    router: Address,
    input: &[u8],
    chain_id: Option<u64>,
) -> Option<ObservedSwap> {
    // Universal Router encodes the V4 action payload as the flat tuple
    // `abi.encode(bytes actions, bytes[] params)`. Older local fixtures encoded a dynamic
    // struct wrapper, so retain that as a compatibility fallback.
    let mut action_calldata = Vec::with_capacity(input.len() + 4);
    action_calldata.extend_from_slice(&V4ActionPayload::decodeCall::SELECTOR);
    action_calldata.extend_from_slice(input);
    let (actions, params) = V4ActionPayload::decodeCall::abi_decode(&action_calldata)
        .ok()
        .map(|decoded| (decoded.actions, decoded.params))
        .or_else(|| {
            V4ActionPlan::abi_decode(input)
                .ok()
                .map(|decoded| (decoded.actions, decoded.params))
        })?;
    let action_count = actions.len().min(params.len());
    for (index, action) in actions.iter().copied().take(action_count).enumerate() {
        let params = params[index].as_ref();
        match action {
            V4_ACTION_SWAP_EXACT_IN_SINGLE => {
                if let Ok(swap) = V4ExactInputSingleParamsV211::abi_decode(params) {
                    let (path, fees, v4_path) =
                        v4_single_path(swap.poolKey, swap.zeroForOne, swap.hookData);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountIn),
                        U256::from(swap.amountOutMinimum),
                    );
                }
                if let Ok(swap) = V4ExactInputSingleParams::abi_decode(params) {
                    let (path, fees, v4_path) =
                        v4_single_path(swap.poolKey, swap.zeroForOne, swap.hookData);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountIn),
                        U256::from(swap.amountOutMinimum),
                    );
                }
            }
            V4_ACTION_SWAP_EXACT_IN => {
                if let Ok(swap) = V4ExactInputParamsV211::abi_decode(params) {
                    let (path, fees, v4_path) = v4_exact_input_path(swap.currencyIn, &swap.path);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountIn),
                        U256::from(swap.amountOutMinimum),
                    );
                }
                if let Ok(swap) = V4ExactInputParams::abi_decode(params) {
                    let (path, fees, v4_path) = v4_exact_input_path(swap.currencyIn, &swap.path);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountIn),
                        U256::from(swap.amountOutMinimum),
                    );
                }
            }
            V4_ACTION_SWAP_EXACT_OUT_SINGLE => {
                if let Ok(swap) = V4ExactOutputSingleParamsV211::abi_decode(params) {
                    let (path, fees, v4_path) =
                        v4_single_path(swap.poolKey, swap.zeroForOne, swap.hookData);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountInMaximum),
                        U256::from(swap.amountOut),
                    );
                }
                if let Ok(swap) = V4ExactOutputSingleParams::abi_decode(params) {
                    let (path, fees, v4_path) =
                        v4_single_path(swap.poolKey, swap.zeroForOne, swap.hookData);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountInMaximum),
                        U256::from(swap.amountOut),
                    );
                }
            }
            V4_ACTION_SWAP_EXACT_OUT => {
                if let Ok(swap) = V4ExactOutputParamsV211::abi_decode(params) {
                    let (path, fees, v4_path) = v4_exact_output_path(swap.currencyOut, &swap.path);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountInMaximum),
                        U256::from(swap.amountOut),
                    );
                }
                if let Ok(swap) = V4ExactOutputParams::abi_decode(params) {
                    let (path, fees, v4_path) = v4_exact_output_path(swap.currencyOut, &swap.path);
                    return observed_v4_swap(
                        router,
                        chain_id,
                        path,
                        fees,
                        v4_path,
                        U256::from(swap.amountInMaximum),
                        U256::from(swap.amountOut),
                    );
                }
            }
            _ => {}
        }
    }
    None
}

fn decode_ur_v2_exact_in(input: &[u8]) -> Option<V2SwapExactInParams> {
    let mut calldata = Vec::with_capacity(input.len() + 4);
    calldata.extend_from_slice(&UniversalRouterCommandPayload::v2ExactInCall::SELECTOR);
    calldata.extend_from_slice(input);
    UniversalRouterCommandPayload::v2ExactInCall::abi_decode(&calldata)
        .ok()
        .map(|call| V2SwapExactInParams {
            recipient: call.recipient,
            amountIn: call.amountIn,
            amountOutMin: call.amountOutMin,
            path: call.path,
            payerIsUser: call.payerIsUser,
        })
        .or_else(|| V2SwapExactInParams::abi_decode(input).ok())
}

fn decode_ur_v2_exact_out(input: &[u8]) -> Option<V2SwapExactOutParams> {
    let mut calldata = Vec::with_capacity(input.len() + 4);
    calldata.extend_from_slice(&UniversalRouterCommandPayload::v2ExactOutCall::SELECTOR);
    calldata.extend_from_slice(input);
    UniversalRouterCommandPayload::v2ExactOutCall::abi_decode(&calldata)
        .ok()
        .map(|call| V2SwapExactOutParams {
            recipient: call.recipient,
            amountOut: call.amountOut,
            amountInMax: call.amountInMax,
            path: call.path,
            payerIsUser: call.payerIsUser,
        })
        .or_else(|| V2SwapExactOutParams::abi_decode(input).ok())
}

fn decode_ur_v3_exact_in(input: &[u8]) -> Option<V3SwapExactInParams> {
    let mut calldata = Vec::with_capacity(input.len() + 4);
    calldata.extend_from_slice(&UniversalRouterCommandPayload::v3ExactInCall::SELECTOR);
    calldata.extend_from_slice(input);
    UniversalRouterCommandPayload::v3ExactInCall::abi_decode(&calldata)
        .ok()
        .map(|call| V3SwapExactInParams {
            recipient: call.recipient,
            amountIn: call.amountIn,
            amountOutMin: call.amountOutMin,
            path: call.path,
            payerIsUser: call.payerIsUser,
        })
        .or_else(|| V3SwapExactInParams::abi_decode(input).ok())
}

fn decode_ur_v3_exact_out(input: &[u8]) -> Option<V3SwapExactOutParams> {
    let mut calldata = Vec::with_capacity(input.len() + 4);
    calldata.extend_from_slice(&UniversalRouterCommandPayload::v3ExactOutCall::SELECTOR);
    calldata.extend_from_slice(input);
    UniversalRouterCommandPayload::v3ExactOutCall::abi_decode(&calldata)
        .ok()
        .map(|call| V3SwapExactOutParams {
            recipient: call.recipient,
            amountOut: call.amountOut,
            amountInMax: call.amountInMax,
            path: call.path,
            payerIsUser: call.payerIsUser,
        })
        .or_else(|| V3SwapExactOutParams::abi_decode(input).ok())
}

fn decode_universal_router(
    router: Address,
    commands: Bytes,
    inputs: Vec<Bytes>,
    chain_id: Option<u64>,
    depth: usize,
) -> Option<ObservedSwap> {
    let cmd_bytes = commands.as_ref();
    let count = std::cmp::min(cmd_bytes.len(), inputs.len());
    for (idx, cmd_byte) in cmd_bytes.iter().enumerate().take(count) {
        let cmd = *cmd_byte & UR_COMMAND_TYPE_MASK;
        let input = &inputs[idx];
        match cmd {
            UR_CMD_V2_SWAP_EXACT_IN => {
                let Some(decoded) = decode_ur_v2_exact_in(input.as_ref()) else {
                    continue;
                };
                return Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    v4_path: Vec::new(),
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V2Like,
                });
            }
            UR_CMD_V2_SWAP_EXACT_OUT => {
                let Some(decoded) = decode_ur_v2_exact_out(input.as_ref()) else {
                    continue;
                };
                return Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    v4_path: Vec::new(),
                    amount_in: decoded.amountInMax,
                    min_out: decoded.amountOut,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V2Like,
                });
            }
            UR_CMD_V3_SWAP_EXACT_IN => {
                let Some(decoded) = decode_ur_v3_exact_in(input.as_ref()) else {
                    continue;
                };
                let Some(path) = parse_v3_path(decoded.path.as_ref()) else {
                    continue;
                };
                return Some(ObservedSwap {
                    router,
                    path: path.tokens.clone(),
                    v3_fees: path.fees.clone(),
                    v3_path: Some(decoded.path.to_vec()),
                    v4_path: Vec::new(),
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V3Like,
                });
            }
            UR_CMD_V3_SWAP_EXACT_OUT => {
                let Some(decoded) = decode_ur_v3_exact_out(input.as_ref()) else {
                    continue;
                };
                let Some(path) = parse_v3_path(decoded.path.as_ref()) else {
                    continue;
                };
                let tokens: Vec<Address> = path.tokens.iter().rev().copied().collect();
                let fees: Vec<u32> = path.fees.iter().rev().copied().collect();
                return Some(ObservedSwap {
                    router,
                    path: tokens.clone(),
                    v3_fees: fees.clone(),
                    v3_path: encode_v3_path(&tokens, &fees),
                    v4_path: Vec::new(),
                    amount_in: decoded.amountInMax,
                    min_out: decoded.amountOut,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V3Like,
                });
            }
            UR_CMD_V4_SWAP => {
                if let Some(observed) = decode_v4_action_plan(router, input.as_ref(), chain_id) {
                    return Some(observed);
                }
            }
            UR_CMD_EXECUTE_SUB_PLAN if depth < MAX_DECODE_RECURSION => {
                let Ok(sub_plan) = UniversalRouterSubPlan::abi_decode(input.as_ref()) else {
                    continue;
                };
                if let Some(observed) = decode_universal_router(
                    router,
                    sub_plan.commands,
                    sub_plan.inputs,
                    chain_id,
                    depth + 1,
                ) {
                    return Some(observed);
                }
            }
            _ => {}
        }
    }
    None
}

pub fn target_token(path: &[Address], wrapped_native: Address) -> Option<Address> {
    if path.is_empty() {
        return None;
    }

    let first = *path.first().unwrap_or(&wrapped_native);
    let last = *path.last().unwrap_or(&wrapped_native);

    if first == wrapped_native && last != wrapped_native {
        return Some(last);
    }

    if last == wrapped_native && first != wrapped_native {
        return Some(first);
    }

    path.iter()
        .copied()
        .rev()
        .find(|addr| addr != &wrapped_native)
}

pub fn direction(observed: &ObservedSwap, wrapped_native: Address) -> SwapDirection {
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

pub fn parse_v3_path(path: &[u8]) -> Option<ParsedV3Path> {
    const ADDRESS_BYTES: usize = 20;
    const FEE_BYTES: usize = 3;
    const HOP_BYTES: usize = ADDRESS_BYTES + FEE_BYTES;

    if path.len() < ADDRESS_BYTES + HOP_BYTES {
        return None;
    }

    let mut tokens = Vec::new();
    let mut fees = Vec::new();

    let first = path.get(..ADDRESS_BYTES)?;
    tokens.push(Address::from_slice(first));

    let mut cursor = ADDRESS_BYTES;
    while cursor + HOP_BYTES <= path.len() {
        let fee_bytes = path.get(cursor..cursor + FEE_BYTES)?;
        let token_bytes = path.get(cursor + FEE_BYTES..cursor + HOP_BYTES)?;

        let fee = U24::try_from_be_slice(fee_bytes).map(|v| v.to::<u32>())?;
        if !v3_fee_sane(fee) {
            return None;
        }

        tokens.push(Address::from_slice(token_bytes));
        fees.push(fee);

        cursor += HOP_BYTES;

        if tokens.len() > 4 {
            return None;
        }
    }

    if cursor != path.len() || tokens.len() < 2 {
        return None;
    }
    if !validate_v3_tokens(&tokens) {
        return None;
    }

    Some(ParsedV3Path { tokens, fees })
}

pub fn encode_v3_path(tokens: &[Address], fees: &[u32]) -> Option<Vec<u8>> {
    if tokens.len() < 2 || fees.len() + 1 != tokens.len() {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(tokens.len() * 23);
    out.extend_from_slice(tokens[0].as_slice());
    for (i, fee) in fees.iter().enumerate() {
        out.extend_from_slice(&fee.to_be_bytes()[1..]);
        out.extend_from_slice(tokens[i + 1].as_slice());
    }
    Some(out)
}

pub fn reverse_v3_path(tokens: &[Address], fees: &[u32]) -> Option<Vec<u8>> {
    if tokens.len() < 2 || fees.len() + 1 != tokens.len() {
        return None;
    }
    let rev_tokens: Vec<Address> = tokens.iter().rev().copied().collect();
    let rev_fees: Vec<u32> = fees.iter().rev().copied().collect();
    encode_v3_path(&rev_tokens, &rev_fees)
}

pub fn v3_fee_sane(fee: u32) -> bool {
    matches!(fee, 100 | 500 | 3000 | 10_000)
}

fn validate_v3_tokens(tokens: &[Address]) -> bool {
    let max_hops = 4;
    tokens.len() >= 2 && tokens.len() <= max_hops
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::services::strategy::routers::{
        DexRouter, KyberAggregationRouterV2, OneInchAggregationRouter, OneInchAggregationRouterV5,
        ParaSwapAugustusV6, RelayRouterV3, TransitSwapRouterV5, UniV2Router, UniV3Multicall,
        UniV3Router, UniV3Router02, UniversalRouter, ZeroXExchangeProxy,
    };
    use alloy::primitives::{B256, Bytes};
    use alloy::primitives::{U160, aliases::U24};
    use alloy::sol_types::SolCall;
    use alloy_sol_types::SolValue;

    #[test]
    fn decodes_swap_router02_exact_input() {
        let router = Address::from([0x68; 20]);
        let token_in = Address::from([0x11; 20]);
        let token_out = Address::from([0x22; 20]);
        let recipient = Address::from([0x33; 20]);
        let path = encode_v3_path(&[token_in, token_out], &[500]).expect("V3 path");
        let call = UniV3Router02::exactInputCall {
            params: UniV3Router02::ExactInputParams {
                path: path.clone().into(),
                recipient,
                amountIn: U256::from(123u64),
                amountOutMinimum: U256::from(100u64),
            },
        };

        let observed = decode_swap_input(router, &call.abi_encode(), U256::ZERO)
            .expect("decode SwapRouter02 exactInput");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.v3_fees, vec![500]);
        assert_eq!(observed.amount_in, U256::from(123u64));
        assert_eq!(observed.min_out, U256::from(100u64));
        assert_eq!(observed.recipient, recipient);
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_swap_router02_exact_output_reversed_path() {
        let router = Address::from([0x68; 20]);
        let token_in = Address::from([0x11; 20]);
        let token_out = Address::from([0x22; 20]);
        let reversed_path =
            encode_v3_path(&[token_out, token_in], &[3000]).expect("reversed V3 path");
        let call = UniV3Router02::exactOutputCall {
            params: UniV3Router02::ExactOutputParams {
                path: reversed_path.into(),
                recipient: Address::from([0x44; 20]),
                amountOut: U256::from(77u64),
                amountInMaximum: U256::from(99u64),
            },
        };

        let observed = decode_swap_input(router, &call.abi_encode(), U256::ZERO)
            .expect("decode SwapRouter02 exactOutput");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.v3_fees, vec![3000]);
        assert_eq!(observed.amount_in, U256::from(99u64));
        assert_eq!(observed.min_out, U256::from(77u64));
    }

    #[test]
    fn decodes_oneinch_swap_description() {
        let router = crate::common::constants::default_oneinch_routers(
            crate::common::constants::CHAIN_ETHEREUM,
        )
        .into_iter()
        .next()
        .unwrap_or_else(|| Address::from([0x11; 20]));
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let recipient = Address::from([0x33; 20]);

        let call = OneInchAggregationRouter::swapCall {
            executor: Address::ZERO,
            desc: OneInchAggregationRouter::SwapDescription {
                srcToken: usdc,
                dstToken: weth,
                srcReceiver: Address::ZERO,
                dstReceiver: recipient,
                amount: U256::from(1_000_000u64),
                minReturnAmount: U256::from(1_000_000_000_000u64),
                flags: U256::ZERO,
            },
            data: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed = decode_swap_input(router, &input, U256::ZERO).expect("decode oneinch swap");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(1_000_000_000_000u64));
        assert_eq!(observed.recipient, recipient);
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn maps_oneinch_native_sentinel_to_weth_mainnet() {
        let router = crate::common::constants::default_oneinch_routers(
            crate::common::constants::CHAIN_ETHEREUM,
        )
        .into_iter()
        .next()
        .unwrap_or_else(|| Address::from([0x11; 20]));
        let native_sentinel = crate::common::constants::native_sentinel_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let dai = Address::from([0x44; 20]);

        let call = OneInchAggregationRouter::swapCall {
            executor: Address::ZERO,
            desc: OneInchAggregationRouter::SwapDescription {
                srcToken: native_sentinel,
                dstToken: dai,
                srcReceiver: Address::ZERO,
                dstReceiver: Address::ZERO,
                amount: U256::from(1_000_000_000_000_000u64),
                minReturnAmount: U256::from(1_000_000_000_000_000u64),
                flags: U256::ZERO,
            },
            data: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed =
            decode_swap_input(router, &input, U256::ZERO).expect("decode oneinch native sentinel");
        assert_eq!(
            observed.path[0],
            crate::common::constants::wrapped_native_for_chain(
                crate::common::constants::CHAIN_ETHEREUM
            )
        );
        assert_eq!(observed.path[1], dai);
    }

    #[test]
    fn explicit_chain_disambiguates_deterministic_balancer_vault_address() {
        let vault = crate::common::constants::default_balancer_vault_for_chain(
            crate::common::constants::CHAIN_SEPOLIA,
        )
        .expect("Sepolia Balancer vault");
        let sepolia_weth = normalize_balancer_asset_for_chain(
            Some(crate::common::constants::CHAIN_SEPOLIA),
            vault,
            Address::ZERO,
        );
        let mainnet_weth = normalize_balancer_asset_for_chain(
            Some(crate::common::constants::CHAIN_ETHEREUM),
            vault,
            Address::ZERO,
        );
        assert_eq!(
            sepolia_weth,
            crate::common::constants::wrapped_native_for_chain(
                crate::common::constants::CHAIN_SEPOLIA
            )
        );
        assert_eq!(
            mainnet_weth,
            crate::common::constants::wrapped_native_for_chain(
                crate::common::constants::CHAIN_ETHEREUM
            )
        );
        assert_ne!(sepolia_weth, mainnet_weth);
    }

    #[test]
    fn unknown_router_does_not_force_mainnet_native_mapping() {
        let router = Address::from([0x99; 20]);
        let native_sentinel = crate::common::constants::native_sentinel_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let dai = Address::from([0x45; 20]);

        let call = OneInchAggregationRouter::swapCall {
            executor: Address::ZERO,
            desc: OneInchAggregationRouter::SwapDescription {
                srcToken: native_sentinel,
                dstToken: dai,
                srcReceiver: Address::ZERO,
                dstReceiver: Address::ZERO,
                amount: U256::from(2_000_000_000_000_000u64),
                minReturnAmount: U256::from(1_000_000u64),
                flags: U256::ZERO,
            },
            data: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed =
            decode_swap_input(router, &input, U256::ZERO).expect("decode oneinch unknown router");
        assert_eq!(observed.path[0], native_sentinel);
        assert_eq!(observed.path[1], dai);
    }

    #[test]
    fn decodes_oneinch_v5_swap_description() {
        let router = Address::from([0x55; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let recipient = Address::from([0x33; 20]);

        let call = OneInchAggregationRouterV5::swapCall {
            executor: Address::ZERO,
            desc: OneInchAggregationRouterV5::SwapDescriptionV5 {
                srcToken: usdc,
                dstToken: weth,
                srcReceiver: Address::ZERO,
                dstReceiver: recipient,
                amount: U256::from(12_345u64),
                minReturnAmount: U256::from(6_789u64),
                flags: U256::ZERO,
            },
            permit: Bytes::new(),
            data: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed = decode_swap_input(router, &input, U256::ZERO).expect("decode oneinch v5");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(12_345u64));
        assert_eq!(observed.min_out, U256::from(6_789u64));
        assert_eq!(observed.recipient, recipient);
    }

    #[test]
    fn decodes_paraswap_v6_exact_amount_in() {
        let router = Address::from([0x66; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let recipient = Address::from([0x77; 20]);
        let call = ParaSwapAugustusV6::swapExactAmountInCall {
            executor: Address::ZERO,
            swapData: ParaSwapAugustusV6::SwapData {
                srcToken: usdc,
                destToken: weth,
                fromAmount: U256::from(1_000_000u64),
                toAmount: U256::from(500_000_000_000_000u64),
                quotedAmount: U256::from(0u64),
                metadata: [0u8; 32].into(),
                beneficiary: recipient,
            },
            partnerAndFee: U256::ZERO,
            permit: Bytes::new(),
            executorData: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed = decode_swap_input(router, &input, U256::ZERO).expect("decode paraswap");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(500_000_000_000_000u64));
        assert_eq!(observed.recipient, recipient);
    }

    #[test]
    fn decodes_kyber_swap_simple_mode() {
        let router = Address::from([0x88; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let recipient = Address::from([0x99; 20]);
        let call = KyberAggregationRouterV2::swapSimpleModeCall {
            caller: Address::from([0x11; 20]),
            desc: KyberAggregationRouterV2::KyberSwapDescription {
                srcToken: usdc,
                dstToken: weth,
                srcReceivers: vec![Address::from([0x12; 20])],
                srcAmounts: vec![U256::from(1_000_000u64)],
                feeReceivers: vec![],
                feeAmounts: vec![],
                dstReceiver: recipient,
                amount: U256::from(1_000_000u64),
                minReturnAmount: U256::from(499_000_000_000_000u64),
                flags: U256::ZERO,
                permit: Bytes::new(),
            },
            executorData: Bytes::new(),
            clientData: Bytes::new(),
        };
        let input = call.abi_encode();
        let observed = decode_swap_input(router, &input, U256::ZERO).expect("decode kyber");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(499_000_000_000_000u64));
        assert_eq!(observed.recipient, recipient);
    }

    #[test]
    fn decodes_zerox_transform_erc20() {
        let router = Address::from([0xaa; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let call = ZeroXExchangeProxy::transformERC20Call {
            inputToken: usdc,
            outputToken: weth,
            inputTokenAmount: U256::from(1_000_000u64),
            minOutputTokenAmount: U256::from(499_000_000_000_000u64),
            transformations: vec![ZeroXExchangeProxy::ZeroXTransformation {
                deploymentNonce: 1u32,
                data: Bytes::new(),
            }],
        };
        let input = call.abi_encode();
        let observed = decode_swap_input(router, &input, U256::ZERO).expect("decode 0x transform");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(499_000_000_000_000u64));
    }

    #[test]
    fn decodes_v3_multicall_nested_exact_input_single() {
        let router = Address::from([0xbb; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let usdc = Address::from([0x22; 20]);
        let inner = UniV3Router::exactInputSingleCall {
            params: UniV3Router::ExactInputSingleParams {
                tokenIn: weth,
                tokenOut: usdc,
                fee: U24::from(500u32),
                recipient: Address::from([0x33; 20]),
                deadline: U256::from(100u64),
                amountIn: U256::from(1_000_000_000_000_000_000u128),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        let wrapped = UniV3Multicall::multicallCall {
            data: vec![Bytes::from(inner.abi_encode())],
        };
        let input = wrapped.abi_encode();
        let observed =
            decode_swap_input(router, &input, U256::ZERO).expect("decode nested multicall");
        assert_eq!(observed.path, vec![weth, usdc]);
        assert_eq!(observed.v3_fees, vec![500u32]);
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_generic_multicall_nested_v2_swap() {
        let wrapper = Address::from([0xba; 20]);
        let token_in = Address::from([0xab; 20]);
        let token_out = Address::from([0xac; 20]);
        let inner = UniV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(777u64),
            amountOutMin: U256::from(123u64),
            path: vec![token_in, token_out],
            to: Address::from([0xad; 20]),
            deadline: U256::from(999u64),
        };
        let wrapped = GenericMulticall::multicallCall {
            data: vec![Bytes::from(inner.abi_encode())],
        };
        let input = wrapped.abi_encode();
        let observed =
            decode_swap_input(wrapper, &input, U256::ZERO).expect("decode generic multicall");
        assert_eq!(observed.router, wrapper);
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(777u64));
        assert_eq!(observed.min_out, U256::from(123u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decodes_generic_multicall_deadline_nested_v3_swap() {
        let wrapper = Address::from([0xbe; 20]);
        let token_in = Address::from([0xbf; 20]);
        let token_out = Address::from([0xc0; 20]);
        let inner = UniV3Router::exactInputSingleCall {
            params: UniV3Router::ExactInputSingleParams {
                tokenIn: token_in,
                tokenOut: token_out,
                fee: U24::from(500u32),
                recipient: Address::from([0xc1; 20]),
                deadline: U256::from(100u64),
                amountIn: U256::from(5_000u64),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        let wrapped = GenericMulticallDeadline::multicallCall {
            deadline: U256::from(777u64),
            data: vec![Bytes::from(inner.abi_encode())],
        };
        let input = wrapped.abi_encode();
        let observed = decode_swap_input(wrapper, &input, U256::ZERO)
            .expect("decode generic multicall deadline");
        assert_eq!(observed.router, wrapper);
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.v3_fees, vec![500u32]);
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_generic_aggregate_multicall_nested_v2_swap() {
        let wrapper = Address::from([0xc2; 20]);
        let router = Address::from([0xc3; 20]);
        let token_in = Address::from([0xc4; 20]);
        let token_out = Address::from([0xc5; 20]);
        let inner = UniV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(444u64),
            amountOutMin: U256::from(111u64),
            path: vec![token_in, token_out],
            to: Address::from([0xc6; 20]),
            deadline: U256::from(1_234u64),
        };
        let wrapped = GenericAggregateMulticall::aggregateCall {
            calls: vec![AggregateCall {
                target: router,
                callData: Bytes::from(inner.abi_encode()),
            }],
        };
        let observed = decode_swap_input(wrapper, &wrapped.abi_encode(), U256::ZERO)
            .expect("decode aggregate nested v2");
        // For aggregate wrappers, router should reflect the nested target.
        assert_eq!(observed.router, router);
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(444u64));
        assert_eq!(observed.min_out, U256::from(111u64));
    }

    #[test]
    fn decodes_generic_aggregate3value_nested_v3_swap() {
        let wrapper = Address::from([0xc7; 20]);
        let router = Address::from([0xc8; 20]);
        let token_in = Address::from([0xc9; 20]);
        let token_out = Address::from([0xca; 20]);
        let inner = UniV3Router::exactInputSingleCall {
            params: UniV3Router::ExactInputSingleParams {
                tokenIn: token_in,
                tokenOut: token_out,
                fee: U24::from(500u32),
                recipient: Address::from([0xcb; 20]),
                deadline: U256::from(100u64),
                amountIn: U256::from(9_999u64),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        let wrapped = GenericAggregateMulticall::aggregate3ValueCall {
            calls: vec![AggregateCall3Value {
                target: router,
                allowFailure: false,
                value: U256::ZERO,
                callData: Bytes::from(inner.abi_encode()),
            }],
        };
        let observed = decode_swap_input(wrapper, &wrapped.abi_encode(), U256::ZERO)
            .expect("decode aggregate3Value nested v3");
        assert_eq!(observed.router, router);
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.v3_fees, vec![500u32]);
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_dex_router_base_request_shape() {
        let router = Address::from([0xdd; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let mut from_token_word = [0u8; 32];
        from_token_word[12..].copy_from_slice(usdc.as_slice());
        let call = DexRouter::swapWrapToWithBaseRequestCall {
            orderId: U256::from(1u64),
            receiver: Address::from([0xee; 20]),
            baseRequest: DexRouter::DexBaseRequest {
                fromToken: U256::from_be_bytes(from_token_word),
                toToken: weth,
                fromTokenAmount: U256::from(1_000_000u64),
                minReturnAmount: U256::from(400_000_000_000_000u64),
                deadLine: U256::from(1_000u64),
            },
        };
        let observed = decode_swap_input(router, &call.abi_encode(), U256::ZERO)
            .expect("decode dex base request");
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(400_000_000_000_000u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decodes_transit_v2_path_shape() {
        let router = Address::from([0xaa; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let dai = Address::from([0x44; 20]);
        let call = TransitSwapRouterV5::exactInputV2SwapCall {
            exactInput: TransitSwapRouterV5::TransitExactInputV2 {
                dstReceiver: Address::from([0xbb; 20]),
                wrappedToken: weth,
                router: U256::from(1u64),
                amount: U256::from(1_000_000u64),
                minReturnAmount: U256::from(990_000u64),
                fee: U256::ZERO,
                path: vec![usdc, weth, dai],
                pool: vec![],
                signature: Bytes::new(),
                channel: "test".to_string(),
            },
            deadline: U256::from(100u64),
        };
        let observed =
            decode_swap_input(router, &call.abi_encode(), U256::ZERO).expect("decode transit v2");
        assert_eq!(observed.path, vec![usdc, weth, dai]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(990_000u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decodes_relay_multicall_nested_swap() {
        let relay = Address::from([0xcc; 20]);
        let nested_router = Address::from([0xdd; 20]);
        let usdc = Address::from([0x22; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let nested_call = UniV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(1_000_000u64),
            amountOutMin: U256::from(500_000_000_000_000u64),
            path: vec![usdc, weth],
            to: Address::from([0x33; 20]),
            deadline: U256::from(123u64),
        };
        let relay_call = RelayRouterV3::multicallCall {
            calls: vec![RelayRouterV3::RelayCall {
                target: nested_router,
                allowFailure: false,
                value: U256::ZERO,
                callData: Bytes::from(nested_call.abi_encode()),
            }],
            refundTo: Address::from([0x44; 20]),
            nftRecipient: Address::from([0x55; 20]),
            metadata: Bytes::new(),
        };
        let observed = decode_swap_input(relay, &relay_call.abi_encode(), U256::ZERO)
            .expect("decode relay nested");
        assert_eq!(observed.router, nested_router);
        assert_eq!(observed.path, vec![usdc, weth]);
        assert_eq!(observed.amount_in, U256::from(1_000_000u64));
        assert_eq!(observed.min_out, U256::from(500_000_000_000_000u64));
    }

    #[test]
    fn relay_multicall_uses_per_call_value_for_nested_eth_swap() {
        let relay = Address::from([0xa1; 20]);
        let nested_router = Address::from([0xa2; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let token_out = Address::from([0xa3; 20]);
        let outer_eth_value = U256::from(2_000_000_000_000_000u64);

        let nested_call = UniV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(1u64),
            path: vec![weth, token_out],
            to: Address::from([0xa4; 20]),
            deadline: U256::from(123u64),
        };
        let relay_call = RelayRouterV3::multicallCall {
            calls: vec![RelayRouterV3::RelayCall {
                target: nested_router,
                allowFailure: false,
                value: U256::ZERO,
                callData: Bytes::from(nested_call.abi_encode()),
            }],
            refundTo: Address::from([0xa5; 20]),
            nftRecipient: Address::from([0xa6; 20]),
            metadata: Bytes::new(),
        };

        let observed = decode_swap_input(relay, &relay_call.abi_encode(), outer_eth_value)
            .expect("decode relay nested eth swap");
        assert_eq!(observed.router, nested_router);
        assert_eq!(observed.path, vec![weth, token_out]);
        assert_eq!(observed.amount_in, outer_eth_value);
    }

    #[test]
    fn relay_multicall_prefers_per_call_value_when_present() {
        let relay = Address::from([0xb1; 20]);
        let nested_router = Address::from([0xb2; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let token_out = Address::from([0xb3; 20]);
        let per_call_value = U256::from(777_000_000_000_000u64);
        let outer_eth_value = U256::from(2_000_000_000_000_000u64);

        let nested_call = UniV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(1u64),
            path: vec![weth, token_out],
            to: Address::from([0xb4; 20]),
            deadline: U256::from(123u64),
        };
        let relay_call = RelayRouterV3::multicallCall {
            calls: vec![RelayRouterV3::RelayCall {
                target: nested_router,
                allowFailure: false,
                value: per_call_value,
                callData: Bytes::from(nested_call.abi_encode()),
            }],
            refundTo: Address::from([0xb5; 20]),
            nftRecipient: Address::from([0xb6; 20]),
            metadata: Bytes::new(),
        };

        let observed = decode_swap_input(relay, &relay_call.abi_encode(), outer_eth_value)
            .expect("decode relay nested eth swap with per-call value");
        assert_eq!(observed.router, nested_router);
        assert_eq!(observed.path, vec![weth, token_out]);
        assert_eq!(observed.amount_in, per_call_value);
    }

    #[test]
    fn decodes_universal_router_v2_command_with_flag_bits() {
        let router = Address::from([0xb1; 20]);
        let token_in = Address::from([0xb2; 20]);
        let token_out = Address::from([0xb3; 20]);
        let params = V2SwapExactInParams {
            recipient: Address::from([0xb4; 20]),
            amountIn: U256::from(9_999u64),
            amountOutMin: U256::from(555u64),
            path: vec![token_in, token_out],
            payerIsUser: true,
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![0x80 | UR_CMD_V2_SWAP_EXACT_IN]),
            inputs: vec![Bytes::from(params.abi_encode())],
        };

        let observed =
            decode_swap_input(router, &call.abi_encode(), U256::ZERO).expect("decode ur v2");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(9_999u64));
        assert_eq!(observed.min_out, U256::from(555u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decodes_universal_router_flat_v3_command_after_permit() {
        let router = Address::from([0xd1; 20]);
        let token_in = Address::from([0xd2; 20]);
        let token_out = Address::from([0xd3; 20]);
        let recipient = Address::from([0xd4; 20]);
        let command = UniversalRouterCommandPayload::v3ExactInCall {
            recipient,
            amountIn: U256::from(42_000u64),
            amountOutMin: U256::from(41_000u64),
            path: encode_v3_path(&[token_in, token_out], &[3_000])
                .expect("V3 path")
                .into(),
            payerIsUser: true,
        };
        let encoded = command.abi_encode();
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![0x0a, UR_CMD_V3_SWAP_EXACT_IN]),
            inputs: vec![Bytes::new(), Bytes::copy_from_slice(&encoded[4..])],
        };

        let observed = decode_swap_input(router, &call.abi_encode(), U256::ZERO)
            .expect("decode production-shaped UR V3 command");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(42_000u64));
        assert_eq!(observed.min_out, U256::from(41_000u64));
        assert_eq!(observed.recipient, recipient);
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_universal_router_nested_sub_plan() {
        let router = Address::from([0xc1; 20]);
        let token_in = Address::from([0xc2; 20]);
        let token_out = Address::from([0xc3; 20]);
        let nested_swap = V3SwapExactInParams {
            recipient: Address::from([0xc4; 20]),
            amountIn: U256::from(42_000u64),
            amountOutMin: U256::from(41_000u64),
            path: encode_v3_path(&[token_in, token_out], &[500])
                .expect("nested V3 path")
                .into(),
            payerIsUser: true,
        };
        let sub_plan = UniversalRouterSubPlan {
            commands: Bytes::from(vec![UR_CMD_V3_SWAP_EXACT_IN]),
            inputs: vec![Bytes::from(nested_swap.abi_encode())],
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![UR_CMD_EXECUTE_SUB_PLAN]),
            inputs: vec![Bytes::from(sub_plan.abi_encode())],
        };

        let observed = decode_swap_input(router, &call.abi_encode(), U256::ZERO)
            .expect("decode Universal Router sub-plan");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(42_000u64));
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_universal_router_v4_legacy_exact_input_single() {
        let router = Address::from([0xb5; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let token_out = Address::from([0xb6; 20]);
        let swap = V4ExactInputSingleParams {
            poolKey: V4PoolKey {
                currency0: Address::ZERO,
                currency1: token_out,
                fee: U24::from(3_000u32),
                tickSpacing: alloy::primitives::aliases::I24::try_from(60i32).unwrap(),
                hooks: Address::ZERO,
            },
            zeroForOne: true,
            amountIn: 12_345u128,
            amountOutMinimum: 678u128,
            hookData: Bytes::new(),
        };
        let plan = V4ActionPayload::decodeCall {
            actions: Bytes::from(vec![V4_ACTION_SWAP_EXACT_IN_SINGLE]),
            params: vec![Bytes::from(swap.abi_encode())],
        };
        let encoded_plan = plan.abi_encode();
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![UR_CMD_V4_SWAP]),
            // Universal Router command inputs omit the synthetic function selector and encode
            // the two parameters as a flat tuple.
            inputs: vec![Bytes::copy_from_slice(&encoded_plan[4..])],
        };

        let observed = decode_swap_input_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
            router,
            &call.abi_encode(),
            U256::ZERO,
        )
        .expect("decode legacy v4 exact-input-single");
        assert_eq!(observed.path, vec![weth, token_out]);
        assert_eq!(observed.v3_fees, vec![3_000]);
        assert_eq!(observed.amount_in, U256::from(12_345u64));
        assert_eq!(observed.min_out, U256::from(678u64));
        assert_eq!(observed.router_kind, RouterKind::V4Like);
        assert_eq!(observed.v4_path.len(), 1);
        assert_eq!(observed.v4_path[0].pool_key.currency0, Address::ZERO);
        assert_eq!(observed.v4_path[0].pool_key.currency1, token_out);
        assert_eq!(observed.v4_path[0].pool_key.tick_spacing, 60);
        assert!(observed.v4_path[0].zero_for_one);
    }

    #[test]
    fn decodes_universal_router_v4_v211_exact_input_multihop() {
        let router = Address::from([0xb7; 20]);
        let token_in = Address::from([0xb8; 20]);
        let token_mid = Address::from([0xb9; 20]);
        let token_out = Address::from([0xba; 20]);
        let path_key = |currency, fee| V4PathKey {
            intermediateCurrency: currency,
            fee: U24::from(fee),
            tickSpacing: alloy::primitives::aliases::I24::try_from(60i32).unwrap(),
            hooks: Address::ZERO,
            hookData: Bytes::new(),
        };
        let swap = V4ExactInputParamsV211 {
            currencyIn: token_in,
            path: vec![path_key(token_mid, 500), path_key(token_out, 3_000)],
            minHopPriceX36: vec![U256::ZERO, U256::ZERO],
            amountIn: 50_000u128,
            amountOutMinimum: 40_000u128,
        };
        let plan = V4ActionPlan {
            actions: Bytes::from(vec![V4_ACTION_SWAP_EXACT_IN]),
            params: vec![Bytes::from(swap.abi_encode())],
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![0x80 | UR_CMD_V4_SWAP]),
            inputs: vec![Bytes::from(plan.abi_encode())],
        };

        let observed = decode_swap_input_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
            router,
            &call.abi_encode(),
            U256::ZERO,
        )
        .expect("decode v2.1.1 v4 exact-input multihop");
        assert_eq!(observed.path, vec![token_in, token_mid, token_out]);
        assert_eq!(observed.v3_fees, vec![500, 3_000]);
        assert_eq!(observed.amount_in, U256::from(50_000u64));
        assert_eq!(observed.min_out, U256::from(40_000u64));
        assert_eq!(observed.router_kind, RouterKind::V4Like);
        assert_eq!(observed.v4_path.len(), 2);
        assert_eq!(observed.v4_path[0].pool_key.fee, 500);
        assert_eq!(observed.v4_path[1].pool_key.fee, 3_000);
    }

    #[test]
    fn universal_router_does_not_mask_reserved_command_bit_into_v3() {
        let router = Address::from([0xbb; 20]);
        let params = V3SwapExactInParams {
            recipient: Address::from([0xbc; 20]),
            amountIn: U256::from(1u64),
            amountOutMin: U256::from(1u64),
            path: Bytes::from(vec![0u8; 43]),
            payerIsUser: true,
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![0x40]),
            inputs: vec![Bytes::from(params.abi_encode())],
        };

        assert!(decode_swap_input(router, &call.abi_encode(), U256::ZERO).is_none());
    }

    #[test]
    fn universal_router_skips_invalid_v3_path_and_decodes_next_command() {
        let router = Address::from([0xc1; 20]);
        let token_in = Address::from([0xc2; 20]);
        let token_out = Address::from([0xc3; 20]);

        let invalid_v3 = V3SwapExactInParams {
            recipient: Address::from([0xc4; 20]),
            amountIn: U256::from(111u64),
            amountOutMin: U256::from(1u64),
            path: Bytes::from(vec![0xde, 0xad]), // malformed V3 path; should be skipped
            payerIsUser: true,
        };
        let valid_v2 = V2SwapExactOutParams {
            recipient: Address::from([0xc5; 20]),
            amountOut: U256::from(222u64),
            amountInMax: U256::from(333u64),
            path: vec![token_in, token_out],
            payerIsUser: true,
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![UR_CMD_V3_SWAP_EXACT_IN, UR_CMD_V2_SWAP_EXACT_OUT]),
            inputs: vec![
                Bytes::from(invalid_v3.abi_encode()),
                Bytes::from(valid_v2.abi_encode()),
            ],
        };

        let observed =
            decode_swap_input(router, &call.abi_encode(), U256::ZERO).expect("decode fallback ur");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(333u64));
        assert_eq!(observed.min_out, U256::from(222u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn universal_router_skips_invalid_v2_decode_and_decodes_next_command() {
        let router = Address::from([0xe1; 20]);
        let token_in = Address::from([0xe2; 20]);
        let token_out = Address::from([0xe3; 20]);

        let valid_v2 = V2SwapExactInParams {
            recipient: Address::from([0xe4; 20]),
            amountIn: U256::from(444u64),
            amountOutMin: U256::from(555u64),
            path: vec![token_in, token_out],
            payerIsUser: true,
        };
        let call = UniversalRouter::executeCall {
            commands: Bytes::from(vec![UR_CMD_V2_SWAP_EXACT_OUT, UR_CMD_V2_SWAP_EXACT_IN]),
            inputs: vec![
                Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                Bytes::from(valid_v2.abi_encode()),
            ],
        };

        let observed =
            decode_swap_input(router, &call.abi_encode(), U256::ZERO).expect("decode fallback ur");
        assert_eq!(observed.path, vec![token_in, token_out]);
        assert_eq!(observed.amount_in, U256::from(444u64));
        assert_eq!(observed.min_out, U256::from(555u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decode_guard_rejects_excessive_nested_multicall_depth() {
        let router = Address::from([0xd1; 20]);
        let weth = crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
        let usdc = Address::from([0xd2; 20]);
        let inner = UniV3Router::exactInputSingleCall {
            params: UniV3Router::ExactInputSingleParams {
                tokenIn: weth,
                tokenOut: usdc,
                fee: U24::from(500u32),
                recipient: Address::from([0xd3; 20]),
                deadline: U256::from(1u64),
                amountIn: U256::from(1_000u64),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };

        let mut payload = inner.abi_encode();
        for _ in 0..=MAX_DECODE_RECURSION {
            payload = UniV3Multicall::multicallCall {
                data: vec![Bytes::from(payload)],
            }
            .abi_encode();
        }

        assert!(
            decode_swap_input(router, &payload, U256::ZERO).is_none(),
            "decode should stop once recursion guard is exceeded"
        );
    }

    #[test]
    fn decodes_zerox_v2_settler_funded_action() {
        let router = Address::from([0xa1; 20]);
        let sell_token = Address::from([0xa2; 20]);
        let buy_token = Address::from([0xa3; 20]);
        let recipient = Address::from([0xa4; 20]);
        let amount = U256::from(2_500_000u64);

        let transfer = ZeroXSettlerActions::TRANSFER_FROMCall {
            recipient: router,
            permit: SettlerPermitTransferFrom {
                permitted: SettlerTokenPermissions {
                    token: sell_token,
                    amount,
                },
                nonce: U256::from(7u64),
                deadline: U256::from(u64::MAX),
            },
            sig: Bytes::from(vec![0x11; 65]),
        };
        let swap = ZeroXSettlerActions::UNISWAPV2Call {
            recipient,
            sellToken: sell_token,
            bps: U256::from(10_000u64),
            pool: Address::from([0xa5; 20]),
            swapInfo: U24::from(30u32),
            amountOutMin: U256::from(2_400_000u64),
        };
        let call = ZeroXSettler::executeCall {
            slippage: SettlerAllowedSlippage {
                recipient,
                buyToken: buy_token,
                minAmountOut: U256::from(2_450_000u64),
            },
            actions: vec![
                Bytes::from(transfer.abi_encode()),
                Bytes::from(swap.abi_encode()),
            ],
            affiliate: B256::ZERO,
        };

        let observed =
            decode_swap_input_for_chain(CHAIN_ETHEREUM, router, &call.abi_encode(), U256::ZERO)
                .expect("decode 0x settler v2");
        assert_eq!(observed.path, vec![sell_token, buy_token]);
        assert_eq!(observed.amount_in, amount);
        assert_eq!(observed.min_out, U256::from(2_450_000u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }

    #[test]
    fn decodes_zerox_v3_settler_permit2_vip_action() {
        let router = Address::from([0xb1; 20]);
        let sell_token = Address::from([0xb2; 20]);
        let buy_token = Address::from([0xb3; 20]);
        let recipient = Address::from([0xb4; 20]);
        let amount = U256::from(8_000_000u64);
        let path = encode_v3_path(&[sell_token, buy_token], &[500]).expect("v3 path");
        let swap = ZeroXSettlerActions::UNISWAPV3_VIPCall {
            recipient,
            permit: SettlerPermitTransferFrom {
                permitted: SettlerTokenPermissions {
                    token: sell_token,
                    amount,
                },
                nonce: U256::from(9u64),
                deadline: U256::from(u64::MAX),
            },
            path: Bytes::from(path),
            sig: Bytes::from(vec![0x22; 65]),
            amountOutMin: U256::from(7_500_000u64),
        };
        let call = ZeroXSettler::executeCall {
            slippage: SettlerAllowedSlippage {
                recipient,
                buyToken: buy_token,
                minAmountOut: U256::from(7_600_000u64),
            },
            actions: vec![Bytes::from(swap.abi_encode())],
            affiliate: B256::ZERO,
        };

        let observed =
            decode_swap_input_for_chain(CHAIN_ETHEREUM, router, &call.abi_encode(), U256::ZERO)
                .expect("decode 0x settler v3 vip");
        assert_eq!(observed.path, vec![sell_token, buy_token]);
        assert_eq!(observed.v3_fees, vec![500]);
        assert_eq!(observed.amount_in, amount);
        assert_eq!(observed.min_out, U256::from(7_600_000u64));
        assert_eq!(observed.router_kind, RouterKind::V3Like);
    }

    #[test]
    fn decodes_zerox_allowance_holder_wrapped_settler_action() {
        let allowance_holder = Address::from([0xc1; 20]);
        let settler = Address::from([0xc2; 20]);
        let sell_token = Address::from([0xc3; 20]);
        let buy_token = Address::from([0xc4; 20]);
        let recipient = Address::from([0xc5; 20]);
        let amount = U256::from(12_000_000u64);
        let swap = ZeroXSettlerActions::UNISWAPV2Call {
            recipient,
            sellToken: sell_token,
            bps: U256::from(7_500u64),
            pool: Address::from([0xc6; 20]),
            swapInfo: U24::from(30u32),
            amountOutMin: U256::from(8_000_000u64),
        };
        let settle = ZeroXSettler::executeCall {
            slippage: SettlerAllowedSlippage {
                recipient,
                buyToken: buy_token,
                minAmountOut: U256::from(8_100_000u64),
            },
            actions: vec![Bytes::from(swap.abi_encode())],
            affiliate: B256::ZERO,
        };
        let call = ZeroXAllowanceHolder::execCall {
            operator: settler,
            token: sell_token,
            amount,
            target: settler,
            data: Bytes::from(settle.abi_encode()),
        };

        let observed = decode_swap_input_for_chain(
            CHAIN_ETHEREUM,
            allowance_holder,
            &call.abi_encode(),
            U256::ZERO,
        )
        .expect("decode 0x allowance holder");
        assert_eq!(observed.router, allowance_holder);
        assert_eq!(observed.path, vec![sell_token, buy_token]);
        assert_eq!(observed.amount_in, U256::from(9_000_000u64));
        assert_eq!(observed.min_out, U256::from(8_100_000u64));
        assert_eq!(observed.router_kind, RouterKind::V2Like);
    }
}
