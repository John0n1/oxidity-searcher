// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::consensus::Transaction as ConsensusTxTrait;
use alloy::primitives::{Address, Bytes, TxKind, U256, aliases::U24};
use alloy::rpc::types::eth::Transaction;
use alloy_sol_types::{SolCall, SolType};

use crate::services::strategy::routers::{
    BalancerVault, DexRouter, KyberAggregationRouterV2, OneInchAggregationRouter,
    OneInchAggregationRouterV5, ParaSwapAugustusV6, RelayApprovalProxyV3, RelayRouterV3,
    TransitSwapRouterV5, UniV2Router, UniV3Multicall, UniV3MulticallDeadline, UniV3Router,
    UniversalRouter, UniversalRouterDeadline, ZeroXExchangeProxy,
};

use alloy::sol;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservedSwap {
    pub router: Address,
    pub path: Vec<Address>,
    pub v3_fees: Vec<u32>,
    pub v3_path: Option<Vec<u8>>,
    pub amount_in: U256,
    pub min_out: U256,
    pub recipient: Address,
    pub router_kind: RouterKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouterKind {
    V2Like,
    V3Like,
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
}

pub fn decode_swap(tx: &Transaction) -> Option<ObservedSwap> {
    let router = match tx.kind() {
        TxKind::Call(addr) => addr,
        TxKind::Create => return None,
    };
    decode_swap_input(router, tx.input(), tx.value())
}

pub fn decode_swap_input(router: Address, input: &[u8], eth_value: U256) -> Option<ObservedSwap> {
    decode_swap_input_inner(router, input, eth_value, 0)
}

const MAX_DECODE_RECURSION: usize = 4;

fn decode_swap_input_inner(
    router: Address,
    input: &[u8],
    eth_value: U256,
    depth: usize,
) -> Option<ObservedSwap> {
    if depth > MAX_DECODE_RECURSION {
        return None;
    }
    if input.len() < 4 {
        return None;
    }

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
            decode_relay_calls(router, decoded.calls, depth, eth_value)
        }
        RelayApprovalProxyV3::transferAndMulticallCall::SELECTOR => {
            let decoded = RelayApprovalProxyV3::transferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value)
        }
        RelayApprovalProxyV3::permitTransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permitTransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value)
        }
        RelayApprovalProxyV3::permit3009TransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permit3009TransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value)
        }
        RelayApprovalProxyV3::permit2TransferAndMulticallCall::SELECTOR => {
            let decoded =
                RelayApprovalProxyV3::permit2TransferAndMulticallCall::abi_decode(input).ok()?;
            decode_relay_approval_calls(router, decoded.calls, depth, eth_value)
        }
        BalancerVault::swapCall::SELECTOR => {
            let decoded = BalancerVault::swapCall::abi_decode(input).ok()?;
            observed_aggregator_swap(
                router,
                normalize_balancer_asset(decoded.singleSwap.assetIn),
                normalize_balancer_asset(decoded.singleSwap.assetOut),
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
            let token_in = normalize_balancer_asset(*decoded.assets.get(idx_in)?);
            let token_out = normalize_balancer_asset(*decoded.assets.get(idx_out)?);
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
                    decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1)
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
                    decode_swap_input_inner(router, nested.as_ref(), eth_value, depth + 1)
                {
                    return Some(observed);
                }
            }
            None
        }
        UniversalRouter::executeCall::SELECTOR => {
            let decoded = UniversalRouter::executeCall::abi_decode(input).ok()?;
            decode_universal_router(router, decoded.commands, decoded.inputs)
        }
        UniversalRouterDeadline::executeCall::SELECTOR => {
            let decoded = UniversalRouterDeadline::executeCall::abi_decode(input).ok()?;
            decode_universal_router(router, decoded.commands, decoded.inputs)
        }
        _ => None,
    }
}

fn normalize_aggregator_token(token: Address) -> Option<Address> {
    if token == Address::ZERO {
        return None;
    }
    let native_sentinel = crate::common::constants::native_sentinel_for_chain(
        crate::common::constants::CHAIN_ETHEREUM,
    );
    if token == native_sentinel {
        return Some(crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        ));
    }
    Some(token)
}

fn normalize_balancer_asset(asset: Address) -> Address {
    if asset == Address::ZERO {
        return crate::common::constants::wrapped_native_for_chain(
            crate::common::constants::CHAIN_ETHEREUM,
        );
    }
    asset
}

fn observed_aggregator_swap(
    router: Address,
    token_in_raw: Address,
    token_out_raw: Address,
    amount_in: U256,
    min_out: U256,
    recipient: Address,
) -> Option<ObservedSwap> {
    let token_in = normalize_aggregator_token(token_in_raw)?;
    let token_out = normalize_aggregator_token(token_out_raw)?;
    if token_in == token_out || amount_in.is_zero() {
        return None;
    }
    Some(ObservedSwap {
        router,
        path: vec![token_in, token_out],
        v3_fees: Vec::new(),
        v3_path: None,
        amount_in,
        min_out,
        recipient,
        router_kind: RouterKind::V2Like,
    })
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

fn observed_from_dex_base_request(
    router: Address,
    base_request: DexRouter::DexBaseRequest,
    recipient: Address,
) -> Option<ObservedSwap> {
    let token_in = u256_word_to_address(base_request.fromToken)?;
    observed_aggregator_swap(
        router,
        token_in,
        base_request.toToken,
        base_request.fromTokenAmount,
        base_request.minReturnAmount,
        recipient,
    )
}

fn observed_transit_v2(
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
        .filter_map(normalize_aggregator_token)
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
) -> Option<ObservedSwap> {
    let _ = router;
    for call in calls.iter() {
        if let Some(observed) =
            decode_swap_input_inner(call.target, call.callData.as_ref(), call.value, depth + 1)
        {
            return Some(observed);
        }
    }
    // Fallback: some relays do not forward per-call value cleanly.
    for call in calls.iter() {
        if let Some(observed) =
            decode_swap_input_inner(call.target, call.callData.as_ref(), eth_value, depth + 1)
        {
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
    decode_relay_calls(router, relay_calls, depth, eth_value)
}

const UR_CMD_V3_SWAP_EXACT_IN: u8 = 0x00;
const UR_CMD_V3_SWAP_EXACT_OUT: u8 = 0x01;
const UR_CMD_V2_SWAP_EXACT_IN: u8 = 0x08;
const UR_CMD_V2_SWAP_EXACT_OUT: u8 = 0x09;

fn decode_universal_router(
    router: Address,
    commands: Bytes,
    inputs: Vec<Bytes>,
) -> Option<ObservedSwap> {
    let cmd_bytes = commands.as_ref();
    let count = std::cmp::min(cmd_bytes.len(), inputs.len());
    for (idx, cmd_byte) in cmd_bytes.iter().enumerate().take(count) {
        let cmd = *cmd_byte & 0x3f;
        let input = &inputs[idx];
        match cmd {
            UR_CMD_V2_SWAP_EXACT_IN => {
                let decoded = V2SwapExactInParams::abi_decode(input.as_ref()).ok()?;
                return Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V2Like,
                });
            }
            UR_CMD_V2_SWAP_EXACT_OUT => {
                let decoded = V2SwapExactOutParams::abi_decode(input.as_ref()).ok()?;
                return Some(ObservedSwap {
                    router,
                    path: decoded.path,
                    v3_fees: Vec::new(),
                    v3_path: None,
                    amount_in: decoded.amountInMax,
                    min_out: decoded.amountOut,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V2Like,
                });
            }
            UR_CMD_V3_SWAP_EXACT_IN => {
                let decoded = V3SwapExactInParams::abi_decode(input.as_ref()).ok()?;
                let Some(path) = parse_v3_path(decoded.path.as_ref()) else {
                    continue;
                };
                return Some(ObservedSwap {
                    router,
                    path: path.tokens.clone(),
                    v3_fees: path.fees.clone(),
                    v3_path: Some(decoded.path.to_vec()),
                    amount_in: decoded.amountIn,
                    min_out: decoded.amountOutMin,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V3Like,
                });
            }
            UR_CMD_V3_SWAP_EXACT_OUT => {
                let decoded = V3SwapExactOutParams::abi_decode(input.as_ref()).ok()?;
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
                    amount_in: decoded.amountInMax,
                    min_out: decoded.amountOut,
                    recipient: decoded.recipient,
                    router_kind: RouterKind::V3Like,
                });
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
        UniV3Router, UniversalRouter, ZeroXExchangeProxy,
    };
    use alloy::primitives::Bytes;
    use alloy::primitives::{U160, aliases::U24};
    use alloy::sol_types::SolCall;
    use alloy_sol_types::SolValue;

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
        assert_eq!(observed.amount_in, U256::ZERO);
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
}
