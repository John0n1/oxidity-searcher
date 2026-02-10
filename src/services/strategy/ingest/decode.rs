// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::consensus::Transaction as ConsensusTxTrait;
use alloy::primitives::{Address, Bytes, TxKind, U256, aliases::U24};
use alloy::rpc::types::eth::Transaction;
use alloy_sol_types::{SolCall, SolType};

use crate::services::strategy::routers::{
    UniV2Router, UniV3Router, UniversalRouter, UniversalRouterDeadline,
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
    if input.len() < 4 {
        return None;
    }

    let selector: [u8; 4] = input[..4].try_into().ok()?;
    match selector {
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
            let Some(path) = parse_v3_path(&params.path) else {
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
        UniV3Router::exactOutputCall::SELECTOR => {
            let decoded = UniV3Router::exactOutputCall::abi_decode(input).ok()?;
            let params = decoded.params;
            let Some(path) = parse_v3_path(&params.path) else {
                return None;
            };
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
    for idx in 0..count {
        let cmd = cmd_bytes[idx] & 0x3f;
        let input = inputs.get(idx)?;
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
