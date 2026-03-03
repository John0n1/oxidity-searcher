// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::constants::default_routers_for_chain;
use alloy::primitives::Address;
use alloy::sol;
use std::collections::HashSet;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV2Router {
        function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) payable returns (uint256[] memory amounts);
        function swapETHForExactTokens(uint256 amountOut, address[] calldata path, address to, uint256 deadline) payable returns (uint256[] memory amounts);
        function swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function swapTokensForExactETH(uint256 amountOut, uint256 amountInMax, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function swapTokensForExactTokens(uint256 amountOut, uint256 amountInMax, address[] calldata path, address to, uint256 deadline) returns (uint256[] memory amounts);
        function swapExactETHForTokensSupportingFeeOnTransferTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) payable;
        function swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline);
        function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline);
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
        struct ExactOutputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountOut;
            uint256 amountInMaximum;
            uint160 sqrtPriceLimitX96;
        }
        struct ExactOutputParams {
            bytes path;
            address recipient;
            uint256 deadline;
            uint256 amountOut;
            uint256 amountInMaximum;
        }
        function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
        function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
        function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);
        function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV3Multicall {
        function multicall(bytes[] calldata data) external payable returns (bytes[] memory results);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV3MulticallDeadline {
        function multicall(uint256 deadline, bytes[] calldata data) external payable returns (bytes[] memory results);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniV3Quoter {
        function quoteExactInputSingle(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint160 sqrtPriceLimitX96) external returns (uint256 amountOut);
        function quoteExactInput(bytes path, uint256 amountIn) external returns (uint256 amountOut);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniversalRouter {
        function execute(bytes commands, bytes[] inputs) external payable;
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract UniversalRouterDeadline {
        function execute(bytes commands, bytes[] inputs, uint256 deadline) external payable;
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract OneInchAggregationRouter {
        struct SwapDescription {
            address srcToken;
            address dstToken;
            address srcReceiver;
            address dstReceiver;
            uint256 amount;
            uint256 minReturnAmount;
            uint256 flags;
        }

        function swap(address executor, SwapDescription calldata desc, bytes calldata data)
            external
            payable
            returns (uint256 returnAmount, uint256 spentAmount);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract OneInchAggregationRouterV5 {
        struct SwapDescriptionV5 {
            address srcToken;
            address dstToken;
            address srcReceiver;
            address dstReceiver;
            uint256 amount;
            uint256 minReturnAmount;
            uint256 flags;
        }

        function swap(address executor, SwapDescriptionV5 calldata desc, bytes calldata permit, bytes calldata data)
            external
            payable
            returns (uint256 returnAmount, uint256 spentAmount);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract ParaSwapAugustusV6 {
        struct SwapData {
            address srcToken;
            address destToken;
            uint256 fromAmount;
            uint256 toAmount;
            uint256 quotedAmount;
            bytes32 metadata;
            address beneficiary;
        }

        function swapExactAmountIn(
            address executor,
            SwapData calldata swapData,
            uint256 partnerAndFee,
            bytes calldata permit,
            bytes calldata executorData
        ) external payable returns (uint256 receivedAmount, uint256 paraswapShare, uint256 partnerShare);

        function swapExactAmountOut(
            address executor,
            SwapData calldata swapData,
            uint256 partnerAndFee,
            bytes calldata permit,
            bytes calldata executorData
        ) external payable returns (uint256 spentAmount, uint256 paraswapShare, uint256 partnerShare);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract KyberAggregationRouterV2 {
        struct KyberSwapDescription {
            address srcToken;
            address dstToken;
            address[] srcReceivers;
            uint256[] srcAmounts;
            address[] feeReceivers;
            uint256[] feeAmounts;
            address dstReceiver;
            uint256 amount;
            uint256 minReturnAmount;
            uint256 flags;
            bytes permit;
        }

        struct KyberExecution {
            address callTarget;
            address approveTarget;
            bytes targetData;
            KyberSwapDescription desc;
            bytes clientData;
        }

        function swap(KyberExecution calldata execution)
            external
            payable
            returns (uint256 returnAmount, uint256 gasUsed);

        function swapGeneric(KyberExecution calldata execution)
            external
            payable
            returns (uint256 returnAmount, uint256 gasUsed);

        function swapSimpleMode(
            address caller,
            KyberSwapDescription calldata desc,
            bytes calldata executorData,
            bytes calldata clientData
        ) external payable returns (uint256 returnAmount, uint256 gasUsed);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract ZeroXExchangeProxy {
        struct ZeroXTransformation {
            uint32 deploymentNonce;
            bytes data;
        }

        function transformERC20(
            address inputToken,
            address outputToken,
            uint256 inputTokenAmount,
            uint256 minOutputTokenAmount,
            ZeroXTransformation[] calldata transformations
        ) external payable returns (uint256 outputTokenAmount);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract DexRouter {
        struct DexBaseRequest {
            uint256 fromToken;
            address toToken;
            uint256 fromTokenAmount;
            uint256 minReturnAmount;
            uint256 deadLine;
        }

        struct DexPath {
            address[] mixAdapters;
            address[] assetTo;
            uint256[] rawData;
            bytes[] extraData;
            uint256 fromToken;
        }

        struct DexExtraData {
            uint256 pathIndex;
            address payer;
            address fromToken;
            address toToken;
            uint256 fromTokenAmountMax;
            uint256 toTokenAmountMax;
            uint256 salt;
            uint256 deadLine;
            bool isPushOrder;
            bytes extension;
        }

        function dagSwapByOrderId(uint256 orderId, DexBaseRequest calldata baseRequest, DexPath[] calldata paths)
            external
            payable
            returns (uint256 returnAmount);

        function dagSwapTo(uint256 orderId, address receiver, DexBaseRequest calldata baseRequest, DexPath[] calldata paths)
            external
            payable
            returns (uint256 returnAmount);

        function smartSwapByOrderId(
            uint256 orderId,
            DexBaseRequest calldata baseRequest,
            uint256[] calldata batchesAmount,
            DexPath[][] calldata batches,
            DexExtraData[] calldata extraData
        ) external payable returns (uint256 returnAmount);

        function smartSwapTo(
            uint256 orderId,
            address receiver,
            DexBaseRequest calldata baseRequest,
            uint256[] calldata batchesAmount,
            DexPath[][] calldata batches,
            DexExtraData[] calldata extraData
        ) external payable returns (uint256 returnAmount);

        function smartSwapByInvest(
            DexBaseRequest calldata baseRequest,
            uint256[] calldata batchesAmount,
            DexPath[][] calldata batches,
            DexExtraData[] calldata extraData,
            address to
        ) external payable returns (uint256 returnAmount);

        function smartSwapByInvestWithRefund(
            DexBaseRequest calldata baseRequest,
            uint256[] calldata batchesAmount,
            DexPath[][] calldata batches,
            DexExtraData[] calldata extraData,
            address to,
            address refundTo
        ) external payable returns (uint256 returnAmount);

        function swapWrapToWithBaseRequest(
            uint256 orderId,
            address receiver,
            DexBaseRequest calldata baseRequest
        ) external payable returns (uint256 returnAmount);

        function uniswapV3SwapToWithBaseRequest(
            uint256 orderId,
            address receiver,
            DexBaseRequest calldata baseRequest,
            uint256[] calldata pools
        ) external payable returns (uint256 returnAmount);

        function unxswapToWithBaseRequest(
            uint256 orderId,
            address receiver,
            DexBaseRequest calldata baseRequest,
            bytes32[] calldata pools
        ) external payable returns (uint256 returnAmount);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract TransitSwapRouterV5 {
        struct TransitExactInputV2 {
            address dstReceiver;
            address wrappedToken;
            uint256 router;
            uint256 amount;
            uint256 minReturnAmount;
            uint256 fee;
            address[] path;
            address[] pool;
            bytes signature;
            string channel;
        }

        struct TransitExactInputV3 {
            address srcToken;
            address dstToken;
            address dstReceiver;
            address wrappedToken;
            uint256 amount;
            uint256 minReturnAmount;
            uint256 fee;
            uint256 deadline;
            uint256[] pools;
            bytes signature;
            string channel;
        }

        function exactInputV2Swap(TransitExactInputV2 calldata exactInput, uint256 deadline)
            external
            payable
            returns (uint256 returnAmount);

        function exactInputV2SwapAndGasUsed(TransitExactInputV2 calldata exactInput, uint256 deadline)
            external
            payable
            returns (uint256 returnAmount, uint256 gasUsed);

        function exactInputV3Swap(TransitExactInputV3 calldata params)
            external
            payable
            returns (uint256 returnAmount);

        function exactInputV3SwapAndGasUsed(TransitExactInputV3 calldata params)
            external
            payable
            returns (uint256 returnAmount, uint256 gasUsed);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract RelayRouterV3 {
        struct RelayCall {
            address target;
            bool allowFailure;
            uint256 value;
            bytes callData;
        }

        function multicall(
            RelayCall[] calldata calls,
            address refundTo,
            address nftRecipient,
            bytes calldata metadata
        ) external payable returns (bytes[] memory returnData);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract RelayApprovalProxyV3 {
        struct RelayApprovalCall {
            address target;
            bool allowFailure;
            uint256 value;
            bytes callData;
        }

        struct PermitTransfer {
            address token;
            address owner;
            uint256 value;
            uint256 nonce;
            uint256 deadline;
            uint8 v;
            bytes32 r;
            bytes32 s;
        }

        struct Permit3009 {
            address from;
            uint256 value;
            uint256 validAfter;
            uint256 validBefore;
            uint8 v;
            bytes32 r;
            bytes32 s;
        }

        struct Permit2TokenPermissions {
            address token;
            uint256 amount;
        }

        struct Permit2BatchTransferFrom {
            Permit2TokenPermissions[] permitted;
            uint256 nonce;
            uint256 deadline;
        }

        function transferAndMulticall(
            address[] calldata tokens,
            uint256[] calldata amounts,
            RelayApprovalCall[] calldata calls,
            address refundTo,
            address nftRecipient,
            bytes calldata metadata
        ) external payable;

        function permitTransferAndMulticall(
            PermitTransfer[] calldata permits,
            RelayApprovalCall[] calldata calls,
            address refundTo,
            address nftRecipient,
            bytes calldata metadata
        ) external payable;

        function permit3009TransferAndMulticall(
            Permit3009[] calldata permits,
            address[] calldata tokens,
            RelayApprovalCall[] calldata calls,
            address refundTo,
            address nftRecipient,
            bytes calldata metadata
        ) external payable;

        function permit2TransferAndMulticall(
            address user,
            Permit2BatchTransferFrom calldata permit,
            RelayApprovalCall[] calldata calls,
            address refundTo,
            address nftRecipient,
            bytes calldata metadata,
            bytes calldata permitSignature
        ) external payable;
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract ERC20 {
        function balanceOf(address) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerVaultFees {
        function getProtocolFeesCollector() external view returns (address);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerProtocolFees {
        function getFlashLoanFeePercentage() external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerVault {
        struct SingleSwap {
            bytes32 poolId;
            uint8 kind;
            address assetIn;
            address assetOut;
            uint256 amount;
            bytes userData;
        }

        struct BatchSwapStep {
            bytes32 poolId;
            uint256 assetInIndex;
            uint256 assetOutIndex;
            uint256 amount;
            bytes userData;
        }

        struct FundManagement {
            address sender;
            bool fromInternalBalance;
            address recipient;
            bool toInternalBalance;
        }

        function queryBatchSwap(
            uint8 kind,
            BatchSwapStep[] calldata swaps,
            address[] calldata assets,
            FundManagement calldata funds
        ) external view returns (int256[] memory assetDeltas);

        function swap(
            SingleSwap calldata singleSwap,
            FundManagement calldata funds,
            uint256 limit,
            uint256 deadline
        ) external payable returns (uint256 amountCalculated);

        function batchSwap(
            uint8 kind,
            BatchSwapStep[] calldata swaps,
            address[] calldata assets,
            FundManagement calldata funds,
            int256[] calldata limits,
            uint256 deadline
        ) external payable returns (int256[] memory);

        function getPoolTokens(bytes32 poolId)
            external
            view
            returns (address[] memory tokens, uint256[] memory balances, uint256 lastChangeBlock);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerPoolId {
        function getPoolId() external view returns (bytes32);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerWeightedPool {
        function getNormalizedWeights() external view returns (uint256[] memory);
        function getSwapFeePercentage() external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract BalancerStablePool {
        function getAmplificationParameter()
            external
            view
            returns (uint256 value, bool isUpdating, uint256 precision);
        function getSwapFeePercentage() external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract CurveRegistry {
        function get_coins(address pool) external view returns (address[8] memory);
        function get_underlying_coins(address pool) external view returns (address[8] memory);
        function get_decimals(address pool) external view returns (uint256[8] memory);
        function get_underlying_decimals(address pool) external view returns (uint256[8] memory);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract CurvePoolLike {
        function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
        function get_dy_underlying(int128 i, int128 j, uint256 dx) external view returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract CurvePoolSwap {
        function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
        function exchange_underlying(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    }

    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract AavePool {
        function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);

        struct AaveReserveConfigurationMap {
            uint256 data;
        }

        struct AaveReserveData {
            AaveReserveConfigurationMap configuration;
            uint128 liquidityIndex;
            uint128 currentLiquidityRate;
            uint128 variableBorrowIndex;
            uint128 currentVariableBorrowRate;
            uint128 currentStableBorrowRate;
            uint40 lastUpdateTimestamp;
            uint16 id;
            address aTokenAddress;
            address stableDebtTokenAddress;
            address variableDebtTokenAddress;
            address interestRateStrategyAddress;
            uint128 accruedToTreasury;
            uint128 unbacked;
            uint128 isolationModeTotalDebt;
        }

        function getReserveData(address asset) external view returns (AaveReserveData memory);
    }
}

fn v2_router_priority(name: &str) -> Option<u8> {
    match name {
        "uniswap_v2_router02" | "uniswap_v2_router" => Some(0),
        "sushiswap_router" => Some(1),
        "pancakeswap_v2_router" => Some(2),
        _ => {
            let generic_v2 = (name.contains("v2_router") || name.contains("router_v2"))
                && !name.contains("universal");
            if generic_v2 { Some(10) } else { None }
        }
    }
}

fn is_non_v2_surface(name: &str) -> bool {
    name.contains("universal")
        || name.contains("aggregation")
        || name.contains("aggregator")
        || name.contains("proxy")
        || name.contains("permit")
        || name.contains("quoter")
        || name.contains("vault")
        || name.contains("relay")
}

fn registry_v2_router_candidates_from_registry(
    routers: &std::collections::HashMap<String, Address>,
) -> Vec<(String, Address)> {
    let mut candidates: Vec<(u8, String, Address)> = routers
        .iter()
        .filter_map(|(name, addr)| {
            let lowered = name.to_ascii_lowercase();
            if is_non_v2_surface(&lowered) {
                return None;
            }
            let priority = v2_router_priority(&lowered)?;
            Some((priority, lowered, *addr))
        })
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (_, name, addr) in candidates {
        if seen.insert(addr) {
            out.push((name, addr));
        }
    }
    out
}

pub fn registry_v2_router_candidates(chain_id: u64) -> Vec<(String, Address)> {
    let routers = default_routers_for_chain(chain_id);
    registry_v2_router_candidates_from_registry(&routers)
}

pub fn registry_v2_router_addresses(chain_id: u64) -> Vec<Address> {
    registry_v2_router_candidates(chain_id)
        .into_iter()
        .map(|(_, address)| address)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256};
    use alloy::sol_types::SolCall;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn decode_critical_selectors_are_unique() {
        let selectors = [
            UniV2Router::swapExactETHForTokensCall::SELECTOR,
            UniV2Router::swapETHForExactTokensCall::SELECTOR,
            UniV2Router::swapExactTokensForETHCall::SELECTOR,
            UniV2Router::swapTokensForExactETHCall::SELECTOR,
            UniV2Router::swapExactTokensForTokensCall::SELECTOR,
            UniV2Router::swapTokensForExactTokensCall::SELECTOR,
            UniV3Router::exactInputSingleCall::SELECTOR,
            UniV3Router::exactOutputSingleCall::SELECTOR,
            UniV3Router::exactInputCall::SELECTOR,
            UniV3Router::exactOutputCall::SELECTOR,
            UniV3Multicall::multicallCall::SELECTOR,
            UniV3MulticallDeadline::multicallCall::SELECTOR,
            UniversalRouter::executeCall::SELECTOR,
            UniversalRouterDeadline::executeCall::SELECTOR,
            RelayRouterV3::multicallCall::SELECTOR,
            RelayApprovalProxyV3::transferAndMulticallCall::SELECTOR,
            RelayApprovalProxyV3::permitTransferAndMulticallCall::SELECTOR,
            RelayApprovalProxyV3::permit3009TransferAndMulticallCall::SELECTOR,
            RelayApprovalProxyV3::permit2TransferAndMulticallCall::SELECTOR,
            TransitSwapRouterV5::exactInputV2SwapCall::SELECTOR,
            TransitSwapRouterV5::exactInputV2SwapAndGasUsedCall::SELECTOR,
            TransitSwapRouterV5::exactInputV3SwapCall::SELECTOR,
            TransitSwapRouterV5::exactInputV3SwapAndGasUsedCall::SELECTOR,
            BalancerVault::swapCall::SELECTOR,
            BalancerVault::batchSwapCall::SELECTOR,
        ];

        let mut unique = HashSet::new();
        for selector in selectors {
            assert!(
                unique.insert(selector),
                "duplicate selector detected: 0x{}",
                hex::encode(selector)
            );
        }
    }

    #[test]
    fn relay_approval_transfer_and_multicall_roundtrips() {
        let nested = RelayApprovalProxyV3::RelayApprovalCall {
            target: Address::from([0x11; 20]),
            allowFailure: false,
            value: U256::from(42u64),
            callData: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
        };
        let call = RelayApprovalProxyV3::transferAndMulticallCall {
            tokens: vec![Address::from([0x22; 20])],
            amounts: vec![U256::from(1000u64)],
            calls: vec![nested.clone()],
            refundTo: Address::from([0x33; 20]),
            nftRecipient: Address::from([0x44; 20]),
            metadata: Bytes::from(vec![0x01, 0x02]),
        };

        let encoded = call.abi_encode();
        let decoded = RelayApprovalProxyV3::transferAndMulticallCall::abi_decode(&encoded)
            .expect("decode transferAndMulticall");
        assert_eq!(decoded.calls.len(), 1);
        assert_eq!(decoded.calls[0].target, nested.target);
        assert_eq!(decoded.calls[0].value, nested.value);
        assert_eq!(decoded.calls[0].callData, nested.callData);
    }

    #[test]
    fn transit_exact_input_v2_roundtrips() {
        let call = TransitSwapRouterV5::exactInputV2SwapCall {
            exactInput: TransitSwapRouterV5::TransitExactInputV2 {
                dstReceiver: Address::from([0x51; 20]),
                wrappedToken: Address::from([0x52; 20]),
                router: U256::from(1u64),
                amount: U256::from(10_000u64),
                minReturnAmount: U256::from(9_900u64),
                fee: U256::from(10u64),
                path: vec![
                    Address::from([0x53; 20]),
                    Address::from([0x54; 20]),
                    Address::from([0x55; 20]),
                ],
                pool: vec![Address::from([0x56; 20]), Address::from([0x57; 20])],
                signature: Bytes::from(vec![0xde, 0xad]),
                channel: "unit-test".to_string(),
            },
            deadline: U256::from(123u64),
        };

        let encoded = call.abi_encode();
        let decoded = TransitSwapRouterV5::exactInputV2SwapCall::abi_decode(&encoded)
            .expect("decode exactInputV2Swap");
        assert_eq!(decoded.exactInput.amount, U256::from(10_000u64));
        assert_eq!(decoded.exactInput.path.len(), 3);
        assert_eq!(decoded.exactInput.channel, "unit-test".to_string());
        assert_eq!(decoded.deadline, U256::from(123u64));
    }

    #[test]
    fn registry_v2_candidates_are_sorted_filtered_and_deduped() {
        let shared_univ2 = Address::from([0x11; 20]);
        let sushi = Address::from([0x12; 20]);
        let pancake = Address::from([0x13; 20]);
        let generic = Address::from([0x14; 20]);
        let mut routers = HashMap::new();
        routers.insert("UNISWAP_V2_ROUTER02".to_string(), shared_univ2);
        routers.insert("UNISWAP_V2_ROUTER".to_string(), shared_univ2);
        routers.insert("SUSHISWAP_ROUTER".to_string(), sushi);
        routers.insert("PANCAKESWAP_V2_ROUTER".to_string(), pancake);
        routers.insert("CUSTOM_V2_ROUTER".to_string(), generic);
        routers.insert(
            "UNISWAP_UNIVERSAL_ROUTER".to_string(),
            Address::from([0x31; 20]),
        );
        routers.insert(
            "ONEINCH_AGGREGATION_ROUTER_V6".to_string(),
            Address::from([0x32; 20]),
        );

        let out = registry_v2_router_candidates_from_registry(&routers);
        assert_eq!(
            out,
            vec![
                ("uniswap_v2_router".to_string(), shared_univ2),
                ("sushiswap_router".to_string(), sushi),
                ("pancakeswap_v2_router".to_string(), pancake),
                ("custom_v2_router".to_string(), generic),
            ]
        );
    }

    #[test]
    fn registry_v2_address_projection_preserves_candidate_order() {
        let mut routers = HashMap::new();
        let first = Address::from([0x41; 20]);
        let second = Address::from([0x42; 20]);
        routers.insert("UNISWAP_V2_ROUTER02".to_string(), first);
        routers.insert("SUSHISWAP_ROUTER".to_string(), second);

        let candidates = registry_v2_router_candidates_from_registry(&routers);
        let addresses: Vec<Address> = candidates.into_iter().map(|(_, address)| address).collect();
        assert_eq!(addresses, vec![first, second]);
    }
}
