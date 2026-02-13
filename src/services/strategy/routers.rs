// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::sol;

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
    }
}
