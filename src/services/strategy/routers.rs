// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::sol;

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
