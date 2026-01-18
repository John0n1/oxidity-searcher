// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface OxidizedFlashExecutor {
        function execute(
            address[] calldata assets,
            uint256[] calldata amounts,
            bytes calldata params
        ) external;

        error OnlyOwner();
        error OnlyVault();
        error LengthMismatch();
        error ZeroAssets();
        error ExecutionFailed(uint256 index, bytes reason); 
        error InsufficientFundsForRepayment(address token, uint256 required, uint256 available);
        error InsufficientETH(uint256 required, uint256 available);
        error InvalidWETHAddress();
        error TokenTransferFailed();
        error ETHTransferFailed();
        error ApprovalFailed();
    }
}