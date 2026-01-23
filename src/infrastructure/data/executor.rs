// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface UnifiedHardenedExecutor {
        function executeBundle(
            address[] calldata targets,
            bytes[] calldata payloads,
            uint256[] calldata values,
            address bribeRecipient,
            uint256 bribeAmount
        ) external payable;

        function executeFlashLoan(
            address[] calldata assets,
            uint256[] calldata amounts,
            bytes calldata params
        ) external;

        function safeApprove(address token, address spender, uint256 amount) external;
        function setProfitReceiver(address newReceiver) external;
        function setSweepPreference(bool sweepToEth) external;

        error OnlyOwner();
        error OnlyVault();
        error LengthMismatch();
        error ZeroAssets();
        error ExecutionFailed(uint256 index, bytes reason);
        error InsufficientFundsForRepayment(address token, uint256 required, uint256 available);
        error InvalidWETHAddress();
        error InvalidProfitReceiver();
        error TokenTransferFailed();
        error ApprovalFailed();
        error BribeFailed();
    }

    // Matches abi.decode(userData, (address[], uint256[], bytes[])) in receiveFlashLoan
    struct FlashCallbackData {
        address[] targets;
        uint256[] values;
        bytes[] payloads;
    }
}
