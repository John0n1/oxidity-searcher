// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==========================================
// INTERFACES
// ==========================================

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    // Removed high-level approve/transfer to force usage of low-level safe helpers
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

// ==========================================
// UNIFIED EXECUTOR (HARDENED)
// ==========================================

contract UnifiedHardenedExecutor is IFlashLoanRecipient {
    // --- Constants & State ---
    address private constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    
    address public immutable owner;
    address public immutable WETH;
    address public profitReceiver;
    bool public sweepProfitToEth;

    // --- Events ---
    event ArbitrageExecuted(uint256 surplus, address token);
    event BundleExecuted(uint256 bribePaid);
    event ProfitReceiverUpdated(address indexed newReceiver);
    event SweepPreferenceUpdated(bool sweepToEth);
    event DistributeFailed(address token, uint256 amount); // Funds left in contract
    event CallFailed(uint256 index, bytes reason);

    // --- Errors ---
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
    error BalanceInvariantBroken(address token, uint256 beforeBalance, uint256 afterBalance);

    constructor(address _profitReceiver, address _weth) {
        if (_profitReceiver == address(0)) revert InvalidProfitReceiver();
        // Harden WETH check: ensure it is actually a contract
        if (_weth == address(0) || _weth.code.length == 0) revert InvalidWETHAddress();
        
        owner = msg.sender;
        profitReceiver = _profitReceiver;
        WETH = _weth;
        sweepProfitToEth = true; 
    }

    receive() external payable {}

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // Allow the contract to call itself (essential for setting approvals mid-bundle)
    modifier onlySelfOrOwner() {
        if (msg.sender != owner && msg.sender != address(this)) revert OnlyOwner();
        _;
    }

    // ==========================================
    // MODE 1: MEV BUNDLE EXECUTION (Direct)
    // ==========================================

    function executeBundle(
        address[] calldata targets,
        bytes[] calldata payloads,
        uint256[] calldata values,
        address bribeRecipient,
        uint256 bribeAmount,
        bool allowPartial,
        address balanceCheckToken
    ) external payable onlyOwner {
        if (targets.length != payloads.length || targets.length != values.length) {
            revert LengthMismatch();
        }

        uint256 tokenBalanceBefore = balanceCheckToken == address(0)
            ? 0
            : IERC20(balanceCheckToken).balanceOf(address(this));

        // 1. Execute all calls
        // msg.value is already credited to address(this).balance
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                if (allowPartial) {
                    emit CallFailed(i, result);
                    continue;
                } else {
                    _revertWithDetails(i, result);
                }
            }
        }

        // 2. Handle Bribe (Miner Tip)
        if (bribeAmount > 0) {
            // FIX: Check current balance AFTER calls. 
            // We don't need to subtract callsTotalValue because those funds are already gone.
            if (address(this).balance < bribeAmount) revert BribeFailed();
            
            address actualRecipient = bribeRecipient == address(0) ? block.coinbase : bribeRecipient;
            
            (bool ok, ) = actualRecipient.call{value: bribeAmount}("");
            if (!ok) revert BribeFailed();
            
            emit BundleExecuted(bribeAmount);
        }

        // 3. Refund / Sweep
        // If profitReceiver rejects ETH, we leave it here to prevent reverting the bundle.
        uint256 remaining = address(this).balance;
        if (remaining > 0) {
            (bool success, ) = profitReceiver.call{value: remaining}("");
            if (!success) emit DistributeFailed(address(0), remaining);
        }

        // 4. Balance invariant (optional)
        if (balanceCheckToken != address(0)) {
            uint256 tokenBalanceAfter = IERC20(balanceCheckToken).balanceOf(address(this));
            if (tokenBalanceAfter < tokenBalanceBefore) {
                revert BalanceInvariantBroken(balanceCheckToken, tokenBalanceBefore, tokenBalanceAfter);
            }
        }
    }

    // ==========================================
    // MODE 2: FLASH LOAN EXECUTION (Balancer)
    // ==========================================

    function executeFlashLoan(
        IERC20[] calldata assets,
        uint256[] calldata amounts,
        bytes calldata params
    ) external onlyOwner {
        if (assets.length == 0) revert ZeroAssets();
        if (assets.length != amounts.length) revert LengthMismatch();

        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this),
            assets,
            amounts,
            params
        );
    }

    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external override {
        if (msg.sender != BALANCER_VAULT) revert OnlyVault();
        // Basic length checks
        if (tokens.length != amounts.length || tokens.length != feeAmounts.length) {
            revert LengthMismatch();
        }

        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) = 
            abi.decode(userData, (address[], uint256[], bytes[]));

        if (targets.length != values.length || targets.length != payloads.length) {
            revert LengthMismatch();
        }

        // 1. Execute Arbitrage Logic
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                _revertWithDetails(i, result);
            }
        }

        // 2. Repay Vault & Take Profit
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 amountOwing = amounts[i] + feeAmounts[i];
            if (amountOwing == 0) continue;

            address tokenAddr = address(tokens[i]);
            uint256 myBalance = IERC20(tokenAddr).balanceOf(address(this));

            if (myBalance < amountOwing) {
                revert InsufficientFundsForRepayment(tokenAddr, amountOwing, myBalance);
            }

            uint256 surplus = myBalance - amountOwing;
            
            if (surplus > 0) {
                // Try to distribute; if it fails (e.g. receiver logic), swallow error 
                // so we can still repay the loan and not revert the tx.
                _distributeProfit(tokenAddr, surplus);
            }

            // Balancer V2 requires us to transfer funds back to the Vault
            _safeTransfer(tokenAddr, BALANCER_VAULT, amountOwing);
        }

        // 3. Sweep loose ETH (e.g. from WETH unwrapping or pure ETH arb)
        uint256 ethBal = address(this).balance;
        if (ethBal > 0) {
            (bool success, ) = profitReceiver.call{value: ethBal}("");
            if (!success) emit DistributeFailed(address(0), ethBal);
        }
    }

    // ==========================================
    // ADMIN & HELPERS
    // ==========================================

    function setProfitReceiver(address newReceiver) external onlyOwner {
        if (newReceiver == address(0)) revert InvalidProfitReceiver();
        profitReceiver = newReceiver;
        emit ProfitReceiverUpdated(newReceiver);
    }

    function setSweepPreference(bool sweepToEth) external onlyOwner {
        sweepProfitToEth = sweepToEth;
        emit SweepPreferenceUpdated(sweepToEth);
    }

    function sweepToken(address token) external onlyOwner {
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal > 0) {
            _safeTransfer(token, profitReceiver, bal);
        }
    }

    function sweepETH() external onlyOwner {
        uint256 bal = address(this).balance;
        if (bal > 0) {
            (bool success, ) = profitReceiver.call{value: bal}("");
            if (!success) revert TokenTransferFailed(); // OK to revert here, manual action
        }
    }

    /// @notice USDT-Safe Approval. 
    /// @dev Can be called by Owner OR by this contract (via flashloan payload).
    function safeApprove(address token, address spender, uint256 amount) external onlySelfOrOwner {
        // Check current allowance first to save gas or handle USDT reset
        uint256 currentAllowance = IERC20(token).allowance(address(this), spender);
        
        // If we need to increase/change and allowance is already non-zero, reset to 0 first
        // (Some tokens revert if you try to change from non-zero to non-zero)
        if (currentAllowance != 0 && currentAllowance != amount) {
            _lowLevelApprove(token, spender, 0);
        }

        if (currentAllowance != amount) {
            _lowLevelApprove(token, spender, amount);
        }
    }

    // ==========================================
    // INTERNAL UTILS
    // ==========================================

    function _distributeProfit(address tokenAddr, uint256 profit) internal {
        if (tokenAddr == WETH && sweepProfitToEth) {
            IWETH(WETH).withdraw(profit);
            // ETH transfer happens at end of function or next step
        } else {
            // Safe transfer, but do not revert if profit receiver acts up.
            // We use low-level call here to swallow failures intentionally during flashloops.
            (bool success, bytes memory data) = tokenAddr.call(
                abi.encodeWithSelector(0xa9059cbb, profitReceiver, profit) // transfer(to, amount)
            );
            if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
                emit DistributeFailed(tokenAddr, profit);
            } else {
                emit ArbitrageExecuted(profit, tokenAddr);
            }
        }
    }

    function _lowLevelApprove(address token, address spender, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x095ea7b3, spender, amount) // approve(spender, amount)
        );
        // Check success AND decode result if data exists
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert ApprovalFailed();
        }
    }

    function _safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value) // transfer(to, value)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TokenTransferFailed();
        }
    }

    function _revertWithDetails(uint256 index, bytes memory result) internal pure {
        if (result.length > 0) {
            assembly {
                let returndata_size := mload(result)
                revert(add(32, result), returndata_size)
            }
        } else {
            revert ExecutionFailed(index, result);
        }
    }
}
