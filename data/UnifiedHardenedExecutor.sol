// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

pragma solidity ^0.8.33;

// ==========================================
// INTERFACES
// ==========================================
// Minimal surfaces to avoid pulling full ABIs; keeps bytecode small.

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

interface IAavePool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IAaveFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// ==========================================
// UNIFIED EXECUTOR (HARDENED)
// ==========================================
/// @title UnifiedHardenedExecutor
/// @notice Single-owner helper for MEV bundles and Balancer/Aave flashloans. Intended to be driven
///         by an off-chain search via private relay (Flashbots / builder). Ownership must remain
///         with that off-chain signer; no shared custody assumed.
/// @dev Hardened for low-level token quirks (USDT-style approvals) and tolerant profit sweeping.

contract UnifiedHardenedExecutor is IFlashLoanRecipient, IAaveFlashLoanSimpleReceiver {
    // --- Constants & State ---
    // Mainnet Balancer vault; change on non-mainnet deployments.
    address private constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    
    address public immutable owner;
    // Mainnet WETH (hardcoded to avoid misconfiguration). Change and redeploy if using another chain.
    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address public profitReceiver;
    bool public sweepProfitToEth;
    address private activeAavePool;

    // --- Events ---
    event ArbitrageExecuted(uint256 surplus, address indexed token);
    event BundleExecuted(uint256 bribePaid);
    event ProfitReceiverUpdated(address indexed newReceiver);
    event SweepPreferenceUpdated(bool sweepToEth);
    event DistributeFailed(address indexed token, uint256 amount); // Funds left in contract
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
    error OnlyPool();
    error InvalidPool();
    error InvalidAsset();

    /// @param _profitReceiver address to receive residual profits/ETH sweeps.
    constructor(address _profitReceiver) {
        if (_profitReceiver == address(0)) revert InvalidProfitReceiver();
        // Harden WETH check: ensure hardcoded WETH is actually a contract
        if (WETH == address(0) || WETH.code.length == 0) revert InvalidWETHAddress();
        
        owner = msg.sender;
        profitReceiver = _profitReceiver;
        sweepProfitToEth = true; 
    }

    receive() external payable {}

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // Allow the contract to call itself (needed for mid-bundle approvals).
    modifier onlySelfOrOwner() {
        if (msg.sender != owner && msg.sender != address(this)) revert OnlyOwner();
        _;
    }

    // ==========================================
    // MODE 1: MEV BUNDLE EXECUTION (Direct)
    // ==========================================

    /// @notice Execute a multicall bundle and optional bribe. Owner-only.
    /// @param targets ordered list of call targets
    /// @param payloads calldata blobs matching each target
    /// @param values msg.value per call (in wei)
    /// @param bribeRecipient optional bribe recipient (zero => block.coinbase)
    /// @param bribeAmount bribe value in wei
    /// @param allowPartial if true, continue on individual call failure and emit CallFailed
    /// @param balanceCheckToken optional ERC20 to enforce non-decreasing balance
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
        if (targets.length == 0) revert LengthMismatch();

        uint256 tokenBalanceBefore = balanceCheckToken == address(0)
            ? 0
            : IERC20(balanceCheckToken).balanceOf(address(this));

        // 1. Execute all calls. msg.value already sits on this contract.
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

        // 2. Optional bribe. Check balance after calls to avoid underpay.
        if (bribeAmount > 0) {
            if (address(this).balance < bribeAmount) revert BribeFailed();
            
            address actualRecipient = bribeRecipient == address(0) ? block.coinbase : bribeRecipient;
            
            (bool ok, ) = actualRecipient.call{value: bribeAmount}("");
            if (!ok) revert BribeFailed();
            
            emit BundleExecuted(bribeAmount);
        }

        // 3. Refund / Sweep. If receiver rejects, keep funds to avoid reverting bundle.
        uint256 remaining = address(this).balance;
        if (remaining > 0) {
            (bool success, ) = profitReceiver.call{value: remaining}("");
            if (!success) emit DistributeFailed(address(0), remaining);
        }

        // 4. Optional balance invariant for a specified token.
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

    /// @notice Initiate a Balancer flashloan with arbitrary callback payload.
    /// @param assets loan tokens
    /// @param amounts loan amounts (must be >0)
    /// @param params abi.encode(targets, values, payloads) for callback execution
    function executeFlashLoan(
        IERC20[] calldata assets,
        uint256[] calldata amounts,
        bytes calldata params
    ) external onlyOwner {
        if (assets.length == 0) revert ZeroAssets();
        if (assets.length != amounts.length) revert LengthMismatch();
        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] == 0) revert ZeroAssets();
        }

        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this),
            assets,
            amounts,
            params
        );
    }

    /// @notice Initiate an Aave V3 simple flashloan. Params encoding matches Balancer path.
    /// @notice Initiate an Aave V3 simple flashloan.
    /// @param pool Aave pool address
    /// @param asset loan token
    /// @param amount loan amount (must be >0)
    /// @param params abi.encode(targets, values, payloads) for callback execution
    function executeAaveFlashLoanSimple(
        address pool,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (pool == address(0)) revert InvalidPool();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();
        activeAavePool = pool;
        IAavePool(pool).flashLoanSimple(address(this), asset, amount, params, 0);
        activeAavePool = address(0);
    }

    /// @inheritdoc IFlashLoanRecipient
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

        // 1. Arbitrage logic supplied by off-chain driver.
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                _revertWithDetails(i, result);
            }
        }

        // 2. Repay vault; distribute surplus if any.
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

        // 3. Sweep loose ETH from unwrapped WETH or native profits.
        uint256 ethBal = address(this).balance;
        if (ethBal > 0) {
            (bool success, ) = profitReceiver.call{value: ethBal}("");
            if (!success) emit DistributeFailed(address(0), ethBal);
        }
    }

    // Aave V3 simple flashloan callback
    /// @inheritdoc IAaveFlashLoanSimpleReceiver
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        if (msg.sender != activeAavePool) revert OnlyPool();
        if (initiator != address(this)) revert OnlyOwner();

        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) =
            abi.decode(params, (address[], uint256[], bytes[]));
        if (targets.length != values.length || targets.length != payloads.length) {
            revert LengthMismatch();
        }

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                _revertWithDetails(i, result);
            }
        }

        uint256 amountOwing = amount + premium;
        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(asset, amountOwing, bal);
        }

        uint256 surplus = bal - amountOwing;
        if (surplus > 0) {
            _distributeProfit(asset, surplus);
        }

        // Aave pulls repayment from receiver via transferFrom, so we must approve the Pool.
        uint256 currentAllowance = IERC20(asset).allowance(address(this), msg.sender);
        if (currentAllowance != 0 && currentAllowance != amountOwing) {
            _lowLevelApprove(asset, msg.sender, 0);
        }
        if (currentAllowance != amountOwing) {
            _lowLevelApprove(asset, msg.sender, amountOwing);
        }

        uint256 ethBal = address(this).balance;
        if (ethBal > 0) {
            (bool ok, ) = profitReceiver.call{value: ethBal}("");
            if (!ok) emit DistributeFailed(address(0), ethBal);
        }
        return true;
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
        // Check current allowance first to save gas and handle USDT-style reset rules.
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
        // Keep USDT/USDC safety: low-level call + bool decode. Swallow failures to avoid
        // reverting flashloan flow; funds stay on contract for manual recovery.
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
        // USDT-safe approve: must reset to zero first in some tokens.
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
