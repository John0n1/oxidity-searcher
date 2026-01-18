interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
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

contract OxidizedFlashExecutor is IFlashLoanRecipient {
    address private constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    address public immutable owner;
    address public profitReceiver;
    address public immutable WETH;
    bool public sweepProfitToEth;

    event ArbitrageExecuted(uint256 surplus, address token);
    event ProfitReceiverUpdated(address indexed newReceiver);
    event SweepPreferenceUpdated(bool sweepToEth);

    error OnlyOwner();
    error OnlyVault();
    error LengthMismatch();
    error ZeroAssets();
    error ExecutionFailed(uint256 index, bytes reason);
    error InsufficientFundsForRepayment(address token, uint256 required, uint256 available);
    error InsufficientETH(uint256 required, uint256 available);
    error InvalidWETHAddress();
    error InvalidProfitReceiver();
    error TokenTransferFailed();
    error ETHTransferFailed();
    error ApprovalFailed();

    constructor(address profitReceiver_, address weth_) {
        if (profitReceiver_ == address(0)) revert InvalidProfitReceiver();
        if (weth_ == address(0)) revert InvalidWETHAddress();
        owner = msg.sender;
        profitReceiver = profitReceiver_;
        WETH = weth_;
        sweepProfitToEth = true; // default: keep treasury in native ETH
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier onlySelfOrOwner() {
        if (msg.sender != owner && msg.sender != address(this)) revert OnlyOwner();
        _;
    }

    function setProfitReceiver(address newReceiver) external onlyOwner {
        if (newReceiver == address(0)) revert InvalidProfitReceiver();
        profitReceiver = newReceiver;
        emit ProfitReceiverUpdated(newReceiver);
    }

    function setSweepPreference(bool sweepToEth) external onlyOwner {
        sweepProfitToEth = sweepToEth;
        emit SweepPreferenceUpdated(sweepToEth);
    }

    function execute(
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
        if (tokens.length != amounts.length || tokens.length != feeAmounts.length) {
            revert LengthMismatch();
        }
        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) = 
            abi.decode(userData, (address[], uint256[], bytes[]));
        if (targets.length != values.length || targets.length != payloads.length) {
            revert LengthMismatch();
        }

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        let returndata_size := mload(result)
                        revert(add(32, result), returndata_size)
                    }
                } else {
                    revert ExecutionFailed(i, result);
                }
            }
        }

        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 amountOwing = amounts[i] + feeAmounts[i];
            if (amountOwing == 0) continue;

            address tokenAddr = address(tokens[i]);
            uint256 myBalance = IERC20(tokenAddr).balanceOf(address(this));
            if (myBalance < amountOwing) {
                revert InsufficientFundsForRepayment(tokenAddr, amountOwing, myBalance);
            }

            // Send profit first, then repay the vault.
            if (myBalance > amountOwing) {
                uint256 surplus = myBalance - amountOwing;
                _distributeProfit(tokenAddr, surplus);
                emit ArbitrageExecuted(surplus, tokenAddr);
            }

            _safeTransfer(tokenAddr, BALANCER_VAULT, amountOwing);
        }

        uint256 ethBal = address(this).balance;
        if (ethBal > 0) {
            _sendETH(profitReceiver, ethBal);
        }
    }

    function safeApprove(address token, address spender, uint256 amount) external onlySelfOrOwner {
        uint256 currentAllowance = IERC20(token).allowance(address(this), spender);
        
        if (currentAllowance < amount) {
            if (currentAllowance > 0) {
                _lowLevelApprove(token, spender, 0);
            }
            _lowLevelApprove(token, spender, amount);
        }
    }

    function _distributeProfit(address tokenAddr, uint256 profit) internal {
        if (tokenAddr == WETH && sweepProfitToEth) {
            IWETH(WETH).withdraw(profit);
            _sendETH(profitReceiver, profit);
        } else {
            _safeTransfer(tokenAddr, profitReceiver, profit);
        }
    }

    function _lowLevelApprove(address token, address spender, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x095ea7b3, spender, amount) // approve(address,uint256)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert ApprovalFailed();
        }
    }

    function _safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value) // transfer(address,uint256)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TokenTransferFailed();
        }
    }

    function _sendETH(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert ETHTransferFailed();
    }

    function withdraw(address token) external onlyOwner {
        if (token == address(0)) {
            _sendETH(owner, address(this).balance);
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            if (balance > 0) {
                _safeTransfer(token, owner, balance);
            }
        }
    }

    function wrapETH(uint256 amount) external payable onlySelfOrOwner {
        if (WETH.code.length == 0) revert InvalidWETHAddress();
        if (address(this).balance < amount) revert InsufficientETH(amount, address(this).balance);
        IWETH(WETH).deposit{value: amount}();
    }

    function unwrapWETH(uint256 amount) external onlySelfOrOwner {
        if (WETH.code.length == 0) revert InvalidWETHAddress();
        IWETH(WETH).withdraw(amount);
    }

    receive() external payable {}
}
