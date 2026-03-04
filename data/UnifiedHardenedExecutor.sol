// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

pragma solidity ^0.8.34;

interface IERC20 {
    /// @notice Returns the token balance held by an account.
    /// @param account Account to query.
    /// @return Current token balance.
    function balanceOf(address account) external view returns (uint256);

    /// @notice Returns the approved allowance from owner to spender.
    /// @param owner Allowance owner.
    /// @param spender Allowance spender.
    /// @return Current approved allowance.
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IWETH {
    /// @notice Wrap native ETH into WETH.
    function deposit() external payable;

    /// @notice Unwrap WETH into native ETH.
    /// @param amount Amount of WETH to unwrap.
    function withdraw(uint256 amount) external;
}

interface IBalancerVault {
    /// @notice Initiates a Balancer flash loan.
    /// @param recipient Flash loan receiver contract.
    /// @param tokens Borrowed token list.
    /// @param amounts Borrowed amount list.
    /// @param userData Opaque callback payload.
    function flashLoan(
        address recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IFlashLoanRecipient {
    /// @notice Balancer flash loan callback.
    /// @param tokens Borrowed tokens.
    /// @param amounts Borrowed principal amounts.
    /// @param feeAmounts Fee amounts owed per token.
    /// @param userData Opaque payload passed from initiation.
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

interface IAavePool {
    /// @notice Initiates an Aave V3 simple flash loan.
    /// @param receiverAddress Flash loan receiver contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed amount.
    /// @param params Opaque callback payload.
    /// @param referralCode Aave referral code.
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IAaveFlashLoanSimpleReceiver {
    /// @notice Aave V3 simple flash loan callback.
    /// @param asset Borrowed token.
    /// @param amount Borrowed principal amount.
    /// @param premium Fee owed to the pool.
    /// @param initiator Original flash loan initiator.
    /// @param params Opaque payload passed from initiation.
    /// @return True when callback execution succeeds.
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IDydxSoloMargin {
    struct AccountInfo {
        address owner;
        uint256 number;
    }

    struct AssetAmount {
        bool sign;
        uint8 denomination;
        uint8 ref;
        uint256 value;
    }

    struct ActionArgs {
        uint8 actionType;
        uint256 accountId;
        AssetAmount amount;
        uint256 primaryMarketId;
        uint256 secondaryMarketId;
        address otherAddress;
        uint256 otherAccountId;
        bytes data;
    }

    function operate(AccountInfo[] calldata accounts, ActionArgs[] calldata actions) external;
    function getNumMarkets() external view returns (uint256);
    function getMarketTokenAddress(uint256 marketId) external view returns (address);
}

interface IDydxCallee {
    function callFunction(
        address sender,
        IDydxSoloMargin.AccountInfo calldata accountInfo,
        bytes calldata data
    ) external;
}

interface IERC3156FlashLender {
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}

interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface IUniswapV2Callee {
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

interface IUniswapV3Pool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external;
}

/// @title UnifiedHardenedExecutor
/// @notice Owner-controlled executor for direct bundles and multi-provider flash loans.
/// @dev Uses low-level token calls to tolerate non-standard ERC20 behavior.
contract UnifiedHardenedExecutor is
    IFlashLoanRecipient,
    IAaveFlashLoanSimpleReceiver,
    IDydxCallee,
    IERC3156FlashBorrower,
    IUniswapV2Callee,
    IUniswapV3FlashCallback
{
    uint256 public constant AUTO_SWEEP_INTERVAL = 15 days;
    uint8 private constant DYDX_ACTION_DEPOSIT = 0;
    uint8 private constant DYDX_ACTION_WITHDRAW = 1;
    uint8 private constant DYDX_ACTION_CALL = 8;
    uint8 private constant DYDX_ASSET_DENOMINATION_WEI = 0;
    uint8 private constant DYDX_ASSET_REFERENCE_DELTA = 0;
    bytes32 private constant ERC3156_CALLBACK_SUCCESS =
        keccak256("ERC3156FlashBorrower.onFlashLoan");
    uint256 private constant UNISWAP_V2_FEE_NUMERATOR = 1000;
    uint256 private constant UNISWAP_V2_FEE_DENOMINATOR = 997;

    address public immutable owner;
    address public immutable WETH;
    address private immutable BALANCER_VAULT;

    address public profitReceiver;
    bool public sweepProfitToEth;
    uint256 public lastSweepAt;
    address private activeAavePool;
    bool private balancerLoanActive;
    bytes32 private balancerLoanContextHash;
    address private activeDydxSolo;
    bytes32 private dydxLoanContextHash;
    address private activeMakerLender;
    bytes32 private makerLoanContextHash;
    address private activeUniswapV2Pair;
    bytes32 private uniswapV2LoanContextHash;
    address private activeUniswapV3Pool;
    bytes32 private uniswapV3LoanContextHash;

    event ArbitrageExecuted(uint256 surplus, address indexed token);
    event BundleExecuted(uint256 bribePaid);
    event ProfitReceiverUpdated(address indexed newReceiver);
    event SweepPreferenceUpdated(bool sweepToEth);
    event DistributeFailed(address indexed token, uint256 amount);
    event CallFailed(uint256 index, bytes reason);
    event ManualSweepExecuted(uint256 timestamp);
    event AutoSweepExecuted(uint256 timestamp);
    event AavePoolStateUpdated(address indexed previousPool, address indexed newPool);
    event BalancerLoanSessionStateUpdated(bool active, bytes32 contextHash);
    event DydxSoloStateUpdated(address indexed previousSolo, address indexed newSolo);
    event MakerFlashLenderStateUpdated(address indexed previousLender, address indexed newLender);
    event UniswapV2PairStateUpdated(address indexed previousPair, address indexed newPair);
    event UniswapV3PoolStateUpdated(address indexed previousPool, address indexed newPool);

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
    error OnlyDydxSolo();
    error OnlyMakerFlashLender();
    error OnlyUniswapV2Pair();
    error OnlyUniswapV3Pool();
    error InvalidPool();
    error InvalidFlashloanPair();
    error InvalidFlashloanLender();
    error InvalidFlashloanSolo();
    error InvalidAsset();
    error InvalidBalancerVault();
    error UnsupportedPairAsset();
    error BalancerTokensNotSorted(uint256 index, address previous, address current);
    error BalancerLoanNotActive();
    error BalancerLoanContextMismatch();
    error BalancerCallbackNotReceived();
    error AaveCallbackNotReceived();
    error DydxLoanNotActive();
    error DydxLoanContextMismatch();
    error DydxCallbackNotReceived();
    error MakerLoanNotActive();
    error MakerLoanContextMismatch();
    error MakerCallbackNotReceived();
    error UniswapV2LoanNotActive();
    error UniswapV2LoanContextMismatch();
    error UniswapV2CallbackNotReceived();
    error UniswapV3LoanNotActive();
    error UniswapV3LoanContextMismatch();
    error UniswapV3CallbackNotReceived();

    /// @notice Deploys the executor.
    /// @dev Sets immutable dependencies and initializes sweep configuration.
    /// @param _profitReceiver Receiver for token and ETH profit sweeps.
    /// @param _weth Wrapped native token address.
    /// @param _balancerVault Balancer vault address used for callbacks.
    constructor(address _profitReceiver, address _weth, address _balancerVault) {
        if (_profitReceiver == address(0)) revert InvalidProfitReceiver();
        if (_weth == address(0) || _weth.code.length == 0) revert InvalidWETHAddress();
        if (_balancerVault == address(0) || _balancerVault.code.length == 0) revert InvalidBalancerVault();

        owner = msg.sender;
        profitReceiver = _profitReceiver;
        WETH = _weth;
        BALANCER_VAULT = _balancerVault;
        sweepProfitToEth = true;
        lastSweepAt = block.timestamp;
    }

    /// @notice Accepts native ETH transfers, including WETH unwrap proceeds.
    receive() external payable {}

    /// @notice Restricts a function to the owner address.
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    /// @notice Restricts a function to owner or self-call.
    /// @dev Self-calls are used for approved internal bundle actions.
    modifier onlySelfOrOwner() {
        if (msg.sender != owner && msg.sender != address(this)) revert OnlyOwner();
        _;
    }

    /// @notice Executes an arbitrary multicall bundle with optional bribe.
    /// @dev If `allowPartial` is false, the first failed subcall reverts the bundle.
    /// @param targets Ordered call targets.
    /// @param payloads Calldata for each target.
    /// @param values ETH value for each call.
    /// @param bribeRecipient Optional bribe recipient. Zero address maps to `block.coinbase`.
    /// @param bribeAmount Bribe amount paid in native ETH.
    /// @param allowPartial Whether failed subcalls are tolerated.
    /// @param balanceCheckToken Optional token used for post-bundle non-decrease check.
    function executeBundle(
        address[] calldata targets,
        bytes[] calldata payloads,
        uint256[] calldata values,
        address bribeRecipient,
        uint256 bribeAmount,
        bool allowPartial,
        address balanceCheckToken
    ) external payable onlyOwner {
        uint256 targetsLen = targets.length;
        if (targetsLen != payloads.length || targetsLen != values.length) {
            revert LengthMismatch();
        }
        if (targetsLen == 0) revert LengthMismatch();

        uint256 tokenBalanceBefore = balanceCheckToken == address(0)
            ? 0
            : IERC20(balanceCheckToken).balanceOf(address(this));

        for (uint256 i = 0; i < targetsLen; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                if (allowPartial) {
                    emit CallFailed(i, result);
                    continue;
                }
                _revertWithDetails(i, result);
            }
        }

        if (bribeAmount > 0) {
            if (address(this).balance < bribeAmount) revert BribeFailed();

            address actualRecipient = bribeRecipient == address(0) ? block.coinbase : bribeRecipient;
            (bool ok, ) = actualRecipient.call{value: bribeAmount}("");
            if (!ok) revert BribeFailed();

            emit BundleExecuted(bribeAmount);
        }

        bool autoSweepRan = false;
        if (autoSweepDue()) {
            address cachedProfitReceiver = profitReceiver;
            autoSweepRan = _transferEthToProfitReceiver(false, cachedProfitReceiver);
        }
        if (autoSweepRan) {
            _recordSweep(true);
        }

        if (balanceCheckToken != address(0)) {
            uint256 tokenBalanceAfter = IERC20(balanceCheckToken).balanceOf(address(this));
            if (tokenBalanceAfter < tokenBalanceBefore) {
                revert BalanceInvariantBroken(balanceCheckToken, tokenBalanceBefore, tokenBalanceAfter);
            }
        }
    }

    /// @notice Starts a Balancer flash loan session.
    /// @dev Stores a single-use context hash that must match callback parameters.
    /// @param assets Sorted borrowed token list.
    /// @param amounts Borrowed amount list, each strictly positive.
    /// @param params ABI-encoded execution payload forwarded to callback.
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
        for (uint256 i = 1; i < assets.length; i++) {
            address previous = address(assets[i - 1]);
            address current = address(assets[i]);
            if (current <= previous) {
                revert BalancerTokensNotSorted(i, previous, current);
            }
        }

        balancerLoanActive = true;
        balancerLoanContextHash = keccak256(abi.encode(assets, amounts, params));
        emit BalancerLoanSessionStateUpdated(true, balancerLoanContextHash);

        IBalancerVault(BALANCER_VAULT).flashLoan(address(this), assets, amounts, params);

        if (balancerLoanActive || balancerLoanContextHash != bytes32(0)) {
            revert BalancerCallbackNotReceived();
        }
    }

    /// @notice Starts an Aave V3 simple flash loan session.
    /// @dev The callback payload layout matches the Balancer route payload layout.
    /// @param pool Aave pool that will invoke the callback.
    /// @param asset Borrowed token address.
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded execution payload forwarded to callback.
    function executeAaveFlashLoanSimple(
        address pool,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (pool == address(0)) revert InvalidPool();
        if (pool.code.length == 0) revert InvalidPool();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();
        address previousPool = activeAavePool;
        activeAavePool = pool;
        emit AavePoolStateUpdated(previousPool, pool);
        IAavePool(pool).flashLoanSimple(address(this), asset, amount, params, 0);
        if (activeAavePool != address(0)) revert AaveCallbackNotReceived();
    }

    /// @notice Starts a dYdX Solo flash loan session.
    /// @param soloMargin dYdX SoloMargin contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeDydxFlashLoan(
        address soloMargin,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (soloMargin == address(0) || soloMargin.code.length == 0) revert InvalidFlashloanSolo();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        uint256 marketId = _dydxFindMarketId(soloMargin, asset);
        uint256 amountOwing = amount + 2;
        bytes memory callbackData = abi.encode(asset, amount, params);

        address previousSolo = activeDydxSolo;
        activeDydxSolo = soloMargin;
        dydxLoanContextHash = keccak256(abi.encode(soloMargin, asset, amount, params));
        emit DydxSoloStateUpdated(previousSolo, soloMargin);

        IDydxSoloMargin.AccountInfo[] memory accounts = new IDydxSoloMargin.AccountInfo[](1);
        accounts[0] = IDydxSoloMargin.AccountInfo({owner: address(this), number: 1});

        IDydxSoloMargin.ActionArgs[] memory actions = new IDydxSoloMargin.ActionArgs[](3);
        actions[0] = _dydxWithdrawAction(marketId, amount);
        actions[1] = _dydxCallAction(callbackData);
        actions[2] = _dydxDepositAction(marketId, amountOwing);

        IDydxSoloMargin(soloMargin).operate(accounts, actions);
        if (activeDydxSolo != address(0) || dydxLoanContextHash != bytes32(0)) {
            revert DydxCallbackNotReceived();
        }
    }

    /// @notice Starts a MakerDAO ERC3156 flash loan session.
    /// @param lender ERC3156 lender contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeMakerFlashLoan(
        address lender,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (lender == address(0) || lender.code.length == 0) revert InvalidFlashloanLender();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        address previousLender = activeMakerLender;
        activeMakerLender = lender;
        makerLoanContextHash = keccak256(abi.encode(lender, asset, amount, params));
        emit MakerFlashLenderStateUpdated(previousLender, lender);

        bool ok = IERC3156FlashLender(lender).flashLoan(address(this), asset, amount, params);
        if (!ok) revert MakerCallbackNotReceived();
        if (activeMakerLender != address(0) || makerLoanContextHash != bytes32(0)) {
            revert MakerCallbackNotReceived();
        }
    }

    /// @notice Starts a Uniswap V2 flash swap session for a single borrowed token.
    /// @param pair Uniswap V2 pair contract.
    /// @param asset Borrowed token (must equal pair token0 or token1).
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeUniswapV2FlashLoan(
        address pair,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (pair == address(0) || pair.code.length == 0) revert InvalidFlashloanPair();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        address token0 = IUniswapV2Pair(pair).token0();
        address token1 = IUniswapV2Pair(pair).token1();
        uint256 amount0Out;
        uint256 amount1Out;
        if (asset == token0) {
            amount0Out = amount;
        } else if (asset == token1) {
            amount1Out = amount;
        } else {
            revert UnsupportedPairAsset();
        }

        address previousPair = activeUniswapV2Pair;
        activeUniswapV2Pair = pair;
        uniswapV2LoanContextHash = keccak256(abi.encode(pair, asset, amount, params));
        emit UniswapV2PairStateUpdated(previousPair, pair);

        IUniswapV2Pair(pair).swap(amount0Out, amount1Out, address(this), abi.encode(asset, amount, params));
        if (activeUniswapV2Pair != address(0) || uniswapV2LoanContextHash != bytes32(0)) {
            revert UniswapV2CallbackNotReceived();
        }
    }

    /// @notice Starts a Uniswap V3 flash loan session for a single borrowed token.
    /// @param pool Uniswap V3 pool contract.
    /// @param asset Borrowed token (must equal pool token0 or token1).
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeUniswapV3FlashLoan(
        address pool,
        address asset,
        uint256 amount,
        bytes calldata params
    ) external onlyOwner {
        if (pool == address(0) || pool.code.length == 0) revert InvalidPool();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        address token0 = IUniswapV3Pool(pool).token0();
        address token1 = IUniswapV3Pool(pool).token1();
        uint256 amount0;
        uint256 amount1;
        if (asset == token0) {
            amount0 = amount;
        } else if (asset == token1) {
            amount1 = amount;
        } else {
            revert UnsupportedPairAsset();
        }

        address previousPool = activeUniswapV3Pool;
        activeUniswapV3Pool = pool;
        uniswapV3LoanContextHash = keccak256(abi.encode(pool, asset, amount, params));
        emit UniswapV3PoolStateUpdated(previousPool, pool);

        IUniswapV3Pool(pool).flash(address(this), amount0, amount1, abi.encode(asset, amount, params));
        if (activeUniswapV3Pool != address(0) || uniswapV3LoanContextHash != bytes32(0)) {
            revert UniswapV3CallbackNotReceived();
        }
    }

    /// @notice Balancer flash loan callback that executes payload calls and repays principal plus fees.
    /// @dev Reverts unless the caller and callback context match the active flash loan session.
    /// @param tokens Borrowed token list.
    /// @param amounts Borrowed principal amounts.
    /// @param feeAmounts Borrowing fee amounts.
    /// @param userData ABI-encoded payload containing `(targets, values, payloads)`.
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external override {
        if (msg.sender != BALANCER_VAULT) revert OnlyVault();
        if (!balancerLoanActive) revert BalancerLoanNotActive();

        bytes32 callbackContext = keccak256(abi.encode(tokens, amounts, userData));
        if (callbackContext != balancerLoanContextHash) revert BalancerLoanContextMismatch();

        balancerLoanActive = false;
        balancerLoanContextHash = bytes32(0);
        emit BalancerLoanSessionStateUpdated(false, bytes32(0));

        if (tokens.length != amounts.length || tokens.length != feeAmounts.length) {
            revert LengthMismatch();
        }

        _executePayloadFromMemory(userData);

        if (_settleBalancerRepayment(tokens, amounts, feeAmounts)) {
            _recordSweep(true);
        }
    }

    /// @notice Aave V3 simple flash loan callback that executes payload calls and approves repayment.
    /// @dev Reverts unless caller is the active pool and initiator is this contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed principal amount.
    /// @param premium Fee owed to the pool.
    /// @param initiator Flash loan initiator expected to be this contract.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    /// @return True when callback processing completes.
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        if (msg.sender != activeAavePool) revert OnlyPool();
        if (initiator != address(this)) revert OnlyOwner();
        address previousPool = activeAavePool;
        activeAavePool = address(0);
        emit AavePoolStateUpdated(previousPool, address(0));

        _executePayloadFromCalldata(params);

        uint256 amountOwing = amount + premium;
        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(asset, amountOwing, bal);
        }

        uint256 currentAllowance = IERC20(asset).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(asset, msg.sender, 0);
            }
            _lowLevelApprove(asset, msg.sender, amountOwing);
        }

        if (_settleAaveAutoSweep(asset, bal - amountOwing)) {
            _recordSweep(true);
        }
        return true;
    }

    /// @notice dYdX callback that executes payload calls and sets token approval for repayment.
    /// @param sender Original sender passed by SoloMargin.
    /// @param accountInfo dYdX account metadata.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function callFunction(
        address sender,
        IDydxSoloMargin.AccountInfo calldata accountInfo,
        bytes calldata data
    ) external override {
        if (msg.sender != activeDydxSolo) revert OnlyDydxSolo();
        if (activeDydxSolo == address(0)) revert DydxLoanNotActive();
        if (sender != address(this) || accountInfo.owner != address(this)) revert OnlyOwner();

        (address asset, uint256 amount, bytes memory params) = abi.decode(data, (address, uint256, bytes));
        bytes32 callbackContext = keccak256(abi.encode(msg.sender, asset, amount, params));
        if (callbackContext != dydxLoanContextHash) revert DydxLoanContextMismatch();

        address previousSolo = activeDydxSolo;
        activeDydxSolo = address(0);
        dydxLoanContextHash = bytes32(0);
        emit DydxSoloStateUpdated(previousSolo, address(0));

        _executePayloadFromMemory(params);

        uint256 amountOwing = amount + 2;
        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(asset, amountOwing, bal);
        }

        uint256 currentAllowance = IERC20(asset).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(asset, msg.sender, 0);
            }
            _lowLevelApprove(asset, msg.sender, amountOwing);
        }

        if (_settleAaveAutoSweep(asset, bal - amountOwing)) {
            _recordSweep(true);
        }
    }

    /// @notice ERC3156 flash loan callback used by MakerDAO flash lender.
    /// @param initiator Flash loan initiator expected to be this contract.
    /// @param token Borrowed token.
    /// @param amount Borrowed amount.
    /// @param fee Flash loan fee.
    /// @param data ABI-encoded payload containing `(targets, values, payloads)`.
    /// @return Callback success selector hash required by ERC3156.
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external override returns (bytes32) {
        if (msg.sender != activeMakerLender) revert OnlyMakerFlashLender();
        if (activeMakerLender == address(0)) revert MakerLoanNotActive();
        if (initiator != address(this)) revert OnlyOwner();

        bytes32 callbackContext = keccak256(abi.encode(msg.sender, token, amount, data));
        if (callbackContext != makerLoanContextHash) revert MakerLoanContextMismatch();

        address previousLender = activeMakerLender;
        activeMakerLender = address(0);
        makerLoanContextHash = bytes32(0);
        emit MakerFlashLenderStateUpdated(previousLender, address(0));

        _executePayloadFromCalldata(data);

        uint256 amountOwing = amount + fee;
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(token, amountOwing, bal);
        }

        uint256 currentAllowance = IERC20(token).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(token, msg.sender, 0);
            }
            _lowLevelApprove(token, msg.sender, amountOwing);
        }

        if (_settleAaveAutoSweep(token, bal - amountOwing)) {
            _recordSweep(true);
        }
        return ERC3156_CALLBACK_SUCCESS;
    }

    /// @notice Uniswap V2 flash swap callback.
    /// @param sender Swap caller expected to be this contract.
    /// @param amount0 Borrowed token0 amount.
    /// @param amount1 Borrowed token1 amount.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external override {
        if (msg.sender != activeUniswapV2Pair) revert OnlyUniswapV2Pair();
        if (activeUniswapV2Pair == address(0)) revert UniswapV2LoanNotActive();
        if (sender != address(this)) revert OnlyOwner();

        (address asset, uint256 amount, bytes memory params) = abi.decode(data, (address, uint256, bytes));
        bytes32 callbackContext = keccak256(abi.encode(msg.sender, asset, amount, params));
        if (callbackContext != uniswapV2LoanContextHash) revert UniswapV2LoanContextMismatch();

        uint256 borrowed = amount0 == 0 ? amount1 : amount0;
        if (borrowed == 0 || amount0 == amount1 || borrowed != amount) {
            revert UniswapV2LoanContextMismatch();
        }

        address previousPair = activeUniswapV2Pair;
        activeUniswapV2Pair = address(0);
        uniswapV2LoanContextHash = bytes32(0);
        emit UniswapV2PairStateUpdated(previousPair, address(0));

        _executePayloadFromMemory(params);

        uint256 amountOwing = _uniswapV2RepaymentAmount(amount);
        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(asset, amountOwing, bal);
        }

        if (_settleAaveAutoSweep(asset, bal - amountOwing)) {
            _recordSweep(true);
        }
        _safeTransfer(asset, msg.sender, amountOwing);
    }

    /// @notice Uniswap V3 flash callback.
    /// @param fee0 Fee owed in token0.
    /// @param fee1 Fee owed in token1.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external override {
        if (msg.sender != activeUniswapV3Pool) revert OnlyUniswapV3Pool();
        if (activeUniswapV3Pool == address(0)) revert UniswapV3LoanNotActive();

        (address asset, uint256 amount, bytes memory params) = abi.decode(data, (address, uint256, bytes));
        bytes32 callbackContext = keccak256(abi.encode(msg.sender, asset, amount, params));
        if (callbackContext != uniswapV3LoanContextHash) revert UniswapV3LoanContextMismatch();

        address previousPool = activeUniswapV3Pool;
        activeUniswapV3Pool = address(0);
        uniswapV3LoanContextHash = bytes32(0);
        emit UniswapV3PoolStateUpdated(previousPool, address(0));

        _executePayloadFromMemory(params);

        uint256 amountOwing;
        address token0 = IUniswapV3Pool(msg.sender).token0();
        if (asset == token0) {
            if (fee1 != 0) revert UniswapV3LoanContextMismatch();
            amountOwing = amount + fee0;
        } else {
            if (fee0 != 0) revert UniswapV3LoanContextMismatch();
            amountOwing = amount + fee1;
        }

        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal < amountOwing) {
            revert InsufficientFundsForRepayment(asset, amountOwing, bal);
        }

        if (_settleAaveAutoSweep(asset, bal - amountOwing)) {
            _recordSweep(true);
        }
        _safeTransfer(asset, msg.sender, amountOwing);
    }

    /// @notice Updates the configured profit receiver.
    /// @param newReceiver New receiver address for sweep transfers.
    function setProfitReceiver(address newReceiver) external onlyOwner {
        if (newReceiver == address(0)) revert InvalidProfitReceiver();
        profitReceiver = newReceiver;
        emit ProfitReceiverUpdated(newReceiver);
    }

    /// @notice Sets whether token profits should be converted from WETH into native ETH before sweep.
    /// @param sweepToEth True to unwrap WETH profits before ETH transfer; false to keep token form.
    function setSweepPreference(bool sweepToEth) external onlyOwner {
        sweepProfitToEth = sweepToEth;
        emit SweepPreferenceUpdated(sweepToEth);
    }

    /// @notice Returns whether the configured auto-sweep interval has elapsed.
    /// @return True when auto sweep is due.
    function autoSweepDue() public view returns (bool) {
        return block.timestamp >= lastSweepAt + AUTO_SWEEP_INTERVAL;
    }

    /// @notice Manually sweeps the full token balance to `profitReceiver`.
    /// @param token ERC20 token address to sweep.
    function sweepToken(address token) external onlyOwner {
        address cachedProfitReceiver = profitReceiver;
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal == 0) return;
        _safeTransfer(token, cachedProfitReceiver, bal);
        _recordSweep(false);
    }

    /// @notice Manually sweeps the full native ETH balance to `profitReceiver`.
    function sweepETH() external onlyOwner {
        address cachedProfitReceiver = profitReceiver;
        if (_transferEthToProfitReceiver(true, cachedProfitReceiver)) {
            _recordSweep(false);
        }
    }

    /// @notice Sets ERC20 allowance with USDT-compatible zero-reset semantics.
    /// @dev Callable by owner or via self-call from bundle/flash payload execution.
    /// @param token ERC20 token to approve.
    /// @param spender Allowance spender.
    /// @param amount Desired allowance value.
    function safeApprove(address token, address spender, uint256 amount) external onlySelfOrOwner {
        uint256 currentAllowance = IERC20(token).allowance(address(this), spender);
        if (currentAllowance == amount) return;
        if (currentAllowance != 0) {
            _lowLevelApprove(token, spender, 0);
        }
        _lowLevelApprove(token, spender, amount);
    }

    /// @notice Decodes and executes payload calls from memory bytes.
    /// @param encodedPayload ABI-encoded `(targets, values, payloads)`.
    function _executePayloadFromMemory(bytes memory encodedPayload) internal {
        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) =
            abi.decode(encodedPayload, (address[], uint256[], bytes[]));
        _executeTargets(targets, values, payloads);
    }

    /// @notice Decodes and executes payload calls from calldata bytes.
    /// @param encodedPayload ABI-encoded `(targets, values, payloads)`.
    function _executePayloadFromCalldata(bytes calldata encodedPayload) internal {
        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) =
            abi.decode(encodedPayload, (address[], uint256[], bytes[]));
        _executeTargets(targets, values, payloads);
    }

    /// @notice Executes target calls with per-call ETH values.
    /// @param targets Ordered call targets.
    /// @param values ETH value for each call.
    /// @param payloads Calldata for each target.
    function _executeTargets(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory payloads
    ) internal {
        uint256 targetsLen = targets.length;
        if (targetsLen != values.length || targetsLen != payloads.length) {
            revert LengthMismatch();
        }

        for (uint256 i = 0; i < targetsLen; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                _revertWithDetails(i, result);
            }
        }
    }

    /// @notice Settles Balancer flash loan repayment and optional lazy auto-sweep.
    /// @param tokens Borrowed tokens.
    /// @param amounts Borrowed principal amounts.
    /// @param feeAmounts Fee amounts owed per token.
    /// @return autoSweepRan True if at least one automatic sweep transfer succeeded.
    function _settleBalancerRepayment(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts
    ) internal returns (bool autoSweepRan) {
        bool dueForAutoSweep = autoSweepDue();
        uint256 tokensLen = tokens.length;
        address balancerVault = BALANCER_VAULT;
        address cachedProfitReceiver = profitReceiver;
        bool cachedSweepToEth = sweepProfitToEth;

        for (uint256 i = 0; i < tokensLen; i++) {
            uint256 amountOwing = amounts[i] + feeAmounts[i];
            if (amountOwing == 0) continue;

            address tokenAddr = address(tokens[i]);
            uint256 myBalance = IERC20(tokenAddr).balanceOf(address(this));

            if (myBalance < amountOwing) {
                revert InsufficientFundsForRepayment(tokenAddr, amountOwing, myBalance);
            }

            uint256 surplus = myBalance - amountOwing;
            if (dueForAutoSweep && surplus > 0) {
                if (_distributeProfit(tokenAddr, surplus, cachedProfitReceiver, cachedSweepToEth)) {
                    autoSweepRan = true;
                }
            }

            _safeTransfer(tokenAddr, balancerVault, amountOwing);
        }

        if (dueForAutoSweep && _transferEthToProfitReceiver(false, cachedProfitReceiver)) {
            autoSweepRan = true;
        }
    }

    /// @notice Handles optional lazy auto-sweep after Aave repayment setup.
    /// @param asset Borrowed asset used for surplus distribution.
    /// @param surplus Surplus balance after reserving repayment amount.
    /// @return autoSweepRan True if at least one automatic sweep transfer succeeded.
    function _settleAaveAutoSweep(address asset, uint256 surplus) internal returns (bool autoSweepRan) {
        bool dueForAutoSweep = autoSweepDue();
        address cachedProfitReceiver = profitReceiver;
        bool cachedSweepToEth = sweepProfitToEth;
        if (dueForAutoSweep && surplus > 0) {
            if (_distributeProfit(asset, surplus, cachedProfitReceiver, cachedSweepToEth)) {
                autoSweepRan = true;
            }
        }
        if (dueForAutoSweep && _transferEthToProfitReceiver(false, cachedProfitReceiver)) {
            autoSweepRan = true;
        }
    }

    /// @notice Finds dYdX market id for a token address.
    /// @param soloMargin dYdX SoloMargin contract.
    /// @param asset Token address to locate.
    /// @return marketId dYdX market id.
    function _dydxFindMarketId(address soloMargin, address asset) internal view returns (uint256 marketId) {
        uint256 numMarkets = IDydxSoloMargin(soloMargin).getNumMarkets();
        for (uint256 i = 0; i < numMarkets; i++) {
            if (IDydxSoloMargin(soloMargin).getMarketTokenAddress(i) == asset) {
                return i;
            }
        }
        revert InvalidAsset();
    }

    /// @notice Builds a dYdX asset amount struct for wei-delta actions.
    /// @param sign Sign flag where true is positive amount.
    /// @param value Amount value.
    /// @return AssetAmount formatted for SoloMargin actions.
    function _dydxAssetAmount(
        bool sign,
        uint256 value
    ) internal pure returns (IDydxSoloMargin.AssetAmount memory) {
        return IDydxSoloMargin.AssetAmount({
            sign: sign,
            denomination: DYDX_ASSET_DENOMINATION_WEI,
            ref: DYDX_ASSET_REFERENCE_DELTA,
            value: value
        });
    }

    /// @notice Builds a dYdX withdraw action.
    /// @param marketId Market id.
    /// @param amount Amount to withdraw.
    /// @return ActionArgs for SoloMargin.
    function _dydxWithdrawAction(
        uint256 marketId,
        uint256 amount
    ) internal view returns (IDydxSoloMargin.ActionArgs memory) {
        return IDydxSoloMargin.ActionArgs({
            actionType: DYDX_ACTION_WITHDRAW,
            accountId: 0,
            amount: _dydxAssetAmount(false, amount),
            primaryMarketId: marketId,
            secondaryMarketId: 0,
            otherAddress: address(this),
            otherAccountId: 0,
            data: new bytes(0)
        });
    }

    /// @notice Builds a dYdX call action.
    /// @param data Callback data.
    /// @return ActionArgs for SoloMargin.
    function _dydxCallAction(bytes memory data) internal view returns (IDydxSoloMargin.ActionArgs memory) {
        return IDydxSoloMargin.ActionArgs({
            actionType: DYDX_ACTION_CALL,
            accountId: 0,
            amount: _dydxAssetAmount(false, 0),
            primaryMarketId: 0,
            secondaryMarketId: 0,
            otherAddress: address(this),
            otherAccountId: 0,
            data: data
        });
    }

    /// @notice Builds a dYdX deposit action.
    /// @param marketId Market id.
    /// @param amount Amount to deposit.
    /// @return ActionArgs for SoloMargin.
    function _dydxDepositAction(
        uint256 marketId,
        uint256 amount
    ) internal view returns (IDydxSoloMargin.ActionArgs memory) {
        return IDydxSoloMargin.ActionArgs({
            actionType: DYDX_ACTION_DEPOSIT,
            accountId: 0,
            amount: _dydxAssetAmount(true, amount),
            primaryMarketId: marketId,
            secondaryMarketId: 0,
            otherAddress: address(this),
            otherAccountId: 0,
            data: new bytes(0)
        });
    }

    /// @notice Calculates single-token repayment required for Uniswap V2 flash swaps.
    /// @param amount Borrowed amount.
    /// @return Amount that must be transferred back to the pair.
    function _uniswapV2RepaymentAmount(uint256 amount) internal pure returns (uint256) {
        uint256 numerator = amount * UNISWAP_V2_FEE_NUMERATOR;
        uint256 quotient = numerator / UNISWAP_V2_FEE_DENOMINATOR;
        if (numerator % UNISWAP_V2_FEE_DENOMINATOR == 0) {
            return quotient;
        }
        return quotient + 1;
    }

    /// @notice Distributes token-denominated profit to receiver based on sweep settings.
    /// @dev On transfer failure, emits `DistributeFailed` and returns false without reverting.
    /// @param tokenAddr Token from which profit is distributed.
    /// @param profit Profit amount.
    /// @param receiver Profit receiver.
    /// @param sweepToEth Whether WETH profits should be unwrapped into ETH.
    /// @return True when token transfer succeeds, false otherwise.
    function _distributeProfit(
        address tokenAddr,
        uint256 profit,
        address receiver,
        bool sweepToEth
    ) internal returns (bool) {
        if (tokenAddr == WETH && sweepToEth) {
            IWETH(WETH).withdraw(profit);
            return false;
        }

        (bool success, bytes memory data) = tokenAddr.call(
            abi.encodeWithSelector(0xa9059cbb, receiver, profit)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            emit DistributeFailed(tokenAddr, profit);
            return false;
        }

        emit ArbitrageExecuted(profit, tokenAddr);
        return true;
    }

    /// @notice Transfers all native ETH held by this contract to receiver.
    /// @param revertOnFailure Whether failed transfer should revert.
    /// @param receiver ETH receiver.
    /// @return True when transfer succeeds, false when no balance or transfer failure is swallowed.
    function _transferEthToProfitReceiver(bool revertOnFailure, address receiver) internal returns (bool) {
        uint256 bal = address(this).balance;
        if (bal == 0) return false;

        (bool success, ) = receiver.call{value: bal}("");
        if (!success) {
            if (revertOnFailure) revert TokenTransferFailed();
            emit DistributeFailed(address(0), bal);
            return false;
        }
        return true;
    }

    /// @notice Records a sweep event and updates sweep timestamp only when needed.
    /// @param automatic True for auto sweep events, false for manual sweep events.
    function _recordSweep(bool automatic) internal {
        uint256 sweepTimestamp = block.timestamp;
        if (lastSweepAt != sweepTimestamp) {
            lastSweepAt = sweepTimestamp;
        }
        if (automatic) {
            emit AutoSweepExecuted(sweepTimestamp);
        } else {
            emit ManualSweepExecuted(sweepTimestamp);
        }
    }

    /// @notice Performs a low-level ERC20 approve call.
    /// @param token ERC20 token.
    /// @param spender Allowance spender.
    /// @param amount Allowance value.
    function _lowLevelApprove(address token, address spender, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x095ea7b3, spender, amount)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert ApprovalFailed();
        }
    }

    /// @notice Performs a low-level ERC20 transfer call.
    /// @param token ERC20 token.
    /// @param to Transfer recipient.
    /// @param value Transfer amount.
    function _safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value)
        );
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TokenTransferFailed();
        }
    }

    /// @notice Reverts with standardized execution context for failed downstream calls.
    /// @param index Index of the failed call in the decoded payload array.
    /// @param result Raw revert bytes returned by the failed call.
    function _revertWithDetails(uint256 index, bytes memory result) internal pure {
        revert ExecutionFailed(index, result);
    }
}
