// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

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
    function flashLoan(address recipient, IERC20[] memory tokens, uint256[] memory amounts, bytes memory userData)
        external;
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
    function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata params)
        external
        returns (bool);
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
    function callFunction(address sender, IDydxSoloMargin.AccountInfo calldata accountInfo, bytes calldata data)
        external;
}

interface IERC3156FlashLender {
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external returns (bool);
}

interface IERC3156FlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        returns (bytes32);
}

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IUniswapV3Pool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external;
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
    uint8 private constant DYDX_ACTION_DEPOSIT = 0;
    uint8 private constant DYDX_ACTION_WITHDRAW = 1;
    uint8 private constant DYDX_ACTION_CALL = 8;
    uint8 private constant DYDX_ASSET_DENOMINATION_WEI = 0;
    uint8 private constant DYDX_ASSET_REFERENCE_DELTA = 0;
    bytes32 private constant ERC3156_CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");
    uint256 private constant UNISWAP_V2_FEE_NUMERATOR = 1000;
    uint256 private constant UNISWAP_V2_FEE_DENOMINATOR = 997;

    address public owner;
    address public pendingOwner;
    address public immutable WETH;
    address public immutable balancerVault;

    address public profitReceiver;
    bool public sweepProfitToEth;
    bool public paused;
    bool private executionActive;
    address private activeAavePool;
    bytes32 private aaveLoanContextHash;
    uint256 private aavePreLoanBalance;
    bool private balancerLoanActive;
    bytes32 private balancerLoanContextHash;
    uint256[] private balancerPreLoanBalances;
    address private activeDydxSolo;
    bytes32 private dydxLoanContextHash;
    uint256 private dydxPreLoanBalance;
    address private activeMakerLender;
    bytes32 private makerLoanContextHash;
    uint256 private makerPreLoanBalance;
    address private activeUniswapV2Pair;
    bytes32 private uniswapV2LoanContextHash;
    uint256 private uniswapV2PreLoanBalance;
    address private activeUniswapV3Pool;
    bytes32 private uniswapV3LoanContextHash;
    uint256 private uniswapV3PreLoanBalance;

    mapping(address => bool) public approvedProviders;

    event ArbitrageExecuted(uint256 surplus, address indexed token);
    event BundleExecuted(uint256 bribePaid);
    event ProfitReceiverUpdated(address indexed newReceiver);
    event SweepPreferenceUpdated(bool sweepToEth);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PauseStateUpdated(bool paused);
    event ProfitSettled(address indexed token, uint256 amount, address indexed receiver);
    event CallFailed(uint256 index, bytes reason);
    event ManualSweepExecuted(uint256 timestamp);
    event AavePoolStateUpdated(address indexed previousPool, address indexed newPool);
    event BalancerLoanSessionStateUpdated(bool active, bytes32 contextHash);
    event DydxSoloStateUpdated(address indexed previousSolo, address indexed newSolo);
    event MakerFlashLenderStateUpdated(address indexed previousLender, address indexed newLender);
    event UniswapV2PairStateUpdated(address indexed previousPair, address indexed newPair);
    event UniswapV3PoolStateUpdated(address indexed previousPool, address indexed newPool);
    event ProviderApprovalUpdated(address indexed provider, bool approved);

    error OnlyOwner();
    error OnlyPendingOwner();
    error ContractPaused();
    error ReentrantExecution();
    error PartialExecutionDisabled();
    error OnlyVault();
    error LengthMismatch();
    error ZeroAssets();
    error ExecutionFailed(uint256 index, bytes reason);
    error InsufficientFundsForRepayment(address token, uint256 required, uint256 available);
    error PrincipalNotReceived();
    error InvalidWETHAddress();
    error InvalidProfitReceiver();
    error InvalidOwner();
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
    error AaveLoanContextMismatch();
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
    error ProviderNotApproved();

    /// @notice Deploys the executor.
    /// @dev Sets immutable dependencies and initializes sweep configuration.
    /// @param _profitReceiver Receiver for token and ETH profit sweeps.
    /// @param _weth Wrapped native token address.
    /// @param _balancerVault Balancer vault address used for callbacks.
    constructor(address _profitReceiver, address _weth, address _balancerVault) {
        if (_profitReceiver == address(0) || _profitReceiver == address(this)) revert InvalidProfitReceiver();
        if (_weth == address(0) || _weth.code.length == 0) revert InvalidWETHAddress();
        if (_balancerVault == address(0) || _balancerVault.code.length == 0) revert InvalidBalancerVault();

        owner = msg.sender;
        profitReceiver = _profitReceiver;
        WETH = _weth;
        balancerVault = _balancerVault;
        approvedProviders[_balancerVault] = true;
        sweepProfitToEth = true;
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

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier nonReentrantInitiation() {
        if (executionActive) revert ReentrantExecution();
        executionActive = true;
        _;
        executionActive = false;
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
    ) external payable onlyOwner whenNotPaused nonReentrantInitiation {
        if (targets.length != payloads.length || targets.length != values.length) {
            revert LengthMismatch();
        }
        if (targets.length == 0) revert LengthMismatch();
        if (allowPartial) revert PartialExecutionDisabled();

        uint256 tokenBalanceBefore =
            balanceCheckToken == address(0) ? 0 : IERC20(balanceCheckToken).balanceOf(address(this));
        uint256 wethBalanceBefore = IERC20(WETH).balanceOf(address(this));
        uint256 ethBalanceBefore = address(this).balance;

        _executeDirectCalls(targets, payloads, values);
        _payBribe(bribeRecipient, bribeAmount);

        if (balanceCheckToken != address(0)) {
            uint256 tokenBalanceAfter = IERC20(balanceCheckToken).balanceOf(address(this));
            if (tokenBalanceAfter < tokenBalanceBefore) {
                revert BalanceInvariantBroken(balanceCheckToken, tokenBalanceBefore, tokenBalanceAfter);
            }
        }

        _settleDirectProfit(wethBalanceBefore, ethBalanceBefore);
    }

    /// @notice Starts a Balancer flash loan session.
    /// @dev Stores a single-use context hash that must match callback parameters.
    /// @param assets Sorted borrowed token list.
    /// @param amounts Borrowed amount list, each strictly positive.
    /// @param params ABI-encoded execution payload forwarded to callback.
    function executeFlashLoan(IERC20[] calldata assets, uint256[] calldata amounts, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(balancerVault);
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
        delete balancerPreLoanBalances;
        for (uint256 i = 0; i < assets.length; i++) {
            balancerPreLoanBalances.push(assets[i].balanceOf(address(this)));
        }
        emit BalancerLoanSessionStateUpdated(true, balancerLoanContextHash);

        IBalancerVault(balancerVault).flashLoan(address(this), assets, amounts, params);

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
    function executeAaveFlashLoanSimple(address pool, address asset, uint256 amount, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(pool);
        if (pool == address(0)) revert InvalidPool();
        if (pool.code.length == 0) revert InvalidPool();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();
        address previousPool = activeAavePool;
        activeAavePool = pool;
        aavePreLoanBalance = IERC20(asset).balanceOf(address(this));
        aaveLoanContextHash = keccak256(abi.encode(pool, asset, amount, params));
        emit AavePoolStateUpdated(previousPool, pool);
        IAavePool(pool).flashLoanSimple(address(this), asset, amount, params, 0);
        if (activeAavePool != address(0) || aaveLoanContextHash != bytes32(0)) revert AaveCallbackNotReceived();
        _resetAllowance(asset, pool);
    }

    /// @notice Starts a dYdX Solo flash loan session.
    /// @param soloMargin dYdX SoloMargin contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeDydxFlashLoan(address soloMargin, address asset, uint256 amount, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(soloMargin);
        if (soloMargin == address(0) || soloMargin.code.length == 0) revert InvalidFlashloanSolo();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        uint256 marketId = _dydxFindMarketId(soloMargin, asset);
        uint256 amountOwing = amount + 2;
        bytes memory callbackData = abi.encode(asset, amount, params);

        address previousSolo = activeDydxSolo;
        activeDydxSolo = soloMargin;
        dydxPreLoanBalance = IERC20(asset).balanceOf(address(this));
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
        _resetAllowance(asset, soloMargin);
    }

    /// @notice Starts a MakerDAO ERC3156 flash loan session.
    /// @param lender ERC3156 lender contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeMakerFlashLoan(address lender, address asset, uint256 amount, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(lender);
        if (lender == address(0) || lender.code.length == 0) revert InvalidFlashloanLender();
        if (asset == address(0)) revert InvalidAsset();
        if (amount == 0) revert ZeroAssets();

        address previousLender = activeMakerLender;
        activeMakerLender = lender;
        makerPreLoanBalance = IERC20(asset).balanceOf(address(this));
        makerLoanContextHash = keccak256(abi.encode(lender, asset, amount, params));
        emit MakerFlashLenderStateUpdated(previousLender, lender);

        bool ok = IERC3156FlashLender(lender).flashLoan(address(this), asset, amount, params);
        if (!ok) revert MakerCallbackNotReceived();
        if (activeMakerLender != address(0) || makerLoanContextHash != bytes32(0)) {
            revert MakerCallbackNotReceived();
        }
        _resetAllowance(asset, lender);
    }

    /// @notice Starts a Uniswap V2 flash swap session for a single borrowed token.
    /// @param pair Uniswap V2 pair contract.
    /// @param asset Borrowed token (must equal pair token0 or token1).
    /// @param amount Borrowed amount.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    function executeUniswapV2FlashLoan(address pair, address asset, uint256 amount, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(pair);
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
        uniswapV2PreLoanBalance = IERC20(asset).balanceOf(address(this));
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
    function executeUniswapV3FlashLoan(address pool, address asset, uint256 amount, bytes calldata params)
        external
        onlyOwner
        whenNotPaused
        nonReentrantInitiation
    {
        _requireApprovedProvider(pool);
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
        uniswapV3PreLoanBalance = IERC20(asset).balanceOf(address(this));
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
        if (msg.sender != balancerVault) revert OnlyVault();
        if (!balancerLoanActive) revert BalancerLoanNotActive();

        bytes32 callbackContext = keccak256(abi.encode(tokens, amounts, userData));
        if (callbackContext != balancerLoanContextHash) revert BalancerLoanContextMismatch();

        balancerLoanActive = false;
        balancerLoanContextHash = bytes32(0);
        emit BalancerLoanSessionStateUpdated(false, bytes32(0));

        if (tokens.length != amounts.length || tokens.length != feeAmounts.length) {
            revert LengthMismatch();
        }

        uint256[] memory preExistingBalances = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 callbackBalance = tokens[i].balanceOf(address(this));
            uint256 preLoan = balancerPreLoanBalances[i];
            if (callbackBalance < preLoan + amounts[i]) {
                revert PrincipalNotReceived();
            }
            preExistingBalances[i] = callbackBalance - amounts[i];
        }
        delete balancerPreLoanBalances;
        _executePayloadFromMemory(userData);
        _settleBalancerRepayment(tokens, amounts, feeAmounts, preExistingBalances);
    }

    /// @notice Aave V3 simple flash loan callback that executes payload calls and approves repayment.
    /// @dev Reverts unless caller is the active pool and initiator is this contract.
    /// @param asset Borrowed token.
    /// @param amount Borrowed principal amount.
    /// @param premium Fee owed to the pool.
    /// @param initiator Flash loan initiator expected to be this contract.
    /// @param params ABI-encoded payload containing `(targets, values, payloads)`.
    /// @return True when callback processing completes.
    function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata params)
        external
        override
        returns (bool)
    {
        if (msg.sender != activeAavePool) revert OnlyPool();
        if (initiator != address(this)) revert OnlyOwner();
        if (aaveLoanContextHash != keccak256(abi.encode(msg.sender, asset, amount, params))) revert AaveLoanContextMismatch();

        address previousPool = activeAavePool;
        activeAavePool = address(0);
        aaveLoanContextHash = bytes32(0);
        emit AavePoolStateUpdated(previousPool, address(0));

        uint256 callbackBalance = IERC20(asset).balanceOf(address(this));
        if (callbackBalance < aavePreLoanBalance + amount) {
            revert PrincipalNotReceived();
        }
        aavePreLoanBalance = 0;
        uint256 preExistingBalance = callbackBalance - amount;
        _executePayloadFromCalldata(params);

        uint256 amountOwing = amount + premium;
        uint256 bal = IERC20(asset).balanceOf(address(this));
        uint256 requiredBalance = preExistingBalance + amountOwing;
        if (bal < requiredBalance) {
            revert InsufficientFundsForRepayment(asset, requiredBalance, bal);
        }

        uint256 currentAllowance = IERC20(asset).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(asset, msg.sender, 0);
            }
            _lowLevelApprove(asset, msg.sender, amountOwing);
        }

        _settleProfit(asset, bal - requiredBalance);
        return true;
    }

    /// @notice dYdX callback that executes payload calls and sets token approval for repayment.
    /// @param sender Original sender passed by SoloMargin.
    /// @param accountInfo dYdX account metadata.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function callFunction(address sender, IDydxSoloMargin.AccountInfo calldata accountInfo, bytes calldata data)
        external
        override
    {
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

        uint256 callbackBalance = IERC20(asset).balanceOf(address(this));
        if (callbackBalance < dydxPreLoanBalance + amount) {
            revert PrincipalNotReceived();
        }
        dydxPreLoanBalance = 0;
        uint256 preExistingBalance = callbackBalance - amount;
        _executePayloadFromMemory(params);

        uint256 amountOwing = amount + 2;
        uint256 bal = IERC20(asset).balanceOf(address(this));
        uint256 requiredBalance = preExistingBalance + amountOwing;
        if (bal < requiredBalance) {
            revert InsufficientFundsForRepayment(asset, requiredBalance, bal);
        }

        uint256 currentAllowance = IERC20(asset).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(asset, msg.sender, 0);
            }
            _lowLevelApprove(asset, msg.sender, amountOwing);
        }

        _settleProfit(asset, bal - requiredBalance);
    }

    /// @notice ERC3156 flash loan callback used by MakerDAO flash lender.
    /// @param initiator Flash loan initiator expected to be this contract.
    /// @param token Borrowed token.
    /// @param amount Borrowed amount.
    /// @param fee Flash loan fee.
    /// @param data ABI-encoded payload containing `(targets, values, payloads)`.
    /// @return Callback success selector hash required by ERC3156.
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        override
        returns (bytes32)
    {
        if (msg.sender != activeMakerLender) revert OnlyMakerFlashLender();
        if (activeMakerLender == address(0)) revert MakerLoanNotActive();
        if (initiator != address(this)) revert OnlyOwner();

        bytes32 callbackContext = keccak256(abi.encode(msg.sender, token, amount, data));
        if (callbackContext != makerLoanContextHash) revert MakerLoanContextMismatch();

        address previousLender = activeMakerLender;
        activeMakerLender = address(0);
        makerLoanContextHash = bytes32(0);
        emit MakerFlashLenderStateUpdated(previousLender, address(0));

        uint256 callbackBalance = IERC20(token).balanceOf(address(this));
        if (callbackBalance < makerPreLoanBalance + amount) {
            revert PrincipalNotReceived();
        }
        makerPreLoanBalance = 0;
        uint256 preExistingBalance = callbackBalance - amount;
        _executePayloadFromCalldata(data);

        uint256 amountOwing = amount + fee;
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 requiredBalance = preExistingBalance + amountOwing;
        if (bal < requiredBalance) {
            revert InsufficientFundsForRepayment(token, requiredBalance, bal);
        }

        uint256 currentAllowance = IERC20(token).allowance(address(this), msg.sender);
        if (currentAllowance != amountOwing) {
            if (currentAllowance != 0) {
                _lowLevelApprove(token, msg.sender, 0);
            }
            _lowLevelApprove(token, msg.sender, amountOwing);
        }

        _settleProfit(token, bal - requiredBalance);
        return ERC3156_CALLBACK_SUCCESS;
    }

    /// @notice Uniswap V2 flash swap callback.
    /// @param sender Swap caller expected to be this contract.
    /// @param amount0 Borrowed token0 amount.
    /// @param amount1 Borrowed token1 amount.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external override {
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

        uint256 callbackBalance = IERC20(asset).balanceOf(address(this));
        if (callbackBalance < uniswapV2PreLoanBalance + amount) {
            revert PrincipalNotReceived();
        }
        uniswapV2PreLoanBalance = 0;
        uint256 preExistingBalance = callbackBalance - amount;
        _executePayloadFromMemory(params);

        uint256 amountOwing = _uniswapV2RepaymentAmount(amount);
        uint256 bal = IERC20(asset).balanceOf(address(this));
        uint256 requiredBalance = preExistingBalance + amountOwing;
        if (bal < requiredBalance) {
            revert InsufficientFundsForRepayment(asset, requiredBalance, bal);
        }

        _settleProfit(asset, bal - requiredBalance);
        _safeTransfer(asset, msg.sender, amountOwing);
    }

    /// @notice Uniswap V3 flash callback.
    /// @param fee0 Fee owed in token0.
    /// @param fee1 Fee owed in token1.
    /// @param data ABI-encoded payload `(asset, amount, params)`.
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external override {
        if (msg.sender != activeUniswapV3Pool) revert OnlyUniswapV3Pool();
        if (activeUniswapV3Pool == address(0)) revert UniswapV3LoanNotActive();

        (address asset, uint256 amount, bytes memory params) = abi.decode(data, (address, uint256, bytes));
        bytes32 callbackContext = keccak256(abi.encode(msg.sender, asset, amount, params));
        if (callbackContext != uniswapV3LoanContextHash) revert UniswapV3LoanContextMismatch();

        address previousPool = activeUniswapV3Pool;
        activeUniswapV3Pool = address(0);
        uniswapV3LoanContextHash = bytes32(0);
        emit UniswapV3PoolStateUpdated(previousPool, address(0));

        uint256 callbackBalance = IERC20(asset).balanceOf(address(this));
        if (callbackBalance < uniswapV3PreLoanBalance + amount) {
            revert PrincipalNotReceived();
        }
        uniswapV3PreLoanBalance = 0;
        uint256 preExistingBalance = callbackBalance - amount;
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
        uint256 requiredBalance = preExistingBalance + amountOwing;
        if (bal < requiredBalance) {
            revert InsufficientFundsForRepayment(asset, requiredBalance, bal);
        }

        _settleProfit(asset, bal - requiredBalance);
        _safeTransfer(asset, msg.sender, amountOwing);
    }

    /// @notice Updates the configured profit receiver.
    /// @param newReceiver New receiver address for sweep transfers.
    function setProfitReceiver(address newReceiver) external onlyOwner {
        if (newReceiver == address(0) || newReceiver == address(this)) revert InvalidProfitReceiver();
        profitReceiver = newReceiver;
        emit ProfitReceiverUpdated(newReceiver);
    }

    /// @notice Sets whether token profits should be converted from WETH into native ETH before sweep.
    /// @param sweepToEth True to unwrap WETH profits before ETH transfer; false to keep token form.
    function setSweepPreference(bool sweepToEth) external onlyOwner {
        sweepProfitToEth = sweepToEth;
        emit SweepPreferenceUpdated(sweepToEth);
    }

    function setPaused(bool newPaused) external onlyOwner {
        paused = newPaused;
        emit PauseStateUpdated(newPaused);
    }

    /// @notice Updates approval state for a flash loan provider.
    /// @param provider Provider address to approve or revoke.
    /// @param approved True to approve; false to revoke.
    function setApprovedProvider(address provider, bool approved) external onlyOwner {
        if (provider == address(0) || provider == address(this) || provider.code.length == 0) revert InvalidPool();
        approvedProviders[provider] = approved;
        emit ProviderApprovalUpdated(provider, approved);
    }

    function _requireApprovedProvider(address provider) internal view {
        if (!approvedProviders[provider]) {
            revert ProviderNotApproved();
        }
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0) || newOwner == address(this)) revert InvalidOwner();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        pendingOwner = address(0);
        emit OwnershipTransferStarted(owner, address(0));
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert OnlyPendingOwner();
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Manually sweeps the full token balance to `profitReceiver`.
    /// @param token ERC20 token address to sweep.
    function sweepToken(address token) external onlyOwner {
        address cachedProfitReceiver = profitReceiver;
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal == 0) return;
        _safeTransfer(token, cachedProfitReceiver, bal);
        emit ManualSweepExecuted(block.timestamp);
    }

    /// @notice Manually sweeps the full native ETH balance to `profitReceiver`.
    function sweepETH() external onlyOwner {
        address cachedProfitReceiver = profitReceiver;
        uint256 balance = address(this).balance;
        if (balance > 0) {
            _transferEthAmount(cachedProfitReceiver, balance, true);
            emit ManualSweepExecuted(block.timestamp);
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

    function _executeDirectCalls(address[] calldata targets, bytes[] calldata payloads, uint256[] calldata values)
        internal
    {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(payloads[i]);
            if (!success) {
                _revertWithDetails(i, result);
            }
        }
    }

    function _payBribe(address recipient, uint256 amount) internal {
        if (amount == 0) return;
        if (address(this).balance < amount) revert BribeFailed();
        address actualRecipient = recipient == address(0) ? block.coinbase : recipient;
        (bool ok,) = actualRecipient.call{value: amount}("");
        if (!ok) revert BribeFailed();
        emit BundleExecuted(amount);
    }

    function _settleDirectProfit(uint256 wethBalanceBefore, uint256 ethBalanceBefore) internal {
        uint256 wethBalanceAfter = IERC20(WETH).balanceOf(address(this));
        uint256 ethBalanceAfter = address(this).balance;

        uint256 capitalBefore = wethBalanceBefore + ethBalanceBefore;
        uint256 capitalAfter = wethBalanceAfter + ethBalanceAfter;

        if (capitalAfter < capitalBefore) {
            revert BalanceInvariantBroken(WETH, capitalBefore, capitalAfter);
        }

        uint256 profit = capitalAfter - capitalBefore;
        if (profit == 0) return;

        if (sweepProfitToEth) {
            uint256 ethAvailable = address(this).balance;
            if (ethAvailable < profit) {
                IWETH(WETH).withdraw(profit - ethAvailable);
            }
            _transferEthAmount(profitReceiver, profit, true);
            emit ProfitSettled(address(0), profit, profitReceiver);
        } else {
            uint256 wethAvailable = IERC20(WETH).balanceOf(address(this));
            if (wethAvailable < profit) {
                IWETH(WETH).deposit{value: profit - wethAvailable}();
            }
            _safeTransfer(WETH, profitReceiver, profit);
            emit ArbitrageExecuted(profit, WETH);
            emit ProfitSettled(WETH, profit, profitReceiver);
        }
    }

    /// @notice Executes target calls with per-call ETH values.
    /// @param targets Ordered call targets.
    /// @param values ETH value for each call.
    /// @param payloads Calldata for each target.
    function _executeTargets(address[] memory targets, uint256[] memory values, bytes[] memory payloads) internal {
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

    /// @notice Settles Balancer repayment without consuming pre-existing executor balances.
    /// @param tokens Borrowed tokens.
    /// @param amounts Borrowed principal amounts.
    /// @param feeAmounts Fee amounts owed per token.
    function _settleBalancerRepayment(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        uint256[] memory preExistingBalances
    ) internal {
        uint256 tokensLen = tokens.length;

        for (uint256 i = 0; i < tokensLen; i++) {
            uint256 amountOwing = amounts[i] + feeAmounts[i];
            if (amountOwing == 0) continue;

            address tokenAddr = address(tokens[i]);
            uint256 myBalance = IERC20(tokenAddr).balanceOf(address(this));
            uint256 requiredBalance = preExistingBalances[i] + amountOwing;
            if (myBalance < requiredBalance) {
                revert InsufficientFundsForRepayment(tokenAddr, requiredBalance, myBalance);
            }
            uint256 profit = myBalance - requiredBalance;
            _safeTransfer(tokenAddr, balancerVault, amountOwing);
            _settleProfit(tokenAddr, profit);
        }
    }

    function _settleProfit(address asset, uint256 profit) internal {
        if (profit == 0) return;
        _distributeProfit(asset, profit, profitReceiver, sweepProfitToEth);
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
    function _dydxAssetAmount(bool sign, uint256 value) internal pure returns (IDydxSoloMargin.AssetAmount memory) {
        return IDydxSoloMargin.AssetAmount({
            sign: sign, denomination: DYDX_ASSET_DENOMINATION_WEI, ref: DYDX_ASSET_REFERENCE_DELTA, value: value
        });
    }

    /// @notice Builds a dYdX withdraw action.
    /// @param marketId Market id.
    /// @param amount Amount to withdraw.
    /// @return ActionArgs for SoloMargin.
    function _dydxWithdrawAction(uint256 marketId, uint256 amount)
        internal
        view
        returns (IDydxSoloMargin.ActionArgs memory)
    {
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
    function _dydxDepositAction(uint256 marketId, uint256 amount)
        internal
        view
        returns (IDydxSoloMargin.ActionArgs memory)
    {
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
    /// @param tokenAddr Token from which profit is distributed.
    /// @param profit Profit amount.
    /// @param receiver Profit receiver.
    /// @param sweepToEth Whether WETH profits should be unwrapped into ETH.
    function _distributeProfit(address tokenAddr, uint256 profit, address receiver, bool sweepToEth) internal {
        if (tokenAddr == WETH && sweepToEth) {
            IWETH(WETH).withdraw(profit);
            _transferEthAmount(receiver, profit, true);
            emit ProfitSettled(tokenAddr, profit, receiver);
            return;
        }
        _safeTransfer(tokenAddr, receiver, profit);
        emit ArbitrageExecuted(profit, tokenAddr);
        emit ProfitSettled(tokenAddr, profit, receiver);
    }

    function _transferEthAmount(address receiver, uint256 amount, bool revertOnFailure) internal {
        if (amount == 0) return;
        (bool success,) = receiver.call{value: amount}("");
        if (!success) {
            if (revertOnFailure) revert TokenTransferFailed();
        }
    }

    /// @notice Performs a low-level ERC20 approve call with bytecode check.
    /// @param token ERC20 token.
    /// @param spender Allowance spender.
    /// @param amount Allowance value.
    function _lowLevelApprove(address token, address spender, uint256 amount) internal {
        if (token.code.length == 0) revert InvalidAsset();
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, spender, amount));
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert ApprovalFailed();
        }
    }

    function _resetAllowance(address token, address spender) internal {
        if (IERC20(token).allowance(address(this), spender) != 0) {
            _lowLevelApprove(token, spender, 0);
        }
    }

    /// @notice Performs a low-level ERC20 transfer call with bytecode check.
    /// @param token ERC20 token.
    /// @param to Transfer recipient.
    /// @param value Transfer amount.
    function _safeTransfer(address token, address to, uint256 value) internal {
        if (token.code.length == 0) revert InvalidAsset();
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
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
