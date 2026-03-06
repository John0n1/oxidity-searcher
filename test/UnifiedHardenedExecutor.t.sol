// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../data/UnifiedHardenedExecutor.sol";

interface Vm {
    function assume(bool condition) external;
    function deal(address account, uint256 newBalance) external;
    function expectRevert(bytes4 revertData) external;
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
}

address constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

abstract contract FoundryTest {
    Vm internal constant vm = Vm(HEVM_ADDRESS);

    function _assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }

    function _assertEq(uint256 left, uint256 right, string memory message) internal pure {
        require(left == right, message);
    }

    function _assertEq(address left, address right, string memory message) internal pure {
        require(left == right, message);
    }

    function _assertEq(bool left, bool right, string memory message) internal pure {
        require(left == right, message);
    }
}

contract ResetApprovalToken is IERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals = 18;
    bool public immutable forceZeroReset;
    uint256 public approveCallCount;

    mapping(address => uint256) internal balances;
    mapping(address => mapping(address => uint256)) internal allowances;
    mapping(uint256 => uint256) public approveValues;

    constructor(string memory tokenName, string memory tokenSymbol, bool requireZeroReset) {
        name = tokenName;
        symbol = tokenSymbol;
        forceZeroReset = requireZeroReset;
    }

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }

    function allowance(address owner, address spender) external view override returns (uint256) {
        return allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        if (forceZeroReset && allowances[msg.sender][spender] != 0 && amount != 0) {
            revert("RESET_REQUIRED");
        }
        allowances[msg.sender][spender] = amount;
        approveCallCount += 1;
        approveValues[approveCallCount] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowances[from][msg.sender];
        require(currentAllowance >= amount, "ALLOWANCE");
        allowances[from][msg.sender] = currentAllowance - amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}

contract MockWETH is ResetApprovalToken, IWETH {
    constructor() ResetApprovalToken("Wrapped Ether", "WETH", false) {}

    function deposit() external payable override {
        mint(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external override {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

contract MockBalancerVault is IBalancerVault {
    function flashLoan(
        address recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external {
        uint256[] memory balancesBefore = new uint256[](tokens.length);
        uint256[] memory feeAmounts = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            balancesBefore[i] = tokens[i].balanceOf(address(this));
            ResetApprovalToken(address(tokens[i])).transfer(recipient, amounts[i]);
        }

        IFlashLoanRecipient(recipient).receiveFlashLoan(tokens, amounts, feeAmounts, userData);

        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 balanceAfter = tokens[i].balanceOf(address(this));
            require(balanceAfter >= balancesBefore[i], "BALANCER_NOT_REPAID");
        }
    }
}

contract CorruptingBalancerVault is IBalancerVault {
    function flashLoan(
        address recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external {
        uint256[] memory feeAmounts = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            ResetApprovalToken(address(tokens[i])).transfer(recipient, amounts[i]);
        }

        IFlashLoanRecipient(recipient).receiveFlashLoan(
            tokens, amounts, feeAmounts, abi.encodePacked(userData, bytes1(0x01))
        );
    }
}

contract MockAavePool is IAavePool {
    uint256 public immutable premium;
    uint256 public lastPulled;

    constructor(uint256 premium_) {
        premium = premium_;
    }

    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16
    ) external override {
        ResetApprovalToken token = ResetApprovalToken(asset);
        token.transfer(receiverAddress, amount + premium);
        bool ok = IAaveFlashLoanSimpleReceiver(receiverAddress).executeOperation(
            asset, amount, premium, receiverAddress, params
        );
        require(ok, "AAVE_CALLBACK_FAILED");
        token.transferFrom(receiverAddress, address(this), amount + premium);
        lastPulled = amount + premium;
    }
}

contract ExecutorHandler is FoundryTest {
    UnifiedHardenedExecutor public executor;
    ResetApprovalToken public token;
    MockWETH public weth;
    MockBalancerVault public vault;
    address public constant APPROVER = address(0xA550);
    address public profitReceiver;

    constructor() {
        token = new ResetApprovalToken("Invariant Token", "IVT", true);
        weth = new MockWETH();
        vault = new MockBalancerVault();
        profitReceiver = address(0xCAFE);
        executor = new UnifiedHardenedExecutor(profitReceiver, address(weth), address(vault));
    }

    function setProfitReceiver(uint160 raw) external {
        uint160 base = uint160(0x1000000000000000000000000000000000000000);
        uint160 sanitized = raw | base;
        address next = raw == 0
            ? address(base + uint160(0xcafe))
            : address(sanitized);
        executor.setProfitReceiver(next);
        profitReceiver = next;
    }

    function setSweepPreference(bool sweepToEth) external {
        executor.setSweepPreference(sweepToEth);
    }

    function safeApproveAmount(uint96 amount) external {
        executor.safeApprove(address(token), APPROVER, uint256(amount % 1_000_000 ether));
    }

    function fundAndSweepToken(uint96 amount) external {
        uint256 boundedAmount = uint256(amount % 1_000 ether);
        if (boundedAmount == 0) {
            return;
        }
        token.mint(address(executor), boundedAmount);
        executor.sweepToken(address(token));
    }

    function fundAndSweepEth(uint96 amount) external {
        uint256 boundedAmount = uint256(amount % 1_000 ether);
        if (boundedAmount == 0) {
            return;
        }
        vm.deal(address(executor), boundedAmount);
        executor.sweepETH();
    }

    function advanceTime(uint32 deltaSeconds) external {
        vm.warp(block.timestamp + uint256(deltaSeconds % 30 days) + 1);
    }
}

contract UnifiedHardenedExecutorUnitTest is FoundryTest {
    address internal constant OUTSIDER = address(0xBEEF);
    address internal constant SPENDER = address(0x9001);
    address internal constant PROFIT_RECEIVER = address(0xCAFE);

    ResetApprovalToken internal token;
    MockWETH internal weth;
    MockBalancerVault internal balancerVault;
    UnifiedHardenedExecutor internal executor;

    function setUp() public {
        token = new ResetApprovalToken("Mock Token", "MOCK", true);
        weth = new MockWETH();
        balancerVault = new MockBalancerVault();
        executor = new UnifiedHardenedExecutor(
            PROFIT_RECEIVER, address(weth), address(balancerVault)
        );
    }

    function test_only_owner_guards_privileged_entrypoints() public {
        address[] memory targets = new address[](1);
        targets[0] = address(token);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = "";
        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        vm.prank(OUTSIDER);
        vm.expectRevert(UnifiedHardenedExecutor.OnlyOwner.selector);
        executor.executeBundle(targets, payloads, values, address(0), 0, false, address(0));

        vm.prank(OUTSIDER);
        vm.expectRevert(UnifiedHardenedExecutor.OnlyOwner.selector);
        executor.sweepETH();

        vm.prank(OUTSIDER);
        vm.expectRevert(UnifiedHardenedExecutor.OnlyOwner.selector);
        executor.safeApprove(address(token), SPENDER, 1);
    }

    function test_safe_approve_zero_resets_before_new_allowance() public {
        executor.safeApprove(address(token), SPENDER, 5);
        executor.safeApprove(address(token), SPENDER, 7);

        _assertEq(token.approveCallCount(), 3, "expected zero-reset approve sequence");
        _assertEq(token.approveValues(1), 5, "first approval should set requested amount");
        _assertEq(token.approveValues(2), 0, "second approval should reset to zero");
        _assertEq(token.approveValues(3), 7, "third approval should set new amount");
    }

    function test_balancer_flashloan_round_trip_repay_and_reset() public {
        token.mint(address(balancerVault), 100 ether);

        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(token));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;
        bytes memory params = abi.encode(new address[](0), new uint256[](0), new bytes[](0));

        executor.executeFlashLoan(assets, amounts, params);

        _assertEq(
            token.balanceOf(address(balancerVault)),
            100 ether,
            "vault balance should be fully repaid"
        );

        vm.prank(address(balancerVault));
        vm.expectRevert(UnifiedHardenedExecutor.BalancerLoanNotActive.selector);
        executor.receiveFlashLoan(assets, amounts, new uint256[](1), params);
    }

    function test_balancer_callback_rejects_context_mismatch() public {
        CorruptingBalancerVault badVault = new CorruptingBalancerVault();
        UnifiedHardenedExecutor badExecutor =
            new UnifiedHardenedExecutor(PROFIT_RECEIVER, address(weth), address(badVault));
        token.mint(address(badVault), 100 ether);

        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(token));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        bytes memory params = abi.encode(new address[](0), new uint256[](0), new bytes[](0));

        vm.expectRevert(UnifiedHardenedExecutor.BalancerLoanContextMismatch.selector);
        badExecutor.executeFlashLoan(assets, amounts, params);
    }

    function test_aave_flashloan_approves_exact_repayment_and_pool_pulls_funds() public {
        MockAavePool pool = new MockAavePool(1 ether);
        token.mint(address(pool), 100 ether);

        executor.executeAaveFlashLoanSimple(
            address(pool),
            address(token),
            10 ether,
            abi.encode(new address[](0), new uint256[](0), new bytes[](0))
        );

        _assertEq(pool.lastPulled(), 11 ether, "pool should pull exact repayment");
        _assertEq(
            token.balanceOf(address(pool)),
            100 ether,
            "pool balance should be restored after callback"
        );
    }

    function test_aave_callback_rejects_unauthorized_callers() public {
        vm.expectRevert(UnifiedHardenedExecutor.OnlyPool.selector);
        executor.executeOperation(address(token), 1, 0, address(executor), bytes(""));
    }

    function test_manual_sweeps_reset_timer_and_clear_due_state() public {
        vm.warp(block.timestamp + executor.AUTO_SWEEP_INTERVAL() + 1);
        token.mint(address(executor), 3 ether);
        vm.deal(address(executor), 2 ether);

        executor.sweepToken(address(token));
        _assertEq(executor.lastSweepAt(), block.timestamp, "token sweep should reset timer");
        _assertEq(executor.autoSweepDue(), false, "token sweep should clear due state");

        vm.warp(block.timestamp + executor.AUTO_SWEEP_INTERVAL() + 1);
        vm.deal(address(executor), 1 ether);
        executor.sweepETH();
        _assertEq(executor.lastSweepAt(), block.timestamp, "eth sweep should reset timer");
        _assertEq(executor.autoSweepDue(), false, "eth sweep should clear due state");
    }

    function testFuzz_safeApprove_preserves_zero_reset_semantics(
        uint96 firstAmount,
        uint96 secondAmount
    ) public {
        vm.assume(firstAmount > 0);
        vm.assume(secondAmount > 0);
        vm.assume(firstAmount != secondAmount);

        executor.safeApprove(address(token), SPENDER, uint256(firstAmount));
        executor.safeApprove(address(token), SPENDER, uint256(secondAmount));

        _assertEq(
            token.allowance(address(executor), SPENDER),
            uint256(secondAmount),
            "final allowance should match the second request"
        );
        _assertEq(token.approveValues(2), 0, "fuzzed approval should zero-reset first");
    }
}

contract UnifiedHardenedExecutorInvariantTest is FoundryTest {
    ExecutorHandler internal handler;

    function setUp() public {
        handler = new ExecutorHandler();
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function invariant_owner_stays_bound_to_handler() public view {
        _assertEq(handler.executor().owner(), address(handler), "owner should remain stable");
    }

    function invariant_profit_receiver_is_never_zero() public view {
        _assertTrue(
            handler.executor().profitReceiver() != address(0),
            "profit receiver should never become zero"
        );
    }

    function invariant_auto_sweep_schedule_matches_last_sweep() public view {
        UnifiedHardenedExecutor exec = handler.executor();
        bool due = block.timestamp >= exec.lastSweepAt() + exec.AUTO_SWEEP_INTERVAL();
        _assertEq(exec.autoSweepDue(), due, "autoSweepDue should reflect lastSweepAt");
    }
}
