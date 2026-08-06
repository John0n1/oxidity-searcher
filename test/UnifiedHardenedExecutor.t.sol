// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {
    UnifiedHardenedExecutor,
    IERC20,
    IFlashLoanRecipient,
    IAaveFlashLoanSimpleReceiver
} from "../data/UnifiedHardenedExecutor.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert() external;
}

contract MockToken {
    string public name = "Mock";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockWETH is MockToken {
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer");
    }

    receive() external payable {}
}

contract MockBalancerVault {
    uint256 public fee;

    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    function flashLoan(address recipient, IERC20[] memory tokens, uint256[] memory amounts, bytes memory userData)
        external
    {
        uint256[] memory fees = new uint256[](tokens.length);
        uint256[] memory balancesBefore = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            balancesBefore[i] = tokens[i].balanceOf(address(this));
            fees[i] = fee;
            require(MockToken(address(tokens[i])).transfer(recipient, amounts[i]), "lend");
        }
        IFlashLoanRecipient(recipient).receiveFlashLoan(tokens, amounts, fees, userData);
        for (uint256 i = 0; i < tokens.length; i++) {
            require(tokens[i].balanceOf(address(this)) >= balancesBefore[i] + fees[i], "not repaid");
        }
    }
}

contract MockRouter {
    function pull(address token, address from, uint256 amount) external {
        require(MockToken(token).transferFrom(from, address(this), amount), "pull");
    }
}

contract MockAavePool {
    MockToken public immutable token;
    uint256 public fee;

    constructor(MockToken token_) {
        token = token_;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    function flashLoanSimple(address receiver, address asset, uint256 amount, bytes calldata params, uint16) external {
        require(asset == address(token), "asset");
        token.mint(receiver, amount);
        require(
            IAaveFlashLoanSimpleReceiver(receiver).executeOperation(asset, amount, fee, receiver, params), "callback"
        );
        require(token.transferFrom(receiver, address(this), amount + fee), "repay");
    }
}

contract RejectEth {
    receive() external payable {
        revert("reject");
    }
}

contract ExecutorActor {
    function setPaused(UnifiedHardenedExecutor executor, bool value) external {
        executor.setPaused(value);
    }

    function acceptOwnership(UnifiedHardenedExecutor executor) external {
        executor.acceptOwnership();
    }
}

contract UnifiedHardenedExecutorTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockWETH private weth;
    MockBalancerVault private vault;
    UnifiedHardenedExecutor private executor;

    receive() external payable {}

    function setUp() public {
        weth = new MockWETH();
        vault = new MockBalancerVault();
        executor = new UnifiedHardenedExecutor(address(this), address(weth), address(vault));
        executor.setSweepPreference(false);
        vm.deal(address(this), 100 ether);
    }

    function testConstructorAndAdministrativeState() public view {
        require(executor.owner() == address(this), "owner");
        require(executor.WETH() == address(weth), "weth");
        require(executor.balancerVault() == address(vault), "vault");
        require(executor.profitReceiver() == address(this), "receiver");
        require(!executor.paused(), "paused");
    }

    function testPauseBlocksExecutionAndUnauthorizedPause() public {
        ExecutorActor actor = new ExecutorActor();
        (bool unauthorized,) = address(actor).call(abi.encodeCall(ExecutorActor.setPaused, (executor, true)));
        require(!unauthorized, "unauthorized pause succeeded");

        executor.setPaused(true);
        address[] memory targets = new address[](1);
        targets[0] = address(weth);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockWETH.deposit, ());
        uint256[] memory values = new uint256[](1);
        (bool ok,) = address(executor)
            .call(
                abi.encodeCall(
                    UnifiedHardenedExecutor.executeBundle, (targets, payloads, values, address(0), 0, false, address(0))
                )
            );
        require(!ok, "paused execution succeeded");
    }

    function testTwoStepOwnershipTransfer() public {
        ExecutorActor actor = new ExecutorActor();
        executor.transferOwnership(address(actor));
        require(executor.owner() == address(this), "ownership changed early");
        require(executor.pendingOwner() == address(actor), "pending owner");
        actor.acceptOwnership(executor);
        require(executor.owner() == address(actor), "ownership not accepted");
        require(executor.pendingOwner() == address(0), "pending not cleared");
    }

    function testDirectExecutionSettlesOnlyCurrentWethDelta() public {
        weth.mint(address(executor), 5 ether);
        uint256 receiverBefore = weth.balanceOf(address(this));

        address[] memory targets = new address[](2);
        targets[0] = address(weth);
        targets[1] = address(weth);
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = abi.encodeCall(MockWETH.deposit, ());
        payloads[1] = abi.encodeCall(MockToken.mint, (address(executor), 0.1 ether));
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;

        executor.executeBundle{value: 1 ether}(targets, payloads, values, address(0), 0, false, address(weth));

        require(weth.balanceOf(address(executor)) == 6 ether, "dust changed");
        require(weth.balanceOf(address(this)) - receiverBefore == 0.1 ether, "wrong profit delta");
    }

    function testExactApprovalCanBeResetAtomically() public {
        MockToken token = new MockToken();
        MockRouter router = new MockRouter();
        token.mint(address(executor), 10 ether);

        address[] memory targets = new address[](3);
        targets[0] = address(executor);
        targets[1] = address(router);
        targets[2] = address(executor);
        bytes[] memory payloads = new bytes[](3);
        payloads[0] = abi.encodeCall(executor.safeApprove, (address(token), address(router), 3 ether));
        payloads[1] = abi.encodeCall(MockRouter.pull, (address(token), address(executor), 3 ether));
        payloads[2] = abi.encodeCall(executor.safeApprove, (address(token), address(router), 0));
        uint256[] memory values = new uint256[](3);

        executor.executeBundle(targets, payloads, values, address(0), 0, false, address(0));
        require(token.allowance(address(executor), address(router)) == 0, "allowance remains");
        require(token.balanceOf(address(router)) == 3 ether, "router did not pull");
    }

    function testBalancerProfitDoesNotIncludePreexistingBalance() public {
        MockToken token = new MockToken();
        token.mint(address(vault), 1_000 ether);
        token.mint(address(executor), 5 ether);
        vault.setFee(1 ether);

        address[] memory targets = new address[](1);
        targets[0] = address(token);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockToken.mint, (address(executor), 10 ether));

        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(token));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100 ether;
        uint256 receiverBefore = token.balanceOf(address(this));

        executor.executeFlashLoan(assets, amounts, abi.encode(targets, values, payloads));

        require(token.balanceOf(address(executor)) == 5 ether, "preexisting balance changed");
        require(token.balanceOf(address(this)) - receiverBefore == 9 ether, "wrong realized profit");
    }

    function testBalancerCannotUseDustToSubsidizeLoss() public {
        MockToken token = new MockToken();
        token.mint(address(vault), 1_000 ether);
        token.mint(address(executor), 5 ether);
        vault.setFee(1 ether);

        address[] memory targets = new address[](1);
        targets[0] = address(token);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockToken.mint, (address(executor), 0));
        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(token));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100 ether;

        (bool ok,) = address(executor)
            .call(
                abi.encodeCall(
                    UnifiedHardenedExecutor.executeFlashLoan, (assets, amounts, abi.encode(targets, values, payloads))
                )
            );
        require(!ok, "dust subsidized losing flash loan");
        require(token.balanceOf(address(executor)) == 5 ether, "revert changed dust");
    }

    function testAaveProfitPreservesDustAndClearsAllowance() public {
        MockToken token = new MockToken();
        MockAavePool pool = new MockAavePool(token);
        pool.setFee(1 ether);
        executor.setApprovedProvider(address(pool), true);
        token.mint(address(executor), 5 ether);

        address[] memory targets = new address[](1);
        targets[0] = address(token);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockToken.mint, (address(executor), 10 ether));
        uint256 receiverBefore = token.balanceOf(address(this));

        executor.executeAaveFlashLoanSimple(
            address(pool), address(token), 100 ether, abi.encode(targets, values, payloads)
        );

        require(token.balanceOf(address(executor)) == 5 ether, "preexisting balance changed");
        require(token.balanceOf(address(this)) - receiverBefore == 9 ether, "wrong realized profit");
        require(token.allowance(address(executor), address(pool)) == 0, "allowance remains");
    }

    function testUnauthorizedCallbacksFailClosed() public {
        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(weth));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        uint256[] memory fees = new uint256[](1);

        (bool balancerOk,) = address(executor)
            .call(abi.encodeCall(UnifiedHardenedExecutor.receiveFlashLoan, (assets, amounts, fees, bytes(""))));
        require(!balancerOk, "unauthorized Balancer callback succeeded");

        (bool aaveOk,) = address(executor)
            .call(
                abi.encodeCall(
                    UnifiedHardenedExecutor.executeOperation, (address(weth), 1 ether, 0, address(executor), bytes(""))
                )
            );
        require(!aaveOk, "unauthorized Aave callback succeeded");
    }

    function testRejectingProfitReceiverRevertsSettlement() public {
        RejectEth receiver = new RejectEth();
        executor.setProfitReceiver(address(receiver));
        executor.setSweepPreference(true);
        vm.deal(address(weth), 10 ether);

        address[] memory targets = new address[](1);
        targets[0] = address(weth);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockToken.mint, (address(executor), 1 ether));
        uint256[] memory values = new uint256[](1);

        vm.expectRevert();
        executor.executeBundle(targets, payloads, values, address(0), 0, false, address(weth));
    }

    function testFuzzBalancerPreservesDustAndSettlesExactDelta(
        uint96 dustSeed,
        uint96 amountSeed,
        uint96 feeSeed,
        uint96 profitSeed
    ) public {
        uint256 dust = uint256(dustSeed) % 1_000_000 ether;
        uint256 amount = 1 + (uint256(amountSeed) % 1_000_000 ether);
        uint256 fee = uint256(feeSeed) % 1_000 ether;
        uint256 profit = uint256(profitSeed) % 1_000_000 ether;
        MockToken token = new MockToken();
        token.mint(address(vault), amount);
        token.mint(address(executor), dust);
        vault.setFee(fee);

        address[] memory targets = new address[](1);
        targets[0] = address(token);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(MockToken.mint, (address(executor), fee + profit));
        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(address(token));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        uint256 receiverBefore = token.balanceOf(address(this));

        executor.executeFlashLoan(assets, amounts, abi.encode(targets, values, payloads));

        require(token.balanceOf(address(executor)) == dust, "dust invariant");
        require(token.balanceOf(address(this)) - receiverBefore == profit, "profit invariant");
        require(token.balanceOf(address(vault)) == amount + fee, "repayment invariant");
    }

    function testConstructorRejectsSelfProfitReceiver() public {
        address computedSelf = address(0x1234567890123456789012345678901234567890);
        vm.expectRevert(UnifiedHardenedExecutor.InvalidProfitReceiver.selector);
        new UnifiedHardenedExecutor(address(0), address(weth), address(vault));
    }

    function testDirectEthToWethDoesNotSweepPrincipal() public {
        vm.deal(address(executor), 10 ether);
        address[] memory targets = new address[](1);
        targets[0] = address(weth);
        uint256[] memory values = new uint256[](1);
        values[0] = 10 ether;
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeWithSignature("deposit()");

        uint256 receiverEthBefore = address(this).balance;
        uint256 receiverWethBefore = weth.balanceOf(address(this));

        executor.executeBundle(targets, payloads, values, address(0), 0, false, address(0));

        require(weth.balanceOf(address(executor)) == 10 ether, "executor holds weth");
        require(address(executor).balance == 0, "executor eth converted");
        require(address(this).balance == receiverEthBefore, "receiver eth unchanged");
        require(weth.balanceOf(address(this)) == receiverWethBefore, "receiver weth unchanged");
    }
}
