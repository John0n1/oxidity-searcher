// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {UnifiedHardenedExecutor, IERC20, IWETH} from "../data/UnifiedHardenedExecutor.sol";

interface ForkVm {
    function createSelectFork(string calldata rpcUrl, uint256 blockNumber) external returns (uint256);
    function deal(address account, uint256 newBalance) external;
    function envOr(string calldata name, string calldata defaultValue) external returns (string memory);
}

contract UnifiedHardenedExecutorForkTest {
    ForkVm private constant vm = ForkVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant MAINNET_WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address private constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    uint256 private constant PINNED_BLOCK = 25_662_000;

    UnifiedHardenedExecutor private executor;

    function setUp() public {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string("http://127.0.0.1:8545"));
        vm.createSelectFork(rpc, PINNED_BLOCK);
        executor = new UnifiedHardenedExecutor(address(this), MAINNET_WETH, BALANCER_VAULT);
        executor.setSweepPreference(false);
    }

    function testPinnedDependenciesAndDirectWethFlow() public {
        require(MAINNET_WETH.code.length > 0, "WETH code");
        require(BALANCER_VAULT.code.length > 0, "Vault code");

        address[] memory targets = new address[](1);
        targets[0] = MAINNET_WETH;
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(IWETH.deposit, ());
        uint256[] memory values = new uint256[](1);
        values[0] = 0.01 ether;
        uint256 beforeBalance = IERC20(MAINNET_WETH).balanceOf(address(this));

        executor.executeBundle{value: 0.01 ether}(targets, payloads, values, address(0), 0, false, MAINNET_WETH);

        require(IERC20(MAINNET_WETH).balanceOf(address(executor)) == 0.01 ether, "executor WETH preserved");
    }

    function testPinnedBalancerFlashCallbackAndRepayment() public {
        vm.deal(address(executor), 0.01 ether);
        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(MAINNET_WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0.01 ether;
        address[] memory targets = new address[](1);
        targets[0] = MAINNET_WETH;
        uint256[] memory values = new uint256[](1);
        values[0] = 0.01 ether;
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = abi.encodeCall(IWETH.deposit, ());
        uint256 beforeBalance = IERC20(MAINNET_WETH).balanceOf(address(this));

        executor.executeFlashLoan(assets, amounts, abi.encode(targets, values, payloads));

        require(IERC20(MAINNET_WETH).balanceOf(address(this)) - beforeBalance == 0.01 ether, "profit delta");
        require(IERC20(MAINNET_WETH).balanceOf(address(executor)) == 0, "executor token dust");
        require(address(executor).balance == 0, "executor ETH dust");
    }
}
