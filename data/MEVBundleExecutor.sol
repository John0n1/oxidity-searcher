// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MEVBundleExecutor
/// @notice Minimal atomic executor intended for MEV bundles.
/// Executes a series of calls and optionally sends a direct bribe to a recipient
/// (e.g. `block.coinbase`) so the whole sequence is atomic and self-contained.
contract MEVBundleExecutor {
    address public immutable owner;

    error NotOwner();
    error LengthMismatch();
    error CallFailed(uint256 index, bytes returndata);
    error BribeFailed();
    error ETHTransferFailed();
    error TokenTransferFailed();

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    /// @param targets Contracts to call.
    /// @param payloads Calldata for each target.
    /// @param values ETH value to forward to each call.
    /// @param bribeRecipient Recipient of the optional bribe (set to `block.coinbase` to tip the builder).
    /// @param bribeAmount Amount of ETH to send as bribe. Must be <= msg.value - sum(values).
    /// @return results Return data for each call.
    function execute(
        address[] calldata targets,
        bytes[] calldata payloads,
        uint256[] calldata values,
        address bribeRecipient,
        uint256 bribeAmount
    ) external payable returns (bytes[] memory results) {
        if (msg.sender != owner) revert NotOwner();
        if (targets.length != payloads.length || targets.length != values.length) {
            revert LengthMismatch();
        }

        results = new bytes[](targets.length);
        uint256 callsTotal;

        for (uint256 i = 0; i < targets.length; i++) {
            callsTotal += values[i];
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(payloads[i]);
            if (!ok) revert CallFailed(i, ret);
            results[i] = ret;
        }

        if (bribeAmount > 0) {
            if (callsTotal + bribeAmount > msg.value) revert BribeFailed();
            (bool ok, ) = bribeRecipient.call{value: bribeAmount}("");
            if (!ok) revert BribeFailed();
        } else if (callsTotal < msg.value) {
            // Refund dust to owner to avoid stuck funds.
            (bool ok, ) = owner.call{value: msg.value - callsTotal}("");
            if (!ok) revert BribeFailed();
        }
    }

    /// @notice Sweep any stuck ETH to the owner.
    function sweepETH() external {
        if (msg.sender != owner) revert NotOwner();
        uint256 bal = address(this).balance;
        if (bal == 0) return;
        (bool ok, ) = payable(owner).call{value: bal}("");
        if (!ok) revert ETHTransferFailed();
    }

    /// @notice Sweep any ERC20 token to the owner.
    function sweepToken(address token) external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0x70a08231, address(this))); // balanceOf
        if (!ok || data.length == 0) revert TokenTransferFailed();
        uint256 bal = abi.decode(data, (uint256));
        if (bal == 0) return;
        (ok, data) = token.call(abi.encodeWithSelector(0xa9059cbb, owner, bal)); // transfer
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TokenTransferFailed();
    }
}
