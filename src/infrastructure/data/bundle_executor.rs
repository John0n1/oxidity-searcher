// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

//! ABI helper for the on-chain MEVBundleExecutor contract (see data/MEVBundleExecutor.sol).
//! This allows us to encode atomic multi-call bundles with an optional bribe.

use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    contract MEVBundleExecutor {
        function execute(
            address[] calldata targets,
            bytes[] calldata payloads,
            uint256[] calldata values,
            address bribeRecipient,
            uint256 bribeAmount
        ) external payable returns (bytes[] memory results);
        function owner() external view returns (address);
    }
}
