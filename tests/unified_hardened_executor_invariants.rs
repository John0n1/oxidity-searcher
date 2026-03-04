// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use std::fs;

fn contract_source() -> String {
    fs::read_to_string("data/UnifiedHardenedExecutor.sol")
        .expect("read data/UnifiedHardenedExecutor.sol")
}

#[test]
fn owner_and_session_guards_are_present() {
    let src = contract_source();
    let required = [
        "modifier onlyOwner()",
        "modifier onlySelfOrOwner()",
        "if (msg.sender != owner) revert OnlyOwner();",
        "if (msg.sender != owner && msg.sender != address(this)) revert OnlyOwner();",
    ];
    for needle in required {
        assert!(
            src.contains(needle),
            "missing owner/session guard in executor source: {needle}"
        );
    }
}

#[test]
fn balancer_callback_auth_context_and_single_use_guards_are_present() {
    let src = contract_source();
    let required = [
        "if (msg.sender != BALANCER_VAULT) revert OnlyVault();",
        "if (!balancerLoanActive) revert BalancerLoanNotActive();",
        "if (callbackContext != balancerLoanContextHash) revert BalancerLoanContextMismatch();",
        "balancerLoanActive = false;",
        "balancerLoanContextHash = bytes32(0);",
        "if (balancerLoanActive || balancerLoanContextHash != bytes32(0))",
    ];
    for needle in required {
        assert!(
            src.contains(needle),
            "missing Balancer callback guard in executor source: {needle}"
        );
    }
}

#[test]
fn aave_callback_auth_and_reset_guards_are_present() {
    let src = contract_source();
    let required = [
        "if (msg.sender != activeAavePool) revert OnlyPool();",
        "if (initiator != address(this)) revert OnlyOwner();",
        "activeAavePool = address(0);",
        "if (activeAavePool != address(0)) revert AaveCallbackNotReceived();",
    ];
    for needle in required {
        assert!(
            src.contains(needle),
            "missing Aave callback guard in executor source: {needle}"
        );
    }
}

#[test]
fn flashloan_repayment_guards_are_present() {
    let src = contract_source();
    let required = [
        "if (myBalance < amountOwing) {",
        "revert InsufficientFundsForRepayment(tokenAddr, amountOwing, myBalance);",
        "if (bal < amountOwing) {",
        "revert InsufficientFundsForRepayment(asset, amountOwing, bal);",
        "_safeTransfer(tokenAddr, BALANCER_VAULT, amountOwing);",
        "_lowLevelApprove(asset, msg.sender, amountOwing);",
    ];
    for needle in required {
        assert!(
            src.contains(needle),
            "missing repayment invariant guard in executor source: {needle}"
        );
    }
}

#[test]
fn flashloan_input_sanity_guards_are_present() {
    let src = contract_source();
    let required = [
        "if (assets.length == 0) revert ZeroAssets();",
        "if (assets.length != amounts.length) revert LengthMismatch();",
        "if (amounts[i] == 0) revert ZeroAssets();",
        "if (current <= previous) {",
        "revert BalancerTokensNotSorted(i, previous, current);",
        "if (pool == address(0)) revert InvalidPool();",
        "if (asset == address(0)) revert InvalidAsset();",
        "if (amount == 0) revert ZeroAssets();",
    ];
    for needle in required {
        assert!(
            src.contains(needle),
            "missing flashloan input sanity guard in executor source: {needle}"
        );
    }
}
