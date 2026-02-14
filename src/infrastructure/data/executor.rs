// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface UnifiedHardenedExecutor {
        function executeBundle(
            address[] calldata targets,
            bytes[] calldata payloads,
            uint256[] calldata values,
            address bribeRecipient,
            uint256 bribeAmount,
            bool allowPartial,
            address balanceCheckToken
        ) external payable;

        function executeFlashLoan(
            address[] calldata assets,
            uint256[] calldata amounts,
            bytes calldata params
        ) external;

        function safeApprove(address token, address spender, uint256 amount) external;
        function setProfitReceiver(address newReceiver) external;
        function setSweepPreference(bool sweepToEth) external;

        // Aave v3 simple flashloan entry
        function executeAaveFlashLoanSimple(
            address pool,
            address asset,
            uint256 amount,
            bytes calldata params
        ) external;

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
    }

    // Matches abi.decode(userData, (address[], uint256[], bytes[])) in receiveFlashLoan
    struct FlashCallbackData {
        address[] targets;
        uint256[] values;
        bytes[] payloads;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy_sol_types::{SolCall, SolType, SolValue};

    #[test]
    fn flash_callback_data_roundtrips() {
        let targets = vec![Address::from([1u8; 20]), Address::from([2u8; 20])];
        let values = vec![U256::from(1u64), U256::from(2u64)];
        let payloads = vec![vec![0xde, 0xad], vec![0xbe, 0xef]];
        let data = FlashCallbackData {
            targets: targets.clone(),
            values: values.clone(),
            payloads: payloads.clone().into_iter().map(Into::into).collect(),
        };

        let encoded = data.abi_encode();
        let decoded =
            <FlashCallbackData as SolType>::abi_decode(&encoded).expect("decode callback");

        assert_eq!(decoded.targets, targets);
        assert_eq!(decoded.values, values);
        assert_eq!(
            decoded
                .payloads
                .iter()
                .map(|b: &alloy::primitives::Bytes| b.clone().to_vec())
                .collect::<Vec<_>>(),
            payloads
        );
    }

    #[test]
    fn execute_flashloan_call_roundtrips() {
        let call = UnifiedHardenedExecutor::executeFlashLoanCall {
            assets: vec![Address::from([3u8; 20])],
            amounts: vec![U256::from(123u64)],
            params: vec![0xca, 0xfe].into(),
        };
        let encoded = call.abi_encode();
        let decoded = UnifiedHardenedExecutor::executeFlashLoanCall::abi_decode(&encoded)
            .expect("decode flashloan call");
        assert_eq!(decoded.assets, call.assets);
        assert_eq!(decoded.amounts, call.amounts);
        assert_eq!(decoded.params, call.params);
    }

    #[test]
    fn execute_bundle_call_roundtrips() {
        let call = UnifiedHardenedExecutor::executeBundleCall {
            targets: vec![Address::from([4u8; 20]), Address::from([5u8; 20])],
            payloads: vec![vec![0x01u8].into(), vec![0x02u8].into()],
            values: vec![U256::from(0u64), U256::from(1u64)],
            bribeRecipient: Address::from([9u8; 20]),
            bribeAmount: U256::from(42u64),
            allowPartial: true,
            balanceCheckToken: Address::from([8u8; 20]),
        };
        let encoded = call.abi_encode();
        let decoded = UnifiedHardenedExecutor::executeBundleCall::abi_decode(&encoded)
            .expect("decode bundle call");
        assert_eq!(decoded.targets, call.targets);
        assert_eq!(decoded.payloads, call.payloads);
        assert_eq!(decoded.values, call.values);
        assert_eq!(decoded.bribeRecipient, call.bribeRecipient);
        assert_eq!(decoded.bribeAmount, call.bribeAmount);
        assert_eq!(decoded.allowPartial, call.allowPartial);
        assert_eq!(decoded.balanceCheckToken, call.balanceCheckToken);
    }
}
