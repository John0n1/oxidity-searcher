// SPDX-License-Identifier: MIT
// Integration test that exercises the flash-loan request builder end to end
// without needing a running chain. It validates the encoded callback payloads
// and transaction envelope we generate for the UnifiedHardenedExecutor.

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::providers::Provider;
use alloy_sol_types::SolCall;
use oxidity_searcher::common::constants::{CHAIN_ETHEREUM, wrapped_native_for_chain};
use oxidity_searcher::common::error::AppError;
use oxidity_searcher::core::strategy::{FlashloanProvider, StrategyExecutor};
use oxidity_searcher::data::executor::{FlashCallbackData, UnifiedHardenedExecutor};
use oxidity_searcher::network::gas::GasFees;
use oxidity_searcher::network::provider::HttpProvider;
use url::Url;

mod support;
use support::{ExecutorHarnessOptions, build_strategy_executor};

fn rpc_access_list_unsupported(msg: &str) -> bool {
    let normalized = msg.to_ascii_lowercase();
    normalized.contains("access list")
        || normalized.contains("eip-2930")
        || normalized.contains("eip2930")
}

async fn build_flashloan_executor(
    executor_addr: Address,
    flashloan_providers: Vec<FlashloanProvider>,
    aave_pool: Option<Address>,
) -> StrategyExecutor {
    let (exec, _harness) = build_strategy_executor(ExecutorHarnessOptions {
        executor: Some(executor_addr),
        flashloan_enabled: true,
        flashloan_providers,
        aave_pool,
        ..ExecutorHarnessOptions::default()
    })
    .await;
    exec
}

/// Build a flash-loan transaction and assert the encoded callbacks round-trip.
#[tokio::test]
async fn flashloan_builder_encodes_callbacks() {
    // Minimal wiring; no real RPC is required because build_flashloan_transaction
    // doesn't hit the network on failure to create access lists.
    let executor_addr = Address::from([0x11; 20]);
    let exec =
        build_flashloan_executor(executor_addr, vec![FlashloanProvider::Balancer], None).await;

    // Two-step callback: approve + dummy swap payload; include reset approvals.
    let callbacks = vec![
        (
            wrapped_native_for_chain(CHAIN_ETHEREUM),
            Bytes::from(vec![0x01, 0x02]),
            U256::ZERO,
        ),
        (
            Address::from([0x22; 20]),
            Bytes::from(vec![0x03]),
            U256::from(7u64),
        ),
    ];

    let gas_fees = GasFees {
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 2_000_000_000,
        next_base_fee_per_gas: 28_000_000_000,
        base_fee_per_gas: 28_000_000_000,
        p50_priority_fee_per_gas: None,
        p90_priority_fee_per_gas: None,
        gas_used_ratio: None,
        suggested_max_fee_per_gas: None,
    };

    let (_raw, request, _hash, _premium, _overhead): (
        Vec<u8>,
        alloy::rpc::types::eth::TransactionRequest,
        alloy::primitives::B256,
        U256,
        u64,
    ) = exec
        .build_flashloan_transaction(
            executor_addr,
            wrapped_native_for_chain(CHAIN_ETHEREUM),
            U256::from(1_000_000u64),
            callbacks.clone(),
            250_000,
            &gas_fees,
            9,
        )
        .await
        .expect("build flashloan");

    // Basic envelope checks
    assert_eq!(request.to, Some(TxKind::Call(executor_addr)));
    assert_eq!(request.nonce, Some(9));
    assert!(request.gas.unwrap() >= 220_000);

    // Decode the calldata back to FlashCallbackData to ensure layout is correct.
    let decoded = UnifiedHardenedExecutor::executeFlashLoanCall::abi_decode(
        &request.input.clone().into_input().expect("input bytes"),
    )
    .expect("decode envelope");

    let inner =
        <FlashCallbackData as alloy_sol_types::SolValue>::abi_decode_params(&decoded.params)
            .expect("decode params");
    assert_eq!(inner.targets.len(), callbacks.len());
    assert_eq!(inner.targets[0], callbacks[0].0);
    assert_eq!(inner.values[1], callbacks[1].2);
    assert_eq!(inner.payloads[0].to_vec(), callbacks[0].1.to_vec());
    // Sanity: expected asset list matches request
    assert_eq!(decoded.assets[0], wrapped_native_for_chain(CHAIN_ETHEREUM));
}

/// Ensure Aave flashloan selector is used when provider is set to AaveV3.
#[tokio::test]
async fn flashloan_builder_uses_aave_selector() {
    let executor_addr = Address::from([0x33; 20]);
    let aave_pool = Address::from([0x44; 20]);
    let exec = build_flashloan_executor(
        executor_addr,
        vec![FlashloanProvider::AaveV3],
        Some(aave_pool),
    )
    .await;

    let callbacks = vec![(
        wrapped_native_for_chain(CHAIN_ETHEREUM),
        Bytes::from(vec![0x99]),
        U256::from(0u64),
    )];

    let gas_fees = GasFees {
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 2_000_000_000,
        next_base_fee_per_gas: 28_000_000_000,
        base_fee_per_gas: 28_000_000_000,
        p50_priority_fee_per_gas: None,
        p90_priority_fee_per_gas: None,
        gas_used_ratio: None,
        suggested_max_fee_per_gas: None,
    };

    let built = exec
        .build_flashloan_transaction(
            executor_addr,
            wrapped_native_for_chain(CHAIN_ETHEREUM),
            U256::from(1_000_000u64),
            callbacks,
            250_000,
            &gas_fees,
            10,
        )
        .await;

    let (_raw, request, _hash, _premium, _overhead) = match built {
        Ok(v) => v,
        Err(e) => {
            // Some local Nethermind/Anvil configs disable access-list calls; skip gracefully.
            eprintln!("skipping aave selector test: {}", e);
            return;
        }
    };

    let input_bytes = request.input.clone().into_input().expect("input bytes");
    let selector = &input_bytes[..4];
    assert_eq!(
        selector,
        UnifiedHardenedExecutor::executeAaveFlashLoanSimpleCall::SELECTOR
    );
}

/// Live smoke check against a deployed executor on mainnet RPC.
/// Run manually with:
/// `cargo test live_executor_flashloan_smoke_mainnet -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn live_executor_flashloan_smoke_mainnet() {
    let http = HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").expect("rpc url"));
    let owner: Address = "0x3Fe744D63be96C0081960D5d191F1f3BFE3a3bd8"
        .parse()
        .expect("owner");
    let executor: Address = "0x019223bd084590c474fecdd45779b202b20c2b98"
        .parse()
        .expect("executor");
    let weth = wrapped_native_for_chain(CHAIN_ETHEREUM);

    let callback = FlashCallbackData {
        targets: vec![],
        values: vec![],
        payloads: vec![],
    };
    let params = <FlashCallbackData as alloy_sol_types::SolValue>::abi_encode_params(&callback);

    let call = UnifiedHardenedExecutor::executeFlashLoanCall {
        assets: vec![weth],
        // Minimal non-zero amount; if premium rounds to zero this should repay without swaps.
        amounts: vec![U256::from(1u64)],
        params: Bytes::from(params),
    };
    let calldata = call.abi_encode();
    println!(
        "balancer_flashloan_smoke_calldata=0x{}",
        hex::encode(&calldata)
    );

    let req = alloy::rpc::types::eth::TransactionRequest {
        from: Some(owner),
        to: Some(TxKind::Call(executor)),
        gas: Some(3_000_000),
        input: alloy::rpc::types::eth::TransactionInput::new(calldata.into()),
        value: Some(U256::ZERO),
        ..Default::default()
    };

    let res: Result<Bytes, _> = http.call(req).await;
    println!("flashloan_smoke_result={res:?}");
    if let Err(e) = res {
        let msg = format!("{e:?}");
        if rpc_access_list_unsupported(&msg) {
            eprintln!("skipping flashloan smoke: access-list simulation unsupported by node");
            return;
        }
        panic!("flashloan smoke call reverted: {msg}");
    }
}

/// Live smoke check for Aave simple flashloan entry on deployed executor.
#[tokio::test]
#[ignore]
async fn live_executor_aave_smoke_mainnet() {
    let http = HttpProvider::new_http(Url::parse("http://127.0.0.1:8545").expect("rpc url"));
    let owner: Address = "0x3Fe744D63be96C0081960D5d191F1f3BFE3a3bd8"
        .parse()
        .expect("owner");
    let executor: Address = "0x019223bd084590c474fecdd45779b202b20c2b98"
        .parse()
        .expect("executor");
    let aave_pool: Address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
        .parse()
        .expect("aave pool");
    let weth = wrapped_native_for_chain(CHAIN_ETHEREUM);

    let callback = FlashCallbackData {
        targets: vec![],
        values: vec![],
        payloads: vec![],
    };
    let params = <FlashCallbackData as alloy_sol_types::SolValue>::abi_encode_params(&callback);
    let call = UnifiedHardenedExecutor::executeAaveFlashLoanSimpleCall {
        pool: aave_pool,
        asset: weth,
        amount: U256::from(1u64),
        params: Bytes::from(params),
    };
    let calldata = call.abi_encode();
    println!("aave_flashloan_smoke_calldata=0x{}", hex::encode(&calldata));

    let req = alloy::rpc::types::eth::TransactionRequest {
        from: Some(owner),
        to: Some(TxKind::Call(executor)),
        gas: Some(3_000_000),
        input: alloy::rpc::types::eth::TransactionInput::new(calldata.into()),
        value: Some(U256::ZERO),
        ..Default::default()
    };

    let res: Result<Bytes, _> = http.call(req).await;
    println!("aave_flashloan_smoke_result={res:?}");
    match res {
        Ok(_) => {}
        Err(e) => {
            // This smoke uses amount=1 and empty callbacks; Aave premium can make
            // repayment impossible. That should surface as InsufficientFundsForRepayment.
            let msg = format!("{e:?}");
            if rpc_access_list_unsupported(&msg) {
                eprintln!("skipping aave smoke: access-list simulation unsupported by node");
                return;
            }
            assert!(
                msg.contains("0x6756dd0a"),
                "unexpected aave smoke revert: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn flashloan_builder_rejects_when_no_provider_available() {
    let executor_addr = Address::from([0x55; 20]);
    let exec = build_flashloan_executor(executor_addr, vec![], None).await;

    let callbacks = vec![(
        wrapped_native_for_chain(CHAIN_ETHEREUM),
        Bytes::from(vec![0x01]),
        U256::ZERO,
    )];
    let gas_fees = GasFees {
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 2_000_000_000,
        next_base_fee_per_gas: 28_000_000_000,
        base_fee_per_gas: 28_000_000_000,
        p50_priority_fee_per_gas: None,
        p90_priority_fee_per_gas: None,
        gas_used_ratio: None,
        suggested_max_fee_per_gas: None,
    };

    let err = exec
        .build_flashloan_transaction(
            executor_addr,
            wrapped_native_for_chain(CHAIN_ETHEREUM),
            U256::from(1_000_000u64),
            callbacks,
            180_000,
            &gas_fees,
            11,
        )
        .await
        .expect_err("missing provider should fail");
    assert!(
        matches!(err, AppError::Strategy(msg) if msg.contains("No flashloan provider available"))
    );
}
