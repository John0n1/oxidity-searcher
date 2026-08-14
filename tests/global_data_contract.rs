// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::Address;
use oxidity_searcher::infrastructure::data::abi::AbiRegistry;
use oxidity_searcher::infrastructure::data::address_registry::AddressRegistry;
use oxidity_searcher::infrastructure::data::pool_index::load_pool_index;
use oxidity_searcher::infrastructure::data::token_manager::TokenManager;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;

const GLOBAL_DATA_PATH: &str = "data/global_data.json";

fn global_data() -> Value {
    let raw = fs::read_to_string(GLOBAL_DATA_PATH).expect("global_data.json must be readable");
    serde_json::from_str(&raw).expect("global_data.json must be valid JSON")
}

fn valid_evm_address(raw: &str) -> bool {
    Address::from_str(raw).is_ok()
}

#[test]
fn rust_consumers_parse_the_canonical_global_data_file() {
    let data = global_data();
    for section in [
        "address_registry",
        "chainlink_feeds",
        "executor_abi",
        "pairs",
        "pool_index",
        "tokenlist",
        "wallet_registry",
    ] {
        assert!(
            data.get(section).is_some(),
            "missing top-level section {section}"
        );
    }

    let token_manager = TokenManager::load_from_file(GLOBAL_DATA_PATH)
        .expect("Rust token loader must accept global_data.json");
    assert!(!token_manager.is_empty(), "token loader produced no tokens");

    assert!(
        !load_pool_index(std::path::Path::new(GLOBAL_DATA_PATH), 1)
            .expect("Rust pool-index loader must accept global_data.json")
            .is_empty(),
        "eligible mainnet pool index is empty"
    );

    let registry = AddressRegistry::load_from_file(GLOBAL_DATA_PATH)
        .expect("Rust address-registry loader must accept global_data.json");
    let mainnet = registry.chain(1).expect("mainnet registry must exist");
    assert!(
        !mainnet.routers.is_empty(),
        "mainnet router registry is empty"
    );

    let mut abi_registry = AbiRegistry::new();
    abi_registry
        .load_from_directory("data")
        .expect("standalone and embedded executor ABIs must parse and match");
    assert!(abi_registry.get("UnifiedHardenedExecutor").is_some());
}

#[test]
fn token_definitions_have_valid_unique_chain_addresses() {
    let data = global_data();
    let tokens = data["tokenlist"].as_array().expect("tokenlist array");
    let mut seen: HashMap<(String, Address), (String, u64)> = HashMap::new();

    for (index, token) in tokens.iter().enumerate() {
        let symbol = token["symbol"].as_str().expect("token symbol").trim();
        assert!(!symbol.is_empty(), "empty token symbol at index {index}");
        let decimals = token["decimals"].as_u64().expect("token decimals");
        assert!(
            decimals <= u8::MAX as u64,
            "invalid decimals at index {index}"
        );
        let addresses = token["addresses"].as_object().expect("token addresses map");
        assert!(
            !addresses.is_empty(),
            "token has no addresses at index {index}"
        );

        for (chain, address_value) in addresses {
            if chain.parse::<u64>().is_err() {
                continue;
            }
            let address_raw = address_value.as_str().expect("token address string");
            let address = Address::from_str(address_raw)
                .unwrap_or_else(|_| panic!("invalid EVM token address {chain}:{address_raw}"));
            let key = (chain.clone(), address);
            if let Some((existing_symbol, existing_decimals)) =
                seen.insert(key, (symbol.to_ascii_uppercase(), decimals))
            {
                assert_eq!(
                    (existing_symbol, existing_decimals),
                    (symbol.to_ascii_uppercase(), decimals),
                    "conflicting token definitions for {chain}:{address_raw}"
                );
            }
        }
    }
}

#[test]
fn pair_records_are_unique_v2_pool_candidates() {
    let data = global_data();
    let pairs = data["pairs"].as_array().expect("pairs array");
    let mut seen = HashSet::new();

    for (index, pair) in pairs.iter().enumerate() {
        let chain_id = pair.get("chain_id").and_then(Value::as_u64).unwrap_or(1);
        let pair_raw = pair["pair"].as_str().expect("pair address");
        let token0 = pair["token0"].as_str().expect("pair token0");
        let token1 = pair["token1"].as_str().expect("pair token1");
        assert!(
            valid_evm_address(pair_raw),
            "invalid pair address at index {index}"
        );
        assert!(valid_evm_address(token0), "invalid token0 at index {index}");
        assert!(valid_evm_address(token1), "invalid token1 at index {index}");
        assert_ne!(
            token0.to_ascii_lowercase(),
            token1.to_ascii_lowercase(),
            "self-pair at index {index}"
        );
        assert!(
            seen.insert((chain_id, pair_raw.to_ascii_lowercase())),
            "duplicate pool address for chain {chain_id}: {pair_raw}"
        );
        if let Some(fee_bps) = pair.get("fee_bps").and_then(Value::as_u64) {
            assert!(fee_bps < 10_000, "invalid fee_bps at index {index}");
        }
        if let Some(factory) = pair.get("factory").and_then(Value::as_str) {
            assert!(
                valid_evm_address(factory),
                "invalid factory at index {index}"
            );
        }
    }
}

#[test]
fn registry_and_feed_entries_are_evm_scoped_and_well_formed() {
    let data = global_data();
    let chains = data["address_registry"]["chains"]
        .as_object()
        .expect("registry chains");
    let known_chains: HashSet<u64> = chains
        .keys()
        .map(|chain| chain.parse::<u64>().expect("numeric registry chain id"))
        .collect();

    for (chain, registry) in chains {
        let chain_id = chain.parse::<u64>().expect("numeric chain id");
        for section in ["routers", "chainlink_feeds"] {
            if let Some(entries) = registry.get(section).and_then(Value::as_object) {
                for (key, value) in entries {
                    let raw = value.as_str().expect("registry address string");
                    assert!(
                        valid_evm_address(raw),
                        "invalid registry address {chain_id}:{section}:{key}={raw}"
                    );
                }
            }
        }
        for key in ["balancer_vault", "aave_pool", "aave_addresses_provider"] {
            if let Some(raw) = registry.get(key).and_then(Value::as_str) {
                assert!(valid_evm_address(raw), "invalid {chain_id}:{key}={raw}");
            }
        }
        for key in [
            "curve_registries",
            "curve_meta_registries",
            "curve_crypto_registries",
        ] {
            if let Some(addresses) = registry.get(key).and_then(Value::as_array) {
                for value in addresses {
                    let raw = value.as_str().expect("registry list address");
                    assert!(valid_evm_address(raw), "invalid {chain_id}:{key}={raw}");
                }
            }
        }
    }

    for (index, feed) in data["chainlink_feeds"]
        .as_array()
        .expect("chainlink_feeds array")
        .iter()
        .enumerate()
    {
        let chain_id = feed["chainId"].as_u64().expect("feed chainId");
        assert!(
            known_chains.contains(&chain_id),
            "feed uses unknown chain {chain_id}"
        );
        let address = feed["address"].as_str().expect("feed address");
        assert!(
            valid_evm_address(address),
            "invalid feed address at index {index}"
        );
        assert!(!feed["base"].as_str().unwrap_or_default().trim().is_empty());
        assert!(!feed["quote"].as_str().unwrap_or_default().trim().is_empty());
    }
}

#[test]
fn curated_pool_index_has_unique_auditable_records() {
    let value = global_data();
    let mainnet = &value["address_registry"]["chains"]["1"];
    let canonical_sources: HashSet<String> = [
        mainnet["routers"]["UNISWAP_V3_FACTORY"].as_str(),
        mainnet["routers"]["UNISWAP_V4_POOL_MANAGER"].as_str(),
        mainnet["balancer_vault"].as_str(),
    ]
    .into_iter()
    .flatten()
    .map(str::to_ascii_lowercase)
    .chain(
        [
            "curve_registries",
            "curve_meta_registries",
            "curve_crypto_registries",
        ]
        .into_iter()
        .flat_map(|key| {
            mainnet[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
        }),
    )
    .collect();
    let records = value["pool_index"]
        .as_array()
        .expect("pool_index must be an array");
    let mut identities = HashSet::new();
    for record in records {
        let protocol = record["protocol"].as_str().expect("pool protocol");
        assert!(
            matches!(
                protocol,
                "uniswap_v3" | "uniswap_v4" | "balancer_v2" | "curve"
            ),
            "unsupported pool protocol {protocol}"
        );
        let pool = record["pool"].as_str().expect("pool address");
        assert!(
            pool.parse::<Address>().is_ok(),
            "invalid pool address {pool}"
        );
        let source = record["canonical_source"]
            .as_str()
            .expect("canonical source")
            .to_ascii_lowercase();
        assert!(
            canonical_sources.contains(&source),
            "pool source is not present in the canonical registry: {source}"
        );
        let pool_id = record["pool_id"].as_str().unwrap_or_default();
        assert!(
            identities.insert((
                protocol.to_string(),
                pool.to_ascii_lowercase(),
                pool_id.to_string()
            )),
            "duplicate curated pool identity {protocol}:{pool}:{pool_id}"
        );
        let tokens = record["tokens"].as_array().expect("pool tokens");
        assert!(tokens.len() >= 2, "pool must have at least two currencies");
        for token in tokens {
            assert!(
                token
                    .as_str()
                    .expect("token address")
                    .parse::<Address>()
                    .is_ok(),
                "invalid curated pool token"
            );
        }
        let eligible = record["eligible"].as_bool().expect("eligible flag");
        let reasons = record["rejection_reasons"]
            .as_array()
            .expect("rejection reasons");
        assert_eq!(eligible, reasons.is_empty(), "eligibility/reasons disagree");
        let created = record["created_block"].as_u64().expect("created block");
        let creation_block_exact = record["creation_block_exact"]
            .as_bool()
            .expect("creation block precision flag");
        if protocol == "curve" {
            assert!(
                !creation_block_exact,
                "Curve registry enumeration must not claim exact deployment-event provenance"
            );
        }
        let measured = record["metrics"]["measured_at_block"]
            .as_u64()
            .expect("measured block");
        assert!(measured >= created, "pool metrics predate pool creation");
        if protocol == "uniswap_v4" {
            assert!(!pool_id.is_empty(), "V4 pool requires pool_id");
        }
    }
}
