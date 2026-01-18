// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>


use alloy::primitives::{address, Address, U256};
use lazy_static::lazy_static;
use std::collections::HashMap;

// Common assets
pub const WETH_MAINNET: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
pub const WETH_OPTIMISM: Address = address!("4200000000000000000000000000000000000006");
pub const WETH_ARBITRUM: Address = address!("82aF49447D8a07e3bd95BD0d56f35241523fBab1");
pub const WETH_POLYGON: Address = address!("7ceB23fD6bC0adD59E62ac25578270cFf1b9f619");
pub const WBNB_BSC: Address = address!("BB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c");

// =============================================================================
// NETWORK CONSTANTS
// =============================================================================

pub const CHAIN_ETHEREUM: u64 = 1;
pub const CHAIN_OPTIMISM: u64 = 10;
pub const CHAIN_BSC: u64 = 56;
pub const CHAIN_POLYGON: u64 = 137;
pub const CHAIN_ARBITRUM: u64 = 42161;

// Block times in seconds (approximate)
pub fn get_block_time(chain_id: u64) -> u64 {
    match chain_id {
        CHAIN_ETHEREUM => 12,
        CHAIN_BSC => 3,
        CHAIN_POLYGON | CHAIN_OPTIMISM | CHAIN_ARBITRUM => 2,
        _ => 12, // Default
    }
}

// =============================================================================
// GAS & TRANSACTION CONSTANTS
// =============================================================================

pub const DEFAULT_GAS_LIMIT: u64 = 250_000;
pub const MAX_GAS_LIMIT: u64 = 8_000_000;
pub const DEFAULT_PRIORITY_FEE_GWEI: u64 = 2;

// =============================================================================
// MEV CONSTANTS (Using U256 for precise Wei math)
// =============================================================================

lazy_static! {
    // 0.00002 ETH (accept small edges by default)
    pub static ref MIN_PROFIT_THRESHOLD_WEI: U256 = U256::from(20_000_000_000_000u64);

    // 0.05 ETH
    pub static ref LOW_BALANCE_THRESHOLD_WEI: U256 = U256::from(50_000_000_000_000_000u64);

    // Router Addresses (Mainnet)
    pub static ref DEX_ROUTERS_MAINNET: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("uniswap_v2", address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"));
        m.insert("uniswap_v3", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("sushiswap", address!("d9e1cE17f2641f24aE83637ab66a2cca9C378B9F"));
        m.insert("balancer_v2", address!("BA12222222228d8Ba445958a75a0704d566BF2C8"));
        m.insert("curve_v1", address!("a5407eae9ba41422680e2e00537571bcc53efbfd")); // 3pool
        m.insert("oneinch", address!("1111111254EEB25477B68fb85Ed929f73A960582")); // 1inch v5 router
        m.insert("matcha_zeroex", address!("def1c0ded9bec7f1a1670819833240f027b25eff")); // 0x Exchange Proxy
        m
    };

    pub static ref DEX_ROUTERS_OPTIMISM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("uniswap_v3", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("sushiswap", address!("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"));
        m.insert("oneinch", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("matcha_zeroex", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));
        m
    };

    pub static ref DEX_ROUTERS_ARBITRUM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("uniswap_v3", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("sushiswap", address!("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"));
        m.insert("oneinch", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("matcha_zeroex", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));
        m
    };

    pub static ref DEX_ROUTERS_POLYGON: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("uniswap_v3", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("sushiswap", address!("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"));
        m.insert("oneinch", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("matcha_zeroex", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));
        m
    };

    pub static ref DEX_ROUTERS_BY_CHAIN: HashMap<u64, &'static HashMap<&'static str, Address>> = {
        let mut m = HashMap::new();
        m.insert(CHAIN_ETHEREUM, &*DEX_ROUTERS_MAINNET);
        m.insert(CHAIN_OPTIMISM, &*DEX_ROUTERS_OPTIMISM);
        m.insert(CHAIN_ARBITRUM, &*DEX_ROUTERS_ARBITRUM);
        m.insert(CHAIN_POLYGON, &*DEX_ROUTERS_POLYGON);
        m
    };

    // Chainlink feeds (symbol -> aggregator) for mainnet
    pub static ref CHAINLINK_FEEDS_MAINNET: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("ETH", address!("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"));
        m.insert("BTC", address!("F4030086522a5bEEa4988F8cA5B36dbC97BeE88c"));
        m.insert("LINK", address!("2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c"));
        m.insert("USDC", address!("8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6"));
        m.insert("USDT", address!("3E7d1eAB13ad0104d2750B8863b489D65364e32D"));
        m.insert("DAI", address!("Aed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9"));
        m.insert("AAVE", address!("547a514d5e3769680Ce22B2361c10Ea13619e8a9"));
        m.insert("UNI", address!("553303d460EE0afB37EdFf9bE42922D8FF63220e"));
        m.insert("MKR", address!("ec1D1B3b0443256cc3860e24a46F108e699484Aa"));
        m.insert("COMP", address!("dbd020CAeF83eFd542f4De03e3cF0C28A4428bd5"));
        m.insert("SNX", address!("dc3ea94cd0ac27d9a86c180091e7f78c683d3699"));
        m.insert("CRV", address!("Cd627aA160A6fA45Eb793D19Ef54f5062F20f33f"));
        m.insert("STETH", address!("CfE54B5cD566aB89272946F602D76Ea879CAb4a8"));
        m.insert("WBTC", address!("fdFD9C85aD200c506Cf9e21F1FD8dd01932FBB23"));
        m
    };

    pub static ref CHAINLINK_FEEDS_OPTIMISM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("ETH", address!("13e3Ee699D1909E989722E753853AE30b17e08c5"));
        m
    };

    pub static ref CHAINLINK_FEEDS_ARBITRUM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("ETH", address!("639Fe6ab55C921f74e7fac1ee960C0B6293ba612"));
        m
    };

    pub static ref CHAINLINK_FEEDS_POLYGON: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();
        m.insert("ETH", address!("327e23A4855b6F663a28c5161541d69Af8973302"));
        m
    };

    pub static ref CHAINLINK_FEEDS_BY_CHAIN: HashMap<u64, &'static HashMap<&'static str, Address>> = {
        let mut m = HashMap::new();
        m.insert(CHAIN_ETHEREUM, &*CHAINLINK_FEEDS_MAINNET);
        m.insert(CHAIN_OPTIMISM, &*CHAINLINK_FEEDS_OPTIMISM);
        m.insert(CHAIN_ARBITRUM, &*CHAINLINK_FEEDS_ARBITRUM);
        m.insert(CHAIN_POLYGON, &*CHAINLINK_FEEDS_POLYGON);
        m
    };

    pub static ref WRAPPED_NATIVE_BY_CHAIN: HashMap<u64, Address> = {
        let mut m = HashMap::new();
        m.insert(CHAIN_ETHEREUM, WETH_MAINNET);
        m.insert(CHAIN_OPTIMISM, WETH_OPTIMISM);
        m.insert(CHAIN_ARBITRUM, WETH_ARBITRUM);
        m.insert(CHAIN_POLYGON, WETH_POLYGON);
        m.insert(CHAIN_BSC, WBNB_BSC);
        m
    };
}

// =============================================================================
// LOGGING DEFAULTS
// =============================================================================

pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const LOG_FILE_NAME: &str = "oxidized_builder.log";

pub fn default_routers_for_chain(chain_id: u64) -> HashMap<String, Address> {
    DEX_ROUTERS_BY_CHAIN
        .get(&chain_id)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.to_string(), Address::from(*v)))
                .collect::<HashMap<String, Address>>()
        })
        .unwrap_or_default()
}

pub fn default_chainlink_feeds(chain_id: u64) -> HashMap<String, Address> {
    CHAINLINK_FEEDS_BY_CHAIN
        .get(&chain_id)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.to_string(), Address::from(*v)))
                .collect::<HashMap<String, Address>>()
        })
        .unwrap_or_default()
}

pub fn wrapped_native_for_chain(chain_id: u64) -> Address {
    WRAPPED_NATIVE_BY_CHAIN
        .get(&chain_id)
        .copied()
        .unwrap_or(WETH_MAINNET)
}
