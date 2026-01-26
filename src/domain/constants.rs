// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.com>

use alloy::primitives::{Address, U256, address};
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
    // -------------------------
    // DEX Routers / Executors
    // -------------------------

    pub static ref DEX_ROUTERS_MAINNET: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // Uniswap
        m.insert("uniswap_v2_router02", address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"));
        m.insert("uniswap_v3_swaprouter", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("uniswap_v3_swaprouter02", address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"));
        m.insert("uniswap_universal_router", address!("66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"));
        m.insert("uniswap_permit2", address!("000000000022D473030F116dDEE9F6B43aC78BA3"));

        // Sushi
        m.insert("sushiswap_router", address!("d9e1cE17f2641f24aE83637ab66a2cca9C378B9F"));

        // Balancer
        m.insert("balancer_v2_vault", address!("BA12222222228d8Ba445958a75a0704d566BF2C8"));

        // Curve (pool address + router)
        m.insert("curve_3pool_susd_v2_swap", address!("a5407eae9ba41422680e2e00537571bcc53efbfd"));
        m.insert("curve_router", address!("99a58482BD75cbab83b27EC03CA68fF489b5788f"));

        // Aggregators / RFQ executors
        m.insert("oneinch_aggregation_router_v5", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("zeroex_exchange_proxy", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));

        m
    };

    pub static ref DEX_ROUTERS_OPTIMISM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // Uniswap
        m.insert("uniswap_v3_swaprouter", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("uniswap_v3_swaprouter02", address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"));
        m.insert("uniswap_universal_router", address!("851116D9223fabED8E56C0e6B8Ad0c31d98B3507"));
        m.insert("uniswap_permit2", address!("000000000022D473030F116dDEE9F6B43aC78BA3"));

        // Sushi (NOTE: NOT 1b02... on OP)
        m.insert("sushiswap_router", address!("2abf469074dc0b54d793850807e6eb5faf2625b1"));

        // Velodrome
        m.insert("velodrome_router_v2", address!("a062aE8A9c5e11aaA026fc2670B0D65cCc8B2858"));
        m.insert("velodrome_router_v1_legacy", address!("a132DAB612dB5cB9fC9Ac426A0Cc215A3423F9c9"));

        // Balancer
        m.insert("balancer_v2_vault", address!("BA12222222228d8Ba445958a75a0704d566BF2C8"));

        // Aggregators / RFQ executors
        m.insert("oneinch_aggregation_router_v5", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("zeroex_exchange_proxy", address!("def1abe32c034e558cdd535791643c58a13acc10"));

        m
    };

    pub static ref DEX_ROUTERS_ARBITRUM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // Uniswap
        m.insert("uniswap_v3_swaprouter", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("uniswap_v3_swaprouter02", address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"));
        m.insert("uniswap_universal_router", address!("a51afafe0263b40edaef0df8781ea9aa03e381a3"));
        m.insert("uniswap_permit2", address!("000000000022D473030F116dDEE9F6B43aC78BA3"));

        // Sushi
        m.insert("sushiswap_router", address!("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"));

        // Camelot (v2 + v3)
        m.insert("camelot_router_v2", address!("c873fEcbd354f5A56E00E710B90EF4201db2448d"));
        m.insert("camelot_router_v3", address!("1F721E2E82F6676FCE4eA07A5958cF098D339e18"));

        // Balancer
        m.insert("balancer_v2_vault", address!("BA12222222228d8Ba445958a75a0704d566BF2C8"));

        // Aggregators / RFQ executors
        m.insert("oneinch_aggregation_router_v5", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("zeroex_exchange_proxy", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));

        m
    };

    pub static ref DEX_ROUTERS_POLYGON: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // Uniswap
        m.insert("uniswap_v3_swaprouter", address!("E592427A0AEce92De3Edee1F18E0157C05861564"));
        m.insert("uniswap_v3_swaprouter02", address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"));
        m.insert("uniswap_universal_router", address!("1095692A6237d83C6a72F3F5eFEdb9A670C49223"));
        m.insert("uniswap_permit2", address!("000000000022D473030F116dDEE9F6B43aC78BA3"));

        // Sushi
        m.insert("sushiswap_router", address!("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"));

        // QuickSwap (UniV2-style)
        m.insert("quickswap_v2_router", address!("a5E0829CaCED8fFDD4De3c43696c57F7D7A678ff"));

        // Balancer
        m.insert("balancer_v2_vault", address!("BA12222222228d8Ba445958a75a0704d566BF2C8"));

        // Aggregators / RFQ executors
        m.insert("oneinch_aggregation_router_v5", address!("1111111254EEB25477B68fb85Ed929f73A960582"));
        m.insert("zeroex_exchange_proxy", address!("def1c0ded9bec7f1a1670819833240f027b25eff"));

        m
    };

    pub static ref DEX_ROUTERS_BSC: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // PancakeSwap (UniV2-style)
        m.insert("pancakeswap_v2_router", address!("10ED43C718714eb63d5aA57B78B54704E256024E"));

        // Aggregators / RFQ executors
        m.insert("oneinch_aggregation_router_v4", address!("11111112542d85B3EF69AE05771c2dCCff4fAa26"));

        m
    };

    pub static ref DEX_ROUTERS_BY_CHAIN: HashMap<u64, &'static HashMap<&'static str, Address>> = {
        let mut m = HashMap::new();
        m.insert(CHAIN_ETHEREUM, &*DEX_ROUTERS_MAINNET);
        m.insert(CHAIN_OPTIMISM, &*DEX_ROUTERS_OPTIMISM);
        m.insert(CHAIN_ARBITRUM, &*DEX_ROUTERS_ARBITRUM);
        m.insert(CHAIN_POLYGON, &*DEX_ROUTERS_POLYGON);
        m.insert(CHAIN_BSC, &*DEX_ROUTERS_BSC);
        m
    };

    // -------------------------
    // Chainlink Feeds (symbol -> aggregator)
    // -------------------------

    // Ethereum mainnet: kept your list, but made WBTC explicit (WBTC/BTC exists; WBTC/USD does not on mainnet)
    pub static ref CHAINLINK_FEEDS_MAINNET: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        m.insert("ETH_USD", address!("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"));
        m.insert("BTC_USD", address!("F4030086522a5bEEa4988F8cA5B36dbC97BeE88c"));
        m.insert("LINK_USD", address!("2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c"));
        m.insert("USDC_USD", address!("8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6"));
        m.insert("USDT_USD", address!("3E7d1eAB13ad0104d2750B8863b489D65364e32D"));
        m.insert("DAI_USD", address!("Aed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9"));

        m.insert("AAVE_USD", address!("547a514d5e3769680Ce22B2361c10Ea13619e8a9"));
        m.insert("UNI_USD", address!("553303d460EE0afB37EdFf9bE42922D8FF63220e"));
        m.insert("MKR_USD", address!("ec1D1B3b0443256cc3860e24a46F108e699484Aa"));
        m.insert("COMP_USD", address!("dbd020CAeF83eFd542f4De03e3cF0C28A4428bd5"));
        m.insert("SNX_USD", address!("dc3ea94cd0ac27d9a86c180091e7f78c683d3699"));
        m.insert("CRV_USD", address!("Cd627aA160A6fA45Eb793D19Ef54f5062F20f33f"));

        // NOTE: this is stETH/ETH (not stETH/USD)
        m.insert("STETH_ETH", address!("CfE54B5cD566aB89272946F602D76Ea879CAb4a8"));

        // NOTE: WBTC/USD is not on Ethereum mainnet; this is WBTC/BTC.
        m.insert("WBTC_BTC", address!("fdFD9C85aD200c506Cf9e21F1FD8dd01932FBB23"));

        m
    };

    pub static ref CHAINLINK_FEEDS_OPTIMISM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        m.insert("ETH_USD",  address!("13e3Ee699D1909E989722E753853AE30b17e08c5"));
        m.insert("BTC_USD",  address!("D702DD976Fb76Fffc2D3963D037dfDae5b04E593"));
        m.insert("WBTC_USD", address!("718A5788b89454aAE3A028AE9c111A29Be6c2a6F"));
        m.insert("LINK_USD", address!("Cc232dcFAAE6354cE191Bd574108c1aD03f86450"));

        m.insert("USDC_USD", address!("16a9FA2FDa030272Ce99B29CF780dFA30361E0f3"));
        m.insert("USDT_USD", address!("ECef79E109e997bCA29c1c0897ec9d7b03647F5E"));
        m.insert("DAI_USD",  address!("8dBa75e83DA73cc766A7e5a0ee71F656BAb470d6"));

        m.insert("OP_USD",   address!("0D276FC14719f9292D5C1eA2198673d1f4269246"));

        m
    };

    pub static ref CHAINLINK_FEEDS_ARBITRUM: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        m.insert("ETH_USD",  address!("639Fe6ab55C921f74e7fac1ee960C0B6293ba612"));
        m.insert("BTC_USD",  address!("6ce185860a4963106506C203335A2910413708e9"));
        m.insert("WBTC_USD", address!("d0C7101eACbB49F3deCcCc166d238410D6D46d57"));
        m.insert("LINK_USD", address!("86E53CF1B870786351Da77A57575e79CB55812CB"));

        m.insert("USDC_USD", address!("50834F3163758fcC1Df9973b6e91f0F0F0434aD3"));
        m.insert("USDT_USD", address!("3f3f5dF88dC9F13eac63DF89EC16ef6e7E25DdE7"));
        m.insert("DAI_USD",  address!("c5C8E77B397E531B8EC06BFb0048328B30E9eCfB"));

        m.insert("ARB_USD",  address!("b2A824043730FE05F3DA2efaFa1CBbe83fa548D6"));

        m
    };

    pub static ref CHAINLINK_FEEDS_POLYGON: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        // (Your previous 0x327e... was not the ETH/USD feed; correct feed below)
        m.insert("ETH_USD",  address!("F9680D99D6C9589e2a93a78A04A279e509205945"));
        m.insert("BTC_USD",  address!("c907E116054Ad103354f2D350FD2514433D57F6f"));
        m.insert("WBTC_USD", address!("DE31F8bFBD8c84b5360CFACCa3539B938dd78ae6"));
        m.insert("LINK_USD", address!("d9FFdb71EbE7496cC440152d43986Aae0AB76665"));

        m.insert("USDC_USD", address!("fE4A8cc5b5B2366C1B58Bea3858e81843581b2F7"));
        m.insert("USDT_USD", address!("0A6513e40db6EB1b165753AD52E80663aeA50545"));
        m.insert("DAI_USD",  address!("4746DeC9e833A82EC7C2C1356372CcF2cfcD2F3D"));

        m.insert("MATIC_USD", address!("AB594600376Ec9fD91F8e885dADF0CE036862dE0"));

        m
    };

    pub static ref CHAINLINK_FEEDS_BSC: HashMap<&'static str, Address> = {
        let mut m = HashMap::new();

        m.insert("BNB_USD", address!("0567F2323251f0AaB15c8dFb1967E4e8A7D42aEE"));
        m.insert("BTC_USD", address!("5741306c21795FdCBb9b265Ea0255F499DFe515C"));
        m.insert("ETH_USD", address!("143db3CEEfbdfe5631aDD3E50f7614B6ba708BA7"));
        m.insert("BUSD_USD", address!("cBb98864Ef56E9042e7d2efef76141f15731B82f"));

        m
    };

    pub static ref CHAINLINK_FEEDS_BY_CHAIN: HashMap<u64, &'static HashMap<&'static str, Address>> = {
        let mut m = HashMap::new();
        m.insert(CHAIN_ETHEREUM, &*CHAINLINK_FEEDS_MAINNET);
        m.insert(CHAIN_OPTIMISM, &*CHAINLINK_FEEDS_OPTIMISM);
        m.insert(CHAIN_ARBITRUM, &*CHAINLINK_FEEDS_ARBITRUM);
        m.insert(CHAIN_POLYGON, &*CHAINLINK_FEEDS_POLYGON);
        m.insert(CHAIN_BSC, &*CHAINLINK_FEEDS_BSC);
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
pub const LOG_FILE_NAME: &str = "oxidity_builder.log";

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
