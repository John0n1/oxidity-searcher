// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::data_path::{resolve_data_path, resolve_required_data_path};
use crate::common::parsing::parse_boolish;
use crate::domain::constants;
use crate::domain::error::AppError;
use crate::services::strategy::strategy::StrategyRuntimeSettings;
use alloy::primitives::{Address, U256, keccak256};
use config::{Config, Environment, File, Map};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ConfigFieldSource {
    pub field: String,
    pub canonical_key: String,
    pub selected_key: Option<String>,
    pub selected_source: String,
    pub redacted_value: Option<String>,
    pub deprecated_since: Option<String>,
    pub remove_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigLoadReport {
    pub field_sources: Vec<ConfigFieldSource>,
    pub warnings: Vec<String>,
    pub effective_config_hash: String,
}

#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub settings: GlobalSettings,
    pub report: ConfigLoadReport,
    pub config_debug: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalSettings {
    // General
    #[serde(default = "default_debug")]
    pub debug: bool,
    #[serde(default = "default_chain", deserialize_with = "deserialize_chain_list")]
    pub chains: Vec<u64>,
    pub database_url: Option<String>,

    // Identity
    pub wallet_key: String,
    pub wallet_address: Address,
    pub profit_receiver_address: Option<Address>,

    // Transaction
    #[serde(default = "default_max_gas")]
    pub max_gas_price_gwei: u64,
    #[serde(default = "default_sim_backend")]
    pub simulation_backend: String, // "revm", "anvil", etc.

    // MEV
    #[serde(default = "default_true")]
    pub flashloan_enabled: bool,
    /// Comma-separated list; supports "auto" prefix, "balancer", "aavev3"
    #[serde(default = "default_flashloan_provider")]
    pub flashloan_provider: String,
    pub executor_address: Option<Address>,
    #[serde(default = "default_true")]
    pub sandwich_attacks_enabled: bool,
    pub http_providers: Option<HashMap<String, String>>,
    pub websocket_providers: Option<HashMap<String, String>>,
    pub ipc_providers: Option<HashMap<String, String>>,
    pub chainlink_feeds: Option<HashMap<String, String>>, // Symbol -> aggregator address
    pub chainlink_feeds_path: Option<String>,
    pub pairs_path: Option<String>,
    pub aave_pools_by_chain: Option<HashMap<String, String>>,
    pub flashbots_relay_url: Option<String>,
    pub bundle_signer_key: Option<String>,
    #[serde(default = "default_bribe_bps")]
    pub executor_bribe_bps: u64,
    pub executor_bribe_recipient: Option<Address>,
    pub tokenlist_path: Option<String>,
    pub address_registry_path: Option<String>,
    pub data_dir: Option<String>,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub strategy_enabled: bool,
    pub strategy_workers: Option<usize>,
    pub metrics_bind: Option<String>,
    pub metrics_token: Option<String>,
    #[serde(default = "default_false")]
    pub metrics_enable_shutdown: bool,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u64,
    /// Multiplier applied to the base dynamic profit floor.
    #[serde(default = "default_profit_guard_base_floor_multiplier_bps")]
    pub profit_guard_base_floor_multiplier_bps: u64,
    /// Multiplier applied to direct execution costs (gas + bribe + premium).
    #[serde(default = "default_profit_guard_cost_multiplier_bps")]
    pub profit_guard_cost_multiplier_bps: u64,
    /// Minimum margin above gas cost required by risk/reward gate.
    #[serde(default = "default_profit_guard_min_margin_bps")]
    pub profit_guard_min_margin_bps: u64,
    /// Liquidity floor used by ratio-based build checks (parts-per-million).
    #[serde(default = "default_liquidity_ratio_floor_ppm")]
    pub liquidity_ratio_floor_ppm: u64,
    /// Minimum native output floor for sell-path checks.
    #[serde(default = "default_sell_min_native_out_wei")]
    pub sell_min_native_out_wei: u64,
    #[serde(default = "default_gas_cap_multiplier_bps")]
    pub gas_cap_multiplier_bps: u64,
    #[serde(default = "default_skip_log_every")]
    pub skip_log_every: u64,
    #[serde(default = "default_allow_non_wrapped_swaps")]
    pub allow_non_wrapped_swaps: bool,
    pub gas_caps_gwei: Option<HashMap<String, u64>>,
    #[serde(default = "default_mev_share_url")]
    pub mev_share_stream_url: String,
    pub mev_share_relay_url: Option<String>,
    #[serde(default = "default_mev_share_history_limit")]
    pub mev_share_history_limit: u32,
    #[serde(default = "default_true")]
    pub mev_share_enabled: bool,
    #[serde(default = "default_mevshare_builders")]
    pub mevshare_builders: Vec<String>,
    #[serde(default = "default_receipt_poll_ms")]
    pub receipt_poll_ms: u64,
    #[serde(default = "default_receipt_timeout_ms")]
    pub receipt_timeout_ms: u64,
    #[serde(default = "default_receipt_confirm_blocks")]
    pub receipt_confirm_blocks: u64,
    #[serde(default = "default_false")]
    pub emergency_exit_on_unknown_receipt: bool,
    #[serde(default = "default_rpc_capability_strict")]
    pub rpc_capability_strict: bool,
    #[serde(default = "default_chainlink_feed_conflict_strict")]
    pub chainlink_feed_conflict_strict: bool,
    #[serde(default = "default_chainlink_feed_audit_strict")]
    pub chainlink_feed_audit_strict: bool,
    #[serde(default = "default_bundle_use_replacement_uuid")]
    pub bundle_use_replacement_uuid: bool,
    #[serde(default = "default_bundle_cancel_previous")]
    pub bundle_cancel_previous: bool,
    #[serde(default = "default_bundle_target_blocks")]
    pub bundle_target_blocks: u64,
    #[serde(default = "default_feed_audit_max_lag_blocks")]
    pub feed_audit_max_lag_blocks: u64,
    #[serde(default = "default_feed_audit_recheck_secs")]
    pub feed_audit_recheck_secs: u64,
    pub feed_audit_public_rpc_url: Option<String>,
    #[serde(default = "default_feed_audit_public_tip_lag_blocks")]
    pub feed_audit_public_tip_lag_blocks: u64,
    #[serde(default = "default_flashloan_adaptive_scale_enabled")]
    pub flashloan_adaptive_scale_enabled: bool,
    #[serde(default = "default_flashloan_adaptive_min_scale_bps")]
    pub flashloan_adaptive_min_scale_bps: u64,
    #[serde(default = "default_flashloan_adaptive_downshift_step_bps")]
    pub flashloan_adaptive_downshift_step_bps: u64,
    #[serde(default = "default_router_risk_min_samples")]
    pub router_risk_min_samples: u64,
    #[serde(default = "default_router_risk_fail_rate_bps")]
    pub router_risk_fail_rate_bps: u64,
    #[serde(default = "default_false")]
    pub router_risk_hard_block: bool,
    #[serde(default = "default_sandwich_risk_max_victim_slippage_bps")]
    pub sandwich_risk_max_victim_slippage_bps: u64,
    #[serde(default = "default_sandwich_risk_small_wallet_wei")]
    pub sandwich_risk_small_wallet_wei: u128,
    #[serde(default = "default_toxic_probe_failure_threshold")]
    pub toxic_probe_failure_threshold: u32,
    #[serde(default = "default_toxic_probe_failure_window_secs")]
    pub toxic_probe_failure_window_secs: u64,
    #[serde(default = "default_balance_cap_curve_k")]
    pub balance_cap_curve_k: f64,
    #[serde(default = "default_balance_cap_min_bps")]
    pub balance_cap_min_bps: u64,
    #[serde(default = "default_balance_cap_max_bps")]
    pub balance_cap_max_bps: u64,
    #[serde(default = "default_auto_slippage_base_bps")]
    pub auto_slippage_base_bps: f64,
    #[serde(default = "default_auto_slippage_balance_log_slope")]
    pub auto_slippage_balance_log_slope: f64,
    #[serde(default = "default_auto_slippage_balance_scale")]
    pub auto_slippage_balance_scale: f64,
    #[serde(default = "default_auto_slippage_vol_mult_bps")]
    pub auto_slippage_vol_mult_bps: u64,
    #[serde(default = "default_auto_slippage_min_bps")]
    pub auto_slippage_min_bps: u64,
    #[serde(default = "default_auto_slippage_max_bps")]
    pub auto_slippage_max_bps: u64,
    #[serde(default = "default_false")]
    pub force_canonical_exec_router: bool,
    #[serde(default = "default_allow_unknown_router_decode")]
    pub allow_unknown_router_decode: bool,
    pub profit_floor_abs_eth: Option<f64>,
    #[serde(default = "default_profit_floor_mult_gas")]
    pub profit_floor_mult_gas: u64,
    pub profit_floor_min_usd: Option<f64>,
    pub gas_ratio_limit_floor_bps: Option<u64>,
    #[serde(default = "default_flashloan_prefer_wallet_max_wei")]
    pub flashloan_prefer_wallet_max_wei: u128,
    #[serde(default = "default_flashloan_value_scale_bps")]
    pub flashloan_value_scale_bps: u64,
    #[serde(default = "default_flashloan_min_notional_wei")]
    pub flashloan_min_notional_wei: u128,
    #[serde(default = "default_flashloan_min_repay_bps")]
    pub flashloan_min_repay_bps: u64,
    #[serde(default = "default_flashloan_reverse_input_bps")]
    pub flashloan_reverse_input_bps: u64,
    #[serde(default = "default_flashloan_prefilter_margin_bps")]
    pub flashloan_prefilter_margin_bps: u64,
    #[serde(default)]
    pub flashloan_prefilter_margin_wei: u128,
    #[serde(default)]
    pub flashloan_prefilter_gas_cost_bps: u64,
    #[serde(default = "default_flashloan_reject_same_router_negative")]
    pub flashloan_reject_same_router_negative: bool,
    #[serde(default)]
    pub flashloan_force: bool,
    #[serde(default)]
    pub flashloan_aggressive: bool,
    #[serde(default = "default_deadline_min_seconds_ahead")]
    pub deadline_min_seconds_ahead: u64,
    #[serde(default = "default_deadline_allow_past_secs")]
    pub deadline_allow_past_secs: u64,
    #[serde(default = "default_liquidation_scan_cooldown_secs")]
    pub liquidation_scan_cooldown_secs: u64,
    #[serde(default = "default_atomic_arb_scan_cooldown_secs")]
    pub atomic_arb_scan_cooldown_secs: u64,
    #[serde(default = "default_true")]
    pub strategy_atomic_arb_enabled: bool,
    #[serde(default = "default_true")]
    pub strategy_liquidation_enabled: bool,
    #[serde(default = "default_true")]
    pub strategy_require_tokenlist: bool,
    #[serde(default = "default_atomic_arb_gas_hint")]
    pub atomic_arb_gas_hint: u64,
    #[serde(default = "default_atomic_arb_max_candidates")]
    pub atomic_arb_max_candidates: usize,
    #[serde(default = "default_atomic_arb_max_attempts")]
    pub atomic_arb_max_attempts: usize,
    #[serde(default = "default_atomic_arb_seed_wei")]
    pub atomic_arb_seed_wei: u128,
    #[serde(default)]
    pub flashloan_allow_nonflash_fallback: bool,

    // Router discovery
    #[serde(default = "default_router_discovery_enabled")]
    pub router_discovery_enabled: bool,
    #[serde(default = "default_router_discovery_min_hits")]
    pub router_discovery_min_hits: u64,
    #[serde(default = "default_router_discovery_flush_every")]
    pub router_discovery_flush_every: u64,
    #[serde(default = "default_router_discovery_check_interval_secs")]
    pub router_discovery_check_interval_secs: u64,
    #[serde(default = "default_router_discovery_auto_allow")]
    pub router_discovery_auto_allow: bool,
    #[serde(default = "default_router_discovery_max_entries")]
    pub router_discovery_max_entries: usize,
    #[serde(default = "default_router_discovery_bootstrap_limit")]
    pub router_discovery_bootstrap_limit: usize,
    #[serde(default = "default_router_discovery_bootstrap_lookback_blocks")]
    pub router_discovery_bootstrap_lookback_blocks: u64,
    #[serde(default = "default_router_discovery_max_rpc_calls_per_cycle")]
    pub router_discovery_max_rpc_calls_per_cycle: u64,
    #[serde(default = "default_router_discovery_cycle_timeout_ms")]
    pub router_discovery_cycle_timeout_ms: u64,
    #[serde(default = "default_router_discovery_failure_budget")]
    pub router_discovery_failure_budget: u64,
    #[serde(default = "default_router_discovery_cooldown_secs")]
    pub router_discovery_cooldown_secs: u64,
    pub router_discovery_cache_path: Option<String>,
    #[serde(default = "default_false")]
    pub router_discovery_force_full_rescan: bool,

    // Per-chain maps
    pub router_allowlist_by_chain: Option<HashMap<String, HashMap<String, String>>>,
    pub chainlink_feeds_by_chain: Option<HashMap<String, HashMap<String, String>>>,
    pub chainlink_feeds_by_chain_eth: Option<HashMap<String, HashMap<String, String>>>,
    pub binance_api_key: Option<String>,
    pub coinmarketcap_api_key: Option<String>,
    pub coingecko_api_key: Option<String>,
    pub cryptocompare_api_key: Option<String>,
    pub coindesk_api_key: Option<String>,
    pub etherscan_api_key: Option<String>,
}

// Defaults
fn default_debug() -> bool {
    false
}
fn default_chain() -> Vec<u64> {
    Vec::new()
}
fn default_max_gas() -> u64 {
    500
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_metrics_port() -> u16 {
    9000
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_slippage_bps() -> u64 {
    12
}
fn default_profit_guard_base_floor_multiplier_bps() -> u64 {
    1_000
}
fn default_profit_guard_cost_multiplier_bps() -> u64 {
    10_000
}
fn default_profit_guard_min_margin_bps() -> u64 {
    0
}
fn default_liquidity_ratio_floor_ppm() -> u64 {
    0
}
fn default_sell_min_native_out_wei() -> u64 {
    1
}
fn default_gas_cap_multiplier_bps() -> u64 {
    12_000
}
fn default_skip_log_every() -> u64 {
    500
}
fn default_allow_non_wrapped_swaps() -> bool {
    true
}
fn default_sim_backend() -> String {
    "debug_tracecall".to_string()
}
fn default_flashloan_provider() -> String {
    "auto,aavev3,balancer".to_string()
}
fn default_mev_share_url() -> String {
    "https://mev-share.flashbots.net".to_string()
}
fn default_mev_share_history_limit() -> u32 {
    200
}
fn default_mevshare_builders() -> Vec<String> {
    vec![
        "flashbots".to_string(),
        "beaverbuild.org".to_string(),
        "rsync".to_string(),
        "Titan".to_string(),
    ]
}
fn default_receipt_poll_ms() -> u64 {
    500
}
fn default_receipt_timeout_ms() -> u64 {
    12_000
}
fn default_receipt_confirm_blocks() -> u64 {
    4
}
fn default_rpc_capability_strict() -> bool {
    true
}
fn default_chainlink_feed_conflict_strict() -> bool {
    true
}
fn default_chainlink_feed_audit_strict() -> bool {
    false
}
fn default_bundle_use_replacement_uuid() -> bool {
    true
}
fn default_bundle_cancel_previous() -> bool {
    false
}
fn default_bundle_target_blocks() -> u64 {
    1
}
fn default_feed_audit_max_lag_blocks() -> u64 {
    20
}
fn default_feed_audit_recheck_secs() -> u64 {
    20
}
fn default_feed_audit_public_tip_lag_blocks() -> u64 {
    2
}
fn default_flashloan_adaptive_scale_enabled() -> bool {
    true
}
fn default_flashloan_adaptive_min_scale_bps() -> u64 {
    1_500
}
fn default_flashloan_adaptive_downshift_step_bps() -> u64 {
    700
}
fn default_router_risk_min_samples() -> u64 {
    20
}
fn default_router_risk_fail_rate_bps() -> u64 {
    4_000
}
fn default_sandwich_risk_max_victim_slippage_bps() -> u64 {
    1_500
}
fn default_sandwich_risk_small_wallet_wei() -> u128 {
    100_000_000_000_000_000u128
}
fn default_toxic_probe_failure_threshold() -> u32 {
    3
}
fn default_toxic_probe_failure_window_secs() -> u64 {
    1_800
}
fn default_balance_cap_curve_k() -> f64 {
    0.8
}
fn default_balance_cap_min_bps() -> u64 {
    8_000
}
fn default_balance_cap_max_bps() -> u64 {
    14_000
}
fn default_auto_slippage_base_bps() -> f64 {
    120.0
}
fn default_auto_slippage_balance_log_slope() -> f64 {
    30.0
}
fn default_auto_slippage_balance_scale() -> f64 {
    100.0
}
fn default_auto_slippage_vol_mult_bps() -> u64 {
    3_500
}
fn default_auto_slippage_min_bps() -> u64 {
    15
}
fn default_auto_slippage_max_bps() -> u64 {
    500
}
fn default_allow_unknown_router_decode() -> bool {
    true
}
fn default_profit_floor_mult_gas() -> u64 {
    1
}
fn default_flashloan_prefer_wallet_max_wei() -> u128 {
    50_000_000_000_000_000u128
}
fn default_flashloan_value_scale_bps() -> u64 {
    7_000
}
fn default_flashloan_min_notional_wei() -> u128 {
    30_000_000_000_000u128
}
fn default_flashloan_min_repay_bps() -> u64 {
    9_000
}
fn default_flashloan_reverse_input_bps() -> u64 {
    10_000
}
fn default_flashloan_prefilter_margin_bps() -> u64 {
    10
}
fn default_flashloan_reject_same_router_negative() -> bool {
    true
}
fn default_deadline_min_seconds_ahead() -> u64 {
    2
}
fn default_deadline_allow_past_secs() -> u64 {
    0
}
fn default_liquidation_scan_cooldown_secs() -> u64 {
    4
}
fn default_atomic_arb_scan_cooldown_secs() -> u64 {
    10
}
fn default_atomic_arb_gas_hint() -> u64 {
    260_000
}
fn default_atomic_arb_max_candidates() -> usize {
    10
}
fn default_atomic_arb_max_attempts() -> usize {
    2
}
fn default_atomic_arb_seed_wei() -> u128 {
    3_000_000_000_000_000u128
}
fn default_bribe_bps() -> u64 {
    0
}
fn default_router_discovery_enabled() -> bool {
    true
}
fn default_router_discovery_min_hits() -> u64 {
    25
}
fn default_router_discovery_flush_every() -> u64 {
    50
}
fn default_router_discovery_check_interval_secs() -> u64 {
    300
}
fn default_router_discovery_auto_allow() -> bool {
    false
}
fn default_router_discovery_max_entries() -> usize {
    10_000
}
fn default_router_discovery_bootstrap_limit() -> usize {
    256
}
fn default_router_discovery_bootstrap_lookback_blocks() -> u64 {
    256
}
fn default_router_discovery_max_rpc_calls_per_cycle() -> u64 {
    512
}
fn default_router_discovery_cycle_timeout_ms() -> u64 {
    7_500
}
fn default_router_discovery_failure_budget() -> u64 {
    16
}
fn default_router_discovery_cooldown_secs() -> u64 {
    45
}

fn deserialize_chain_list<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error, SeqAccess, Visitor};
    use std::fmt;

    struct ChainVisitor;

    impl<'de> Visitor<'de> for ChainVisitor {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of chain ids or a string with comma-separated ids")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            parse_chain_list(v).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(elem) = seq.next_element::<u64>()? {
                out.push(elem);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(ChainVisitor)
}

#[derive(Clone, Copy)]
struct EnvFieldSpec {
    field: &'static str,
    target_env_key: &'static str,
    canonical_key: &'static str,
    aliases: &'static [&'static str],
    required: bool,
    redact: bool,
    deprecated_since: Option<&'static str>,
    remove_after: Option<&'static str>,
}

impl EnvFieldSpec {
    fn all() -> &'static [EnvFieldSpec] {
        &[
            EnvFieldSpec {
                field: "wallet_key",
                target_env_key: "WALLET_KEY",
                canonical_key: "OXIDITY_WALLET_PRIVATE_KEY",
                aliases: &["WALLET_KEY", "WALLET_PRIVATE_KEY"],
                required: true,
                redact: true,
                deprecated_since: Some("0.1.1"),
                remove_after: Some("0.3.0"),
            },
            EnvFieldSpec {
                field: "wallet_address",
                target_env_key: "WALLET_ADDRESS",
                canonical_key: "OXIDITY_WALLET_ADDRESS",
                aliases: &["WALLET_ADDRESS"],
                required: true,
                redact: false,
                deprecated_since: Some("0.1.1"),
                remove_after: Some("0.3.0"),
            },
            EnvFieldSpec {
                field: "executor_address",
                target_env_key: "EXECUTOR_ADDRESS",
                canonical_key: "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
                aliases: &["FLASHLOAN_CONTRACT_ADDRESS", "EXECUTOR_ADDRESS"],
                required: true,
                redact: false,
                deprecated_since: Some("0.1.1"),
                remove_after: Some("0.3.0"),
            },
            EnvFieldSpec {
                field: "bundle_signer_key",
                target_env_key: "BUNDLE_SIGNER_KEY",
                canonical_key: "OXIDITY_BUNDLE_PRIVATE_KEY",
                aliases: &["BUNDLE_SIGNER_KEY", "BUNDLE_PRIVATE_KEY"],
                required: true,
                redact: true,
                deprecated_since: Some("0.1.1"),
                remove_after: Some("0.3.0"),
            },
            EnvFieldSpec {
                field: "log_level",
                target_env_key: "LOG_LEVEL",
                canonical_key: "OXIDITY_LOG_LEVEL",
                aliases: &["LOG_LEVEL", "RUST_LOG"],
                required: false,
                redact: false,
                deprecated_since: Some("0.1.1"),
                remove_after: Some("0.3.0"),
            },
        ]
    }
}

#[derive(Default)]
struct EnvResolution {
    overrides: Map<String, String>,
    field_sources: Vec<ConfigFieldSource>,
    warnings: Vec<String>,
    config_debug: bool,
}

fn redact_value(raw: &str, redact: bool) -> String {
    if redact {
        if raw.trim().is_empty() {
            return "<empty>".to_string();
        }
        return "<redacted>".to_string();
    }
    raw.to_string()
}

fn is_passthrough_env_key(key: &str) -> bool {
    const EXACT: &[&str] = &[
        "CHAINS",
        "DATABASE_URL",
        "FLASHBOTS_RELAY_URL",
        "MEV_SHARE_RELAY_URL",
        "MEV_SHARE_STREAM_URL",
        "MEV_SHARE_ENABLED",
        "MEV_SHARE_HISTORY_LIMIT",
        "METRICS_BIND",
        "METRICS_TOKEN",
        "METRICS_PORT",
        "METRICS_ENABLE_SHUTDOWN",
        "DATA_DIR",
        "TOKENLIST_PATH",
        "ADDRESS_REGISTRY_PATH",
        "PAIRS_PATH",
        "CHAINLINK_FEEDS_PATH",
        "STRATEGY_WORKERS",
        "ETHERSCAN_API_KEY",
        "BINANCE_API_KEY",
        "COINMARKETCAP_API_KEY",
        "COINGECKO_API_KEY",
        "CRYPTOCOMPARE_API_KEY",
        "COINDESK_API_KEY",
        "PROFIT_FLOOR_ABS_ETH",
        "PROFIT_FLOOR_MULT_GAS",
        "PROFIT_FLOOR_MIN_USD",
        "GAS_RATIO_LIMIT_FLOOR_BPS",
        "BUNDLE_TARGET_BLOCKS",
        "CHAINLINK_FEED_CONFLICT_STRICT",
        "CHAINLINK_FEED_AUDIT_STRICT",
        "RPC_CAPABILITY_STRICT",
        "BUNDLE_USE_REPLACEMENT_UUID",
        "BUNDLE_CANCEL_PREVIOUS",
        "ALLOW_UNKNOWN_ROUTER_DECODE",
        "FORCE_CANONICAL_EXEC_ROUTER",
        "ROUTER_RISK_MIN_SAMPLES",
        "ROUTER_RISK_FAIL_RATE_BPS",
        "ROUTER_RISK_HARD_BLOCK",
        "SANDWICH_RISK_MAX_VICTIM_SLIPPAGE_BPS",
        "SANDWICH_RISK_SMALL_WALLET_WEI",
        "TOXIC_PROBE_FAILURE_THRESHOLD",
        "TOXIC_PROBE_FAILURE_WINDOW_SECS",
        "BALANCE_CAP_CURVE_K",
        "BALANCE_CAP_MIN_BPS",
        "BALANCE_CAP_MAX_BPS",
        "AUTO_SLIPPAGE_BASE_BPS",
        "AUTO_SLIPPAGE_BALANCE_LOG_SLOPE",
        "AUTO_SLIPPAGE_BALANCE_SCALE",
        "AUTO_SLIPPAGE_VOL_MULT_BPS",
        "AUTO_SLIPPAGE_MIN_BPS",
        "AUTO_SLIPPAGE_MAX_BPS",
        "FLASHLOAN_ADAPTIVE_SCALE_ENABLED",
        "FLASHLOAN_ADAPTIVE_MIN_SCALE_BPS",
        "FLASHLOAN_ADAPTIVE_DOWNSHIFT_STEP_BPS",
        "FLASHLOAN_PREFER_WALLET_MAX_WEI",
        "FLASHLOAN_VALUE_SCALE_BPS",
        "FLASHLOAN_MIN_NOTIONAL_WEI",
        "FLASHLOAN_MIN_REPAY_BPS",
        "FLASHLOAN_REVERSE_INPUT_BPS",
        "FLASHLOAN_PREFILTER_MARGIN_BPS",
        "FLASHLOAN_PREFILTER_MARGIN_WEI",
        "FLASHLOAN_PREFILTER_GAS_COST_BPS",
        "FLASHLOAN_REJECT_SAME_ROUTER_NEGATIVE",
        "FLASHLOAN_FORCE",
        "FLASHLOAN_AGGRESSIVE",
        "FLASHLOAN_ALLOW_NONFLASH_FALLBACK",
        "DEADLINE_MIN_SECONDS_AHEAD",
        "DEADLINE_ALLOW_PAST_SECS",
        "LIQUIDATION_SCAN_COOLDOWN_SECS",
        "ATOMIC_ARB_SCAN_COOLDOWN_SECS",
        "STRATEGY_ATOMIC_ARB_ENABLED",
        "STRATEGY_LIQUIDATION_ENABLED",
        "STRATEGY_REQUIRE_TOKENLIST",
        "ATOMIC_ARB_GAS_HINT",
        "ATOMIC_ARB_MAX_CANDIDATES",
        "ATOMIC_ARB_MAX_ATTEMPTS",
        "ATOMIC_ARB_SEED_WEI",
        "FEED_AUDIT_MAX_LAG_BLOCKS",
        "FEED_AUDIT_RECHECK_SECS",
        "FEED_AUDIT_PUBLIC_RPC_URL",
        "FEED_AUDIT_PUBLIC_TIP_LAG_BLOCKS",
    ];
    const PREFIXES: &[&str] = &[
        "HTTP_PROVIDER",
        "WEBSOCKET_PROVIDER",
        "WEBSOCKET_URL",
        "IPC_PROVIDER",
        "IPC_PATH",
        "GAS_CAPS_GWEI",
        "ROUTER_RISK_",
        "SANDWICH_RISK_",
        "FLASHLOAN_",
        "AUTO_SLIPPAGE_",
        "BALANCE_CAP_",
        "GAS_RATIO_",
        "CHAINLINK_",
        "ROUTER_DISCOVERY_",
    ];
    if EXACT.contains(&key) {
        return true;
    }
    PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

fn is_allowlisted_prefixed_env_key(key: &str) -> bool {
    if is_passthrough_env_key(key) {
        return true;
    }
    EnvFieldSpec::all().iter().any(|spec| {
        spec.target_env_key == key
            || spec
                .canonical_key
                .strip_prefix("OXIDITY_")
                .is_some_and(|k| k == key)
    })
}

fn resolve_env_contract() -> EnvResolution {
    let mut resolution = EnvResolution::default();
    let mut used_keys: HashSet<String> = HashSet::new();

    for spec in EnvFieldSpec::all() {
        let canonical = std::env::var(spec.canonical_key)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let mut alias_hit: Option<(&'static str, String)> = None;
        for alias in spec.aliases {
            if let Ok(raw) = std::env::var(alias) {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                alias_hit = Some((alias, trimmed.to_string()));
                break;
            }
        }

        let (selected_key, selected_value, selected_source) = match (canonical, alias_hit) {
            (Some(canonical_value), Some((alias, alias_value))) => {
                if canonical_value != alias_value {
                    resolution.warnings.push(format!(
                        "Config conflict for {}: canonical {} and legacy {} differ; canonical value selected",
                        spec.field, spec.canonical_key, alias
                    ));
                }
                (
                    Some(spec.canonical_key.to_string()),
                    Some(canonical_value),
                    "canonical".to_string(),
                )
            }
            (Some(canonical_value), None) => (
                Some(spec.canonical_key.to_string()),
                Some(canonical_value),
                "canonical".to_string(),
            ),
            (None, Some((alias, alias_value))) => {
                resolution.warnings.push(format!(
                    "Legacy env {} is deprecated for {}; use {} (deprecated since {}, remove after {})",
                    alias,
                    spec.field,
                    spec.canonical_key,
                    spec.deprecated_since.unwrap_or("n/a"),
                    spec.remove_after.unwrap_or("n/a")
                ));
                (
                    Some(alias.to_string()),
                    Some(alias_value),
                    "legacy_alias".to_string(),
                )
            }
            (None, None) => (None, None, "unset".to_string()),
        };

        if let Some(value) = selected_value.clone() {
            resolution
                .overrides
                .insert(spec.target_env_key.to_string(), value);
        }
        if let Some(key) = selected_key.clone() {
            used_keys.insert(key);
        }

        resolution.field_sources.push(ConfigFieldSource {
            field: spec.field.to_string(),
            canonical_key: spec.canonical_key.to_string(),
            selected_key: selected_key.clone(),
            selected_source,
            redacted_value: selected_value
                .as_deref()
                .map(|value| redact_value(value, spec.redact)),
            deprecated_since: spec.deprecated_since.map(ToString::to_string),
            remove_after: spec.remove_after.map(ToString::to_string),
        });
    }

    for (raw_key, raw_value) in std::env::vars() {
        let key = raw_key.trim().to_string();
        let value = raw_value.trim().to_string();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if used_keys.contains(&key) {
            continue;
        }
        if key == "OXIDITY_CONFIG_DEBUG" {
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ) {
                resolution.config_debug = true;
            }
            continue;
        }
        if let Some(stripped) = key.strip_prefix("OXIDITY_") {
            if stripped.is_empty() {
                continue;
            }
            if is_allowlisted_prefixed_env_key(stripped) {
                resolution
                    .overrides
                    .insert(stripped.to_string(), value.clone());
                used_keys.insert(key);
            } else {
                resolution.warnings.push(format!(
                    "Ignoring unsupported prefixed env key {} (not in allowlist)",
                    key
                ));
            }
            continue;
        }
        if is_passthrough_env_key(&key) {
            resolution.overrides.insert(key.clone(), value);
        }
    }

    resolution
}

fn redact_effective_config(value: &mut Value) {
    const SECRET_FIELDS: &[&str] = &[
        "wallet_key",
        "bundle_signer_key",
        "metrics_token",
        "binance_api_key",
        "coinmarketcap_api_key",
        "coingecko_api_key",
        "cryptocompare_api_key",
        "coindesk_api_key",
        "etherscan_api_key",
    ];
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if SECRET_FIELDS.contains(&k.as_str()) {
                    *v = json!("<redacted>");
                } else {
                    redact_effective_config(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_effective_config(item);
            }
        }
        _ => {}
    }
}

fn effective_config_hash(settings: &GlobalSettings) -> String {
    let mut value = serde_json::to_value(settings).unwrap_or_else(|_| json!({}));
    redact_effective_config(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    format!("0x{}", hex::encode(keccak256(bytes)))
}

impl GlobalSettings {
    pub fn load_with_path(path: Option<&str>) -> Result<Self, AppError> {
        Ok(Self::load_with_report(path)?.settings)
    }

    pub fn load_with_report(path: Option<&str>) -> Result<LoadedSettings, AppError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let selected_config = resolve_config_path(path);
        let env_resolution = resolve_env_contract();
        let mut builder = Config::builder();

        if let Some(ref selected_path) = selected_config {
            builder = builder.add_source(File::from(Path::new(selected_path)).required(true));
        } else {
            builder = builder.add_source(File::with_name("config").required(false));
        }
        // Deterministic precedence: CLI (in main) > allowlisted env/.env > selected profile file.
        builder = builder.add_source(
            Environment::default()
                .source(Some(env_resolution.overrides.clone()))
                .try_parsing(true)
                .ignore_empty(true),
        );

        let mut settings: GlobalSettings = builder.build()?.try_deserialize()?;

        // Allow CHAINS env to be comma/space separated string (e.g. "1,137")
        if let Some(chains_str) = env_resolution.overrides.get("CHAINS") {
            settings.chains = parse_chain_list(chains_str)?;
        }

        let mut missing_required: Vec<&str> = Vec::new();
        for spec in EnvFieldSpec::all().iter().filter(|s| s.required) {
            let has_value = match spec.field {
                "wallet_key" => !settings.wallet_key.trim().is_empty(),
                "wallet_address" => settings.wallet_address != Address::ZERO,
                "executor_address" => settings.executor_address.is_some(),
                "bundle_signer_key" => settings
                    .bundle_signer_key
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|v| !v.is_empty()),
                _ => false,
            };
            if !has_value {
                missing_required.push(spec.canonical_key);
            }
        }
        if !missing_required.is_empty() {
            missing_required.sort();
            missing_required.dedup();
            return Err(AppError::Config(format!(
                "Missing required configuration values: {}",
                missing_required.join(", ")
            )));
        }

        let report = ConfigLoadReport {
            field_sources: env_resolution.field_sources,
            warnings: env_resolution.warnings,
            effective_config_hash: effective_config_hash(&settings),
        };

        Ok(LoadedSettings {
            settings,
            report,
            config_debug: env_resolution.config_debug,
        })
    }

    fn data_dir_value(&self) -> Option<String> {
        std::env::var("DATA_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.data_dir
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
    }

    pub fn data_dir(&self) -> Option<String> {
        self.data_dir_value()
    }

    fn resolve_path_setting(
        &self,
        env_key: &str,
        configured: Option<&str>,
        default_path: &str,
        required: bool,
    ) -> Result<String, AppError> {
        let raw = std::env::var(env_key)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                configured
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| default_path.to_string());
        let data_dir = self.data_dir_value();
        let resolved = if required {
            resolve_required_data_path(&raw, data_dir.as_deref())?
        } else {
            resolve_data_path(&raw, data_dir.as_deref())
        };
        Ok(resolved.to_string_lossy().to_string())
    }

    pub fn load() -> Result<Self, AppError> {
        Self::load_with_path(None)
    }

    fn first_non_empty_env<I, S>(keys: I) -> Option<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for key in keys {
            if let Ok(value) = std::env::var(key.as_ref()) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn provider_from_map(map: Option<&HashMap<String, String>>, chain_id: u64) -> Option<String> {
        map.and_then(|m| m.get(&chain_id.to_string()).cloned())
    }

    fn primary_provider_from_map(map: &HashMap<String, String>) -> Option<String> {
        if let Some((_, url)) = map
            .iter()
            .filter_map(|(k, v)| k.parse::<u64>().ok().map(|chain_id| (chain_id, v)))
            .min_by_key(|(chain_id, _)| *chain_id)
        {
            return Some(url.clone());
        }
        map.iter().next().map(|(_, url)| url.clone())
    }

    /// Best-effort primary HTTP RPC URL for chain auto-detection.
    pub fn primary_http_provider(&self) -> Option<String> {
        // Prefer explicit map entry with smallest numeric key.
        if let Some(map) = &self.http_providers
            && let Some(url) = Self::primary_provider_from_map(map)
        {
            return Some(url);
        }
        // Environment fallbacks (accept legacy lowercase and uppercase aliases).
        Self::first_non_empty_env([
            "HTTP_PROVIDER",
            "http_provider",
            "HTTP_PROVIDER_1",
            "http_provider_1",
        ])
    }

    /// Helper to get RPC URL for a specific chain
    pub fn get_http_provider(&self, chain_id: u64) -> Result<String, AppError> {
        if let Some(url) = Self::provider_from_map(self.http_providers.as_ref(), chain_id) {
            return Ok(url);
        }

        let candidates = [
            format!("HTTP_PROVIDER_{}", chain_id),
            format!("http_provider_{}", chain_id),
            "HTTP_PROVIDER".to_string(),
            "http_provider".to_string(),
        ];
        if let Some(url) = Self::first_non_empty_env(candidates) {
            return Ok(url);
        }

        Err(AppError::Config(format!(
            "No RPC URL found for chain {}",
            chain_id
        )))
    }

    /// Helper to get WS URL for a specific chain
    pub fn get_websocket_provider(&self, chain_id: u64) -> Result<String, AppError> {
        if let Some(url) = Self::provider_from_map(self.websocket_providers.as_ref(), chain_id) {
            return Ok(url);
        }

        let candidates = [
            format!("WEBSOCKET_PROVIDER_{}", chain_id),
            format!("WEBSOCKET_URL_{}", chain_id),
            "WEBSOCKET_PROVIDER".to_string(),
            "WEBSOCKET_URL".to_string(),
        ];

        if let Some(url) = Self::first_non_empty_env(candidates) {
            return Ok(url);
        }

        Err(AppError::Config(format!(
            "No WS URL found for chain {}",
            chain_id
        )))
    }

    /// Optional IPC URL for a specific chain, preferring explicit config and then env.
    pub fn get_ipc_provider(&self, chain_id: u64) -> Option<String> {
        if let Some(url) = Self::provider_from_map(self.ipc_providers.as_ref(), chain_id) {
            return Some(url);
        }

        let candidates = [
            format!("IPC_PROVIDER_{}", chain_id),
            format!("IPC_PATH_{}", chain_id),
            "IPC_PROVIDER".to_string(),
            "IPC_PATH".to_string(),
        ];

        Self::first_non_empty_env(candidates)
    }

    pub fn get_chainlink_feed(&self, symbol: &str) -> Option<String> {
        self.chainlink_feeds
            .as_ref()
            .and_then(|m| m.get(&symbol.to_uppercase()).cloned())
    }

    pub fn profit_receiver_or_wallet(&self) -> Address {
        self.profit_receiver_address.unwrap_or(self.wallet_address)
    }

    pub fn tokenlist_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "TOKENLIST_PATH",
            self.tokenlist_path.as_deref(),
            "data/tokenlist.json",
            true,
        )
    }

    pub fn address_registry_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "ADDRESS_REGISTRY_PATH",
            self.address_registry_path.as_deref(),
            "data/address_registry.json",
            true,
        )
    }

    pub fn pairs_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "PAIRS_PATH",
            self.pairs_path.as_deref(),
            "data/pairs.json",
            false,
        )
    }

    pub fn database_url(&self) -> String {
        std::env::var("DATABASE_URL")
            .ok()
            .or_else(|| self.database_url.clone())
            .unwrap_or_else(|| "sqlite://oxidity_searcher.db".to_string())
    }

    pub fn flashbots_relay_url(&self) -> String {
        self.flashbots_relay_url
            .clone()
            .or_else(|| std::env::var("FLASHBOTS_RELAY_URL").ok())
            .unwrap_or_else(|| "https://relay.flashbots.net".to_string())
    }

    pub fn router_discovery_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.router_discovery_check_interval_secs.max(30))
    }

    pub fn bundle_signer_key(&self) -> String {
        self.bundle_signer_key
            .clone()
            .unwrap_or_else(|| self.wallet_key.clone())
    }

    pub fn strategy_worker_limit(&self) -> usize {
        if let Ok(v) = std::env::var("STRATEGY_WORKERS")
            && let Ok(parsed) = v.parse::<usize>()
        {
            return parsed.max(1);
        }
        self.strategy_workers.unwrap_or(32).max(1)
    }

    pub fn metrics_bind_value(&self) -> Option<String> {
        self.metrics_bind.clone()
    }

    pub fn metrics_token_value(&self) -> Option<String> {
        self.metrics_token.clone()
    }

    pub fn metrics_enable_shutdown_value(&self) -> bool {
        self.metrics_enable_shutdown
    }

    pub fn etherscan_api_key_value(&self) -> Option<String> {
        self.etherscan_api_key.clone()
    }

    pub fn router_discovery_bootstrap_limit_value(&self) -> usize {
        self.router_discovery_bootstrap_limit.clamp(1, 10_000)
    }

    pub fn router_discovery_bootstrap_lookback_blocks_value(&self) -> u64 {
        self.router_discovery_bootstrap_lookback_blocks
            .clamp(1, 20_000)
    }

    pub fn router_discovery_max_rpc_calls_per_cycle_value(&self) -> u64 {
        self.router_discovery_max_rpc_calls_per_cycle
            .clamp(16, 20_000)
    }

    pub fn router_discovery_cycle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.router_discovery_cycle_timeout_ms.clamp(500, 60_000))
    }

    pub fn router_discovery_failure_budget_value(&self) -> u64 {
        self.router_discovery_failure_budget.clamp(1, 500)
    }

    pub fn router_discovery_cooldown(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.router_discovery_cooldown_secs.clamp(5, 3_600))
    }

    pub fn router_discovery_cache_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "ROUTER_DISCOVERY_CACHE_PATH",
            self.router_discovery_cache_path.as_deref(),
            "data/router_discovery_cache.json",
            false,
        )
    }

    pub fn gas_cap_for_chain(&self, chain_id: u64) -> Option<u64> {
        self.gas_caps_gwei
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()).cloned())
    }

    pub fn flashloan_providers(
        &self,
    ) -> Vec<crate::services::strategy::strategy::FlashloanProvider> {
        use crate::services::strategy::strategy::FlashloanProvider::*;
        let raw = self.flashloan_provider.to_lowercase();
        let mut parts: Vec<&str> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let mut auto = false;
        if let Some(pos) = parts.iter().position(|p| *p == "auto") {
            auto = true;
            parts.remove(pos);
        }
        let mut out = Vec::new();
        for p in parts {
            match p {
                "aave" | "aavev3" | "aave_v3" => out.push(AaveV3),
                "balancer" => out.push(Balancer),
                _ => {}
            }
        }
        if out.is_empty() && auto {
            out = vec![AaveV3, Balancer];
        }
        if out.is_empty() {
            out = vec![Balancer];
        }
        out
    }

    pub fn routers_for_chain(&self, chain_id: u64) -> Result<HashMap<String, Address>, AppError> {
        let mut out = constants::default_routers_for_chain(chain_id);

        if let Some(map) = self
            .router_allowlist_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            let parsed = parse_address_map(map, "router_allowlist_by_chain")?;
            out.extend(parsed);
        }

        Ok(out)
    }

    pub fn gas_cap_multiplier_bps_value(&self) -> u64 {
        self.gas_cap_multiplier_bps.max(10_000)
    }

    pub fn profit_guard_base_floor_multiplier_bps_value(&self) -> u64 {
        self.profit_guard_base_floor_multiplier_bps.clamp(0, 20_000)
    }

    pub fn profit_guard_cost_multiplier_bps_value(&self) -> u64 {
        self.profit_guard_cost_multiplier_bps.clamp(0, 20_000)
    }

    pub fn profit_guard_min_margin_bps_value(&self) -> u64 {
        self.profit_guard_min_margin_bps.clamp(0, 5_000)
    }

    pub fn liquidity_ratio_floor_ppm_value(&self) -> u64 {
        self.liquidity_ratio_floor_ppm.clamp(0, 10_000)
    }

    pub fn sell_min_native_out_wei_value(&self) -> u64 {
        self.sell_min_native_out_wei.max(1)
    }

    pub fn skip_log_every_value(&self) -> u64 {
        self.skip_log_every.max(1)
    }

    pub fn aave_pool_for_chain(&self, chain_id: u64) -> Option<Address> {
        if let Some(map) = self
            .aave_pools_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
            && let Ok(addr) = Address::from_str(map)
        {
            return Some(addr);
        }
        constants::default_aave_pool(chain_id)
    }

    pub fn chainlink_feeds_for_chain(
        &self,
        chain_id: u64,
    ) -> Result<HashMap<String, Address>, AppError> {
        let mut out: HashMap<String, Address> = HashMap::new();

        if let Some(map) = self
            .chainlink_feeds_by_chain
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            out.extend(parse_address_map(map, "chainlink_feeds_by_chain")?);
        }

        if let Some(map) = self
            .chainlink_feeds_by_chain_eth
            .as_ref()
            .and_then(|m| m.get(&chain_id.to_string()))
        {
            let parsed = parse_address_map(map, "chainlink_feeds_by_chain_eth")?;
            for (k, v) in parsed {
                out.insert(format!("{}_ETH", k), v);
            }
        }

        if out.is_empty()
            && let Some(map) = &self.chainlink_feeds
        {
            out.extend(parse_address_map(map, "chainlink_feeds")?);
        }

        if out.is_empty()
            && let Some(map) = load_chainlink_feeds_from_file(
                &self.chainlink_feeds_path()?,
                chain_id,
                self.chainlink_feed_conflict_strict_for_chain(chain_id),
            )?
        {
            out.extend(map);
        }

        if out.is_empty() {
            out = constants::default_chainlink_feeds(chain_id);
        }
        let mut stable_aliases: Vec<(String, Address)> = Vec::new();
        for (key, addr) in out.iter() {
            if let Some((base, quote)) = key.rsplit_once('_')
                && stable_quote(quote)
            {
                stable_aliases.push((base.to_uppercase(), *addr));
            }
        }
        for (base, addr) in stable_aliases {
            out.entry(base).or_insert(addr);
        }

        Ok(out)
    }

    pub fn chainlink_feeds_path(&self) -> Result<String, AppError> {
        self.resolve_path_setting(
            "CHAINLINK_FEEDS_PATH",
            self.chainlink_feeds_path.as_deref(),
            "data/chainlink_feeds.json",
            false,
        )
    }

    pub fn mev_share_relay_url(&self) -> String {
        if let Ok(v) = std::env::var("MEV_SHARE_RELAY_URL")
            && !v.trim().is_empty()
        {
            return v;
        }
        if let Some(v) = &self.mev_share_relay_url
            && !v.trim().is_empty()
        {
            return v.clone();
        }
        if let Ok(mut parsed) = Url::parse(&self.mev_share_stream_url) {
            parsed.set_path("");
            parsed.set_query(None);
            parsed.set_fragment(None);
            return parsed.to_string().trim_end_matches('/').to_string();
        }
        self.mev_share_stream_url.clone()
    }

    pub fn mevshare_builders_value(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .mevshare_builders
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if out.is_empty() {
            out = default_mevshare_builders();
        }
        out
    }

    pub fn receipt_poll_ms_value(&self) -> u64 {
        self.receipt_poll_ms.max(100)
    }

    pub fn receipt_timeout_ms_value(&self) -> u64 {
        self.receipt_timeout_ms.max(self.receipt_poll_ms_value())
    }

    pub fn receipt_confirm_blocks_value(&self) -> u64 {
        self.receipt_confirm_blocks.max(1)
    }

    pub fn rpc_capability_strict_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.rpc_capability_strict
        } else {
            false
        }
    }

    pub fn chainlink_feed_conflict_strict_for_chain(&self, _chain_id: u64) -> bool {
        env_bool("CHAINLINK_FEED_CONFLICT_STRICT").unwrap_or(self.chainlink_feed_conflict_strict)
    }

    pub fn chainlink_feed_audit_strict_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.chainlink_feed_audit_strict
        } else {
            false
        }
    }

    pub fn bundle_use_replacement_uuid_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.bundle_use_replacement_uuid
        } else {
            false
        }
    }

    pub fn bundle_cancel_previous_for_chain(&self, chain_id: u64) -> bool {
        if chain_id == constants::CHAIN_ETHEREUM {
            self.bundle_cancel_previous
        } else {
            false
        }
    }

    pub fn bundle_target_blocks_value(&self) -> u64 {
        self.bundle_target_blocks.clamp(1, 5)
    }

    pub fn feed_audit_max_lag_blocks_value(&self) -> u64 {
        self.feed_audit_max_lag_blocks.max(1)
    }

    pub fn feed_audit_recheck_secs_value(&self) -> u64 {
        self.feed_audit_recheck_secs.max(5)
    }

    pub fn feed_audit_public_rpc_url_value(&self) -> Option<String> {
        self.feed_audit_public_rpc_url
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn feed_audit_public_tip_lag_blocks_value(&self) -> u64 {
        self.feed_audit_public_tip_lag_blocks.clamp(1, 64)
    }

    pub fn strategy_runtime_settings(&self) -> StrategyRuntimeSettings {
        let profit_floor_abs_wei = self
            .profit_floor_abs_eth
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(|eth| {
                let wei = (eth * 1_000_000_000_000_000_000f64).round();
                if !wei.is_finite() || wei <= 0.0 {
                    U256::ZERO
                } else if wei > u128::MAX as f64 {
                    U256::from(u128::MAX)
                } else {
                    U256::from(wei as u128)
                }
            })
            .unwrap_or(U256::ZERO);

        StrategyRuntimeSettings {
            flashloan_adaptive_scale_enabled: self.flashloan_adaptive_scale_enabled,
            flashloan_adaptive_min_scale_bps: self
                .flashloan_adaptive_min_scale_bps
                .clamp(500, 10_000),
            flashloan_adaptive_downshift_step_bps: self
                .flashloan_adaptive_downshift_step_bps
                .clamp(50, 5_000),
            router_risk_min_samples: self.router_risk_min_samples.clamp(1, 500),
            router_risk_fail_rate_bps: self.router_risk_fail_rate_bps.clamp(500, 10_000),
            router_risk_hard_block: self.router_risk_hard_block,
            sandwich_risk_max_victim_slippage_bps: self
                .sandwich_risk_max_victim_slippage_bps
                .clamp(100, 9_500),
            sandwich_risk_small_wallet_wei: U256::from(
                self.sandwich_risk_small_wallet_wei
                    .clamp(1_000_000_000_000_000u128, 5_000_000_000_000_000_000u128),
            ),
            toxic_probe_failure_threshold: self.toxic_probe_failure_threshold.clamp(1, 20),
            toxic_probe_failure_window_secs: self.toxic_probe_failure_window_secs.clamp(30, 86_400),
            balance_cap_curve_k: self.balance_cap_curve_k.clamp(0.01, 10.0),
            balance_cap_min_bps: self.balance_cap_min_bps.clamp(1, 20_000),
            balance_cap_max_bps: self
                .balance_cap_max_bps
                .max(self.balance_cap_min_bps.clamp(1, 20_000))
                .clamp(1, 20_000),
            auto_slippage_base_bps: self.auto_slippage_base_bps.clamp(1.0, 5_000.0),
            auto_slippage_balance_log_slope: self.auto_slippage_balance_log_slope.clamp(0.0, 500.0),
            auto_slippage_balance_scale: self.auto_slippage_balance_scale.clamp(1.0, 10_000.0),
            auto_slippage_vol_mult_bps: self.auto_slippage_vol_mult_bps.clamp(0, 50_000),
            auto_slippage_min_bps: self.auto_slippage_min_bps.clamp(1, 9_999),
            auto_slippage_max_bps: self
                .auto_slippage_max_bps
                .max(self.auto_slippage_min_bps.clamp(1, 9_999))
                .clamp(1, 9_999),
            force_canonical_exec_router: self.force_canonical_exec_router,
            allow_unknown_router_decode: self.allow_unknown_router_decode,
            profit_floor_abs_wei,
            profit_floor_mult_gas: self.profit_floor_mult_gas.clamp(1, 100),
            profit_floor_min_usd: self
                .profit_floor_min_usd
                .filter(|v| v.is_finite() && *v > 0.0),
            gas_ratio_limit_floor_bps: self.gas_ratio_limit_floor_bps.map(|v| v.clamp(0, 9_999)),
            flashloan_prefer_wallet_max_wei: U256::from(self.flashloan_prefer_wallet_max_wei),
            flashloan_value_scale_bps: self.flashloan_value_scale_bps.clamp(50, 10_000),
            flashloan_min_notional_wei: U256::from(self.flashloan_min_notional_wei),
            flashloan_min_repay_bps: self.flashloan_min_repay_bps.clamp(7_000, 12_000),
            flashloan_reverse_input_bps: self.flashloan_reverse_input_bps.clamp(9_500, 10_000),
            flashloan_prefilter_margin_bps: self.flashloan_prefilter_margin_bps.clamp(0, 2_000),
            flashloan_prefilter_margin_wei: U256::from(self.flashloan_prefilter_margin_wei),
            flashloan_prefilter_gas_cost_bps: self
                .flashloan_prefilter_gas_cost_bps
                .clamp(0, 10_000),
            flashloan_reject_same_router_negative: self.flashloan_reject_same_router_negative,
            flashloan_force: self.flashloan_force,
            flashloan_aggressive: self.flashloan_aggressive,
            deadline_min_seconds_ahead: self.deadline_min_seconds_ahead.clamp(0, 300),
            deadline_allow_past_secs: self.deadline_allow_past_secs.clamp(0, 900),
            liquidation_scan_cooldown_secs: self.liquidation_scan_cooldown_secs.clamp(1, 120),
            atomic_arb_scan_cooldown_secs: self.atomic_arb_scan_cooldown_secs.clamp(1, 120),
            strategy_atomic_arb_enabled: self.strategy_atomic_arb_enabled,
            strategy_liquidation_enabled: self.strategy_liquidation_enabled,
            strategy_require_tokenlist: self.strategy_require_tokenlist,
            atomic_arb_gas_hint: self.atomic_arb_gas_hint.clamp(120_000, 700_000),
            atomic_arb_max_candidates: self.atomic_arb_max_candidates.clamp(2, 64),
            atomic_arb_max_attempts: self.atomic_arb_max_attempts.clamp(1, 8),
            atomic_arb_seed_wei: U256::from(self.atomic_arb_seed_wei),
            flashloan_allow_nonflash_fallback: self.flashloan_allow_nonflash_fallback,
        }
    }

    pub fn price_api_keys(&self) -> crate::network::price_feed::PriceApiKeys {
        crate::network::price_feed::PriceApiKeys {
            binance: self.binance_api_key.clone(),
            coinmarketcap: self.coinmarketcap_api_key.clone(),
            coingecko: self.coingecko_api_key.clone(),
            cryptocompare: self.cryptocompare_api_key.clone(),
            coindesk: self.coindesk_api_key.clone(),
            etherscan: self.etherscan_api_key.clone(),
        }
    }
}

impl LoadedSettings {
    pub fn effective_config_json(&self) -> Value {
        let mut value = serde_json::to_value(&self.settings).unwrap_or_else(|_| json!({}));
        redact_effective_config(&mut value);
        value
    }
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key).ok().as_deref().and_then(parse_boolish)
}

fn resolve_config_path(path: Option<&str>) -> Option<String> {
    if let Some(path) = path {
        return Some(path.to_string());
    }
    detect_active_config_file()
}

fn detect_active_config_file() -> Option<String> {
    // Check common config.*.toml files first
    let priority_files = [
        "config.prod.toml",
        "config.dev.toml",
        "config.testnet.toml",
        "config.example.toml",
        "config.toml",
    ];

    for file in priority_files.iter() {
        if let Some(true) = config_has_active_flag(file) {
            return Some((*file).to_string());
        }
    }

    // Fallback: scan current dir for config.*.toml with THIS_ACTIVE = true
    if let Ok(entries) = fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("config.")
                && name.ends_with(".toml")
                && let Some(true) = config_has_active_flag(name)
            {
                return Some(name.to_string());
            }
        }
    }

    None
}

fn config_has_active_flag(path: &str) -> Option<bool> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }

    Config::builder()
        .add_source(File::from(p))
        .build()
        .ok()?
        .get_bool("THIS_ACTIVE")
        .ok()
}

fn parse_chain_list(raw: &str) -> Result<Vec<u64>, AppError> {
    let cleaned = raw.trim_matches(|c| c == '`' || c == '"' || c == '\'');
    let mut out = Vec::new();
    for part in cleaned.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let id: u64 = p
            .parse()
            .map_err(|_| AppError::Config(format!("Invalid chain id '{}'", p)))?;
        out.push(id);
    }
    if out.is_empty() {
        return Err(AppError::Config("CHAINS env is empty".into()));
    }
    Ok(out)
}

fn parse_address_map(
    raw: &HashMap<String, String>,
    field: &str,
) -> Result<HashMap<String, Address>, AppError> {
    raw.iter()
        .map(|(k, v)| {
            Address::from_str(v)
                .map(|addr| (k.to_uppercase(), addr))
                .map_err(|_| AppError::InvalidAddress(format!("{field}:{k} -> {v}")))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainlinkFeedEntry {
    base: String,
    quote: String,
    chain_id: u64,
    address: String,
}

fn alias_base_symbol(base: &str) -> String {
    match base.to_uppercase().as_str() {
        "WETH" => "ETH".to_string(),
        "WBTC" => "BTC".to_string(),
        other => other.to_string(),
    }
}

fn quote_priority(quote: &str) -> usize {
    match quote {
        "USD" => 0,
        "USDT" | "USDC" => 1,
        "ETH" => 2,
        _ => 3,
    }
}

fn stable_quote(quote: &str) -> bool {
    matches!(quote, "USD" | "USDT" | "USDC")
}

#[derive(Clone, Debug)]
struct NormalizedChainlinkFeedEntry {
    base: String,
    quote: String,
    address: Address,
    index: usize,
}

fn normalize_chainlink_feed_entries(
    entries: Vec<ChainlinkFeedEntry>,
    chain_id: u64,
) -> Result<(Vec<NormalizedChainlinkFeedEntry>, usize), AppError> {
    let mut dedupe = HashSet::new();
    let mut normalized = Vec::new();
    let mut deduped_count = 0usize;

    for (index, entry) in entries.into_iter().enumerate() {
        if entry.chain_id != chain_id {
            continue;
        }
        let base = alias_base_symbol(&entry.base);
        let quote = entry.quote.to_uppercase();
        let address = Address::from_str(&entry.address).map_err(|_| {
            AppError::InvalidAddress(format!("chainlink_feeds:{base} -> {}", entry.address))
        })?;
        let dedupe_key = format!("{base}|{quote}|{:#x}", address);
        if !dedupe.insert(dedupe_key) {
            deduped_count = deduped_count.saturating_add(1);
            continue;
        }
        normalized.push(NormalizedChainlinkFeedEntry {
            base,
            quote,
            address,
            index,
        });
    }

    Ok((normalized, deduped_count))
}

fn load_chainlink_feeds_from_file(
    path: &str,
    chain_id: u64,
    strict_conflicts: bool,
) -> Result<Option<HashMap<String, Address>>, AppError> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(file_path)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json read failed: {}", e)))?;
    let entries: Vec<ChainlinkFeedEntry> = serde_json::from_str(&raw)
        .map_err(|e| AppError::Config(format!("chainlink_feeds json parse failed: {}", e)))?;
    let (normalized_entries, deduped_count) = normalize_chainlink_feed_entries(entries, chain_id)?;

    let canonical = constants::default_chainlink_feeds(chain_id);
    let mut selected: HashMap<String, (String, Address, usize, usize)> = HashMap::new();
    let mut by_base_quote: HashMap<(String, String), Vec<Address>> = HashMap::new();
    let seen_any = !normalized_entries.is_empty() || deduped_count > 0;
    for entry in normalized_entries {
        let base = entry.base;
        let quote = entry.quote;
        let addr = entry.address;
        let index = entry.index;
        by_base_quote
            .entry((base.clone(), quote.clone()))
            .or_default()
            .push(addr);

        let new_score = quote_priority(&quote);
        let canonical_key = format!("{}_{}", base, quote);
        let canonical_rank = match canonical.get(&canonical_key) {
            Some(expected) if *expected == addr => 0usize,
            _ => 1usize,
        };
        let replace = match selected.get(&base) {
            None => true,
            Some((existing_quote, existing_addr, existing_canonical_rank, existing_index)) => {
                let existing_score = quote_priority(existing_quote);
                if new_score != existing_score {
                    new_score < existing_score
                } else if canonical_rank != *existing_canonical_rank {
                    canonical_rank < *existing_canonical_rank
                } else if addr != *existing_addr {
                    addr.to_string().to_lowercase() < existing_addr.to_string().to_lowercase()
                } else {
                    index < *existing_index
                }
            }
        };

        if replace {
            selected.insert(base, (quote, addr, canonical_rank, index));
        }
    }
    if deduped_count > 0 {
        tracing::debug!(
            target: "config",
            chain_id,
            deduped = deduped_count,
            "Chainlink feed normalization removed duplicate entries"
        );
    }

    let mut resolved_conflicts: Vec<String> = Vec::new();
    let mut unresolved_conflicts: Vec<String> = Vec::new();
    for ((base, quote), addrs) in by_base_quote {
        let mut uniq: Vec<Address> = Vec::new();
        for addr in addrs {
            if !uniq.contains(&addr) {
                uniq.push(addr);
            }
        }
        if uniq.len() > 1 {
            uniq.sort();
            let list = uniq
                .iter()
                .map(|a| format!("{:#x}", a))
                .collect::<Vec<_>>()
                .join(",");
            let key = format!("{}_{}", base, quote);
            let canonical_addr = canonical.get(&key).copied();
            let selected_for_quote =
                selected
                    .get(&base)
                    .and_then(|(selected_quote, selected_addr, _, _)| {
                        if selected_quote == &quote {
                            Some(*selected_addr)
                        } else {
                            None
                        }
                    });
            let selected_str = selected_for_quote
                .map(|a| format!("{:#x}", a))
                .unwrap_or_else(|| "<not-selected>".to_string());
            let canonical_str = canonical_addr
                .map(|a| format!("{:#x}", a))
                .unwrap_or_else(|| "<none>".to_string());

            let canonical_resolves = canonical_addr
                .map(|addr| uniq.contains(&addr))
                .unwrap_or(false);
            let record = format!(
                "{base}/{quote} -> [{list}] selected={selected_str} canonical={canonical_str}"
            );
            if canonical_resolves {
                resolved_conflicts.push(record);
            } else {
                unresolved_conflicts.push(record);
            }
        }
    }
    if !resolved_conflicts.is_empty() {
        for conflict in resolved_conflicts.iter().take(12) {
            tracing::debug!(
                target: "config",
                chain_id,
                strict = strict_conflicts,
                conflict = %conflict,
                "Chainlink feed conflict resolved via canonical tie-break"
            );
        }
    }
    if !unresolved_conflicts.is_empty() {
        for conflict in unresolved_conflicts.iter().take(12) {
            tracing::warn!(
                target: "config",
                chain_id,
                strict = strict_conflicts,
                conflict = %conflict,
                "Chainlink feed conflict unresolved"
            );
        }
        if strict_conflicts {
            return Err(AppError::Config(format!(
                "chainlink_feeds contains unresolved conflicting duplicate base/quote feeds on chain {} ({} unresolved, {} resolved); strict mode rejects ambiguous feed sets",
                chain_id,
                unresolved_conflicts.len(),
                resolved_conflicts.len()
            )));
        }
    }

    if selected.is_empty() {
        if seen_any {
            tracing::warn!(
                target: "config",
                chain_id,
                "No usable Chainlink feed entries selected from chainlink_feeds file"
            );
        }
        return Ok(None);
    }

    let mut out = HashMap::new();
    for (base, (quote, addr, _, _)) in selected {
        out.insert(format!("{base}_{quote}"), addr);
        if stable_quote(&quote) {
            out.entry(base).or_insert(addr);
        }
    }

    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn env_lock_guard() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn base_settings() -> GlobalSettings {
        GlobalSettings {
            debug: default_debug(),
            chains: Vec::new(),
            database_url: None,
            wallet_key: "0x0".to_string(),
            wallet_address: Address::ZERO,
            profit_receiver_address: None,
            max_gas_price_gwei: default_max_gas(),
            simulation_backend: default_sim_backend(),
            flashloan_enabled: default_true(),
            flashloan_provider: default_flashloan_provider(),
            executor_address: None,
            sandwich_attacks_enabled: default_true(),
            http_providers: None,
            websocket_providers: None,
            ipc_providers: None,
            chainlink_feeds: None,
            chainlink_feeds_path: None,
            pairs_path: None,
            flashbots_relay_url: None,
            bundle_signer_key: None,
            executor_bribe_bps: default_bribe_bps(),
            executor_bribe_recipient: None,
            tokenlist_path: None,
            address_registry_path: None,
            data_dir: None,
            metrics_port: default_metrics_port(),
            log_level: default_log_level(),
            strategy_enabled: default_true(),
            strategy_workers: None,
            metrics_bind: None,
            metrics_token: None,
            metrics_enable_shutdown: default_false(),
            slippage_bps: default_slippage_bps(),
            profit_guard_base_floor_multiplier_bps: default_profit_guard_base_floor_multiplier_bps(
            ),
            profit_guard_cost_multiplier_bps: default_profit_guard_cost_multiplier_bps(),
            profit_guard_min_margin_bps: default_profit_guard_min_margin_bps(),
            liquidity_ratio_floor_ppm: default_liquidity_ratio_floor_ppm(),
            sell_min_native_out_wei: default_sell_min_native_out_wei(),
            gas_cap_multiplier_bps: default_gas_cap_multiplier_bps(),
            skip_log_every: default_skip_log_every(),
            allow_non_wrapped_swaps: default_allow_non_wrapped_swaps(),
            gas_caps_gwei: None,
            mev_share_stream_url: default_mev_share_url(),
            mev_share_relay_url: None,
            mev_share_history_limit: default_mev_share_history_limit(),
            mev_share_enabled: default_true(),
            mevshare_builders: default_mevshare_builders(),
            receipt_poll_ms: default_receipt_poll_ms(),
            receipt_timeout_ms: default_receipt_timeout_ms(),
            receipt_confirm_blocks: default_receipt_confirm_blocks(),
            emergency_exit_on_unknown_receipt: default_false(),
            rpc_capability_strict: default_rpc_capability_strict(),
            chainlink_feed_conflict_strict: default_chainlink_feed_conflict_strict(),
            chainlink_feed_audit_strict: default_chainlink_feed_audit_strict(),
            bundle_use_replacement_uuid: default_bundle_use_replacement_uuid(),
            bundle_cancel_previous: default_bundle_cancel_previous(),
            bundle_target_blocks: default_bundle_target_blocks(),
            feed_audit_max_lag_blocks: default_feed_audit_max_lag_blocks(),
            feed_audit_recheck_secs: default_feed_audit_recheck_secs(),
            feed_audit_public_rpc_url: None,
            feed_audit_public_tip_lag_blocks: default_feed_audit_public_tip_lag_blocks(),
            flashloan_adaptive_scale_enabled: default_flashloan_adaptive_scale_enabled(),
            flashloan_adaptive_min_scale_bps: default_flashloan_adaptive_min_scale_bps(),
            flashloan_adaptive_downshift_step_bps: default_flashloan_adaptive_downshift_step_bps(),
            router_risk_min_samples: default_router_risk_min_samples(),
            router_risk_fail_rate_bps: default_router_risk_fail_rate_bps(),
            router_risk_hard_block: default_false(),
            sandwich_risk_max_victim_slippage_bps: default_sandwich_risk_max_victim_slippage_bps(),
            sandwich_risk_small_wallet_wei: default_sandwich_risk_small_wallet_wei(),
            toxic_probe_failure_threshold: default_toxic_probe_failure_threshold(),
            toxic_probe_failure_window_secs: default_toxic_probe_failure_window_secs(),
            balance_cap_curve_k: default_balance_cap_curve_k(),
            balance_cap_min_bps: default_balance_cap_min_bps(),
            balance_cap_max_bps: default_balance_cap_max_bps(),
            auto_slippage_base_bps: default_auto_slippage_base_bps(),
            auto_slippage_balance_log_slope: default_auto_slippage_balance_log_slope(),
            auto_slippage_balance_scale: default_auto_slippage_balance_scale(),
            auto_slippage_vol_mult_bps: default_auto_slippage_vol_mult_bps(),
            auto_slippage_min_bps: default_auto_slippage_min_bps(),
            auto_slippage_max_bps: default_auto_slippage_max_bps(),
            force_canonical_exec_router: default_false(),
            allow_unknown_router_decode: default_allow_unknown_router_decode(),
            profit_floor_abs_eth: None,
            profit_floor_mult_gas: default_profit_floor_mult_gas(),
            profit_floor_min_usd: None,
            gas_ratio_limit_floor_bps: None,
            flashloan_prefer_wallet_max_wei: default_flashloan_prefer_wallet_max_wei(),
            flashloan_value_scale_bps: default_flashloan_value_scale_bps(),
            flashloan_min_notional_wei: default_flashloan_min_notional_wei(),
            flashloan_min_repay_bps: default_flashloan_min_repay_bps(),
            flashloan_reverse_input_bps: default_flashloan_reverse_input_bps(),
            flashloan_prefilter_margin_bps: default_flashloan_prefilter_margin_bps(),
            flashloan_prefilter_margin_wei: 0,
            flashloan_prefilter_gas_cost_bps: 0,
            flashloan_reject_same_router_negative: default_flashloan_reject_same_router_negative(),
            flashloan_force: false,
            flashloan_aggressive: false,
            deadline_min_seconds_ahead: default_deadline_min_seconds_ahead(),
            deadline_allow_past_secs: default_deadline_allow_past_secs(),
            liquidation_scan_cooldown_secs: default_liquidation_scan_cooldown_secs(),
            atomic_arb_scan_cooldown_secs: default_atomic_arb_scan_cooldown_secs(),
            strategy_atomic_arb_enabled: default_true(),
            strategy_liquidation_enabled: default_true(),
            strategy_require_tokenlist: default_true(),
            atomic_arb_gas_hint: default_atomic_arb_gas_hint(),
            atomic_arb_max_candidates: default_atomic_arb_max_candidates(),
            atomic_arb_max_attempts: default_atomic_arb_max_attempts(),
            atomic_arb_seed_wei: default_atomic_arb_seed_wei(),
            flashloan_allow_nonflash_fallback: false,
            router_discovery_enabled: default_router_discovery_enabled(),
            router_discovery_min_hits: default_router_discovery_min_hits(),
            router_discovery_flush_every: default_router_discovery_flush_every(),
            router_discovery_check_interval_secs: default_router_discovery_check_interval_secs(),
            router_discovery_auto_allow: default_router_discovery_auto_allow(),
            router_discovery_max_entries: default_router_discovery_max_entries(),
            router_discovery_bootstrap_limit: default_router_discovery_bootstrap_limit(),
            router_discovery_bootstrap_lookback_blocks:
                default_router_discovery_bootstrap_lookback_blocks(),
            router_discovery_max_rpc_calls_per_cycle:
                default_router_discovery_max_rpc_calls_per_cycle(),
            router_discovery_cycle_timeout_ms: default_router_discovery_cycle_timeout_ms(),
            router_discovery_failure_budget: default_router_discovery_failure_budget(),
            router_discovery_cooldown_secs: default_router_discovery_cooldown_secs(),
            router_discovery_cache_path: None,
            router_discovery_force_full_rescan: default_false(),
            router_allowlist_by_chain: None,
            chainlink_feeds_by_chain: None,
            chainlink_feeds_by_chain_eth: None,
            aave_pools_by_chain: None,
            binance_api_key: None,
            coinmarketcap_api_key: None,
            coingecko_api_key: None,
            cryptocompare_api_key: None,
            coindesk_api_key: None,
            etherscan_api_key: None,
        }
    }

    fn stash_env(keys: &[&str]) -> Vec<(String, Option<String>)> {
        keys.iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect()
    }

    fn restore_env(snapshot: Vec<(String, Option<String>)>) {
        for (key, value) in snapshot {
            if let Some(v) = value {
                unsafe { std::env::set_var(key, v) };
            } else {
                unsafe { std::env::remove_var(key) };
            }
        }
    }

    #[test]
    fn ipc_provider_prefers_configured_map() {
        let mut settings = base_settings();
        settings.ipc_providers = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/test.ipc".to_string(),
        )]));
        assert_eq!(
            settings.get_ipc_provider(1).as_deref(),
            Some("/tmp/test.ipc")
        );
    }

    #[test]
    fn primary_http_provider_prefers_smallest_numeric_map_key() {
        let mut settings = base_settings();
        settings.http_providers = Some(HashMap::from([
            ("abc".to_string(), "https://non-numeric.example".to_string()),
            ("137".to_string(), "https://polygon.example".to_string()),
            ("1".to_string(), "https://mainnet.example".to_string()),
        ]));
        assert_eq!(
            settings.primary_http_provider().as_deref(),
            Some("https://mainnet.example")
        );
    }

    #[test]
    fn http_provider_accepts_uppercase_env_aliases() {
        let _env_lock = env_lock_guard();
        let old_upper_chain = std::env::var("HTTP_PROVIDER_1").ok();
        let old_lower_chain = std::env::var("http_provider_1").ok();
        let old_upper_default = std::env::var("HTTP_PROVIDER").ok();
        let old_lower_default = std::env::var("http_provider").ok();
        unsafe {
            std::env::remove_var("HTTP_PROVIDER_1");
            std::env::remove_var("http_provider_1");
            std::env::remove_var("HTTP_PROVIDER");
            std::env::remove_var("http_provider");
            std::env::set_var("HTTP_PROVIDER_1", "https://upper-chain.example");
        }

        let settings = base_settings();
        assert_eq!(
            settings.get_http_provider(1).unwrap_or_default(),
            "https://upper-chain.example"
        );

        if let Some(v) = old_upper_chain {
            unsafe { std::env::set_var("HTTP_PROVIDER_1", v) };
        } else {
            unsafe { std::env::remove_var("HTTP_PROVIDER_1") };
        }
        if let Some(v) = old_lower_chain {
            unsafe { std::env::set_var("http_provider_1", v) };
        } else {
            unsafe { std::env::remove_var("http_provider_1") };
        }
        if let Some(v) = old_upper_default {
            unsafe { std::env::set_var("HTTP_PROVIDER", v) };
        } else {
            unsafe { std::env::remove_var("HTTP_PROVIDER") };
        }
        if let Some(v) = old_lower_default {
            unsafe { std::env::set_var("http_provider", v) };
        } else {
            unsafe { std::env::remove_var("http_provider") };
        }
    }

    #[test]
    fn ws_lookup_does_not_use_ipc_entries() {
        let _env_lock = env_lock_guard();
        let old_ws_1 = std::env::var("WEBSOCKET_PROVIDER_1").ok();
        let old_ws = std::env::var("WEBSOCKET_PROVIDER").ok();
        let old_websocket_1 = std::env::var("WEBSOCKET_URL_1").ok();
        let old_websocket = std::env::var("WEBSOCKET_URL").ok();
        unsafe {
            std::env::remove_var("WEBSOCKET_PROVIDER_1");
            std::env::remove_var("WEBSOCKET_PROVIDER");
            std::env::remove_var("WEBSOCKET_URL_1");
            std::env::remove_var("WEBSOCKET_URL");
        }

        let mut settings = base_settings();
        settings.ipc_providers = Some(HashMap::from([(
            "1".to_string(),
            "/tmp/socket.ipc".to_string(),
        )]));
        settings.websocket_providers = None;

        let err = settings.get_websocket_provider(1).unwrap_err();
        match err {
            AppError::Config(msg) => assert!(msg.contains("No WS URL")),
            other => panic!("Unexpected error variant: {other:?}"),
        }

        if let Some(v) = old_ws_1 {
            unsafe { std::env::set_var("WEBSOCKET_PROVIDER_1", v) };
        }
        if let Some(v) = old_ws {
            unsafe { std::env::set_var("WEBSOCKET_PROVIDER", v) };
        }
        if let Some(v) = old_websocket_1 {
            unsafe { std::env::set_var("WEBSOCKET_URL_1", v) };
        }
        if let Some(v) = old_websocket {
            unsafe { std::env::set_var("WEBSOCKET_URL", v) };
        }
    }

    #[test]
    fn mev_share_relay_url_prefers_config_value() {
        let _env_lock = env_lock_guard();
        unsafe { std::env::remove_var("MEV_SHARE_RELAY_URL") };
        let mut settings = base_settings();
        settings.mev_share_relay_url = Some("https://relay.example".to_string());
        assert_eq!(
            settings.mev_share_relay_url(),
            "https://relay.example".to_string()
        );
    }

    #[test]
    fn flashloan_providers_ignore_removed_aave_v2_aliases() {
        use crate::services::strategy::strategy::FlashloanProvider::Balancer;

        let mut settings = base_settings();
        settings.flashloan_provider = "aavev2,aave_v2".to_string();
        assert_eq!(settings.flashloan_providers(), vec![Balancer]);
    }

    #[test]
    fn flashloan_providers_auto_uses_supported_provider_set_only() {
        use crate::services::strategy::strategy::FlashloanProvider::{AaveV3, Balancer};

        let mut settings = base_settings();
        settings.flashloan_provider = "auto,aavev2".to_string();
        assert_eq!(settings.flashloan_providers(), vec![AaveV3, Balancer]);
    }

    #[test]
    fn ipc_provider_requires_explicit_config_or_env() {
        let _env_lock = env_lock_guard();
        unsafe {
            std::env::remove_var("IPC_PROVIDER_1");
            std::env::remove_var("IPC_PATH_1");
            std::env::remove_var("IPC_PROVIDER");
            std::env::remove_var("IPC_PATH");
        }
        let settings = base_settings();
        assert!(settings.get_ipc_provider(1).is_none());
    }

    #[test]
    fn mevshare_builders_defaults_when_empty() {
        let mut settings = base_settings();
        settings.mevshare_builders.clear();
        assert_eq!(
            settings.mevshare_builders_value(),
            default_mevshare_builders()
        );
    }

    #[test]
    fn receipt_tuning_values_have_safe_floor() {
        let mut settings = base_settings();
        settings.receipt_poll_ms = 0;
        settings.receipt_timeout_ms = 1;
        settings.receipt_confirm_blocks = 0;
        assert_eq!(settings.receipt_poll_ms_value(), 100);
        assert_eq!(settings.receipt_timeout_ms_value(), 100);
        assert_eq!(settings.receipt_confirm_blocks_value(), 1);
    }

    #[test]
    fn rpc_capability_strict_defaults_to_mainnet_only() {
        let settings = base_settings();
        assert!(settings.rpc_capability_strict_for_chain(1));
        assert!(!settings.rpc_capability_strict_for_chain(137));
    }

    #[test]
    fn chainlink_feed_conflict_strict_applies_globally() {
        let _env_lock = env_lock_guard();
        let old = std::env::var("CHAINLINK_FEED_CONFLICT_STRICT").ok();
        unsafe { std::env::remove_var("CHAINLINK_FEED_CONFLICT_STRICT") };
        let settings = base_settings();
        assert!(settings.chainlink_feed_conflict_strict_for_chain(1));
        assert!(settings.chainlink_feed_conflict_strict_for_chain(137));
        if let Some(v) = old {
            unsafe { std::env::set_var("CHAINLINK_FEED_CONFLICT_STRICT", v) };
        }
    }

    #[test]
    fn chainlink_feed_conflict_strict_respects_env_override() {
        let _env_lock = env_lock_guard();
        let old = std::env::var("CHAINLINK_FEED_CONFLICT_STRICT").ok();
        unsafe {
            std::env::set_var("CHAINLINK_FEED_CONFLICT_STRICT", "false");
        }
        let settings = base_settings();
        assert!(!settings.chainlink_feed_conflict_strict_for_chain(1));
        assert!(!settings.chainlink_feed_conflict_strict_for_chain(137));
        if let Some(v) = old {
            unsafe { std::env::set_var("CHAINLINK_FEED_CONFLICT_STRICT", v) };
        } else {
            unsafe { std::env::remove_var("CHAINLINK_FEED_CONFLICT_STRICT") };
        }
    }

    #[test]
    fn chainlink_feed_audit_strict_defaults_disabled() {
        let settings = base_settings();
        assert!(!settings.chainlink_feed_audit_strict_for_chain(1));
        assert!(!settings.chainlink_feed_audit_strict_for_chain(137));
    }

    #[test]
    fn chainlink_loader_prefers_canonical_on_equal_priority_quotes() {
        let tmp =
            std::env::temp_dir().join(format!("chainlink-feeds-test-{}.json", std::process::id()));
        let body = r#"
[
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5147eA642CAEF7BD9c1265AadcA78f997AbB9649"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, false)
            .expect("loader result")
            .expect("selected feeds");

        std::fs::remove_file(&tmp).ok();

        let eth = selected.get("ETH").copied().expect("ETH feed");
        assert_eq!(
            format!("{:#x}", eth),
            "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419"
        );
    }

    #[test]
    fn chainlink_loader_accepts_resolved_conflicts_in_strict_mode() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-strict-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5147eA642CAEF7BD9c1265AadcA78f997AbB9649"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, true)
            .expect("loader result")
            .expect("selected feeds");

        std::fs::remove_file(&tmp).ok();

        let eth = selected.get("ETH").copied().expect("ETH feed");
        assert_eq!(
            format!("{:#x}", eth),
            "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419"
        );
    }

    #[test]
    fn chainlink_loader_dedupes_identical_entries() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-dedupe-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"WETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"},
  {"base":"ETH","quote":"USD","chainId":1,"address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");
        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, false)
            .expect("loader result")
            .expect("selected feeds");
        std::fs::remove_file(&tmp).ok();
        assert_eq!(selected.len(), 2);
        assert!(selected.contains_key("ETH"));
        assert!(selected.contains_key("ETH_USD"));
    }

    #[test]
    fn chainlink_loader_non_usd_does_not_alias_base_key() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-non-usd-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"FOO","quote":"ETH","chainId":1,"address":"0x1111111111111111111111111111111111111111"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");
        let selected = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, false)
            .expect("loader result")
            .expect("selected feeds");
        std::fs::remove_file(&tmp).ok();
        assert!(selected.contains_key("FOO_ETH"));
        assert!(!selected.contains_key("FOO"));
    }

    #[test]
    fn chainlink_loader_rejects_unresolved_conflicts_in_strict_mode() {
        let tmp = std::env::temp_dir().join(format!(
            "chainlink-feeds-strict-unresolved-test-{}.json",
            std::process::id()
        ));
        let body = r#"
[
  {"base":"FOO","quote":"USD","chainId":1,"address":"0x1111111111111111111111111111111111111111"},
  {"base":"FOO","quote":"USD","chainId":1,"address":"0x2222222222222222222222222222222222222222"}
]
"#;
        std::fs::write(&tmp, body).expect("write temp chainlink file");

        let err = load_chainlink_feeds_from_file(tmp.to_str().expect("utf8 path"), 1, true)
            .expect_err("strict unresolved conflict mode should fail");

        std::fs::remove_file(&tmp).ok();

        assert!(
            matches!(err, AppError::Config(msg) if msg.contains("unresolved conflicting duplicate"))
        );
    }

    #[test]
    fn explicit_config_path_wins_over_active_discovery() {
        let resolved = resolve_config_path(Some("custom-config.toml"));
        assert_eq!(resolved.as_deref(), Some("custom-config.toml"));
    }

    #[test]
    fn canonical_env_contract_loads_required_fields() {
        let _env_lock = env_lock_guard();
        let keys = [
            "OXIDITY_WALLET_PRIVATE_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
            "OXIDITY_LOG_LEVEL",
        ];
        let snapshot = stash_env(&keys);
        unsafe {
            std::env::set_var("OXIDITY_WALLET_PRIVATE_KEY", "canonical_wallet");
            std::env::set_var(
                "OXIDITY_WALLET_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            );
            std::env::set_var(
                "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
                "0x0000000000000000000000000000000000000002",
            );
            std::env::set_var("OXIDITY_BUNDLE_PRIVATE_KEY", "canonical_bundle");
            std::env::set_var("OXIDITY_LOG_LEVEL", "warn");
        }

        let tmp = std::env::temp_dir().join(format!(
            "config-canonical-contract-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&tmp, "").expect("write temp config");

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.wallet_key, "canonical_wallet");
        assert_eq!(loaded.log_level, "warn");
        assert_eq!(
            loaded.executor_address,
            Some(
                Address::from_str("0x0000000000000000000000000000000000000002")
                    .expect("valid address"),
            )
        );

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }

    #[test]
    fn canonical_wins_over_legacy_alias_conflict() {
        let _env_lock = env_lock_guard();
        let keys = [
            "OXIDITY_WALLET_PRIVATE_KEY",
            "WALLET_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "EXECUTOR_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
            "BUNDLE_SIGNER_KEY",
        ];
        let snapshot = stash_env(&keys);
        unsafe {
            std::env::set_var("OXIDITY_WALLET_PRIVATE_KEY", "canonical_wallet");
            std::env::set_var("WALLET_KEY", "legacy_wallet");
            std::env::set_var(
                "OXIDITY_WALLET_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            );
            std::env::set_var(
                "WALLET_ADDRESS",
                "0x0000000000000000000000000000000000000003",
            );
            std::env::set_var(
                "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
                "0x0000000000000000000000000000000000000002",
            );
            std::env::set_var(
                "EXECUTOR_ADDRESS",
                "0x0000000000000000000000000000000000000004",
            );
            std::env::set_var("OXIDITY_BUNDLE_PRIVATE_KEY", "canonical_bundle");
            std::env::set_var("BUNDLE_SIGNER_KEY", "legacy_bundle");
        }

        let tmp = std::env::temp_dir().join(format!(
            "config-canonical-conflict-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&tmp, "").expect("write temp config");

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.wallet_key, "canonical_wallet");
        assert_eq!(loaded.bundle_signer_key(), "canonical_bundle");

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }

    #[test]
    fn unrelated_env_noise_is_ignored() {
        let _env_lock = env_lock_guard();
        let keys = [
            "DEBUG",
            "OXIDITY_WALLET_PRIVATE_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
        ];
        let snapshot = stash_env(&keys);
        unsafe {
            std::env::set_var("DEBUG", "release");
            std::env::set_var("OXIDITY_WALLET_PRIVATE_KEY", "canonical_wallet");
            std::env::set_var(
                "OXIDITY_WALLET_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            );
            std::env::set_var(
                "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
                "0x0000000000000000000000000000000000000002",
            );
            std::env::set_var("OXIDITY_BUNDLE_PRIVATE_KEY", "canonical_bundle");
        }

        let tmp = std::env::temp_dir().join(format!(
            "config-noise-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&tmp, "").expect("write temp config");

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert!(!loaded.debug);

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }

    #[test]
    fn unknown_prefixed_env_key_is_ignored_with_warning() {
        let _env_lock = env_lock_guard();
        let keys = [
            "OXIDITY_NOT_A_REAL_KEY",
            "OXIDITY_WALLET_PRIVATE_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
        ];
        let snapshot = stash_env(&keys);
        unsafe {
            std::env::set_var("OXIDITY_NOT_A_REAL_KEY", "xyz");
            std::env::set_var("OXIDITY_WALLET_PRIVATE_KEY", "canonical_wallet");
            std::env::set_var(
                "OXIDITY_WALLET_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            );
            std::env::set_var(
                "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
                "0x0000000000000000000000000000000000000002",
            );
            std::env::set_var("OXIDITY_BUNDLE_PRIVATE_KEY", "canonical_bundle");
        }

        let tmp = std::env::temp_dir().join(format!(
            "config-prefixed-unknown-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&tmp, "").expect("write temp config");

        let loaded = GlobalSettings::load_with_report(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert!(
            loaded
                .report
                .warnings
                .iter()
                .any(|w| w.contains("OXIDITY_NOT_A_REAL_KEY"))
        );
        assert!(!loaded.settings.debug);

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }

    #[test]
    fn env_overrides_selected_profile_file_values() {
        let _env_lock = env_lock_guard();
        let tmp = std::env::temp_dir().join(format!(
            "config-env-override-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let body = r#"
wallet_key = "file_wallet_key"
wallet_address = "0x0000000000000000000000000000000000000001"
executor_address = "0x0000000000000000000000000000000000000002"
bundle_signer_key = "file_bundle_signer_key"
"#;
        std::fs::write(&tmp, body).expect("write temp config");
        let snapshot = stash_env(&[
            "WALLET_KEY",
            "OXIDITY_WALLET_PRIVATE_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
        ]);
        unsafe {
            std::env::remove_var("OXIDITY_WALLET_PRIVATE_KEY");
            std::env::remove_var("OXIDITY_WALLET_ADDRESS");
            std::env::remove_var("OXIDITY_FLASHLOAN_CONTRACT_ADDRESS");
            std::env::remove_var("OXIDITY_BUNDLE_PRIVATE_KEY");
            std::env::set_var("WALLET_KEY", "env_wallet_key");
        }

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.wallet_key, "env_wallet_key");

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }

    #[test]
    fn chains_env_overrides_profile_file_even_when_selected() {
        let _env_lock = env_lock_guard();
        let tmp = std::env::temp_dir().join(format!(
            "config-chains-env-override-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let body = r#"
wallet_key = "file_wallet_key"
wallet_address = "0x0000000000000000000000000000000000000001"
executor_address = "0x0000000000000000000000000000000000000002"
bundle_signer_key = "file_bundle_signer_key"
chains = [1]
"#;
        std::fs::write(&tmp, body).expect("write temp config");
        let snapshot = stash_env(&[
            "CHAINS",
            "OXIDITY_WALLET_PRIVATE_KEY",
            "OXIDITY_WALLET_ADDRESS",
            "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS",
            "OXIDITY_BUNDLE_PRIVATE_KEY",
        ]);
        unsafe {
            std::env::remove_var("OXIDITY_WALLET_PRIVATE_KEY");
            std::env::remove_var("OXIDITY_WALLET_ADDRESS");
            std::env::remove_var("OXIDITY_FLASHLOAN_CONTRACT_ADDRESS");
            std::env::remove_var("OXIDITY_BUNDLE_PRIVATE_KEY");
            std::env::set_var("CHAINS", "1,137");
        }

        let loaded = GlobalSettings::load_with_path(Some(tmp.to_str().expect("utf8 path")))
            .expect("load settings");
        assert_eq!(loaded.chains, vec![1, 137]);

        std::fs::remove_file(&tmp).ok();
        restore_env(snapshot);
    }
}
