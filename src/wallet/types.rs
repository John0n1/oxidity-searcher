// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletBootstrapResponse {
    pub product_name: String,
    pub tagline: String,
    pub support_email: String,
    pub default_chain_id: u64,
    pub chains: Vec<WalletChain>,
    pub features: WalletFeatureFlags,
    pub downloads: WalletDownloadLinks,
    pub business: WalletBusinessLinks,
    pub copy: WalletCopyBlocks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletChain {
    pub id: u64,
    pub slug: String,
    pub name: String,
    pub rpc_label: String,
    pub native_currency: String,
    pub source_label: String,
    pub explorer_address_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletFeatureFlags {
    pub private_execution: bool,
    pub mev_protection: bool,
    pub sponsorship: bool,
    pub extension: bool,
    pub android: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletDownloadLinks {
    pub extension_url: String,
    pub android_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletBusinessLinks {
    pub contact_url: String,
    pub docs_url: String,
    pub status_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletCopyBlocks {
    pub welcome_title: String,
    pub welcome_body: String,
    pub walkthrough: Vec<WalletWalkthroughCard>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletWalkthroughCard {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletQuotePreviewRequest {
    pub chain_id: u64,
    pub sell_token: String,
    pub buy_token: String,
    pub sell_amount: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPortfolioRequest {
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletQuotePreviewResponse {
    pub chain_id: u64,
    pub sell_token: String,
    pub buy_token: String,
    pub sell_amount: String,
    pub estimated_buy_amount: String,
    pub estimated_price_impact_bps: u64,
    pub gas_estimate_wei: String,
    pub execution_mode: String,
    pub sponsorship_eligible: bool,
    pub rebate_eligible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletHealthResponse {
    pub status: String,
    pub chain_id: u64,
    pub product: String,
    pub healthy_chains: usize,
    pub total_chains: usize,
    pub chains: Vec<WalletChainHealth>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainHealth {
    pub chain_id: u64,
    pub name: String,
    pub native_currency: String,
    pub source_label: String,
    pub rpc_label: String,
    pub status: String,
    pub latest_block: Option<u64>,
    pub gas_price_wei: Option<String>,
    pub ws_enabled: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPortfolioResponse {
    pub address: String,
    pub refreshed_at: String,
    pub summary: WalletPortfolioSummary,
    pub chains: Vec<WalletPortfolioChain>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPortfolioSummary {
    pub tracked_chains: usize,
    pub healthy_chains: usize,
    pub funded_chains: usize,
    pub default_chain_balance: Option<String>,
    pub default_chain_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPortfolioChain {
    pub chain_id: u64,
    pub slug: String,
    pub name: String,
    pub native_currency: String,
    pub source_label: String,
    pub status: String,
    pub latest_block: Option<u64>,
    pub gas_price_wei: Option<String>,
    pub balance_wei: Option<String>,
    pub balance_display: Option<String>,
    pub explorer_address_url: String,
    pub error: Option<String>,
}
