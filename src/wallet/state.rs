// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

use crate::network::provider::{ConnectionFactory, HttpProvider};
use crate::wallet::config::{WalletChainConfig, WalletServiceConfig};
use crate::wallet::types::{
    WalletBootstrapResponse, WalletBusinessLinks, WalletChain, WalletChainHealth, WalletCopyBlocks,
    WalletDownloadLinks, WalletFeatureFlags, WalletHealthResponse, WalletPortfolioChain,
    WalletPortfolioRequest, WalletPortfolioResponse, WalletPortfolioSummary,
    WalletQuotePreviewRequest, WalletQuotePreviewResponse, WalletWalkthroughCard,
};
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use chrono::Utc;
use futures::future::join_all;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

const CHAIN_PROBE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone)]
struct WalletChainRuntime {
    config: WalletChainConfig,
    provider: HttpProvider,
}

#[derive(Debug, Clone)]
pub struct WalletServiceState {
    config: WalletServiceConfig,
    rates: HashMap<(&'static str, &'static str), f64>,
    chains: Vec<WalletChainRuntime>,
}

#[derive(Debug, Clone)]
struct ChainProbe {
    chain_id: u64,
    slug: String,
    name: String,
    native_currency: String,
    source_label: String,
    rpc_label: String,
    latest_block: Option<u64>,
    gas_price_wei: Option<String>,
    balance_wei: Option<String>,
    balance_display: Option<String>,
    explorer_address_url: String,
    ws_enabled: bool,
    error: Option<String>,
}

impl WalletServiceState {
    pub async fn new(config: WalletServiceConfig) -> Result<Self, String> {
        let chains = config
            .chains
            .iter()
            .cloned()
            .map(|chain| {
                let provider = ConnectionFactory::http(&chain.http_url, None).map_err(|error| {
                    format!("wallet RPC config failed for {}: {error}", chain.name)
                })?;
                Ok(WalletChainRuntime {
                    config: chain,
                    provider,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let rates = HashMap::from([
            (("ETH", "USDC"), 3_450.0),
            (("ETH", "USDT"), 3_448.0),
            (("ETH", "DAI"), 3_442.0),
            (("USDC", "ETH"), 1.0 / 3_450.0),
            (("USDT", "ETH"), 1.0 / 3_448.0),
            (("DAI", "ETH"), 1.0 / 3_442.0),
        ]);

        Ok(Self {
            config,
            rates,
            chains,
        })
    }

    pub async fn health(&self) -> WalletHealthResponse {
        let chains = self.collect_chain_probes(None).await;
        let healthy_chains = chains.iter().filter(|chain| chain.error.is_none()).count();

        WalletHealthResponse {
            status: if healthy_chains == self.chains.len() {
                "ok".to_string()
            } else if healthy_chains == 0 {
                "degraded".to_string()
            } else {
                "partial".to_string()
            },
            chain_id: self.config.default_chain_id,
            product: self.config.product_name.clone(),
            healthy_chains,
            total_chains: self.chains.len(),
            chains: chains
                .into_iter()
                .map(|chain| WalletChainHealth {
                    chain_id: chain.chain_id,
                    name: chain.name,
                    native_currency: chain.native_currency,
                    source_label: chain.source_label,
                    rpc_label: chain.rpc_label,
                    status: if chain.error.is_none() {
                        "ok".to_string()
                    } else {
                        "degraded".to_string()
                    },
                    latest_block: chain.latest_block,
                    gas_price_wei: chain.gas_price_wei,
                    ws_enabled: chain.ws_enabled,
                    error: chain.error,
                })
                .collect(),
        }
    }

    pub fn bootstrap(&self) -> WalletBootstrapResponse {
        WalletBootstrapResponse {
            product_name: self.config.product_name.clone(),
            tagline: "A self-custody wallet with live multi-chain reads, private-ready routing, and a cleaner path into business infrastructure.".to_string(),
            support_email: self.config.support_email.clone(),
            default_chain_id: self.config.default_chain_id,
            chains: self
                .chains
                .iter()
                .map(|chain| WalletChain {
                    id: chain.config.id,
                    slug: chain.config.slug.clone(),
                    name: chain.config.name.clone(),
                    rpc_label: chain.config.rpc_label.clone(),
                    native_currency: chain.config.native_currency.clone(),
                    source_label: chain.config.source_label.clone(),
                    explorer_address_url: chain.config.explorer_address_url.clone(),
                })
                .collect(),
            features: WalletFeatureFlags {
                private_execution: true,
                mev_protection: true,
                sponsorship: true,
                extension: true,
                android: true,
            },
            downloads: WalletDownloadLinks {
                extension_url: self.config.extension_download_url.clone(),
                android_url: self.config.android_download_url.clone(),
            },
            business: WalletBusinessLinks {
                contact_url: self.config.business_contact_url.clone(),
                docs_url: self.config.docs_url.clone(),
                status_url: self.config.status_url.clone(),
            },
            copy: WalletCopyBlocks {
                welcome_title: "Self-custody with live chain access".to_string(),
                welcome_body: "Create or import a wallet, keep keys local, and read live balances across Ethereum and supported EVM networks without dropping to a generic public wallet stack.".to_string(),
                walkthrough: vec![
                    WalletWalkthroughCard {
                        id: "portfolio".to_string(),
                        title: "Live multi-chain portfolio".to_string(),
                        description: "Ethereum mainnet comes from the local node. The supported L2 and sidechain reads come from dedicated PublicNode endpoints.".to_string(),
                    },
                    WalletWalkthroughCard {
                        id: "private".to_string(),
                        title: "Private execution where it helps".to_string(),
                        description: "Routing stays private-ready for flows that benefit from avoiding the public mempool.".to_string(),
                    },
                    WalletWalkthroughCard {
                        id: "business".to_string(),
                        title: "Same wallet, stronger path for teams".to_string(),
                        description: "The public wallet is also the front door into partner access, reporting, and production onboarding.".to_string(),
                    },
                ],
            },
        }
    }

    pub async fn portfolio(
        &self,
        request: WalletPortfolioRequest,
    ) -> Result<WalletPortfolioResponse, String> {
        let address = Address::from_str(request.address.trim())
            .map_err(|_| "address must be a valid 0x-prefixed EVM address".to_string())?;

        let chains = self.collect_chain_probes(Some(address)).await;
        let healthy_chains = chains.iter().filter(|chain| chain.error.is_none()).count();
        let funded_chains = chains
            .iter()
            .filter(|chain| {
                chain
                    .balance_wei
                    .as_deref()
                    .map(|value| value != "0")
                    .unwrap_or(false)
            })
            .count();

        let default_chain = chains
            .iter()
            .find(|chain| chain.chain_id == self.config.default_chain_id);

        Ok(WalletPortfolioResponse {
            address: request.address,
            refreshed_at: Utc::now().to_rfc3339(),
            summary: WalletPortfolioSummary {
                tracked_chains: chains.len(),
                healthy_chains,
                funded_chains,
                default_chain_balance: default_chain.and_then(|chain| chain.balance_display.clone()),
                default_chain_symbol: default_chain.map(|chain| chain.native_currency.clone()),
            },
            chains: chains
                .into_iter()
                .map(|chain| WalletPortfolioChain {
                    chain_id: chain.chain_id,
                    slug: chain.slug,
                    name: chain.name,
                    native_currency: chain.native_currency,
                    source_label: chain.source_label,
                    status: if chain.error.is_none() {
                        "ok".to_string()
                    } else {
                        "degraded".to_string()
                    },
                    latest_block: chain.latest_block,
                    gas_price_wei: chain.gas_price_wei,
                    balance_wei: chain.balance_wei,
                    balance_display: chain.balance_display,
                    explorer_address_url: chain.explorer_address_url,
                    error: chain.error,
                })
                .collect(),
            notes: vec![
                "Balances are live native-asset reads from the configured chain providers.".to_string(),
                "Execution and transaction indexing are separate phases; this endpoint only reports current network state.".to_string(),
            ],
        })
    }

    pub async fn quote_preview(
        &self,
        request: WalletQuotePreviewRequest,
    ) -> Result<WalletQuotePreviewResponse, String> {
        let sell_token = normalize_symbol(&request.sell_token);
        let buy_token = normalize_symbol(&request.buy_token);

        if sell_token == buy_token {
            return Err("sellToken and buyToken must differ".to_string());
        }

        let Some(chain) = self
            .chains
            .iter()
            .find(|chain| chain.config.id == request.chain_id)
        else {
            return Err(format!("unsupported chainId {}", request.chain_id));
        };

        let sell_amount = request
            .sell_amount
            .trim()
            .parse::<f64>()
            .map_err(|_| "sellAmount must be a valid decimal string".to_string())?;

        if sell_amount <= 0.0 {
            return Err("sellAmount must be greater than zero".to_string());
        }

        let Some(rate) = self.rates.get(&(sell_token.as_str(), buy_token.as_str())) else {
            return Err(format!(
                "unsupported preview pair {} -> {}",
                sell_token, buy_token
            ));
        };

        let chain_health = probe_chain(chain.clone(), None).await;
        let chain_healthy = chain_health.error.is_none();
        let estimated_buy_amount = sell_amount * rate;
        let estimated_price_impact_bps = if sell_amount < 0.25 {
            12
        } else if sell_amount < 1.0 {
            22
        } else {
            38
        };
        let gas_estimate_wei = chain_health
            .gas_price_wei
            .unwrap_or_else(|| "1200000000".to_string());
        let sponsorship_eligible = chain_healthy
            && request.chain_id == 1
            && sell_token == "ETH"
            && matches!(buy_token.as_str(), "USDC" | "USDT" | "DAI")
            && sell_amount <= 0.5;
        let rebate_eligible = chain_healthy && sell_amount >= 0.25 && sell_token == "ETH";

        let mut notes = vec![
            "This is a wallet-side preview, not a signed executable quote.".to_string(),
            "Route previews still use the current policy model; swap execution and settlement are separate phases."
                .to_string(),
        ];

        if chain_healthy {
            notes.push(format!(
                "{} is live and responding. Private routing remains the preferred mode when the backend accepts the flow.",
                chain.config.name
            ));
        } else {
            notes.push(format!(
                "{} is currently degraded, so this preview should be treated as indicative only.",
                chain.config.name
            ));
        }

        if sponsorship_eligible {
            notes.push(
                "This flow fits the current sponsorship policy envelope, subject to runtime checks."
                    .to_string(),
            );
        } else {
            notes.push(
                "This flow is not automatically treated as sponsorship-eligible by the current policy model."
                    .to_string(),
            );
        }

        Ok(WalletQuotePreviewResponse {
            chain_id: request.chain_id,
            sell_token,
            buy_token,
            sell_amount: request.sell_amount,
            estimated_buy_amount: format!("{estimated_buy_amount:.6}"),
            estimated_price_impact_bps,
            gas_estimate_wei,
            execution_mode: if chain_healthy {
                "private".to_string()
            } else {
                "standard".to_string()
            },
            sponsorship_eligible,
            rebate_eligible,
            notes,
        })
    }

    async fn collect_chain_probes(&self, address: Option<Address>) -> Vec<ChainProbe> {
        join_all(
            self.chains
                .iter()
                .cloned()
                .map(|chain| async move { probe_chain(chain, address).await }),
        )
        .await
    }
}

async fn probe_chain(chain: WalletChainRuntime, address: Option<Address>) -> ChainProbe {
    let block_provider = chain.provider.clone();
    let gas_provider = chain.provider.clone();
    let balance_provider = chain.provider.clone();

    let block_future = async move {
        timeout(CHAIN_PROBE_TIMEOUT, block_provider.get_block_number())
            .await
            .map_err(|_| "latest block request timed out".to_string())?
            .map_err(|error| format!("latest block request failed: {error}"))
    };

    let gas_future = async move {
        timeout(CHAIN_PROBE_TIMEOUT, gas_provider.get_gas_price())
            .await
            .map_err(|_| "gas price request timed out".to_string())?
            .map_err(|error| format!("gas price request failed: {error}"))
    };

    let balance_future = async move {
        let Some(address) = address else {
            return Ok(None);
        };

        timeout(CHAIN_PROBE_TIMEOUT, balance_provider.get_balance(address))
            .await
            .map_err(|_| "balance request timed out".to_string())?
            .map(Some)
            .map_err(|error| format!("balance request failed: {error}"))
    };

    let (block_result, gas_result, balance_result) =
        tokio::join!(block_future, gas_future, balance_future);

    let latest_block = block_result.as_ref().ok().copied();
    let gas_price_wei = gas_result.as_ref().ok().map(ToString::to_string);
    let balance_wei = balance_result
        .as_ref()
        .ok()
        .and_then(|value| value.as_ref().map(ToString::to_string));
    let balance_display = balance_result
        .as_ref()
        .ok()
        .and_then(|value| value.as_ref().map(|balance| format_wei(*balance, 18, 6)));

    let errors = [block_result.err(), gas_result.err(), balance_result.err()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    ChainProbe {
        chain_id: chain.config.id,
        slug: chain.config.slug.clone(),
        name: chain.config.name.clone(),
        native_currency: chain.config.native_currency.clone(),
        source_label: chain.config.source_label.clone(),
        rpc_label: chain.config.rpc_label.clone(),
        latest_block,
        gas_price_wei,
        balance_wei,
        balance_display,
        explorer_address_url: chain.config.explorer_address_url.clone(),
        ws_enabled: chain.config.ws_url.is_some(),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn format_wei(value: U256, decimals: usize, precision: usize) -> String {
    let raw = value.to_string();
    if decimals == 0 {
        return raw;
    }

    if raw == "0" {
        return "0.000000".to_string();
    }

    if raw.len() <= decimals {
        let fraction = format!("{:0>width$}", raw, width = decimals);
        let trimmed = fraction
            .trim_end_matches('0')
            .chars()
            .take(precision)
            .collect::<String>();
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            format!("0.{trimmed}")
        }
    } else {
        let split = raw.len() - decimals;
        let whole = &raw[..split];
        let fraction = raw[split..]
            .chars()
            .take(precision)
            .collect::<String>()
            .trim_end_matches('0')
            .to_string();
        if fraction.is_empty() {
            whole.to_string()
        } else {
            format!("{whole}.{fraction}")
        }
    }
}

fn normalize_symbol(input: &str) -> String {
    input.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WalletServiceConfig {
        WalletServiceConfig {
            bind: "127.0.0.1".to_string(),
            port: 9555,
            product_name: "Oxidity Wallet".to_string(),
            support_email: "support@oxidity.io".to_string(),
            public_site_url: "https://wallet.oxidity.io".to_string(),
            business_contact_url: "https://oxidity.io/partners?requested=wallet".to_string(),
            docs_url: "https://oxidity.io/developers".to_string(),
            status_url: "https://oxidity.io/status".to_string(),
            extension_download_url:
                "https://wallet.oxidity.io/downloads/oxidity-wallet-extension.zip".to_string(),
            android_download_url: "https://wallet.oxidity.io/downloads/oxidity-wallet-debug.apk"
                .to_string(),
            default_chain_id: 1,
            chains: vec![WalletChainConfig {
                id: 1,
                slug: "ethereum".to_string(),
                name: "Ethereum".to_string(),
                rpc_label: "Local node".to_string(),
                native_currency: "ETH".to_string(),
                http_url: "http://127.0.0.1:8545".to_string(),
                ws_url: Some("ws://127.0.0.1:8546".to_string()),
                explorer_address_url: "https://etherscan.io/address/".to_string(),
                source_label: "local-node".to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn bootstrap_exposes_live_chain_metadata() {
        let state = WalletServiceState::new(config()).await.expect("state");
        let bootstrap = state.bootstrap();

        assert_eq!(bootstrap.product_name, "Oxidity Wallet");
        assert_eq!(bootstrap.chains.len(), 1);
        assert_eq!(bootstrap.chains[0].slug, "ethereum");
        assert_eq!(bootstrap.chains[0].source_label, "local-node");
    }

    #[tokio::test]
    async fn quote_preview_supports_eth_to_usdc() {
        let state = WalletServiceState::new(config()).await.expect("state");
        let preview = state
            .quote_preview(WalletQuotePreviewRequest {
                chain_id: 1,
                sell_token: "eth".to_string(),
                buy_token: "usdc".to_string(),
                sell_amount: "0.5".to_string(),
            })
            .await
            .expect("quote preview");

        assert_eq!(preview.buy_token, "USDC");
        assert_eq!(preview.estimated_buy_amount, "1725.000000");
    }

    #[tokio::test]
    async fn quote_preview_rejects_unknown_pairs() {
        let state = WalletServiceState::new(config()).await.expect("state");
        let error = state
            .quote_preview(WalletQuotePreviewRequest {
                chain_id: 1,
                sell_token: "eth".to_string(),
                buy_token: "uni".to_string(),
                sell_amount: "1.0".to_string(),
            })
            .await
            .expect_err("unknown pair should fail");

        assert!(error.contains("unsupported preview pair"));
    }

    #[test]
    fn format_wei_handles_fractional_values() {
        let value = U256::from(1_234_560_000_000_000_000u128);
        assert_eq!(format_wei(value, 18, 6), "1.23456");
        assert_eq!(format_wei(U256::ZERO, 18, 6), "0.000000");
    }
}
