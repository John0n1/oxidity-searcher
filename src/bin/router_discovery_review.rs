// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use clap::{Parser, ValueEnum};
use dashmap::DashSet;
use oxidity_searcher::app::config::GlobalSettings;
use oxidity_searcher::common::error::AppError;
use oxidity_searcher::data::db::Database;
use oxidity_searcher::services::strategy::execution::strategy::{
    AllowlistCategory, classify_allowlist_entry,
};
use oxidity_searcher::services::strategy::router_discovery::{
    RouterDiscovery, RouterDiscoveryBudget, RouterDiscoveryConfig,
};
use std::sync::Arc;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Json,
    Table,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "review and optionally approve pending router discovery entries"
)]
struct Cli {
    #[arg(long)]
    config: Option<String>,

    #[arg(long)]
    chain_id: Option<u64>,

    #[arg(long, default_value_t = 20)]
    limit: usize,

    #[arg(long)]
    lookback_blocks: Option<u64>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    #[arg(long, default_value_t = false)]
    approve_classified: bool,
}

fn default_chain_id(settings: &GlobalSettings) -> u64 {
    settings.chains.first().copied().unwrap_or(1)
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let settings = GlobalSettings::load_with_path(cli.config.as_deref())?;
    let chain_id = cli.chain_id.unwrap_or_else(|| default_chain_id(&settings));
    let lookback_blocks = cli
        .lookback_blocks
        .unwrap_or_else(|| settings.router_discovery_bootstrap_lookback_blocks_value());

    let db = Database::new(&settings.database_url()).await?;
    let allowlist = Arc::new(DashSet::new());
    for (name, address) in settings.routers_for_chain(chain_id)? {
        match classify_allowlist_entry(&name) {
            AllowlistCategory::Routers => {
                allowlist.insert(address);
            }
            AllowlistCategory::Wrappers | AllowlistCategory::Infra => {
                db.set_router_status(
                    chain_id,
                    &format!("{address:#x}"),
                    "ignored",
                    None,
                    Some(&format!("static_allowlist:{name}")),
                )
                .await?;
            }
        }
    }
    if let Ok(dynamic_approved) = db.approved_routers(chain_id).await {
        for address in dynamic_approved {
            allowlist.insert(address);
        }
    }

    let discovery = RouterDiscovery::new(RouterDiscoveryConfig {
        chain_id,
        allowlist,
        db: db.clone(),
        http_provider: settings.get_http_provider(chain_id).ok(),
        etherscan_api_key: settings.etherscan_api_key_value(),
        enabled: true,
        auto_allow: false,
        min_hits: settings.router_discovery_min_hits,
        flush_every: settings.router_discovery_flush_every,
        check_interval: settings.router_discovery_check_interval(),
        max_entries: settings.router_discovery_max_entries,
        budget: RouterDiscoveryBudget {
            max_blocks_per_cycle: settings.router_discovery_bootstrap_lookback_blocks_value(),
            max_rpc_calls_per_cycle: settings.router_discovery_max_rpc_calls_per_cycle_value(),
            cycle_timeout: settings.router_discovery_cycle_timeout(),
            failure_budget: settings.router_discovery_failure_budget_value(),
            cooldown: settings.router_discovery_cooldown(),
        },
        cache_path: settings.router_discovery_cache_path().ok(),
        force_full_rescan: false,
    })?;

    let entries = discovery
        .review_top_unknown_routers(cli.limit, lookback_blocks)
        .await?;

    if cli.approve_classified {
        for entry in &entries {
            if let Some(classification) = &entry.classification {
                db.set_router_status(
                    chain_id,
                    &entry.address,
                    "approved",
                    Some(&classification.kind),
                    Some(&classification.note),
                )
                .await?;
            }
        }
    }

    match cli.format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into())
            );
        }
        OutputFormat::Table => {
            println!("{:<44} {:>10} {:<8} note", "router", "seen", "kind");
            for entry in entries {
                let kind = entry
                    .classification
                    .as_ref()
                    .map(|value| value.kind.as_str())
                    .unwrap_or("-");
                let note = entry
                    .classification
                    .as_ref()
                    .map(|value| value.note.as_str())
                    .unwrap_or("needs_manual_review");
                println!(
                    "{:<44} {:>10} {:<8} {}",
                    entry.address, entry.seen_count, kind, note
                );
            }
        }
    }

    Ok(())
}
