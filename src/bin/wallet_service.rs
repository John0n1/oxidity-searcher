// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Oxidity <john@oxidity.io>

use clap::Parser;
use oxidity_searcher::wallet::config::WalletServiceConfig;
use oxidity_searcher::wallet::server::serve;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "Oxidity wallet service")]
struct Cli {
    #[arg(long)]
    bind: Option<String>,

    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut config = WalletServiceConfig::from_env();
    if let Some(bind) = cli.bind {
        config.bind = bind;
    }
    if let Some(port) = cli.port {
        config.port = port;
    }

    serve(config).await?;
    Ok(())
}
