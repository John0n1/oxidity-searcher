// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use clap::Parser;
use oxidity_searcher::app::config::GlobalSettings;
use oxidity_searcher::common::error::AppError;
use oxidity_searcher::data::db::Database;

#[derive(Parser, Debug)]
#[command(author, version, about = "review recent onboarding requests")]
struct Cli {
    #[arg(long)]
    config: Option<String>,

    #[arg(long, default_value_t = 20)]
    limit: u64,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let settings = GlobalSettings::load_with_path(cli.config.as_deref())?;
    let db = Database::new(&settings.database_url()).await?;
    let requests = db.recent_onboarding_requests(cli.limit).await?;

    println!(
        "{:<6} {:<19} {:<24} {:<18} {:<12} organization",
        "id", "created_at", "email", "recommended", "track"
    );
    for request in requests {
        println!(
            "{:<6} {:<19} {:<24} {:<18} {:<12} {}",
            request.id,
            request.created_at,
            request.email,
            truncate(&request.recommended_path, 18),
            request.requested_track,
            request.organization
        );
    }

    Ok(())
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if idx + 1 >= width {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}
