// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const MIGRATIONS_DIR: &str = "migrations";
const MIGRATIONS_LEGACY_DIR: &str = "migrations_legacy";

fn normalize_ident(raw: &str) -> String {
    raw.trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == '(')
        .to_lowercase()
}

fn collapse_ws(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_create_table_target(line: &str) -> Option<String> {
    let compact = collapse_ws(line);
    let tokens: Vec<&str> = compact.split(' ').collect();
    if tokens.len() < 3 {
        return None;
    }
    if !(tokens[0].eq_ignore_ascii_case("create") && tokens[1].eq_ignore_ascii_case("table")) {
        return None;
    }

    let mut idx = 2usize;
    if idx + 2 < tokens.len()
        && tokens[idx].eq_ignore_ascii_case("if")
        && tokens[idx + 1].eq_ignore_ascii_case("not")
        && tokens[idx + 2].eq_ignore_ascii_case("exists")
    {
        idx += 3;
    }
    tokens
        .get(idx)
        .map(|name| format!("table:{}", normalize_ident(name)))
}

fn parse_alter_add_column_target(line: &str) -> Option<String> {
    let compact = collapse_ws(line);
    let tokens: Vec<&str> = compact.split(' ').collect();
    if tokens.len() < 6 {
        return None;
    }
    if !(tokens[0].eq_ignore_ascii_case("alter") && tokens[1].eq_ignore_ascii_case("table")) {
        return None;
    }
    let table = normalize_ident(tokens[2]);
    let add_idx = tokens.iter().position(|t| t.eq_ignore_ascii_case("add"))?;
    if !tokens.get(add_idx + 1)?.eq_ignore_ascii_case("column") {
        return None;
    }
    let column = normalize_ident(tokens.get(add_idx + 2)?);
    Some(format!("column:{table}:{column}"))
}

fn duplicate_targets_for_dir(migrations_dir: &str) -> BTreeMap<String, Vec<String>> {
    let mut files: Vec<_> = fs::read_dir(Path::new(migrations_dir))
        .expect("read migrations dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sql"))
        .collect();
    files.sort();

    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for path in files {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.sql")
            .to_string();
        let sql = fs::read_to_string(&path).expect("read migration");
        for raw_line in sql.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("--") {
                continue;
            }
            if let Some(target) = parse_create_table_target(line) {
                seen.entry(target).or_default().push(file_name.clone());
            }
            if let Some(target) = parse_alter_add_column_target(line) {
                seen.entry(target).or_default().push(file_name.clone());
            }
        }
    }
    seen.into_iter()
        .filter(|(_, files)| files.len() > 1)
        .collect()
}

#[test]
fn active_migration_targets_are_not_duplicated() {
    let duplicates = duplicate_targets_for_dir(MIGRATIONS_DIR);
    assert!(
        duplicates.is_empty(),
        "Unexpected duplicate migration DDL targets in {}: {:?}",
        MIGRATIONS_DIR,
        duplicates
    );
}

#[test]
fn legacy_migration_targets_are_only_known_historical_duplicates() {
    let allowed_historical_duplicates: BTreeSet<String> = ["table:nonce_state"]
        .into_iter()
        .map(String::from)
        .collect();
    let duplicates = duplicate_targets_for_dir(MIGRATIONS_LEGACY_DIR);
    let unexpected: Vec<(String, Vec<String>)> = duplicates
        .iter()
        .filter(|(target, _)| !allowed_historical_duplicates.contains(*target))
        .map(|(target, files)| (target.clone(), files.clone()))
        .collect();

    assert!(
        unexpected.is_empty(),
        "Unexpected duplicate migration DDL targets in {}: {:?}",
        MIGRATIONS_LEGACY_DIR,
        unexpected
    );
}
