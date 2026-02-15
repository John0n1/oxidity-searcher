use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn git_ls_files() -> Option<Vec<String>> {
    let out = Command::new("git")
        .args(["ls-files"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    Some(body.lines().map(|s| s.to_string()).collect())
}

fn is_git_tracked(path: &Path) -> bool {
    let Some(path_str) = path.to_str() else {
        return false;
    };
    let status = Command::new("git")
        .args(["ls-files", "--error-unmatch", path_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(status, Ok(s) if s.success())
}

fn is_placeholder_secret(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_lowercase();
    normalized.is_empty()
        || normalized == "null"
        || normalized == "none"
        || normalized == "your_key_here"
        || normalized == "replace_me"
        || normalized.contains("replace_me")
        || normalized == "changeme"
        || normalized.contains("example")
        || normalized.contains("placeholder")
        || normalized.contains("dummy")
        || normalized.contains("test")
}

/// Fail CI if config files contain 64-hex private keys or obvious secrets.
#[test]
fn no_committed_hex_keys_in_configs() {
    let re = Regex::new(r"0x?[a-fA-F0-9]{64}").unwrap();
    let key_re = Regex::new(
        r"(?i)\b(wallet_key|bundle_signer_key|private_key|mnemonic|etherscan_api_key|alchemy_api_key|infura_api_key|api_key)\b\s*[:=]\s*([^\s#]+)"
    )
    .unwrap();

    let mut candidates: Vec<String> = vec![
        "config.toml".to_string(),
        "config.prod.toml".to_string(),
        "config.dev.toml".to_string(),
        ".env.example".to_string(),
    ];

    if let Ok(entries) = fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with(".env") && is_git_tracked(&path) {
                candidates.push(name.to_string());
            }
        }
    }

    candidates.sort();
    candidates.dedup();

    for file in candidates {
        if !Path::new(&file).exists() {
            continue;
        }
        let body = fs::read_to_string(&file).expect("read config");
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if re.is_match(trimmed) {
                panic!("Secret-looking hex in {} at line {}", file, idx + 1);
            }
            if let Some(caps) = key_re.captures(trimmed) {
                let value = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
                if !is_placeholder_secret(value) {
                    panic!("Secret-looking assignment in {} at line {}", file, idx + 1);
                }
            }
        }
    }
}

#[test]
fn no_tracked_dotenv_files_except_example() {
    let Some(files) = git_ls_files() else {
        return;
    };
    let offenders: Vec<String> = files
        .into_iter()
        .filter(|f| f.starts_with(".env") && f != ".env.example")
        .collect();
    assert!(
        offenders.is_empty(),
        "Tracked dotenv files are not allowed (except .env.example): {:?}",
        offenders
    );
}
