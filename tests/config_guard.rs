use regex::Regex;
use std::fs;
use std::path::Path;

/// Fail CI if config files contain 64-hex private keys or obvious secrets.
#[test]
fn no_committed_hex_keys_in_configs() {
    let re = Regex::new(r"0x?[a-fA-F0-9]{64}").unwrap();
    let candidates = ["config.toml", "config.prod.toml", "config.dev.toml"];
    for file in candidates {
        if !Path::new(file).exists() {
            continue;
        }
        let body = fs::read_to_string(file).expect("read config");
        for (idx, line) in body.lines().enumerate() {
            if re.is_match(line) {
                panic!("Secret-looking hex in {} at line {}", file, idx + 1);
            }
        }
    }
}
