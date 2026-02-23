// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use alloy::primitives::{Address, B256, U256};
use std::str::FromStr;

pub fn parse_boolish(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(strip_0x(s)).ok()
}

pub fn parse_b256_hex(s: &str) -> Option<B256> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

pub fn parse_address_hex(s: &str) -> Option<Address> {
    Address::from_str(strip_0x(s)).ok()
}

pub fn parse_u64_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(strip_0x(s), 16).ok()
}

pub fn parse_u128_hex(s: &str) -> Option<u128> {
    u128::from_str_radix(strip_0x(s), 16).ok()
}

pub fn parse_u256_hex(s: &str) -> Option<U256> {
    U256::from_str_radix(strip_0x(s), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsers_accept_lower_and_upper_prefixes() {
        assert_eq!(parse_u64_hex("0x2a"), Some(42));
        assert_eq!(parse_u64_hex("0X2a"), Some(42));
        assert_eq!(parse_u128_hex("0X64"), Some(100));
        assert_eq!(parse_u256_hex("0X0"), Some(U256::ZERO));
        assert_eq!(parse_hex_bytes("0Xabcd"), Some(vec![0xab, 0xcd]));
    }

    #[test]
    fn parse_boolish_rejects_invalid_values() {
        assert_eq!(parse_boolish("true"), Some(true));
        assert_eq!(parse_boolish("OFF"), Some(false));
        assert_eq!(parse_boolish("tru"), None);
    }
}
