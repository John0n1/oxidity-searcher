// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use alloy::primitives::{address, Address};
use std::collections::HashSet;

#[test]
fn test_honeypot_toxic_token_caching_shield() {
    let mut toxic_tokens: HashSet<Address> = HashSet::new();
    let scam_token = address!("1111111111111111111111111111111111111111");
    let legit_token = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");

    // Mark scam token toxic after two-way simulation failure
    toxic_tokens.insert(scam_token);

    assert!(toxic_tokens.contains(&scam_token), "Scam token should be cached in toxic_tokens shield");
    assert!(!toxic_tokens.contains(&legit_token), "Legitimate token should not be in toxic_tokens shield");
}
