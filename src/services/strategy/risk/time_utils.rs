// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

#![allow(clippy::must_use_candidate)]

use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current UNIX timestamp in seconds.
pub fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
