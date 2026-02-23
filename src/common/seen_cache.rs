// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use dashmap::DashSet;
use std::collections::VecDeque;
use std::hash::Hash;
use tokio::sync::Mutex;

/// Insert `key` into a bounded seen set. Returns `true` only for first-seen keys.
pub async fn remember_with_bounded_order<T>(
    seen: &DashSet<T>,
    order: &Mutex<VecDeque<T>>,
    key: T,
    max_len: usize,
) -> bool
where
    T: Copy + Eq + Hash,
{
    if !seen.insert(key) {
        return false;
    }
    let mut guard = order.lock().await;
    guard.push_back(key);
    if guard.len() > max_len
        && let Some(oldest) = guard.pop_front()
    {
        seen.remove(&oldest);
    }
    true
}
