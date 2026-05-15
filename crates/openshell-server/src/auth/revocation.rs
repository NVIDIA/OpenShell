// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-JWT revocation set.
//!
//! Tracks `jti` claims that have been explicitly revoked (sandbox deleted
//! or token refreshed). The validator consults this set on every sandbox
//! JWT validation and rejects matches as `Unauthenticated`.
//!
//! PR-2 implementation is in-memory only; a gateway restart clears the
//! set. The token TTL (24 h default) bounds the exposure window. PR 5
//! (refresh RPC) introduces persistence to `Store` so revocations survive
//! restarts.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory `jti` deny-list with TTL-based pruning.
#[derive(Debug, Default)]
pub struct RevocationSet {
    entries: RwLock<HashMap<String, i64>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `jti` as revoked until `expires_at_ms` (after which it would
    /// naturally fail signature validation due to `exp`, so we can drop it).
    pub fn revoke(&self, jti: &str, expires_at_ms: i64) {
        let mut entries = self.entries.write().expect("revocation lock poisoned");
        entries.insert(jti.to_string(), expires_at_ms);
    }

    /// Returns true if `jti` is currently revoked.
    pub fn is_revoked(&self, jti: &str) -> bool {
        let entries = self.entries.read().expect("revocation lock poisoned");
        entries.contains_key(jti)
    }

    /// Drop entries whose `exp` is in the past. Called periodically (or on
    /// demand from tests) to bound memory growth.
    pub fn prune_expired(&self) -> usize {
        let now = now_ms();
        let mut entries = self.entries.write().expect("revocation lock poisoned");
        let before = entries.len();
        entries.retain(|_, exp| *exp > now);
        before - entries.len()
    }

    /// Number of currently tracked revocations. Test/diagnostic only.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_jti_is_detected() {
        let set = RevocationSet::new();
        let future = now_ms() + 60_000;
        set.revoke("abc", future);
        assert!(set.is_revoked("abc"));
        assert!(!set.is_revoked("xyz"));
    }

    #[test]
    fn prune_drops_expired_entries() {
        let set = RevocationSet::new();
        set.revoke("expired", now_ms() - 1_000);
        set.revoke("future", now_ms() + 60_000);
        let dropped = set.prune_expired();
        assert_eq!(dropped, 1);
        assert!(!set.is_revoked("expired"));
        assert!(set.is_revoked("future"));
    }

    #[test]
    fn re_revoking_overwrites_expiry() {
        let set = RevocationSet::new();
        set.revoke("dup", now_ms() + 1_000);
        set.revoke("dup", now_ms() + 99_000);
        assert_eq!(set.len(), 1);
    }
}
