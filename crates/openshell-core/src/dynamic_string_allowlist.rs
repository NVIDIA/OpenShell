// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::watch;

/// Thread-safe dynamic allowlist of strings shared across component boundaries.
///
/// An allowlist created with [`Self::new`] starts unsynced: it is empty only
/// because its source has not been read yet. The first [`Self::replace`] (or
/// an explicit [`Self::mark_synced`]) marks it synced, so callers can tell a
/// missing entry from a list that has not loaded.
#[derive(Debug, Clone)]
pub struct DynamicStringAllowlist {
    inner: Arc<RwLock<BTreeSet<String>>>,
    synced: Arc<watch::Sender<bool>>,
}

impl DynamicStringAllowlist {
    fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<String>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, BTreeSet<String>> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Create an empty, unsynced allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(BTreeSet::new())),
            synced: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Create a synced allowlist from a known set.
    #[must_use]
    pub fn from_set(set: BTreeSet<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(set)),
            synced: Arc::new(watch::Sender::new(true)),
        }
    }

    /// Replace the whole set from an authoritative listing and mark the
    /// allowlist synced.
    pub fn replace(&self, new_set: BTreeSet<String>) {
        *self.write_guard() = new_set;
        self.mark_synced();
    }

    /// Mark the allowlist synced without changing its contents.
    pub fn mark_synced(&self) {
        self.synced
            .send_if_modified(|synced| !std::mem::replace(synced, true));
    }

    /// Whether the allowlist has received its first authoritative listing.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        *self.synced.borrow()
    }

    /// Wait up to `timeout` for the allowlist to sync. Returns whether it is
    /// synced.
    pub async fn wait_synced(&self, timeout: Duration) -> bool {
        let mut synced = self.synced.subscribe();
        tokio::time::timeout(timeout, synced.wait_for(|synced| *synced))
            .await
            .is_ok_and(|result| result.is_ok())
    }

    pub fn merge(&self, additional: &BTreeSet<String>) {
        self.write_guard().extend(additional.iter().cloned());
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<String>> {
        self.read_guard()
    }

    #[must_use]
    pub fn contains(&self, namespace: &str) -> bool {
        self.read_guard().contains(namespace)
    }

    pub fn insert(&self, name: String) -> bool {
        self.write_guard().insert(name)
    }

    pub fn remove(&self, name: &str) -> bool {
        self.write_guard().remove(name)
    }

    #[must_use]
    pub fn shared(&self) -> Arc<RwLock<BTreeSet<String>>> {
        Arc::clone(&self.inner)
    }
}

impl Default for DynamicStringAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_allowlist_is_unsynced_until_replaced() {
        let allowlist = DynamicStringAllowlist::new();
        assert!(!allowlist.is_synced());

        allowlist.insert("ns1".to_string());
        assert!(!allowlist.is_synced());

        allowlist.replace(BTreeSet::from(["ns1".to_string()]));
        assert!(allowlist.is_synced());
    }

    #[test]
    fn from_set_and_mark_synced_report_synced() {
        assert!(DynamicStringAllowlist::from_set(BTreeSet::new()).is_synced());

        let allowlist = DynamicStringAllowlist::new();
        allowlist.mark_synced();
        assert!(allowlist.is_synced());
        assert!(allowlist.read().is_empty());
    }

    #[tokio::test]
    async fn wait_synced_times_out_while_unsynced() {
        let allowlist = DynamicStringAllowlist::new();
        assert!(!allowlist.wait_synced(Duration::from_millis(20)).await);
    }

    #[tokio::test]
    async fn wait_synced_returns_when_a_clone_is_replaced() {
        let allowlist = DynamicStringAllowlist::new();
        let writer = allowlist.clone();
        let waiter =
            tokio::spawn(async move { allowlist.wait_synced(Duration::from_secs(30)).await });
        tokio::task::yield_now().await;
        writer.replace(BTreeSet::from(["ns1".to_string()]));
        assert!(waiter.await.unwrap());
    }
}
