// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use tokio::sync::watch;

/// Thread-safe dynamic allowlist of strings shared across component boundaries.
#[derive(Debug, Clone)]
pub struct DynamicStringAllowlist {
    inner: Arc<RwLock<BTreeSet<String>>>,
    initial_sync: Arc<watch::Sender<bool>>,
}

impl DynamicStringAllowlist {
    fn with_initial_sync_state(set: BTreeSet<String>, initially_synced: bool) -> Self {
        let (initial_sync, _) = watch::channel(initially_synced);
        Self {
            inner: Arc::new(RwLock::new(set)),
            initial_sync: Arc::new(initial_sync),
        }
    }

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

    #[must_use]
    pub fn new() -> Self {
        Self::with_initial_sync_state(BTreeSet::new(), false)
    }

    #[must_use]
    pub fn from_set(set: BTreeSet<String>) -> Self {
        Self::with_initial_sync_state(set, true)
    }

    pub fn replace(&self, new_set: BTreeSet<String>) {
        *self.write_guard() = new_set;
    }

    /// Replace the allowlist from an authoritative source snapshot and unblock
    /// consumers waiting for the first successful synchronization.
    pub fn replace_and_mark_initially_synced(&self, new_set: BTreeSet<String>) {
        self.replace(new_set);
        self.initial_sync.send_replace(true);
    }

    #[must_use]
    pub fn is_initially_synced(&self) -> bool {
        *self.initial_sync.borrow()
    }

    /// Wait until an authoritative source snapshot has populated the allowlist.
    pub async fn wait_until_initially_synced(&self) {
        let mut initial_sync = self.initial_sync.subscribe();
        if *initial_sync.borrow_and_update() {
            return;
        }
        while initial_sync.changed().await.is_ok() {
            if *initial_sync.borrow_and_update() {
                return;
            }
        }
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
    use std::time::Duration;

    #[tokio::test]
    async fn authoritative_replace_completes_initial_sync() {
        let allowlist = DynamicStringAllowlist::new();
        assert!(!allowlist.is_initially_synced());

        let waiter = {
            let allowlist = allowlist.clone();
            tokio::spawn(async move { allowlist.wait_until_initially_synced().await })
        };
        allowlist.replace_and_mark_initially_synced(BTreeSet::new());

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("initial sync waiter should be notified")
            .expect("initial sync waiter should finish");
        assert!(allowlist.is_initially_synced());
    }

    #[test]
    fn static_set_is_initially_synced() {
        let allowlist = DynamicStringAllowlist::from_set(BTreeSet::new());
        assert!(allowlist.is_initially_synced());
    }
}
