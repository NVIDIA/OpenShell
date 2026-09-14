// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

/// Thread-safe dynamic allowlist of Kubernetes operator-mode namespaces.
///
/// This type lives in the public core API because both the Kubernetes driver
/// and gateway authentication boundary consume it.
#[derive(Debug, Clone)]
pub struct OperatorNamespaceAllowlist {
    inner: Arc<RwLock<BTreeSet<String>>>,
}

impl OperatorNamespaceAllowlist {
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
        Self {
            inner: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    #[must_use]
    pub fn from_set(set: BTreeSet<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(set)),
        }
    }

    pub fn replace(&self, new_set: BTreeSet<String>) {
        *self.write_guard() = new_set;
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

impl Default for OperatorNamespaceAllowlist {
    fn default() -> Self {
        Self::new()
    }
}
