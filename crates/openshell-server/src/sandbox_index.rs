// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory indexes for correlating Kubernetes objects back to sandbox ids.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use openshell_core::proto::Sandbox;

#[derive(Debug, Clone, Default)]
pub struct SandboxIndex {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    sandbox_name_to_id: HashMap<String, String>,
    agent_pod_to_id: HashMap<String, String>,
}

impl SandboxIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_from_sandbox(&self, sandbox: &Sandbox) {
        let mut inner = self.inner.write().expect("sandbox index lock poisoned");
        if !sandbox.name.is_empty() {
            inner
                .sandbox_name_to_id
                .insert(sandbox.name.clone(), sandbox.id.clone());
        }

        if let Some(status) = sandbox.status.as_ref()
            && !status.agent_pod.is_empty()
        {
            inner
                .agent_pod_to_id
                .insert(status.agent_pod.clone(), sandbox.id.clone());
        }
    }

    pub fn remove_sandbox(&self, sandbox_id: &str) {
        let mut inner = self.inner.write().expect("sandbox index lock poisoned");
        inner.sandbox_name_to_id.retain(|_, v| v != sandbox_id);
        inner.agent_pod_to_id.retain(|_, v| v != sandbox_id);
    }

    #[must_use]
    pub fn sandbox_id_for_sandbox_name(&self, name: &str) -> Option<String> {
        let inner = self.inner.read().expect("sandbox index lock poisoned");
        inner.sandbox_name_to_id.get(name).cloned()
    }

    #[must_use]
    pub fn sandbox_id_for_agent_pod(&self, pod: &str) -> Option<String> {
        let inner = self.inner.read().expect("sandbox index lock poisoned");
        inner.agent_pod_to_id.get(pod).cloned()
    }
}
