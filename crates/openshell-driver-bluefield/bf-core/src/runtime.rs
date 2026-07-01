// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime adapter contract.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{DpuClaim, Result, RuntimePlan};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub name: String,
    pub supports_proxy_only: bool,
    pub supports_direct_device: bool,
    pub supports_storage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHandle {
    pub runtime: String,
    pub sandbox_id: String,
    pub namespace: String,
    pub name: String,
    pub native_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuntimeResourceRequirements {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
}

impl RuntimeResourceRequirements {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpu_request.is_empty()
            && self.cpu_limit.is_empty()
            && self.memory_request.is_empty()
            && self.memory_limit.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeWorkload {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub namespace: String,
    pub image: Option<String>,
    pub log_level: Option<String>,
    pub environment: Vec<(String, String)>,
    pub template_environment: Vec<(String, String)>,
    pub template_labels: Vec<(String, String)>,
    pub agent_socket_path: Option<String>,
    pub gpu: bool,
    pub resources: Option<RuntimeResourceRequirements>,
    pub platform_config: serde_json::Value,
}

impl Default for RuntimeWorkload {
    fn default() -> Self {
        Self {
            sandbox_id: String::new(),
            sandbox_name: String::new(),
            namespace: String::new(),
            image: None,
            log_level: None,
            environment: Vec::new(),
            template_environment: Vec::new(),
            template_labels: Vec::new(),
            agent_socket_path: None,
            gpu: false,
            resources: None,
            platform_config: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCondition {
    pub r#type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSandboxStatus {
    pub handle: RuntimeHandle,
    pub sandbox_name: String,
    pub agent_fd: String,
    pub sandbox_fd: String,
    pub conditions: Vec<RuntimeCondition>,
    pub deleting: bool,
}

impl RuntimeSandboxStatus {
    #[must_use]
    pub fn ready(handle: RuntimeHandle) -> Self {
        Self {
            sandbox_name: handle.name.clone(),
            handle,
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![RuntimeCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "RuntimeObserved".to_string(),
                message: "Runtime workload observed".to_string(),
                last_transition_time: String::new(),
            }],
            deleting: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeEventKind {
    Created,
    Updated,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub kind: RuntimeEventKind,
    pub handle: RuntimeHandle,
    pub message: String,
}

#[async_trait]
pub trait RuntimeAdapter: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> RuntimeCapabilities;

    async fn validate_claim(&self, claim: &DpuClaim) -> Result<()>;

    /// Validate the final runtime plan after BlueField lifecycle extensions
    /// have had a chance to add DPU claim material.
    async fn validate_plan(&self, plan: &RuntimePlan) -> Result<()> {
        if let Some(claim) = &plan.dpu_claim {
            self.validate_claim(claim).await?;
        }
        Ok(())
    }

    async fn create(&self, plan: RuntimePlan) -> Result<RuntimeHandle>;
    async fn stop(&self, handle: &RuntimeHandle) -> Result<()>;
    async fn delete(&self, handle: &RuntimeHandle) -> Result<()>;
    async fn get(&self, sandbox_id: &str) -> Result<Option<RuntimeHandle>>;
    async fn list(&self) -> Result<Vec<RuntimeHandle>>;

    async fn status(&self, sandbox_id: &str) -> Result<Option<RuntimeSandboxStatus>> {
        Ok(self.get(sandbox_id).await?.map(RuntimeSandboxStatus::ready))
    }

    async fn list_statuses(&self) -> Result<Vec<RuntimeSandboxStatus>> {
        let handles = self.list().await?;
        Ok(handles
            .into_iter()
            .map(RuntimeSandboxStatus::ready)
            .collect())
    }

    async fn reconcile(
        &self,
        plan: &RuntimePlan,
        existing: Option<RuntimeHandle>,
    ) -> Result<Option<RuntimeHandle>> {
        let _ = plan;
        Ok(existing)
    }
}
