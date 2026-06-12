//! BlueField driver lifecycle extension framework.
//!
//! This mirrors the in-tree VM lifecycle extension hook chain, but the hooks
//! run inside the external BlueField compute driver and apply to any runtime.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{DpuClaim, NetworkMode, Result, RuntimeHandle, RuntimeWorkload, StorageMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxIdentity {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleContext {
    pub sandbox: SandboxIdentity,
    pub runtime: String,
    pub network_mode: NetworkMode,
    pub storage_mode: StorageMode,
    pub node: Option<String>,
    pub policy_hash: Option<String>,
    pub labels: Vec<(String, String)>,
    pub annotations: Vec<(String, String)>,
}

impl LifecycleContext {
    #[must_use]
    pub fn extension_enabled(&self, key: &str) -> bool {
        let extension_label = format!("openshell.io/extension.{key}");
        self.labels
            .iter()
            .chain(self.annotations.iter())
            .any(|(name, value)| name == &extension_label && value == "enabled")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub runtime: String,
    pub workload: RuntimeWorkload,
    pub environment: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
    pub annotations: Vec<(String, String)>,
    pub dpu_claim: Option<DpuClaim>,
}

impl RuntimePlan {
    #[must_use]
    pub fn new(runtime: impl Into<String>) -> Self {
        Self {
            runtime: runtime.into(),
            workload: RuntimeWorkload::default(),
            environment: Vec::new(),
            labels: Vec::new(),
            annotations: Vec::new(),
            dpu_claim: None,
        }
    }

    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.environment.push((key.into(), value.into()));
    }

    pub fn set_label(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.labels.push((key.into(), value.into()));
    }

    pub fn set_annotation(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.push((key.into(), value.into()));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchAbortReason {
    RuntimeCreateFailed,
    BeforeRuntimeCreateFailed,
    DpuAttachFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreContext {
    pub sandbox: SandboxIdentity,
    pub runtime: String,
    pub runtime_handle: Option<RuntimeHandle>,
    pub dpu_claim: Option<DpuClaim>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleActivation {
    Global,
    OnRequest { key: &'static str },
}

#[async_trait]
pub trait BluefieldLifecycleExtension: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;

    fn activation(&self) -> LifecycleActivation {
        LifecycleActivation::Global
    }

    /// Pure planning hook.
    async fn configure_runtime(
        &self,
        _ctx: &LifecycleContext,
        _plan: &mut RuntimePlan,
    ) -> Result<()> {
        Ok(())
    }

    /// Side-effect hook before the runtime creates the workload.
    async fn before_runtime_create(
        &self,
        _ctx: &LifecycleContext,
        _plan: &mut RuntimePlan,
    ) -> Result<()> {
        Ok(())
    }

    /// Cleanup hook when runtime creation aborts.
    async fn after_runtime_create_failed(
        &self,
        _ctx: &LifecycleContext,
        _plan: &RuntimePlan,
        _reason: LaunchAbortReason,
    ) -> Result<()> {
        Ok(())
    }

    /// Cleanup hook after the runtime deletes the workload.
    async fn after_runtime_delete(
        &self,
        _ctx: &LifecycleContext,
        _plan: &RuntimePlan,
    ) -> Result<()> {
        Ok(())
    }

    /// Re-adopt claims before restoring an existing runtime workload.
    async fn before_runtime_restore(
        &self,
        _ctx: &RestoreContext,
        _plan: &mut RuntimePlan,
    ) -> Result<()> {
        Ok(())
    }

    /// Reconcile DPU state after runtime restore completes.
    async fn after_runtime_restore(
        &self,
        _ctx: &RestoreContext,
        _plan: &RuntimePlan,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct LifecycleRegistry {
    extensions: Vec<Arc<dyn BluefieldLifecycleExtension>>,
}

impl LifecycleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, extension: Arc<dyn BluefieldLifecycleExtension>) {
        self.extensions.push(extension);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    fn active<'a>(
        &'a self,
        ctx: &'a LifecycleContext,
    ) -> impl Iterator<Item = &'a Arc<dyn BluefieldLifecycleExtension>> {
        self.extensions.iter().filter(move |extension| {
            matches!(extension.activation(), LifecycleActivation::Global)
                || matches!(
                    extension.activation(),
                    LifecycleActivation::OnRequest { key } if ctx.extension_enabled(key)
                )
        })
    }

    pub async fn configure_runtime(
        &self,
        ctx: &LifecycleContext,
        plan: &mut RuntimePlan,
    ) -> Result<()> {
        for extension in self.active(ctx) {
            extension.configure_runtime(ctx, plan).await?;
        }
        Ok(())
    }

    pub async fn before_runtime_create(
        &self,
        ctx: &LifecycleContext,
        plan: &mut RuntimePlan,
    ) -> Result<()> {
        for extension in self.active(ctx) {
            extension.before_runtime_create(ctx, plan).await?;
        }
        Ok(())
    }

    pub async fn after_runtime_create_failed(
        &self,
        ctx: &LifecycleContext,
        plan: &RuntimePlan,
        reason: LaunchAbortReason,
    ) -> Result<()> {
        let active = self.active(ctx).cloned().collect::<Vec<_>>();
        for extension in active.iter().rev() {
            extension
                .after_runtime_create_failed(ctx, plan, reason)
                .await?;
        }
        Ok(())
    }

    pub async fn after_runtime_delete(
        &self,
        ctx: &LifecycleContext,
        plan: &RuntimePlan,
    ) -> Result<()> {
        let active = self.active(ctx).cloned().collect::<Vec<_>>();
        for extension in active.iter().rev() {
            extension.after_runtime_delete(ctx, plan).await?;
        }
        Ok(())
    }

    pub async fn before_runtime_restore(
        &self,
        ctx: &RestoreContext,
        plan: &mut RuntimePlan,
    ) -> Result<()> {
        let lifecycle_ctx = LifecycleContext {
            sandbox: ctx.sandbox.clone(),
            runtime: ctx.runtime.clone(),
            network_mode: ctx
                .dpu_claim
                .as_ref()
                .map(|claim| claim.network_mode.clone())
                .unwrap_or_default(),
            storage_mode: ctx
                .dpu_claim
                .as_ref()
                .map(|claim| claim.storage_mode.clone())
                .unwrap_or_default(),
            node: ctx.dpu_claim.as_ref().and_then(|claim| claim.node.clone()),
            policy_hash: ctx
                .dpu_claim
                .as_ref()
                .and_then(|claim| claim.policy_hash.clone()),
            labels: Vec::new(),
            annotations: Vec::new(),
        };
        for extension in self.active(&lifecycle_ctx) {
            extension.before_runtime_restore(ctx, plan).await?;
        }
        Ok(())
    }

    pub async fn after_runtime_restore(
        &self,
        ctx: &RestoreContext,
        plan: &RuntimePlan,
    ) -> Result<()> {
        let lifecycle_ctx = LifecycleContext {
            sandbox: ctx.sandbox.clone(),
            runtime: ctx.runtime.clone(),
            network_mode: ctx
                .dpu_claim
                .as_ref()
                .map(|claim| claim.network_mode.clone())
                .unwrap_or_default(),
            storage_mode: ctx
                .dpu_claim
                .as_ref()
                .map(|claim| claim.storage_mode.clone())
                .unwrap_or_default(),
            node: ctx.dpu_claim.as_ref().and_then(|claim| claim.node.clone()),
            policy_hash: ctx
                .dpu_claim
                .as_ref()
                .and_then(|claim| claim.policy_hash.clone()),
            labels: Vec::new(),
            annotations: Vec::new(),
        };
        for extension in self.active(&lifecycle_ctx) {
            extension.after_runtime_restore(ctx, plan).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug)]
    struct RecordingExtension {
        name: &'static str,
        activation: LifecycleActivation,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl BluefieldLifecycleExtension for RecordingExtension {
        fn name(&self) -> &'static str {
            self.name
        }

        fn activation(&self) -> LifecycleActivation {
            self.activation
        }

        async fn configure_runtime(
            &self,
            _ctx: &LifecycleContext,
            _plan: &mut RuntimePlan,
        ) -> Result<()> {
            self.events
                .lock()
                .expect("events lock poisoned")
                .push(format!("{}:configure", self.name));
            Ok(())
        }

        async fn after_runtime_delete(
            &self,
            _ctx: &LifecycleContext,
            _plan: &RuntimePlan,
        ) -> Result<()> {
            self.events
                .lock()
                .expect("events lock poisoned")
                .push(format!("{}:delete", self.name));
            Ok(())
        }
    }

    fn ctx(labels: Vec<(String, String)>) -> LifecycleContext {
        LifecycleContext {
            sandbox: SandboxIdentity {
                sandbox_id: "sb".to_string(),
                sandbox_name: "sandbox".to_string(),
                namespace: "default".to_string(),
            },
            runtime: "vm".to_string(),
            network_mode: NetworkMode::ProxyOnly,
            storage_mode: StorageMode::None,
            node: None,
            policy_hash: None,
            labels,
            annotations: Vec::new(),
        }
    }

    #[tokio::test]
    async fn registry_runs_cleanup_in_reverse_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut registry = LifecycleRegistry::new();
        registry.push(Arc::new(RecordingExtension {
            name: "first",
            activation: LifecycleActivation::Global,
            events: events.clone(),
        }));
        registry.push(Arc::new(RecordingExtension {
            name: "second",
            activation: LifecycleActivation::Global,
            events: events.clone(),
        }));

        let ctx = ctx(Vec::new());
        let mut plan = RuntimePlan::new("vm");
        registry.configure_runtime(&ctx, &mut plan).await.unwrap();
        registry.after_runtime_delete(&ctx, &plan).await.unwrap();

        assert_eq!(
            *events.lock().expect("events lock poisoned"),
            vec![
                "first:configure".to_string(),
                "second:configure".to_string(),
                "second:delete".to_string(),
                "first:delete".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn registry_filters_on_request_extensions() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut registry = LifecycleRegistry::new();
        registry.push(Arc::new(RecordingExtension {
            name: "requested",
            activation: LifecycleActivation::OnRequest { key: "network" },
            events: events.clone(),
        }));

        let mut plan = RuntimePlan::new("vm");
        registry
            .configure_runtime(&ctx(Vec::new()), &mut plan)
            .await
            .unwrap();
        assert!(events.lock().expect("events lock poisoned").is_empty());

        registry
            .configure_runtime(
                &ctx(vec![(
                    "openshell.io/extension.network".to_string(),
                    "enabled".to_string(),
                )]),
                &mut plan,
            )
            .await
            .unwrap();
        assert_eq!(
            *events.lock().expect("events lock poisoned"),
            vec!["requested:configure".to_string()]
        );
    }
}
