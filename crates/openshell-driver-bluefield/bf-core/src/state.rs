//! Persisted BlueField driver state.

use serde::{Deserialize, Serialize};

use crate::{DpuClaim, RuntimeHandle, RuntimePlan, SandboxIdentity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxRecordPhase {
    Creating,
    Ready,
    Stopped,
    Deleting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub sandbox: SandboxIdentity,
    pub runtime: String,
    pub phase: SandboxRecordPhase,
    pub plan: RuntimePlan,
    pub runtime_handle: Option<RuntimeHandle>,
    pub dpu_claim: Option<DpuClaim>,
    pub message: Option<String>,
}

impl SandboxRecord {
    #[must_use]
    pub fn new(sandbox: SandboxIdentity, plan: RuntimePlan) -> Self {
        Self {
            runtime: plan.runtime.clone(),
            sandbox,
            phase: SandboxRecordPhase::Creating,
            runtime_handle: None,
            dpu_claim: plan.dpu_claim.clone(),
            plan,
            message: None,
        }
    }
}
