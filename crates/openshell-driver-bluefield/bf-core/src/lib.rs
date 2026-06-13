//! Shared contracts for the BlueField compute driver.

pub mod assignment;
pub mod claim;
pub mod error;
pub mod handles;
pub mod lifecycle;
pub mod role;
pub mod runtime;
pub mod state;

pub use assignment::BluefieldAssignment;
pub use claim::{DpuClaim, NetworkMode, StorageMode};
pub use error::{BluefieldError, Result};
pub use handles::{AttachSpec, FunctionKind, FunctionSlot, NetFunction, ProxyPlacement};
pub use lifecycle::{
    BluefieldLifecycleExtension, LaunchAbortReason, LifecycleActivation, LifecycleContext,
    LifecycleRegistry, RestoreContext, RuntimePlan, SandboxIdentity,
};
pub use role::BluefieldRole;
pub use runtime::{
    RuntimeAdapter, RuntimeCapabilities, RuntimeCondition, RuntimeEvent, RuntimeEventKind,
    RuntimeHandle, RuntimeResourceRequirements, RuntimeSandboxStatus, RuntimeWorkload,
};
pub use state::{SandboxRecord, SandboxRecordPhase};
