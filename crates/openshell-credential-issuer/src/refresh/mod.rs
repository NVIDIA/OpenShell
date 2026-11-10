// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded refresh execution. Ports preserve the gateway's existing durable
//! format and provider commit semantics; this is not a remote service contract.

#[doc(hidden)]
pub mod engine;
pub mod minter;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use tonic::Status;

use crate::{CredentialIssuer, Handles, RefreshMaterialDeletion, SecretOwner};
pub use engine::{
    effective_authorization_epoch, enqueue_pending_secret_deletion, refresh_has_expiration,
    refresh_material_scope, refresh_state_name, set_refresh_expiration_presence,
};
pub use minter::{next_refresh_at_ms, refresh_strategy_name, strategy_secret_material_keys};

/// Lossless Rust projection of the existing refresh record. Legacy inline
/// material remains readable. Debug is redacted; material is not serializable.
#[derive(Clone, Default)]
pub struct RefreshState {
    pub metadata: Option<openshell_core::proto::ObjectMeta>,
    pub provider_id: String,
    pub provider_name: String,
    pub credential_key: String,
    pub strategy: i32,
    pub material: HashMap<String, String>,
    pub secret_material_keys: Vec<String>,
    pub expires_at_ms: i64,
    pub next_refresh_at_ms: i64,
    pub last_refresh_at_ms: i64,
    pub status: String,
    pub last_error: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub refresh_before: Option<prost_types::Duration>,
    pub max_lifetime: Option<prost_types::Duration>,
    pub additional_output_keys: HashMap<String, String>,
    pub authorization_epoch: String,
    pub secret_material_handles: Handles,
    pub pending_secret_deletions: Vec<RefreshMaterialDeletion>,
    pub recovery_action: i32,
    pub failure_code: String,
    pub provider_error_subtype: String,
    pub last_error_at_ms: i64,
}

impl std::fmt::Debug for RefreshState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshState")
            .field("provider_id", &self.provider_id)
            .field("credential_key", &self.credential_key)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl ObjectId for RefreshState {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}
impl ObjectName for RefreshState {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}
impl ObjectWorkspace for RefreshState {
    fn object_workspace(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.workspace.as_str())
    }
    fn requires_workspace() -> bool {
        true
    }
}

impl From<&RefreshState> for minter::MintRequest {
    fn from(state: &RefreshState) -> Self {
        Self {
            strategy: state.strategy,
            material: state.material.clone(),
            token_url: state.token_url.clone(),
            scopes: state.scopes.clone(),
            max_lifetime: state.max_lifetime,
            additional_output_keys: state.additional_output_keys.clone(),
        }
    }
}

/// Owned RAII lease. Dropping the initiating RPC must not release this lease;
/// the detached attempt retains it through mint and both commit transitions.
pub trait RefreshLease: Send {}

#[async_trait]
pub trait RefreshStateStore: std::fmt::Debug + Send + Sync {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status>;
    async fn get_by_id(&self, id: &str) -> Result<Option<RefreshState>, Status>;
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status>;
    async fn create(&self, state: &RefreshState) -> Result<(), Status>;
    async fn replace(&self, state: &RefreshState, version: u64) -> Result<Option<u64>, Status>;
    async fn delete(&self, id: &str, version: u64) -> Result<(), Status>;
    async fn acquire(&self, provider_id: &str, key: &str) -> Result<Box<dyn RefreshLease>, Status>;
}

/// Only staged handles (or the existing inline/test fallback) cross this port.
/// No Debug: inline outputs are secret. Expiration covers exactly the minted keys.
pub struct RefreshOutputs<'a> {
    pub credential_key: &'a str,
    pub additional_keys: Vec<String>,
    pub handles: Option<&'a Handles>,
    pub inline: &'a HashMap<String, String>,
    pub expiration: Option<prost_types::Timestamp>,
}

/// Snapshot-bound provider integration. The implementation owns its observed
/// provider; commit must never re-resolve the name and target a replacement.
#[async_trait]
pub trait RefreshAttempt: Send + Sync {
    fn owner(&self) -> SecretOwner<'_>;
    async fn prepare_workspace(&self) -> Result<(), Status>;
    /// A successful result means outputs are live. Cleanup errors are not commit
    /// failures. Return only handles replaced in the winning provider CAS.
    async fn commit(&self, outputs: RefreshOutputs<'_>) -> Result<Handles, Status>;
}

/// Temporary embedded compatibility port; stable references must remove it
/// before refresh can be externalized. Never used as a notification callback.
#[async_trait]
pub trait GatewayRefreshCommit: std::fmt::Debug + Send + Sync {
    async fn observe(
        &self,
        workspace: &str,
        provider_name: &str,
    ) -> Result<Box<dyn RefreshAttempt>, Status>;
}

/// Non-secret invalidation hint. A completed-mint marker coalesces waiters; it
/// is not a monotonically increasing secret version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshChange {
    pub workspace: String,
    pub provider_name: String,
    pub credential_key: String,
    pub completed_mint: Option<String>,
}

pub trait RefreshCommitSink {
    fn notify(&self, change: &RefreshChange);
}

/// The gateway invokes the sink at its existing orchestration points, not from
/// the detached engine task (export and canceled manual RPCs do not publish).
#[async_trait]
pub trait CredentialRefresh: Send + Sync {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status>;
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status>;
    async fn create(&self, state: RefreshState) -> Result<(), Status>;
    async fn replace(&self, state: RefreshState, version: u64) -> Result<bool, Status>;
    async fn delete(&self, state: RefreshState) -> Result<(), Status>;
    async fn rotate(
        &self,
        workspace: &str,
        provider_name: &str,
        key: &str,
    ) -> Result<RefreshState, Status>;
    async fn ensure_fresh(&self, snapshot: RefreshState) -> Result<RefreshState, Status>;
    async fn sweep(&self) -> Result<Vec<RefreshChange>, Status>;
}

#[derive(Clone, Debug)]
pub struct RefreshRuntime {
    store: Arc<dyn RefreshStateStore>,
    credentials: Option<Arc<dyn CredentialIssuer>>,
    gateway: Arc<dyn GatewayRefreshCommit>,
}

impl RefreshRuntime {
    pub fn new(
        store: Arc<dyn RefreshStateStore>,
        credentials: Option<Arc<dyn CredentialIssuer>>,
        gateway: Arc<dyn GatewayRefreshCommit>,
    ) -> Self {
        Self {
            store,
            credentials,
            gateway,
        }
    }
}

#[cfg(test)]
mod tests;
