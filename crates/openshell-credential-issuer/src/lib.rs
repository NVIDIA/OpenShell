// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded credential storage boundary. Provider semantics and delivery remain
//! in the gateway; existing driver contracts and durable identities are unchanged.

mod embedded;
mod owner;
pub mod refresh;
mod refresh_material;

pub use embedded::EmbeddedCredentialIssuer;
pub use owner::{SecretOwner, SecretOwnerKind};

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use openshell_core::extension_protocol::NegotiatedExtension;
use openshell_core::proto::CredentialHandle;
use tonic::Status;

/// Persistence port supplied by the embedding process. Implementations operate
/// on encrypted envelopes, never plaintext, and must preserve conditional writes.
pub mod persistence {
    pub use openshell_driver_db_credstore::{
        CredentialObjectWrite, DbCredstoreObjectStore, DbCredstoreWriteCondition, OBJECT_TYPE,
        StoredCredentialObject,
    };
}

/// Credential-specific projection of existing gateway settings, not a new
/// operator-facing configuration format. Deliberately does not implement Debug:
/// backend tables may contain authentication material.
#[derive(Clone, Default)]
pub struct IssuerConfig {
    pub credential_drivers: Vec<String>,
    pub default_credential_driver: Option<String>,
    pub credential_storage: toml::Table,
    pub driver_configs: BTreeMap<String, toml::Value>,
}

impl From<&openshell_core::Config> for IssuerConfig {
    fn from(config: &openshell_core::Config) -> Self {
        Self {
            credential_drivers: config.credential_drivers.clone(),
            default_credential_driver: config.default_credential_driver.clone(),
            ..Self::default()
        }
    }
}

pub type Handles = HashMap<String, CredentialHandle>;

/// Per-write identity is distinct from the owner so losing staged writes cannot
/// overwrite a winner's committed secret. None preserves the owner's default ID.
/// No Debug implementation: values are secret.
pub struct StoreSecrets<'a> {
    pub owner: SecretOwner<'a>,
    pub object_id: Option<&'a str>,
    pub values: &'a HashMap<String, String>,
    pub existing_handles: &'a Handles,
}

/// A resolved value and backend expiration, without provider-level policy.
/// No Debug implementation: values are secret.
pub struct ResolvedSecret {
    pub credential_key: String,
    pub value: String,
    pub expiration_time: Option<prost_types::Timestamp>,
}

#[derive(Debug, Clone, Copy)]
pub struct RefreshMaterialScope<'a> {
    pub provider_name: &'a str,
    pub workspace: &'a str,
    pub provider_id: &'a str,
    pub credential_key: &'a str,
}

impl RefreshMaterialScope<'_> {
    fn owner(&self) -> SecretOwner<'_> {
        SecretOwner::provider(self.workspace, self.provider_id, self.provider_name)
    }
}

/// Plain Rust projection of a pending deletion; no gateway-private protobufs
/// cross the issuer boundary. Missing fields retain existing recovery errors.
#[derive(Clone, Default)]
pub struct RefreshMaterialDeletion {
    pub material_key: String,
    pub handle: Option<CredentialHandle>,
}

/// Storage boundary shared by every gateway secret consumer. This is an
/// in-process interface, not the future versioned issuer service contract.
#[async_trait]
pub trait CredentialIssuer: std::fmt::Debug + Send + Sync {
    fn validate_handles(&self, handles: &Handles) -> Result<(), Status>;
    fn stores_provider_credentials(&self) -> bool;
    fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool;
    fn negotiated_extensions(&self) -> &[NegotiatedExtension];

    async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status>;
    async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status>;
    async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status>;

    async fn store_refresh_material_with_object_id(
        &self,
        scope: RefreshMaterialScope<'_>,
        object_id: &str,
        material: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status>;
    async fn resolve_refresh_material(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, String>, Status>;
    async fn delete_refresh_material_handles(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<(), Status>;
    async fn delete_refresh_material_deletions(
        &self,
        scope: RefreshMaterialScope<'_>,
        deletions: &[RefreshMaterialDeletion],
    ) -> Result<(), Status>;
}

#[cfg(any(test, feature = "test-support"))]
pub type TestGate = (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
);

#[async_trait]
impl CredentialIssuer for EmbeddedCredentialIssuer {
    fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        Self::validate_handles(self, handles)
    }
    fn stores_provider_credentials(&self) -> bool {
        Self::stores_provider_credentials(self)
    }
    fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        Self::storage_owns_handle(self, handle)
    }
    fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        Self::negotiated_extensions(self)
    }
    async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status> {
        Self::store(self, request).await
    }
    async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        Self::delete(self, owner, handles).await
    }
    async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status> {
        Self::resolve(self, owner, handles).await
    }
    async fn store_refresh_material_with_object_id(
        &self,
        scope: RefreshMaterialScope<'_>,
        object_id: &str,
        material: &HashMap<String, String>,
        existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        Self::store_refresh_material_with_object_id(
            self,
            scope,
            object_id,
            material,
            existing_handles,
        )
        .await
    }
    async fn resolve_refresh_material(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        Self::resolve_refresh_material(self, scope, handles).await
    }
    async fn delete_refresh_material_handles(
        &self,
        scope: RefreshMaterialScope<'_>,
        handles: &Handles,
    ) -> Result<(), Status> {
        Self::delete_refresh_material_handles(self, scope, handles).await
    }
    async fn delete_refresh_material_deletions(
        &self,
        scope: RefreshMaterialScope<'_>,
        deletions: &[RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        Self::delete_refresh_material_deletions(self, scope, deletions).await
    }
}
