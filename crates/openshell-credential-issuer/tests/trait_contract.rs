// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A separate consumer must implement only the storage contract, including when
//! Cargo enables `test-support` through another workspace member.

use std::collections::HashMap;

use async_trait::async_trait;
use openshell_core::extension_protocol::NegotiatedExtension;
use openshell_core::proto::CredentialHandle;
use openshell_credential_issuer::{
    CredentialIssuer, Handles, RefreshMaterialDeletion, RefreshMaterialScope, ResolvedSecret,
    SecretOwner, StoreSecrets,
};
use tonic::{Code, Status};

#[derive(Debug)]
struct StorageOnlyIssuer;

// Deliberately no embedded test hooks or feature-dependent methods. Adding a
// required hook to CredentialIssuer breaks this consumer's compilation.
#[async_trait]
impl CredentialIssuer for StorageOnlyIssuer {
    fn validate_handles(&self, _handles: &Handles) -> Result<(), Status> {
        Ok(())
    }

    fn stores_provider_credentials(&self) -> bool {
        false
    }

    fn storage_owns_handle(&self, _handle: &CredentialHandle) -> bool {
        false
    }

    fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        &[]
    }

    async fn store(&self, _request: StoreSecrets<'_>) -> Result<Handles, Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn delete(&self, _owner: SecretOwner<'_>, _handles: &Handles) -> Result<(), Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn resolve(
        &self,
        _owner: SecretOwner<'_>,
        _handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn store_refresh_material_with_object_id(
        &self,
        _scope: RefreshMaterialScope<'_>,
        _object_id: &str,
        _material: &HashMap<String, String>,
        _existing_handles: &Handles,
    ) -> Result<Handles, Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn resolve_refresh_material(
        &self,
        _scope: RefreshMaterialScope<'_>,
        _handles: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn delete_refresh_material_handles(
        &self,
        _scope: RefreshMaterialScope<'_>,
        _handles: &Handles,
    ) -> Result<(), Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }

    async fn delete_refresh_material_deletions(
        &self,
        _scope: RefreshMaterialScope<'_>,
        _deletions: &[RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        Err(Status::unimplemented("storage-only contract fixture"))
    }
}

#[tokio::test]
async fn storage_implementation_needs_no_embedded_test_hooks() {
    let issuer: &dyn CredentialIssuer = &StorageOnlyIssuer;
    let handles = Handles::new();
    issuer.validate_handles(&handles).unwrap();
    assert!(!issuer.stores_provider_credentials());
    assert!(issuer.negotiated_extensions().is_empty());
    let result = issuer
        .resolve(
            SecretOwner::provider("workspace", "provider-id", "provider"),
            &handles,
        )
        .await;
    assert!(matches!(result, Err(status) if status.code() == Code::Unimplemented));
}
