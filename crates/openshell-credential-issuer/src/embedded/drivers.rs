// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Extracted credential-driver implementation.

use super::CredentialDriver;
use async_trait::async_trait;
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential, StoreCredentialRequest,
};
use openshell_driver_db_credstore::DbCredstoreCredentialDriver;
use openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver;
use openshell_driver_vault::VaultCredentialDriver;
use tonic::Status;

#[async_trait]
impl CredentialDriver for KubernetesSecretsCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}

#[async_trait]
impl CredentialDriver for DbCredstoreCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}

#[async_trait]
impl CredentialDriver for VaultCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Self::store_credential(self, request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        Self::delete_credential(self, request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        Self::resolve_credentials(self, requests).await
    }
}
