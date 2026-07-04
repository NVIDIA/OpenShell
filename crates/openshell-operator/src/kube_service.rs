// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes client service for operator CRUD operations.
//!
//! Provides typed API handles for Deployments, Services, and SandboxRuntime
//! CRDs, wrapping the raw `kube::Client` with operator-specific convenience
//! methods.

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Service;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use tracing::debug;

use crate::crd::SandboxRuntime;
use crate::error::{OperatorError, Result};

/// Kubernetes client service for operator CRUD operations.
#[derive(Clone)]
pub struct KubeService {
    client: Client,
}

impl KubeService {
    /// Create a new service wrapping the given client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get a namespaced API handle for Deployments.
    pub fn deployments(&self, namespace: &str) -> Api<Deployment> {
        Api::namespaced(self.client.clone(), namespace)
    }

    /// Get a namespaced API handle for Services.
    pub fn services(&self, namespace: &str) -> Api<Service> {
        Api::namespaced(self.client.clone(), namespace)
    }

    /// Get a namespaced API handle for `SandboxRuntime` CRDs.
    pub fn sandbox_runtimes(&self, namespace: &str) -> Api<SandboxRuntime> {
        Api::namespaced(self.client.clone(), namespace)
    }

    /// Apply (create or update) a Deployment using server-side apply.
    ///
    /// Server-side apply is idempotent and handles both creation and updates.
    pub async fn apply_deployment(
        &self,
        namespace: &str,
        deployment: &Deployment,
        field_manager: &str,
    ) -> Result<Deployment> {
        let api = self.deployments(namespace);
        let name = deployment
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| OperatorError::MissingField("deployment.metadata.name".into()))?;

        let result = api
            .patch(
                name,
                &PatchParams::apply(field_manager),
                &Patch::Apply(deployment),
            )
            .await?;

        debug!(name, namespace, "deployment applied");
        Ok(result)
    }

    /// Apply (create or update) a Service using server-side apply.
    pub async fn apply_service(
        &self,
        namespace: &str,
        service: &Service,
        field_manager: &str,
    ) -> Result<Service> {
        let api = self.services(namespace);
        let name = service
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| OperatorError::MissingField("service.metadata.name".into()))?;

        let result = api
            .patch(
                name,
                &PatchParams::apply(field_manager),
                &Patch::Apply(service),
            )
            .await?;

        debug!(name, namespace, "service applied");
        Ok(result)
    }

    /// Delete a Deployment by name. Returns `Ok(())` if not found.
    pub async fn delete_deployment(&self, namespace: &str, name: &str) -> Result<()> {
        let api = self.deployments(namespace);
        match api.delete(name, &Default::default()).await {
            Ok(_) => {
                debug!(name, namespace, "deployment deleted");
                Ok(())
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                debug!(name, namespace, "deployment not found, nothing to delete");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a Service by name. Returns `Ok(())` if not found.
    pub async fn delete_service(&self, namespace: &str, name: &str) -> Result<()> {
        let api = self.services(namespace);
        match api.delete(name, &Default::default()).await {
            Ok(_) => {
                debug!(name, namespace, "service deleted");
                Ok(())
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                debug!(name, namespace, "service not found, nothing to delete");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Update the status subresource of a `SandboxRuntime`.
    pub async fn update_status(
        &self,
        namespace: &str,
        name: &str,
        runtime: &SandboxRuntime,
    ) -> Result<SandboxRuntime> {
        let api = self.sandbox_runtimes(namespace);
        let result = api
            .replace_status(name, &PostParams::default(), serde_json::to_vec(runtime)?)
            .await?;
        debug!(name, namespace, "status updated");
        Ok(result)
    }
}
