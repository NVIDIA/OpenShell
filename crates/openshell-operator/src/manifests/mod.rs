// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload manifest builders.
//!
//! Constructs Kubernetes Deployment and Service manifests from
//! `SandboxRuntime` specifications, analogous to Kagenti's
//! `_build_deployment_manifest` and `_build_service_manifest`.

pub mod deployment;
pub mod service;

pub use deployment::build_deployment;
pub use service::build_service;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Resource;

use crate::crd::SandboxRuntime;

/// Build an owner reference for garbage collection.
///
/// When the `SandboxRuntime` is deleted, Kubernetes will automatically
/// garbage-collect owned Deployments and Services via this reference.
///
/// Shared function used by both deployment and service builders (V1 review fix).
pub(crate) fn build_owner_reference(runtime: &SandboxRuntime) -> OwnerReference {
    OwnerReference {
        api_version: SandboxRuntime::api_version(&()).to_string(),
        kind: SandboxRuntime::kind(&()).to_string(),
        name: runtime.metadata.name.clone().unwrap_or_default(),
        uid: runtime.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}
