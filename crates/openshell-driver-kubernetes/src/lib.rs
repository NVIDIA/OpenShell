// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod bootstrap;
pub mod config;
pub mod driver;
mod extension_api;
pub mod grpc;
pub mod otel_tracing;
pub mod sandboxclaim;
mod warm_pool;

pub use bootstrap::{
    K8sIdentityResolver, KubernetesSupervisorBootstrapIdentityProvider, LiveK8sResolver,
};
pub use config::{
    AppArmorProfile, DEFAULT_GATEWAY_ID, DEFAULT_PROXY_UID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
    DEFAULT_WORKSPACE_STORAGE_SIZE, KubernetesComputeConfig, KubernetesSidecarConfig,
    KubernetesWarmPoolingConfig, ManagedSshIngressConfig, OperatorNamespaceAllowlist,
    SupervisorSideloadMethod, SupervisorTopology, WorkspaceMode, managed_namespace_prefix,
};
pub use driver::{KubernetesComputeDriver, KubernetesDriverError};
pub use grpc::ComputeDriverService;
pub use sandboxclaim::SandboxClaimActivationController;
pub use warm_pool::WarmActivationSupport;
