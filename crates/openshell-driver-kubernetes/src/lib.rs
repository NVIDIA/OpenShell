// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod driver;
pub mod grpc;
pub mod isolation;
pub mod otel_tracing;
mod proxy_pod;

pub use config::{
    DEFAULT_GATEWAY_ID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, KubernetesProxyPodConfig, ManagedSshIngressConfig, WorkspaceMode,
    managed_namespace_prefix,
};
pub use driver::{KubernetesComputeDriver, KubernetesDriverError};
pub use grpc::ComputeDriverService;
pub use openshell_core::DynamicStringAllowlist as OperatorNamespaceAllowlist;
