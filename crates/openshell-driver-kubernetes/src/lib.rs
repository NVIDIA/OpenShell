// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod config;

#[cfg(not(target_os = "windows"))]
pub mod driver;
#[cfg(not(target_os = "windows"))]
pub mod grpc;

pub use config::{
    AppArmorProfile, DEFAULT_PROXY_UID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
    DEFAULT_WORKSPACE_STORAGE_SIZE, KubernetesComputeConfig, KubernetesSidecarConfig,
    SupervisorSideloadMethod, SupervisorTopology,
};

#[cfg(not(target_os = "windows"))]
pub use driver::{KubernetesComputeDriver, KubernetesDriverError};
#[cfg(not(target_os = "windows"))]
pub use grpc::ComputeDriverService;
