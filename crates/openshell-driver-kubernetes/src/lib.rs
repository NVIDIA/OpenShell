// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod driver;
pub mod grpc;

pub use config::{
    AppArmorProfile, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, SupervisorSideloadMethod, SupervisorTopology,
};
pub use driver::{KubernetesComputeDriver, KubernetesDriverError};
pub use grpc::ComputeDriverService;

/// Compile-out guard: greppable proof this crate is linked into a binary.
///
/// `tasks/scripts/verify-drivers-compiled-out.sh` asserts this string is
/// present when `--features driver-kubernetes` is on and absent when it is
/// off. `#[used]` prevents dead-code elimination; the linker cannot drop it.
/// Do not remove without updating the verify script.
#[used]
static COMPILE_MARKER: &str = "OPENSHELL_DRIVER_MARKER:kubernetes";
