// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU resource requirement helpers.

pub use openshell_driver_sdk::gpu::*;

use crate::proto::ResourceRequirements as SandboxResourceRequirements;

/// Return whether sandbox resource requirements request a GPU.
#[must_use]
pub fn sandbox_gpu_requested(resources: Option<&SandboxResourceRequirements>) -> bool {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .is_some()
}

/// Return the requested sandbox GPU count, if one was specified.
#[must_use]
pub fn sandbox_gpu_count(resources: Option<&SandboxResourceRequirements>) -> Option<u32> {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .and_then(|gpu| gpu.count)
}
