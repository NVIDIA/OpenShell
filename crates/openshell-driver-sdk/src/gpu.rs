// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU resource requirement helpers.

use crate::proto::compute::v1::{
    GpuResourceRequirements as DriverGpuResourceRequirements,
    ResourceRequirements as DriverResourceRequirements,
};

/// Return the effective compute-driver GPU count.
///
/// A present GPU requirement with an omitted count requests one GPU.
///
/// # Errors
/// Returns an error when a GPU requirement explicitly requests zero GPUs.
pub fn effective_driver_gpu_count(
    gpu: Option<&DriverGpuResourceRequirements>,
) -> Result<Option<u32>, String> {
    let Some(gpu) = gpu else {
        return Ok(None);
    };
    let count = gpu.count.unwrap_or(1);
    if count == 0 {
        return Err("gpu count must be greater than 0".to_string());
    }
    Ok(Some(count))
}

/// Return the requested compute-driver GPU requirements, if present.
#[must_use]
pub fn driver_gpu_requirements(
    resources: Option<&DriverResourceRequirements>,
) -> Option<&DriverGpuResourceRequirements> {
    resources.and_then(|resources| resources.gpu.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_driver_gpu_count_normalizes_missing_count() {
        let gpu = DriverGpuResourceRequirements { count: None };

        assert_eq!(effective_driver_gpu_count(Some(&gpu)), Ok(Some(1)));
        assert_eq!(effective_driver_gpu_count(None), Ok(None));
    }

    #[test]
    fn effective_driver_gpu_count_rejects_zero_count() {
        let gpu = DriverGpuResourceRequirements { count: Some(0) };

        assert_eq!(
            effective_driver_gpu_count(Some(&gpu)),
            Err("gpu count must be greater than 0".to_string())
        );
    }
}
