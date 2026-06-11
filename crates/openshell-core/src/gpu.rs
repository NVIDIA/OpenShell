// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU resource requirement helpers.

use crate::config::CDI_GPU_DEVICE_ALL;
use crate::proto::ResourceRequirements as SandboxResourceRequirements;
use crate::proto::compute::v1::{
    GpuResourceRequirements as DriverGpuResourceRequirements,
    ResourceRequirements as DriverResourceRequirements,
};

/// Return whether sandbox resource requirements request a GPU.
#[must_use]
pub fn public_gpu_requested(resources: Option<&SandboxResourceRequirements>) -> bool {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .is_some()
}

/// Return the requested sandbox GPU count, if one was specified.
#[must_use]
pub fn public_gpu_count(resources: Option<&SandboxResourceRequirements>) -> Option<u32> {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .and_then(|gpu| gpu.count)
}

/// Return whether compute-driver resource requirements request a GPU.
#[must_use]
pub fn driver_gpu_requested(resources: Option<&DriverResourceRequirements>) -> bool {
    driver_gpu_requirements(resources).is_some()
}

/// Return the requested compute-driver GPU count, if one was specified.
#[must_use]
pub fn driver_gpu_count(resources: Option<&DriverResourceRequirements>) -> Option<u32> {
    driver_gpu_requirements(resources).and_then(|gpu| gpu.count)
}

/// Return the requested compute-driver GPU requirements, if present.
#[must_use]
pub fn driver_gpu_requirements(
    resources: Option<&DriverResourceRequirements>,
) -> Option<&DriverGpuResourceRequirements> {
    resources.and_then(|resources| resources.gpu.as_ref())
}

/// Resolve a compute-driver GPU request into CDI device identifiers.
///
/// `None` means no GPU was requested. A GPU request with no explicit CDI
/// devices uses the CDI all-GPU request; otherwise the driver-configured CDI
/// devices pass through unchanged.
#[must_use]
pub fn cdi_gpu_device_ids(
    gpu: Option<&DriverGpuResourceRequirements>,
    cdi_devices: &[String],
) -> Option<Vec<String>> {
    match gpu {
        Some(_) if cdi_devices.is_empty() => Some(vec![CDI_GPU_DEVICE_ALL.to_string()]),
        Some(_) => Some(cdi_devices.to_vec()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(None, &[]), None);
    }

    #[test]
    fn cdi_gpu_device_ids_defaults_empty_request_to_all_gpus() {
        let gpu = DriverGpuResourceRequirements { count: None };

        assert_eq!(
            cdi_gpu_device_ids(Some(&gpu), &[]),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_explicit_device_ids_through() {
        let gpu = DriverGpuResourceRequirements { count: None };

        assert_eq!(
            cdi_gpu_device_ids(
                Some(&gpu),
                &[
                    "nvidia.com/gpu=0".to_string(),
                    "nvidia.com/gpu=1".to_string()
                ]
            ),
            Some(vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ])
        );
    }
}
