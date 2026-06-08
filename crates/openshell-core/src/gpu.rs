// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU request helpers.

use crate::config::CDI_GPU_DEVICE_ALL;
use crate::proto::ResourceRequirements as PublicResourceRequirements;
use crate::proto::compute::v1::ResourceRequirements as DriverResourceRequirements;

/// Return whether public resource requirements request a GPU.
#[must_use]
pub fn public_gpu_requested(resources: Option<&PublicResourceRequirements>) -> bool {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .is_some()
}

/// Return the requested public GPU count, if one was specified.
#[must_use]
pub fn public_gpu_count(resources: Option<&PublicResourceRequirements>) -> Option<u32> {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .and_then(|gpu| gpu.count)
}

/// Return whether driver resource requirements request a GPU.
#[must_use]
pub fn driver_gpu_requested(resources: Option<&DriverResourceRequirements>) -> bool {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .is_some()
}

/// Return the requested driver GPU count, if one was specified.
#[must_use]
pub fn driver_gpu_count(resources: Option<&DriverResourceRequirements>) -> Option<u32> {
    resources
        .and_then(|resources| resources.gpu.as_ref())
        .and_then(|gpu| gpu.count)
}

/// Resolve a GPU request into CDI device identifiers.
///
/// `None` means no GPU was requested. A GPU request with no explicit CDI
/// devices uses the CDI all-GPU request; otherwise the driver-configured CDI
/// devices pass through unchanged.
#[must_use]
pub fn cdi_gpu_device_ids(gpu: bool, cdi_devices: &[String]) -> Option<Vec<String>> {
    gpu.then(|| {
        if cdi_devices.is_empty() {
            vec![CDI_GPU_DEVICE_ALL.to_string()]
        } else {
            cdi_devices.to_vec()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(false, &[]), None);
    }

    #[test]
    fn cdi_gpu_device_ids_defaults_empty_request_to_all_gpus() {
        assert_eq!(
            cdi_gpu_device_ids(true, &[]),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_explicit_device_ids_through() {
        assert_eq!(
            cdi_gpu_device_ids(
                true,
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
