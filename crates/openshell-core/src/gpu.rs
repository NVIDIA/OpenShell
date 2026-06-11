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

/// Validate a compute-driver GPU request against driver-owned specific devices.
///
/// Drivers call this when a sandbox request combines portable GPU requirements
/// with exact device identifiers in `driver_config`.
///
/// # Errors
/// Returns an error when the sandbox GPU request is absent or when `gpu.count`
/// does not equal the number of specific devices. A single exact device is
/// compatible with the default sandbox GPU request where `gpu.count` is absent.
pub fn validate_specific_gpu_device_request(
    gpu: Option<&DriverGpuResourceRequirements>,
    specific_devices: &[String],
    driver_config_field: &str,
) -> Result<(), String> {
    let device_count = specific_devices.len();
    if device_count == 0 {
        return Ok(());
    }

    let Some(gpu) = gpu else {
        return Err(format!("{driver_config_field} requires a gpu request"));
    };

    let Some(count) = gpu.count else {
        if device_count == 1 {
            return Ok(());
        }
        return Err(format!(
            "{driver_config_field} requires an explicit gpu count matching its length ({device_count})"
        ));
    };

    if usize::try_from(count).ok() != Some(device_count) {
        return Err(format!(
            "gpu count ({count}) must match {driver_config_field} length ({device_count})"
        ));
    }

    Ok(())
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

    #[test]
    fn validate_specific_gpu_device_request_ignores_empty_devices() {
        validate_specific_gpu_device_request(None, &[], "driver_config.cdi_devices")
            .expect("empty exact device lists should not be validated");
    }

    #[test]
    fn validate_specific_gpu_device_request_accepts_matching_count() {
        let gpu = DriverGpuResourceRequirements { count: Some(2) };
        let specific_devices = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ];

        validate_specific_gpu_device_request(
            Some(&gpu),
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect("matching count should be accepted");
    }

    #[test]
    fn validate_specific_gpu_device_request_accepts_missing_count_for_one_device() {
        let gpu = DriverGpuResourceRequirements { count: None };
        let specific_devices = vec!["nvidia.com/gpu=0".to_string()];

        validate_specific_gpu_device_request(
            Some(&gpu),
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect("single exact device should be compatible with a default GPU request");
    }

    #[test]
    fn validate_specific_gpu_device_request_rejects_missing_gpu_request() {
        let specific_devices = vec!["nvidia.com/gpu=0".to_string()];

        let err = validate_specific_gpu_device_request(
            None,
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect_err("missing GPU request should be rejected");

        assert_eq!(err, "driver_config.cdi_devices requires a gpu request");
    }

    #[test]
    fn validate_specific_gpu_device_request_rejects_missing_count_for_multiple_devices() {
        let gpu = DriverGpuResourceRequirements { count: None };
        let specific_devices = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ];

        let err = validate_specific_gpu_device_request(
            Some(&gpu),
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect_err("missing count should be rejected for multiple devices");

        assert_eq!(
            err,
            "driver_config.cdi_devices requires an explicit gpu count matching its length (2)"
        );
    }

    #[test]
    fn validate_specific_gpu_device_request_rejects_mismatch() {
        let gpu = DriverGpuResourceRequirements { count: Some(2) };
        let specific_devices = vec!["nvidia.com/gpu=0".to_string()];

        let err = validate_specific_gpu_device_request(
            Some(&gpu),
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect_err("mismatched count should be rejected");

        assert_eq!(
            err,
            "gpu count (2) must match driver_config.cdi_devices length (1)"
        );
    }
}
