// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU request helpers.

use crate::config::CDI_GPU_DEVICE_ALL;
use crate::proto::compute::v1::GpuRequestSpec;

/// Resolve a driver GPU request into CDI device identifiers.
///
/// `None` means no GPU was requested. Presence with no explicit device IDs
/// uses the CDI all-GPU request; otherwise the driver-native IDs pass through.
#[must_use]
pub fn cdi_gpu_device_ids(gpu: Option<&GpuRequestSpec>) -> Option<Vec<String>> {
    match gpu {
        Some(gpu) if gpu.device_id.is_empty() => Some(vec![CDI_GPU_DEVICE_ALL.to_string()]),
        Some(gpu) => Some(gpu.device_id.clone()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(None), None);
    }

    #[test]
    fn cdi_gpu_device_ids_defaults_empty_request_to_all_gpus() {
        let request = GpuRequestSpec { device_id: vec![] };

        assert_eq!(
            cdi_gpu_device_ids(Some(&request)),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_single_device_id_through() {
        let request = GpuRequestSpec {
            device_id: vec!["nvidia.com/gpu=0".to_string()],
        };

        assert_eq!(
            cdi_gpu_device_ids(Some(&request)),
            Some(vec!["nvidia.com/gpu=0".to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_multiple_device_ids_through() {
        let request = GpuRequestSpec {
            device_id: vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string(),
            ],
        };

        assert_eq!(
            cdi_gpu_device_ids(Some(&request)),
            Some(vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ])
        );
    }
}
