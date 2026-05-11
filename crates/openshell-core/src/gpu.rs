// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU request helpers.

use crate::config::CDI_GPU_DEVICE_ALL;

/// Resolve the existing GPU request fields into CDI device identifiers.
///
/// `None` means no GPU was requested. A GPU request with no explicit device
/// ID uses the CDI all-GPU request; otherwise the driver-native ID passes
/// through unchanged.
#[must_use]
pub fn cdi_gpu_device_ids(gpu: bool, gpu_device: &str) -> Option<Vec<String>> {
    gpu.then(|| {
        if gpu_device.is_empty() {
            vec![CDI_GPU_DEVICE_ALL.to_string()]
        } else {
            vec![gpu_device.to_string()]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(false, ""), None);
    }

    #[test]
    fn cdi_gpu_device_ids_defaults_empty_request_to_all_gpus() {
        assert_eq!(
            cdi_gpu_device_ids(true, ""),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_explicit_device_id_through() {
        assert_eq!(
            cdi_gpu_device_ids(true, "nvidia.com/gpu=0"),
            Some(vec!["nvidia.com/gpu=0".to_string()])
        );
    }
}
