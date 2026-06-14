// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU request helpers.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::CDI_GPU_DEVICE_ALL;

const CDI_NVIDIA_GPU_PREFIX: &str = "nvidia.com/gpu=";
const CDI_NVIDIA_GPU_ALL_SUFFIX: &str = "all";

/// Normalized CDI GPU inventory used by local container drivers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdiGpuInventory {
    device_ids: Vec<String>,
}

impl CdiGpuInventory {
    /// Build a normalized inventory from runtime-reported CDI device IDs.
    #[must_use]
    pub fn new(device_ids: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut device_ids = device_ids
            .into_iter()
            .filter_map(|id| {
                let id = id.as_ref().trim();
                id.starts_with(CDI_NVIDIA_GPU_PREFIX)
                    .then(|| id.to_string())
            })
            .collect::<Vec<_>>();
        device_ids.sort();
        device_ids.dedup();
        Self { device_ids }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.device_ids
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.device_ids.is_empty()
    }

    fn default_device_family(
        &self,
        allow_all_devices: bool,
    ) -> Result<Vec<String>, CdiGpuSelectionError> {
        let mut indexed = self
            .device_ids
            .iter()
            .filter_map(|id| {
                let suffix = cdi_nvidia_gpu_suffix(id)?;
                let index = suffix.parse::<u64>().ok()?;
                Some((index, id.clone()))
            })
            .collect::<Vec<_>>();
        if !indexed.is_empty() {
            indexed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            return Ok(indexed.into_iter().map(|(_, id)| id).collect());
        }

        let mut named = self
            .device_ids
            .iter()
            .filter_map(|id| {
                let suffix = cdi_nvidia_gpu_suffix(id)?;
                (suffix != CDI_NVIDIA_GPU_ALL_SUFFIX).then(|| id.clone())
            })
            .collect::<Vec<_>>();
        if !named.is_empty() {
            named.sort();
            return Ok(named);
        }

        if self.device_ids.iter().any(|id| id == CDI_GPU_DEVICE_ALL) {
            if !allow_all_devices {
                return Err(CdiGpuSelectionError::AllDevicesDefaultUnsupported);
            }
            return Ok(vec![CDI_GPU_DEVICE_ALL.to_string()]);
        }

        Err(CdiGpuSelectionError::NoAvailableDevices)
    }
}

/// Concurrency-safe round-robin cursor for default CDI GPU selection.
#[derive(Debug, Default)]
pub struct CdiGpuRoundRobin {
    next: AtomicUsize,
}

impl CdiGpuRoundRobin {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }

    /// Return the next default device ID and advance the cursor.
    pub fn next_default_device_id(
        &self,
        inventory: &CdiGpuInventory,
        allow_all_devices: bool,
    ) -> Result<String, CdiGpuSelectionError> {
        self.selected_default_device_id(inventory, true, allow_all_devices)
    }

    /// Return the current default device ID without advancing the cursor.
    pub fn peek_default_device_id(
        &self,
        inventory: &CdiGpuInventory,
        allow_all_devices: bool,
    ) -> Result<String, CdiGpuSelectionError> {
        self.selected_default_device_id(inventory, false, allow_all_devices)
    }

    fn selected_default_device_id(
        &self,
        inventory: &CdiGpuInventory,
        consume: bool,
        allow_all_devices: bool,
    ) -> Result<String, CdiGpuSelectionError> {
        let devices = inventory.default_device_family(allow_all_devices)?;
        let base = if consume {
            self.next.fetch_add(1, Ordering::Relaxed)
        } else {
            self.next.load(Ordering::Relaxed)
        };
        Ok(devices[base % devices.len()].clone())
    }
}

/// CDI GPU selection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdiGpuSelectionError {
    NoAvailableDevices,
    MissingDefaultDevice,
    AllDevicesDefaultUnsupported,
}

impl fmt::Display for CdiGpuSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAvailableDevices => f.write_str("no NVIDIA CDI GPU devices were discovered"),
            Self::MissingDefaultDevice => {
                f.write_str("GPU request requires a selected default CDI GPU device")
            }
            Self::AllDevicesDefaultUnsupported => f.write_str(
                "default GPU request resolved only to nvidia.com/gpu=all, which is not allowed on this platform; set driver_config.cdi_devices to [\"nvidia.com/gpu=all\"] explicitly to request all GPUs",
            ),
        }
    }
}

impl std::error::Error for CdiGpuSelectionError {}

/// Resolve a local runtime GPU request into CDI device identifiers.
///
/// `None` means no GPU was requested. Explicit driver-configured CDI devices
/// pass through unchanged. A default GPU request uses the driver-selected
/// default CDI ID.
pub fn cdi_gpu_device_ids(
    gpu: bool,
    cdi_devices: &[String],
    selected_default_device: Option<&str>,
) -> Result<Option<Vec<String>>, CdiGpuSelectionError> {
    if !gpu {
        return Ok(None);
    }
    if !cdi_devices.is_empty() {
        return Ok(Some(cdi_devices.to_vec()));
    }
    let device = selected_default_device.ok_or(CdiGpuSelectionError::MissingDefaultDevice)?;
    Ok(Some(vec![device.to_string()]))
}

/// Resolve a GPU request with the legacy all-GPU default.
#[must_use]
pub fn cdi_gpu_device_ids_or_all(gpu: bool, cdi_devices: &[String]) -> Option<Vec<String>> {
    gpu.then(|| {
        if cdi_devices.is_empty() {
            vec![CDI_GPU_DEVICE_ALL.to_string()]
        } else {
            cdi_devices.to_vec()
        }
    })
}

fn cdi_nvidia_gpu_suffix(id: &str) -> Option<&str> {
    id.strip_prefix(CDI_NVIDIA_GPU_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(false, &[], None), Ok(None));
    }

    #[test]
    fn cdi_gpu_device_ids_uses_selected_default_device() {
        assert_eq!(
            cdi_gpu_device_ids(true, &[], Some("nvidia.com/gpu=0")),
            Ok(Some(vec!["nvidia.com/gpu=0".to_string()]))
        );
    }

    #[test]
    fn cdi_gpu_device_ids_rejects_missing_default_device() {
        assert_eq!(
            cdi_gpu_device_ids(true, &[], None),
            Err(CdiGpuSelectionError::MissingDefaultDevice)
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
                ],
                None
            ),
            Ok(Some(vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ]))
        );
    }

    #[test]
    fn cdi_gpu_device_ids_or_all_uses_all_when_no_devices_are_configured() {
        assert_eq!(
            cdi_gpu_device_ids_or_all(true, &[]),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn inventory_filters_and_deduplicates_nvidia_gpu_ids() {
        let inventory = CdiGpuInventory::new([
            "nvidia.com/gpu=1",
            "vendor.example/device=0",
            "nvidia.com/gpu=1",
            " nvidia.com/gpu=0 ",
        ]);

        assert_eq!(
            inventory.as_slice(),
            &vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ]
        );
    }

    #[test]
    fn round_robin_prefers_indexed_family_and_sorts_numerically() {
        let inventory = CdiGpuInventory::new([
            "nvidia.com/gpu=10",
            "nvidia.com/gpu=UUID-b",
            "nvidia.com/gpu=2",
            "nvidia.com/gpu=all",
        ]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=2".to_string())
        );
        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=10".to_string())
        );
        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=2".to_string())
        );
    }

    #[test]
    fn round_robin_uses_named_family_when_no_indexed_ids_exist() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=UUID-b", "nvidia.com/gpu=UUID-a"]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=UUID-a".to_string())
        );
    }

    #[test]
    fn round_robin_uses_all_only_inventory_when_allowed() {
        let inventory = CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.next_default_device_id(&inventory, true),
            Ok(CDI_GPU_DEVICE_ALL.to_string())
        );
    }

    #[test]
    fn round_robin_rejects_all_only_inventory_when_not_allowed() {
        let inventory = CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Err(CdiGpuSelectionError::AllDevicesDefaultUnsupported)
        );
    }

    #[test]
    fn round_robin_rejects_empty_inventory() {
        let inventory = CdiGpuInventory::new(["vendor.example/device=0"]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Err(CdiGpuSelectionError::NoAvailableDevices)
        );
    }

    #[test]
    fn peek_does_not_advance_round_robin_cursor() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]);
        let selector = CdiGpuRoundRobin::new();

        assert_eq!(
            selector.peek_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=0".to_string())
        );
        assert_eq!(
            selector.peek_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=0".to_string())
        );
        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=0".to_string())
        );
        assert_eq!(
            selector.next_default_device_id(&inventory, false),
            Ok("nvidia.com/gpu=1".to_string())
        );
    }
}
