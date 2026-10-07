// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU resource requirement helpers.

use std::collections::HashSet;
use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::CDI_GPU_DEVICE_ALL;
use crate::proto::ResourceRequirements as SandboxResourceRequirements;
use crate::proto::compute::v1::{
    GpuResourceRequirements as DriverGpuResourceRequirements,
    ResourceRequirements as DriverResourceRequirements,
};

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

#[derive(Debug)]
struct CdiGpuSelectorState {
    inventory: CdiGpuInventory,
    allow_all_devices: bool,
}

/// Concurrency-safe default CDI GPU selector used by local container drivers.
#[derive(Debug)]
pub struct CdiGpuDefaultSelector {
    state: RwLock<CdiGpuSelectorState>,
    round_robin: CdiGpuRoundRobin,
}

impl CdiGpuDefaultSelector {
    /// Create a selector with an initial discovered CDI GPU inventory snapshot.
    #[must_use]
    pub fn new(inventory: CdiGpuInventory, allow_all_devices: bool) -> Self {
        Self {
            state: RwLock::new(CdiGpuSelectorState {
                inventory,
                allow_all_devices,
            }),
            round_robin: CdiGpuRoundRobin::new(),
        }
    }

    /// Replace the cached inventory snapshot without resetting the cursor.
    pub fn refresh(&self, inventory: CdiGpuInventory, allow_all_devices: bool) {
        let mut state = self
            .state
            .write()
            .expect("CDI GPU selector state lock poisoned");
        state.inventory = inventory;
        state.allow_all_devices = allow_all_devices;
    }

    /// Return the cached normalized inventory snapshot.
    #[must_use]
    pub fn device_ids(&self) -> Vec<String> {
        self.state
            .read()
            .expect("CDI GPU selector state lock poisoned")
            .inventory
            .as_slice()
            .to_vec()
    }

    /// Return the current default device IDs without advancing the cursor.
    pub fn peek_device_ids(&self, count: u32) -> Result<Vec<String>, CdiGpuSelectionError> {
        self.selected_device_ids(count, false)
    }

    /// Return the next default device IDs and advance the cursor.
    pub fn next_device_ids(&self, count: u32) -> Result<Vec<String>, CdiGpuSelectionError> {
        self.selected_device_ids(count, true)
    }

    fn selected_device_ids(
        &self,
        count: u32,
        consume: bool,
    ) -> Result<Vec<String>, CdiGpuSelectionError> {
        let state = self
            .state
            .read()
            .expect("CDI GPU selector state lock poisoned");
        self.round_robin.selected_default_device_ids(
            &state.inventory,
            count,
            consume,
            state.allow_all_devices,
        )
    }
}

/// Concurrency-safe round-robin cursor for default CDI GPU selection.
#[derive(Debug, Default)]
struct CdiGpuRoundRobin {
    next: AtomicUsize,
}

impl CdiGpuRoundRobin {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }

    fn selected_default_device_ids(
        &self,
        inventory: &CdiGpuInventory,
        count: u32,
        consume: bool,
        allow_all_devices: bool,
    ) -> Result<Vec<String>, CdiGpuSelectionError> {
        let devices = inventory.default_device_family(allow_all_devices)?;
        let count =
            usize::try_from(count).map_err(|_| CdiGpuSelectionError::InsufficientDevices {
                requested: count,
                available: u32::try_from(devices.len()).unwrap_or(u32::MAX),
            })?;
        let available = devices.len();
        if count > available {
            return Err(CdiGpuSelectionError::InsufficientDevices {
                requested: u32::try_from(count).unwrap_or(u32::MAX),
                available: u32::try_from(available).unwrap_or(u32::MAX),
            });
        }
        let base = if consume {
            self.next.fetch_add(count, Ordering::Relaxed)
        } else {
            self.next.load(Ordering::Relaxed)
        };
        Ok((0..count)
            .map(|offset| devices[(base + offset) % available].clone())
            .collect())
    }
}

/// CDI GPU selection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdiGpuSelectionError {
    NoAvailableDevices,
    AllDevicesDefaultUnsupported,
    InsufficientDevices { requested: u32, available: u32 },
}

impl fmt::Display for CdiGpuSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAvailableDevices => f.write_str("no NVIDIA CDI GPU devices were discovered"),
            Self::AllDevicesDefaultUnsupported => f.write_str(
                "default GPU request resolved only to nvidia.com/gpu=all, which is not allowed on this platform; set driver_config.cdi_devices to [\"nvidia.com/gpu=all\"] explicitly to request all GPUs",
            ),
            Self::InsufficientDevices {
                requested,
                available: 0,
            } => write!(
                f,
                "GPU sandbox requested {requested} GPUs, but no selectable NVIDIA CDI GPU devices are available"
            ),
            Self::InsufficientDevices {
                requested,
                available: 1,
            } => write!(
                f,
                "GPU sandbox requested {requested} GPUs, but only 1 selectable NVIDIA CDI GPU device is available"
            ),
            Self::InsufficientDevices {
                requested,
                available,
            } => write!(
                f,
                "GPU sandbox requested {requested} GPUs, but only {available} selectable NVIDIA CDI GPU devices are available"
            ),
        }
    }
}

impl std::error::Error for CdiGpuSelectionError {}

fn cdi_nvidia_gpu_suffix(id: &str) -> Option<&str> {
    id.strip_prefix(CDI_NVIDIA_GPU_PREFIX)
}

// Local equivalent of the upstream CDI parser until its public API is released:
// https://github.com/cncf-tags/container-device-interface-rs/pull/177
fn is_qualified_name(device: &str) -> bool {
    let Some((kind, name)) = device.split_once('=') else {
        return false;
    };
    let Some((vendor, class)) = kind.split_once('/') else {
        return false;
    };
    let valid_component = |value: &str, device_name: bool| {
        let bytes = value.as_bytes();
        bytes.first().is_some_and(|byte| {
            if device_name {
                byte.is_ascii_alphanumeric()
            } else {
                byte.is_ascii_alphabetic()
            }
        }) && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.')
                    || (device_name && *byte == b':')
            })
    };
    valid_component(vendor, false) && valid_component(class, false) && valid_component(name, true)
}

/// Validate vendor-agnostic CDI qualified names without resolving or authorizing devices.
///
/// # Errors
/// Returns an error for host paths or malformed `<vendor>/<class>=<name>` selectors.
pub fn validate_cdi_device_names(devices: &[String], field: &str) -> Result<(), String> {
    if devices.iter().any(|device| !is_qualified_name(device)) {
        return Err(format!(
            "{field} must contain CDI qualified names (<vendor>/<class>=<name>)"
        ));
    }
    Ok(())
}

/// Validate explicit CDI selectors and their GPU request requirements.
///
/// Docker and Podman use this helper; drivers with other identifier formats use
/// [`validate_specific_gpu_device_request`] directly.
///
/// # Errors
/// Returns an error for malformed CDI names or invalid GPU request requirements.
pub fn validate_cdi_gpu_device_request(
    gpu: Option<&DriverGpuResourceRequirements>,
    devices: &[String],
    field: &str,
) -> Result<(), String> {
    validate_cdi_device_names(devices, field)?;
    validate_specific_gpu_device_request(gpu, devices, field)
}

/// Validate a compute-driver GPU request against driver-owned specific devices.
///
/// Drivers call this when a sandbox request combines portable GPU requirements
/// with exact device identifiers in `driver_config`.
///
/// # Errors
/// Returns an error when the sandbox GPU request is absent, when `gpu.count`
/// is zero, when device IDs are duplicated, or when the effective GPU count
/// does not equal the number of specific devices.
pub fn validate_specific_gpu_device_request(
    gpu: Option<&DriverGpuResourceRequirements>,
    specific_devices: &[String],
    driver_config_field: &str,
) -> Result<(), String> {
    let device_count = specific_devices.len();
    if device_count == 0 {
        return Ok(());
    }

    let mut seen = HashSet::with_capacity(device_count);
    for device in specific_devices {
        if !seen.insert(device.as_str()) {
            return Err(format!(
                "{driver_config_field} contains duplicate device ID '{device}'"
            ));
        }
    }

    let Some(count) = effective_driver_gpu_count(gpu)? else {
        return Err(format!("{driver_config_field} requires a gpu request"));
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
    fn cdi_device_names_accept_vendor_agnostic_selectors() {
        for device in [
            "nvidia.com/gpu=0",
            "nvidia.com/gpu=all",
            "nvidia.com/gpu=GPU-5b2d",
            "nvidia.com/gpu=MIG-5b2d",
            "nvidia.com/gpu=0:1",
            "example.com/accelerator=card_0.1",
            "intel.com/gpu=0",
            "amd.com/gpu=0",
            "v/c=0",
        ] {
            let devices = vec![device.to_string()];
            validate_cdi_device_names(&devices, "driver_config.cdi_devices")
                .unwrap_or_else(|error| panic!("{device:?}: {error}"));
        }
    }

    #[test]
    fn cdi_device_names_reject_host_paths_and_malformed_selectors() {
        for device in [
            "",
            "/dev/sda",
            "/dev",
            "/dev/sda:/dev/sda:rwm",
            "dev/sda",
            "../dev/sda",
            "vendor/gpu",
            "/gpu=0",
            "vendor/=0",
            "vendor/gpu=",
            "vendor/gpu=/dev/sda",
            "vendor/gpu=0/1",
            "vendor/gpu=0=1",
            "vendor/gpu=0,1",
            "vendor/gpu=-0",
            "vendor/gpu=0:",
            "vendor/gpu=0 ",
            " vendor/gpu=0",
            "vendor/gpu=0\n",
            "vendor/gpu=0\0",
            "vendor/gpu=é",
            "véndor/gpu=0",
            "vendor/gpü=0",
            "0vendor/gpu=0",
            "vendor/0gpu=0",
            "vendor./gpu=0",
            "vendor/gpu-=0",
            "vendor/gpu/other=0",
        ] {
            let error =
                validate_cdi_device_names(&[device.to_string()], "driver_config.cdi_devices")
                    .unwrap_err();
            assert!(error.contains("CDI qualified names"), "{device:?}: {error}");
        }
    }

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
    fn selector_prefers_indexed_family_and_sorts_numerically() {
        let inventory = CdiGpuInventory::new([
            "nvidia.com/gpu=10",
            "nvidia.com/gpu=UUID-b",
            "nvidia.com/gpu=2",
            "nvidia.com/gpu=all",
        ]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=2".to_string()])
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=10".to_string()])
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=2".to_string()])
        );
    }

    #[test]
    fn selector_uses_named_family_when_no_indexed_ids_exist() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=UUID-b", "nvidia.com/gpu=UUID-a"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=UUID-a".to_string()])
        );
    }

    #[test]
    fn selector_uses_all_only_inventory_when_allowed() {
        let inventory = CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]);
        let selector = CdiGpuDefaultSelector::new(inventory, true);

        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn selector_rejects_all_only_inventory_when_not_allowed() {
        let inventory = CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(1),
            Err(CdiGpuSelectionError::AllDevicesDefaultUnsupported)
        );
    }

    #[test]
    fn selector_rejects_empty_inventory() {
        let inventory = CdiGpuInventory::new(["vendor.example/device=0"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(1),
            Err(CdiGpuSelectionError::NoAvailableDevices)
        );
    }

    #[test]
    fn peek_does_not_advance_round_robin_cursor() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.peek_device_ids(1),
            Ok(vec!["nvidia.com/gpu=0".to_string()])
        );
        assert_eq!(
            selector.peek_device_ids(1),
            Ok(vec!["nvidia.com/gpu=0".to_string()])
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=0".to_string()])
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=1".to_string()])
        );
    }

    #[test]
    fn selector_selects_multiple_distinct_devices_in_cursor_order() {
        let inventory =
            CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1", "nvidia.com/gpu=2"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(2),
            Ok(vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ])
        );
        assert_eq!(
            selector.next_device_ids(2),
            Ok(vec![
                "nvidia.com/gpu=2".to_string(),
                "nvidia.com/gpu=0".to_string()
            ])
        );
    }

    #[test]
    fn selector_rejects_count_larger_than_selectable_family_without_advancing() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(3),
            Err(CdiGpuSelectionError::InsufficientDevices {
                requested: 3,
                available: 2
            })
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=0".to_string()])
        );
    }

    #[test]
    fn selector_treats_all_only_inventory_as_one_selectable_device() {
        let inventory = CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]);
        let selector = CdiGpuDefaultSelector::new(inventory, true);

        assert_eq!(
            selector.next_device_ids(2),
            Err(CdiGpuSelectionError::InsufficientDevices {
                requested: 2,
                available: 1
            })
        );
    }

    #[test]
    fn selector_refreshes_inventory_without_resetting_cursor() {
        let inventory = CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]);
        let selector = CdiGpuDefaultSelector::new(inventory, false);

        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=0".to_string()])
        );
        selector.refresh(
            CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1", "nvidia.com/gpu=2"]),
            false,
        );
        assert_eq!(
            selector.next_device_ids(1),
            Ok(vec!["nvidia.com/gpu=1".to_string()])
        );
    }

    #[test]
    fn specific_gpu_device_request_preserves_non_cdi_identifiers() {
        let gpu = DriverGpuResourceRequirements { count: Some(1) };
        let devices = vec!["0000:2d:00.0".to_string()];
        validate_specific_gpu_device_request(Some(&gpu), &devices, "driver_config.gpu_device_ids")
            .expect("generic GPU request validation must accept PCI device identifiers");
        let error =
            validate_cdi_gpu_device_request(Some(&gpu), &devices, "driver_config.cdi_devices")
                .expect_err("CDI drivers must reject non-CDI identifiers");
        assert!(error.contains("CDI qualified names"));
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
            "gpu count (1) must match driver_config.cdi_devices length (2)"
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

    #[test]
    fn validate_specific_gpu_device_request_rejects_duplicate_ids() {
        let gpu = DriverGpuResourceRequirements { count: Some(2) };
        let specific_devices = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=0".to_string(),
        ];

        let err = validate_specific_gpu_device_request(
            Some(&gpu),
            &specific_devices,
            "driver_config.cdi_devices",
        )
        .expect_err("duplicates should be rejected");

        assert_eq!(
            err,
            "driver_config.cdi_devices contains duplicate device ID 'nvidia.com/gpu=0'"
        );
    }
}
