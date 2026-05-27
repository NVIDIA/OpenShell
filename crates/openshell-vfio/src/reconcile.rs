// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pci::PciBindState;
use crate::sysfs::{SysfsRoot, write_sysfs};
use std::fs;
use std::path::Path;

/// Reconcile stale VFIO bindings left over from a previous crash.
///
/// Loads persisted state, checks each PCI device, and restores any that are
/// still bound to `vfio-pci`. Returns the list of BDFs that were restored.
/// Removes the state file only when all bindings are resolved; rewrites it with
/// the remaining entries when some restorations fail so they can be retried on
/// the next process start.
pub fn reconcile_stale_bindings(sysfs: &SysfsRoot, state_path: &Path) -> Vec<String> {
    let state = match PciBindState::load(state_path) {
        Ok(s) => s,
        Err(err) => {
            tracing::debug!(%err, path = %state_path.display(), "no stale VFIO bind state to reconcile");
            return Vec::new();
        }
    };

    // Any in-memory refcounts are stale (from a previous process that crashed).
    // Clear them so deregister writes through to sysfs.
    crate::bind::clear_vfio_id_refcounts();

    let mut restored = Vec::new();
    let mut failed_bindings = Vec::new();

    for binding in &state.bindings {
        match crate::bind::current_driver_name(sysfs, &binding.bdf) {
            Some(ref drv) if drv == "vfio-pci" => {
                tracing::warn!(
                    bdf = %binding.bdf,
                    sandbox_id = %binding.sandbox_id,
                    "stale VFIO binding detected, restoring PCI device to host driver"
                );
                if let Err(err) = crate::bind::restore_to_host_driver(sysfs, &binding.bdf) {
                    tracing::error!(bdf = %binding.bdf, %err, "failed to restore stale VFIO binding");
                    failed_bindings.push(binding.clone());
                    continue;
                }
                restored.push(binding.bdf.clone());
            }
            _ => {
                let device = sysfs.pci_device_ref(&binding.bdf);
                if let Ok(val) = device.driver_override()
                    && val == "vfio-pci"
                {
                    tracing::warn!(
                        bdf = %binding.bdf,
                        sandbox_id = %binding.sandbox_id,
                        "stale driver_override detected, clearing and re-probing"
                    );
                    crate::bind::deregister_vfio_new_id(sysfs, &binding.bdf);
                    if let Err(err) = device.clear_driver_override() {
                        tracing::error!(bdf = %binding.bdf, %err, "failed to clear stale driver_override");
                        failed_bindings.push(binding.clone());
                        continue;
                    }
                    let probe = sysfs.drivers_probe();
                    if let Err(err) = write_sysfs(&probe, &binding.bdf) {
                        tracing::error!(bdf = %binding.bdf, %err, "failed to re-probe after clearing driver_override");
                    }
                    restored.push(binding.bdf.clone());
                } else {
                    tracing::debug!(bdf = %binding.bdf, "PCI device no longer bound to vfio-pci, skipping");
                }
            }
        }
    }

    if failed_bindings.is_empty() {
        if let Err(err) = fs::remove_file(state_path) {
            tracing::warn!(%err, path = %state_path.display(), "failed to remove stale bind state file");
        }
    } else {
        let remaining = PciBindState {
            bindings: failed_bindings,
        };
        match serde_json::to_string_pretty(&remaining) {
            Ok(json) => {
                if let Err(err) = fs::write(state_path, json) {
                    tracing::error!(%err, path = %state_path.display(), "failed to persist remaining stale bindings");
                } else {
                    tracing::warn!(
                        count = remaining.bindings.len(),
                        "some VFIO bindings could not be restored; state preserved for retry"
                    );
                }
            }
            Err(err) => {
                tracing::error!(%err, "failed to serialize remaining stale bindings");
            }
        }
    }

    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_refcounts;
    use crate::pci::{PciBindState, PciBinding};
    use crate::test_support::{
        create_pci_device, create_probe_file, set_mock_driver, setup_mock_sysfs,
    };
    use std::fs;

    #[test]
    fn test_reconcile_clears_stale_driver_override_when_not_on_vfio() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 2684");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x2684",
            "0x030000",
            42,
        );
        create_probe_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "nvidia");
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let state_path = tmp.path().join("gpu-state.json");
        let state = PciBindState {
            bindings: vec![PciBinding {
                bdf: "0000:2d:00.0".to_string(),
                sandbox_id: "sandbox-orphan".to_string(),
                bound_at_ms: 0,
            }],
        };
        state.save(&state_path).unwrap();

        let restored = reconcile_stale_bindings(&sysfs, &state_path);
        assert!(restored.contains(&"0000:2d:00.0".to_string()));

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(
            override_val.trim(),
            "",
            "driver_override should be cleared even when device is not on vfio-pci"
        );
    }
}
