// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::VfioError;
use crate::pci::{PciBindGuard, PciInfo};
use crate::sysfs::{SysfsRoot, validate_bdf};
use std::fs;

const NVIDIA_VENDOR_ID: &str = "0x10de";
const GPU_CLASS_DISPLAY_VGA: &str = "0x030000";
const GPU_CLASS_DISPLAY_3D: u32 = 0x0302;

fn is_gpu_class(class_str: &str) -> bool {
    if class_str == GPU_CLASS_DISPLAY_VGA {
        return true;
    }
    // 3D controller: 0x0302xx
    if let Some(hex) = class_str.strip_prefix("0x")
        && let Ok(val) = u32::from_str_radix(hex, 16)
    {
        return (val >> 8) == GPU_CLASS_DISPLAY_3D;
    }
    false
}

/// Scan sysfs for NVIDIA GPUs eligible for VFIO passthrough.
pub fn probe_host_nvidia_vfio_readiness(sysfs: &SysfsRoot) -> Vec<PciInfo> {
    let devices_dir = sysfs.pci_devices_dir();
    let entries = match fs::read_dir(&devices_dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(path = %devices_dir.display(), %err, "cannot read PCI devices directory");
            return Vec::new();
        }
    };

    let mut gpus = Vec::new();

    for entry in entries.filter_map(Result::ok) {
        let bdf = entry.file_name().to_string_lossy().into_owned();
        let device = sysfs.pci_device_ref(&bdf);

        let Ok(vendor) = device.vendor() else {
            continue;
        };
        if vendor != NVIDIA_VENDOR_ID {
            continue;
        }

        let Ok(class) = device.class() else {
            continue;
        };
        if !is_gpu_class(&class) {
            continue;
        }

        let device_id = device.device_id().unwrap_or_default();

        let name = device
            .read_trimmed("label")
            .unwrap_or_else(|_| format!("NVIDIA {device_id}"));

        let Ok(iommu_group) = sysfs.iommu_group(&bdf) else {
            continue;
        };

        gpus.push(PciInfo {
            bdf,
            name,
            vendor,
            device: device_id,
            iommu_group,
        });
    }

    gpus
}

/// Bind a GPU to `vfio-pci`, returning an RAII guard that restores it on drop.
///
/// Also binds all companion devices in the same IOMMU group (e.g. the HD Audio
/// function on consumer GPUs). All bound companions are tracked and restored
/// when the guard is dropped.
pub fn prepare_gpu_for_passthrough(
    sysfs: &SysfsRoot,
    bdf: &str,
) -> Result<PciBindGuard, VfioError> {
    validate_bdf(bdf)?;

    let device = sysfs.pci_device_ref(bdf);
    if !device.exists() {
        return Err(VfioError::GpuNotFound {
            bdf: bdf.to_string(),
        });
    }

    let class = device.class()?;
    if !is_gpu_class(&class) {
        return Err(VfioError::NotGpu {
            bdf: bdf.to_string(),
            class,
        });
    }

    let iommu_group = device.iommu_group()?;
    let group_devices = sysfs.iommu_group_devices(iommu_group)?;
    let peers: Vec<String> = group_devices.into_iter().filter(|d| d != bdf).collect();

    let mut bound_companions = Vec::new();
    for peer in &peers {
        if !sysfs.pci_device_ref(peer).exists() {
            continue;
        }
        match crate::bind::bind_device_to_vfio(sysfs, peer) {
            Ok(was_bound) => {
                if was_bound {
                    tracing::info!(bdf = %peer, iommu_group, "bound IOMMU group companion to vfio-pci");
                    bound_companions.push(peer.clone());
                }
            }
            Err(err) => {
                for already_bound in bound_companions.iter().rev() {
                    if let Err(restore_err) =
                        crate::bind::restore_to_host_driver(sysfs, already_bound)
                    {
                        tracing::error!(bdf = %already_bound, error = %restore_err, "failed to restore companion during rollback");
                    }
                }
                return Err(VfioError::BindFailed {
                    bdf: peer.clone(),
                    reason: format!("IOMMU group {iommu_group} companion bind failed: {err}"),
                });
            }
        }
    }

    match crate::bind::bind_device_to_vfio(sysfs, bdf) {
        Ok(was_bound) => {
            if was_bound {
                tracing::info!(bdf, "GPU bound to vfio-pci");
            } else {
                tracing::info!(bdf, "GPU already bound to vfio-pci");
            }
        }
        Err(err) => {
            for companion in bound_companions.iter().rev() {
                if let Err(restore_err) = crate::bind::restore_to_host_driver(sysfs, companion) {
                    tracing::error!(bdf = %companion, error = %restore_err, "failed to restore companion during rollback");
                }
            }
            return Err(err);
        }
    }

    let vfio_id = crate::bind::vfio_id_string(sysfs, bdf);

    Ok(PciBindGuard::new_armed(
        bdf.to_string(),
        bound_companions,
        sysfs.clone(),
        vfio_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_refcounts;
    use crate::test_support::{
        create_pci_device, create_probe_file, set_mock_driver, setup_mock_sysfs,
    };

    #[test]
    fn test_probe_discovers_nvidia_gpu() {
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

        let gpus = probe_host_nvidia_vfio_readiness(&sysfs);
        assert_eq!(gpus.len(), 1);
        assert_eq!(gpus[0].bdf, "0000:2d:00.0");
        assert_eq!(gpus[0].vendor, "0x10de");
        assert_eq!(gpus[0].device, "0x2684");
        assert_eq!(gpus[0].iommu_group, 42);
    }

    #[test]
    fn test_probe_skips_non_nvidia() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:01:00.0",
            "0x8086",
            "0x1234",
            "0x030000",
            10,
        );

        let gpus = probe_host_nvidia_vfio_readiness(&sysfs);
        assert!(gpus.is_empty());
    }

    #[test]
    fn test_probe_skips_non_gpu_nvidia() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.1",
            "0x10de",
            "0x228b",
            "0x040300",
            42,
        );

        let gpus = probe_host_nvidia_vfio_readiness(&sysfs);
        assert!(gpus.is_empty());
    }

    #[test]
    fn test_is_gpu_class() {
        assert!(is_gpu_class("0x030000"));
        assert!(is_gpu_class("0x030200"));
        assert!(is_gpu_class("0x030201"));
        assert!(!is_gpu_class("0x040300"));
        assert!(!is_gpu_class("0x060000"));
        assert!(!is_gpu_class(""));
    }

    #[test]
    fn test_prepare_gpu_skips_already_bound_companions() {
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
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.1",
            "0x10de",
            "0x228b",
            "0x040300",
            42,
        );
        create_probe_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");
        set_mock_driver(&sysfs, "0000:2d:00.1", "vfio-pci");

        let guard = prepare_gpu_for_passthrough(&sysfs, "0000:2d:00.0").unwrap();

        assert!(guard.companion_bdfs.is_empty());
        assert_eq!(guard.bdf, "0000:2d:00.0");
    }

    #[test]
    fn test_prepare_gpu_accepts_non_nvidia_gpu() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("8086 56a0");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:03:00.0",
            "0x8086",
            "0x56a0",
            "0x030200",
            11,
        );
        create_probe_file(&sysfs);
        set_mock_driver(&sysfs, "0000:03:00.0", "vfio-pci");

        let guard = prepare_gpu_for_passthrough(&sysfs, "0000:03:00.0").unwrap();

        assert!(guard.companion_bdfs.is_empty());
        assert_eq!(guard.bdf, "0000:03:00.0");
    }

    #[test]
    fn test_prepare_gpu_rejects_non_gpu_device() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:04:00.0",
            "0x8086",
            "0x1234",
            "0x020000",
            12,
        );

        let err = prepare_gpu_for_passthrough(&sysfs, "0000:04:00.0").unwrap_err();

        assert!(matches!(
            err,
            VfioError::NotGpu {
                bdf,
                class
            } if bdf == "0000:04:00.0" && class == "0x020000"
        ));
    }

    #[test]
    fn test_prepare_gpu_solo_iommu_group_no_companions() {
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
            99,
        );
        create_probe_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");

        let guard = prepare_gpu_for_passthrough(&sysfs, "0000:2d:00.0").unwrap();
        assert!(guard.companion_bdfs.is_empty());
    }
}
