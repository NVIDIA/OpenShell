// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::SysfsRoot;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::TempDir;

pub fn setup_mock_sysfs() -> (TempDir, SysfsRoot) {
    let tmp = TempDir::new().unwrap();
    let sysfs = SysfsRoot::new(tmp.path());
    (tmp, sysfs)
}

pub fn create_pci_device(
    sysfs: &SysfsRoot,
    tmp: &Path,
    bdf: &str,
    vendor: &str,
    device: &str,
    class: &str,
    iommu_group: u32,
) {
    let dev = sysfs.pci_device(bdf);
    fs::create_dir_all(&dev).unwrap();

    fs::write(dev.join("vendor"), format!("{vendor}\n")).unwrap();
    fs::write(dev.join("device"), format!("{device}\n")).unwrap();
    fs::write(dev.join("class"), format!("{class}\n")).unwrap();

    let group_dir = tmp.join(format!("kernel/iommu_groups/{iommu_group}"));
    fs::create_dir_all(&group_dir).unwrap();
    symlink(&group_dir, dev.join("iommu_group")).unwrap();

    let group_devices_dir = group_dir.join("devices");
    fs::create_dir_all(&group_devices_dir).unwrap();
    symlink(&dev, group_devices_dir.join(bdf)).unwrap();
}

/// Helper to create a fake driver symlink for a mock PCI device.
pub fn set_mock_driver(sysfs: &SysfsRoot, bdf: &str, driver_name: &str) {
    let driver_dir = sysfs.base().join(format!("bus/pci/drivers/{driver_name}"));
    fs::create_dir_all(&driver_dir).unwrap();
    let dev_driver_link = sysfs.pci_device(bdf).join("driver");
    let _ = fs::remove_file(&dev_driver_link);
    symlink(&driver_dir, &dev_driver_link).unwrap();
}

pub fn create_probe_file(sysfs: &SysfsRoot) {
    let probe = sysfs.drivers_probe();
    fs::create_dir_all(probe.parent().unwrap()).unwrap();
    fs::write(&probe, "").unwrap();
}

pub fn create_remove_id_file(sysfs: &SysfsRoot) {
    let remove_id_path = sysfs.vfio_pci_remove_id();
    fs::create_dir_all(remove_id_path.parent().unwrap()).unwrap();
    fs::write(remove_id_path, "").unwrap();
}

pub fn create_new_id_file(sysfs: &SysfsRoot) {
    let new_id_path = sysfs.vfio_pci_new_id();
    fs::create_dir_all(new_id_path.parent().unwrap()).unwrap();
    fs::write(new_id_path, "").unwrap();
}
