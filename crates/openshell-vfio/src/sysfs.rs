// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::VfioError;
use std::fs;
use std::path::{Path, PathBuf};

/// Abstraction over sysfs paths, enabling test mocks via a temporary directory.
#[derive(Debug, Clone)]
pub struct SysfsRoot {
    base: PathBuf,
}

/// View of a single PCI device under a [`SysfsRoot`].
pub(crate) struct SysfsPciDevice<'a> {
    sysfs: &'a SysfsRoot,
    bdf: &'a str,
}

impl SysfsRoot {
    /// Production root pointing at the real `/sys` filesystem.
    pub fn system() -> Self {
        Self {
            base: PathBuf::from("/sys"),
        }
    }

    /// Custom root for testing.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    #[cfg(test)]
    pub(crate) fn base(&self) -> &Path {
        &self.base
    }

    pub fn pci_devices_dir(&self) -> PathBuf {
        self.base.join("bus/pci/devices")
    }

    pub fn pci_device(&self, bdf: &str) -> PathBuf {
        self.pci_devices_dir().join(bdf)
    }

    pub(crate) fn pci_device_ref<'a>(&'a self, bdf: &'a str) -> SysfsPciDevice<'a> {
        SysfsPciDevice { sysfs: self, bdf }
    }

    pub fn drivers_probe(&self) -> PathBuf {
        self.base.join("bus/pci/drivers_probe")
    }

    pub fn vfio_pci_new_id(&self) -> PathBuf {
        self.base.join("bus/pci/drivers/vfio-pci/new_id")
    }

    pub fn vfio_pci_remove_id(&self) -> PathBuf {
        self.base.join("bus/pci/drivers/vfio-pci/remove_id")
    }

    pub fn iommu_group(&self, bdf: &str) -> Result<u32, VfioError> {
        let link = self.pci_device(bdf).join("iommu_group");
        let target = fs::read_link(&link).map_err(|_| VfioError::NoIommuGroup {
            bdf: bdf.to_string(),
        })?;
        let group_str =
            target
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| VfioError::NoIommuGroup {
                    bdf: bdf.to_string(),
                })?;
        group_str
            .parse::<u32>()
            .map_err(|_| VfioError::NoIommuGroup {
                bdf: bdf.to_string(),
            })
    }

    /// Enumerate all PCI BDFs in the given IOMMU group.
    pub fn iommu_group_devices(&self, group_id: u32) -> Result<Vec<String>, VfioError> {
        let group_dir = self
            .base
            .join(format!("kernel/iommu_groups/{group_id}/devices"));
        let entries = fs::read_dir(&group_dir).map_err(|source| VfioError::SysfsIo {
            path: group_dir.display().to_string(),
            source,
        })?;
        let mut devices = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            devices.push(entry.file_name().to_string_lossy().into_owned());
        }
        devices.sort();
        Ok(devices)
    }
}

impl SysfsPciDevice<'_> {
    pub(crate) fn path(&self) -> PathBuf {
        self.sysfs.pci_device(self.bdf)
    }

    pub(crate) fn exists(&self) -> bool {
        self.path().exists()
    }

    pub(crate) fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    pub(crate) fn read_trimmed(&self, name: &str) -> Result<String, VfioError> {
        read_sysfs_trimmed(&self.file(name))
    }

    pub(crate) fn vendor(&self) -> Result<String, VfioError> {
        self.read_trimmed("vendor")
    }

    pub(crate) fn device_id(&self) -> Result<String, VfioError> {
        self.read_trimmed("device")
    }

    pub(crate) fn class(&self) -> Result<String, VfioError> {
        self.read_trimmed("class")
    }

    pub(crate) fn driver_name(&self) -> Option<String> {
        fs::read_link(self.file("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }

    pub(crate) fn driver_override_path(&self) -> PathBuf {
        self.file("driver_override")
    }

    pub(crate) fn driver_override(&self) -> Result<String, VfioError> {
        self.read_trimmed("driver_override")
    }

    pub(crate) fn clear_driver_override(&self) -> Result<(), VfioError> {
        write_sysfs(&self.driver_override_path(), "\n")
    }

    pub(crate) fn driver_unbind_path(&self) -> PathBuf {
        self.file("driver/unbind")
    }

    pub(crate) fn iommu_group(&self) -> Result<u32, VfioError> {
        self.sysfs.iommu_group(self.bdf)
    }

    /// Read vendor and device IDs from sysfs and format as `"VVVV DDDD"` (no `0x` prefix).
    pub(crate) fn vfio_id_string(&self) -> Option<String> {
        let vendor = self.vendor().ok()?;
        let device = self.device_id().ok()?;
        let vendor_hex = vendor.strip_prefix("0x").unwrap_or(&vendor);
        let device_hex = device.strip_prefix("0x").unwrap_or(&device);
        Some(format!("{vendor_hex} {device_hex}"))
    }
}

/// Validate a PCI BDF address (format `DDDD:BB:DD.F`).
pub fn validate_bdf(bdf: &str) -> Result<(), VfioError> {
    let bytes = bdf.as_bytes();
    if bytes.len() != 12 {
        return Err(VfioError::InvalidBdf {
            bdf: bdf.to_string(),
        });
    }

    // Expected layout: [hex x 4]:[hex x 2]:[hex x 2].[hex x 1]
    //                   0123     4 56     7 89     A B
    let ok = is_hex(bytes[0])
        && is_hex(bytes[1])
        && is_hex(bytes[2])
        && is_hex(bytes[3])
        && bytes[4] == b':'
        && is_hex(bytes[5])
        && is_hex(bytes[6])
        && bytes[7] == b':'
        && is_hex(bytes[8])
        && is_hex(bytes[9])
        && bytes[10] == b'.'
        && is_hex(bytes[11]);

    if ok {
        Ok(())
    } else {
        Err(VfioError::InvalidBdf {
            bdf: bdf.to_string(),
        })
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Returns `true` if `data` contains only safe characters for sysfs values
/// (alphanumeric plus `:`, `.`, `-`, `_`).
pub fn validate_sysfs_data(data: &str) -> bool {
    !data.is_empty()
        && data
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ':' | '.' | '-' | '_'))
}

pub(crate) fn read_sysfs_trimmed(path: &Path) -> Result<String, VfioError> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|source| VfioError::SysfsIo {
            path: path.display().to_string(),
            source,
        })
}

pub(crate) fn write_sysfs(path: &Path, value: &str) -> Result<(), VfioError> {
    fs::write(path, value).map_err(|source| VfioError::SysfsIo {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{create_pci_device, setup_mock_sysfs};
    use std::path::PathBuf;

    #[test]
    fn test_validate_bdf_valid() {
        assert!(validate_bdf("0000:2d:00.0").is_ok());
        assert!(validate_bdf("0000:00:00.0").is_ok());
        assert!(validate_bdf("abcd:ef:01.a").is_ok());
        assert!(validate_bdf("ABCD:EF:01.A").is_ok());
    }

    #[test]
    fn test_validate_bdf_invalid() {
        assert!(validate_bdf("").is_err());
        assert!(validate_bdf("0000:2d:00").is_err());
        assert!(validate_bdf("0000:2d:00.00").is_err());
        assert!(validate_bdf("000g:2d:00.0").is_err());
        assert!(validate_bdf("0000-2d-00.0").is_err());
        assert!(validate_bdf("0000:2d:00:0").is_err());
    }

    #[test]
    fn test_validate_bdf_rejects_metacharacters() {
        assert!(validate_bdf("$(rm -rf /)").is_err());
        assert!(validate_bdf("; echo pwned").is_err());
        assert!(validate_bdf("0000:2d;00.0").is_err());
        assert!(validate_bdf("0000:2d:0`.0").is_err());
        assert!(validate_bdf("../../../../").is_err());
    }

    #[test]
    fn test_validate_sysfs_data() {
        assert!(validate_sysfs_data("0x10de"));
        assert!(validate_sysfs_data("vfio-pci"));
        assert!(validate_sysfs_data("nvidia_gpu_0"));
        assert!(validate_sysfs_data("0000:2d:00.0"));

        assert!(!validate_sysfs_data(""));
        assert!(!validate_sysfs_data("$(echo)"));
        assert!(!validate_sysfs_data("a b"));
        assert!(!validate_sysfs_data("foo;bar"));
        assert!(!validate_sysfs_data("a\nb"));
    }

    #[test]
    fn test_sysfs_root_paths() {
        let sysfs = SysfsRoot::system();
        assert_eq!(
            sysfs.pci_device("0000:2d:00.0"),
            PathBuf::from("/sys/bus/pci/devices/0000:2d:00.0")
        );
        assert_eq!(
            sysfs.pci_devices_dir(),
            PathBuf::from("/sys/bus/pci/devices")
        );
        assert_eq!(
            sysfs.drivers_probe(),
            PathBuf::from("/sys/bus/pci/drivers_probe")
        );
        assert_eq!(
            sysfs.vfio_pci_new_id(),
            PathBuf::from("/sys/bus/pci/drivers/vfio-pci/new_id")
        );
        assert_eq!(
            sysfs.vfio_pci_remove_id(),
            PathBuf::from("/sys/bus/pci/drivers/vfio-pci/remove_id")
        );

        let custom = SysfsRoot::new("/tmp/test-sys");
        assert_eq!(
            custom.pci_device("0000:01:00.0"),
            PathBuf::from("/tmp/test-sys/bus/pci/devices/0000:01:00.0")
        );
    }

    #[test]
    fn test_sysfs_root_iommu_group() {
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

        assert_eq!(sysfs.iommu_group("0000:2d:00.0").unwrap(), 42);
        assert!(sysfs.iommu_group("0000:ff:ff.f").is_err());
    }

    #[test]
    fn test_iommu_group_devices_lists_all_members() {
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

        let devices = sysfs.iommu_group_devices(42).unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.contains(&"0000:2d:00.0".to_string()));
        assert!(devices.contains(&"0000:2d:00.1".to_string()));
    }

    #[test]
    fn test_iommu_group_devices_single_device() {
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

        let devices = sysfs.iommu_group_devices(99).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0], "0000:2d:00.0");
    }
}
