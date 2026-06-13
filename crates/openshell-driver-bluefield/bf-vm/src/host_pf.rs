// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

const NVIDIA_VENDOR: &str = "0x15b3";
const PCI_NETWORK_CLASS_PREFIX: &str = "0x02";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostPfSource {
    ConfiguredBdf,
    ConfiguredNetdev,
    AutoDiscovered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedHostPf {
    pub(crate) bdf: String,
    pub(crate) source: HostPfSource,
}

pub(crate) fn resolve_host_pf(
    configured: Option<&str>,
    sysfs_root: &Path,
) -> Result<ResolvedHostPf, String> {
    if let Some(value) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return resolve_configured_host_pf(value, sysfs_root);
    }
    auto_discover_host_pf(sysfs_root)
}

fn resolve_configured_host_pf(value: &str, sysfs_root: &Path) -> Result<ResolvedHostPf, String> {
    let pci_path = sysfs_root.join("bus/pci/devices").join(value);
    if pci_path.is_dir() {
        return Ok(ResolvedHostPf {
            bdf: value.to_string(),
            source: HostPfSource::ConfiguredBdf,
        });
    }

    let netdev_device = sysfs_root.join("class/net").join(value).join("device");
    let target = std::fs::read_link(&netdev_device).map_err(|err| {
        format!(
            "BlueField host PF {value:?} is neither a PCI BDF under {} nor a netdev under {}: {err}",
            sysfs_root.join("bus/pci/devices").display(),
            sysfs_root.join("class/net").display()
        )
    })?;
    let bdf = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("BlueField netdev {value:?} device link has no PCI BDF"))?
        .to_string();

    Ok(ResolvedHostPf {
        bdf,
        source: HostPfSource::ConfiguredNetdev,
    })
}

fn auto_discover_host_pf(sysfs_root: &Path) -> Result<ResolvedHostPf, String> {
    let mut candidates = discover_bluefield_pf_candidates(sysfs_root)?;
    candidates.sort();
    match candidates.len() {
        0 => Err(
            "no BlueField-capable PF with configured SR-IOV VFs found; set OPENSHELL_BLUEFIELD_HOST_PF to the PF netdev or PCI BDF"
                .to_string(),
        ),
        1 => Ok(ResolvedHostPf {
            bdf: candidates.remove(0),
            source: HostPfSource::AutoDiscovered,
        }),
        _ => Err(format!(
            "multiple BlueField-capable PFs found: {}; set OPENSHELL_BLUEFIELD_HOST_PF to one PF netdev or PCI BDF",
            candidates.join(", ")
        )),
    }
}

fn discover_bluefield_pf_candidates(sysfs_root: &Path) -> Result<Vec<String>, String> {
    let devices = sysfs_root.join("bus/pci/devices");
    let entries = std::fs::read_dir(&devices)
        .map_err(|err| format!("read PCI devices from {}: {err}", devices.display()))?;
    let mut candidates = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !is_bluefield_network_pf(&path) {
            continue;
        }
        let bdf = entry.file_name().to_string_lossy().into_owned();
        candidates.push(bdf);
    }
    Ok(candidates)
}

fn is_bluefield_network_pf(path: &Path) -> bool {
    let vendor = read_trimmed(path.join("vendor"));
    let class = read_trimmed(path.join("class"));
    let total_vfs = read_trimmed(path.join("sriov_totalvfs"))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    vendor.as_deref() == Some(NVIDIA_VENDOR)
        && class
            .as_deref()
            .is_some_and(|value| value.starts_with(PCI_NETWORK_CLASS_PREFIX))
        && total_vfs > 0
        && has_any_virtfn(path)
}

fn has_any_virtfn(path: &Path) -> bool {
    (0..256).any(|index| {
        path.join(format!("virtfn{index}"))
            .symlink_metadata()
            .is_ok()
    })
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_sysfs_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openshell-bf-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn write_device(root: &std::path::Path, bdf: &str, vendor: &str, class: &str, total_vfs: &str) {
        let dir = root.join("bus/pci/devices").join(bdf);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vendor"), vendor).unwrap();
        std::fs::write(dir.join("class"), class).unwrap();
        std::fs::write(dir.join("sriov_totalvfs"), total_vfs).unwrap();
    }

    #[test]
    fn resolves_configured_bdf_to_pf_bdf() {
        let root = temp_sysfs_root("bdf");
        write_device(&root, "0000:b1:00.0", "0x15b3\n", "0x020000\n", "30\n");

        let resolved = resolve_host_pf(Some("0000:b1:00.0"), &root).unwrap();

        assert_eq!(resolved.bdf, "0000:b1:00.0");
        assert_eq!(resolved.source, HostPfSource::ConfiguredBdf);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_configured_netdev_to_pf_bdf() {
        let root = temp_sysfs_root("netdev");
        write_device(&root, "0000:b1:00.0", "0x15b3\n", "0x020000\n", "30\n");
        std::fs::create_dir_all(root.join("class/net/enp177s0f0np0")).unwrap();
        symlink(
            "../../../bus/pci/devices/0000:b1:00.0",
            root.join("class/net/enp177s0f0np0/device"),
        )
        .unwrap();

        let resolved = resolve_host_pf(Some("enp177s0f0np0"), &root).unwrap();

        assert_eq!(resolved.bdf, "0000:b1:00.0");
        assert_eq!(resolved.source, HostPfSource::ConfiguredNetdev);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_selects_single_bluefield_pf_with_vfs() {
        let root = temp_sysfs_root("auto");
        write_device(&root, "0000:b1:00.0", "0x15b3\n", "0x020000\n", "30\n");
        std::fs::create_dir_all(root.join("bus/pci/devices/0000:b1:04.1")).unwrap();
        symlink(
            "../0000:b1:04.1",
            root.join("bus/pci/devices/0000:b1:00.0/virtfn29"),
        )
        .unwrap();

        let resolved = resolve_host_pf(None, &root).unwrap();

        assert_eq!(resolved.bdf, "0000:b1:00.0");
        assert_eq!(resolved.source, HostPfSource::AutoDiscovered);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_multiple_auto_candidates_with_specific_message() {
        let root = temp_sysfs_root("multiple");
        for (bdf, vf) in [
            ("0000:b1:00.0", "0000:b1:04.1"),
            ("0000:b2:00.0", "0000:b2:04.1"),
        ] {
            write_device(&root, bdf, "0x15b3\n", "0x020000\n", "8\n");
            std::fs::create_dir_all(root.join("bus/pci/devices").join(vf)).unwrap();
            symlink(
                format!("../{vf}"),
                root.join("bus/pci/devices").join(bdf).join("virtfn0"),
            )
            .unwrap();
        }

        let err = resolve_host_pf(None, &root).unwrap_err();

        assert!(err.contains("multiple BlueField-capable PFs found"));
        assert!(err.contains("OPENSHELL_BLUEFIELD_HOST_PF"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
