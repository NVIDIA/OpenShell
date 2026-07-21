// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GPU device passthrough.
//!
//! This driver reuses `OpenShell`'s shared CDI GPU inventory/selection logic
//! (`openshell_core::gpu`) — the same code the Docker/Podman drivers use to
//! pick `nvidia.com/gpu=<N>` device IDs from a locally discovered inventory.
//! What differs from those drivers is what happens *after* a device ID is
//! selected: Docker/Podman hand the CDI device ID string to the container
//! engine's own CDI implementation, which resolves it into device nodes,
//! environment variables, mounts, and hooks. containerd's raw
//! `containers.v1`/`tasks.v1` API (as opposed to its CRI plugin, which is
//! not in scope for a non-Kubernetes driver) does not do this resolution
//! for us, so this driver has to.
//!
//! **Scope for this initial cut:** kernel device-node passthrough only
//! (`/dev/nvidia<N>` plus the shared control devices). This does not
//! perform full CDI spec injection (userspace driver library mounts,
//! `nvidia-ctk`-style hooks) the way `nvidia-container-toolkit` does for
//! Docker/Podman/containerd's CRI plugin. GPU workloads that only need
//! kernel device access work; workloads that need the NVIDIA userspace
//! libraries injected do not yet. This is called out explicitly rather than
//! silently producing a sandbox that can open the device but can't actually
//! use it — see `driver.rs` for where `ValidateSandboxCreate` surfaces this.
//! Full CDI injection is tracked as follow-up work.

use std::path::{Path, PathBuf};

use oci_spec::runtime::{LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceType};
use openshell_core::gpu::CdiGpuInventory;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

/// Device nodes shared by every NVIDIA GPU device (control + unified
/// virtual memory), always added alongside per-GPU device nodes.
const NVIDIA_CONTROL_DEVICES: &[&str] =
    &["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"];

/// Build a normalized CDI GPU inventory from raw `/dev/nvidia<N>` character
/// devices.
///
/// Mirrors `openshell-driver-podman`'s `local_podman_cdi_gpu_inventory_from`
/// so the two drivers discover the same set of devices from the same host
/// state.
#[must_use]
pub fn local_cdi_gpu_inventory_from(dev_root: &Path) -> CdiGpuInventory {
    let device_ids = std::fs::read_dir(dev_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let index = name.strip_prefix("nvidia")?;
            (!index.is_empty() && index.chars().all(|ch| ch.is_ascii_digit()))
                .then(|| format!("nvidia.com/gpu={index}"))
        })
        .collect::<Vec<_>>();
    CdiGpuInventory::new(device_ids)
}

#[must_use]
pub fn local_cdi_gpu_inventory() -> CdiGpuInventory {
    local_cdi_gpu_inventory_from(Path::new("/dev"))
}

/// Device nodes (host paths) a set of selected `nvidia.com/gpu=<N>` CDI
/// device IDs resolve to.
#[must_use]
pub fn device_paths_for(device_ids: &[String]) -> Vec<PathBuf> {
    if device_ids.is_empty() {
        return Vec::new();
    }
    let mut paths: Vec<PathBuf> = device_ids
        .iter()
        .filter_map(|id| id.strip_prefix("nvidia.com/gpu="))
        .filter(|suffix| suffix.chars().all(|ch| ch.is_ascii_digit()))
        .map(|index| PathBuf::from(format!("/dev/nvidia{index}")))
        .collect();
    paths.extend(NVIDIA_CONTROL_DEVICES.iter().map(PathBuf::from));
    paths
}

/// Build OCI `LinuxDevice` + cgroup device-allow entries for a set of host
/// device node paths.
///
/// Reads each node's actual major/minor via `stat(2)` so the cgroup
/// allow-list matches the real device numbers rather than guessed
/// well-known ones (NVIDIA device major numbers are not perfectly stable
/// across distributions).
///
/// # Errors
/// Returns an error (as a string, for the caller to fold into
/// `ComputeDriverError::Precondition`) if a device path does not exist or
/// is not a character device. Callers should treat this as "GPU requested
/// but not actually present," matching the other drivers' behavior for a
/// missing GPU.
pub fn resolve_devices(paths: &[PathBuf]) -> Result<Vec<oci_spec::runtime::LinuxDevice>, String> {
    paths
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path)
                .map_err(|err| format!("GPU device {} unavailable: {err}", path.display()))?;
            if !metadata.file_type().is_char_device() {
                return Err(format!("{} is not a character device", path.display()));
            }
            let rdev = metadata.rdev();
            LinuxDeviceBuilder::default()
                .path(path.clone())
                .typ(LinuxDeviceType::C)
                .major(i64::from(device_major(rdev)))
                .minor(i64::from(device_minor(rdev)))
                .file_mode(0o666u32)
                .build()
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// Build the matching cgroup device-allow-list entries for a set of
/// resolved OCI devices.
///
/// Required alongside the device nodes themselves — without an explicit
/// cgroup allow entry the kernel's device cgroup controller denies
/// `open()` even though the node exists in the mount namespace.
#[must_use]
pub fn cgroup_device_allow_entries(
    devices: &[oci_spec::runtime::LinuxDevice],
) -> Vec<LinuxDeviceCgroup> {
    devices.iter().map(LinuxDeviceCgroup::from).collect()
}

/// Extract the major device number from a `st_rdev` value, using the glibc
/// `gnu_dev_major` encoding (stable across Linux; matches what `stat(1)`,
/// `ls -l`, and every container runtime already assume).
#[must_use]
#[allow(clippy::cast_possible_truncation)] // masked to 32 bits by construction
fn device_major(rdev: u64) -> u32 {
    (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)) as u32
}

/// Extract the minor device number from a `st_rdev` value (`gnu_dev_minor`
/// encoding).
#[must_use]
#[allow(clippy::cast_possible_truncation)] // masked to 32 bits by construction
fn device_minor(rdev: u64) -> u32 {
    ((rdev & 0xff) | ((rdev >> 12) & !0xff)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_paths_include_shared_control_devices() {
        let paths = device_paths_for(&["nvidia.com/gpu=0".to_string()]);
        assert!(paths.contains(&PathBuf::from("/dev/nvidia0")));
        assert!(paths.contains(&PathBuf::from("/dev/nvidiactl")));
        assert!(paths.contains(&PathBuf::from("/dev/nvidia-uvm")));
    }

    #[test]
    fn empty_device_ids_yield_no_paths() {
        assert!(device_paths_for(&[]).is_empty());
    }

    #[test]
    fn major_minor_round_trip_for_known_encoding() {
        // Encode major=195 minor=0 (a real NVIDIA GPU major on many distros)
        // using the same glibc `gnu_dev_makedev` formula, then decode.
        let major: u64 = 195;
        let minor: u64 = 0;
        let rdev = (major & 0xfff) << 8
            | (minor & 0xff)
            | ((major & !0xfff) << 32)
            | ((minor & !0xff) << 12);
        assert_eq!(device_major(rdev), 195);
        assert_eq!(device_minor(rdev), 0);
    }

    #[test]
    fn major_minor_round_trip_for_high_minor() {
        let major: u64 = 195;
        let minor: u64 = 255;
        let rdev = (major & 0xfff) << 8
            | (minor & 0xff)
            | ((major & !0xfff) << 32)
            | ((minor & !0xff) << 12);
        assert_eq!(device_major(rdev), 195);
        assert_eq!(device_minor(rdev), 255);
    }

    #[test]
    fn inventory_discovers_nvidia_devices_from_dev_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["nvidia0", "nvidia1", "nvidiactl", "not-nvidia"] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let inventory = local_cdi_gpu_inventory_from(dir.path());
        let ids = inventory.as_slice();
        assert!(ids.contains(&"nvidia.com/gpu=0".to_string()));
        assert!(ids.contains(&"nvidia.com/gpu=1".to_string()));
        assert!(!ids.iter().any(|id| id.contains("ctl")));
    }
}
