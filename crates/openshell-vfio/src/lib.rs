// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side NVIDIA GPU VFIO bind/unbind for VM passthrough.

#![allow(unsafe_code)]
//!
//! This module scans Linux sysfs (`/sys/bus/pci/devices`) for NVIDIA GPUs
//! (vendor ID `0x10de`), checks their driver binding, and verifies IOMMU
//! group cleanliness — the prerequisites for passing a physical GPU into
//! a cloud-hypervisor VM via VFIO.
//!
//! Returns per-device readiness for multi-GPU hosts.
//!
//! On non-Linux platforms, probing returns an empty list.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Per-device readiness state for NVIDIA GPU VFIO passthrough.
///
/// Each variant represents a distinct readiness state for a single PCI device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostNvidiaVfioReadiness {
    /// The current platform does not support VFIO passthrough (non-Linux).
    UnsupportedPlatform,

    /// No PCI device with NVIDIA vendor ID (`0x10de`) was found.
    NoNvidiaDevice,

    /// An NVIDIA device exists but is bound to the nvidia (or other non-VFIO) driver.
    BoundToNvidia,

    /// An NVIDIA device is bound to `vfio-pci` and its IOMMU group is clean — ready for passthrough.
    VfioBoundReady,

    /// An NVIDIA device is bound to `vfio-pci` but its IOMMU group contains
    /// devices not bound to `vfio-pci`, which prevents safe passthrough.
    VfioBoundDirtyGroup,

    /// Some NVIDIA devices are bound to `vfio-pci` while others use
    /// a different driver (mixed fleet).
    MixedVfioAndOther,
}

impl fmt::Display for HostNvidiaVfioReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(
                f,
                "VFIO passthrough is not supported on this platform (Linux required)"
            ),
            Self::NoNvidiaDevice => write!(f, "no NVIDIA PCI device found"),
            Self::BoundToNvidia => {
                write!(f, "NVIDIA device found but not bound to vfio-pci driver")
            }
            Self::VfioBoundReady => write!(
                f,
                "NVIDIA device bound to vfio-pci and IOMMU group is clean"
            ),
            Self::VfioBoundDirtyGroup => write!(
                f,
                "NVIDIA device bound to vfio-pci but IOMMU group contains non-VFIO devices"
            ),
            Self::MixedVfioAndOther => write!(
                f,
                "some NVIDIA devices are on vfio-pci while others use a different driver"
            ),
        }
    }
}

const NVIDIA_VENDOR_ID: &str = "0x10de";

#[cfg(target_os = "linux")]
const SYSFS_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reject sysfs data containing characters outside the safe set for shell
/// interpolation. All legitimate sysfs writes in this crate use PCI BDF
/// addresses, driver names, or single digits — this blocks anything else.
#[cfg(target_os = "linux")]
fn validate_sysfs_data(data: &str) -> Result<(), std::io::Error> {
    if data.is_empty()
        || data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b':')
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("sysfs data contains unexpected characters: {data:?}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn sysfs_write_with_timeout(
    path: &std::path::Path,
    data: &str,
    timeout: Duration,
) -> Result<(), std::io::Error> {
    use std::process::{Command, Stdio};
    use std::thread;

    validate_sysfs_data(data)?;

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"printf '%s' '{}' > '{}'"#,
            data.replace('\'', "'\\''"),
            path.display().to_string().replace('\'', "'\\''")
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "failed to spawn sysfs write subprocess for {}: {e}",
                    path.display()
                ),
            )
        })?;

    let poll_interval = Duration::from_millis(100);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let mut stderr_buf = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut stderr_buf);
                }
                let hint = if stderr_buf.contains("Permission denied") {
                    " — run as root"
                } else {
                    ""
                };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "sysfs write to {} failed (exit {}){hint}: {stderr_buf}",
                        path.display(),
                        status.code().unwrap_or(-1),
                    ),
                ));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let pid = child.id();
                    let _ = child.kill();
                    // CRITICAL: Do NOT call child.wait() here. If the child
                    // is stuck in uninterruptible sleep (D-state) — which is
                    // the nvidia unbind deadlock scenario — wait() will block
                    // the parent indefinitely, making it unkillable too.
                    //
                    // Dropping the Child struct closes pipe handles but does
                    // NOT wait. The zombie child is reparented to init and
                    // reaped when/if it eventually exits.
                    drop(child);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "sysfs write to {} timed out after {:.0}s (subprocess pid {pid}) — \
                             possible nvidia driver deadlock. The subprocess may still be \
                             stuck in kernel space; a reboot may be required to clear it.",
                            path.display(),
                            timeout.as_secs_f64(),
                        ),
                    ));
                }
                thread::sleep(poll_interval);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Check whether a PCI device supports MSI-X by walking the PCI capability
/// list in the sysfs `config` file. MSI-X is capability ID `0x11`.
///
/// cloud-hypervisor's VFIO code assumes MSI-X and will panic if the device
/// only has MSI. This pre-flight check prevents a cryptic crash.
#[cfg(target_os = "linux")]
pub fn check_msix_support(sysfs: &SysfsRoot, pci_addr: &str) -> bool {
    let config_path = sysfs.sys_bus_pci_devices().join(pci_addr).join("config");
    let config = match std::fs::read(&config_path) {
        Ok(data) => data,
        Err(_) => return false,
    };

    // PCI config space: capability pointer at offset 0x34.
    if config.len() < 0x35 {
        return false;
    }

    // Status register (offset 0x06, bit 4) indicates capability list present.
    if config.len() > 0x07 && (config[0x06] & 0x10) == 0 {
        return false;
    }

    // PCI spec: capability pointers are DWORD-aligned (low 2 bits reserved).
    let mut cap_ptr = (config[0x34] & 0xFC) as usize;
    // Walk the capability linked list (max 48 iterations to avoid infinite loops).
    for _ in 0..48 {
        if cap_ptr == 0 || cap_ptr + 1 >= config.len() {
            break;
        }
        let cap_id = config[cap_ptr];
        if cap_id == 0x11 {
            return true;
        }
        cap_ptr = (config[cap_ptr + 1] & 0xFC) as usize;
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn check_msix_support(_sysfs: &SysfsRoot, _pci_addr: &str) -> bool {
    false
}

/// Validates that `addr` matches the PCI BDF format `DDDD:BB:DD.F`.
fn validate_pci_addr(addr: &str) -> Result<(), std::io::Error> {
    let bytes = addr.as_bytes();
    let valid = bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes[..4].iter().all(|b| b.is_ascii_hexdigit())
        && bytes[5..7].iter().all(|b| b.is_ascii_hexdigit())
        && bytes[8..10].iter().all(|b| b.is_ascii_hexdigit())
        && bytes[11] >= b'0'
        && bytes[11] <= b'7';
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid PCI address '{addr}': expected DDDD:BB:DD.F format"),
        ))
    }
}

/// Probe the host for NVIDIA GPU VFIO readiness by scanning Linux sysfs.
///
/// Returns a per-device list of `(pci_address, readiness)` tuples for every
/// NVIDIA GPU found. On non-Linux platforms the list is empty.
///
/// On Linux, walks `/sys/bus/pci/devices/` and for each device:
/// 1. Reads `vendor` to check for NVIDIA (`0x10de`).
/// 2. Reads the `driver` symlink to determine which kernel driver is bound.
/// 3. If bound to `vfio-pci`, inspects the `iommu_group/devices/` directory
///    to verify all group members are also on `vfio-pci`.
pub fn probe_host_nvidia_vfio_readiness() -> Vec<(String, HostNvidiaVfioReadiness)> {
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }

    #[cfg(target_os = "linux")]
    {
        probe_linux_sysfs()
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_sysfs() -> Vec<(String, HostNvidiaVfioReadiness)> {
    use std::fs;
    use std::path::Path;

    let pci_devices = Path::new("/sys/bus/pci/devices");
    let entries = match fs::read_dir(pci_devices) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for entry in entries.filter_map(Result::ok) {
        let dev_path = entry.path();

        let vendor = match fs::read_to_string(dev_path.join("vendor")) {
            Ok(v) => v.trim().to_lowercase(),
            Err(_) => continue,
        };

        if vendor != NVIDIA_VENDOR_ID {
            continue;
        }

        let pci_addr = entry.file_name().to_string_lossy().to_string();

        let driver_link = dev_path.join("driver");
        let driver_name = fs::read_link(&driver_link).ok().and_then(|target| {
            target
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
        });

        let state = match driver_name.as_deref() {
            Some("vfio-pci") => {
                let iommu_group_devices = dev_path.join("iommu_group/devices");
                let group_clean = match fs::read_dir(&iommu_group_devices) {
                    Ok(group_entries) => group_entries.filter_map(Result::ok).all(|ge| {
                        let peer_path = iommu_group_devices.join(ge.file_name()).join("driver");
                        fs::read_link(&peer_path)
                            .ok()
                            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().to_string()))
                            .as_deref()
                            == Some("vfio-pci")
                    }),
                    Err(_) => false,
                };

                if group_clean {
                    HostNvidiaVfioReadiness::VfioBoundReady
                } else {
                    HostNvidiaVfioReadiness::VfioBoundDirtyGroup
                }
            }
            _ => HostNvidiaVfioReadiness::BoundToNvidia,
        };

        results.push((pci_addr, state));
    }

    results
}

/// Returns whether any NVIDIA GPU is fully available for VM passthrough.
///
/// Requires `OPENSHELL_VM_GPU_E2E=1` to activate probing. When the env var
/// is unset or not `"1"`, returns `false` unconditionally so non-GPU CI
/// runners are never affected.
///
/// When activated, checks two conditions:
/// 1. At least one NVIDIA device reports [`VfioBoundReady`].
/// 2. The cloud-hypervisor binary exists in `runtime_dir` (if provided).
pub fn nvidia_gpu_available_for_vm_passthrough(runtime_dir: Option<PathBuf>) -> bool {
    if std::env::var("OPENSHELL_VM_GPU_E2E").as_deref() != Ok("1") {
        return false;
    }

    let has_vfio_ready = probe_host_nvidia_vfio_readiness()
        .iter()
        .any(|(_, state)| *state == HostNvidiaVfioReadiness::VfioBoundReady);

    if !has_vfio_ready {
        return false;
    }

    runtime_dir
        .map(|dir| dir.join("cloud-hypervisor").is_file())
        .unwrap_or(false)
}

/// Sysfs root path, defaulting to "/" in production and a temp dir in tests.
#[derive(Debug, Clone)]
pub struct SysfsRoot(PathBuf);

impl Default for SysfsRoot {
    fn default() -> Self {
        Self(PathBuf::from("/"))
    }
}

impl SysfsRoot {
    #[cfg(test)]
    pub fn new(root: PathBuf) -> Self {
        Self(root)
    }

    pub fn sys_bus_pci_devices(&self) -> PathBuf {
        self.0.join("sys/bus/pci/devices")
    }

    pub fn sys_class_drm(&self) -> PathBuf {
        self.0.join("sys/class/drm")
    }

    pub fn sys_module(&self, module: &str) -> PathBuf {
        self.0.join("sys/module").join(module)
    }

    pub fn sys_bus_pci_drivers(&self, driver: &str) -> PathBuf {
        self.0.join("sys/bus/pci/drivers").join(driver)
    }

    pub fn sys_kernel_iommu_groups(&self) -> PathBuf {
        self.0.join("sys/kernel/iommu_groups")
    }

    fn is_real_sysfs(&self) -> bool {
        self.0 == std::path::Path::new("/")
    }

    #[cfg(target_os = "linux")]
    fn write_sysfs(&self, path: &std::path::Path, data: &str) -> Result<(), std::io::Error> {
        if self.is_real_sysfs() {
            sysfs_write_with_timeout(path, data, SYSFS_WRITE_TIMEOUT)
        } else {
            std::fs::write(path, data).map_err(|e| {
                std::io::Error::new(e.kind(), format!("failed to write {}: {e}", path.display()))
            })
        }
    }
}

#[cfg(target_os = "linux")]
pub fn check_display_attached(sysfs: &SysfsRoot, pci_addr: &str) -> bool {
    use std::fs;

    let drm_dir = sysfs.sys_class_drm();
    let entries = match fs::read_dir(&drm_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("card") || name.contains('-') {
            continue;
        }

        let card_dir = entry.path();
        let device_link = card_dir.join("device");

        let target = match fs::read_link(&device_link) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !target.to_string_lossy().ends_with(pci_addr) {
            continue;
        }

        let boot_vga_path = card_dir.join("device").join("boot_vga");
        if let Ok(val) = fs::read_to_string(&boot_vga_path) {
            if val.trim() == "1" {
                return true;
            }
        }

        if let Ok(sub_entries) = fs::read_dir(&card_dir) {
            for sub in sub_entries.filter_map(Result::ok) {
                let sub_name = sub.file_name().to_string_lossy().to_string();
                if sub_name.starts_with(&format!("{name}-")) {
                    if let Ok(status) = fs::read_to_string(sub.path().join("status")) {
                        if status.trim() == "connected" {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

#[cfg(not(target_os = "linux"))]
pub fn check_display_attached(_sysfs: &SysfsRoot, _pci_addr: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
/// Checks whether any process on the host has an open handle to an NVIDIA GPU
/// device (`/dev/nvidia*`). This is a host-wide check across ALL NVIDIA GPUs,
/// not scoped to a single PCI address. Returns a list of (pid, comm) pairs.
pub fn check_active_gpu_processes() -> std::io::Result<Vec<(u32, String)>> {
    use std::fs;

    let mut result = Vec::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot scan /proc for active GPU processes: {e} — \
                     refusing to unbind (fail-closed)"
                ),
            ));
        }
    };

    for proc_entry in proc_dir.filter_map(Result::ok) {
        let pid: u32 = match proc_entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = proc_entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fds.filter_map(Result::ok) {
            if let Ok(target) = fs::read_link(fd_entry.path()) {
                if target.to_string_lossy().starts_with("/dev/nvidia") {
                    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    result.push((pid, comm));
                    break;
                }
            }
        }
    }

    Ok(result)
}

#[cfg(not(target_os = "linux"))]
pub fn check_active_gpu_processes() -> std::io::Result<Vec<(u32, String)>> {
    Ok(vec![])
}

#[cfg(target_os = "linux")]
pub fn check_iommu_enabled(sysfs: &SysfsRoot, pci_addr: &str) -> bool {
    let iommu_groups = sysfs.sys_kernel_iommu_groups();
    if !iommu_groups.is_dir() {
        return false;
    }
    sysfs
        .sys_bus_pci_devices()
        .join(pci_addr)
        .join("iommu_group")
        .exists()
}

#[cfg(not(target_os = "linux"))]
pub fn check_iommu_enabled(_sysfs: &SysfsRoot, _pci_addr: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn check_vfio_modules_loaded(sysfs: &SysfsRoot) -> bool {
    sysfs.sys_module("vfio_pci").is_dir() && sysfs.sys_module("vfio_iommu_type1").is_dir()
}

#[cfg(not(target_os = "linux"))]
pub fn check_vfio_modules_loaded(_sysfs: &SysfsRoot) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn check_sysfs_permissions(sysfs: &SysfsRoot, pci_addr: &str) -> bool {
    use nix::unistd::{AccessFlags, access};

    let dev_dir = sysfs.sys_bus_pci_devices().join(pci_addr);
    let driver_override = dev_dir.join("driver_override");
    let unbind = dev_dir.join("driver/unbind");
    let bind = sysfs.sys_bus_pci_drivers("vfio-pci").join("bind");

    let writable = |path: &std::path::Path| -> bool { access(path, AccessFlags::W_OK).is_ok() };

    let unbind_ok = !unbind.exists() || writable(&unbind);
    writable(&driver_override) && unbind_ok && writable(&bind)
}

#[cfg(not(target_os = "linux"))]
pub fn check_sysfs_permissions(_sysfs: &SysfsRoot, _pci_addr: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn current_driver(sysfs: &SysfsRoot, pci_addr: &str) -> Option<String> {
    let driver_link = sysfs.sys_bus_pci_devices().join(pci_addr).join("driver");
    std::fs::read_link(&driver_link)
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().to_string()))
}

#[cfg(not(target_os = "linux"))]
pub fn current_driver(_sysfs: &SysfsRoot, _pci_addr: &str) -> Option<String> {
    None
}

/// Nvidia kernel modules that hold internal references to GPU devices and can
/// prevent a clean unbind. Unloaded in order (most-dependent first).
#[cfg(target_os = "linux")]
const NVIDIA_SUBMODULES: &[&str] = &["nvidia_uvm", "nvidia_drm", "nvidia_modeset"];

/// Timeout for nvidia prep commands (nvidia-smi, modprobe). These commands
/// can wedge if the nvidia driver is in a bad state.
#[cfg(target_os = "linux")]
const NVIDIA_PREP_TIMEOUT: Duration = Duration::from_secs(15);

/// Run a command with a timeout. Returns `Some(ExitStatus)` on success,
/// `None` on timeout or spawn failure. On timeout, kills the child and
/// drops it without calling `wait()` (same D-state safety as sysfs writes).
#[cfg(target_os = "linux")]
fn run_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    use std::thread;

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return None,
    };

    let poll_interval = Duration::from_millis(100);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    drop(child);
                    return None;
                }
                thread::sleep(poll_interval);
            }
            Err(_) => return None,
        }
    }
}

/// Best-effort preparation of the nvidia driver before a raw sysfs unbind.
///
/// Reduces the probability of the nvidia unbind deadlock by:
/// 1. Disabling persistence mode (nvidia-persistenced holds device refs).
/// 2. Unloading nvidia submodules that keep internal references open.
///
/// All commands run with a timeout — if `nvidia-smi` or `modprobe` hangs
/// (which can happen when the nvidia driver is in a bad state), the parent
/// process is not blocked. Failures are logged but not fatal.
#[cfg(target_os = "linux")]
fn nvidia_pre_unbind_prep(pci_addr: &str) {
    use std::process::{Command, Stdio};

    // 1. Disable persistence mode via nvidia-smi (if available).
    let mut cmd = Command::new("nvidia-smi");
    cmd.args(["-i", pci_addr, "-pm", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match run_with_timeout(cmd, NVIDIA_PREP_TIMEOUT) {
        Some(s) if s.success() => {
            eprintln!("GPU {pci_addr}: disabled nvidia persistence mode");
        }
        None => {
            eprintln!(
                "GPU {pci_addr}: nvidia-smi timed out after {:.0}s — skipping persistence mode",
                NVIDIA_PREP_TIMEOUT.as_secs_f64()
            );
        }
        _ => {}
    }

    // 2. Unload nvidia submodules that hold device references.
    //    This is best-effort — modules may be in use by other GPUs.
    for module in NVIDIA_SUBMODULES {
        let mut cmd = Command::new("modprobe");
        cmd.args(["-r", module])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match run_with_timeout(cmd, NVIDIA_PREP_TIMEOUT) {
            Some(s) if s.success() => {
                eprintln!("GPU {pci_addr}: unloaded {module}");
            }
            None => {
                eprintln!(
                    "GPU {pci_addr}: modprobe -r {module} timed out after {:.0}s",
                    NVIDIA_PREP_TIMEOUT.as_secs_f64()
                );
            }
            _ => {}
        }
    }
}

/// Reload nvidia kernel modules so the driver's sysfs bind file exists.
///
/// Called during restore to ensure `modprobe nvidia` brings back the driver
/// that `nvidia_pre_unbind_prep` may have unloaded. Loads the base `nvidia`
/// module plus its dependent submodules in the correct order.
#[cfg(target_os = "linux")]
fn nvidia_reload_modules() {
    use std::process::{Command, Stdio};

    // Load in dependency order: base module first, then dependents.
    // If the base "nvidia" module fails, skip submodules (they depend on it).
    for (i, module) in ["nvidia", "nvidia_modeset", "nvidia_uvm", "nvidia_drm"]
        .iter()
        .enumerate()
    {
        let mut cmd = Command::new("modprobe");
        cmd.arg(module)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        match run_with_timeout(cmd, NVIDIA_PREP_TIMEOUT) {
            Some(s) if s.success() => {
                eprintln!("GPU: loaded {module} for restore");
            }
            None => {
                eprintln!(
                    "GPU: modprobe {module} timed out after {:.0}s during restore",
                    NVIDIA_PREP_TIMEOUT.as_secs_f64()
                );
                break;
            }
            Some(s) => {
                eprintln!(
                    "GPU: modprobe {module} exited {} during restore (non-fatal)",
                    s.code().unwrap_or(-1)
                );
                if i == 0 {
                    break;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn bind_gpu_to_vfio(sysfs: &SysfsRoot, pci_addr: &str) -> Result<String, std::io::Error> {
    validate_pci_addr(pci_addr)?;
    let drv = current_driver(sysfs, pci_addr);

    if drv.as_deref() == Some("vfio-pci") {
        return Ok("vfio-pci".to_string());
    }

    let dev_dir = sysfs.sys_bus_pci_devices().join(pci_addr);

    if drv.is_some() {
        let is_nvidia = drv.as_deref() == Some("nvidia");
        if is_nvidia && sysfs.is_real_sysfs() {
            nvidia_pre_unbind_prep(pci_addr);

            // nvidia_pre_unbind_prep may cascade-remove the nvidia module when
            // all submodules are unloaded, which automatically unbinds the device.
            // Re-check before attempting the sysfs unbind write.
            if current_driver(sysfs, pci_addr).is_none() {
                eprintln!("GPU {pci_addr}: device already unbound after nvidia module cleanup");
            } else if current_driver(sysfs, pci_addr).as_deref() == Some("vfio-pci") {
                return Ok("vfio-pci".to_string());
            }
        }

        // Only attempt the sysfs unbind if a driver is still bound.
        if current_driver(sysfs, pci_addr).is_some() {
            let unbind = dev_dir.join("driver/unbind");
            let unbind_result = sysfs.write_sysfs(&unbind, pci_addr);

            if let Err(ref e) = unbind_result {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    // The nvidia unbind deadlock can complete the unbind at the
                    // hardware level while the syscall never returns to userspace.
                    // Check if the device is actually unbound despite the timeout.
                    if current_driver(sysfs, pci_addr).is_none() {
                        eprintln!(
                            "GPU {pci_addr}: sysfs unbind timed out but device is unbound — \
                             continuing (zombie subprocess may linger until reboot)"
                        );
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "Failed to unbind {pci_addr}: timed out and device is still \
                                 bound to {}. A reboot may be required.",
                                drv.as_deref().unwrap_or("unknown"),
                            ),
                        ));
                    }
                } else {
                    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        " — run as root"
                    } else {
                        ""
                    };
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to unbind device at {path}{hint}",
                            path = unbind.display()
                        ),
                    ));
                }
            }
        }
    }

    let driver_override = dev_dir.join("driver_override");
    if let Err(e) = sysfs.write_sysfs(&driver_override, "vfio-pci") {
        if let Some(ref orig) = drv {
            let orig_bind = sysfs.sys_bus_pci_drivers(orig).join("bind");
            let _ = sysfs.write_sysfs(&orig_bind, pci_addr);
        }
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            " — run as root"
        } else {
            ""
        };
        return Err(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to write driver_override at {path}{hint}",
                path = driver_override.display()
            ),
        ));
    }

    let vfio_bind = sysfs.sys_bus_pci_drivers("vfio-pci").join("bind");
    if let Err(e) = sysfs.write_sysfs(&vfio_bind, pci_addr) {
        let _ = sysfs.write_sysfs(&driver_override, "");
        if let Some(ref orig) = drv {
            let orig_bind = sysfs.sys_bus_pci_drivers(orig).join("bind");
            let _ = sysfs.write_sysfs(&orig_bind, pci_addr);
        }
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            " — run as root"
        } else {
            ""
        };
        return Err(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to bind to vfio-pci at {path}{hint} — is the vfio-pci module loaded?",
                path = vfio_bind.display()
            ),
        ));
    }

    // When the device had no driver (e.g. nvidia modules were already unloaded
    // from a previous crash), infer "nvidia" from the vendor ID so the restore
    // path knows which driver to rebind to.
    let original = match drv {
        Some(d) if !d.is_empty() => d,
        _ => {
            let vendor = std::fs::read_to_string(dev_dir.join("vendor"))
                .map(|v| v.trim().to_lowercase())
                .unwrap_or_default();
            if vendor == NVIDIA_VENDOR_ID {
                eprintln!(
                    "GPU {pci_addr}: no driver was bound, defaulting restore target to nvidia"
                );
                "nvidia".to_string()
            } else {
                String::new()
            }
        }
    };

    Ok(original)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_gpu_to_vfio(_sysfs: &SysfsRoot, _pci_addr: &str) -> Result<String, std::io::Error> {
    Ok(String::new())
}

#[cfg(target_os = "linux")]
pub fn rebind_gpu_to_original(
    sysfs: &SysfsRoot,
    pci_addr: &str,
    original_driver: &str,
) -> Result<(), std::io::Error> {
    validate_pci_addr(pci_addr)?;
    let dev_dir = sysfs.sys_bus_pci_devices().join(pci_addr);

    if current_driver(sysfs, pci_addr).is_some() {
        let unbind = dev_dir.join("driver/unbind");
        sysfs.write_sysfs(&unbind, pci_addr).map_err(|e| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                " — run as root"
            } else {
                ""
            };
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to unbind device at {path}{hint}",
                    path = unbind.display()
                ),
            )
        })?;
    }

    let driver_override = dev_dir.join("driver_override");
    sysfs.write_sysfs(&driver_override, "").map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            " — run as root"
        } else {
            ""
        };
        std::io::Error::new(
            e.kind(),
            format!(
                "Failed to clear driver_override at {path}{hint}",
                path = driver_override.display()
            ),
        )
    })?;

    if !original_driver.is_empty() && original_driver != "none" {
        // The nvidia driver bind path requires the kernel module to be loaded.
        // nvidia_pre_unbind_prep may have unloaded it (cascade from submodules),
        // or it may have been absent since before we started. Reload it so the
        // driver's bind file exists in sysfs.
        if original_driver == "nvidia" && sysfs.is_real_sysfs() {
            nvidia_reload_modules();
        }

        let bind = sysfs.sys_bus_pci_drivers(original_driver).join("bind");
        if let Err(e) = sysfs.write_sysfs(&bind, pci_addr) {
            eprintln!(
                "GPU {pci_addr}: explicit bind to {original_driver} failed ({e}), \
                 falling back to PCI rescan"
            );
            let rescan = sysfs.0.join("sys/bus/pci/rescan");
            let _ = sysfs.write_sysfs(&rescan, "1");
            // Give the kernel time to re-probe and bind drivers.
            std::thread::sleep(Duration::from_secs(1));

            if current_driver(sysfs, pci_addr).is_none() {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to restore {pci_addr} to {original_driver}: \
                         explicit bind and PCI rescan both failed. \
                         Manual fix: sudo modprobe nvidia && echo {pci_addr} | \
                         sudo tee /sys/bus/pci/drivers/nvidia/bind"
                    ),
                ));
            }
            let new_drv = current_driver(sysfs, pci_addr).unwrap_or_default();
            eprintln!("GPU {pci_addr}: PCI rescan bound device to {new_drv}");
        }
    } else {
        let rescan = sysfs.0.join("sys/bus/pci/rescan");
        let _ = sysfs.write_sysfs(&rescan, "1");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn rebind_gpu_to_original(
    _sysfs: &SysfsRoot,
    _pci_addr: &str,
    _original_driver: &str,
) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn iommu_group_peers(sysfs: &SysfsRoot, pci_addr: &str) -> Result<Vec<String>, std::io::Error> {
    validate_pci_addr(pci_addr)?;
    let iommu_devices = sysfs
        .sys_bus_pci_devices()
        .join(pci_addr)
        .join("iommu_group/devices");

    let entries = match std::fs::read_dir(&iommu_devices) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };

    let mut peers = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name != pci_addr {
            peers.push(name);
        }
    }
    Ok(peers)
}

#[cfg(not(target_os = "linux"))]
pub fn iommu_group_peers(
    _sysfs: &SysfsRoot,
    _pci_addr: &str,
) -> Result<Vec<String>, std::io::Error> {
    Ok(vec![])
}

#[cfg(target_os = "linux")]
pub fn bind_iommu_group_peers(
    sysfs: &SysfsRoot,
    pci_addr: &str,
) -> Result<Vec<(String, String)>, std::io::Error> {
    let peers = iommu_group_peers(sysfs, pci_addr)?;
    let mut restore_list = Vec::new();

    for peer in peers {
        match bind_gpu_to_vfio(sysfs, &peer) {
            Ok(original) => {
                if original != "vfio-pci" {
                    restore_list.push((peer, original));
                }
            }
            Err(e) => {
                let _ = rebind_iommu_group_peers(sysfs, &restore_list);
                return Err(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to bind IOMMU peer {peer}: {e}. Rolled back {} peer(s).",
                        restore_list.len()
                    ),
                ));
            }
        }
    }

    Ok(restore_list)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_iommu_group_peers(
    _sysfs: &SysfsRoot,
    _pci_addr: &str,
) -> Result<Vec<(String, String)>, std::io::Error> {
    Ok(vec![])
}

#[cfg(target_os = "linux")]
pub fn rebind_iommu_group_peers(
    sysfs: &SysfsRoot,
    peers: &[(String, String)],
) -> Result<(), std::io::Error> {
    let mut first_err = None;
    for (peer_addr, original_driver) in peers {
        if let Err(e) = rebind_gpu_to_original(sysfs, peer_addr, original_driver) {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn rebind_iommu_group_peers(
    _sysfs: &SysfsRoot,
    _peers: &[(String, String)],
) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_iommu_group_clean(sysfs: &SysfsRoot, pci_addr: &str) -> bool {
    let peers = match iommu_group_peers(sysfs, pci_addr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    peers
        .iter()
        .all(|peer| current_driver(sysfs, peer).as_deref() == Some("vfio-pci"))
}

#[cfg(not(target_os = "linux"))]
fn is_iommu_group_clean(_sysfs: &SysfsRoot, _pci_addr: &str) -> bool {
    false
}

/// Captures the bind state for a GPU so it can be restored on shutdown.
#[derive(Debug)]
pub struct GpuBindState {
    /// PCI address of the GPU that was bound.
    pub pci_addr: String,
    /// Driver the GPU was on before binding (e.g. "nvidia").
    pub original_driver: String,
    /// IOMMU group peers that were rebound, with their original drivers.
    pub peer_binds: Vec<(String, String)>,
    /// Whether this instance performed the bind (false if GPU was already on vfio-pci).
    pub did_bind: bool,
}

impl GpuBindState {
    /// Restore the GPU and its IOMMU peers to their original drivers.
    pub fn restore(&self) -> Result<(), std::io::Error> {
        self.restore_with_sysfs(&SysfsRoot::default())
    }

    pub fn restore_with_sysfs(&self, sysfs: &SysfsRoot) -> Result<(), std::io::Error> {
        if !self.did_bind {
            return Ok(());
        }

        // Always attempt peer restore even if GPU restore fails, so the
        // audio companion (and any other IOMMU group peers) aren't left
        // stranded on vfio-pci.
        eprintln!(
            "GPU: rebinding {} to {}",
            self.pci_addr, self.original_driver
        );
        let gpu_result = rebind_gpu_to_original(sysfs, &self.pci_addr, &self.original_driver);
        let peer_result = rebind_iommu_group_peers(sysfs, &self.peer_binds);

        if let Err(ref gpu_err) = gpu_result {
            if let Err(ref peer_err) = peer_result {
                eprintln!("GPU: peer restore also failed: {peer_err}");
            }
            return Err(std::io::Error::new(gpu_err.kind(), gpu_err.to_string()));
        }
        peer_result
    }
}

/// RAII guard that restores GPU driver binding when dropped.
///
/// Ensures the GPU is rebound to its original driver on normal exit,
/// early return (?), or panic. Cannot protect against SIGKILL.
pub struct GpuBindGuard {
    state: Option<GpuBindState>,
}

impl GpuBindGuard {
    pub fn new(state: GpuBindState) -> Self {
        Self { state: Some(state) }
    }

    /// Take the state out, preventing restore on drop.
    pub fn disarm(&mut self) -> Option<GpuBindState> {
        self.state.take()
    }

    /// Get the PCI address of the bound GPU, if any.
    pub fn pci_addr(&self) -> Option<&str> {
        self.state.as_ref().map(|s| s.pci_addr.as_str())
    }
}

impl Drop for GpuBindGuard {
    fn drop(&mut self) {
        if let Some(ref state) = self.state {
            eprintln!(
                "GPU: restoring {} to {} (cleanup)",
                state.pci_addr, state.original_driver
            );
            if let Err(e) = state.restore() {
                eprintln!("GPU: restore failed: {e}");
            }
        }
    }
}

/// Prepare a GPU for VFIO passthrough: run safety checks, select, and bind.
///
/// When `requested_bdf` is Some, targets that specific device.
/// When None (auto mode), selects the best available GPU.
///
/// All safety checks are hard failures — if any check fails, this returns
/// an error and does not bind anything.
pub fn prepare_gpu_for_passthrough(
    requested_bdf: Option<&str>,
) -> Result<GpuBindState, std::io::Error> {
    prepare_gpu_with_sysfs(&SysfsRoot::default(), requested_bdf)
}

pub fn prepare_gpu_with_sysfs(
    sysfs: &SysfsRoot,
    requested_bdf: Option<&str>,
) -> Result<GpuBindState, std::io::Error> {
    match requested_bdf {
        Some(bdf) => prepare_specific_gpu(sysfs, bdf),
        None => prepare_auto_gpu(sysfs),
    }
}

fn prepare_specific_gpu(sysfs: &SysfsRoot, bdf: &str) -> Result<GpuBindState, std::io::Error> {
    validate_pci_addr(bdf)?;

    let dev_dir = sysfs.sys_bus_pci_devices().join(bdf);
    if !dev_dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("PCI device {bdf} not found in sysfs"),
        ));
    }

    let vendor = std::fs::read_to_string(dev_dir.join("vendor"))
        .map(|v| v.trim().to_lowercase())
        .unwrap_or_default();
    if vendor != NVIDIA_VENDOR_ID {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("PCI device {bdf} is not an NVIDIA device (vendor: {vendor})"),
        ));
    }
    let class = std::fs::read_to_string(dev_dir.join("class"))
        .map(|c| c.trim().to_lowercase())
        .unwrap_or_default();
    if !class.starts_with("0x03") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("PCI device {bdf} is not a GPU (class: {class})"),
        ));
    }

    if !check_msix_support(sysfs, bdf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "GPU {bdf}: device does not support MSI-X (only MSI). \
                 cloud-hypervisor requires MSI-X for VFIO passthrough. \
                 This is a hardware/firmware limitation of this GPU model."
            ),
        ));
    }

    if current_driver(sysfs, bdf).as_deref() == Some("vfio-pci") && is_iommu_group_clean(sysfs, bdf)
    {
        return Ok(GpuBindState {
            pci_addr: bdf.to_string(),
            original_driver: "vfio-pci".to_string(),
            peer_binds: vec![],
            did_bind: false,
        });
    }

    if check_display_attached(sysfs, bdf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GPU {bdf}: has active display outputs"),
        ));
    }

    let procs = check_active_gpu_processes().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("GPU {bdf}: cannot verify GPU is idle — {e}"),
        )
    })?;
    if !procs.is_empty() {
        let desc: Vec<String> = procs
            .iter()
            .map(|(pid, comm)| format!("{pid} ({comm})"))
            .collect();
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GPU {bdf}: in use by PIDs: {}", desc.join(", ")),
        ));
    }

    if !check_iommu_enabled(sysfs, bdf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GPU {bdf}: IOMMU not enabled or device has no IOMMU group"),
        ));
    }

    if !check_vfio_modules_loaded(sysfs) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GPU {bdf}: VFIO kernel modules not loaded"),
        ));
    }

    if !check_sysfs_permissions(sysfs, bdf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("GPU {bdf}: insufficient sysfs permissions — run as root"),
        ));
    }

    let original_driver = bind_gpu_to_vfio(sysfs, bdf)?;
    let peer_binds = match bind_iommu_group_peers(sysfs, bdf) {
        Ok(peers) => peers,
        Err(e) => {
            let _ = rebind_gpu_to_original(sysfs, bdf, &original_driver);
            return Err(e);
        }
    };

    Ok(GpuBindState {
        pci_addr: bdf.to_string(),
        original_driver,
        peer_binds,
        did_bind: true,
    })
}

fn prepare_auto_gpu(sysfs: &SysfsRoot) -> Result<GpuBindState, std::io::Error> {
    let pci_dir = sysfs.sys_bus_pci_devices();
    let entries = std::fs::read_dir(&pci_dir).map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot read {}: {e}", pci_dir.display()))
    })?;

    let mut nvidia_addrs = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let dev_path = entry.path();
        let vendor = match std::fs::read_to_string(dev_path.join("vendor")) {
            Ok(v) => v.trim().to_lowercase(),
            Err(_) => continue,
        };
        let class = match std::fs::read_to_string(dev_path.join("class")) {
            Ok(c) => c.trim().to_lowercase(),
            Err(_) => continue,
        };
        if vendor == NVIDIA_VENDOR_ID && class.starts_with("0x03") {
            nvidia_addrs.push(entry.file_name().to_string_lossy().to_string());
        }
    }

    if nvidia_addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no NVIDIA PCI device found",
        ));
    }

    nvidia_addrs.sort();

    for addr in &nvidia_addrs {
        if current_driver(sysfs, addr).as_deref() == Some("vfio-pci")
            && is_iommu_group_clean(sysfs, addr)
        {
            return Ok(GpuBindState {
                pci_addr: addr.clone(),
                original_driver: "vfio-pci".to_string(),
                peer_binds: vec![],
                did_bind: false,
            });
        }
    }

    let mut blocked: Vec<(String, String)> = Vec::new();
    let active_procs = check_active_gpu_processes()
        .map_err(|e| std::io::Error::new(e.kind(), format!("cannot verify GPUs are idle — {e}")))?;

    for addr in &nvidia_addrs {
        if !check_msix_support(sysfs, addr) {
            blocked.push((
                addr.clone(),
                "no MSI-X support (required by cloud-hypervisor)".to_string(),
            ));
            continue;
        }

        if current_driver(sysfs, addr).as_deref() == Some("vfio-pci") {
            blocked.push((addr.clone(), "IOMMU group not clean".to_string()));
            continue;
        }

        if check_display_attached(sysfs, addr) {
            blocked.push((addr.clone(), "has active display outputs".to_string()));
            continue;
        }

        if !active_procs.is_empty() {
            let desc: Vec<String> = active_procs
                .iter()
                .map(|(pid, comm)| format!("{pid} ({comm})"))
                .collect();
            blocked.push((addr.clone(), format!("in use by PIDs: {}", desc.join(", "))));
            continue;
        }

        if !check_iommu_enabled(sysfs, addr) {
            blocked.push((addr.clone(), "IOMMU not enabled".to_string()));
            continue;
        }

        if !check_vfio_modules_loaded(sysfs) {
            blocked.push((addr.clone(), "VFIO modules not loaded".to_string()));
            continue;
        }

        if !check_sysfs_permissions(sysfs, addr) {
            blocked.push((addr.clone(), "insufficient sysfs permissions".to_string()));
            continue;
        }

        eprintln!("GPU: binding {addr} for VFIO passthrough");
        let original_driver = bind_gpu_to_vfio(sysfs, addr)?;
        let peer_binds = match bind_iommu_group_peers(sysfs, addr) {
            Ok(peers) => peers,
            Err(e) => {
                let _ = rebind_gpu_to_original(sysfs, addr, &original_driver);
                return Err(e);
            }
        };

        return Ok(GpuBindState {
            pci_addr: addr.clone(),
            original_driver,
            peer_binds,
            did_bind: true,
        });
    }

    let mut msg =
        String::from("GPU passthrough blocked by safety checks.\n\n  Detected devices:\n");
    for (addr, reason) in &blocked {
        msg.push_str(&format!("    {addr}: {reason}\n"));
    }
    msg.push_str("\n  No GPU is available for passthrough.");

    Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn passthrough_gate_is_false_without_env_var() {
        // SAFETY: test runs single-threaded; no other thread reads this var.
        unsafe { std::env::remove_var("OPENSHELL_VM_GPU_E2E") };
        assert!(
            !nvidia_gpu_available_for_vm_passthrough(None),
            "gate must return false when OPENSHELL_VM_GPU_E2E is unset"
        );
    }

    #[test]
    fn probe_returns_no_device_or_readiness_on_typical_ci() {
        let results = probe_host_nvidia_vfio_readiness();

        #[cfg(not(target_os = "linux"))]
        assert!(results.is_empty(), "non-Linux should return empty Vec");

        #[cfg(target_os = "linux")]
        {
            // CI machines typically have no NVIDIA GPU bound to vfio-pci.
            // Accept an empty list or any per-device readiness state.
            for (addr, state) in &results {
                assert!(!addr.is_empty(), "PCI address should not be empty");
                assert!(
                    matches!(
                        state,
                        HostNvidiaVfioReadiness::BoundToNvidia
                            | HostNvidiaVfioReadiness::VfioBoundReady
                            | HostNvidiaVfioReadiness::VfioBoundDirtyGroup
                    ),
                    "unexpected per-device readiness state for {addr}: {state:?}"
                );
            }
        }
    }

    #[test]
    fn display_impl_is_meaningful() {
        let states = [
            HostNvidiaVfioReadiness::UnsupportedPlatform,
            HostNvidiaVfioReadiness::NoNvidiaDevice,
            HostNvidiaVfioReadiness::BoundToNvidia,
            HostNvidiaVfioReadiness::VfioBoundReady,
            HostNvidiaVfioReadiness::VfioBoundDirtyGroup,
            HostNvidiaVfioReadiness::MixedVfioAndOther,
        ];
        for state in &states {
            let msg = format!("{state}");
            assert!(!msg.is_empty(), "Display for {state:?} should not be empty");
        }
    }

    /// Build a minimal PCI config space (64 bytes) with a capability list
    /// containing a single MSI-X entry (cap ID 0x11) so `check_msix_support`
    /// sees the device as passthrough-capable.
    fn mock_pci_config_with_msix() -> Vec<u8> {
        let mut cfg = vec![0u8; 64];
        // Status register (offset 0x06): set bit 4 = capabilities list present.
        cfg[0x06] = 0x10;
        // Capabilities pointer (offset 0x34): first cap at 0x40.
        cfg[0x34] = 0x40;
        // Extend to include the capability at offset 0x40.
        cfg.resize(0x42, 0);
        // Cap at 0x40: ID = 0x11 (MSI-X), next = 0x00 (end of list).
        cfg[0x40] = 0x11;
        cfg[0x41] = 0x00;
        cfg
    }

    fn mock_pci_device(root: &Path, pci_addr: &str, vendor: &str, driver: Option<&str>) {
        use std::fs;
        let dev_dir = root.join("sys/bus/pci/devices").join(pci_addr);
        fs::create_dir_all(&dev_dir).unwrap();
        fs::write(dev_dir.join("vendor"), vendor).unwrap();
        fs::write(dev_dir.join("class"), "0x030000").unwrap();
        fs::write(dev_dir.join("config"), mock_pci_config_with_msix()).unwrap();
        if let Some(drv) = driver {
            let driver_dir = root.join("sys/bus/pci/drivers").join(drv);
            fs::create_dir_all(&driver_dir).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(&driver_dir, dev_dir.join("driver")).unwrap();
        }
        fs::write(dev_dir.join("driver_override"), "").unwrap();
    }

    fn mock_drm_card(root: &Path, card: &str, pci_addr: &str, outputs: &[(&str, &str)]) {
        use std::fs;
        let card_dir = root.join("sys/class/drm").join(card);
        fs::create_dir_all(&card_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            root.join("sys/bus/pci/devices").join(pci_addr),
            card_dir.join("device"),
        )
        .unwrap();
        for (output, status) in outputs {
            let out_dir = card_dir.join(format!("{card}-{output}"));
            fs::create_dir_all(&out_dir).unwrap();
            fs::write(out_dir.join("status"), status).unwrap();
        }
    }

    fn mock_iommu_group(root: &Path, group_id: u32, members: &[&str]) {
        use std::fs;
        let group_dir = root.join(format!("sys/kernel/iommu_groups/{group_id}/devices"));
        fs::create_dir_all(&group_dir).unwrap();
        for member in members {
            let dev_dir = root.join("sys/bus/pci/devices").join(member);
            fs::create_dir_all(&dev_dir).unwrap();
            #[cfg(unix)]
            {
                let iommu_group_target = root.join(format!("sys/kernel/iommu_groups/{group_id}"));
                let _ =
                    std::os::unix::fs::symlink(&iommu_group_target, dev_dir.join("iommu_group"));
                let _ = std::os::unix::fs::symlink(&dev_dir, group_dir.join(member));
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn display_attached_detects_active_framebuffer() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        mock_drm_card(
            root.path(),
            "card0",
            "0000:41:00.0",
            &[("DP-1", "connected")],
        );
        assert!(check_display_attached(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn display_attached_false_on_headless() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        mock_drm_card(
            root.path(),
            "card0",
            "0000:41:00.0",
            &[("DP-1", "disconnected")],
        );
        assert!(!check_display_attached(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn display_attached_false_no_drm_card() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        assert!(!check_display_attached(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn iommu_check_fails_without_groups_dir() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        assert!(!check_iommu_enabled(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn iommu_check_passes_with_group() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        mock_iommu_group(root.path(), 15, &["0000:41:00.0"]);
        assert!(check_iommu_enabled(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vfio_modules_loaded_true() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_iommu_type1")).unwrap();
        assert!(check_vfio_modules_loaded(&sysfs));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vfio_modules_missing() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        assert!(!check_vfio_modules_loaded(&sysfs));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn permissions_writable() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        let bind_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&bind_dir).unwrap();
        fs::write(bind_dir.join("bind"), "").unwrap();
        assert!(check_sysfs_permissions(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn permissions_readonly_driver_override() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        let driver_override = root
            .path()
            .join("sys/bus/pci/devices/0000:41:00.0/driver_override");
        fs::set_permissions(&driver_override, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(!check_sysfs_permissions(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn permissions_readonly_bind() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        let bind_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&bind_dir).unwrap();
        let bind_path = bind_dir.join("bind");
        fs::write(&bind_path, "").unwrap();
        fs::set_permissions(&bind_path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(!check_sysfs_permissions(&sysfs, "0000:41:00.0"));
    }

    fn mock_bindable_gpu(root: &Path, pci_addr: &str) {
        mock_pci_device(root, pci_addr, "0x10de", Some("nvidia"));
        let drv_unbind = root.join("sys/bus/pci/drivers/nvidia/unbind");
        fs::write(&drv_unbind, "").unwrap();
        let vfio_dir = root.join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&vfio_dir).unwrap();
        fs::write(vfio_dir.join("bind"), "").unwrap();
        mock_iommu_group(root, 15, &[pci_addr]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bind_gpu_writes_correct_sysfs_paths() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");

        bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();

        let unbind_content =
            fs::read_to_string(root.path().join("sys/bus/pci/drivers/nvidia/unbind")).unwrap();
        assert_eq!(unbind_content, "0000:41:00.0");

        let override_content = fs::read_to_string(
            root.path()
                .join("sys/bus/pci/devices/0000:41:00.0/driver_override"),
        )
        .unwrap();
        assert_eq!(override_content, "vfio-pci");

        let bind_content =
            fs::read_to_string(root.path().join("sys/bus/pci/drivers/vfio-pci/bind")).unwrap();
        assert_eq!(bind_content, "0000:41:00.0");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bind_returns_original_driver() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");

        let result = bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();
        assert_eq!(result, "nvidia");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bind_noop_when_already_vfio() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", Some("vfio-pci"));
        let vfio_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&vfio_dir).unwrap();
        fs::write(vfio_dir.join("bind"), "").unwrap();

        let nvidia_unbind = root.path().join("sys/bus/pci/drivers/nvidia/unbind");
        fs::create_dir_all(nvidia_unbind.parent().unwrap()).unwrap();
        fs::write(&nvidia_unbind, "").unwrap();

        let result = bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();
        assert_eq!(result, "vfio-pci");

        let unbind_content = fs::read_to_string(&nvidia_unbind).unwrap();
        assert_eq!(
            unbind_content, "",
            "nvidia unbind should NOT have been written"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rebind_clears_driver_override() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();

        let dev_dir = root.path().join("sys/bus/pci/devices/0000:41:00.0");
        let vfio_driver_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        #[cfg(unix)]
        {
            let _ = fs::remove_file(dev_dir.join("driver"));
            std::os::unix::fs::symlink(&vfio_driver_dir, dev_dir.join("driver")).unwrap();
        }
        fs::write(vfio_driver_dir.join("unbind"), "").unwrap();
        let nvidia_dir = root.path().join("sys/bus/pci/drivers/nvidia");
        fs::create_dir_all(&nvidia_dir).unwrap();
        fs::write(nvidia_dir.join("bind"), "").unwrap();

        rebind_gpu_to_original(&sysfs, "0000:41:00.0", "nvidia").unwrap();

        let override_content = fs::read_to_string(dev_dir.join("driver_override")).unwrap();
        assert_eq!(override_content, "");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rebind_writes_to_original_driver_bind() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();

        let dev_dir = root.path().join("sys/bus/pci/devices/0000:41:00.0");
        let vfio_driver_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        #[cfg(unix)]
        {
            let _ = fs::remove_file(dev_dir.join("driver"));
            std::os::unix::fs::symlink(&vfio_driver_dir, dev_dir.join("driver")).unwrap();
        }
        fs::write(vfio_driver_dir.join("unbind"), "").unwrap();
        let nvidia_dir = root.path().join("sys/bus/pci/drivers/nvidia");
        fs::create_dir_all(&nvidia_dir).unwrap();
        fs::write(nvidia_dir.join("bind"), "").unwrap();

        rebind_gpu_to_original(&sysfs, "0000:41:00.0", "nvidia").unwrap();

        let bind_content = fs::read_to_string(nvidia_dir.join("bind")).unwrap();
        assert_eq!(bind_content, "0000:41:00.0");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn iommu_peers_listed_correctly() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        mock_pci_device(root.path(), "0000:41:00.1", "0x10de", None);
        mock_iommu_group(root.path(), 15, &["0000:41:00.0", "0000:41:00.1"]);

        let peers = iommu_group_peers(&sysfs, "0000:41:00.0").unwrap();
        assert_eq!(peers, vec!["0000:41:00.1"]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn iommu_peers_bound_together() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        mock_pci_device(root.path(), "0000:41:00.1", "0x10de", Some("nvidia"));
        let drv_unbind = root.path().join("sys/bus/pci/drivers/nvidia/unbind");
        fs::write(&drv_unbind, "").unwrap();
        mock_iommu_group(root.path(), 15, &["0000:41:00.0", "0000:41:00.1"]);

        let restore = bind_iommu_group_peers(&sysfs, "0000:41:00.0").unwrap();
        assert_eq!(
            restore,
            vec![("0000:41:00.1".to_string(), "nvidia".to_string())]
        );

        let override_content = fs::read_to_string(
            root.path()
                .join("sys/bus/pci/devices/0000:41:00.1/driver_override"),
        )
        .unwrap();
        assert_eq!(override_content, "vfio-pci");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn peer_restore_rebinds_to_original() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        mock_pci_device(root.path(), "0000:41:00.1", "0x10de", Some("nvidia"));
        let drv_unbind = root.path().join("sys/bus/pci/drivers/nvidia/unbind");
        fs::write(&drv_unbind, "").unwrap();
        mock_iommu_group(root.path(), 15, &["0000:41:00.0", "0000:41:00.1"]);

        let restore = bind_iommu_group_peers(&sysfs, "0000:41:00.0").unwrap();

        let dev_dir = root.path().join("sys/bus/pci/devices/0000:41:00.1");
        let vfio_driver_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        #[cfg(unix)]
        {
            let _ = fs::remove_file(dev_dir.join("driver"));
            std::os::unix::fs::symlink(&vfio_driver_dir, dev_dir.join("driver")).unwrap();
        }
        fs::write(vfio_driver_dir.join("unbind"), "").unwrap();
        let nvidia_dir = root.path().join("sys/bus/pci/drivers/nvidia");
        fs::create_dir_all(&nvidia_dir).unwrap();
        fs::write(nvidia_dir.join("bind"), "").unwrap();

        rebind_iommu_group_peers(&sysfs, &restore).unwrap();

        let override_content = fs::read_to_string(dev_dir.join("driver_override")).unwrap();
        assert_eq!(override_content, "");
    }

    fn mock_multi_gpu_host(root: &Path) {
        // GPU 0: on nvidia, has display attached
        mock_bindable_gpu(root, "0000:41:00.0");
        mock_drm_card(root, "card0", "0000:41:00.0", &[("DP-1", "connected")]);

        // GPU 1: on nvidia, idle (no display, no processes)
        mock_bindable_gpu(root, "0000:42:00.0");

        // GPU 2: already on vfio-pci, clean IOMMU group
        mock_pci_device(root, "0000:43:00.0", "0x10de", Some("vfio-pci"));
        mock_iommu_group(root, 17, &["0000:43:00.0"]);

        fs::create_dir_all(root.join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.join("sys/module/vfio_iommu_type1")).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn auto_prefers_already_vfio() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_multi_gpu_host(root.path());

        let state = prepare_gpu_with_sysfs(&sysfs, None).unwrap();
        assert_eq!(state.pci_addr, "0000:43:00.0");
        assert!(!state.did_bind);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn auto_selects_idle_gpu_when_no_vfio() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());

        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", Some("nvidia"));
        mock_drm_card(
            root.path(),
            "card0",
            "0000:41:00.0",
            &[("DP-1", "connected")],
        );
        mock_iommu_group(root.path(), 15, &["0000:41:00.0"]);

        mock_pci_device(root.path(), "0000:42:00.0", "0x10de", Some("nvidia"));
        mock_iommu_group(root.path(), 16, &["0000:42:00.0"]);

        let drv_unbind = root.path().join("sys/bus/pci/drivers/nvidia/unbind");
        fs::write(&drv_unbind, "").unwrap();
        let vfio_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&vfio_dir).unwrap();
        fs::write(vfio_dir.join("bind"), "").unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_iommu_type1")).unwrap();

        let state = prepare_gpu_with_sysfs(&sysfs, None).unwrap();
        assert_eq!(state.pci_addr, "0000:42:00.0");
        assert!(state.did_bind);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn auto_fails_when_all_blocked() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());

        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", Some("nvidia"));
        mock_drm_card(
            root.path(),
            "card0",
            "0000:41:00.0",
            &[("DP-1", "connected")],
        );
        mock_iommu_group(root.path(), 15, &["0000:41:00.0"]);

        mock_pci_device(root.path(), "0000:42:00.0", "0x10de", Some("nvidia"));
        mock_drm_card(
            root.path(),
            "card1",
            "0000:42:00.0",
            &[("HDMI-1", "connected")],
        );
        mock_iommu_group(root.path(), 16, &["0000:42:00.0"]);

        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_iommu_type1")).unwrap();

        let err = prepare_gpu_with_sysfs(&sysfs, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("display"),
            "error should mention display: {msg}"
        );
        assert!(
            msg.contains("0000:41:00.0"),
            "error should list first GPU: {msg}"
        );
        assert!(
            msg.contains("0000:42:00.0"),
            "error should list second GPU: {msg}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn auto_fails_on_empty_host() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());

        fs::create_dir_all(root.path().join("sys/bus/pci/devices")).unwrap();

        let err = prepare_gpu_with_sysfs(&sysfs, None).unwrap_err();
        assert!(
            err.to_string().contains("no NVIDIA PCI device found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn specific_bdf_binds_target() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_iommu_type1")).unwrap();

        let state = prepare_gpu_with_sysfs(&sysfs, Some("0000:41:00.0")).unwrap();
        assert_eq!(state.pci_addr, "0000:41:00.0");
        assert!(state.did_bind);
        assert_eq!(state.original_driver, "nvidia");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn specific_bdf_validates_format() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());

        let err = prepare_gpu_with_sysfs(&sysfs, Some("invalid")).unwrap_err();
        assert!(
            err.to_string().contains("invalid PCI address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn specific_bdf_fails_display_check() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", Some("nvidia"));
        mock_drm_card(
            root.path(),
            "card0",
            "0000:41:00.0",
            &[("DP-1", "connected")],
        );

        let err = prepare_gpu_with_sysfs(&sysfs, Some("0000:41:00.0")).unwrap_err();
        assert!(
            err.to_string().contains("display"),
            "error should mention display: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn specific_bdf_fails_iommu_check() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", Some("nvidia"));

        let err = prepare_gpu_with_sysfs(&sysfs, Some("0000:41:00.0")).unwrap_err();
        assert!(
            err.to_string().contains("IOMMU"),
            "error should mention IOMMU: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_bindable_gpu(root.path(), "0000:41:00.0");
        fs::create_dir_all(root.path().join("sys/module/vfio_pci")).unwrap();
        fs::create_dir_all(root.path().join("sys/module/vfio_iommu_type1")).unwrap();

        let state = prepare_gpu_with_sysfs(&sysfs, Some("0000:41:00.0")).unwrap();
        assert!(state.did_bind);
        assert_eq!(state.original_driver, "nvidia");

        let dev_dir = root.path().join("sys/bus/pci/devices/0000:41:00.0");
        let vfio_driver_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        #[cfg(unix)]
        {
            let _ = fs::remove_file(dev_dir.join("driver"));
            std::os::unix::fs::symlink(&vfio_driver_dir, dev_dir.join("driver")).unwrap();
        }
        fs::write(vfio_driver_dir.join("unbind"), "").unwrap();
        let nvidia_dir = root.path().join("sys/bus/pci/drivers/nvidia");
        fs::create_dir_all(&nvidia_dir).unwrap();
        fs::write(nvidia_dir.join("bind"), "").unwrap();

        state.restore_with_sysfs(&sysfs).unwrap();

        let override_content = fs::read_to_string(dev_dir.join("driver_override")).unwrap();
        assert_eq!(override_content, "");

        let bind_content = fs::read_to_string(nvidia_dir.join("bind")).unwrap();
        assert_eq!(bind_content, "0000:41:00.0");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_noop_when_did_not_bind() {
        let state = GpuBindState {
            pci_addr: "0000:43:00.0".to_string(),
            original_driver: "vfio-pci".to_string(),
            peer_binds: vec![],
            did_bind: false,
        };
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        state.restore_with_sysfs(&sysfs).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bind_unbound_nvidia_defaults_to_nvidia_driver() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        // Device with no driver bound (simulating post-crash state).
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        let vfio_dir = root.path().join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&vfio_dir).unwrap();
        fs::write(vfio_dir.join("bind"), "").unwrap();

        let result = bind_gpu_to_vfio(&sysfs, "0000:41:00.0").unwrap();
        assert_eq!(
            result, "nvidia",
            "unbound NVIDIA device should default to nvidia as restore driver"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn msix_detected_in_config() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        mock_pci_device(root.path(), "0000:41:00.0", "0x10de", None);
        assert!(check_msix_support(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn msix_absent_msi_only() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        let dev_dir = root.path().join("sys/bus/pci/devices").join("0000:41:00.0");
        fs::create_dir_all(&dev_dir).unwrap();
        // Config with MSI (cap 0x05) only, no MSI-X (0x11).
        let mut cfg = vec![0u8; 0x42];
        cfg[0x06] = 0x10; // capabilities list present
        cfg[0x34] = 0x40; // cap pointer
        cfg[0x40] = 0x05; // MSI capability
        cfg[0x41] = 0x00; // end of list
        fs::write(dev_dir.join("config"), &cfg).unwrap();
        assert!(!check_msix_support(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn msix_empty_cap_list() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        let dev_dir = root.path().join("sys/bus/pci/devices").join("0000:41:00.0");
        fs::create_dir_all(&dev_dir).unwrap();
        let mut cfg = vec![0u8; 0x40];
        cfg[0x06] = 0x10; // capabilities list present
        cfg[0x34] = 0x00; // null cap pointer
        fs::write(dev_dir.join("config"), &cfg).unwrap();
        assert!(!check_msix_support(&sysfs, "0000:41:00.0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn msix_circular_cap_list() {
        let root = tempfile::tempdir().unwrap();
        let sysfs = SysfsRoot::new(root.path().to_path_buf());
        let dev_dir = root.path().join("sys/bus/pci/devices").join("0000:41:00.0");
        fs::create_dir_all(&dev_dir).unwrap();
        // Circular: cap at 0x40 points back to 0x40.
        let mut cfg = vec![0u8; 0x42];
        cfg[0x06] = 0x10;
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x05; // MSI (not MSI-X)
        cfg[0x41] = 0x40; // points back to self
        fs::write(dev_dir.join("config"), &cfg).unwrap();
        // Should terminate via the 48-iteration guard, not hang.
        assert!(!check_msix_support(&sysfs, "0000:41:00.0"));
    }

    #[test]
    fn guard_has_pci_addr() {
        let state = GpuBindState {
            pci_addr: "0000:41:00.0".to_string(),
            original_driver: "nvidia".to_string(),
            peer_binds: vec![],
            did_bind: true,
        };
        let guard = GpuBindGuard::new(state);
        assert_eq!(guard.pci_addr(), Some("0000:41:00.0"));
    }

    #[test]
    fn guard_disarm_returns_state() {
        let state = GpuBindState {
            pci_addr: "0000:41:00.0".to_string(),
            original_driver: "nvidia".to_string(),
            peer_binds: vec![],
            did_bind: true,
        };
        let mut guard = GpuBindGuard::new(state);
        let taken = guard.disarm();
        assert!(taken.is_some());
        assert_eq!(guard.pci_addr(), None);
    }

    #[test]
    fn guard_disarm_prevents_double_restore() {
        let state = GpuBindState {
            pci_addr: "0000:41:00.0".to_string(),
            original_driver: "nvidia".to_string(),
            peer_binds: vec![],
            did_bind: true,
        };
        let mut guard = GpuBindGuard::new(state);
        let _ = guard.disarm();
        let second = guard.disarm();
        assert!(second.is_none());
    }

    #[test]
    fn guard_drop_noop_when_did_not_bind() {
        let state = GpuBindState {
            pci_addr: "0000:41:00.0".to_string(),
            original_driver: "nvidia".to_string(),
            peer_binds: vec![],
            did_bind: false,
        };
        let guard = GpuBindGuard::new(state);
        drop(guard);
    }

    #[test]
    fn guard_drop_on_panic_is_safe() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let state = GpuBindState {
                pci_addr: "0000:41:00.0".to_string(),
                original_driver: "nvidia".to_string(),
                peer_binds: vec![],
                did_bind: false,
            };
            let _guard = GpuBindGuard::new(state);
            panic!("test panic");
        }));
        assert!(result.is_err());
    }
}
