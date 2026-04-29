// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VFIO GPU passthrough lifecycle management for `OpenShell` VM sandboxes.
//!
//! Provides discovery, binding, and crash-recovery for NVIDIA GPUs using
//! the VFIO subsystem. All sysfs access goes through [`SysfsRoot`] so the
//! entire stack is testable without root or real hardware.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const NVIDIA_VENDOR_ID: &str = "0x10de";
const GPU_CLASS_DISPLAY_VGA: &str = "0x030000";
const GPU_CLASS_DISPLAY_3D: u32 = 0x0302;

const VFIO_BIND_POLL_INTERVAL: Duration = Duration::from_millis(100);
const VFIO_BIND_MAX_POLL_ATTEMPTS: u32 = 20;

/// Reference counter for vendor:device ID registrations in the vfio-pci
/// match table. Multiple GPUs may share the same vendor:device pair (e.g.,
/// two A100s). We only write to the kernel's `new_id`/`remove_id` sysfs
/// files when the first GPU registers or the last GPU deregisters an ID.
static VFIO_ID_REFCOUNTS: std::sync::LazyLock<Mutex<HashMap<String, usize>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VfioError {
    #[error("GPU {bdf} not found in sysfs")]
    GpuNotFound { bdf: String },

    #[error("GPU {bdf} is not an NVIDIA device (vendor={vendor})")]
    NotNvidia { bdf: String, vendor: String },

    #[error("GPU {bdf} has no IOMMU group — is IOMMU enabled?")]
    NoIommuGroup { bdf: String },

    #[error("GPU {bdf} IOMMU group {group} has other non-vfio-pci devices: {peers:?}")]
    IommuGroupConflict {
        bdf: String,
        group: u32,
        peers: Vec<String>,
    },

    #[error("failed to bind GPU {bdf} to vfio-pci: {reason}")]
    BindFailed { bdf: String, reason: String },

    #[error("failed to unbind GPU {bdf} from vfio-pci: {reason}")]
    UnbindFailed { bdf: String, reason: String },

    #[error("sysfs I/O error for {path}: {source}")]
    SysfsIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid PCI BDF address: {bdf}")]
    InvalidBdf { bdf: String },
}

// ---------------------------------------------------------------------------
// SysfsRoot
// ---------------------------------------------------------------------------

/// Abstraction over sysfs paths, enabling test mocks via a temporary directory.
#[derive(Debug, Clone)]
pub struct SysfsRoot {
    base: PathBuf,
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

    pub fn pci_devices_dir(&self) -> PathBuf {
        self.base.join("bus/pci/devices")
    }

    pub fn pci_device(&self, bdf: &str) -> PathBuf {
        self.pci_devices_dir().join(bdf)
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

// ---------------------------------------------------------------------------
// GpuInfo
// ---------------------------------------------------------------------------

/// Information about a discovered NVIDIA GPU eligible for VFIO passthrough.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpuInfo {
    pub bdf: String,
    pub name: String,
    pub vendor: String,
    pub device: String,
    pub iommu_group: u32,
}

// ---------------------------------------------------------------------------
// GpuBindGuard
// ---------------------------------------------------------------------------

/// RAII guard that restores a GPU to its host driver when dropped.
///
/// Call [`disarm`](Self::disarm) to transfer ownership (e.g. the VM took over
/// the device successfully and we should not unbind it on cleanup).
pub struct GpuBindGuard {
    bdf: String,
    companion_bdfs: Vec<String>,
    sysfs: SysfsRoot,
    disarmed: bool,
    /// Cached "VVVV DDDD" string captured at bind time so that
    /// deregistration from vfio-pci's match table succeeds even if the
    /// device's sysfs entries have disappeared (e.g. physical removal).
    vfio_id: Option<String>,
}

impl GpuBindGuard {
    pub fn bdf(&self) -> &str {
        &self.bdf
    }

    /// Prevent the guard from restoring the GPU on drop.
    pub fn disarm(mut self) {
        self.disarmed = true;
    }
}

impl GpuBindGuard {
    /// Deregister the cached vfio-pci match-table entry, then restore the
    /// device to its host driver.
    ///
    /// Using the cached ID avoids re-reading vendor/device from sysfs,
    /// which would fail if the GPU has been physically removed.
    fn restore_with_cached_id(&self) {
        if let Some(ref id_str) = self.vfio_id {
            deregister_vfio_id_by_value(&self.sysfs, id_str);
        }

        for peer in &self.companion_bdfs {
            if let Err(err) = restore_gpu_to_host_driver(&self.sysfs, peer) {
                tracing::error!(bdf = %peer, error = %err, "failed to restore companion device to host driver");
            }
        }

        if let Err(err) =
            restore_gpu_to_host_driver_ex(&self.sysfs, &self.bdf, self.vfio_id.is_some())
        {
            tracing::error!(bdf = %self.bdf, error = %err, "failed to restore GPU to host driver");
        }
    }
}

impl Drop for GpuBindGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        if self.vfio_id.is_some() {
            self.restore_with_cached_id();
        } else {
            for peer in &self.companion_bdfs {
                if let Err(err) = restore_gpu_to_host_driver(&self.sysfs, peer) {
                    tracing::error!(bdf = %peer, error = %err, "failed to restore companion device to host driver on drop");
                }
            }
            if let Err(err) = restore_gpu_to_host_driver(&self.sysfs, &self.bdf) {
                tracing::error!(bdf = %self.bdf, error = %err, "failed to restore GPU to host driver on drop");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GpuBindState (crash-recovery persistence)
// ---------------------------------------------------------------------------

/// Persisted record of GPUs currently bound to vfio-pci, for crash recovery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpuBindState {
    pub bindings: Vec<GpuBinding>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpuBinding {
    pub bdf: String,
    pub sandbox_id: String,
    pub bound_at_ms: i64,
}

impl GpuBindState {
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, path)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a PCI BDF address (format `DDDD:BB:DD.F`).
pub fn validate_bdf(bdf: &str) -> Result<(), VfioError> {
    let bytes = bdf.as_bytes();
    if bytes.len() != 12 {
        return Err(VfioError::InvalidBdf {
            bdf: bdf.to_string(),
        });
    }

    // Expected layout: [hex×4]:[hex×2]:[hex×2].[hex×1]
    //                   0123  4 56  7 89  A B
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

// ---------------------------------------------------------------------------
// Sysfs helpers
// ---------------------------------------------------------------------------

fn read_sysfs_trimmed(path: &Path) -> Result<String, VfioError> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|source| VfioError::SysfsIo {
            path: path.display().to_string(),
            source,
        })
}

fn write_sysfs(path: &Path, value: &str) -> Result<(), VfioError> {
    fs::write(path, value).map_err(|source| VfioError::SysfsIo {
        path: path.display().to_string(),
        source,
    })
}

fn current_driver_name(sysfs: &SysfsRoot, bdf: &str) -> Option<String> {
    let driver_link = sysfs.pci_device(bdf).join("driver");
    fs::read_link(&driver_link)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

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

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Scan sysfs for NVIDIA GPUs eligible for VFIO passthrough.
pub fn probe_host_nvidia_vfio_readiness(sysfs: &SysfsRoot) -> Vec<GpuInfo> {
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
        let dev_dir = sysfs.pci_device(&bdf);

        let Ok(vendor) = read_sysfs_trimmed(&dev_dir.join("vendor")) else {
            continue;
        };
        if vendor != NVIDIA_VENDOR_ID {
            continue;
        }

        let Ok(class) = read_sysfs_trimmed(&dev_dir.join("class")) else {
            continue;
        };
        if !is_gpu_class(&class) {
            continue;
        }

        let device = read_sysfs_trimmed(&dev_dir.join("device")).unwrap_or_default();

        let name = read_sysfs_trimmed(&dev_dir.join("label"))
            .unwrap_or_else(|_| format!("NVIDIA {device}"));

        let Ok(iommu_group) = sysfs.iommu_group(&bdf) else {
            continue;
        };

        gpus.push(GpuInfo {
            bdf,
            name,
            vendor,
            device,
            iommu_group,
        });
    }

    gpus
}

// ---------------------------------------------------------------------------
// Bind / unbind
// ---------------------------------------------------------------------------

/// Read vendor and device IDs from sysfs and format as `"VVVV DDDD"` (no `0x` prefix).
fn vfio_id_string(sysfs: &SysfsRoot, bdf: &str) -> Option<String> {
    let dev_dir = sysfs.pci_device(bdf);
    let vendor = read_sysfs_trimmed(&dev_dir.join("vendor")).ok()?;
    let device = read_sysfs_trimmed(&dev_dir.join("device")).ok()?;
    let vendor_hex = vendor.strip_prefix("0x").unwrap_or(&vendor);
    let device_hex = device.strip_prefix("0x").unwrap_or(&device);
    Some(format!("{vendor_hex} {device_hex}"))
}

/// Best-effort registration of a device's vendor:device ID with `vfio-pci`.
///
/// Some kernel configurations require the ID to be pre-registered in
/// `/sys/bus/pci/drivers/vfio-pci/new_id` before `drivers_probe` will
/// bind the device, even when `driver_override` is set. Writing an
/// already-registered ID returns `EEXIST`, which we silently ignore.
fn register_vfio_new_id(sysfs: &SysfsRoot, bdf: &str) {
    let Some(id_str) = vfio_id_string(sysfs, bdf) else {
        return;
    };

    let should_write = {
        let mut map = VFIO_ID_REFCOUNTS.lock().unwrap();
        let count = map.entry(id_str.clone()).or_insert(0);
        *count += 1;
        *count == 1
    };

    if !should_write {
        tracing::debug!(
            bdf, id = %id_str,
            "vfio-pci new_id already registered by another GPU, refcount incremented"
        );
        return;
    }

    let new_id_path = sysfs.vfio_pci_new_id();
    match write_sysfs(&new_id_path, &id_str) {
        Ok(()) => {
            tracing::debug!(bdf, id = %id_str, "registered vfio-pci new_id");
        }
        Err(_) => {
            tracing::debug!(
                bdf, id = %id_str,
                "vfio-pci new_id write skipped (already registered or driver not loaded)"
            );
        }
    }
}

/// Best-effort deregistration of a device's vendor:device ID from `vfio-pci`.
///
/// Reverses the effect of [`register_vfio_new_id`] by writing to
/// `/sys/bus/pci/drivers/vfio-pci/remove_id`. This prevents vfio-pci
/// from winning the probe race against the host driver when
/// `drivers_probe` runs during restore.
///
/// `ENODEV` is silently ignored (the ID may never have been registered
/// or was already removed).
fn deregister_vfio_new_id(sysfs: &SysfsRoot, bdf: &str) {
    let Some(id_str) = vfio_id_string(sysfs, bdf) else {
        return;
    };

    let should_write = {
        let mut map = VFIO_ID_REFCOUNTS.lock().unwrap();
        match map.get_mut(&id_str) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => {
                map.remove(&id_str);
                true
            }
            None => true,
        }
    };

    if !should_write {
        tracing::debug!(
            bdf, id = %id_str,
            "vfio-pci remove_id skipped (other GPUs still using this ID)"
        );
        return;
    }

    let remove_id_path = sysfs.vfio_pci_remove_id();
    match write_sysfs(&remove_id_path, &id_str) {
        Ok(()) => {
            tracing::debug!(bdf, id = %id_str, "deregistered vfio-pci new_id");
        }
        Err(_) => {
            tracing::debug!(
                bdf, id = %id_str,
                "vfio-pci remove_id write skipped (not registered or already removed)"
            );
        }
    }
}

/// Best-effort deregistration using a pre-captured ID string.
///
/// Unlike [`deregister_vfio_new_id`], this does not read vendor/device
/// from sysfs at call time, making it reliable even when the device has
/// been physically removed or sysfs is otherwise inaccessible.
fn deregister_vfio_id_by_value(sysfs: &SysfsRoot, id_str: &str) {
    let remove_id_path = sysfs.vfio_pci_remove_id();
    match write_sysfs(&remove_id_path, id_str) {
        Ok(()) => {
            tracing::debug!(id = %id_str, "deregistered vfio-pci new_id (by cached value)");
        }
        Err(_) => {
            tracing::debug!(
                id = %id_str,
                "vfio-pci remove_id write skipped (not registered or already removed)"
            );
        }
    }
}

/// Bind a single PCI device to `vfio-pci`. Skips devices already bound.
fn bind_device_to_vfio(sysfs: &SysfsRoot, bdf: &str) -> Result<bool, VfioError> {
    if let Some(drv) = current_driver_name(sysfs, bdf) {
        if drv == "vfio-pci" {
            return Ok(false);
        }
        let unbind_path = sysfs.pci_device(bdf).join("driver/unbind");
        write_sysfs(&unbind_path, bdf).map_err(|e| VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("unbind from {drv}: {e}"),
        })?;
        tracing::info!(bdf, driver = %drv, "unbound device from current driver");
    }

    register_vfio_new_id(sysfs, bdf);

    let override_path = sysfs.pci_device(bdf).join("driver_override");
    if let Err(e) = write_sysfs(&override_path, "vfio-pci") {
        deregister_vfio_new_id(sysfs, bdf);
        return Err(VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("driver_override: {e}"),
        });
    }

    if let Err(e) = write_sysfs(&sysfs.drivers_probe(), bdf) {
        deregister_vfio_new_id(sysfs, bdf);
        return Err(VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("drivers_probe: {e}"),
        });
    }

    if matches!(current_driver_name(sysfs, bdf).as_deref(), Some("vfio-pci")) {
        return Ok(true);
    }

    // The kernel processes drivers_probe asynchronously on some systems;
    // poll briefly to let the driver attach before declaring failure.
    for _ in 0..VFIO_BIND_MAX_POLL_ATTEMPTS {
        std::thread::sleep(VFIO_BIND_POLL_INTERVAL);
        if matches!(current_driver_name(sysfs, bdf).as_deref(), Some("vfio-pci")) {
            tracing::debug!(bdf, "vfio-pci binding confirmed after polling");
            return Ok(true);
        }
    }

    deregister_vfio_new_id(sysfs, bdf);
    Err(VfioError::BindFailed {
        bdf: bdf.to_string(),
        reason: format!(
            "after drivers_probe with {}ms polling, driver is {:?} instead of vfio-pci",
            VFIO_BIND_MAX_POLL_ATTEMPTS as u64 * VFIO_BIND_POLL_INTERVAL.as_millis() as u64,
            current_driver_name(sysfs, bdf)
                .as_deref()
                .unwrap_or("<none>")
        ),
    })
}

/// Bind a GPU to `vfio-pci`, returning an RAII guard that restores it on drop.
///
/// Also binds all companion devices in the same IOMMU group (e.g. the
/// HD Audio function on consumer GPUs). All bound companions are tracked
/// and restored when the guard is dropped.
pub fn prepare_gpu_for_passthrough(
    sysfs: &SysfsRoot,
    bdf: &str,
) -> Result<GpuBindGuard, VfioError> {
    validate_bdf(bdf)?;

    let dev_dir = sysfs.pci_device(bdf);
    if !dev_dir.exists() {
        return Err(VfioError::GpuNotFound {
            bdf: bdf.to_string(),
        });
    }

    let vendor = read_sysfs_trimmed(&dev_dir.join("vendor"))?;
    if vendor != NVIDIA_VENDOR_ID {
        return Err(VfioError::NotNvidia {
            bdf: bdf.to_string(),
            vendor,
        });
    }

    let iommu_group = sysfs.iommu_group(bdf)?;
    let group_devices = sysfs.iommu_group_devices(iommu_group)?;
    let peers: Vec<String> = group_devices.into_iter().filter(|d| d != bdf).collect();

    let mut bound_companions = Vec::new();
    for peer in &peers {
        if !sysfs.pci_device(peer).exists() {
            continue;
        }
        match bind_device_to_vfio(sysfs, peer) {
            Ok(was_bound) => {
                if was_bound {
                    tracing::info!(bdf = %peer, iommu_group, "bound IOMMU group companion to vfio-pci");
                    bound_companions.push(peer.clone());
                }
            }
            Err(err) => {
                for already_bound in bound_companions.iter().rev() {
                    if let Err(restore_err) = restore_gpu_to_host_driver(sysfs, already_bound) {
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

    match bind_device_to_vfio(sysfs, bdf) {
        Ok(was_bound) => {
            if was_bound {
                tracing::info!(bdf, "GPU bound to vfio-pci");
            } else {
                tracing::info!(bdf, "GPU already bound to vfio-pci");
            }
        }
        Err(err) => {
            for companion in bound_companions.iter().rev() {
                if let Err(restore_err) = restore_gpu_to_host_driver(sysfs, companion) {
                    tracing::error!(bdf = %companion, error = %restore_err, "failed to restore companion during rollback");
                }
            }
            return Err(err);
        }
    }

    let vfio_id = vfio_id_string(sysfs, bdf);

    Ok(GpuBindGuard {
        bdf: bdf.to_string(),
        companion_bdfs: bound_companions,
        sysfs: sysfs.clone(),
        disarmed: false,
        vfio_id,
    })
}

/// Restore a GPU from `vfio-pci` back to the host's default driver.
fn restore_gpu_to_host_driver(sysfs: &SysfsRoot, bdf: &str) -> Result<(), VfioError> {
    restore_gpu_to_host_driver_ex(sysfs, bdf, false)
}

/// Inner restore implementation.
///
/// When `skip_deregister` is `true` the caller has already removed the
/// device's vendor:device ID from vfio-pci's match table (e.g. via a
/// cached value), so we skip the sysfs-based deregistration.
fn restore_gpu_to_host_driver_ex(
    sysfs: &SysfsRoot,
    bdf: &str,
    skip_deregister: bool,
) -> Result<(), VfioError> {
    let dev_dir = sysfs.pci_device(bdf);

    if !skip_deregister {
        // Deregister the device ID from vfio-pci's match table before
        // unbind+reprobe. Without this, drivers_probe re-binds to vfio-pci
        // via the still-registered new_id entry.
        deregister_vfio_new_id(sysfs, bdf);
    }

    let unbind_path = dev_dir.join("driver/unbind");
    if unbind_path.exists() {
        write_sysfs(&unbind_path, bdf).map_err(|e| VfioError::UnbindFailed {
            bdf: bdf.to_string(),
            reason: format!("unbind: {e}"),
        })?;
    }

    let override_path = dev_dir.join("driver_override");
    if override_path.exists() {
        write_sysfs(&override_path, "\n").map_err(|e| VfioError::UnbindFailed {
            bdf: bdf.to_string(),
            reason: format!("clear driver_override: {e}"),
        })?;
    }

    let probe = sysfs.drivers_probe();
    if probe.exists() {
        write_sysfs(&probe, bdf).map_err(|e| VfioError::UnbindFailed {
            bdf: bdf.to_string(),
            reason: format!("drivers_probe: {e}"),
        })?;
    }

    tracing::info!(bdf, "GPU restored to host driver");
    Ok(())
}

// ---------------------------------------------------------------------------
// Crash-recovery reconciliation
// ---------------------------------------------------------------------------

/// Reconcile stale VFIO bindings left over from a previous crash.
///
/// Loads persisted state, checks each GPU, and restores any that are still
/// bound to `vfio-pci`. Returns the list of BDFs that were restored.
/// Removes the state file only when all bindings are resolved; rewrites it
/// with the remaining entries when some restorations fail so they can be
/// retried on the next process start.
pub fn reconcile_stale_bindings(sysfs: &SysfsRoot, state_path: &Path) -> Vec<String> {
    let state = match GpuBindState::load(state_path) {
        Ok(s) => s,
        Err(err) => {
            tracing::debug!(%err, path = %state_path.display(), "no stale GPU bind state to reconcile");
            return Vec::new();
        }
    };

    // Any in-memory refcounts are stale (from a previous process that
    // crashed). Clear them so deregister writes through to sysfs.
    if let Ok(mut map) = VFIO_ID_REFCOUNTS.lock() {
        map.clear();
    }

    let mut restored = Vec::new();
    let mut failed_bindings = Vec::new();

    for binding in &state.bindings {
        match current_driver_name(sysfs, &binding.bdf) {
            Some(ref drv) if drv == "vfio-pci" => {
                tracing::warn!(
                    bdf = %binding.bdf,
                    sandbox_id = %binding.sandbox_id,
                    "stale VFIO binding detected, restoring GPU to host driver"
                );
                if let Err(err) = restore_gpu_to_host_driver(sysfs, &binding.bdf) {
                    tracing::error!(bdf = %binding.bdf, %err, "failed to restore stale GPU binding");
                    failed_bindings.push(binding.clone());
                    continue;
                }
                restored.push(binding.bdf.clone());
            }
            _ => {
                let override_path = sysfs.pci_device(&binding.bdf).join("driver_override");
                if let Ok(val) = read_sysfs_trimmed(&override_path)
                    && val == "vfio-pci"
                {
                    tracing::warn!(
                        bdf = %binding.bdf,
                        sandbox_id = %binding.sandbox_id,
                        "stale driver_override detected, clearing and re-probing"
                    );
                    deregister_vfio_new_id(sysfs, &binding.bdf);
                    if let Err(err) = write_sysfs(&override_path, "\n") {
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
                    tracing::debug!(bdf = %binding.bdf, "GPU no longer bound to vfio-pci, skipping");
                }
            }
        }
    }

    if failed_bindings.is_empty() {
        if let Err(err) = fs::remove_file(state_path) {
            tracing::warn!(%err, path = %state_path.display(), "failed to remove stale bind state file");
        }
    } else {
        let remaining = GpuBindState {
            bindings: failed_bindings,
        };
        match serde_json::to_string_pretty(&remaining) {
            Ok(json) => {
                if let Err(err) = fs::write(state_path, json) {
                    tracing::error!(%err, path = %state_path.display(), "failed to persist remaining stale bindings");
                } else {
                    tracing::warn!(
                        count = remaining.bindings.len(),
                        "some GPU bindings could not be restored; state preserved for retry"
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn setup_mock_sysfs() -> (TempDir, SysfsRoot) {
        let tmp = TempDir::new().unwrap();
        let sysfs = SysfsRoot::new(tmp.path());
        (tmp, sysfs)
    }

    fn create_pci_device(
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

    /// Remove a specific vendor:device key from the global refcount map.
    /// Used by tests to clean up their own entries without disturbing
    /// parallel tests that hold refcounts for different device IDs.
    fn clear_vfio_id_refcount(id: &str) {
        VFIO_ID_REFCOUNTS.lock().unwrap().remove(id);
    }

    // -- validate_bdf -------------------------------------------------------

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
        assert!(validate_bdf("0000:2d:00").is_err()); // too short
        assert!(validate_bdf("0000:2d:00.00").is_err()); // too long
        assert!(validate_bdf("000g:2d:00.0").is_err()); // non-hex
        assert!(validate_bdf("0000-2d-00.0").is_err()); // wrong separators
        assert!(validate_bdf("0000:2d:00:0").is_err()); // colon instead of dot
    }

    #[test]
    fn test_validate_bdf_rejects_metacharacters() {
        assert!(validate_bdf("$(rm -rf /)").is_err());
        assert!(validate_bdf("; echo pwned").is_err());
        assert!(validate_bdf("0000:2d;00.0").is_err());
        assert!(validate_bdf("0000:2d:0`.0").is_err());
        assert!(validate_bdf("../../../../").is_err());
    }

    // -- validate_sysfs_data ------------------------------------------------

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

    // -- probe_host_nvidia_vfio_readiness -----------------------------------

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
        // Audio device class 0x040300
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

    // -- GpuBindState -------------------------------------------------------

    #[test]
    fn test_gpu_bind_state_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("gpu-state.json");

        let state = GpuBindState {
            bindings: vec![
                GpuBinding {
                    bdf: "0000:2d:00.0".to_string(),
                    sandbox_id: "sandbox-123".to_string(),
                    bound_at_ms: 1_700_000_000_000,
                },
                GpuBinding {
                    bdf: "0000:3b:00.0".to_string(),
                    sandbox_id: "sandbox-456".to_string(),
                    bound_at_ms: 1_700_000_001_000,
                },
            ],
        };

        state.save(&path).unwrap();
        let loaded = GpuBindState::load(&path).unwrap();

        assert_eq!(loaded.bindings.len(), 2);
        assert_eq!(loaded.bindings[0].bdf, "0000:2d:00.0");
        assert_eq!(loaded.bindings[0].sandbox_id, "sandbox-123");
        assert_eq!(loaded.bindings[1].bdf, "0000:3b:00.0");
    }

    // -- SysfsRoot ----------------------------------------------------------

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

    // -- is_gpu_class -------------------------------------------------------

    #[test]
    fn test_is_gpu_class() {
        assert!(is_gpu_class("0x030000"));
        assert!(is_gpu_class("0x030200"));
        assert!(is_gpu_class("0x030201"));
        assert!(!is_gpu_class("0x040300"));
        assert!(!is_gpu_class("0x060000"));
        assert!(!is_gpu_class(""));
    }

    // -- iommu_group_devices ------------------------------------------------

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

    // -- register_vfio_new_id -----------------------------------------------

    #[test]
    fn test_register_vfio_new_id_writes_vendor_device() {
        clear_vfio_id_refcount("10de 26b3");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b3",
            "0x030000",
            42,
        );

        let new_id_path = sysfs.vfio_pci_new_id();
        fs::create_dir_all(new_id_path.parent().unwrap()).unwrap();
        fs::write(&new_id_path, "").unwrap();

        register_vfio_new_id(&sysfs, "0000:2d:00.0");

        let written = fs::read_to_string(&new_id_path).unwrap();
        assert_eq!(written, "10de 26b3");
    }

    #[test]
    fn test_register_vfio_new_id_ignores_missing_new_id_file() {
        clear_vfio_id_refcount("10de 26b4");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b4",
            "0x030000",
            42,
        );

        // Don't create the new_id file — should not panic or error
        register_vfio_new_id(&sysfs, "0000:2d:00.0");
    }

    // -- deregister_vfio_new_id ---------------------------------------------

    #[test]
    fn test_deregister_vfio_new_id_writes_vendor_device() {
        clear_vfio_id_refcount("10de 26b5");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b5",
            "0x030000",
            42,
        );

        let remove_id_path = sysfs.vfio_pci_remove_id();
        fs::create_dir_all(remove_id_path.parent().unwrap()).unwrap();
        fs::write(&remove_id_path, "").unwrap();

        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");

        let written = fs::read_to_string(&remove_id_path).unwrap();
        assert_eq!(written, "10de 26b5");
    }

    #[test]
    fn test_deregister_vfio_new_id_ignores_missing_remove_id_file() {
        clear_vfio_id_refcount("10de 26b6");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b6",
            "0x030000",
            42,
        );

        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");
    }

    // -- refcount safety ----------------------------------------------------

    #[test]
    fn test_register_deregister_refcount() {
        clear_vfio_id_refcount("10de 26b8");
        let (tmp, sysfs) = setup_mock_sysfs();

        // Two GPUs with the same vendor:device ID (e.g., two A100s).
        // Uses 0x26b8 — unique to this test to avoid parallel interference.
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b8",
            "0x030000",
            42,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:3b:00.0",
            "0x10de",
            "0x26b8",
            "0x030200",
            43,
        );

        let new_id_path = sysfs.vfio_pci_new_id();
        fs::create_dir_all(new_id_path.parent().unwrap()).unwrap();
        fs::write(&new_id_path, "").unwrap();

        let remove_id_path = sysfs.vfio_pci_remove_id();
        fs::write(&remove_id_path, "").unwrap();

        // Register the same vendor:device for two different BDFs
        register_vfio_new_id(&sysfs, "0000:2d:00.0");
        let written = fs::read_to_string(&new_id_path).unwrap();
        assert_eq!(
            written, "10de 26b8",
            "first register should write to new_id"
        );

        // Clear the file to detect whether the second register writes
        fs::write(&new_id_path, "").unwrap();
        register_vfio_new_id(&sysfs, "0000:3b:00.0");
        let written = fs::read_to_string(&new_id_path).unwrap();
        assert_eq!(
            written, "",
            "second register should NOT write to new_id (refcount > 1)"
        );

        // Deregister once — should NOT write to remove_id (one GPU still using it)
        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");
        let written = fs::read_to_string(&remove_id_path).unwrap();
        assert_eq!(
            written, "",
            "first deregister should NOT write to remove_id"
        );

        // Deregister again — should write to remove_id (last user)
        deregister_vfio_new_id(&sysfs, "0000:3b:00.0");
        let written = fs::read_to_string(&remove_id_path).unwrap();
        assert_eq!(
            written, "10de 26b8",
            "second deregister SHOULD write to remove_id"
        );
    }

    // -- companion binding --------------------------------------------------

    /// Helper to create a fake driver symlink for a mock PCI device.
    fn set_mock_driver(sysfs: &SysfsRoot, bdf: &str, driver_name: &str) {
        let driver_dir = sysfs.base.join(format!("bus/pci/drivers/{driver_name}"));
        fs::create_dir_all(&driver_dir).unwrap();
        let dev_driver_link = sysfs.pci_device(bdf).join("driver");
        let _ = fs::remove_file(&dev_driver_link);
        symlink(&driver_dir, &dev_driver_link).unwrap();
    }

    #[test]
    fn test_prepare_gpu_skips_already_bound_companions() {
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

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        // Both devices already on vfio-pci
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");
        set_mock_driver(&sysfs, "0000:2d:00.1", "vfio-pci");

        let guard = prepare_gpu_for_passthrough(&sysfs, "0000:2d:00.0").unwrap();

        // Both were already bound, no companions should be tracked for restore
        assert!(guard.companion_bdfs.is_empty());
        assert_eq!(guard.bdf, "0000:2d:00.0");
    }

    #[test]
    fn test_prepare_gpu_solo_iommu_group_no_companions() {
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

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        // GPU already on vfio-pci
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");

        let guard = prepare_gpu_for_passthrough(&sysfs, "0000:2d:00.0").unwrap();
        assert!(guard.companion_bdfs.is_empty());
    }

    #[test]
    fn test_bind_device_to_vfio_already_bound() {
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

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");

        let was_bound = bind_device_to_vfio(&sysfs, "0000:2d:00.0").unwrap();
        assert!(!was_bound, "should report false when already on vfio-pci");
    }

    #[test]
    fn test_guard_drop_restores_companions() {
        clear_vfio_id_refcount("10de 2684");
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

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        // Simulate bound state: driver link and driver_override both set
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");
        set_mock_driver(&sysfs, "0000:2d:00.1", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();
        fs::write(
            sysfs.pci_device("0000:2d:00.1").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        {
            let _guard = GpuBindGuard {
                bdf: "0000:2d:00.0".to_string(),
                companion_bdfs: vec!["0000:2d:00.1".to_string()],
                sysfs: sysfs.clone(),
                disarmed: false,
                vfio_id: None,
            };
            // guard drops here — should attempt restore on both devices
        }

        // After drop, driver_override should be cleared (written with "\n")
        let gpu_override =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(
            gpu_override.trim(),
            "",
            "GPU driver_override should be cleared after drop"
        );

        let companion_override =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.1").join("driver_override")).unwrap();
        assert_eq!(
            companion_override.trim(),
            "",
            "companion driver_override should be cleared after drop"
        );
    }

    #[test]
    fn test_guard_disarm_skips_restore() {
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

        // Write a non-empty driver_override to verify it's NOT cleared
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let guard = GpuBindGuard {
            bdf: "0000:2d:00.0".to_string(),
            companion_bdfs: vec![],
            sysfs: sysfs.clone(),
            disarmed: false,
            vfio_id: None,
        };
        guard.disarm();

        // driver_override should still be vfio-pci (not cleared by disarmed guard)
        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(override_val, "vfio-pci");
    }

    // -- restore writes remove_id -------------------------------------------

    #[test]
    fn test_restore_gpu_deregisters_new_id_before_reprobe() {
        clear_vfio_id_refcount("10de 26b7");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b7",
            "0x030000",
            42,
        );

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        let remove_id_path = sysfs.vfio_pci_remove_id();
        fs::create_dir_all(remove_id_path.parent().unwrap()).unwrap();
        fs::write(&remove_id_path, "").unwrap();

        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        restore_gpu_to_host_driver(&sysfs, "0000:2d:00.0").unwrap();

        let written = fs::read_to_string(&remove_id_path).unwrap();
        assert_eq!(
            written, "10de 26b7",
            "remove_id should be written during restore"
        );
    }

    // -- reconcile_stale_bindings -------------------------------------------

    #[test]
    fn test_reconcile_clears_stale_driver_override_when_not_on_vfio() {
        clear_vfio_id_refcount("10de 2684");
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

        let probe = sysfs.drivers_probe();
        fs::create_dir_all(probe.parent().unwrap()).unwrap();
        fs::write(&probe, "").unwrap();

        set_mock_driver(&sysfs, "0000:2d:00.0", "nvidia");
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let state_path = tmp.path().join("gpu-state.json");
        let state = GpuBindState {
            bindings: vec![GpuBinding {
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
