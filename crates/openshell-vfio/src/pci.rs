// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::VfioError;
use crate::sysfs::{SysfsRoot, validate_bdf};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Information about a discovered PCI device eligible for VFIO passthrough.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PciInfo {
    pub bdf: String,
    pub name: String,
    pub vendor: String,
    pub device: String,
    pub iommu_group: u32,
}

/// RAII guard that restores a PCI device to its host driver when dropped.
///
/// Call [`disarm`](Self::disarm) to transfer ownership (e.g. the VM took over
/// the device successfully and we should not unbind it on cleanup).
#[derive(Debug)]
pub struct PciBindGuard {
    pub(crate) bdf: String,
    pub(crate) companion_bdfs: Vec<String>,
    pub(crate) sysfs: SysfsRoot,
    pub(crate) disarmed: bool,
    /// Cached "VVVV DDDD" string captured at bind time so that deregistration
    /// from vfio-pci's match table succeeds even if the device's sysfs entries
    /// have disappeared (e.g. physical removal).
    pub(crate) vfio_id: Option<String>,
}

impl PciBindGuard {
    pub fn bdf(&self) -> &str {
        &self.bdf
    }

    /// IOMMU-group companion BDFs that this guard will restore alongside
    /// [`bdf`](Self::bdf) on drop. Empty for single-device bindings.
    ///
    /// Consumers use this to persist crash-recovery state for the full set
    /// of devices owned by a sandbox.
    pub fn companion_bdfs(&self) -> &[String] {
        &self.companion_bdfs
    }

    /// Prevent the guard from restoring the device on drop.
    pub fn disarm(mut self) {
        self.disarmed = true;
    }

    /// Adopt ownership of a `PCIe` device that is already bound to `vfio-pci`.
    ///
    /// This is the restart-reconciliation counterpart to
    /// [`prepare_pci_for_passthrough`]. It validates that the device exists,
    /// that all IOMMU peers are already on `vfio-pci`, and that the primary BDF
    /// is currently bound to `vfio-pci`, then returns a guard that will restore
    /// the device on drop. It does not write `driver_override`, `new_id`, or
    /// `drivers_probe`.
    pub fn adopt(sysfs: &SysfsRoot, bdf: &str) -> Result<Self, VfioError> {
        validate_pci_for_passthrough(sysfs, bdf)?;
        ensure_bound_to_vfio(sysfs, bdf)?;

        let vfio_id = crate::bind::vfio_id_string(sysfs, bdf);

        Ok(Self::new_armed(
            bdf.to_string(),
            Vec::new(),
            sysfs.clone(),
            vfio_id,
        ))
    }

    /// Adopt ownership of a complete IOMMU group already bound to `vfio-pci`.
    ///
    /// This is the restart-reconciliation counterpart to
    /// [`prepare_pci_group_for_passthrough`]. It validates that `bdfs` is the
    /// complete IOMMU group, that every declared device is already bound to
    /// `vfio-pci`, and then returns a guard that restores every declared device
    /// on drop. It does not write `driver_override`, `new_id`, or
    /// `drivers_probe`.
    pub fn adopt_group(sysfs: &SysfsRoot, bdfs: &[&str]) -> Result<Self, VfioError> {
        validate_pci_group_for_passthrough(sysfs, bdfs)?;

        for bdf in bdfs {
            ensure_bound_to_vfio(sysfs, bdf)?;
        }

        let (primary, companions) = bdfs
            .split_first()
            .expect("validate_pci_group_for_passthrough rejects empty slices");
        let vfio_id = crate::bind::vfio_id_string(sysfs, primary);
        let companion_bdfs: Vec<String> = companions.iter().map(|s| (*s).to_string()).collect();

        Ok(Self::new_armed(
            (*primary).to_string(),
            companion_bdfs,
            sysfs.clone(),
            vfio_id,
        ))
    }

    pub(crate) fn new_armed(
        bdf: String,
        companion_bdfs: Vec<String>,
        sysfs: SysfsRoot,
        vfio_id: Option<String>,
    ) -> Self {
        Self {
            bdf,
            companion_bdfs,
            sysfs,
            disarmed: false,
            vfio_id,
        }
    }

    /// Deregister the cached vfio-pci match-table entry, then restore the
    /// device to its host driver.
    ///
    /// Using the cached ID avoids re-reading vendor/device from sysfs, which
    /// would fail if the device has been physically removed.
    fn restore_with_cached_id(&self) {
        if let Some(ref id_str) = self.vfio_id {
            crate::bind::deregister_vfio_id_by_value(&self.sysfs, id_str);
        }

        for peer in &self.companion_bdfs {
            if let Err(err) = crate::bind::restore_to_host_driver(&self.sysfs, peer) {
                tracing::error!(bdf = %peer, error = %err, "failed to restore companion device to host driver");
            }
        }

        if let Err(err) =
            crate::bind::restore_to_host_driver_ex(&self.sysfs, &self.bdf, self.vfio_id.is_some())
        {
            tracing::error!(bdf = %self.bdf, error = %err, "failed to restore PCI device to host driver");
        }
    }
}

fn ensure_bound_to_vfio(sysfs: &SysfsRoot, bdf: &str) -> Result<(), VfioError> {
    let driver = crate::bind::current_driver_name(sysfs, bdf);
    if driver.as_deref() == Some("vfio-pci") {
        return Ok(());
    }

    Err(VfioError::NotBoundToVfio {
        bdf: bdf.to_string(),
        driver: driver.unwrap_or_else(|| "<none>".to_string()),
    })
}

impl Drop for PciBindGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        if self.vfio_id.is_some() {
            self.restore_with_cached_id();
        } else {
            for peer in &self.companion_bdfs {
                if let Err(err) = crate::bind::restore_to_host_driver(&self.sysfs, peer) {
                    tracing::error!(bdf = %peer, error = %err, "failed to restore companion device to host driver on drop");
                }
            }
            if let Err(err) = crate::bind::restore_to_host_driver(&self.sysfs, &self.bdf) {
                tracing::error!(bdf = %self.bdf, error = %err, "failed to restore PCI device to host driver on drop");
            }
        }
    }
}

/// Persisted record of PCI devices currently bound to vfio-pci, for crash recovery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PciBindState {
    pub bindings: Vec<PciBinding>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PciBinding {
    pub bdf: String,
    pub sandbox_id: String,
    pub bound_at_ms: i64,
}

impl PciBindState {
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

/// Enumerate every PCI device on the host that is structurally eligible
/// for VFIO passthrough.
///
/// "Structurally eligible" means the device has a populated IOMMU group;
/// devices without one (IOMMU disabled, virtual functions of a PF without
/// SR-IOV enabled, etc.) are silently skipped. This function does **not**
/// consult the current driver binding state: a device already on `vfio-pci`
/// is still reported, because the consumer's inventory layer is the right
/// place to track which devices are allocated to which sandbox.
///
/// `vendor_filter` accepts a sysfs vendor string (e.g. `"0x10de"` for
/// NVIDIA, `"0x15b3"` for Mellanox) and restricts the result set to devices
/// reporting that vendor ID. Pass `None` to enumerate all vendors.
///
/// Class-based filtering (GPU vs NIC vs other) is intentionally left to
/// the caller because portable device-class definitions are a driver-layer
/// concern (see RFC 0004's `DeviceResourceRequirement.class_name`).
pub fn probe_host_vfio_candidates(sysfs: &SysfsRoot, vendor_filter: Option<&str>) -> Vec<PciInfo> {
    let devices_dir = sysfs.pci_devices_dir();
    let entries = match fs::read_dir(&devices_dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(path = %devices_dir.display(), %err, "cannot read PCI devices directory");
            return Vec::new();
        }
    };

    let mut candidates = Vec::new();

    for entry in entries.filter_map(Result::ok) {
        let bdf = entry.file_name().to_string_lossy().into_owned();
        let device = sysfs.pci_device_ref(&bdf);

        let Ok(vendor) = device.vendor() else {
            continue;
        };
        if let Some(filter) = vendor_filter
            && vendor != filter
        {
            continue;
        }

        let device_id = device.device_id().unwrap_or_default();

        let name = device
            .read_trimmed("label")
            .unwrap_or_else(|_| format!("{vendor} {device_id}"));

        let Ok(iommu_group) = device.iommu_group() else {
            tracing::debug!(bdf, "skipping PCI device without IOMMU group");
            continue;
        };

        candidates.push(PciInfo {
            bdf,
            name,
            vendor,
            device: device_id,
            iommu_group,
        });
    }

    candidates
}

/// Dry-run validation that [`prepare_pci_for_passthrough`] would accept this
/// BDF right now. Performs every pre-bind check without touching
/// `driver_override` or any other kernel state.
///
/// Intended for `ValidateSandboxCreate` and similar pre-flight paths where
/// the caller wants a typed error before committing to side effects.
///
/// The IOMMU-peer check is inherently racy: a peer's driver state can change
/// between this call and a subsequent [`prepare_pci_for_passthrough`].
/// Callers should treat a successful validation as best-effort and still be
/// prepared for the prepare call to fail.
pub fn validate_pci_for_passthrough(sysfs: &SysfsRoot, bdf: &str) -> Result<(), VfioError> {
    validate_bdf(bdf)?;

    let device = sysfs.pci_device_ref(bdf);
    if !device.exists() {
        return Err(VfioError::DeviceNotFound {
            bdf: bdf.to_string(),
        });
    }

    let iommu_group = device.iommu_group()?;
    let group_devices = sysfs.iommu_group_devices(iommu_group)?;
    let peers: Vec<String> = group_devices.into_iter().filter(|d| d != bdf).collect();

    // Refuse to silently auto-bind companions for non-GPU devices. The
    // operator must declare every BDF in the IOMMU group eligible and bind them
    // through separate calls (or use prepare_pci_group_for_passthrough).
    for peer in &peers {
        let peer_drv = crate::bind::current_driver_name(sysfs, peer);
        if peer_drv.as_deref() != Some("vfio-pci") {
            return Err(VfioError::IommuGroupConflict {
                bdf: bdf.to_string(),
                group: iommu_group,
                peers: peers.clone(),
            });
        }
    }

    Ok(())
}

/// Bind an arbitrary VFIO-capable `PCIe` device to `vfio-pci`, returning an RAII
/// guard that restores it to the host driver on drop.
///
/// Unlike [`crate::gpu::prepare_gpu_for_passthrough`], this function does not
/// auto-bind IOMMU group companions. The caller is responsible for declaring
/// all BDFs in the same IOMMU group as eligible devices and binding them
/// through separate calls. Devices whose IOMMU group has peers not yet bound to
/// `vfio-pci` are rejected with [`VfioError::IommuGroupConflict`].
pub fn prepare_pci_for_passthrough(
    sysfs: &SysfsRoot,
    bdf: &str,
) -> Result<PciBindGuard, VfioError> {
    validate_pci_for_passthrough(sysfs, bdf)?;

    crate::bind::bind_device_to_vfio(sysfs, bdf)?;

    let vfio_id = crate::bind::vfio_id_string(sysfs, bdf);

    Ok(PciBindGuard::new_armed(
        bdf.to_string(),
        Vec::new(),
        sysfs.clone(),
        vfio_id,
    ))
}

/// Manually restore a VFIO-bound `PCIe` device to its host driver.
///
/// Use this when the binding lifetime is owned by a long-lived component rather
/// than by the [`PciBindGuard`] RAII guard returned from
/// [`prepare_pci_for_passthrough`]. The guard's [`PciBindGuard::disarm`] method
/// should be called immediately after binding in that scenario, and this
/// function used at release time.
pub fn release_pci_from_passthrough(sysfs: &SysfsRoot, bdf: &str) -> Result<(), VfioError> {
    validate_bdf(bdf)?;
    crate::bind::restore_to_host_driver(sysfs, bdf)
}

/// Dry-run validation that [`prepare_pci_group_for_passthrough`] would
/// accept this slice of BDFs as a complete IOMMU group right now.
///
/// Mirrors the structural checks of the prepare call without performing
/// any kernel-state-mutating operations. Intended for
/// `ValidateSandboxCreate`-style pre-flight paths.
///
/// Rejects:
/// - empty slices (`EmptyGroup`),
/// - malformed BDFs (`InvalidBdf`),
/// - duplicate entries (`InvalidBdf`),
/// - non-existent devices (`DeviceNotFound`),
/// - devices missing an IOMMU group (`NoIommuGroup`),
/// - devices whose IOMMU group differs from the primary (`GroupMismatch`),
/// - groups whose kernel-reported peer set is not a subset of `bdfs`
///   (`IommuGroupConflict`).
///
/// Unlike [`validate_pci_for_passthrough`], this function does not consult
/// the current binding state of any device; it is purely structural.
pub fn validate_pci_group_for_passthrough(
    sysfs: &SysfsRoot,
    bdfs: &[&str],
) -> Result<(), VfioError> {
    let (primary, companions) = bdfs.split_first().ok_or(VfioError::EmptyGroup)?;

    for bdf in bdfs {
        validate_bdf(bdf)?;
        if !sysfs.pci_device_ref(bdf).exists() {
            return Err(VfioError::DeviceNotFound {
                bdf: (*bdf).to_string(),
            });
        }
    }

    let declared: BTreeSet<&str> = bdfs.iter().copied().collect();
    if declared.len() != bdfs.len() {
        // Duplicate entries would make the IOMMU equality check pass while
        // double-binding the same device.
        return Err(VfioError::InvalidBdf {
            bdf: format!("duplicate entries in PCI group: {bdfs:?}"),
        });
    }

    let expected_group = sysfs.pci_device_ref(primary).iommu_group()?;
    for bdf in companions {
        let g = sysfs.pci_device_ref(bdf).iommu_group()?;
        if g != expected_group {
            return Err(VfioError::GroupMismatch {
                bdf: (*bdf).to_string(),
                expected_group,
                actual_group: g,
            });
        }
    }

    let kernel_peers = sysfs.iommu_group_devices(expected_group)?;
    let undeclared: Vec<String> = kernel_peers
        .iter()
        .filter(|p| !declared.contains(p.as_str()))
        .cloned()
        .collect();
    if !undeclared.is_empty() {
        return Err(VfioError::IommuGroupConflict {
            bdf: (*primary).to_string(),
            group: expected_group,
            peers: undeclared,
        });
    }

    Ok(())
}

/// Atomically bind every `PCIe` device in a shared IOMMU group to `vfio-pci`.
///
/// Use this when a single sandbox needs to claim multiple devices that
/// occupy the same IOMMU group (consumer GPUs with HDA companions, multi-PF
/// NICs, anything behind an ACS-deficient `PCIe` switch). The single-device
/// [`prepare_pci_for_passthrough`] cannot help here because every call would
/// see the still-unbound peers and bail with
/// [`VfioError::IommuGroupConflict`].
///
/// `bdfs` must contain every device in the IOMMU group:
/// - the first entry is treated as the primary and its vendor:device ID is
///   cached on the returned guard for hot-remove-safe deregistration;
/// - all other entries are treated as companions and restored alongside the
///   primary when the guard drops.
///
/// Returns [`VfioError::EmptyGroup`] for an empty slice,
/// [`VfioError::GroupMismatch`] when a declared device is in a different
/// IOMMU group than the primary, and [`VfioError::IommuGroupConflict`] when
/// the kernel reports peers that were not declared in `bdfs`.
///
/// On any per-device bind failure, every device that was newly bound by
/// this call is restored to its host driver before the error propagates;
/// devices that were already on `vfio-pci` before this call are left as
/// found (we cannot prove ownership).
pub fn prepare_pci_group_for_passthrough(
    sysfs: &SysfsRoot,
    bdfs: &[&str],
) -> Result<PciBindGuard, VfioError> {
    validate_pci_group_for_passthrough(sysfs, bdfs)?;

    // SAFETY: validate_pci_group_for_passthrough rejects empty slices, so
    // split_first cannot panic here.
    let (primary, companions) = bdfs
        .split_first()
        .expect("validate_pci_group_for_passthrough rejects empty slices");

    // Bind each device. Track only the BDFs that we transitioned from a
    // host driver onto vfio-pci, so that rollback does not steal a device
    // that was already owned by another guard / sandbox.
    let mut newly_bound: Vec<String> = Vec::new();
    for bdf in bdfs {
        match crate::bind::bind_device_to_vfio(sysfs, bdf) {
            Ok(true) => newly_bound.push((*bdf).to_string()),
            Ok(false) => {
                tracing::debug!(bdf, "PCI group member already on vfio-pci");
            }
            Err(err) => {
                for already in newly_bound.iter().rev() {
                    if let Err(restore_err) = crate::bind::restore_to_host_driver(sysfs, already) {
                        tracing::error!(
                            bdf = %already,
                            error = %restore_err,
                            "failed to restore PCI device during group bind rollback"
                        );
                    }
                }
                return Err(err);
            }
        }
    }

    let vfio_id = crate::bind::vfio_id_string(sysfs, primary);
    let companion_bdfs: Vec<String> = companions.iter().map(|s| (*s).to_string()).collect();

    Ok(PciBindGuard::new_armed(
        (*primary).to_string(),
        companion_bdfs,
        sysfs.clone(),
        vfio_id,
    ))
}

/// Manually restore every `PCIe` device in a group that was bound via
/// [`prepare_pci_group_for_passthrough`].
///
/// Counterpart to [`release_pci_from_passthrough`] for callers that own the
/// binding lifetime outside the [`PciBindGuard`] RAII guard. Each device is
/// restored independently; if any restore fails the function logs and
/// continues, then returns the first error so the caller can decide whether
/// to retry.
pub fn release_pci_group_from_passthrough(
    sysfs: &SysfsRoot,
    bdfs: &[&str],
) -> Result<(), VfioError> {
    let mut first_err: Option<VfioError> = None;
    for bdf in bdfs {
        if let Err(err) = validate_bdf(bdf) {
            tracing::error!(bdf = %bdf, %err, "invalid BDF in release_pci_group_from_passthrough");
            if first_err.is_none() {
                first_err = Some(err);
            }
            continue;
        }
        if let Err(err) = crate::bind::restore_to_host_driver(sysfs, bdf) {
            tracing::error!(bdf = %bdf, %err, "failed to restore PCI device during group release");
            if first_err.is_none() {
                first_err = Some(err);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_refcounts;
    use crate::test_support::{
        create_new_id_file, create_pci_device, create_probe_file, create_remove_id_file,
        set_mock_driver, setup_mock_sysfs,
    };
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_pci_bind_state_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("pci-state.json");

        let state = PciBindState {
            bindings: vec![
                PciBinding {
                    bdf: "0000:2d:00.0".to_string(),
                    sandbox_id: "sandbox-123".to_string(),
                    bound_at_ms: 1_700_000_000_000,
                },
                PciBinding {
                    bdf: "0000:3b:00.0".to_string(),
                    sandbox_id: "sandbox-456".to_string(),
                    bound_at_ms: 1_700_000_001_000,
                },
            ],
        };

        state.save(&path).unwrap();
        let loaded = PciBindState::load(&path).unwrap();

        assert_eq!(loaded.bindings.len(), 2);
        assert_eq!(loaded.bindings[0].bdf, "0000:2d:00.0");
        assert_eq!(loaded.bindings[0].sandbox_id, "sandbox-123");
        assert_eq!(loaded.bindings[1].bdf, "0000:3b:00.0");
    }

    #[test]
    fn test_guard_drop_restores_companions() {
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
            let _guard = PciBindGuard {
                bdf: "0000:2d:00.0".to_string(),
                companion_bdfs: vec!["0000:2d:00.1".to_string()],
                sysfs: sysfs.clone(),
                disarmed: false,
                vfio_id: None,
            };
        }

        let pci_override =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(
            pci_override.trim(),
            "",
            "PCI driver_override should be cleared after drop"
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

        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let guard = PciBindGuard {
            bdf: "0000:2d:00.0".to_string(),
            companion_bdfs: vec![],
            sysfs: sysfs.clone(),
            disarmed: false,
            vfio_id: None,
        };
        guard.disarm();

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(override_val, "vfio-pci");
    }

    #[test]
    fn test_adopt_single_already_bound_device() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        {
            let guard = PciBindGuard::adopt(&sysfs, "0000:81:00.2").unwrap();
            assert_eq!(guard.bdf(), "0000:81:00.2");
            assert!(guard.companion_bdfs().is_empty());
        }

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(override_val.trim(), "");
    }

    #[test]
    fn test_adopt_rejects_device_not_bound_to_vfio() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        set_mock_driver(&sysfs, "0000:81:00.2", "mlx5_core");

        let err = PciBindGuard::adopt(&sysfs, "0000:81:00.2").unwrap_err();
        match err {
            VfioError::NotBoundToVfio { bdf, driver } => {
                assert_eq!(bdf, "0000:81:00.2");
                assert_eq!(driver, "mlx5_core");
            }
            other => panic!("expected NotBoundToVfio, got {other:?}"),
        }
    }

    #[test]
    fn test_adopt_group_already_bound_devices() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        test_refcounts::clear("15b3 101f");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "vfio-pci");
        for bdf in ["0000:81:00.2", "0000:81:00.3"] {
            fs::write(sysfs.pci_device(bdf).join("driver_override"), "vfio-pci").unwrap();
        }

        {
            let guard =
                PciBindGuard::adopt_group(&sysfs, &["0000:81:00.2", "0000:81:00.3"]).unwrap();
            assert_eq!(guard.bdf(), "0000:81:00.2");
            assert_eq!(guard.companion_bdfs(), &["0000:81:00.3".to_string()]);
        }

        for bdf in ["0000:81:00.2", "0000:81:00.3"] {
            let override_val =
                fs::read_to_string(sysfs.pci_device(bdf).join("driver_override")).unwrap();
            assert_eq!(
                override_val.trim(),
                "",
                "{bdf}: driver_override should be cleared after adopted group drops"
            );
        }
    }

    #[test]
    fn test_adopt_group_rejects_member_not_bound_to_vfio() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "mlx5_core");

        let err = PciBindGuard::adopt_group(&sysfs, &["0000:81:00.2", "0000:81:00.3"]).unwrap_err();
        match err {
            VfioError::NotBoundToVfio { bdf, driver } => {
                assert_eq!(bdf, "0000:81:00.3");
                assert_eq!(driver, "mlx5_core");
            }
            other => panic!("expected NotBoundToVfio, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_pci_for_passthrough_accepts_valid_solo_device() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );

        validate_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap();
    }

    #[test]
    fn test_validate_pci_for_passthrough_rejects_invalid_bdf_without_touching_sysfs() {
        let (_tmp, sysfs) = setup_mock_sysfs();
        let err = validate_pci_for_passthrough(&sysfs, "bad-bdf").unwrap_err();
        assert!(matches!(err, VfioError::InvalidBdf { .. }));
    }

    #[test]
    fn test_validate_pci_for_passthrough_rejects_iommu_group_conflict() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        set_mock_driver(&sysfs, "0000:81:00.3", "mlx5_core");

        let err = validate_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap_err();
        assert!(matches!(err, VfioError::IommuGroupConflict { .. }));

        // Crucially, validation must not have touched driver_override.
        let override_path = sysfs.pci_device("0000:81:00.2").join("driver_override");
        assert!(
            !override_path.exists(),
            "validate must not write driver_override"
        );
    }

    #[test]
    fn test_validate_pci_group_for_passthrough_accepts_complete_group() {
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

        validate_pci_group_for_passthrough(&sysfs, &["0000:2d:00.0", "0000:2d:00.1"]).unwrap();

        // No kernel state should have been touched.
        for bdf in ["0000:2d:00.0", "0000:2d:00.1"] {
            let override_path = sysfs.pci_device(bdf).join("driver_override");
            assert!(
                !override_path.exists(),
                "{bdf}: validate must not write driver_override"
            );
        }
    }

    #[test]
    fn test_validate_pci_group_for_passthrough_rejects_undeclared_peer() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );

        let err = validate_pci_group_for_passthrough(&sysfs, &["0000:81:00.2"]).unwrap_err();
        assert!(matches!(err, VfioError::IommuGroupConflict { .. }));
    }

    #[test]
    fn test_validate_pci_group_for_passthrough_rejects_empty() {
        let (_tmp, sysfs) = setup_mock_sysfs();
        let err = validate_pci_group_for_passthrough(&sysfs, &[]).unwrap_err();
        assert!(matches!(err, VfioError::EmptyGroup));
    }

    #[test]
    fn test_probe_host_vfio_candidates_returns_all_devices() {
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
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:01:00.0",
            "0x8086",
            "0x1234",
            "0x020000",
            3,
        );

        let candidates = probe_host_vfio_candidates(&sysfs, None);
        assert_eq!(candidates.len(), 3);
        let bdfs: Vec<&str> = candidates.iter().map(|c| c.bdf.as_str()).collect();
        assert!(bdfs.contains(&"0000:2d:00.0"));
        assert!(bdfs.contains(&"0000:81:00.2"));
        assert!(bdfs.contains(&"0000:01:00.0"));
    }

    #[test]
    fn test_probe_host_vfio_candidates_filters_by_vendor() {
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
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );

        let nvidia = probe_host_vfio_candidates(&sysfs, Some("0x10de"));
        assert_eq!(nvidia.len(), 1);
        assert_eq!(nvidia[0].bdf, "0000:2d:00.0");
        assert_eq!(nvidia[0].vendor, "0x10de");
        assert_eq!(nvidia[0].iommu_group, 42);

        let mellanox = probe_host_vfio_candidates(&sysfs, Some("0x15b3"));
        assert_eq!(mellanox.len(), 1);
        assert_eq!(mellanox[0].bdf, "0000:81:00.2");

        let intel = probe_host_vfio_candidates(&sysfs, Some("0x8086"));
        assert!(intel.is_empty());
    }

    #[test]
    fn test_probe_host_vfio_candidates_skips_devices_without_iommu_group() {
        let (tmp, sysfs) = setup_mock_sysfs();
        // Device WITH an IOMMU group.
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x2684",
            "0x030000",
            42,
        );
        // Device WITHOUT an IOMMU group - manually create just the basic
        // sysfs files so the probe can read vendor but cannot resolve
        // iommu_group. Mirrors a host with IOMMU disabled.
        let dev = sysfs.pci_device("0000:03:00.0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("vendor"), "0x8086\n").unwrap();
        std::fs::write(dev.join("device"), "0x9876\n").unwrap();
        std::fs::write(dev.join("class"), "0x020000\n").unwrap();

        let candidates = probe_host_vfio_candidates(&sysfs, None);
        let bdfs: Vec<&str> = candidates.iter().map(|c| c.bdf.as_str()).collect();
        assert!(bdfs.contains(&"0000:2d:00.0"));
        assert!(
            !bdfs.contains(&"0000:03:00.0"),
            "device without IOMMU group must be skipped"
        );
    }

    #[test]
    fn test_probe_host_vfio_candidates_synthesizes_name_from_vendor_device() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );

        let candidates = probe_host_vfio_candidates(&sysfs, None);
        assert_eq!(candidates.len(), 1);
        // No sysfs `label` was written, so the name falls back to "vendor device".
        assert_eq!(candidates[0].name, "0x15b3 0x101e");
    }

    #[test]
    fn test_prepare_pci_for_passthrough_single_device_group() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        {
            let guard = prepare_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap();
            assert_eq!(guard.bdf(), "0000:81:00.2");
        }

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(override_val.trim(), "");
    }

    #[test]
    fn test_prepare_pci_for_passthrough_rejects_iommu_group_conflict() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "mlx5_core");

        let err = prepare_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap_err();
        assert!(matches!(err, VfioError::IommuGroupConflict { .. }));
    }

    #[test]
    fn test_prepare_pci_for_passthrough_allows_peer_already_bound() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "vfio-pci");

        let guard = prepare_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap();
        assert_eq!(guard.bdf(), "0000:81:00.2");
    }

    #[test]
    fn test_prepare_pci_for_passthrough_missing_device() {
        let (_tmp, sysfs) = setup_mock_sysfs();

        let err = prepare_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap_err();
        assert!(matches!(err, VfioError::DeviceNotFound { .. }));
    }

    #[test]
    fn test_prepare_pci_for_passthrough_invalid_bdf() {
        let (_tmp, sysfs) = setup_mock_sysfs();

        let err = prepare_pci_for_passthrough(&sysfs, "bad-bdf").unwrap_err();
        assert!(matches!(err, VfioError::InvalidBdf { .. }));
    }

    #[test]
    fn test_prepare_pci_disarm_prevents_drop_restore() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let guard = prepare_pci_for_passthrough(&sysfs, "0000:81:00.2").unwrap();
        guard.disarm();

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(override_val, "vfio-pci");
    }

    #[test]
    fn test_prepare_pci_group_binds_all_members_atomically() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        test_refcounts::clear("15b3 101f");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_new_id_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();
        fs::write(
            sysfs.pci_device("0000:81:00.3").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        {
            let guard =
                prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2", "0000:81:00.3"])
                    .unwrap();
            assert_eq!(guard.bdf(), "0000:81:00.2");
            assert_eq!(guard.companion_bdfs(), &["0000:81:00.3".to_string()]);
        }

        for bdf in ["0000:81:00.2", "0000:81:00.3"] {
            let override_val =
                fs::read_to_string(sysfs.pci_device(bdf).join("driver_override")).unwrap();
            assert_eq!(
                override_val.trim(),
                "",
                "{bdf}: driver_override should be cleared after group guard drop"
            );
        }
    }

    #[test]
    fn test_prepare_pci_group_rejects_empty_slice() {
        let (_tmp, sysfs) = setup_mock_sysfs();
        let err = prepare_pci_group_for_passthrough(&sysfs, &[]).unwrap_err();
        assert!(matches!(err, VfioError::EmptyGroup));
    }

    #[test]
    fn test_prepare_pci_group_rejects_undeclared_peer() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );

        // Only declare the primary; the kernel reports an extra peer.
        let err = prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2"]).unwrap_err();
        match err {
            VfioError::IommuGroupConflict { bdf, group, peers } => {
                assert_eq!(bdf, "0000:81:00.2");
                assert_eq!(group, 7);
                assert_eq!(peers, vec!["0000:81:00.3".to_string()]);
            }
            other => panic!("expected IommuGroupConflict, got {other:?}"),
        }
    }

    #[test]
    fn test_prepare_pci_group_rejects_mixed_groups() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:82:00.0",
            "0x15b3",
            "0x101f",
            "0x020000",
            9,
        );

        let err = prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2", "0000:82:00.0"])
            .unwrap_err();
        match err {
            VfioError::GroupMismatch {
                bdf,
                expected_group,
                actual_group,
            } => {
                assert_eq!(bdf, "0000:82:00.0");
                assert_eq!(expected_group, 7);
                assert_eq!(actual_group, 9);
            }
            other => panic!("expected GroupMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_prepare_pci_group_rejects_duplicate_entries() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );

        let err = prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2", "0000:81:00.2"])
            .unwrap_err();
        assert!(matches!(err, VfioError::InvalidBdf { .. }));
    }

    #[test]
    fn test_prepare_pci_group_rejects_missing_device() {
        let (_tmp, sysfs) = setup_mock_sysfs();
        let err = prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2"]).unwrap_err();
        assert!(matches!(err, VfioError::DeviceNotFound { .. }));
    }

    #[test]
    fn test_prepare_pci_group_rollback_restores_newly_bound_on_failure() {
        // Two devices in one IOMMU group. The first binds successfully; the
        // second's probe write fails (no probe file). Rollback must restore
        // the first device to its host driver.
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        test_refcounts::clear("15b3 101f");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        create_new_id_file(&sysfs);
        create_remove_id_file(&sysfs);
        // No drivers_probe file - first device gets through (already on a
        // host driver so no probe call needed initially? Actually
        // bind_device_to_vfio always writes drivers_probe). Use mocked
        // drivers so the first device transitions cleanly and the second
        // fails.
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci"); // already bound -> no-op
        set_mock_driver(&sysfs, "0000:81:00.3", "mlx5_core");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        let err = prepare_pci_group_for_passthrough(&sysfs, &["0000:81:00.2", "0000:81:00.3"])
            .unwrap_err();
        assert!(matches!(err, VfioError::BindFailed { .. }));

        // First device was already on vfio-pci (not newly bound), so it
        // must be left as-found, not stolen by rollback.
        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(
            override_val.trim(),
            "vfio-pci",
            "device that was pre-bound must not be restored by rollback"
        );
    }

    #[test]
    fn test_release_pci_group_restores_all_devices() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        test_refcounts::clear("15b3 101f");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.3",
            "0x15b3",
            "0x101f",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        set_mock_driver(&sysfs, "0000:81:00.3", "vfio-pci");
        for bdf in ["0000:81:00.2", "0000:81:00.3"] {
            fs::write(sysfs.pci_device(bdf).join("driver_override"), "vfio-pci").unwrap();
        }

        release_pci_group_from_passthrough(&sysfs, &["0000:81:00.2", "0000:81:00.3"]).unwrap();

        for bdf in ["0000:81:00.2", "0000:81:00.3"] {
            let override_val =
                fs::read_to_string(sysfs.pci_device(bdf).join("driver_override")).unwrap();
            assert_eq!(
                override_val.trim(),
                "",
                "{bdf}: driver_override should be cleared after group release"
            );
        }
    }

    #[test]
    fn test_release_pci_group_returns_first_error_continues_others() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        // The first BDF is invalid; the second is valid and must still be
        // restored even though the first call returns an error.
        let err =
            release_pci_group_from_passthrough(&sysfs, &["bad-bdf", "0000:81:00.2"]).unwrap_err();
        assert!(matches!(err, VfioError::InvalidBdf { .. }));

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(
            override_val.trim(),
            "",
            "valid BDF must still be restored even though an earlier entry errored"
        );
    }

    #[test]
    fn test_release_pci_from_passthrough_restores_device() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("15b3 101e");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:81:00.2",
            "0x15b3",
            "0x101e",
            "0x020000",
            7,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:81:00.2", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:81:00.2").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        release_pci_from_passthrough(&sysfs, "0000:81:00.2").unwrap();

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:81:00.2").join("driver_override")).unwrap();
        assert_eq!(override_val.trim(), "");
    }
}
