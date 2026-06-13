// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin BlueField-side wrapper over the `openshell-vfio` substrate.
//!
//! Binding actually mutates host sysfs, so these helpers are kept behind
//! explicit calls the extension makes in `before_launch` / restore, never at
//! construction time.

use openshell_vfio::{
    PciBindGuard, SysfsRoot, prepare_pci_for_passthrough, release_pci_from_passthrough,
    validate_pci_for_passthrough,
};

use bf_inventory::FunctionSlot;

/// Host capability probe for VF passthrough. Injectable so tests (and hosts
/// without the device) don't need real hardware. Implementations check that
/// *this* host can actually pass a given BDF through to a guest.
pub trait HostReadiness: std::fmt::Debug + Send + Sync {
    /// Returns `Err(reason)` if the host cannot pass `host_bdf` through
    /// (IOMMU disabled, device missing, IOMMU-group conflict, ...).
    fn check_passthrough(&self, host_bdf: &str) -> Result<(), String>;
}

/// Default [`HostReadiness`] backed by the real `/sys` via `openshell-vfio`.
#[derive(Debug)]
pub struct SysfsHostReadiness {
    sysfs: SysfsRoot,
}

impl SysfsHostReadiness {
    #[must_use]
    pub fn new(sysfs: SysfsRoot) -> Self {
        Self { sysfs }
    }
}

impl Default for SysfsHostReadiness {
    fn default() -> Self {
        Self {
            sysfs: SysfsRoot::system(),
        }
    }
}

impl HostReadiness for SysfsHostReadiness {
    fn check_passthrough(&self, host_bdf: &str) -> Result<(), String> {
        validate_pci_for_passthrough(&self.sysfs, host_bdf).map_err(|err| err.to_string())
    }
}

pub(crate) trait VfBinding: std::fmt::Debug + Send {
    fn disarm(self: Box<Self>);
}

#[derive(Debug)]
struct RealVfBinding(PciBindGuard);

impl VfBinding for RealVfBinding {
    fn disarm(self: Box<Self>) {
        let Self(guard) = *self;
        guard.disarm();
    }
}

pub(crate) trait VfBinder: std::fmt::Debug + Send + Sync {
    fn bind_slot(&self, slot: &FunctionSlot) -> Result<Box<dyn VfBinding>, String>;
    fn adopt_slot(&self, slot: &FunctionSlot) -> Result<Box<dyn VfBinding>, String>;
    fn release_slot(&self, slot: &FunctionSlot) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub(crate) struct SysfsVfBinder {
    sysfs: SysfsRoot,
}

impl SysfsVfBinder {
    pub(crate) fn new(sysfs: SysfsRoot) -> Self {
        Self { sysfs }
    }
}

impl Default for SysfsVfBinder {
    fn default() -> Self {
        Self::new(SysfsRoot::system())
    }
}

impl VfBinder for SysfsVfBinder {
    fn bind_slot(&self, slot: &FunctionSlot) -> Result<Box<dyn VfBinding>, String> {
        bind_slot(&self.sysfs, slot)
            .map(|guard| {
                let binding: Box<dyn VfBinding> = Box::new(RealVfBinding(guard));
                binding
            })
            .map_err(|err| err.to_string())
    }

    fn adopt_slot(&self, slot: &FunctionSlot) -> Result<Box<dyn VfBinding>, String> {
        adopt_slot(&self.sysfs, slot)
            .map(|guard| {
                let binding: Box<dyn VfBinding> = Box::new(RealVfBinding(guard));
                binding
            })
            .map_err(|err| err.to_string())
    }

    fn release_slot(&self, slot: &FunctionSlot) -> Result<(), String> {
        release_slot(&self.sysfs, slot).map_err(|err| err.to_string())
    }
}

/// Bind a claimed VF slot to `vfio-pci`, returning the RAII guard.
///
/// The caller is expected to `disarm()` the guard once QEMU owns the device
/// and to persist the binding for restart reconciliation.
pub fn bind_slot(
    sysfs: &SysfsRoot,
    slot: &FunctionSlot,
) -> Result<PciBindGuard, openshell_vfio::VfioError> {
    prepare_pci_for_passthrough(sysfs, &slot.host_bdf)
}

/// Re-take ownership of a VF already bound to `vfio-pci` after a driver
/// restart, without rebinding or mutating sysfs.
pub fn adopt_slot(
    sysfs: &SysfsRoot,
    slot: &FunctionSlot,
) -> Result<PciBindGuard, openshell_vfio::VfioError> {
    PciBindGuard::adopt(sysfs, &slot.host_bdf)
}

/// Restore a VF slot's device to its host driver at teardown time.
pub fn release_slot(
    sysfs: &SysfsRoot,
    slot: &FunctionSlot,
) -> Result<(), openshell_vfio::VfioError> {
    release_pci_from_passthrough(sysfs, &slot.host_bdf)
}
