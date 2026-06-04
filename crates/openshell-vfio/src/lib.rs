// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VFIO `PCIe` passthrough lifecycle management for `OpenShell` VM sandboxes.
//!
//! Provides discovery, binding, and crash-recovery for VFIO-capable PCI
//! devices using the kernel's `vfio-pci` driver. All sysfs access goes through
//! [`SysfsRoot`] so the entire stack is testable without root or real hardware.
//!
//! This crate is organized into:
//!
//! - [`sysfs`] - generic sysfs primitives (paths, validation, IO helpers)
//! - [`bind`] - generic bind/unbind/probe mechanics
//! - [`pci`] - generic device types and the public passthrough API
//! - [`reconcile`] - crash-recovery for stale bindings
//! - [`gpu`] - GPU passthrough helpers plus NVIDIA-specific inventory probing

pub mod bind;
pub mod error;
pub mod gpu;
pub mod pci;
pub mod reconcile;
pub mod sysfs;

#[cfg(test)]
mod test_support;

pub use error::VfioError;
pub use gpu::{prepare_gpu_for_passthrough, probe_host_nvidia_vfio_readiness};
pub use pci::{
    PciBindGuard, PciBindState, PciBinding, PciInfo, prepare_pci_for_passthrough,
    prepare_pci_group_for_passthrough, probe_host_vfio_candidates, release_pci_from_passthrough,
    release_pci_group_from_passthrough, validate_pci_for_passthrough,
    validate_pci_group_for_passthrough,
};
pub use reconcile::reconcile_stale_bindings;
pub use sysfs::{SysfsRoot, validate_bdf, validate_sysfs_data};

// ----------------------------------------------------------------------
// Source-compatibility aliases for the pre-refactor public API.
// Existing callers continue to compile without source changes. Plan to remove
// these in a follow-up once all internal callers have migrated to the new names.
// ----------------------------------------------------------------------

pub use pci::PciBindGuard as GpuBindGuard;
pub use pci::PciBindState as GpuBindState;
pub use pci::PciBinding as GpuBinding;
pub use pci::PciInfo as GpuInfo;
