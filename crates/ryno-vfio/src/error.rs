// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum VfioError {
    #[error("GPU {bdf} not found in sysfs")]
    GpuNotFound { bdf: String },

    #[error("VFIO PCIe device {bdf} not found in sysfs")]
    DeviceNotFound { bdf: String },

    #[error("GPU {bdf} is not an NVIDIA device (vendor={vendor})")]
    NotNvidia { bdf: String, vendor: String },

    #[error("PCI device {bdf} is not a GPU display controller (class={class})")]
    NotGpu { bdf: String, class: String },

    #[error("PCI device {bdf} has no IOMMU group - is IOMMU enabled?")]
    NoIommuGroup { bdf: String },

    #[error("PCI device {bdf} IOMMU group {group} has other non-vfio-pci devices: {peers:?}")]
    IommuGroupConflict {
        bdf: String,
        group: u32,
        peers: Vec<String>,
    },

    #[error("PCI device {bdf} is in IOMMU group {actual_group}, expected {expected_group}")]
    GroupMismatch {
        bdf: String,
        expected_group: u32,
        actual_group: u32,
    },

    #[error("PCI device {bdf} is not bound to vfio-pci (driver={driver})")]
    NotBoundToVfio { bdf: String, driver: String },

    #[error("empty PCI group passed to prepare_pci_group_for_passthrough")]
    EmptyGroup,

    #[error("failed to bind PCI device {bdf} to vfio-pci: {reason}")]
    BindFailed { bdf: String, reason: String },

    #[error("failed to unbind PCI device {bdf} from vfio-pci: {reason}")]
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
