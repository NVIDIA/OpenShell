// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the libkrun-backed VM compute driver.
//!
//! The VM driver runs as a separate subprocess (`openshell-driver-vm`) and
//! is wired up via a Unix domain socket. These settings are gateway-local
//! plumbing — they describe where the driver binary lives, where it keeps
//! its state, and the default VM shape — and are intentionally kept out of
//! the shared `openshell-core` config.

use std::path::PathBuf;

/// Configuration for launching and talking to the VM compute driver.
#[derive(Debug, Clone)]
pub struct VmComputeConfig {
    /// Working directory for VM driver sandbox state.
    pub state_dir: PathBuf,

    /// Optional override for the `openshell-driver-vm` binary path.
    /// When `None`, the gateway resolves a sibling of its own executable.
    pub compute_driver_bin: Option<PathBuf>,

    /// libkrun log level used by the VM driver helper.
    pub krun_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    pub vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    pub mem_mib: u32,

    /// Host-side CA certificate for the guest's mTLS client bundle.
    pub guest_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for the guest's mTLS client bundle.
    pub guest_tls_cert: Option<PathBuf>,

    /// Host-side private key for the guest's mTLS client bundle.
    pub guest_tls_key: Option<PathBuf>,
}

impl VmComputeConfig {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        PathBuf::from("target/openshell-vm-driver")
    }

    /// Default libkrun log level.
    #[must_use]
    pub const fn default_krun_log_level() -> u32 {
        1
    }

    /// Default vCPU count.
    #[must_use]
    pub const fn default_vcpus() -> u8 {
        2
    }

    /// Default memory allocation, in MiB.
    #[must_use]
    pub const fn default_mem_mib() -> u32 {
        2048
    }
}

impl Default for VmComputeConfig {
    fn default() -> Self {
        Self {
            state_dir: Self::default_state_dir(),
            compute_driver_bin: None,
            krun_log_level: Self::default_krun_log_level(),
            vcpus: Self::default_vcpus(),
            mem_mib: Self::default_mem_mib(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
        }
    }
}
