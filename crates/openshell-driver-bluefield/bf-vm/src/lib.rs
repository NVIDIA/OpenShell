// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField VM lifecycle integration for the OpenShell VM driver.

pub mod cli;
mod config;
pub mod extension;
pub mod extensions;
pub mod guest_egress;
pub mod kernel;
mod slots;
mod state;
pub mod vf;

pub use bf_core::ProxyPlacement;
pub use cli::BluefieldDriverArgs;
pub use config::BluefieldDriverConfig;
pub use extension::BluefieldExtension;
pub use openshell_driver_vm::{
    BackendFeature, ExtensionCapabilities, ExtensionDescriptor, GuestInitDropin, LaunchAbortReason,
    LaunchPlan, LifecycleError, LifecycleExtension, LifecycleExtensionRegistry, LifecycleResult,
    RestoreContext, VM_RUNTIME_DIR_ENV, VmBackend, VmDriver, VmDriverConfig, VmLaunchConfig,
    cleanup_stale_tap_interfaces, configured_runtime_dir, driver, gpu, lifecycle, procguard,
    run_vm,
};

pub mod runtime {
    pub use openshell_driver_vm::{
        VM_RUNTIME_DIR_ENV, VmBackend, VmLaunchConfig, cleanup_stale_tap_interfaces,
        configured_runtime_dir, run_vm,
    };
}
