// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// `defaults-without-telemetry` is an alias for the default feature set minus
// `telemetry`, not a switch that turns telemetry off. Cargo cannot subtract a
// default feature, so adding it on top of the defaults would otherwise produce
// a telemetry-on build that reads as telemetry-free. Fail the build instead.
#[cfg(all(feature = "telemetry", feature = "defaults-without-telemetry"))]
compile_error!(
    "features `telemetry` and `defaults-without-telemetry` are mutually exclusive; \
     build a telemetry-free VM driver with `--no-default-features --features defaults-without-telemetry`"
);

#[cfg(feature = "compute-driver")]
pub mod driver;
#[cfg(feature = "compute-driver")]
mod embedded_runtime;
#[cfg(feature = "compute-driver")]
mod ffi;
#[cfg(feature = "compute-driver")]
pub mod gpu;
#[cfg(feature = "compute-driver")]
mod isolation;
#[cfg(feature = "compute-driver")]
pub mod lifecycle;
#[cfg(feature = "compute-driver")]
pub mod otel_tracing;
#[cfg(feature = "compute-driver")]
pub mod procguard;
#[cfg(feature = "compute-driver")]
mod rootfs;
#[cfg(feature = "compute-driver")]
mod runtime;

#[cfg(feature = "compute-driver")]
pub use driver::{VmDriver, VmDriverConfig};
#[cfg(feature = "compute-driver")]
pub use lifecycle::{
    BackendFeature, ExtensionCapabilities, ExtensionDescriptor, GuestInitDropin, LaunchAbortReason,
    LaunchPlan, LifecycleError, LifecycleExtension, LifecycleExtensionRegistry, LifecycleResult,
    RestoreContext,
};
#[cfg(feature = "compute-driver")]
pub use runtime::{
    VM_RUNTIME_DIR_ENV, VmBackend, VmLaunchConfig, VsockPortMap, configured_runtime_dir, run_vm,
};
