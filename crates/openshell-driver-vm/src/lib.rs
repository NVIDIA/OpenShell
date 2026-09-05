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

pub mod driver;
mod embedded_runtime;
mod ffi;
pub mod gpu;
pub mod lifecycle;
mod nft_ruleset;
pub mod otel_tracing;
pub mod procguard;
mod rootfs;
mod runtime;

pub use driver::{VmDriver, VmDriverConfig};
pub use lifecycle::{
    BackendFeature, ExtensionCapabilities, ExtensionDescriptor, GuestInitDropin, LaunchAbortReason,
    LaunchPlan, LifecycleError, LifecycleExtension, LifecycleExtensionRegistry, LifecycleResult,
    RestoreContext,
};
pub use runtime::{
    VM_RUNTIME_DIR_ENV, VmBackend, VmLaunchConfig, cleanup_stale_tap_interfaces,
    configured_runtime_dir, run_vm,
};
