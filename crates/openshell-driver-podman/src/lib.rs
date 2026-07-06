// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod client;
pub mod config;
pub(crate) mod container;
pub mod driver;
pub mod grpc;
#[cfg(test)]
pub(crate) mod test_utils;
pub(crate) mod watcher;

pub use config::PodmanComputeConfig;
pub use driver::PodmanComputeDriver;
pub use grpc::ComputeDriverService;

/// Compile-out guard: greppable proof this crate is linked into a binary.
///
/// `tasks/scripts/verify-drivers-compiled-out.sh` asserts this string is
/// present when `--features driver-podman` is on and absent when it is
/// off. `#[used]` prevents dead-code elimination; the linker cannot drop it.
/// Do not remove without updating the verify script.
#[used]
static COMPILE_MARKER: &str = "OPENSHELL_DRIVER_MARKER:podman";
