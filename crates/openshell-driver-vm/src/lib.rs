// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod driver;
mod embedded_runtime;
mod ffi;
pub mod procguard;
mod rootfs;
mod runtime;

pub use driver::{VmDriver, VmDriverConfig};
pub use runtime::{VM_RUNTIME_DIR_ENV, VmLaunchConfig, configured_runtime_dir, run_vm};
