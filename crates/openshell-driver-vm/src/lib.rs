// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod driver;
mod embedded_runtime;
mod ffi;
mod rootfs;
mod runtime;

pub const GUEST_SSH_PORT: u16 = 2222;

pub use driver::{VmDriver, VmDriverConfig};
pub use runtime::{VM_RUNTIME_DIR_ENV, VmLaunchConfig, configured_runtime_dir, run_vm};
