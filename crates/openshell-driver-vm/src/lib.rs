// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod driver;
mod embedded_runtime;
mod ffi;
pub mod oci;
mod rootfs;
mod runtime;
pub mod state_disk;

pub const GUEST_SSH_PORT: u16 = 2222;

pub use driver::{VmDriver, VmDriverConfig};
pub use runtime::{
    ImportVsock, StateDisk, VM_RUNTIME_DIR_ENV, VmLaunchConfig, configured_runtime_dir, run_vm,
};
pub use state_disk::{
    DEFAULT_STATE_DISK_SIZE_BYTES, IMPORT_VSOCK_PORT, STATE_DISK_BLOCK_ID, SandboxStatePaths,
    ensure_state_disk, prepare_import_socket_dir, verify_import_socket_path,
};
