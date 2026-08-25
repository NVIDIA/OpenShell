// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental Firecracker Isolation Backend.
//!
//! The logical supervisor and RFC 0012 lifecycle live on the host. A private
//! guest mode of the same driver binary only transports lifecycle operations
//! and invokes the existing `openshell-supervisor-process` implementation.

pub mod backend;
pub mod compute;
pub mod guest;
mod protocol;
pub mod runtime;

pub use backend::{BACKEND_NAME, FirecrackerHostBackend, FirecrackerTopology};
pub use compute::{FirecrackerComputeConfig, FirecrackerComputeDriver};
pub use guest::{DEFAULT_GUEST_CONFIG_PATH, GuestConfig, run_guest};
pub use runtime::{FirecrackerLaunchConfig, FirecrackerVm};
