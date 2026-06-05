// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell MXC compute driver.
//!
//! Implements the gateway's `ComputeDriver` gRPC contract backed by Microsoft
//! MXC (`wxc-exec`) on Windows. The driver is **in-process**, runs the agent
//! directly (exec-in-driver), and self-reports `Ready` — there is no
//! in-sandbox supervisor, no host-side surrogate, and no `ConnectSupervisor`
//! relay.
//!
//! This crate compiles to an **empty stub** on non-Windows targets so the
//! Linux build stays green. All implementation code is gated on
//! `#[cfg(target_os = "windows")]`.

#![allow(clippy::result_large_err)]

#[cfg(target_os = "windows")]
mod driver;
#[cfg(target_os = "windows")]
mod grpc;
#[cfg(target_os = "windows")]
mod mxc;
#[cfg(target_os = "windows")]
mod policy;

#[cfg(target_os = "windows")]
pub use driver::{MxcComputeBackend, MxcComputeConfig};
#[cfg(target_os = "windows")]
pub use grpc::ComputeDriverService;
