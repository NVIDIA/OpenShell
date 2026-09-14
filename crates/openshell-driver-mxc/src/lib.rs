// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` MXC compute driver.
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
// Embedded mapper logic (source of truth; was the `openshell-policy-mapper`
// crate). Windows-only — MXC and the policy mapper are not built for Linux/WSL.
#[cfg(target_os = "windows")]
mod policy_map;

#[cfg(target_os = "windows")]
pub use driver::{MxcBackend, MxcComputeBackend, MxcComputeConfig};
#[cfg(target_os = "windows")]
pub use grpc::ComputeDriverService;
// Re-export the embedded mapper API so the windows-only example and integration
// test can reach it without making `policy_map` a public module.
#[cfg(target_os = "windows")]
pub use policy::{EmbeddedPolicyMapper, MapCtx, MapError, MappedConfig, PolicyMapper};
#[cfg(target_os = "windows")]
pub use policy_map::{
    DEFAULT_COMMAND, DEFAULT_CONTAINMENT, DEFAULT_MXC_VERSION, LossItem, MxcMappingOptions,
    MxcMappingResult, OPEN_SHELL_SUPERSET_GAPS, SplitPolicyResult, build_loss_report, map_to_mxc,
    render_readme, split_policy,
};
