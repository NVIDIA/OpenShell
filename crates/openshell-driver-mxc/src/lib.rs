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
#[cfg(any(target_os = "windows", test))]
mod policy;
// Embedded mapper logic (source of truth; was the `openshell-policy-mapper`
// crate). Production code is Windows-only; tests run the pure mapper on Linux.
#[cfg(any(target_os = "windows", test))]
#[cfg_attr(not(target_os = "windows"), allow(unused_imports))]
mod policy_map;
// Real-time ETW → OCSF audit consumer (Plane A). Consumes the OS Sandboxing
// provider MXC drives and emits OCSF through the gateway's tracing sink.
// Windows-only.
#[cfg(target_os = "windows")]
mod etw_consumer;

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
