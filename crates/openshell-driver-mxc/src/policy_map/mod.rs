// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Map an `OpenShell` sandbox policy to a Microsoft MXC `ContainerConfig`.
//!
//! This module is the **source of truth** for the OpenShell→MXC policy mapping
//! (it was the standalone `openshell-policy-mapper` crate). It is embedded in the
//! MXC driver as a module, consumed by the [`crate::policy`] seam.
//!
//! It reuses the canonical typed [`SandboxPolicy`] from `openshell-policy`
//! (obtained via `openshell_policy::parse_sandbox_policy`) rather than re-parsing
//! YAML, so the policy schema has a single source of truth.
//!
//! Two mapping shapes are intended:
//!
//! - [`map_to_mxc`] — the *coarse / standalone* mapping. `OpenShell` network
//!   policy is flattened into an MXC host allowlist (`network.allowedHosts`),
//!   and anything MXC cannot express (ports, protocol, L7 rules, binary scope)
//!   is recorded in the loss report. Use this when MXC enforces network on its
//!   own, with no `OpenShell` proxy in the loop.
//! - [`split_policy`] — the *lossless* split for the Windows MXC compute
//!   driver: MXC handles filesystem + containment + a `network.proxy` redirect,
//!   while the full `OpenShell` network policy is preserved in a trimmed policy
//!   enforced by the host CONNECT proxy.
//!
//! The report/loss-report helpers are only exercised by the example and the
//! integration tests, so the Windows lib build would otherwise warn on them;
//! `#![allow(dead_code)]` keeps the module quiet without per-item churn.
//!
//! [`SandboxPolicy`]: openshell_core::proto::SandboxPolicy

#![allow(dead_code)]

mod config;
mod loss;
mod map;
mod report;

pub use config::{DEFAULT_COMMAND, DEFAULT_CONTAINMENT, DEFAULT_MXC_VERSION};
pub use loss::{LossItem, OPEN_SHELL_SUPERSET_GAPS};
pub use map::{MxcMappingOptions, MxcMappingResult, SplitPolicyResult, map_to_mxc, split_policy};
pub use report::{build_loss_report, render_readme};
