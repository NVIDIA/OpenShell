// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace and bypass-rule helpers retained in the sandbox crate.
//!
//! Hardening (landlock + seccomp + `PreparedSandbox`) lives in
//! `openshell-supervisor-process::sandbox`. The netns piece stays here
//! because both eventual leaf crates (`openshell-supervisor-networking` and
//! `openshell-supervisor-process`) read from it; its final home is decided
//! when `run_networking` and `run_process` are extracted.

#[cfg(target_os = "linux")]
pub mod linux;
