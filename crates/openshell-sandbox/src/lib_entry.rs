// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

#[cfg(not(target_os = "windows"))]
include!("lib.rs");

#[cfg(target_os = "windows")]
include!("lib_win.rs");
