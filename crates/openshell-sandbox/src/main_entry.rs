// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox - process sandbox and monitor.

#[cfg(not(target_os = "windows"))]
include!("main.rs");

#[cfg(target_os = "windows")]
include!("main_win.rs");
