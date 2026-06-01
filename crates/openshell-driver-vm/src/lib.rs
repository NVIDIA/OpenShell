// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
pub fn windows_unsupported() -> &'static str {
    "openshell-driver-vm is unsupported on Windows"
}

#[cfg(not(target_os = "windows"))]
include!("lib_unix.rs");
