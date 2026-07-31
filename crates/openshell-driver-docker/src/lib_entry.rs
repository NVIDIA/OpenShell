// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker compute driver.

#![allow(clippy::result_large_err)]

#[cfg(not(target_os = "windows"))]
include!("lib.rs");

#[cfg(target_os = "windows")]
include!("lib_win.rs");
