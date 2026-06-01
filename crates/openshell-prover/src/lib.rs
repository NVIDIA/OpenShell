// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(target_os = "windows"))]
include!("lib_unix.rs");

#[cfg(target_os = "windows")]
pub fn prove(
    _policy_path: &str,
    _credentials_path: &str,
    _registry_dir: Option<&str>,
    _accepted_risks_path: Option<&str>,
    _compact: bool,
) -> miette::Result<i32> {
    Err(miette::miette!(
        "policy prover is not available on Windows in this build"
    ))
}
