// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows stub for local Dockerfile image builds.

use std::collections::HashMap;
use std::path::Path;

use miette::Result;

// Keep this stub's signature aligned with the supported-platform implementation.
#[allow(clippy::implicit_hasher)]
pub async fn build_local_image(
    _dockerfile_path: &Path,
    _tag: &str,
    _context_dir: &Path,
    _build_args: &HashMap<String, String>,
    _on_log: &mut impl FnMut(String),
) -> Result<()> {
    Err(miette::miette!(
        "local Dockerfile sandbox sources are unsupported on Windows"
    ))
}
