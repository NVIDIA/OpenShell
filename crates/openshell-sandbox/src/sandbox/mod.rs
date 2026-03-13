// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform sandboxing implementation.

use crate::policy::SandboxPolicy;
use miette::Result;
#[cfg(not(target_os = "linux"))]
use tracing::warn;

#[cfg(target_os = "linux")]
pub mod linux;

/// Apply sandboxing rules for the current platform.
///
/// # Errors
///
/// Returns an error if the sandbox cannot be applied.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(policy, workdir)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, workdir);
        warn!("Sandbox policy provided but platform sandboxing is not yet implemented");
        Ok(())
    }
}
