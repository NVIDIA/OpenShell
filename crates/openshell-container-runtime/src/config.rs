// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration defaults used only by the desktop compute drivers.

use std::num::NonZeroI64;

// ── Public default constants ────────────────────────────────────────────
//
// Canonical source for default values used across multiple crates.
// Clap `default_value_t` annotations and runtime fallbacks should
// reference these constants instead of hardcoding literals.

/// Default SSH port inside sandbox containers.
pub const DEFAULT_SSH_PORT: u16 = 2222;

/// Default cgroup PID limit for local container sandboxes.
pub const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;

/// Typed default cgroup PID limit for local container sandboxes.
#[must_use]
pub fn default_sandbox_pids_limit() -> Option<NonZeroI64> {
    NonZeroI64::new(DEFAULT_SANDBOX_PIDS_LIMIT)
}

/// CDI device identifier for requesting all NVIDIA GPUs.
pub const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_sandbox_pids_default_matches_positive_constant() {
        assert_eq!(
            default_sandbox_pids_limit().map(NonZeroI64::get),
            Some(DEFAULT_SANDBOX_PIDS_LIMIT)
        );
    }
}
