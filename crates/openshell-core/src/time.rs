// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Time utilities shared across `OpenShell` crates.

use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current Unix timestamp in milliseconds, saturating to [`i64::MAX`]
/// on overflow.  Returns `0` if the system clock is before the Unix epoch.
///
/// Prefer this over local implementations of the same pattern.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
