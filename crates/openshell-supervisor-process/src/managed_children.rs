// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

static MANAGED_CHILDREN: LazyLock<Mutex<HashSet<i32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Add `pid` to the supervised-child set. Non-positive or out-of-range values
/// are silently ignored.
pub fn register(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    if pid <= 0 {
        return;
    }
    if let Ok(mut children) = MANAGED_CHILDREN.lock() {
        children.insert(pid);
    }
}

/// Remove `pid` from the supervised-child set. Non-positive or out-of-range
/// values are silently ignored.
pub fn unregister(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    if pid <= 0 {
        return;
    }
    if let Ok(mut children) = MANAGED_CHILDREN.lock() {
        children.remove(&pid);
    }
}

/// Return `true` if `pid` is currently in the supervised-child set.
#[must_use]
pub fn is_managed(pid: i32) -> bool {
    MANAGED_CHILDREN
        .lock()
        .is_ok_and(|children| children.contains(&pid))
}
