// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

static MANAGED_CHILDREN: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Identity of one registry entry. The generation prevents an old waiter from
/// removing a newer child that reused the same numeric PID after reap.
#[derive(Clone, Copy)]
pub struct ManagedChild {
    pid: i32,
    generation: u64,
}

/// A managed-child registration accepted by [`unregister`].
///
/// New boundary-owned processes retain a generation-bearing token. Legacy
/// supervisor paths still identify their child by PID; supporting both keeps
/// the registry race-safe for new code without forcing an unrelated rewrite
/// of the canonical main-process and SSH paths.
pub enum ManagedChildRegistration {
    Token(ManagedChild),
    Pid(u32),
}

impl From<ManagedChild> for ManagedChildRegistration {
    fn from(value: ManagedChild) -> Self {
        Self::Token(value)
    }
}

impl From<u32> for ManagedChildRegistration {
    fn from(value: u32) -> Self {
        Self::Pid(value)
    }
}

/// Exclusive access to the managed-child registry.
///
/// A process spawner holds this guard from immediately before `spawn` or
/// `fork` until the returned PID is registered. The orphan reaper holds the
/// same guard while deciding whether to reap an exited child. This closes the
/// otherwise unavoidable window in which a fast-exiting managed child exists
/// but its PID has not yet been published.
pub struct RegistryGuard(MutexGuard<'static, HashMap<i32, u64>>);

impl RegistryGuard {
    /// Add a newly spawned managed child.
    pub fn register(&mut self, pid: u32) -> Option<ManagedChild> {
        let Ok(pid) = i32::try_from(pid) else {
            return None;
        };
        if pid <= 0 {
            return None;
        }
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.0.insert(pid, generation);
        Some(ManagedChild { pid, generation })
    }

    /// Return whether the PID belongs to an explicit waiter.
    #[must_use]
    pub fn contains(&self, pid: i32) -> bool {
        self.0.contains_key(&pid)
    }
}

/// Lock the registry for an atomic spawn-and-register or inspect-and-reap
/// operation.
pub fn lock() -> RegistryGuard {
    RegistryGuard(
        MANAGED_CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Register a child for a legacy caller that cannot retain a generation token.
pub fn register(pid: u32) {
    let _ = lock().register(pid);
}

/// Remove exactly this supervised-child registration. A newer registration
/// for a reused PID is preserved.
pub fn unregister(child: impl Into<ManagedChildRegistration>) {
    if let Ok(mut children) = MANAGED_CHILDREN.lock() {
        match child.into() {
            ManagedChildRegistration::Token(child)
                if children.get(&child.pid) == Some(&child.generation) =>
            {
                children.remove(&child.pid);
            }
            ManagedChildRegistration::Pid(pid) => {
                if let Ok(pid) = i32::try_from(pid) {
                    children.remove(&pid);
                }
            }
            ManagedChildRegistration::Token(_) => {}
        }
    }
}

/// Return `true` if `pid` is currently in the supervised-child set.
#[must_use]
pub fn is_managed(pid: i32) -> bool {
    lock().contains(pid)
}

/// Wait until a managed child is terminal without reaping it.
///
/// Keeping the child as a zombie prevents PID/process-group reuse until the
/// owner publishes terminal state and performs the final wait.
pub fn wait_until_terminal(pid: u32) -> std::io::Result<()> {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    let pid = i32::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "PID out of range"))?;
    waitid(
        Id::Pid(nix::unistd::Pid::from_raw(pid)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
    )
    .map(|_| ())
    .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_unregister_preserves_reused_pid_registration() {
        let pid = i32::MAX as u32;
        let first = lock().register(pid).expect("first registration");
        let second = lock().register(pid).expect("replacement registration");

        unregister(first);
        assert!(is_managed(i32::try_from(pid).expect("test pid")));

        unregister(second);
        assert!(!is_managed(i32::try_from(pid).expect("test pid")));
    }
}
