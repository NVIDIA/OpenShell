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
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

static MANAGED_CHILDREN: LazyLock<Mutex<HashSet<i32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn lock_children() -> MutexGuard<'static, HashSet<i32>> {
    MANAGED_CHILDREN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn insert(children: &mut HashSet<i32>, pid: Option<u32>) {
    let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) else {
        return;
    };
    if pid > 0 {
        children.insert(pid);
    }
}

/// Spawn a supervised child and register its PID before the orphan reaper can
/// inspect it.
///
/// The registry lock intentionally spans `spawn`. Otherwise a fast child can
/// exit and be reaped after `spawn` returns but before its PID is registered,
/// causing the child's explicit waiter to fail with `ECHILD`.
pub fn spawn_registered<T, E>(
    spawn: impl FnOnce() -> Result<T, E>,
    pid: impl FnOnce(&T) -> Option<u32>,
) -> Result<T, E> {
    let mut children = lock_children();
    let child = spawn()?;
    insert(&mut children, pid(&child));
    Ok(child)
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
    lock_children().remove(&pid);
}

/// Run `reap` only when `pid` is not a supervised child.
///
/// The registry lock remains held while `reap` runs so child creation cannot
/// open a spawn-to-registration window between the membership check and reap.
pub fn reap_if_unmanaged<T>(pid: i32, reap: impl FnOnce() -> T) -> Option<T> {
    let children = lock_children();
    if children.contains(&pid) {
        None
    } else {
        Some(reap())
    }
}

#[cfg(test)]
mod tests {
    use super::{reap_if_unmanaged, spawn_registered, unregister};
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
    use nix::unistd::Pid;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn spawned_child_is_registered_before_returning() {
        let pid = 1_000_000_u32;
        let child = spawn_registered(|| Ok::<_, ()>(pid), |pid| Some(*pid)).unwrap();
        let mut reaped = false;

        let result = reap_if_unmanaged(i32::try_from(child).unwrap(), || {
            reaped = true;
        });

        assert!(result.is_none());
        assert!(!reaped);
        unregister(pid);
    }

    #[test]
    fn reaper_cannot_steal_child_while_registration_is_in_progress() {
        // Keep `spawn` paused after its logical child exists but before it
        // returns the PID. This is the exact window that previously let the
        // orphan reaper consume a fast child's status.
        let pid = 1_000_002_u32;
        let (spawn_entered_tx, spawn_entered_rx) = mpsc::channel();
        let (complete_spawn_tx, complete_spawn_rx) = mpsc::channel();
        let (reap_attempted_tx, reap_attempted_rx) = mpsc::channel();
        let (reap_result_tx, reap_result_rx) = mpsc::channel();

        let spawn = std::thread::spawn(move || {
            spawn_registered(
                || {
                    spawn_entered_tx.send(()).unwrap();
                    complete_spawn_rx.recv().unwrap();
                    Ok::<_, ()>(pid)
                },
                |child| Some(*child),
            )
            .unwrap();
        });
        spawn_entered_rx.recv().unwrap();

        let reaper = std::thread::spawn(move || {
            reap_attempted_tx.send(()).unwrap();
            let result = reap_if_unmanaged(i32::try_from(pid).unwrap(), || "reaped");
            reap_result_tx.send(result).unwrap();
        });
        reap_attempted_rx.recv().unwrap();

        assert!(
            reap_result_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "the reaper must wait until the child is registered"
        );

        complete_spawn_tx.send(()).unwrap();
        spawn.join().unwrap();
        assert_eq!(reap_result_rx.recv().unwrap(), None);
        reaper.join().unwrap();
        unregister(pid);
    }

    #[test]
    fn unmanaged_child_can_be_reaped() {
        let result = reap_if_unmanaged(1_000_001, || "reaped");

        assert_eq!(result, Some("reaped"));
    }

    #[test]
    fn fast_child_remains_waitable_after_orphan_reap_attempt() {
        let mut child = spawn_registered(
            || Command::new("sh").args(["-c", "exit 11"]).spawn(),
            |child| Some(child.id()),
        )
        .expect("spawn and register fast child");
        let child_pid = child.id();
        let pid = Pid::from_raw(i32::try_from(child_pid).unwrap());

        // Observe the completed child without consuming its status, exactly
        // as the orphan reaper does before its managed-PID check.
        loop {
            match waitid(
                Id::Pid(pid),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            ) {
                Ok(WaitStatus::StillAlive) => std::thread::yield_now(),
                Ok(_) => break,
                Err(error) => panic!("observe fast child: {error}"),
            }
        }

        let reaped = reap_if_unmanaged(pid.as_raw(), || waitpid(pid, Some(WaitPidFlag::WNOHANG)));
        assert!(
            reaped.is_none(),
            "the orphan reaper must leave a registered child to its explicit waiter"
        );

        let wait = child.wait();
        unregister(child_pid);
        assert!(
            wait.is_ok(),
            "the explicit child waiter must retain the exit status"
        );
    }
}
