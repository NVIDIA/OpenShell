// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Duration;

static MANAGED_CHILDREN: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static REAPER_EVENT_FD: AtomicI32 = AtomicI32::new(-1);
const REAPER_RECOVERY_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
static REAPER_SCAN_COUNT: AtomicU64 = AtomicU64::new(0);

extern "C" fn notify_reaper_on_sigchld(_: libc::c_int) {
    let fd = REAPER_EVENT_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let wakeup = 1_u64;
        // SAFETY: write is async-signal-safe; the process-lifetime eventfd is
        // nonblocking, so a full counter cannot stall the signal handler.
        unsafe {
            libc::write(fd, (&raw const wakeup).cast(), size_of::<u64>());
        }
    }
}

/// Identity of one registry entry. The generation prevents an old waiter from
/// removing a newer child that reused the same numeric PID after reap.
#[derive(Clone, Copy)]
pub struct ManagedChild {
    pid: i32,
    generation: u64,
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

/// Register a child and return the generation-bearing removal token.
pub fn register(pid: u32) -> Option<ManagedChild> {
    lock().register(pid)
}

/// Remove exactly this supervised-child registration. A newer registration
/// for a reused PID is preserved.
pub fn unregister(child: ManagedChild) {
    if let Ok(mut children) = MANAGED_CHILDREN.lock()
        && children.get(&child.pid) == Some(&child.generation)
    {
        children.remove(&child.pid);
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
pub fn wait_until_terminal(pid: u32) -> io::Result<()> {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID out of range"))?;
    waitid(
        Id::Pid(nix::unistd::Pid::from_raw(pid)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
    )
    .map(|_| ())
    .map_err(io::Error::other)
}

/// Start the background reaper used when `openshell-sandbox` owns PID 1.
///
/// Explicitly managed children remain owned by their normal waiters. Only
/// unregistered children adopted from the workload process tree are reaped.
pub fn start_orphan_reaper() -> io::Result<()> {
    // This is installed before the boundary starts its runtime threads or
    // workload children. The descriptor and handler live until process exit.
    // SAFETY: eventfd has scalar arguments and returns a new descriptor.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    REAPER_EVENT_FD.store(fd, Ordering::Release);
    let action = nix::sys::signal::SigAction::new(
        nix::sys::signal::SigHandler::Handler(notify_reaper_on_sigchld),
        nix::sys::signal::SaFlags::SA_RESTART | nix::sys::signal::SaFlags::SA_NOCLDSTOP,
        nix::sys::signal::SigSet::empty(),
    );
    // SAFETY: the handler only reads a lock-free atomic and writes to the
    // nonblocking eventfd, both valid for the remaining process lifetime.
    unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGCHLD, &action) }
        .map_err(io::Error::other)?;
    std::thread::Builder::new()
        .name("openshell-orphan-reaper".to_string())
        .spawn(move || {
            loop {
                if let Err(error) = reap_unmanaged_children_once() {
                    tracing::debug!(%error, "orphan reaper scan failed");
                }
                if let Err(error) = wait_for_reaper_event(fd) {
                    tracing::debug!(%error, "orphan reaper notification failed");
                    std::thread::sleep(REAPER_RECOVERY_INTERVAL);
                }
            }
        })
        .map(|_| ())
}

fn wait_for_reaper_event(fd: libc::c_int) -> io::Result<()> {
    let mut notification = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one valid pollfd for the process-lifetime eventfd.
    let ready = unsafe {
        libc::poll(
            &raw mut notification,
            1,
            i32::try_from(REAPER_RECOVERY_INTERVAL.as_millis()).unwrap(),
        )
    };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(error);
    }
    if ready == 0 {
        return Ok(());
    }
    if notification.revents & libc::POLLIN == 0 {
        return Err(io::Error::other("orphan reaper eventfd is not readable"));
    }
    let mut count = 0_u64;
    // Drain before scanning: a SIGCHLD arriving during the next scan remains
    // queued and triggers another pass. A single read drains coalesced writes.
    // SAFETY: read writes one u64 into valid storage; the fd is nonblocking.
    let read = unsafe { libc::read(fd, (&raw mut count).cast(), size_of::<u64>()) };
    if read == isize::try_from(size_of::<u64>()).expect("u64 size fits isize")
        || (read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock)
    {
        Ok(())
    } else if read < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("short orphan reaper eventfd read"))
    }
}

fn reap_unmanaged_children_once() -> io::Result<usize> {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

    #[cfg(test)]
    REAPER_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);
    let children = direct_child_pids()?;
    let registry = lock();
    let mut reaped = 0;
    for pid in children {
        if registry.contains(pid) {
            continue;
        }
        match waitpid(nix::unistd::Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive)
            | Err(nix::errno::Errno::ECHILD | nix::errno::Errno::ESRCH) => {}
            Ok(_) => reaped += 1,
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    Ok(reaped)
}

fn direct_child_pids() -> io::Result<HashSet<i32>> {
    let mut children = HashSet::new();
    for task in std::fs::read_dir("/proc/self/task")? {
        let task = task?;
        let path = task.path().join("children");
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        children.extend(
            contents
                .split_ascii_whitespace()
                .filter_map(|value| value.parse::<i32>().ok())
                .filter(|pid| *pid > 0),
        );
    }
    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
    use nix::unistd::Pid;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn fork_exiting_child() -> i32 {
        // SAFETY: the child does not run Rust code after fork; it exits through
        // libc immediately, avoiding inherited test-harness locks.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: terminate without unwinding or touching Rust state.
            unsafe { libc::_exit(0) };
        }
        assert!(pid > 0, "fork failed: {}", io::Error::last_os_error());
        pid
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition did not become true");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn orphan_reaper_waits_while_idle_and_reaps_only_unmanaged_children() {
        const HELPER_ENV: &str = "OPENSHELL_ORPHAN_REAPER_TEST_HELPER";
        if std::env::var_os(HELPER_ENV).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "managed_children::tests::orphan_reaper_waits_while_idle_and_reaps_only_unmanaged_children",
                    "--nocapture",
                ])
                .env(HELPER_ENV, "1")
                .output()
                .expect("start isolated reaper test process");
            assert!(
                output.status.success(),
                "reaper test failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }

        start_orphan_reaper().expect("start orphan reaper");
        wait_until(|| REAPER_SCAN_COUNT.load(Ordering::Relaxed) > 0);
        let idle_scan_count = REAPER_SCAN_COUNT.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(REAPER_SCAN_COUNT.load(Ordering::Relaxed), idle_scan_count);

        let mut registry = lock();
        let managed_pid = fork_exiting_child();
        let managed = registry
            .register(u32::try_from(managed_pid).unwrap())
            .unwrap();
        drop(registry);
        wait_until(|| {
            matches!(
                waitid(
                    Id::Pid(Pid::from_raw(managed_pid)),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT
                ),
                Ok(WaitStatus::Exited(..))
            )
        });
        wait_until(|| REAPER_SCAN_COUNT.load(Ordering::Relaxed) > idle_scan_count);
        assert!(matches!(
            waitpid(Pid::from_raw(managed_pid), None),
            Ok(WaitStatus::Exited(..))
        ));
        unregister(managed);

        let orphan_pids: Vec<i32> = (0..8).map(|_| fork_exiting_child()).collect();
        wait_until(|| {
            let children = direct_child_pids().expect("inspect direct children");
            orphan_pids.iter().all(|pid| !children.contains(pid))
        });
        for pid in orphan_pids {
            assert_eq!(
                waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)),
                Err(nix::errno::Errno::ECHILD)
            );
        }
    }

    #[test]
    fn fast_child_remains_waitable_after_orphan_reap_attempt() {
        let mut registry = lock();
        let mut child = Command::new("sh")
            .args(["-c", "exit 11"])
            .spawn()
            .expect("spawn fast child");
        let child_pid = child.id();
        let managed_child = registry.register(child_pid).expect("register fast child");
        drop(registry);
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

        let registry = lock();
        let reaped = if registry.contains(pid.as_raw()) {
            None
        } else {
            Some(waitpid(pid, Some(WaitPidFlag::WNOHANG)))
        };
        drop(registry);
        assert!(
            reaped.is_none(),
            "the orphan reaper must leave a registered child to its explicit waiter"
        );

        let wait = child.wait();
        unregister(managed_child);
        assert!(
            wait.is_ok(),
            "the explicit child waiter must retain the exit status"
        );
    }

    #[test]
    fn reaper_cannot_steal_child_while_registration_is_in_progress() {
        // Keep the logical spawn paused before its PID is registered. This is
        // the exact window that previously let the orphan reaper consume a
        // fast child's status.
        let pid = 1_000_002_u32;
        let (spawn_entered_tx, spawn_entered_rx) = mpsc::channel();
        let (complete_spawn_tx, complete_spawn_rx) = mpsc::channel();
        let (registered_tx, registered_rx) = mpsc::channel();
        let (reap_attempted_tx, reap_attempted_rx) = mpsc::channel();
        let (reap_result_tx, reap_result_rx) = mpsc::channel();

        let spawn = std::thread::spawn(move || {
            let mut registry = lock();
            spawn_entered_tx.send(()).unwrap();
            complete_spawn_rx.recv().unwrap();
            let managed_child = registry.register(pid).expect("register child");
            assert!(registered_tx.send(managed_child).is_ok());
        });
        spawn_entered_rx.recv().unwrap();

        let reaper = std::thread::spawn(move || {
            reap_attempted_tx.send(()).unwrap();
            let registry = lock();
            reap_result_tx
                .send(registry.contains(i32::try_from(pid).unwrap()))
                .unwrap();
        });
        reap_attempted_rx.recv().unwrap();

        assert!(
            reap_result_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "the reaper must wait until the child is registered"
        );

        complete_spawn_tx.send(()).unwrap();
        let managed_child = registered_rx.recv().unwrap();
        spawn.join().unwrap();
        assert!(reap_result_rx.recv().unwrap());
        reaper.join().unwrap();
        unregister(managed_child);
    }

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

    #[test]
    fn child_pid_parser_observes_a_live_child() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn child");
        assert!(
            direct_child_pids()
                .expect("read direct children")
                .contains(&i32::try_from(child.id()).expect("child PID"))
        );
        child.kill().expect("kill child");
        child.wait().expect("wait for child");
    }
}
