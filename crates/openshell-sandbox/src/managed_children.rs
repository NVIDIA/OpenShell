// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex, MutexGuard};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
static MANAGED_CHILDREN: LazyLock<Mutex<HashMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(target_os = "linux")]
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Identity of one registry entry. The generation prevents an old waiter from
/// removing a newer child that reused the same numeric PID after reap.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ManagedChildRegistration {
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
#[cfg(target_os = "linux")]
struct RegistryGuard(MutexGuard<'static, HashMap<i32, u64>>);

#[cfg(target_os = "linux")]
impl RegistryGuard {
    /// Add a newly spawned managed child.
    fn register(&mut self, pid: u32) -> Option<ManagedChildRegistration> {
        let Ok(pid) = i32::try_from(pid) else {
            return None;
        };
        if pid <= 0 {
            return None;
        }
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.0.insert(pid, generation);
        Some(ManagedChildRegistration { pid, generation })
    }

    /// Return whether the PID belongs to an explicit waiter.
    #[must_use]
    fn contains(&self, pid: i32) -> bool {
        self.0.contains_key(&pid)
    }
}

/// Lock the registry for an atomic spawn-and-register or inspect-and-reap
/// operation.
#[cfg(target_os = "linux")]
fn lock() -> RegistryGuard {
    RegistryGuard(
        MANAGED_CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Remove exactly this supervised-child registration. A newer registration
/// for a reused PID is preserved.
#[cfg(target_os = "linux")]
fn unregister(child: ManagedChildRegistration) {
    if let Ok(mut children) = MANAGED_CHILDREN.lock()
        && children.get(&child.pid) == Some(&child.generation)
    {
        children.remove(&child.pid);
    }
}

/// Return `true` if `pid` is currently in the supervised-child set.
#[cfg(all(test, target_os = "linux"))]
#[must_use]
fn is_managed(pid: i32) -> bool {
    lock().contains(pid)
}

fn valid_pid(pid: Option<u32>) -> Option<u32> {
    let pid = pid.and_then(|pid| i32::try_from(pid).ok())?;
    (pid > 0).then(|| u32::try_from(pid).expect("positive i32 fits in u32"))
}

/// A child whose exit status is owned by the sandbox runtime.
///
/// Construction holds the Linux registry lock across the real spawn and PID
/// insertion, so the orphan reaper cannot consume a fast child's status
/// between those operations. Other platforms retain the same ownership API
/// without enabling Linux-only reaper bookkeeping.
pub(crate) struct ManagedChild<C> {
    child: C,
    pid: Option<u32>,
    #[cfg(target_os = "linux")]
    registration: Option<ManagedChildRegistration>,
}

impl<C> ManagedChild<C> {
    /// Spawn a child and register its PID before returning it.
    pub(crate) fn spawn<E>(
        spawn: impl FnOnce() -> Result<C, E>,
        pid: impl FnOnce(&C) -> Option<u32>,
    ) -> Result<Self, E> {
        #[cfg(target_os = "linux")]
        {
            let mut registry = lock();
            let child = spawn()?;
            let pid = valid_pid(pid(&child));
            let registration = pid.and_then(|pid| registry.register(pid));
            Ok(Self {
                child,
                pid,
                registration,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let child = spawn()?;
            let pid = valid_pid(pid(&child));
            Ok(Self { child, pid })
        }
    }

    /// Return the child's PID when it was available at spawn time.
    #[must_use]
    pub(crate) const fn id(&self) -> Option<u32> {
        self.pid
    }

    fn unregister(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(registration) = self.registration.take() {
            unregister(registration);
        }
        self.pid = None;
    }
}

impl<C> Drop for ManagedChild<C> {
    fn drop(&mut self) {
        self.unregister();
    }
}

fn log_wait_error(pid: Option<u32>, error: &std::io::Error) {
    if error.raw_os_error() == Some(libc::ECHILD) {
        tracing::error!(
            pid = ?pid,
            error = %error,
            "managed child status was reaped before its explicit waiter"
        );
    }
}

impl ManagedChild<tokio::process::Child> {
    /// Wait for a Tokio child and release its managed PID.
    pub(crate) async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait().await;
        if let Err(error) = &status {
            log_wait_error(self.pid, error);
        }
        self.unregister();
        status
    }

    /// Observe a Tokio child without blocking.
    pub(crate) fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match self.child.try_wait() {
            Ok(status) => {
                if status.is_some() {
                    self.unregister();
                }
                Ok(status)
            }
            Err(error) => {
                log_wait_error(self.pid, &error);
                self.unregister();
                Err(error)
            }
        }
    }

    /// Take the child's stdin handle without exposing the child itself.
    pub(crate) fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the child's stdout handle without exposing the child itself.
    pub(crate) fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's stderr handle without exposing the child itself.
    pub(crate) fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }
}

impl ManagedChild<std::process::Child> {
    /// Wait for a standard-library child and release its managed PID.
    pub(crate) fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait();
        if let Err(error) = &status {
            log_wait_error(self.pid, error);
        }
        self.unregister();
        status
    }

    /// Take the child's stdin handle without exposing the child itself.
    pub(crate) fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the child's stdout handle without exposing the child itself.
    pub(crate) fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's stderr handle without exposing the child itself.
    pub(crate) fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }
}

/// Wait until a managed child is terminal without reaping it.
///
/// Keeping the child as a zombie prevents PID/process-group reuse until the
/// owner publishes terminal state and performs the final wait.
#[cfg(target_os = "linux")]
pub(crate) fn wait_until_terminal(pid: u32) -> io::Result<()> {
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
#[cfg(target_os = "linux")]
pub(crate) fn start_orphan_reaper() -> io::Result<()> {
    std::thread::Builder::new()
        .name("openshell-orphan-reaper".to_string())
        .spawn(|| {
            loop {
                if let Err(error) = reap_unmanaged_children_once() {
                    tracing::debug!(%error, "orphan reaper scan failed");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .map(|_| ())
}

#[cfg(target_os = "linux")]
fn reap_unmanaged_children_once() -> io::Result<usize> {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

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

#[cfg(target_os = "linux")]
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
    use nix::unistd::Pid;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    use tokio::process::Command as TokioCommand;

    #[test]
    fn spawned_child_is_registered_before_returning() {
        let pid = 1_000_000_u32;
        let child = ManagedChild::spawn(|| Ok::<_, ()>(pid), |pid| Some(*pid)).unwrap();

        assert!(is_managed(i32::try_from(child.id().unwrap()).unwrap()));
        drop(child);
        assert!(!is_managed(i32::try_from(pid).unwrap()));
    }

    #[test]
    fn fast_child_remains_waitable_after_orphan_reap_attempt() {
        let mut child = ManagedChild::spawn(
            || Command::new("sh").args(["-c", "exit 11"]).spawn(),
            |child| Some(child.id()),
        )
        .expect("spawn and register fast child");
        let child_pid = child.id().unwrap();
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
        assert!(
            wait.is_ok(),
            "the explicit child waiter must retain the exit status"
        );
        assert!(!is_managed(pid.as_raw()));
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

    #[tokio::test]
    async fn tokio_try_wait_retains_then_releases_management() {
        let mut child = ManagedChild::spawn(
            || {
                let mut command = TokioCommand::new("sh");
                command.args(["-c", "read -r _"]).stdin(Stdio::piped());
                command.spawn()
            },
            tokio::process::Child::id,
        )
        .expect("spawn managed Tokio child");
        let pid = i32::try_from(child.id().unwrap()).unwrap();
        let stdin = child.take_stdin().expect("stdin must be piped");

        assert!(child.try_wait().expect("observe Tokio child").is_none());
        assert!(is_managed(pid), "a running child must remain managed");

        drop(stdin);
        child.wait().await.expect("wait for Tokio child");
        assert!(
            !is_managed(pid),
            "a waited child must release its managed PID"
        );
    }
}

#[cfg(test)]
mod cross_platform_tests {
    use super::ManagedChild;
    use std::process::{Command, Stdio};

    #[test]
    fn managed_child_retains_valid_pid_on_every_platform() {
        let child = ManagedChild::spawn(|| Ok::<_, ()>(1_000_003_u32), |pid| Some(*pid))
            .expect("construct managed child");

        assert_eq!(child.id(), Some(1_000_003));
    }

    #[test]
    fn standard_child_waits_through_managed_wrapper() {
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = ManagedChild::spawn(
            || {
                Command::new(executable)
                    .arg("--help")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            },
            |child| Some(child.id()),
        )
        .expect("spawn test child");

        assert!(child.wait().expect("wait for test child").success());
    }

    #[tokio::test]
    async fn tokio_child_waits_through_managed_wrapper() {
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = ManagedChild::spawn(
            || {
                let mut command = tokio::process::Command::new(executable);
                command
                    .arg("--help")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                command.spawn()
            },
            tokio::process::Child::id,
        )
        .expect("spawn test child");

        assert!(child.wait().await.expect("wait for test child").success());
    }
}
