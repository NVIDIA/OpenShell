// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracker for sandbox-managed child PIDs.
//!
//! The supervisor spawns several long-lived children (the entrypoint, SSH
//! sessions). Each registers its PID here on spawn and removes it on exit so
//! the orchestrator's `SIGCHLD` reaper can distinguish supervised processes
//! from incidental zombies.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

#[cfg(target_os = "linux")]
static MANAGED_CHILDREN: LazyLock<Mutex<HashSet<i32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(target_os = "linux")]
fn lock_children() -> MutexGuard<'static, HashSet<i32>> {
    MANAGED_CHILDREN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn valid_pid(pid: Option<u32>) -> Option<u32> {
    let pid = pid.and_then(|pid| i32::try_from(pid).ok())?;
    (pid > 0).then(|| u32::try_from(pid).expect("positive i32 fits in u32"))
}

#[cfg(target_os = "linux")]
fn insert(children: &mut HashSet<i32>, pid: Option<u32>) -> Option<u32> {
    let pid = valid_pid(pid)?;
    children.insert(i32::try_from(pid).expect("validated PID fits in i32"));
    Some(pid)
}

/// A child whose exit status is owned by the supervisor.
///
/// The wrapper keeps lifecycle ownership inside the supervisor. On Linux,
/// construction holds the registry lock across the real spawn and PID
/// insertion, so the orphan reaper cannot consume a fast child's status
/// between those operations. Other platforms retain the same API without
/// reaper bookkeeping.
pub struct ManagedChild<C> {
    child: C,
    pid: Option<u32>,
}

impl<C> ManagedChild<C> {
    /// Spawn a supervised child and register its PID before returning it.
    pub fn spawn<E>(
        spawn: impl FnOnce() -> Result<C, E>,
        pid: impl FnOnce(&C) -> Option<u32>,
    ) -> Result<Self, E> {
        #[cfg(target_os = "linux")]
        {
            let mut children = lock_children();
            let child = spawn()?;
            let pid = insert(&mut children, pid(&child));
            Ok(Self { child, pid })
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
    pub const fn id(&self) -> Option<u32> {
        self.pid
    }

    fn unregister(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(pid) = self.pid.take() {
            unregister(pid);
        }

        #[cfg(not(target_os = "linux"))]
        let _ = self.pid.take();
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
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait().await;
        if let Err(error) = &status {
            log_wait_error(self.pid, error);
        }
        self.unregister();
        status
    }

    /// Observe a Tokio child without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
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
    pub fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the child's stdout handle without exposing the child itself.
    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's stderr handle without exposing the child itself.
    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }
}

impl ManagedChild<std::process::Child> {
    /// Wait for a standard-library child and release its managed PID.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait();
        if let Err(error) = &status {
            log_wait_error(self.pid, error);
        }
        self.unregister();
        status
    }

    /// Take the child's stdin handle without exposing the child itself.
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the child's stdout handle without exposing the child itself.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's stderr handle without exposing the child itself.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }
}

/// Remove `pid` from the supervised-child set. Non-positive or out-of-range
/// values are silently ignored.
#[cfg(target_os = "linux")]
fn unregister(pid: u32) {
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
#[cfg(target_os = "linux")]
pub fn reap_if_unmanaged<T>(pid: i32, reap: impl FnOnce() -> T) -> Option<T> {
    let children = lock_children();
    if children.contains(&pid) {
        None
    } else {
        Some(reap())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ManagedChild, reap_if_unmanaged};
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
        let mut reaped = false;

        let result = reap_if_unmanaged(i32::try_from(child.id().unwrap()).unwrap(), || {
            reaped = true;
        });

        assert!(result.is_none());
        assert!(!reaped);
        drop(child);
        assert_eq!(
            reap_if_unmanaged(i32::try_from(pid).unwrap(), || "reaped"),
            Some("reaped")
        );
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
            ManagedChild::spawn(
                || {
                    spawn_entered_tx.send(()).unwrap();
                    complete_spawn_rx.recv().unwrap();
                    Ok::<_, ()>(pid)
                },
                |child| Some(*child),
            )
            .unwrap()
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
        let child = spawn.join().unwrap();
        assert_eq!(reap_result_rx.recv().unwrap(), None);
        reaper.join().unwrap();
        drop(child);
    }

    #[test]
    fn unmanaged_child_can_be_reaped() {
        let result = reap_if_unmanaged(1_000_001, || "reaped");

        assert_eq!(result, Some("reaped"));
    }

    #[test]
    fn fast_child_remains_waitable_after_orphan_reap_attempt() {
        let mut child = ManagedChild::spawn(
            || Command::new("sh").args(["-c", "exit 11"]).spawn(),
            |child| Some(child.id()),
        )
        .expect("spawn and register fast child");
        let pid = Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap());

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
        assert!(
            wait.is_ok(),
            "the explicit child waiter must retain the exit status"
        );
        assert_eq!(
            reap_if_unmanaged(pid.as_raw(), || "reaped"),
            Some("reaped"),
            "a completed child must no longer block orphan reaping"
        );
    }

    #[tokio::test]
    async fn tokio_try_wait_retains_then_releases_management() {
        let mut child = ManagedChild::spawn(
            || {
                let mut command = TokioCommand::new("sh");
                command.args(["-c", "read -r _"]).stdin(Stdio::piped());
                command.spawn()
            },
            |child| child.id(),
        )
        .expect("spawn managed Tokio child");
        let pid = i32::try_from(child.id().unwrap()).unwrap();
        let stdin = child.take_stdin().expect("stdin must be piped");

        assert!(child.try_wait().expect("observe Tokio child").is_none());
        assert_eq!(
            reap_if_unmanaged(pid, || "reaped"),
            None,
            "a running child must remain managed"
        );

        drop(stdin);
        child.wait().await.expect("wait for Tokio child");
        assert_eq!(
            reap_if_unmanaged(pid, || "reaped"),
            Some("reaped"),
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
