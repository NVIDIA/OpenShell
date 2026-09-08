// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One-listener launch thread for capability-free workload descendants.
//!
//! Seccomp filters are per-thread. This launcher installs the networking
//! listener without TSYNC, then serializes every fork/exec operation on that
//! thread. Children inherit the filter while the sandbox's broker and
//! lifecycle threads remain unfiltered. The listener moves to the caller over
//! an in-process channel; no descriptor handoff syscall or reusable exception
//! is needed.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

use super::seccomp_notify::{NotificationListener, install_workload_listener};

type LaunchJob = Box<dyn FnOnce() + Send + 'static>;

/// Serialized child-launch executor whose thread owns the inherited listener
/// filter.
#[derive(Clone)]
pub struct WorkloadLauncher {
    jobs: mpsc::SyncSender<LaunchJob>,
    alive: Arc<AtomicBool>,
}

impl WorkloadLauncher {
    /// Execute one prebuilt spawn operation on the filtered launcher thread.
    ///
    /// The closure must only perform audited launch work. It must not open an
    /// INET socket itself: the launcher is trusted and deliberately has no
    /// notification broker.
    pub fn execute<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> io::Result<T> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "workload launcher is not running",
            ));
        }
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        self.jobs
            .send(Box::new(move || {
                let _ = result_tx.send(operation());
            }))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "workload launcher stopped"))?;
        result_rx.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "workload launcher dropped the spawn result",
            )
        })
    }

    /// Whether the launch thread is still able to accept work.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

/// Start the only workload launcher and return its listener to an unfiltered
/// sandbox thread.
pub fn start() -> io::Result<(WorkloadLauncher, NotificationListener)> {
    let (jobs_tx, jobs_rx) = mpsc::sync_channel::<LaunchJob>(64);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let alive = Arc::new(AtomicBool::new(true));
    let thread_alive = alive.clone();
    thread::Builder::new()
        .name("openshell-workload-launcher".to_string())
        .spawn(move || {
            match install_workload_listener() {
                Ok(listener) => {
                    if ready_tx.send(Ok(listener)).is_err() {
                        thread_alive.store(false, Ordering::Release);
                        return;
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(io::Error::new(
                        error.kind(),
                        format!("install workload listener: {error}"),
                    )));
                    thread_alive.store(false, Ordering::Release);
                    return;
                }
            }
            while let Ok(job) = jobs_rx.recv() {
                job();
            }
            thread_alive.store(false, Ordering::Release);
        })
        .map_err(|error| io::Error::other(format!("start workload launcher thread: {error}")))?;

    let listener = ready_rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "workload launcher exited before publishing its listener",
        )
    })??;
    Ok((
        WorkloadLauncher {
            jobs: jobs_tx,
            alive,
        },
        listener,
    ))
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::mem::size_of;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    use super::*;

    #[test]
    fn one_listener_mediates_launcher_and_inherited_child() {
        let (launcher, listener) = start().expect("start launcher");
        let executable = std::env::current_exe().expect("test executable");
        let mut child = launcher
            .execute(move || {
                let mut command = std::process::Command::new(executable);
                command
                    .arg("--exact")
                    .arg("linux::workload_launcher::tests::inherited_listener_child")
                    .arg("--nocapture")
                    .env("OPENSHELL_WORKLOAD_LAUNCHER_CHILD", "1");
                command.spawn()
            })
            .expect("launcher result")
            .expect("spawn child");
        let notification = listener.receive().expect("receive child socket");
        assert_eq!(i64::from(notification.syscall), libc::SYS_socket);
        assert!(
            std::path::Path::new(&format!("/proc/{}/task/{}", child.id(), notification.tid))
                .exists()
        );
        // SAFETY: eventfd returns one newly owned descriptor on success.
        let eventfd = unsafe { libc::eventfd(7, libc::EFD_CLOEXEC) };
        assert!(eventfd >= 0, "eventfd: {}", io::Error::last_os_error());
        // SAFETY: successful eventfd returned one owned descriptor.
        let eventfd = unsafe { OwnedFd::from_raw_fd(eventfd) };
        listener
            .add_fd_and_send(notification.id, eventfd.as_raw_fd(), true)
            .expect("inject child descriptor");
        assert!(child.wait().expect("wait child").success());
        assert!(launcher.is_alive());
        assert!(listener.as_raw_fd() >= 0);
    }

    #[test]
    fn inherited_listener_child() {
        if std::env::var_os("OPENSHELL_WORKLOAD_LAUNCHER_CHILD").is_none() {
            return;
        }
        // SAFETY: the inherited listener intercepts this scalar socket call
        // and returns the descriptor injected by the parent test.
        let descriptor = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        assert!(descriptor >= 0, "socket: {}", io::Error::last_os_error());
        let mut value = 0_u64;
        // SAFETY: the broker injected an eventfd and `value` is live storage.
        let read = unsafe {
            libc::read(
                descriptor,
                std::ptr::addr_of_mut!(value).cast(),
                size_of::<u64>(),
            )
        };
        // SAFETY: descriptor is owned by this process.
        unsafe { libc::close(descriptor) };
        assert_eq!(
            read,
            isize::try_from(size_of::<u64>()).expect("u64 size fits")
        );
        assert_eq!(value, 7);
    }
}
