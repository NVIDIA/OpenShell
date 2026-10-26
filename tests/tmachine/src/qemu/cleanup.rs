// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeping QEMU from outliving tmachine.
//!
//! Dropping a VM handle stops QEMU (`kill_on_drop`). Two mechanisms make sure
//! that happens, or that QEMU dies anyway:
//!
//! - [`until_signal`] drops the work it runs on `SIGTERM`, `SIGINT` or
//!   `SIGHUP`, and with it every VM handle the work holds.
//! - On Linux, QEMU asks the kernel to kill it when its parent dies
//!   (`PR_SET_PDEATHSIG`), which also covers `SIGKILL`.
//!
//! A leaked QEMU holds the SSH forward port, so the next run on that host
//! fails until someone kills it by hand.

use std::future::Future;

use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

/// Run `work` to completion, or until the process receives `SIGTERM`,
/// `SIGINT` or `SIGHUP`. On a signal, `work` is dropped, which stops any VM
/// it started, and the result is the conventional exit status, 128 plus the
/// signal number.
///
/// Wrap a binary's `main` body in this. Blocking calls in `work` must run off
/// the runtime thread, or the signal is not noticed until they return.
///
/// # Panics
///
/// If the runtime can't install the signal handlers.
pub async fn until_signal<T>(work: impl Future<Output = T>) -> Result<T, i32> {
    let stream = |kind| signal(kind).expect("install tmachine signal handler");
    let (mut term, mut int, mut hup) = (
        stream(SignalKind::terminate()),
        stream(SignalKind::interrupt()),
        stream(SignalKind::hangup()),
    );
    tokio::select! {
        result = work => Ok(result),
        _ = term.recv() => Err(128 + libc::SIGTERM),
        _ = int.recv() => Err(128 + libc::SIGINT),
        _ = hup.recv() => Err(128 + libc::SIGHUP),
    }
}

/// Make a child die when this process dies, on platforms that support it.
#[cfg(target_os = "linux")]
pub(super) fn die_with_parent(command: &mut Command) {
    // SAFETY: the closure runs between fork and exec and calls only
    // `prctl`, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            // PR_SET_PDEATHSIG fires when the thread that spawned the child
            // exits, so the runtime must keep its spawning thread alive:
            // tmachine's binaries use a current-thread runtime.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn die_with_parent(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn returns_the_work_result_without_a_signal() {
        assert_eq!(until_signal(async { 7 }).await, Ok(7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_signal_ends_the_work_with_the_conventional_status() {
        let result = until_signal(async {
            // SAFETY: the handlers are installed before `work` is polled, so
            // this signal reaches them instead of terminating the test.
            unsafe { libc::raise(libc::SIGHUP) };
            std::future::pending::<()>().await;
        })
        .await;
        assert_eq!(result, Err(128 + libc::SIGHUP));
    }
}
