// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeping QEMU from outliving tmachine.
//!
//! Dropping a VM handle stops QEMU, but a destructor never runs when the
//! process is killed by a signal. Two mechanisms cover that:
//!
//! - On Linux, QEMU asks the kernel to kill it when its parent dies
//!   (`PR_SET_PDEATHSIG`), whatever the reason, including `SIGKILL`.
//! - [`cleanup_on_signals`] kills every tracked QEMU on `SIGTERM`, `SIGINT`
//!   and `SIGHUP` and exits, which also covers hosts without that kernel
//!   feature.
//!
//! A leaked QEMU holds the SSH forward port, so the next run on that host
//! fails until someone kills it by hand.

use std::sync::Mutex;

use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

static LIVE: Mutex<Vec<u32>> = Mutex::new(Vec::new());

pub(super) fn track(pid: u32) {
    if let Ok(mut live) = LIVE.lock() {
        live.push(pid);
    }
}

pub(super) fn forget(pid: u32) {
    if let Ok(mut live) = LIVE.lock() {
        live.retain(|candidate| *candidate != pid);
    }
}

/// Kill every QEMU this process started and has not yet reaped.
fn kill_all() {
    let pids = LIVE.lock().map(|live| live.clone()).unwrap_or_default();
    for pid in pids {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: `kill` has no memory-safety preconditions. A recycled
            // PID is not a concern: entries are removed when the VM handle
            // that owns the child is dropped, and the child is reaped by it.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
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

/// Kill every VM started through tmachine when the process receives
/// `SIGTERM`, `SIGINT` or `SIGHUP`, then exit with the conventional status.
///
/// Call once from a binary's `main`, inside the Tokio runtime.
pub fn cleanup_on_signals() {
    for (kind, number) in [
        (SignalKind::terminate(), libc::SIGTERM),
        (SignalKind::interrupt(), libc::SIGINT),
        (SignalKind::hangup(), libc::SIGHUP),
    ] {
        let Ok(mut stream) = signal(kind) else {
            eprintln!("tmachine: could not install the signal {number} handler; VMs may leak");
            continue;
        };
        tokio::spawn(async move {
            stream.recv().await;
            kill_all();
            std::process::exit(128 + number);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_and_forgets_pids() {
        // Out of range for a `pid_t`, so a concurrent `kill_all` skips them.
        let (kept, dropped) = (u32::MAX - 1, u32::MAX - 2);
        track(kept);
        track(dropped);
        forget(dropped);
        let live = LIVE.lock().unwrap().clone();
        assert!(live.contains(&kept));
        assert!(!live.contains(&dropped));
        forget(kept);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kill_all_stops_tracked_children_and_handlers_install() {
        // Installing handlers must not change behavior until a signal arrives.
        cleanup_on_signals();
        let child = Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        track(pid);
        kill_all();
        let mut child = child;
        let status = child.wait().await.unwrap();
        assert!(!status.success());
        forget(pid);
    }
}
