// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-directed workload signals delivered through retained pidfds.
//!
//! Linux accepts a worker TID for `kill()`, so scalar seccomp checks against the
//! sandbox leader do not suffice. Resolve the thread group, exclude the live
//! sandbox, and retain the target before delivery. Never continue an inspected
//! numeric PID: it could be reused by a newly created sandbox worker.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::linux::seccomp_notify::{Notification, NotificationListener};
use crate::linux::task_memory;

/// Emulate one positive-target kill or `rt_sigqueueinfo` notification.
///
/// The sandbox and workload must use the same procfs/PID namespace. The
/// sandbox TGID remains live throughout delivery, so an excluded numeric TGID
/// cannot be reused. Group/broadcast signaling remains deliberately denied.
/// Plain kill is broker-originated; queued signals retain their supplied
/// siginfo. Kernel signal permission and siginfo checks still apply.
pub fn mediate_process_signal(
    listener: &NotificationListener,
    notification: Notification,
    sandbox_tgid: u32,
) -> io::Result<()> {
    listener.validate_id(notification.id)?;
    let target = scalar_int(notification.args[0]);
    let signal = scalar_int(notification.args[1]);
    if target <= 0 || !(0..=64).contains(&signal) {
        return Err(io::Error::from_raw_os_error(if target <= 0 {
            libc::EPERM
        } else {
            libc::EINVAL
        }));
    }
    let target = u32::try_from(target).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
    let retained = retain_signal_target(target, sandbox_tgid)?;
    // SAFETY: all-zero siginfo consists of valid integer/pointer fields. A
    // queued operation copies the entire object once before it is consumed.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let info_ptr = match i64::from(notification.syscall) {
        libc::SYS_kill => std::ptr::null(),
        libc::SYS_rt_sigqueueinfo => {
            // SAFETY: bytes exclusively spans the live siginfo object; all bit
            // patterns are valid and task_memory requires a complete copy.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    (&raw mut info).cast::<u8>(),
                    size_of::<libc::siginfo_t>(),
                )
            };
            task_memory::read_exact(notification.tid, notification.args[2], bytes)?;
            // Positive/kernel-origin and SI_TKILL codes cannot be impersonated.
            if info.si_code >= 0 || info.si_code == libc::SI_TKILL {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            &raw const info
        }
        _ => return Err(io::Error::from_raw_os_error(libc::ENOSYS)),
    };
    listener.validate_id(notification.id)?;
    // SAFETY: retained owns a live pidfd; info is null or a complete trusted
    // copy. The kernel targets that process object, never a reused numeric PID.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            retained.as_raw_fd(),
            signal,
            info_ptr,
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    listener.respond_value(notification.id, 0)
}

fn scalar_int(value: u64) -> i32 {
    let bytes = value.to_ne_bytes();
    #[cfg(target_endian = "little")]
    let scalar = [bytes[0], bytes[1], bytes[2], bytes[3]];
    #[cfg(target_endian = "big")]
    let scalar = [bytes[4], bytes[5], bytes[6], bytes[7]];
    i32::from_ne_bytes(scalar)
}

fn retain_signal_target(tid: u32, sandbox_tgid: u32) -> io::Result<OwnedFd> {
    if sandbox_tgid == 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    let target_group = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
    if target_group == sandbox_tgid || target_group == 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    // SAFETY: pidfd_open takes only scalar arguments and returns a new owned FD.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target_group, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(|_| io::Error::other("pidfd does not fit RawFd"))?;
    // SAFETY: successful pidfd_open transferred this descriptor to the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_worker_cannot_signal_the_sandbox_through_a_tid() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let listener = crate::linux::seccomp_notify::install_workload_listener().unwrap();
            sender.send(listener).unwrap();
            // SAFETY: gettid has no arguments; signal zero checks permission
            // without delivering a signal to the disposable test thread.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let result = unsafe { libc::syscall(libc::SYS_kill, tid, 0) };
            (result, io::Error::last_os_error().raw_os_error())
        });
        let listener = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let notification = listener.receive().unwrap();
        let error =
            mediate_process_signal(&listener, notification, std::process::id()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        listener
            .respond_errno(notification.id, libc::EPERM)
            .unwrap();
        assert_eq!(worker.join().unwrap(), (-1, Some(libc::EPERM)));
    }

    #[test]
    fn retained_child_can_be_signaled_without_numeric_pid_delivery() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let retained = retain_signal_target(child.id(), std::process::id()).unwrap();
        // SAFETY: this pidfd owns the disposable child launched by this test.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    retained.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
        assert!(!child.wait().unwrap().success());
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    retained.as_raw_fd(),
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            -1
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn rejects_live_sandbox_worker_tid() {
        let sandbox_tgid = std::process::id();
        std::thread::spawn(move || {
            // SAFETY: gettid has no arguments or side effects.
            let tid = u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
            assert_ne!(tid, sandbox_tgid);
            assert_eq!(
                retain_signal_target(tid, sandbox_tgid)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn rejects_leader_and_preserves_scalar_pid_semantics() {
        let pid = std::process::id();
        assert_eq!(
            retain_signal_target(pid, pid).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(scalar_int(u64::MAX), -1);
        assert_eq!(scalar_int(1 << 32 | 0x7b), 123);
    }
}
