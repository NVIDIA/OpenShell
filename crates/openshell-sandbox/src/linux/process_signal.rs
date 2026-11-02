// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-directed workload signals delivered through retained pidfds.
//!
//! Linux accepts a worker TID for `kill()`, so scalar seccomp checks against the
//! sandbox leader do not suffice. Resolve the thread group, exclude the live
//! sandbox, and retain the target before delivery. Never continue an inspected
//! numeric PID or process group: either could gain a trusted member after a
//! check and before delivery.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::linux::seccomp_notify::{Notification, NotificationListener};
use crate::linux::task_memory;

/// Emulate one kill or `rt_sigqueueinfo` notification.
///
/// The sandbox and workload must use the same procfs/PID namespace. The
/// sandbox TGID remains live throughout delivery, so an excluded numeric TGID
/// cannot be reused. Group delivery retains and checks every workload member
/// before signaling any of them. Plain kill is broker-originated; queued
/// signals retain their supplied siginfo. Kernel signal permission and siginfo
/// checks still apply.
pub fn mediate_process_signal(
    listener: &NotificationListener,
    notification: Notification,
    sandbox_tgid: u32,
    workload_frozen: &AtomicBool,
) -> io::Result<()> {
    listener.validate_id(notification.id)?;
    let target = scalar_int(notification.args[0]);
    let signal = scalar_int(notification.args[1]);
    if !(0..=64).contains(&signal) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    refuse_resume_while_frozen(signal, workload_frozen)?;
    let retained = if target > 0 {
        let target =
            u32::try_from(target).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
        vec![retain_signal_target(target, sandbox_tgid)?]
    } else {
        retain_group_signal_targets(notification.tid, target, sandbox_tgid)?
    };
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
    let mut delivered = false;
    let mut last_error = io::Error::from_raw_os_error(libc::ESRCH);
    for member in &retained {
        listener.validate_id(notification.id)?;
        refuse_resume_while_frozen(signal, workload_frozen)?;
        // SAFETY: each pidfd retains one checked workload process. The kernel
        // cannot redirect this signal to a later occupant of its numeric PID.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                member.as_raw_fd(),
                signal,
                info_ptr,
                0,
            )
        };
        if result < 0 {
            last_error = io::Error::last_os_error();
        } else {
            delivered = true;
        }
    }
    if !delivered {
        return Err(last_error);
    }
    listener.respond_value(notification.id, 0)
}

#[derive(Clone, Copy)]
struct ProcessStat {
    parent: u32,
    group: u32,
    session: u32,
    start_time: u64,
    live: bool,
}

fn read_process_stat(pid: u32) -> io::Result<ProcessStat> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::from_raw_os_error(libc::ESRCH)
        } else {
            error
        }
    })?;
    // comm can contain spaces and parentheses. Fields after its final ") "
    // start at state (3), then parent (4), pgrp (5), session (6), and start (22).
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM))?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let parse = |index: usize| {
        fields
            .get(index)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM))?
            .parse::<u32>()
            .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))
    };
    Ok(ProcessStat {
        parent: parse(1)?,
        group: parse(2)?,
        session: parse(3)?,
        start_time: fields
            .get(19)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM))?
            .parse()
            .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?,
        live: !matches!(fields.first(), Some(&("Z" | "X" | "x"))),
    })
}

fn workload_root(mut pid: u32, sandbox_tgid: u32) -> io::Result<Option<u32>> {
    for _ in 0..256 {
        let parent = read_process_stat(pid)?.parent;
        if parent == sandbox_tgid {
            return Ok(Some(pid));
        }
        if parent <= 1 {
            return Ok(None);
        }
        pid = parent;
    }
    Ok(None)
}

fn requested_group(target: i32, caller_group: u32) -> io::Result<u32> {
    if target == -1 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let group = if target == 0 {
        caller_group
    } else {
        u32::try_from(
            target
                .checked_neg()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM))?,
        )
        .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?
    };
    if group <= 1 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(group)
}

fn retain_group_signal_targets(
    caller_tid: u32,
    target: i32,
    sandbox_tgid: u32,
) -> io::Result<Vec<OwnedFd>> {
    if sandbox_tgid == 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let calling_process = thread_group_id(caller_tid)?;
    if calling_process == sandbox_tgid {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let caller = read_process_stat(calling_process)?;
    let caller_root = workload_root(calling_process, sandbox_tgid)?
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM))?;
    let group = requested_group(target, caller.group)?;
    if group == read_process_stat(sandbox_tgid)?.group {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    let mut retained = Vec::new();
    let mut caller_member = None;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_process_stat(pid) {
            Ok(stat) => stat,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(error) => return Err(error),
        };
        if stat.group != group || !stat.live {
            continue;
        }
        if pid == sandbox_tgid || stat.session != caller.session {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let member = match retain_signal_target(pid, sandbox_tgid) {
            Ok(member) => member,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(error) => return Err(error),
        };
        let current = match read_process_stat(pid) {
            Ok(current) => current,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(error) => return Err(error),
        };
        if current.start_time != stat.start_time
            || current.group != group
            || current.session != caller.session
            || workload_root(pid, sandbox_tgid)? != Some(caller_root)
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if pid == calling_process {
            caller_member = Some(member);
        } else {
            retained.push(member);
        }
    }
    // A terminating signal to the blocked caller invalidates its seccomp
    // notification. Deliver to other checked members first so validation
    // before each send cannot abandon the rest of the group.
    if let Some(member) = caller_member {
        retained.push(member);
    }
    if retained.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(retained)
}

/// Continue a thread-directed signal (`tkill`, `tgkill`,
/// `rt_tgsigqueueinfo`) aimed at an untrusted workload thread.
///
/// Continuing preserves Linux's thread-directed signal semantics, including
/// the cancellation signal used by musl. The static child filter rejects the
/// sandbox leader as a `tgkill`/`rt_tgsigqueueinfo` group, and the kernel
/// rejects a thread outside the named group, so those two are notified only
/// for `SIGCONT`. A `tkill` names a bare thread, so its group is resolved here;
/// a target reused between this check and continuation stays inside the same
/// PID namespace.
pub fn mediate_thread_signal(
    listener: &NotificationListener,
    notification: Notification,
    sandbox_tgid: u32,
    workload_frozen: &AtomicBool,
) -> io::Result<()> {
    listener.validate_id(notification.id)?;
    let signal = match i64::from(notification.syscall) {
        libc::SYS_tkill => {
            let target = scalar_int(notification.args[0]);
            let signal = scalar_int(notification.args[1]);
            if target <= 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            let target =
                u32::try_from(target).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
            let target_group = thread_group_id(target)?;
            if target_group == sandbox_tgid || target_group == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            signal
        }
        libc::SYS_tgkill | libc::SYS_rt_tgsigqueueinfo => scalar_int(notification.args[2]),
        _ => return Err(io::Error::from_raw_os_error(libc::ENOSYS)),
    };
    if !(0..=64).contains(&signal) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    listener.validate_id(notification.id)?;
    refuse_resume_while_frozen(signal, workload_frozen)?;
    listener.respond_continue(notification.id)
}

/// While the boundary has stopped the workload for supervisor recovery, a
/// workload process that was not yet stopped must not resume the others.
///
/// The flag is read immediately before delivery. The freezer does not wait
/// for in-flight notifications, so a signal already past this check when the
/// freeze begins can still be delivered.
fn refuse_resume_while_frozen(signal: i32, workload_frozen: &AtomicBool) -> io::Result<()> {
    if signal == libc::SIGCONT && workload_frozen.load(Ordering::Acquire) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
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
    let target_group = thread_group_id(tid)?;
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

fn thread_group_id(tid: u32) -> io::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::from_raw_os_error(libc::ESRCH)
        } else {
            error
        }
    })?;
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))
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
        let error = mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
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

    #[test]
    fn group_target_rejects_broadcast_and_init_group() {
        assert_eq!(
            requested_group(-1, 20).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            requested_group(-1, 1).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            requested_group(0, 1).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            requested_group(i32::MIN, 20).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(requested_group(0, 20).unwrap(), 20);
        assert_eq!(requested_group(-21, 20).unwrap(), 21);
    }

    #[test]
    fn group_targets_put_the_blocked_caller_last() {
        use std::io::{BufRead as _, Write as _};
        use std::os::unix::process::CommandExt as _;

        const CHILD_MARKER: &str = "OPENSHELL_GROUP_TARGET_ORDER_CHILD";
        const MEMBER_PREFIX: &str = "OPENSHELL_GROUP_MEMBER=";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let mut sibling = std::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            println!("{MEMBER_PREFIX}{}", sibling.id());
            io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30));
            let _ = sibling.wait();
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux::process_signal::tests::group_targets_put_the_blocked_caller_last",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let caller_pid = child.id();
        // SAFETY: getpgid only inspects the live child created for this test.
        assert_eq!(
            unsafe { libc::getpgid(i32::try_from(caller_pid).unwrap()) },
            i32::try_from(caller_pid).unwrap()
        );
        let reader = io::BufReader::new(child.stdout.take().unwrap());
        let _sibling_pid = reader
            .lines()
            .map(|line| line.unwrap())
            .find_map(|line| line.strip_prefix(MEMBER_PREFIX).map(str::to_owned))
            .expect("child reported group member")
            .parse::<u32>()
            .unwrap();

        let last_pid =
            retain_group_signal_targets(caller_pid, 0, std::process::id()).and_then(|members| {
                assert_eq!(members.len(), 2);
                let last_fd = members.last().unwrap().as_raw_fd();
                let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{last_fd}"))?;
                fdinfo
                    .lines()
                    .find_map(|line| line.strip_prefix("Pid:")?.trim().parse::<u32>().ok())
                    .ok_or_else(|| io::Error::other("pidfd has no Pid field"))
            });
        // SAFETY: this signal targets only the disposable test process group.
        unsafe { libc::kill(-i32::try_from(caller_pid).unwrap(), libc::SIGKILL) };
        child.wait().unwrap();
        assert_eq!(last_pid.unwrap(), caller_pid);
    }
}
