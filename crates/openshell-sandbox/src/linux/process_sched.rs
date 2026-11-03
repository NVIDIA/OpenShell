// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker mediation of scheduling, priority, and resource-limit syscalls.
//!
//! A cBPF filter cannot compare an argument against the caller's own thread
//! group, and `SECCOMP_RET_ERRNO` outranks `SECCOMP_USER_NOTIF`, so an errno
//! deny for these syscalls would bypass the broker instead of narrowing the
//! target. They are therefore notified and decided here: the kernel performs
//! the operation when it names the caller's own thread group and it is denied
//! with EPERM otherwise. Continuing matches native semantics, where one
//! workload thread may legitimately reconfigure its own affinity, parameters,
//! scheduler, nice value, or limits, and may do the same for a sibling thread
//! or process in its group.
//!
//! Every workload and pty spawn also round-trips one `prlimit64` notification.
//! The child hardening hook lowers the core limit with rustix `setrlimit`,
//! which compiles to `prlimit64(0, ...)` on Linux, before `exec`. That
//! `pid == 0` call is intentionally mediated and continued; the broker owns
//! the listener from startup, so pre-exec progress depends on broker
//! responsiveness rather than deadlocking on it.
//!
//! Every one of these calls now waits in the same user-notification round trip
//! as `openat`, `connect`, and `sendto`. A signal handled without `SA_RESTART`
//! can therefore surface as EINTR from a call POSIX defines as
//! non-interruptible, and with `SA_RESTART` the call restarts and re-notifies.
//! Python (PEP 475) and Go retry EINTR automatically, and the broker answers in
//! microseconds, so the practical exposure is a raw C handler installed without
//! `SA_RESTART`.
//!
//! This mediation continues an inspected numeric target. Linux offers no
//! pidfd-equivalent for `sched_*`, `prlimit64`, or `setpriority`, so the broker
//! resolves the target through procfs and continues the syscall with that
//! numeric TID. A PID reused between the resolution and kernel execution could
//! therefore redirect the call onto a foreign task of the same UID. The
//! deviation is accepted: it is the same risk class as the `tkill`
//! resolve-then-continue precedent in `process_signal`, the trusted sandbox
//! leader is a live PID the static `sandbox_tgid` equal-deny refuses, and the
//! window is a single broker round trip.

use std::io;

use crate::linux::proc_status::thread_group_id;
use crate::linux::seccomp_notify::{Notification, NotificationListener};

/// Scheduling, priority, and resource-limit syscalls mediated by the broker.
///
/// Each entry pairs the syscall number with the argument that carries the
/// target PID. `setpriority(which, who, nice)` is the exception: its target is
/// argument 1, after the `PRIO_*` selector. The notified set, the broker
/// dispatch, the static child filter, and the decode below all derive from
/// this table, so adding a syscall is a one-place edit and the target position
/// cannot diverge between them.
pub(crate) const MEDIATED_PROCESS_SCHED_SYSCALLS: &[(i64, usize)] = &[
    (libc::SYS_prlimit64, 0),
    (libc::SYS_sched_setaffinity, 0),
    (libc::SYS_sched_setattr, 0),
    (libc::SYS_sched_setparam, 0),
    (libc::SYS_sched_setscheduler, 0),
    (libc::SYS_setpriority, 1),
];

/// Continue one scheduling, priority, or resource-limit notification.
///
/// `pid == 0`, and `setpriority(PRIO_PROCESS, 0, ...)`, names the caller and is
/// always allowed without reading the caller's thread group: the comparison is
/// vacuous. A named target is resolved through procfs and must share the
/// caller's thread group.
///
/// `setpriority` accepts only `PRIO_PROCESS`. `PRIO_USER` with `who = 0` would
/// touch every process of the shared workload UID, and `PRIO_PGRP` with
/// `who = 0` names a process group an untrusted child could rejoin before
/// calling, exactly as the static kill pid-zero deny reasons. Both stay denied
/// with EPERM, while a selector the kernel does not define keeps the native
/// EINVAL.
///
/// A negative target keeps the errno its syscall returns natively: the
/// `sched_setparam`/`sched_setscheduler`/`sched_setattr` trio rejects it with
/// EINVAL before any lookup, while `setpriority`, `prlimit64`, and
/// `sched_setaffinity` fail their lookup with ESRCH. A target that no longer
/// exists keeps ESRCH too. Any other failure to identify the target fails
/// closed with EPERM.
pub fn mediate_process_sched(
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    listener.validate_id(notification.id)?;
    let syscall = i64::from(notification.syscall);
    if syscall == libc::SYS_setpriority {
        match scalar_argument(notification.args[0]).cast_unsigned() {
            libc::PRIO_PROCESS => {}
            libc::PRIO_PGRP | libc::PRIO_USER => {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
    let target = scalar_argument(notification.args[pid_argument_index(syscall)?]);
    if target == 0 {
        // The caller names itself, so no thread group has to be read.
        return listener.respond_continue(notification.id);
    }
    if target < 0 {
        return Err(io::Error::from_raw_os_error(negative_target_errno(syscall)));
    }
    let caller_group = thread_group_id(notification.tid)?;
    if resolve_target_group(target.cast_unsigned())? != caller_group {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    // Continuing an inspected numeric target has the reuse window documented
    // in the module documentation.
    listener.respond_continue(notification.id)
}

/// Return the errno a negative target produces natively for one mediated
/// syscall.
///
/// The `sched_setparam`, `sched_setscheduler`, and `sched_setattr` entry points
/// reject a negative PID with EINVAL before any process lookup, while the other
/// mediated syscalls reach their lookup and fail with ESRCH. Only a syscall from
/// [`MEDIATED_PROCESS_SCHED_SYSCALLS`] reaches this rule.
fn negative_target_errno(syscall: i64) -> i32 {
    match syscall {
        libc::SYS_sched_setparam | libc::SYS_sched_setscheduler | libc::SYS_sched_setattr => {
            libc::EINVAL
        }
        _ => libc::ESRCH,
    }
}

/// Return the argument index carrying the target PID for one mediated syscall.
///
/// A syscall outside the mediated set cannot be decided here, so it fails
/// closed with ENOSYS as an unhandled notification.
fn pid_argument_index(syscall: i64) -> io::Result<usize> {
    MEDIATED_PROCESS_SCHED_SYSCALLS
        .iter()
        .find(|(mediated, _)| *mediated == syscall)
        .map(|&(_, index)| index)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Decode one 32-bit scalar argument the way the kernel does.
///
/// Registers arrive as 64-bit words, but the PID and the `PRIO_*` selector are
/// `int` fields that the kernel truncates. Decoding the same low 32 bits keeps
/// the inspected value equal to the value the kernel would act on, so a
/// sign-extended negative PID is recognized as negative here too.
fn scalar_argument(value: u64) -> i32 {
    let bytes = value.to_ne_bytes();
    #[cfg(target_endian = "little")]
    let scalar = [bytes[0], bytes[1], bytes[2], bytes[3]];
    #[cfg(target_endian = "big")]
    let scalar = [bytes[4], bytes[5], bytes[6], bytes[7]];
    i32::from_ne_bytes(scalar)
}

/// Resolve a named target's thread group, preserving ESRCH and nothing else.
fn resolve_target_group(tid: u32) -> io::Result<u32> {
    thread_group_id(tid).map_err(|error| {
        if error.raw_os_error() == Some(libc::ESRCH) {
            error
        } else {
            io::Error::from_raw_os_error(libc::EPERM)
        }
    })
}
