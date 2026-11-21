// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker mediation of scheduling, priority, and resource-limit syscalls.
//!
//! A cBPF filter cannot compare an argument against the caller's own thread
//! group, and `SECCOMP_RET_ERRNO` outranks `SECCOMP_USER_NOTIF`, so an errno
//! deny for these syscalls would bypass the broker instead of narrowing the
//! target. A call that names a target is therefore notified and decided here:
//! the kernel performs the operation when it names the caller's own thread
//! group and it is denied with EPERM otherwise. Continuing matches native
//! semantics, where one workload thread may legitimately reconfigure its own
//! affinity, parameters, scheduler, nice value, or limits, and may do the same
//! for a sibling thread or process in its group.
//!
//! A call with `pid == 0` names only the caller, which cBPF can check, so the
//! listener filter runs it natively and never notifies it (see
//! [`MediatedSyscall::caller_only_arguments`]). Those calls keep the
//! non-interruptible behavior they have without mediation, and the
//! `prlimit64(0, ...)` every workload and pty spawn issues before `exec` does
//! not wait on the broker.
//!
//! A named target waits in the same user-notification round trip as `openat`,
//! `connect`, and `sendto`. A signal handled without `SA_RESTART` can therefore
//! surface as EINTR from a call POSIX defines as non-interruptible, and with
//! `SA_RESTART` the call restarts and re-notifies. The broker answers in
//! microseconds, so the practical exposure is a handler installed without
//! `SA_RESTART` that fires during a named-target call.
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
use crate::linux::seccomp_notify::{Notification, NotificationListener, scalar_int};

/// `setpriority` selectors from the Linux UAPI.
///
/// libc types these constants differently per C library (`c_uint` on glibc,
/// `c_int` on musl), so the decoded selector is compared against local values.
const PRIO_PROCESS: u32 = 0;
const PRIO_PGRP: u32 = 1;
const PRIO_USER: u32 = 2;

/// One scheduling, priority, or resource-limit syscall mediated by the broker.
pub(crate) struct MediatedSyscall {
    /// Native syscall number.
    pub(crate) number: i64,
    /// Argument that carries the target PID.
    pub(crate) pid_argument: u8,
    /// `(argument, value)` that must also hold before a zero PID names only
    /// the caller.
    selector: Option<(u8, u32)>,
}

impl MediatedSyscall {
    const fn new(number: i64, pid_argument: u8) -> Self {
        Self {
            number,
            pid_argument,
            selector: None,
        }
    }

    /// `(argument, value)` pairs that all hold exactly when the call can reach
    /// only the calling thread or process.
    ///
    /// The listener filter runs such a call natively. Every value is an `int`
    /// the kernel truncates, so only the low 32 bits of each argument count.
    pub(crate) fn caller_only_arguments(&self) -> impl Iterator<Item = (u8, u32)> {
        self.selector
            .into_iter()
            .chain(std::iter::once((self.pid_argument, 0)))
    }

    /// Whether a zero PID needs a selector argument to name only the caller.
    pub(crate) const fn has_selector(&self) -> bool {
        self.selector.is_some()
    }
}

/// Scheduling, priority, and resource-limit syscalls mediated by the broker.
///
/// `setpriority(which, who, nice)` is the exception to the PID position: its
/// target is argument 1, and `who == 0` names the caller only under
/// `PRIO_PROCESS`. The notified set, its native `pid == 0` path, the broker
/// dispatch, the static child filter, and the decode below all derive from
/// this table, so adding a syscall is a one-place edit and the target position
/// cannot diverge between them.
///
/// The native `pid == 0` path is policy, not only decode: the listener filter
/// allows a caller-only call before the broker sees it. A future broker-side
/// limit on self-directed calls has to drop that path for its entry too.
pub(crate) const MEDIATED_PROCESS_SCHED_SYSCALLS: &[MediatedSyscall] = &[
    MediatedSyscall::new(libc::SYS_prlimit64, 0),
    MediatedSyscall::new(libc::SYS_sched_setaffinity, 0),
    MediatedSyscall::new(libc::SYS_sched_setattr, 0),
    MediatedSyscall::new(libc::SYS_sched_setparam, 0),
    MediatedSyscall::new(libc::SYS_sched_setscheduler, 0),
    MediatedSyscall {
        number: libc::SYS_setpriority,
        pid_argument: 1,
        selector: Some((0, PRIO_PROCESS)),
    },
];

/// Return the table entry for one mediated syscall number.
pub(crate) fn mediated_syscall(syscall: i64) -> Option<&'static MediatedSyscall> {
    MEDIATED_PROCESS_SCHED_SYSCALLS
        .iter()
        .find(|mediated| mediated.number == syscall)
}

/// Whether the broker decides this syscall through [`mediate_process_sched`].
pub(crate) fn is_mediated(syscall: i64) -> bool {
    mediated_syscall(syscall).is_some()
}

/// Continue one scheduling, priority, or resource-limit notification.
///
/// `pid == 0`, and `setpriority(PRIO_PROCESS, 0, ...)`, names the caller. The
/// listener filter runs those calls natively, so they are not expected here;
/// one that arrives anyway is allowed without reading a thread group, since
/// the comparison is vacuous. A named target is resolved through procfs and
/// must share the caller's thread group.
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
/// exists keeps ESRCH too. Any other failure to identify the target, and any
/// failure to identify the caller, fails closed with EPERM.
///
/// A syscall outside the mediated set cannot be decided here, so it fails
/// closed with ENOSYS as an unhandled notification.
pub fn mediate_process_sched(
    listener: &NotificationListener,
    notification: Notification,
) -> io::Result<()> {
    listener.validate_id(notification.id)?;
    let syscall = i64::from(notification.syscall);
    let mediated =
        mediated_syscall(syscall).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?;
    if syscall == libc::SYS_setpriority {
        match scalar_int(notification.args[0]).cast_unsigned() {
            PRIO_PROCESS => {}
            PRIO_PGRP | PRIO_USER => {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
    let target = scalar_int(notification.args[usize::from(mediated.pid_argument)]);
    if target == 0 {
        // The caller names itself, so no thread group has to be read.
        return listener.respond_continue(notification.id);
    }
    if target < 0 {
        return Err(io::Error::from_raw_os_error(negative_target_errno(syscall)));
    }
    let caller_group = resolve_caller_group(notification.tid)?;
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

/// Resolve the notifying thread's group, failing closed on any error.
///
/// The caller is blocked in its notification, so a lookup failure never means
/// "no such target"; it means the comparison cannot be made.
fn resolve_caller_group(tid: u32) -> io::Result<u32> {
    thread_group_id(tid).map_err(|_| io::Error::from_raw_os_error(libc::EPERM))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// No task can hold this TID: it is above the kernel's `PID_MAX_LIMIT`.
    const ABSENT_TID: u32 = u32::MAX;

    #[test]
    fn caller_lookup_fails_closed_while_target_lookup_keeps_esrch() {
        assert_eq!(
            resolve_caller_group(ABSENT_TID).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            resolve_target_group(ABSENT_TID).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn only_setpriority_needs_a_selector_to_name_the_caller() {
        for mediated in MEDIATED_PROCESS_SCHED_SYSCALLS {
            let arguments: Vec<_> = mediated.caller_only_arguments().collect();
            if mediated.number == libc::SYS_setpriority {
                assert_eq!(arguments, [(0, PRIO_PROCESS), (1, 0)]);
            } else {
                assert_eq!(arguments, [(0, 0)]);
            }
        }
    }
}
