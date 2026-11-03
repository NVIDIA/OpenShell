// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-directed workload signals delivered through retained pidfds.
//!
//! Linux accepts a worker TID for `kill()`, so scalar seccomp checks against the
//! sandbox leader do not suffice. Resolve the thread group, exclude the live
//! sandbox, and retain the target before delivery. Never continue an inspected
//! numeric PID in another group: it could be reused by a newly created sandbox
//! worker.
//!
//! A self-directed signal, one whose target group is the notifying thread's own
//! group, is continued instead of emulated. After the notification wait the
//! kernel executes the syscall natively, so its result and `siginfo` are the
//! workload's own: an errno such as EAGAIN stays visible, `si_pid`/`si_uid`
//! name the workload rather than the broker, and a handler runs exactly when it
//! would natively. Continuing an inspected numeric TID has the same PID-reuse
//! window as the `tkill` resolve-then-continue precedent below: the target is in
//! the caller's own thread group, and the trusted sandbox leader stays excluded
//! by the earlier `retain_signal_target` deny.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

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
    workload_frozen: &AtomicBool,
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
    refuse_resume_while_frozen(signal, workload_frozen)?;
    let target = u32::try_from(target).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
    let (retained, target_group) = retain_signal_target(target, sandbox_tgid)?;
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
            // Native `rt_sigqueueinfo` overwrites `si_signo` with the syscall
            // signal argument; `pidfd_send_signal` rejects a mismatch with
            // EINVAL.
            info.si_signo = signal;
            &raw const info
        }
        _ => return Err(io::Error::from_raw_os_error(libc::ENOSYS)),
    };
    listener.validate_id(notification.id)?;
    refuse_resume_while_frozen(signal, workload_frozen)?;
    // A self-directed signal is continued so the kernel performs it natively
    // once this notification is answered, never delivered through a pidfd while
    // the notifying thread is still blocked here. Group-directed self-signals
    // also wake every sibling thread in the group, exactly as native delivery
    // does; a sibling blocked in another mediated syscall can then observe
    // EINTR from it (see the `process_sched` module documentation).
    if target_group == thread_group_id(notification.tid)? {
        return listener.respond_continue(notification.id);
    }
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

fn retain_signal_target(tid: u32, sandbox_tgid: u32) -> io::Result<(OwnedFd, u32)> {
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
    Ok((unsafe { OwnedFd::from_raw_fd(fd) }, target_group))
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
    use crate::linux::process_sched::mediate_process_sched;
    use std::sync::atomic::AtomicI32;

    /// Value carried in `sigval.sival_ptr` to prove the queued payload survives.
    const QUEUED_VALUE: usize = 0x5150;

    /// Write end of the report pipe used by the forked child's handler.
    static REPORT_PIPE: AtomicI32 = AtomicI32::new(-1);

    /// Overlay for the `siginfo_t` `_sifields._rt` fields used by `SI_QUEUE`.
    ///
    /// `__pad0` must be spelled out: glibc places it at offset 12 so that
    /// `si_pid` starts at 16, `si_uid` at 20, and the libc `si_value` accessor
    /// at 24. The `value` field therefore sits at the offset `si_value` reads.
    #[repr(C)]
    struct QueuedSiginfo {
        signo: libc::c_int,
        errno: libc::c_int,
        code: libc::c_int,
        pad0: libc::c_int,
        pid: libc::pid_t,
        uid: libc::uid_t,
        value: libc::sigval,
    }

    extern "C" fn report_queued_signal(
        _signal: libc::c_int,
        info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        // SAFETY: an SA_SIGINFO handler receives a live kernel siginfo.
        let (signo, value) = unsafe { ((*info).si_signo, (*info).si_value().sival_ptr.addr()) };
        let record = [signo, i32::try_from(value).unwrap_or(-1)];
        // SAFETY: the report descriptor is an inherited pipe write end and
        // write is async-signal-safe.
        unsafe {
            libc::write(
                REPORT_PIPE.load(Ordering::Relaxed),
                record.as_ptr().cast(),
                size_of_val(&record),
            );
        }
    }

    /// Build a queued-signal `siginfo` whose `si_signo` deliberately differs
    /// from the signal passed to `rt_sigqueueinfo`.
    fn queued_siginfo() -> libc::siginfo_t {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `siginfo_t` starts with the three `c_int` fields then the
        // `_sifields._rt` fields; the overlay is `repr(C)` and stays in bounds.
        unsafe {
            (&raw mut info)
                .cast::<QueuedSiginfo>()
                .write(QueuedSiginfo {
                    signo: libc::SIGUSR2,
                    errno: 0,
                    code: libc::SI_QUEUE,
                    pad0: 0,
                    pid: 0,
                    uid: 0,
                    value: libc::sigval {
                        sival_ptr: std::ptr::without_provenance_mut(QUEUED_VALUE),
                    },
                });
        }
        info
    }

    /// Wait in a forked child for one queued `SIGUSR1`.
    ///
    /// The handler reports the observed `si_signo` and `si_value` through the
    /// inherited pipe. Only async-signal-safe libc calls run here and no Rust
    /// cleanup follows `fork`.
    fn queued_signal_child(read_fd: libc::c_int, write_fd: libc::c_int) -> ! {
        // SAFETY: the child owns its inherited descriptors and reports through
        // the write end only.
        unsafe {
            libc::close(read_fd);
            REPORT_PIPE.store(write_fd, Ordering::Relaxed);
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut blocked);
            libc::sigemptyset(&raw mut empty);
            libc::sigaddset(&raw mut blocked, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &raw const blocked, std::ptr::null_mut());
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = report_queued_signal as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&raw mut action.sa_mask);
            if libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
            // Bound the wait so a missing delivery fails instead of hanging.
            libc::alarm(10);
            let ready = 1_u8;
            if libc::write(write_fd, (&raw const ready).cast(), 1) != 1 {
                libc::_exit(2);
            }
            // Unblocks SIGUSR1 atomically with the wait.
            libc::sigsuspend(&raw const empty);
            libc::_exit(0);
        }
    }

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

    /// A queued signal must reach the target with the requested `si_signo`.
    ///
    /// Native `rt_sigqueueinfo` overwrites `si_signo` with the syscall signal
    /// argument, and `pidfd_send_signal` rejects a mismatched `si_signo` with
    /// EINVAL, so mediation must mirror that overwrite.
    #[test]
    fn queued_signal_preserves_signo_and_value() {
        let mut descriptors = [0_i32; 2];
        // SAFETY: pipe fills both entries of the live array with new FDs.
        assert_eq!(
            unsafe { libc::pipe(descriptors.as_mut_ptr()) },
            0,
            "pipe failed"
        );
        let [read_fd, write_fd] = descriptors;

        // SAFETY: the child body runs only async-signal-safe libc calls before
        // `_exit`, so the multi-threaded test process is safe to fork.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            queued_signal_child(read_fd, write_fd);
        }
        // SAFETY: the parent only reads the report pipe.
        assert_eq!(unsafe { libc::close(write_fd) }, 0, "close failed");

        let mut ready = [0_u8; 1];
        // SAFETY: read fills the live readiness buffer from the inherited pipe.
        let ready_bytes = unsafe { libc::read(read_fd, ready.as_mut_ptr().cast(), 1) };
        assert_eq!(ready_bytes, 1, "child did not install its signal handler");

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let target = u32::try_from(child).expect("child PID fits u32");
        let worker = std::thread::spawn(move || {
            let listener = crate::linux::seccomp_notify::install_workload_listener().unwrap();
            sender.send(listener).unwrap();
            let info = queued_siginfo();
            // SAFETY: `info` outlives the kernel's copy; the worker blocks in
            // the notified syscall until the broker responds.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigqueueinfo,
                    libc::c_long::from(target),
                    libc::c_long::from(libc::SIGUSR1),
                    &raw const info,
                )
            };
            let error = if result < 0 {
                io::Error::last_os_error().raw_os_error()
            } else {
                None
            };
            (result, error)
        });

        let listener = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let notification = listener.receive().unwrap();
        assert_eq!(i64::from(notification.syscall), libc::SYS_rt_sigqueueinfo);
        let mediation = mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        );
        if let Err(error) = &mediation {
            listener
                .respond_errno(notification.id, error.raw_os_error().unwrap_or(libc::EPERM))
                .unwrap();
            // SAFETY: the child is this test's direct descendant and would
            // otherwise wait out its alarm.
            unsafe { libc::kill(child, libc::SIGKILL) };
        }
        let worker_result = worker.join().unwrap();

        let mut status = 0;
        // SAFETY: the child is a live direct descendant of this process.
        assert_eq!(
            unsafe { libc::waitpid(child, &raw mut status, 0) },
            child,
            "waitpid failed"
        );
        let mut observed = [0_i32; 2];
        // SAFETY: read fills the live record buffer; the parent closed the
        // write end, so a child that never reported leaves the pipe at EOF.
        let reported = unsafe {
            libc::read(
                read_fd,
                observed.as_mut_ptr().cast(),
                size_of_val(&observed),
            )
        };
        // SAFETY: this process still owns the read end.
        assert_eq!(unsafe { libc::close(read_fd) }, 0, "close failed");

        assert!(
            mediation.is_ok(),
            "queued signal mediation failed: {:?}",
            mediation.as_ref().err()
        );
        assert_eq!(worker_result, (0, None));
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not exit cleanly: {status}"
        );
        assert_eq!(
            reported,
            isize::try_from(size_of_val(&observed)).unwrap(),
            "child did not report the delivered siginfo"
        );
        assert_eq!(observed[0], libc::SIGUSR1);
        assert_eq!(observed[1], i32::try_from(QUEUED_VALUE).unwrap());
    }

    #[test]
    fn retained_child_can_be_signaled_without_numeric_pid_delivery() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let (retained, target_group) =
            retain_signal_target(child.id(), std::process::id()).unwrap();
        assert_eq!(target_group, child.id());
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

    /// Record one delivered signal through the inherited report pipe.
    extern "C" fn note_delivery(
        _signal: libc::c_int,
        _info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        let byte = 1_u8;
        // SAFETY: the report descriptor is an inherited pipe write end and
        // write is async-signal-safe.
        unsafe {
            libc::write(
                REPORT_PIPE.load(Ordering::Relaxed),
                (&raw const byte).cast(),
                1,
            );
        }
    }

    /// Fork a child of the filtered launcher thread.
    ///
    /// The launcher thread owns the only workload filter, so its child inherits
    /// it and its `kill` is notified while the test thread holds the listener.
    /// The child body must stay async-signal-safe and never return, so no Rust
    /// state is touched in the child after `fork`.
    fn launch_filtered_child(
        launcher: &crate::linux::workload_launcher::WorkloadLauncher,
        child_body: impl FnOnce() + Send + 'static,
    ) -> libc::pid_t {
        launcher
            .execute(move || {
                // SAFETY: see the function contract above; `child_body`
                // diverges, so only the parent returns through the channel.
                let child = unsafe { libc::fork() };
                if child == 0 {
                    child_body();
                    // SAFETY: the child body must not return, but never fall
                    // through into the launcher's channel code if it does.
                    unsafe { libc::_exit(1) };
                }
                child
            })
            .expect("launcher result")
    }

    /// Send `SIGUSR1` to the forked child's own process and wait for it.
    ///
    /// Continuing the notification lets the kernel deliver the signal natively,
    /// so the handler runs exactly when it would without mediation. The child
    /// still waits on the report pipe so a missing delivery fails instead of
    /// passing silently. SIGALRM bounds the wait.
    fn self_signal_child(read_fd: libc::c_int, write_fd: libc::c_int) -> ! {
        // SAFETY: only async-signal-safe libc calls run here and no Rust
        // cleanup follows `fork`.
        unsafe {
            REPORT_PIPE.store(write_fd, Ordering::Relaxed);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = note_delivery as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&raw mut action.sa_mask);
            if libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
            libc::alarm(10);
            let pid = libc::c_long::from(libc::getpid());
            if libc::syscall(libc::SYS_kill, pid, libc::c_long::from(libc::SIGUSR1)) != 0 {
                libc::_exit(3);
            }
            let mut seen = [0_u8; 1];
            if libc::read(read_fd, seen.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(4);
            }
            libc::_exit(0);
        }
    }

    /// Send a queued `SIGUSR1` to the child's own thread group.
    ///
    /// The queued payload deliberately carries a different `si_signo`: native
    /// `rt_sigqueueinfo` overwrites it with the syscall signal argument.
    /// Continuing lets the kernel apply that overwrite natively, so delivery
    /// only succeeds when the continued syscall keeps its signal number. The
    /// child then reads the handler's report and exits with a code that names
    /// the failure.
    fn self_queued_signal_child(read_fd: libc::c_int, write_fd: libc::c_int) -> ! {
        // SAFETY: only async-signal-safe libc calls and stack writes run here;
        // no Rust cleanup follows `fork`.
        unsafe {
            REPORT_PIPE.store(write_fd, Ordering::Relaxed);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = report_queued_signal as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&raw mut action.sa_mask);
            if libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
            libc::alarm(10);
            let info = queued_siginfo();
            let pid = libc::c_long::from(libc::getpid());
            if libc::syscall(
                libc::SYS_rt_sigqueueinfo,
                pid,
                libc::c_long::from(libc::SIGUSR1),
                &raw const info,
            ) != 0
            {
                libc::_exit(3);
            }
            let mut observed = [0_i32; 2];
            let expected = isize::try_from(size_of_val(&observed)).expect("record size fits isize");
            if libc::read(
                read_fd,
                observed.as_mut_ptr().cast(),
                size_of_val(&observed),
            ) != expected
            {
                libc::_exit(4);
            }
            let expected_value = i32::try_from(QUEUED_VALUE).expect("payload fits i32");
            if observed[0] != libc::SIGUSR1 || observed[1] != expected_value {
                libc::_exit(5);
            }
            libc::_exit(0);
        }
    }

    /// Queue a blocked real-time signal with the pending queue exhausted.
    ///
    /// The child lowers its own pending-signal limit with `prlimit64(0, ...)`,
    /// which is itself an own-group mediated call, then queues `SIGRTMIN + 1`
    /// to its own process. The blocked real-time signal cannot be delivered
    /// inline, so the kernel has to queue it and reports EAGAIN once the queue
    /// is full.
    fn queue_limited_signal_child() -> ! {
        // SAFETY: only async-signal-safe libc calls and stack writes run here;
        // no Rust cleanup follows `fork`.
        unsafe {
            libc::alarm(10);
            let signal = libc::SIGRTMIN() + 1;
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut blocked);
            libc::sigaddset(&raw mut blocked, signal);
            if libc::sigprocmask(libc::SIG_BLOCK, &raw const blocked, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::syscall(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_SIGPENDING,
                &raw const limit,
                std::ptr::null_mut::<libc::rlimit>(),
            ) != 0
            {
                libc::_exit(2);
            }
            let mut info: libc::siginfo_t = std::mem::zeroed();
            (&raw mut info)
                .cast::<QueuedSiginfo>()
                .write(QueuedSiginfo {
                    signo: signal,
                    errno: 0,
                    code: libc::SI_QUEUE,
                    pad0: 0,
                    pid: 0,
                    uid: 0,
                    value: libc::sigval {
                        sival_ptr: std::ptr::null_mut(),
                    },
                });
            let pid = libc::c_long::from(libc::getpid());
            let result = libc::syscall(
                libc::SYS_rt_sigqueueinfo,
                pid,
                libc::c_long::from(signal),
                &raw const info,
            );
            let error = *libc::__errno_location();
            libc::_exit(if result == -1 && error == libc::EAGAIN {
                0
            } else {
                3
            });
        }
    }

    /// Deliver `SIGTERM` to a process outside the child's thread group.
    fn foreign_signal_child(target: u32) -> ! {
        // SAFETY: kill takes scalar arguments and the disposable target was
        // spawned by the test.
        unsafe {
            let result = libc::syscall(
                libc::SYS_kill,
                libc::c_long::from(target),
                libc::c_long::from(libc::SIGTERM),
            );
            libc::_exit(if result == 0 { 0 } else { 3 });
        }
    }

    /// A self-directed kill is continued so the kernel performs it natively.
    ///
    /// The notifying thread is still blocked in the notification wait when the
    /// broker decides, so delivering through a pidfd would interrupt the syscall
    /// being emulated. Continuing lets the kernel run the syscall and deliver
    /// the signal itself, and the child exits cleanly once its handler reports
    /// the delivery.
    #[test]
    fn self_directed_signal_is_continued_to_the_kernel() {
        let mut descriptors = [0_i32; 2];
        // SAFETY: pipe fills both entries of the live array with new FDs.
        assert_eq!(
            unsafe { libc::pipe(descriptors.as_mut_ptr()) },
            0,
            "pipe failed"
        );
        let [read_fd, write_fd] = descriptors;

        let (launcher, listener) =
            crate::linux::workload_launcher::start().expect("start launcher");
        let child = launch_filtered_child(&launcher, move || self_signal_child(read_fd, write_fd));
        assert!(child > 0, "fork failed");
        // SAFETY: the child holds its own inherited descriptors.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        let notification = listener.receive().expect("receive self-directed kill");
        assert_eq!(i64::from(notification.syscall), libc::SYS_kill);
        assert_eq!(
            thread_group_id(notification.tid).unwrap(),
            u32::try_from(child).expect("child PID fits u32"),
            "notification must come from the filtered child"
        );
        mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        )
        .expect("self-directed mediation");

        let mut status = 0;
        // SAFETY: the child is this test's direct descendant.
        assert_eq!(
            unsafe { libc::waitpid(child, &raw mut status, 0) },
            child,
            "waitpid failed"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not observe its self-directed signal: {status}"
        );
    }

    /// A self-directed queued signal is continued with its signal number.
    ///
    /// This is the only path where both rules interact: the payload arrives
    /// with a different `si_signo`, which native `rt_sigqueueinfo` overwrites,
    /// and the target group is the notifying thread's own. Continuing lets the
    /// kernel apply both natively, so the handler must observe `SIGUSR1`.
    #[test]
    fn self_directed_queued_signal_is_continued_to_the_kernel() {
        let mut descriptors = [0_i32; 2];
        // SAFETY: pipe fills both entries of the live array with new FDs.
        assert_eq!(
            unsafe { libc::pipe(descriptors.as_mut_ptr()) },
            0,
            "pipe failed"
        );
        let [read_fd, write_fd] = descriptors;

        let (launcher, listener) =
            crate::linux::workload_launcher::start().expect("start launcher");
        let child = launch_filtered_child(&launcher, move || {
            self_queued_signal_child(read_fd, write_fd)
        });
        assert!(child > 0, "fork failed");
        // SAFETY: the child holds its own inherited descriptors.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        let notification = listener
            .receive()
            .expect("receive self-directed queued signal");
        assert_eq!(i64::from(notification.syscall), libc::SYS_rt_sigqueueinfo);
        assert_eq!(
            thread_group_id(notification.tid).unwrap(),
            u32::try_from(child).expect("child PID fits u32"),
            "notification must come from the filtered child"
        );
        mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        )
        .expect("self-directed queued mediation");

        let mut status = 0;
        // SAFETY: the child is this test's direct descendant.
        assert_eq!(
            unsafe { libc::waitpid(child, &raw mut status, 0) },
            child,
            "waitpid failed"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not observe its own queued signal: {status}"
        );
    }

    /// A self-directed queued signal keeps the errno native delivery reports.
    ///
    /// With the workload's real-time signal queue exhausted the kernel cannot
    /// queue the signal and reports EAGAIN. Continuing lets the kernel return
    /// that failure to the workload; answering zero on its behalf would report
    /// a success the native syscall never gives and silently drop the signal.
    #[test]
    fn self_directed_signal_reports_native_delivery_errors() {
        let (launcher, listener) =
            crate::linux::workload_launcher::start().expect("start launcher");
        let child = launch_filtered_child(&launcher, || queue_limited_signal_child());
        assert!(child > 0, "fork failed");

        // The child lowers its pending-signal limit first; that own-group
        // `prlimit64(0, ...)` must be continued before the queued signal.
        let limit = listener.receive().expect("receive self prlimit64");
        assert_eq!(i64::from(limit.syscall), libc::SYS_prlimit64);
        mediate_process_sched(&listener, limit).expect("continue self limit");

        let notification = listener
            .receive()
            .expect("receive self-directed queued signal");
        assert_eq!(i64::from(notification.syscall), libc::SYS_rt_sigqueueinfo);
        assert_eq!(
            thread_group_id(notification.tid).unwrap(),
            u32::try_from(child).expect("child PID fits u32"),
            "notification must come from the filtered child"
        );
        mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        )
        .expect("self-directed queued mediation");

        let mut status = 0;
        // SAFETY: the child is this test's direct descendant.
        assert_eq!(
            unsafe { libc::waitpid(child, &raw mut status, 0) },
            child,
            "waitpid failed"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not observe the native EAGAIN: {status}"
        );
    }

    /// A process-directed kill of another group must deliver and answer zero.
    ///
    /// The target is spawned by the unfiltered test thread so the only notified
    /// syscall is the child's `kill`; an inverted self-group comparison would
    /// answer without delivering and leave the target alive.
    #[test]
    fn foreign_signal_is_delivered_before_the_answer() {
        let mut target = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn target");
        let target_pid = target.id();

        let (launcher, listener) =
            crate::linux::workload_launcher::start().expect("start launcher");
        let child = launch_filtered_child(&launcher, move || foreign_signal_child(target_pid));
        assert!(child > 0, "fork failed");

        let notification = listener.receive().expect("receive foreign kill");
        assert_eq!(i64::from(notification.syscall), libc::SYS_kill);
        assert_eq!(
            thread_group_id(notification.tid).unwrap(),
            u32::try_from(child).expect("child PID fits u32"),
            "notification must come from the filtered child"
        );
        mediate_process_signal(
            &listener,
            notification,
            std::process::id(),
            &AtomicBool::new(false),
        )
        .expect("foreign mediation");

        let mut status = 0;
        // SAFETY: the child is this test's direct descendant.
        assert_eq!(
            unsafe { libc::waitpid(child, &raw mut status, 0) },
            child,
            "waitpid failed"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not observe a successful foreign kill: {status}"
        );
        assert!(!target.wait().unwrap().success(), "target survived SIGTERM");
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
