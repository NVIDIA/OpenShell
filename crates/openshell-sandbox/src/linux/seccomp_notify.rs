// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal, typed wrappers for Linux seccomp user notification.
//!
//! The wrappers validate notification IDs around every operation and keep raw
//! UAPI structures private. Production policy and queueing belong to the
//! sandbox crate; this module owns only the kernel ABI and active conformance
//! probe.

#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
/// Linux 5.19: once the listener has received a notification, the notifying
/// task waits for the response in a killable sleep instead of an
/// interruptible one.
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 5;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(any(test, target_arch = "x86_64"))]
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

const CONNECTED_SEND_FLAGS: u32 =
    (libc::MSG_DONTWAIT | libc::MSG_EOR | libc::MSG_MORE | libc::MSG_NOSIGNAL | libc::MSG_OOB)
        as u32;
const PROBE_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Scalar `(level, option)` pairs `setsockopt` may set without a broker round
/// trip.
///
/// The broker decides `setsockopt` from these two scalar arguments alone and
/// continues every pair it does not deny, so allowing an exact pair in the
/// filter returns the same result without waking the broker. The list is a
/// narrow whitelist rather than the complement of the broker's denied set:
/// every other pair, and every call whose level or option does not fit a
/// non-negative C `int`, still notifies and keeps the broker's `EPERM` and
/// `EINVAL` results.
pub(crate) const SETSOCKOPT_FAST_PATH: &[(i32, i32)] = &[
    (libc::IPPROTO_TCP, libc::TCP_NODELAY),
    (libc::SOL_SOCKET, libc::SO_REUSEADDR),
    (libc::SOL_SOCKET, libc::SO_KEEPALIVE),
];

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

#[allow(clippy::cast_possible_truncation)]
const fn ioc(direction: u32, number: u32, size: usize) -> libc::c_ulong {
    ((direction << IOC_DIRSHIFT)
        | (SECCOMP_IOC_MAGIC << IOC_TYPESHIFT)
        | (number << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

const fn iowr<T>(number: u32) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, number, size_of::<T>())
}

const fn iow<T>(number: u32) -> libc::c_ulong {
    ioc(IOC_WRITE, number, size_of::<T>())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawNotification {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawResponse {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawAddFd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawNotificationSizes {
    notification: u16,
    response: u16,
    data: u16,
}

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = iowr::<RawNotification>(0);
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = iowr::<RawResponse>(1);
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = iow::<u64>(2);
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = iow::<RawAddFd>(3);
#[cfg(feature = "perf-harness")]
const SECCOMP_IOCTL_NOTIF_SET_FLAGS: libc::c_ulong = iow::<u64>(4);
#[cfg(feature = "perf-harness")]
const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: libc::c_ulong = 1;

/// One validated seccomp user-notification request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notification {
    /// Kernel-unique notification identifier.
    pub id: u64,
    /// Notifying Linux thread ID.
    pub tid: u32,
    /// Native syscall number.
    pub syscall: i32,
    /// Raw syscall arguments.
    pub args: [u64; 6],
}

/// Result of exercising the unprivileged notification API under the active
/// kernel, outer seccomp profile, and LSM posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationProbeReport {
    features: NotificationProbeFeatures,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NotificationProbeFeatures(u8);

impl NotificationProbeReport {
    /// Whether ID validation and response delivery completed.
    #[must_use]
    pub fn notification_round_trip(self) -> bool {
        self.features.0 & 1 != 0
    }

    /// Whether atomic ADDFD-SEND injected a close-on-exec descriptor.
    #[must_use]
    pub fn addfd_send(self) -> bool {
        self.features.0 & 2 != 0
    }

    /// Whether connected null-destination `sendto` bypassed notification while
    /// destination-bearing and unsafe-flag variants remained mediated.
    #[must_use]
    pub fn connected_send_fast_path(self) -> bool {
        self.features.0 & 4 != 0
    }

    /// Whether whitelisted scalar `setsockopt` pairs bypassed notification
    /// while other pairs and unrepresentable arguments remained mediated.
    #[must_use]
    pub fn scalar_setsockopt_fast_path(self) -> bool {
        self.features.0 & 8 != 0
    }
}

/// Owned listener returned by `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
///
/// Two kinds of listener exist. [`install_listener`] installs one without
/// `WAIT_KILLABLE_RECV`: a signal can interrupt a notified syscall at any
/// time, which the kernel then restarts or fails with `EINTR`, so broker
/// handlers check the notification is still live before acting and answer a
/// repeated operation as the kernel would. [`install_workload_listener`]
/// installs the production listener with `WAIT_KILLABLE_RECV`, because it
/// writes syscall results into the notifying task's memory; see that
/// function for what the flag changes.
pub struct NotificationListener {
    fd: OwnedFd,
}

impl NotificationListener {
    /// Raw listener descriptor for readiness integration and diagnostics.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Ask the kernel to wake this listener synchronously, on the notifying
    /// task's CPU (Linux 6.6 and newer).
    ///
    /// Only the opt-in performance harness can request this. Production
    /// listeners keep the default wakeup: the hint was measured and not
    /// adopted.
    #[cfg(feature = "perf-harness")]
    pub fn enable_sync_wakeup(&self) -> io::Result<()> {
        let request = SECCOMP_IOCTL_NOTIF_SET_FLAGS;
        // musl models the request as `c_int`; the value fits either type.
        #[cfg(target_env = "musl")]
        let request = libc::c_int::from_ne_bytes(
            u32::try_from(request)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "ioctl request exceeds 32 bits")
                })?
                .to_ne_bytes(),
        );
        // SAFETY: this ioctl takes its flags by value, not through a pointer.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                request,
                SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Receive the next kernel notification.
    pub fn receive(&self) -> io::Result<Notification> {
        let mut raw = RawNotification::default();
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_RECV,
            std::ptr::addr_of_mut!(raw).cast(),
        )?;
        Ok(Notification {
            id: raw.id,
            tid: raw.pid,
            syscall: raw.data.nr,
            args: raw.data.args,
        })
    }

    /// Verify that a notification still refers to a blocked live task.
    pub fn validate_id(&self, id: u64) -> io::Result<()> {
        let mut id = id;
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            std::ptr::addr_of_mut!(id).cast(),
        )?;
        Ok(())
    }

    /// Return a successful scalar result to the notifying syscall.
    pub fn respond_value(&self, id: u64, value: i64) -> io::Result<()> {
        self.validate_id(id)?;
        let mut response = RawResponse {
            id,
            val: value,
            error: 0,
            flags: 0,
        };
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::addr_of_mut!(response).cast(),
        )?;
        Ok(())
    }

    /// Return `errno` to the notifying syscall.
    pub fn respond_errno(&self, id: u64, errno: i32) -> io::Result<()> {
        if errno <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seccomp response errno must be positive",
            ));
        }
        self.validate_id(id)?;
        let mut response = RawResponse {
            id,
            val: 0,
            error: -errno,
            flags: 0,
        };
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::addr_of_mut!(response).cast(),
        )?;
        Ok(())
    }

    /// Continue a verified local-kernel operation in the notifying task.
    ///
    /// Callers must not use this for an external INET operation or where a
    /// mutable workload pointer is part of the authorization decision.
    pub fn respond_continue(&self, id: u64) -> io::Result<()> {
        self.validate_id(id)?;
        let mut response = RawResponse {
            id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::addr_of_mut!(response).cast(),
        )?;
        Ok(())
    }

    /// Atomically inject `source` and complete the notifying syscall with the
    /// allocated target FD. The target receives `O_CLOEXEC` when requested.
    pub fn add_fd_and_send(
        &self,
        notification_id: u64,
        source: RawFd,
        close_on_exec: bool,
    ) -> io::Result<RawFd> {
        self.validate_id(notification_id)?;
        let srcfd = u32::try_from(source)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source FD is negative"))?;
        let mut addfd = RawAddFd {
            id: notification_id,
            flags: SECCOMP_ADDFD_FLAG_SEND,
            srcfd,
            newfd: 0,
            newfd_flags: if close_on_exec {
                u32::try_from(libc::O_CLOEXEC).map_err(io::Error::other)?
            } else {
                0
            },
        };
        ioctl_ptr(
            self.fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_ADDFD,
            std::ptr::addr_of_mut!(addfd).cast(),
        )
        .and_then(|fd| {
            RawFd::try_from(fd).map_err(|_| io::Error::other("injected FD does not fit RawFd"))
        })
    }
}

/// Install a non-TSYNC listener filter on the calling thread.
///
/// Only the named syscalls notify. Unexpected architectures are killed, x32
/// syscalls are killed on x86-64, and all other native syscalls are allowed.
pub fn install_listener(syscalls: &[i64]) -> io::Result<NotificationListener> {
    if syscalls.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one notified syscall is required",
        ));
    }
    let mut syscalls = syscalls.to_vec();
    syscalls.sort_unstable();
    syscalls.dedup();
    let rules = syscalls
        .into_iter()
        .map(FilterRule::Notify)
        .collect::<Vec<_>>();
    install_rules(&rules, ListenerWait::Interruptible)
}

/// Install a listener for exactly `syscalls` with `WAIT_KILLABLE_RECV`, the
/// production wait mode, so tests can observe that mode in isolation.
#[cfg(test)]
pub(crate) fn install_wait_killable_listener(syscalls: &[i64]) -> io::Result<NotificationListener> {
    let rules = syscalls
        .iter()
        .map(|syscall| FilterRule::Notify(*syscall))
        .collect::<Vec<_>>();
    install_rules(&rules, ListenerWait::KillableOnceReceived)
}

/// Install the capability-free workload listener on the calling launcher
/// thread.
///
/// The filter mediates every syscall that can create, select, or materially
/// reconfigure an INET endpoint. Connected `send()`/null-destination
/// `sendto()` retains the audited cBPF fast path. `accept`/`accept4` run
/// natively: the broker binds every INET socket to loopback before injecting
/// it, and accepted sockets inherit their listener's binding. `setsockopt`
/// allows the [`SETSOCKOPT_FAST_PATH`] pairs in the filter. Every `open`,
/// `openat`, and `openat2` notifies, and so does every path-based metadata
/// call in [`metadata_syscalls`]: the broker serves provider and CA trust
/// files by descriptor injection and answers their metadata by writing the
/// result into the caller's buffer.
///
/// That write is why the listener is installed with `WAIT_KILLABLE_RECV`: a
/// task can have only one listener (a second fails with `EBUSY`), so the
/// flag covers every notified syscall. Before the broker receives a
/// notification, signals interrupt the syscall as before. Once received,
/// only a fatal signal ends the wait; a handled signal is delivered after the
/// broker responds. A `connect` awaiting the supervisor's network admission
/// decision therefore ignores handled `SIGALRM` and `SIGINT` until the broker
/// answers or its 30-second decision timeout fails the call; DNS relay waits
/// are bounded at 10 seconds. A blocking loopback `connect` is completed by
/// the broker with a native `libc::connect` on a duplicate of the socket and
/// waits for the kernel's connect timeout, which can exceed 30 seconds.
/// Fatal signals still terminate the task throughout. In return, a received
/// notification ends only by response or death, so a written result can never
/// land in a stack frame the task has left.
pub fn install_workload_listener() -> io::Result<NotificationListener> {
    install_rules(&workload_filter_rules(), ListenerWait::KillableOnceReceived)
}

/// How a notifying task waits for the broker's response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerWait {
    /// Any signal interrupts the wait at any time.
    Interruptible,
    /// `WAIT_KILLABLE_RECV`: only a fatal signal interrupts the wait once the
    /// broker has received the notification.
    KillableOnceReceived,
}

/// Qualify the notification ABI, set `no_new_privs` on the calling thread,
/// and install `rules` there.
fn install_rules(rules: &[FilterRule], wait: ListenerWait) -> io::Result<NotificationListener> {
    verify_notification_sizes()?;
    set_no_new_privileges()?;
    install_notification_filter(rules, wait)
}

/// The path-based metadata syscalls the workload listener notifies.
///
/// `newfstatat`, `statx`, `faccessat`, and `faccessat2`, plus the legacy
/// `stat`, `lstat`, and `access` entry points on x86-64. Descriptor based
/// calls (`fstat`, `statx` with an empty path) are not among them: an
/// injected descriptor answers them in the kernel.
pub fn metadata_syscalls() -> Vec<i64> {
    #[allow(unused_mut)] // The legacy entry points exist only on x86-64.
    let mut syscalls = vec![
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
    ];
    #[cfg(target_arch = "x86_64")]
    syscalls.extend([libc::SYS_stat, libc::SYS_lstat, libc::SYS_access]);
    syscalls
}

/// Whether `syscall` is one of [`metadata_syscalls`].
#[must_use]
pub fn is_metadata_syscall(syscall: i64) -> bool {
    if matches!(
        syscall,
        libc::SYS_newfstatat | libc::SYS_statx | libc::SYS_faccessat | libc::SYS_faccessat2
    ) {
        return true;
    }
    #[cfg(target_arch = "x86_64")]
    if matches!(syscall, libc::SYS_stat | libc::SYS_lstat | libc::SYS_access) {
        return true;
    }
    false
}

fn workload_filter_rules() -> Vec<FilterRule> {
    #[allow(unused_mut)] // SYS_open is unavailable on some architectures.
    let mut syscalls = vec![
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_setsockopt,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_openat,
        libc::SYS_openat2,
    ];
    #[cfg(target_arch = "x86_64")]
    syscalls.push(libc::SYS_open);
    syscalls.extend(metadata_syscalls());
    syscalls
        .into_iter()
        .map(|syscall| {
            if syscall == libc::SYS_setsockopt {
                return FilterRule::ScalarSetsockopt;
            }
            FilterRule::Notify(syscall)
        })
        .collect()
}

/// One syscall's treatment in a listener filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilterRule {
    /// Notify with the syscall's standing treatment: connected `sendto` and
    /// non-`SIGCONT` thread signals keep their audited fast paths.
    Notify(i64),
    /// `setsockopt`, allowing only [`SETSOCKOPT_FAST_PATH`] pairs natively.
    ScalarSetsockopt,
}

impl FilterRule {
    const fn syscall(self) -> i64 {
        match self {
            Self::Notify(syscall) => syscall,
            Self::ScalarSetsockopt => libc::SYS_setsockopt,
        }
    }
}

/// Run a no-capability conformance probe.
///
/// This uses the production launcher-thread shape: the listener is created on
/// one dedicated thread and moved to an unfiltered broker thread through an
/// in-process channel.
pub fn probe_notification_api() -> io::Result<NotificationProbeReport> {
    probe_scalar_round_trip()?;
    probe_addfd_send()?;
    probe_connected_sendto_fast_path()?;
    probe_scalar_setsockopt_fast_path()?;
    Ok(NotificationProbeReport {
        features: NotificationProbeFeatures(1 | 2 | 4 | 8),
    })
}

fn probe_scalar_round_trip() -> io::Result<()> {
    const PROBE_VALUE: libc::c_long = 0x5a17;
    let (sender, receiver) = mpsc::sync_channel(1);
    let launcher = thread::spawn(move || -> io::Result<libc::c_long> {
        let listener = install_listener(&[libc::SYS_getppid])?;
        sender
            .send(listener)
            .map_err(|_| io::Error::other("notification broker disappeared"))?;
        // SAFETY: getppid has no pointer arguments. The installed filter causes
        // the kernel to block here until the broker validates and responds.
        Ok(unsafe { libc::syscall(libc::SYS_getppid) })
    });

    let Ok(listener) = receiver.recv() else {
        return Err(launcher_failure(launcher, "notification"));
    };
    let notification = match receive_probe_notification(&listener) {
        Ok(notification) => notification,
        Err(error) => {
            let _ = launcher.join();
            return Err(error);
        }
    };
    if i64::from(notification.syscall) != libc::SYS_getppid {
        return Err(io::Error::other("unexpected scalar probe syscall"));
    }
    listener.respond_value(notification.id, PROBE_VALUE)?;
    let observed = launcher
        .join()
        .map_err(|_| io::Error::other("notification launcher panicked"))??;
    if observed != PROBE_VALUE {
        return Err(io::Error::other("seccomp response value was not delivered"));
    }
    Ok(())
}

fn probe_addfd_send() -> io::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let launcher = thread::spawn(move || -> io::Result<()> {
        let listener = install_listener(&[libc::SYS_socket])?;
        sender
            .send(listener)
            .map_err(|_| io::Error::other("ADDFD broker disappeared"))?;
        // SAFETY: arguments are scalar constants; the intercepted syscall is
        // completed by ADDFD-SEND and returns the injected descriptor number.
        let injected = unsafe {
            libc::syscall(
                libc::SYS_socket,
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        if injected < 0 {
            return Err(io::Error::last_os_error());
        }
        let injected = RawFd::try_from(injected)
            .map_err(|_| io::Error::other("injected descriptor does not fit RawFd"))?;
        // SAFETY: ADDFD-SEND returned one newly owned descriptor to this task.
        let injected = unsafe { OwnedFd::from_raw_fd(injected) };
        let descriptor_flags = rustix::io::fcntl_getfd(&injected)?;
        if !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(io::Error::other("ADDFD did not preserve close-on-exec"));
        }
        let mut value = [0_u8; size_of::<u64>()];
        let read = rustix::io::read(&injected, &mut value[..]);
        if read != Ok(value.len()) || u64::from_ne_bytes(value) != 7 {
            return Err(io::Error::other("injected eventfd was not usable"));
        }
        Ok(())
    });

    let Ok(listener) = receiver.recv() else {
        return Err(launcher_failure(launcher, "ADDFD"));
    };
    let notification = match receive_probe_notification(&listener) {
        Ok(notification) => notification,
        Err(error) => {
            let _ = launcher.join();
            return Err(error);
        }
    };
    if i64::from(notification.syscall) != libc::SYS_socket {
        return Err(io::Error::other("unexpected ADDFD probe syscall"));
    }
    let source = rustix::event::eventfd(7, rustix::event::EventfdFlags::CLOEXEC)?;
    listener.add_fd_and_send(notification.id, source.as_raw_fd(), true)?;
    launcher
        .join()
        .map_err(|_| io::Error::other("ADDFD launcher panicked"))??;
    Ok(())
}

fn probe_connected_sendto_fast_path() -> io::Result<()> {
    let (sender_fd, receiver_fd) = std::os::unix::net::UnixStream::pair()?;

    let (sender, receiver) = mpsc::sync_channel(1);
    let launcher = thread::spawn(move || -> io::Result<()> {
        let listener = install_listener(&[libc::SYS_sendto])?;
        sender
            .send(listener)
            .map_err(|_| io::Error::other("sendto broker disappeared"))?;

        let direct = b"direct";
        // SAFETY: the buffer is live and a null destination on this connected
        // socket is equivalent to send(). The filter must allow this call
        // without a broker round trip.
        let sent = unsafe {
            libc::sendto(
                sender_fd.as_raw_fd(),
                direct.as_ptr().cast(),
                direct.len(),
                libc::MSG_NOSIGNAL,
                std::ptr::null(),
                0,
            )
        };
        if sent != isize::try_from(direct.len()).map_err(io::Error::other)? {
            return Err(io::Error::last_os_error());
        }

        let mut payload = [0_u8; 6];
        let read = rustix::io::read(&receiver_fd, &mut payload[..]);
        if read != Ok(payload.len()) || &payload != direct {
            return Err(io::Error::other(
                "connected sendto fast path did not relay data",
            ));
        }

        let destination = libc::sockaddr_un {
            sun_family: libc::sa_family_t::try_from(libc::AF_UNIX).map_err(io::Error::other)?,
            sun_path: [0; 108],
        };
        // SAFETY: all pointers refer to live values. This deliberately
        // destination-bearing call must be denied by the broker.
        let result = unsafe {
            libc::sendto(
                sender_fd.as_raw_fd(),
                direct.as_ptr().cast(),
                direct.len(),
                0,
                std::ptr::addr_of!(destination).cast(),
                libc::socklen_t::try_from(size_of::<libc::sa_family_t>())
                    .map_err(io::Error::other)?,
            )
        };
        if result != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return Err(io::Error::other(
                "destination-bearing sendto bypassed notification",
            ));
        }

        // A null destination with Fast Open must not use the connected-send
        // fast path either.
        // SAFETY: the live buffer and null address form a valid syscall; the
        // broker supplies the expected denial.
        let result = unsafe {
            libc::sendto(
                sender_fd.as_raw_fd(),
                direct.as_ptr().cast(),
                direct.len(),
                libc::MSG_FASTOPEN,
                std::ptr::null(),
                0,
            )
        };
        if result != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EOPNOTSUPP) {
            return Err(io::Error::other(
                "MSG_FASTOPEN sendto bypassed notification",
            ));
        }
        Ok(())
    });

    let Ok(listener) = receiver.recv() else {
        return Err(launcher_failure(launcher, "sendto"));
    };
    let destination = match receive_probe_notification(&listener) {
        Ok(notification) => notification,
        Err(error) => {
            let _ = launcher.join();
            return Err(error);
        }
    };
    if i64::from(destination.syscall) != libc::SYS_sendto
        || destination.args[4] == 0
        || destination.args[5] == 0
    {
        return Err(io::Error::other(
            "destination-bearing sendto notification was malformed",
        ));
    }
    listener.respond_errno(destination.id, libc::EACCES)?;

    let fast_open = match receive_probe_notification(&listener) {
        Ok(notification) => notification,
        Err(error) => {
            let _ = launcher.join();
            return Err(error);
        }
    };
    if i64::from(fast_open.syscall) != libc::SYS_sendto
        || fast_open.args[4] != 0
        || fast_open.args[5] != 0
        || fast_open.args[3] & u64::from(libc::MSG_FASTOPEN as u32) == 0
    {
        return Err(io::Error::other(
            "Fast Open sendto notification was malformed",
        ));
    }
    listener.respond_errno(fast_open.id, libc::EOPNOTSUPP)?;

    launcher
        .join()
        .map_err(|_| io::Error::other("sendto launcher panicked"))??;
    Ok(())
}

/// Raw `setsockopt` whose level and option keep all 64 argument bits, so the
/// probe can present values a C `int` prototype would truncate.
fn raw_setsockopt(fd: RawFd, level: u64, option: u64) -> io::Result<()> {
    let value: libc::c_int = 1;
    // SAFETY: the value pointer and length describe one live C int.
    let result = unsafe {
        libc::syscall(
            libc::SYS_setsockopt,
            fd,
            level,
            option,
            std::ptr::addr_of!(value),
            size_of::<libc::c_int>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn expect_errno(result: io::Result<()>, errno: i32, what: &str) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(errno) => Ok(()),
        Ok(()) => Err(io::Error::other(format!("{what} unexpectedly succeeded"))),
        Err(error) => Err(io::Error::other(format!(
            "{what} returned {error} instead of errno {errno}"
        ))),
    }
}

const fn unsigned_argument(value: libc::c_int) -> u64 {
    value.unsigned_abs() as u64
}

fn probe_scalar_setsockopt_fast_path() -> io::Result<()> {
    const HIGH_WORD: u64 = 1 << 32;
    const ABOVE_INT_MAX: u64 = 0x8000_0000;
    let (socket, _peer) = std::os::unix::net::UnixStream::pair()?;
    let level_tcp = unsigned_argument(libc::IPPROTO_TCP);
    let level_socket = unsigned_argument(libc::SOL_SOCKET);
    let nodelay = unsigned_argument(libc::TCP_NODELAY);
    let reuse = unsigned_argument(libc::SO_REUSEADDR);
    let bind_device = unsigned_argument(libc::SO_BINDTODEVICE);

    let (sender, receiver) = mpsc::sync_channel(1);
    let launcher = thread::spawn(move || -> io::Result<()> {
        let listener = install_rules(&[FilterRule::ScalarSetsockopt], ListenerWait::Interruptible)?;
        sender
            .send(listener)
            .map_err(|_| io::Error::other("setsockopt broker disappeared"))?;
        let fd = socket.as_raw_fd();
        // Whitelisted pairs run in the kernel. SO_REUSEADDR succeeds on any
        // socket; TCP_NODELAY on this UNIX socket returns the kernel's own
        // EOPNOTSUPP, which no broker response in this probe produces.
        raw_setsockopt(fd, level_socket, reuse)?;
        expect_errno(
            raw_setsockopt(fd, level_tcp, nodelay),
            libc::EOPNOTSUPP,
            "native TCP_NODELAY on a UNIX socket",
        )?;
        // Everything else notifies, in this order.
        expect_errno(
            raw_setsockopt(fd, level_socket, bind_device),
            libc::EPERM,
            "denied socket option",
        )?;
        expect_errno(
            raw_setsockopt(fd, level_tcp | HIGH_WORD, nodelay),
            libc::EINVAL,
            "socket option level with a nonzero upper word",
        )?;
        expect_errno(
            raw_setsockopt(fd, level_tcp, nodelay | HIGH_WORD),
            libc::EINVAL,
            "socket option name with a nonzero upper word",
        )?;
        expect_errno(
            raw_setsockopt(fd, level_tcp, nodelay | ABOVE_INT_MAX),
            libc::EINVAL,
            "socket option name above INT_MAX",
        )
    });

    let Ok(listener) = receiver.recv() else {
        return Err(launcher_failure(launcher, "setsockopt"));
    };
    for (level, option, errno) in [
        (level_socket, bind_device, libc::EPERM),
        (level_tcp | HIGH_WORD, nodelay, libc::EINVAL),
        (level_tcp, nodelay | HIGH_WORD, libc::EINVAL),
        (level_tcp, nodelay | ABOVE_INT_MAX, libc::EINVAL),
    ] {
        let notification = match receive_probe_notification(&listener) {
            Ok(notification) => notification,
            Err(error) => {
                // A launcher that failed on its own explains the missing
                // notification better than the timeout does.
                return Err(match launcher.join() {
                    Ok(Err(launcher_error)) => launcher_error,
                    _ => error,
                });
            }
        };
        if i64::from(notification.syscall) != libc::SYS_setsockopt
            || notification.args[1] != level
            || notification.args[2] != option
        {
            let _ = listener.respond_errno(notification.id, libc::EIO);
            let _ = launcher.join();
            return Err(io::Error::other(
                "scalar setsockopt fast path notified an unexpected call",
            ));
        }
        listener.respond_errno(notification.id, errno)?;
    }
    launcher
        .join()
        .map_err(|_| io::Error::other("setsockopt launcher panicked"))??;
    Ok(())
}

/// Recover the real error from a probe launcher that exited before handing its
/// listener to the broker.
///
/// The launcher owns the only `install_listener` result, so a failed install
/// just closes the handover channel. Join the thread to report the kernel's
/// refusal, including the errno that identifies a restrictive host. Return
/// that error unchanged rather than reformatting it, so `raw_os_error` still
/// reports the kernel's errno to callers that branch on it.
fn launcher_failure<T>(launcher: thread::JoinHandle<io::Result<T>>, role: &str) -> io::Error {
    match launcher.join() {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => io::Error::other(format!(
            "{role} launcher exited before sending its listener"
        )),
        Err(_) => io::Error::other(format!("{role} launcher panicked")),
    }
}

fn receive_probe_notification(listener: &NotificationListener) -> io::Result<Notification> {
    use std::os::fd::AsFd as _;

    let mut descriptors = [nix::poll::PollFd::new(
        listener.fd.as_fd(),
        nix::poll::PollFlags::POLLIN | nix::poll::PollFlags::POLLHUP,
    )];
    let timeout =
        nix::poll::PollTimeout::try_from(PROBE_NOTIFICATION_TIMEOUT).map_err(io::Error::other)?;
    let ready = nix::poll::poll(&mut descriptors, timeout)?;
    if ready == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "seccomp notification probe timed out",
        ));
    }
    if !descriptors[0]
        .revents()
        .unwrap_or_else(nix::poll::PollFlags::empty)
        .contains(nix::poll::PollFlags::POLLIN)
    {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "seccomp notification probe listener closed",
        ));
    }
    listener.receive()
}

fn install_notification_filter(
    rules: &[FilterRule],
    wait: ListenerWait,
) -> io::Result<NotificationListener> {
    let mut program = build_filter(rules)?;
    let length = u16::try_from(program.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seccomp filter is too large"))?;
    let mut fprog = libc::sock_fprog {
        len: length,
        filter: program.as_mut_ptr(),
    };
    let flags = match wait {
        ListenerWait::Interruptible => SECCOMP_FILTER_FLAG_NEW_LISTENER,
        ListenerWait::KillableOnceReceived => {
            SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
        }
    };
    // SAFETY: `fprog` points to a live classic-BPF program for the duration of
    // the syscall. The returned nonnegative value is a newly owned FD.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            std::ptr::addr_of_mut!(fprog),
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if wait == ListenerWait::KillableOnceReceived && error.raw_os_error() == Some(libc::EINVAL)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "kernel refused SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV ({error}); the sandbox requires Linux 5.19 or newer with user-notification wait-killable support"
                ),
            ));
        }
        return Err(error);
    }
    let fd = RawFd::try_from(result)
        .map_err(|_| io::Error::other("seccomp listener FD does not fit RawFd"))?;
    // SAFETY: successful NEW_LISTENER returns one newly owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(NotificationListener { fd })
}

fn build_filter(rules: &[FilterRule]) -> io::Result<Vec<libc::sock_filter>> {
    let mut program = vec![
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, native_audit_arch(), 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];

    #[cfg(target_arch = "x86_64")]
    program.extend([
        jump(BPF_JMP_JSET_K, X32_SYSCALL_BIT, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
    ]);

    // One rule per syscall, in ascending syscall order. A syscall named twice
    // is rejected rather than letting the first block silently win.
    let mut rules = rules.to_vec();
    rules.sort_unstable_by_key(|rule| rule.syscall());
    if rules
        .windows(2)
        .any(|pair| pair[0].syscall() == pair[1].syscall())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seccomp filter names a syscall more than once",
        ));
    }
    for rule in rules {
        let syscall = match rule {
            FilterRule::Notify(syscall) => syscall,
            FilterRule::ScalarSetsockopt => {
                append_setsockopt_filter(&mut program)?;
                continue;
            }
        };
        if syscall == libc::SYS_sendto {
            append_sendto_filter(&mut program)?;
            continue;
        }
        if matches!(syscall, libc::SYS_tgkill | libc::SYS_rt_tgsigqueueinfo) {
            append_resume_signal_filter(&mut program, syscall)?;
            continue;
        }
        let syscall = u32::try_from(syscall)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative syscall number"))?;
        program.extend([
            jump(BPF_JMP_JEQ_K, syscall, 0, 1),
            stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        ]);
    }
    program.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    Ok(program)
}

fn append_sendto_filter(program: &mut Vec<libc::sock_filter>) -> io::Result<()> {
    const SPECIAL_LENGTH: u8 = 20;
    let syscall = u32::try_from(libc::SYS_sendto)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative sendto syscall"))?;
    program.push(jump(BPF_JMP_JEQ_K, syscall, 0, SPECIAL_LENGTH));

    for offset in [
        argument_word_offset(4, 0),
        argument_word_offset(4, 1),
        argument_word_offset(5, 0),
        argument_word_offset(5, 1),
        argument_word_offset(3, 1),
    ] {
        program.extend([
            stmt(BPF_LD_W_ABS, offset),
            jump(BPF_JMP_JEQ_K, 0, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        ]);
    }
    program.extend([
        stmt(BPF_LD_W_ABS, argument_word_offset(3, 0)),
        stmt(BPF_ALU_AND_K, !CONNECTED_SEND_FLAGS),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    Ok(())
}

/// Allow exactly the [`SETSOCKOPT_FAST_PATH`] pairs; notify everything else.
///
/// The kernel reads `level` and `optname` as C `int`s, ignoring the upper
/// argument words. The broker instead refuses any value that does not fit a
/// non-negative `i32` with `EINVAL`, so a nonzero upper word must notify
/// rather than be compared by its low word. Whitelisted values are small
/// positive constants, so an exact low-word match with a zero upper word is
/// exactly a value the broker would accept and continue.
fn append_setsockopt_filter(program: &mut Vec<libc::sock_filter>) -> io::Result<()> {
    const HIGH_WORD_CHECKS: usize = 6;
    const PAIR_LENGTH: usize = 5;
    let syscall = u32::try_from(libc::SYS_setsockopt)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative setsockopt syscall"))?;
    let body = HIGH_WORD_CHECKS + PAIR_LENGTH * SETSOCKOPT_FAST_PATH.len() + 1;
    let skip = u8::try_from(body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "setsockopt filter too long"))?;
    program.push(jump(BPF_JMP_JEQ_K, syscall, 0, skip));
    for argument in [1, 2] {
        program.extend([
            stmt(BPF_LD_W_ABS, argument_word_offset(argument, 1)),
            jump(BPF_JMP_JEQ_K, 0, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        ]);
    }
    for (level, option) in SETSOCKOPT_FAST_PATH {
        let level = u32::try_from(*level).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "negative socket option level")
        })?;
        let option = u32::try_from(*option).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "negative socket option name")
        })?;
        program.extend([
            stmt(BPF_LD_W_ABS, argument_word_offset(1, 0)),
            jump(BPF_JMP_JEQ_K, level, 0, 3),
            stmt(BPF_LD_W_ABS, argument_word_offset(2, 0)),
            jump(BPF_JMP_JEQ_K, option, 0, 1),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]);
    }
    program.push(stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF));
    Ok(())
}

/// Notify a thread-group signal only when it sends `SIGCONT`, which the broker
/// refuses while the workload is frozen. Every other signal (for example Go's
/// preemption signal) stays in the kernel.
fn append_resume_signal_filter(
    program: &mut Vec<libc::sock_filter>,
    syscall: i64,
) -> io::Result<()> {
    let syscall = u32::try_from(syscall)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative syscall number"))?;
    let resume = u32::try_from(libc::SIGCONT)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative signal number"))?;
    program.extend([
        jump(BPF_JMP_JEQ_K, syscall, 0, 4),
        stmt(BPF_LD_W_ABS, argument_word_offset(2, 0)),
        jump(BPF_JMP_JEQ_K, resume, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    Ok(())
}

const fn argument_word_offset(argument: u32, word: u32) -> u32 {
    SECCOMP_DATA_ARGS_OFFSET + argument * 8 + word * 4
}

#[cfg(target_arch = "x86_64")]
const fn native_audit_arch() -> u32 {
    0xc000_003e
}

#[cfg(target_arch = "aarch64")]
const fn native_audit_arch() -> u32 {
    0xc000_00b7
}

const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt,
        jf,
        k: value,
    }
}

fn set_no_new_privileges() -> io::Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS accepts scalar arguments and only tightens
    // the calling thread's privilege behavior.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn verify_notification_sizes() -> io::Result<()> {
    let mut sizes = RawNotificationSizes::default();
    // SAFETY: the kernel writes only the fixed-size `RawNotificationSizes`
    // object supplied here.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            std::ptr::addr_of_mut!(sizes),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    for (name, kernel, local) in [
        (
            "notification",
            usize::from(sizes.notification),
            size_of::<RawNotification>(),
        ),
        (
            "response",
            usize::from(sizes.response),
            size_of::<RawResponse>(),
        ),
        ("data", usize::from(sizes.data), size_of::<SeccompData>()),
    ] {
        if kernel != local {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel seccomp {name} size {kernel} differs from supported size {local}"),
            ));
        }
    }
    Ok(())
}

fn ioctl_ptr(fd: RawFd, request: libc::c_ulong, argument: *mut libc::c_void) -> io::Result<i64> {
    // `libc::ioctl` models the request as `c_ulong` for glibc and `c_int`
    // for musl. Linux UAPI request values fit both representations.
    #[cfg(target_env = "musl")]
    let request = u32::try_from(request).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "ioctl request exceeds 32 bits")
    })?;
    #[cfg(target_env = "musl")]
    let request = libc::c_int::from_ne_bytes(request.to_ne_bytes());
    // SAFETY: every caller supplies the UAPI structure encoded into `request`,
    // alive and writable for the ioctl duration.
    let result = unsafe { libc::ioctl(fd, request, argument) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(i64::from(result))
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::process::Command;

    use super::*;

    const NONDUMPABLE_PROBE_CHILD: &str = "OPENSHELL_NONDUMPABLE_PROBE_CHILD";
    const REJECTED_INSTALL_PROBE_CHILD: &str = "OPENSHELL_REJECTED_INSTALL_PROBE_CHILD";

    #[test]
    fn filter_rejects_empty_syscall_set() {
        let error = install_listener(&[]).err().expect("empty filter must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// Evaluate a classic-BPF seccomp program over one syscall, supporting
    /// exactly the instructions this module emits.
    fn evaluate(program: &[libc::sock_filter], syscall: i64, args: [u64; 6]) -> u32 {
        let data = SeccompData {
            nr: i32::try_from(syscall).unwrap(),
            arch: native_audit_arch(),
            instruction_pointer: 0,
            args,
        };
        let word = |offset: u32| -> u32 {
            let offset = offset as usize;
            if offset == 0 {
                return data.nr.cast_unsigned();
            }
            if offset == 4 {
                return data.arch;
            }
            let index = (offset - 16) / 8;
            let value = data.args[index];
            if (offset - 16).is_multiple_of(8) {
                (value & 0xffff_ffff) as u32
            } else {
                (value >> 32) as u32
            }
        };
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        loop {
            let instruction = program[pc];
            pc += 1;
            match instruction.code {
                BPF_LD_W_ABS => accumulator = word(instruction.k),
                BPF_ALU_AND_K => accumulator &= instruction.k,
                BPF_RET_K => return instruction.k,
                BPF_JMP_JEQ_K | BPF_JMP_JSET_K => {
                    let taken = if instruction.code == BPF_JMP_JEQ_K {
                        accumulator == instruction.k
                    } else {
                        accumulator & instruction.k != 0
                    };
                    pc += usize::from(if taken {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                other => panic!("unsupported BPF opcode {other:#x}"),
            }
        }
    }

    fn arg(value: i32) -> u64 {
        u64::from(value.cast_unsigned())
    }

    #[test]
    fn workload_filter_allows_only_whitelisted_scalar_setsockopt() {
        const HIGH: u64 = 1 << 32;
        {
            let program = build_filter(&workload_filter_rules()).unwrap();
            let decide = |level: u64, option: u64| {
                evaluate(
                    &program,
                    libc::SYS_setsockopt,
                    [3, level, option, 0x7000_0000_1000, 4, 0],
                )
            };
            for (level, option) in SETSOCKOPT_FAST_PATH {
                let (level, option) = (arg(*level), arg(*option));
                assert_eq!(decide(level, option), SECCOMP_RET_ALLOW);
                // The broker refuses values outside a non-negative i32 with
                // EINVAL; none of them may take the fast path.
                for (level, option) in [
                    (level | HIGH, option),
                    (level, option | HIGH),
                    (level | 0x8000_0000, option),
                    (level, option | 0x8000_0000),
                    (level | (u64::MAX << 32), option),
                    (option, level),
                ] {
                    if SETSOCKOPT_FAST_PATH
                        .iter()
                        .any(|pair| (arg(pair.0), arg(pair.1)) == (level, option))
                    {
                        continue;
                    }
                    assert_eq!(
                        decide(level, option),
                        SECCOMP_RET_USER_NOTIF,
                        "{level:#x}/{option:#x}"
                    );
                }
            }
            // Every pair outside the whitelist notifies, including each
            // denied option and other benign ones.
            for (level, option) in [
                (libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
                (libc::SOL_SOCKET, libc::SO_BINDTOIFINDEX),
                (libc::IPPROTO_IP, libc::IP_UNICAST_IF),
                (libc::IPPROTO_IP, libc::IP_MULTICAST_IF),
                (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_IF),
                (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF),
                (libc::IPPROTO_IPV6, libc::IPV6_ADDRFORM),
                (libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT),
                (libc::IPPROTO_TCP, libc::TCP_FASTOPEN),
                (libc::SOL_SOCKET, libc::SO_RCVBUF),
                (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
                (libc::IPPROTO_IP, libc::TCP_NODELAY),
                (libc::IPPROTO_TCP, libc::SO_REUSEADDR),
            ] {
                assert_eq!(
                    decide(arg(level), arg(option)),
                    SECCOMP_RET_USER_NOTIF,
                    "{level}/{option}"
                );
            }
        }
    }

    #[test]
    fn workload_filter_keeps_precedence_around_the_new_fast_paths() {
        let unsupported_arch = |program: &[libc::sock_filter]| {
            // A foreign architecture is killed before any syscall rule.
            let mut pc = 0;
            assert_eq!(program[pc].code, BPF_LD_W_ABS);
            assert_eq!(program[pc].k, SECCOMP_DATA_ARCH_OFFSET);
            pc += 1;
            assert_eq!(program[pc].k, native_audit_arch());
            assert_eq!(program[pc + 1].k, SECCOMP_RET_KILL_PROCESS);
        };
        {
            let program = build_filter(&workload_filter_rules()).unwrap();
            unsupported_arch(&program);
            let decide = |syscall: i64, args: [u64; 6]| evaluate(&program, syscall, args);
            // Mediated syscalls on either side of setsockopt and openat in
            // number order still notify; unrelated syscalls are allowed.
            for syscall in [
                libc::SYS_socket,
                libc::SYS_connect,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_sendmsg,
                libc::SYS_sendmmsg,
                libc::SYS_kill,
                libc::SYS_tkill,
                libc::SYS_rt_sigqueueinfo,
                libc::SYS_openat2,
            ] {
                assert_eq!(decide(syscall, [0; 6]), SECCOMP_RET_USER_NOTIF, "{syscall}");
            }
            for syscall in [libc::SYS_getpid, libc::SYS_read, libc::SYS_getsockopt] {
                assert_eq!(decide(syscall, [0; 6]), SECCOMP_RET_ALLOW, "{syscall}");
            }
            // The audited sendto and resume-signal paths are unchanged.
            assert_eq!(
                decide(libc::SYS_sendto, [3, 1, 1, 0, 0, 0]),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                decide(libc::SYS_sendto, [3, 1, 1, 0, 0x1000, 16]),
                SECCOMP_RET_USER_NOTIF
            );
            assert_eq!(
                decide(libc::SYS_tgkill, [1, 1, arg(libc::SIGCONT), 0, 0, 0]),
                SECCOMP_RET_USER_NOTIF
            );
            assert_eq!(
                decide(libc::SYS_tgkill, [1, 1, arg(libc::SIGURG), 0, 0, 0]),
                SECCOMP_RET_ALLOW
            );
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                evaluate(
                    &program,
                    libc::SYS_setsockopt | i64::from(X32_SYSCALL_BIT),
                    [3, arg(libc::IPPROTO_TCP), arg(libc::TCP_NODELAY), 0, 4, 0]
                ),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn workload_filter_notifies_every_open() {
        let program = build_filter(&workload_filter_rules()).unwrap();
        for flags in [
            libc::O_RDONLY,
            libc::O_RDONLY | libc::O_CLOEXEC,
            libc::O_RDONLY | libc::O_DIRECTORY,
            libc::O_WRONLY,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        ] {
            assert_eq!(
                evaluate(&program, libc::SYS_openat, [0, 0x1000, arg(flags), 0, 0, 0]),
                SECCOMP_RET_USER_NOTIF,
                "{flags:#o}"
            );
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                evaluate(&program, libc::SYS_open, [0x1000, arg(flags), 0, 0, 0, 0]),
                SECCOMP_RET_USER_NOTIF,
                "{flags:#o}"
            );
        }
        assert_eq!(
            evaluate(&program, libc::SYS_openat2, [0, 0x1000, 0x2000, 24, 0, 0]),
            SECCOMP_RET_USER_NOTIF
        );
    }

    #[test]
    fn workload_filter_notifies_every_metadata_syscall() {
        let program = build_filter(&workload_filter_rules()).unwrap();
        for syscall in metadata_syscalls() {
            assert!(is_metadata_syscall(syscall));
            assert_eq!(
                evaluate(&program, syscall, [0x1000, 0x2000, 0, 0, 0, 0]),
                SECCOMP_RET_USER_NOTIF,
                "{syscall}"
            );
        }
        // Descriptor-based metadata stays in the kernel.
        assert_eq!(
            evaluate(&program, libc::SYS_fstat, [3, 0x1000, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert!(!is_metadata_syscall(libc::SYS_fstat));
    }

    const WAIT_KILLABLE_CHILD: &str = "OPENSHELL_WAIT_KILLABLE_CHILD";
    const WAIT_KILLABLE_MARKER: &CStr = c"/openshell-wait-killable-marker";
    const CHILD_INTERRUPTED: i32 = 7;
    static HANDLED_SIGNALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn count_handled_signal(_: libc::c_int) {
        HANDLED_SIGNALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Child of [`wait_killable_listener_defers_handled_signals_until_the_response`]:
    /// a notified `faccessat` of the marker path with a `SIGUSR1` handler
    /// installed, then a second one that is only ever ended by `SIGKILL`.
    fn wait_killable_child() -> ! {
        let marker_access = || {
            // SAFETY: the marker path is a live NUL-terminated string.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_faccessat,
                    libc::AT_FDCWD,
                    WAIT_KILLABLE_MARKER.as_ptr(),
                    libc::F_OK,
                    0,
                )
            };
            (result, io::Error::last_os_error().raw_os_error())
        };
        // SAFETY: a plain handler without SA_RESTART, so an interruptible
        // wait reports EINTR instead of restarting.
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = count_handled_signal as *const () as usize;
            libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask));
            libc::sigaction(
                libc::SIGUSR1,
                std::ptr::addr_of!(action),
                std::ptr::null_mut(),
            )
        };
        if installed != 0 {
            std::process::exit(2);
        }
        match marker_access() {
            (-1, Some(libc::EINTR)) => std::process::exit(CHILD_INTERRUPTED),
            (-1, Some(libc::EACCES))
                if HANDLED_SIGNALS.load(std::sync::atomic::Ordering::SeqCst) == 1 => {}
            _ => std::process::exit(3),
        }
        let _ = marker_access();
        std::process::exit(4);
    }

    /// Run the child under a `faccessat` listener of the given kind and
    /// report `(notification still valid after SIGUSR1, child exit status)`.
    fn observe_signal_during_notification(wait_killable: bool) -> (bool, std::process::ExitStatus) {
        let executable = std::env::current_exe().expect("test executable");
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let listener = if wait_killable {
                install_wait_killable_listener(&[libc::SYS_faccessat])
            } else {
                install_listener(&[libc::SYS_faccessat])
            }
            .expect("install listener");
            let child = Command::new(executable)
                .arg("--exact")
                .arg("linux::seccomp_notify::tests::wait_killable_listener_defers_handled_signals_until_the_response")
                .arg("--nocapture")
                .env(WAIT_KILLABLE_CHILD, "1")
                .spawn()
                .expect("spawn child");
            sender.send((listener, child)).expect("hand over");
        });
        let (listener, mut child) = receiver.recv().expect("listener and child");
        let marker_notification = || {
            loop {
                let notification = receive_probe_notification(&listener).expect("notification");
                let mut path = [0_u8; 32];
                let marker = WAIT_KILLABLE_MARKER.to_bytes_with_nul();
                if crate::linux::task_memory::read_exact(
                    notification.tid,
                    notification.args[1],
                    &mut path[..marker.len()],
                )
                .is_ok()
                    && &path[..marker.len()] == marker
                {
                    return notification;
                }
                listener
                    .respond_continue(notification.id)
                    .expect("continue startup access");
            }
        };

        let first = marker_notification();
        // SAFETY: a thread-directed signal to the notifying task.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_tgkill, child.id(), first.tid, libc::SIGUSR1) },
            0
        );
        thread::sleep(Duration::from_millis(300));
        let still_valid = listener.validate_id(first.id).is_ok();
        if still_valid {
            listener
                .respond_errno(first.id, libc::EACCES)
                .expect("answer the first access");
            let second = marker_notification();
            child.kill().expect("kill child");
            let status = child.wait().expect("wait child");
            assert_eq!(
                listener.validate_id(second.id).unwrap_err().raw_os_error(),
                Some(libc::ENOENT),
                "a killed task ends its notification"
            );
            // A result for a dead notification is neither written nor an
            // error: there is no task left to answer.
            crate::provider_files::complete_with_result(&listener, &second, 0x1000, &[0; 16])
                .expect("dead notification completes quietly");
            return (true, status);
        }
        (false, child.wait().expect("wait child"))
    }

    #[test]
    fn wait_killable_listener_defers_handled_signals_until_the_response() {
        use std::os::unix::process::ExitStatusExt as _;
        if std::env::var_os(WAIT_KILLABLE_CHILD).is_some() {
            wait_killable_child();
        }
        // Production listener: the handled signal waits for the response,
        // and only SIGKILL ends the second notification.
        let (still_valid, status) = observe_signal_during_notification(true);
        assert!(still_valid);
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{status}");
        // Interruptible listener: the same signal ends the notification and
        // the syscall fails with EINTR.
        let (still_valid, status) = observe_signal_during_notification(false);
        assert!(!still_valid);
        assert_eq!(status.code(), Some(CHILD_INTERRUPTED), "{status}");
    }

    #[test]
    fn filter_rejects_a_syscall_named_twice() {
        let error = build_filter(&[
            FilterRule::Notify(libc::SYS_setsockopt),
            FilterRule::ScalarSetsockopt,
        ])
        .expect_err("duplicate syscall must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn active_notification_probe_passes() {
        let report = probe_notification_api().expect("active notification probe");
        assert!(report.scalar_setsockopt_fast_path());
        assert!(report.notification_round_trip());
        assert!(report.addfd_send());
        assert!(report.connected_send_fast_path());
    }

    #[test]
    fn notification_probe_ignores_unavailable_self_task_memory() {
        if std::env::var_os(NONDUMPABLE_PROBE_CHILD).is_some() {
            // Match the production broker posture and Kata kernels that omit
            // CONFIG_CROSS_MEMORY_ATTACH. The notification API probe must not
            // inspect this trusted process through /proc/self/mem: a
            // nondumpable non-root process cannot open that file, while the
            // separately qualified dumpable workload child remains readable.
            if rustix::process::geteuid().as_raw() == 0 {
                // SAFETY: this disposable subprocess permanently drops its
                // supplementary groups and root identity before probing.
                assert_eq!(unsafe { libc::setgroups(0, std::ptr::null()) }, 0);
                assert_eq!(unsafe { libc::setgid(65_534) }, 0);
                assert_eq!(unsafe { libc::setuid(65_534) }, 0);
            }
            // SAFETY: PR_SET_DUMPABLE accepts one scalar flag and only
            // tightens this disposable test process.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let self_mem_error = std::fs::File::open("/proc/self/mem")
                .expect_err("nondumpable unprivileged self memory must be inaccessible");
            assert_eq!(self_mem_error.kind(), io::ErrorKind::PermissionDenied);
            install_process_vm_enosys_filter().expect("install process-VM ENOSYS filter");
            probe_notification_api().expect("probe notification API without self task memory");
            return;
        }

        let executable = std::env::current_exe().expect("resolve test executable");
        let status = Command::new(executable)
            .arg("--exact")
            .arg("linux::seccomp_notify::tests::notification_probe_ignores_unavailable_self_task_memory")
            .arg("--nocapture")
            .env(NONDUMPABLE_PROBE_CHILD, "1")
            .status()
            .expect("run disposable nondumpable probe process");
        assert!(status.success(), "nondumpable probe child failed: {status}");
    }

    #[test]
    fn notification_probe_reports_rejected_listener_install() {
        if std::env::var_os(REJECTED_INSTALL_PROBE_CHILD).is_some() {
            // Model a host that refuses the listener install with EPERM.
            // The install happens on the launcher thread, so the probe must
            // join that thread to report the kernel's refusal instead of only
            // observing a closed channel.
            install_set_mode_filter_eperm_filter().expect("install SET_MODE_FILTER EPERM filter");
            let error = probe_notification_api().expect_err("rejected install must fail the probe");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(
                error.to_string().contains("os error 1"),
                "probe error must carry the install errno, got: {error}"
            );
            return;
        }

        let executable = std::env::current_exe().expect("resolve test executable");
        let status = Command::new(executable)
            .arg("--exact")
            .arg("linux::seccomp_notify::tests::notification_probe_reports_rejected_listener_install")
            .arg("--nocapture")
            .env(REJECTED_INSTALL_PROBE_CHILD, "1")
            .status()
            .expect("run disposable rejected-install probe process");
        assert!(
            status.success(),
            "rejected-install probe child failed: {status}"
        );
    }

    /// Refuse `seccomp(SECCOMP_SET_MODE_FILTER, ...)` with `EPERM` while the
    /// notification size query keeps working, so `install_listener` fails the
    /// way a restrictive host does.
    fn install_set_mode_filter_eperm_filter() -> io::Result<()> {
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        let seccomp_number = u32::try_from(libc::SYS_seccomp)
            .map_err(|_| io::Error::other("syscall number does not fit u32"))?;
        let mut instructions = [
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(BPF_JMP_JEQ_K, seccomp_number, 0, 3),
            stmt(BPF_LD_W_ABS, argument_word_offset(0, 0)),
            jump(BPF_JMP_JEQ_K, SECCOMP_SET_MODE_FILTER, 0, 1),
            stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM.unsigned_abs()),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ];
        let length = u16::try_from(instructions.len())
            .map_err(|_| io::Error::other("test seccomp filter is too large"))?;
        let mut program = libc::sock_fprog {
            len: length,
            filter: instructions.as_mut_ptr(),
        };
        set_no_new_privileges()?;
        // SAFETY: program references the complete live test filter. No flags
        // are required because the disposable process has one calling thread.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0,
                std::ptr::addr_of_mut!(program),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn install_process_vm_enosys_filter() -> io::Result<()> {
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        let syscall_number = |number: libc::c_long| {
            u32::try_from(number).map_err(|_| io::Error::other("syscall number does not fit u32"))
        };
        let mut instructions = [
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(
                BPF_JMP_JEQ_K,
                syscall_number(libc::SYS_process_vm_readv)?,
                0,
                1,
            ),
            stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS.unsigned_abs()),
            jump(
                BPF_JMP_JEQ_K,
                syscall_number(libc::SYS_process_vm_writev)?,
                0,
                1,
            ),
            stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS.unsigned_abs()),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ];
        let length = u16::try_from(instructions.len())
            .map_err(|_| io::Error::other("test seccomp filter is too large"))?;
        let mut program = libc::sock_fprog {
            len: length,
            filter: instructions.as_mut_ptr(),
        };
        set_no_new_privileges()?;
        // SAFETY: program references the complete live test filter. No flags
        // are required because the disposable process has one calling thread.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0,
                std::ptr::addr_of_mut!(program),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[test]
    fn errno_response_rejects_nonpositive_values() {
        // The input validation occurs before the listener FD is used.
        let duplicated =
            rustix::io::dup(io::stderr()).expect("duplicate stderr for validation test");
        let listener = NotificationListener { fd: duplicated };
        let error = listener
            .respond_errno(1, 0)
            .expect_err("zero errno must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
