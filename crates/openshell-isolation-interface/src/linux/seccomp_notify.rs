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

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 5;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

const CONNECTED_SEND_FLAGS: u32 =
    (libc::MSG_DONTWAIT | libc::MSG_EOR | libc::MSG_MORE | libc::MSG_NOSIGNAL | libc::MSG_OOB)
        as u32;

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
    /// Whether `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` was accepted.
    pub wait_killable_recv: bool,
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

    /// Whether process-VM read and write syscalls are admitted for same-process
    /// memory, before the stronger child-credential probe runs in a driver.
    #[must_use]
    pub fn task_memory_copy(self) -> bool {
        self.features.0 & 4 != 0
    }

    /// Whether connected null-destination `sendto` bypassed notification while
    /// destination-bearing and unsafe-flag variants remained mediated.
    #[must_use]
    pub fn connected_send_fast_path(self) -> bool {
        self.features.0 & 8 != 0
    }
}

/// Owned listener returned by `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub struct NotificationListener {
    fd: OwnedFd,
    wait_killable_recv: bool,
}

impl NotificationListener {
    /// Whether the listener was installed with killable receive waits.
    #[must_use]
    pub fn wait_killable_recv(&self) -> bool {
        self.wait_killable_recv
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
                u32::try_from(libc::O_CLOEXEC).expect("O_CLOEXEC fits u32")
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
    verify_notification_sizes()?;
    set_no_new_privileges()?;

    match install_listener_with_flags(syscalls, true) {
        Ok(listener) => Ok(listener),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            install_listener_with_flags(syscalls, false)
        }
        Err(error) => Err(error),
    }
}

/// Run a no-capability conformance probe.
///
/// This uses the production launcher-thread shape: the listener is created on
/// one dedicated thread and moved to an unfiltered broker thread through an
/// in-process channel.
pub fn probe_notification_api() -> io::Result<NotificationProbeReport> {
    let wait_killable_recv = probe_scalar_round_trip()?;
    probe_addfd_send()?;
    probe_task_memory_copy()?;
    probe_connected_sendto_fast_path()?;
    Ok(NotificationProbeReport {
        wait_killable_recv,
        features: NotificationProbeFeatures(1 | 2 | 4 | 8),
    })
}

fn probe_scalar_round_trip() -> io::Result<bool> {
    const PROBE_VALUE: libc::c_long = 0x5a17;
    let (sender, receiver) = mpsc::sync_channel(1);
    let launcher = thread::spawn(move || -> io::Result<libc::c_long> {
        let listener = install_listener(&[libc::SYS_getppid])?;
        let wait_killable = listener.wait_killable_recv();
        sender
            .send((listener, wait_killable))
            .map_err(|_| io::Error::other("notification broker disappeared"))?;
        // SAFETY: getppid has no pointer arguments. The installed filter causes
        // the kernel to block here until the broker validates and responds.
        Ok(unsafe { libc::syscall(libc::SYS_getppid) })
    });

    let (listener, wait_killable) = receiver
        .recv()
        .map_err(|_| io::Error::other("notification launcher disappeared"))?;
    let notification = listener.receive()?;
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
    Ok(wait_killable)
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
        // SAFETY: `injected` was returned as an open descriptor by the kernel.
        let descriptor_flags = unsafe { libc::fcntl(injected, libc::F_GETFD) };
        if descriptor_flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor_flags & libc::FD_CLOEXEC == 0 {
            return Err(io::Error::other("ADDFD did not preserve close-on-exec"));
        }
        let mut value = 0_u64;
        // SAFETY: eventfd reads exactly one u64 into a valid aligned pointer.
        let read = unsafe {
            libc::read(
                injected,
                std::ptr::addr_of_mut!(value).cast(),
                size_of::<u64>(),
            )
        };
        // SAFETY: close consumes the descriptor returned by the kernel.
        unsafe { libc::close(injected) };
        let word_size = isize::try_from(size_of::<u64>()).expect("u64 size fits isize");
        if read != word_size || value != 7 {
            return Err(io::Error::other("injected eventfd was not usable"));
        }
        Ok(())
    });

    let listener = receiver
        .recv()
        .map_err(|_| io::Error::other("ADDFD launcher disappeared"))?;
    let notification = listener.receive()?;
    if i64::from(notification.syscall) != libc::SYS_socket {
        return Err(io::Error::other("unexpected ADDFD probe syscall"));
    }
    // SAFETY: eventfd has no pointer arguments and returns an owned descriptor.
    let source = unsafe { libc::eventfd(7, libc::EFD_CLOEXEC) };
    if source < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: eventfd returned a new owned descriptor.
    let source = unsafe { OwnedFd::from_raw_fd(source) };
    listener.add_fd_and_send(notification.id, source.as_raw_fd(), true)?;
    launcher
        .join()
        .map_err(|_| io::Error::other("ADDFD launcher panicked"))??;
    Ok(())
}

fn probe_task_memory_copy() -> io::Result<()> {
    let source = 0x1122_3344_5566_7788_u64;
    let mut copied = 0_u64;
    let local = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(copied).cast(),
        iov_len: size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: std::ptr::addr_of!(source).cast_mut().cast(),
        iov_len: size_of::<u64>(),
    };
    // SAFETY: both iovecs point to live same-process u64 values for the full
    // call. This is an admission probe, not the cross-task production codec.
    let read = unsafe {
        libc::process_vm_readv(
            libc::getpid(),
            std::ptr::addr_of!(local),
            1,
            std::ptr::addr_of!(remote),
            1,
            0,
        )
    };
    let word_size = isize::try_from(size_of::<u64>()).expect("u64 size fits isize");
    if read != word_size || copied != source {
        return Err(io::Error::last_os_error());
    }

    let replacement = 0xaabb_ccdd_eeff_0011_u64;
    let local = libc::iovec {
        iov_base: std::ptr::addr_of!(replacement).cast_mut().cast(),
        iov_len: size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(copied).cast(),
        iov_len: size_of::<u64>(),
    };
    // SAFETY: both iovecs point to live same-process u64 values for the full
    // call. The write is bounded to the destination value.
    let written = unsafe {
        libc::process_vm_writev(
            libc::getpid(),
            std::ptr::addr_of!(local),
            1,
            std::ptr::addr_of!(remote),
            1,
            0,
        )
    };
    if written != word_size || copied != replacement {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn probe_connected_sendto_fast_path() -> io::Result<()> {
    let mut pair = [-1; 2];
    // SAFETY: `pair` points to storage for exactly two returned descriptors.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socketpair returned two independently owned FDs.
    let sender_fd = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    // SAFETY: successful socketpair returned two independently owned FDs.
    let receiver_fd = unsafe { OwnedFd::from_raw_fd(pair[1]) };

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
        if sent != isize::try_from(direct.len()).expect("probe length fits isize") {
            return Err(io::Error::last_os_error());
        }

        let mut payload = [0_u8; 6];
        // SAFETY: the receive buffer is live for its full declared length.
        let read = unsafe {
            libc::read(
                receiver_fd.as_raw_fd(),
                payload.as_mut_ptr().cast(),
                payload.len(),
            )
        };
        if read != isize::try_from(payload.len()).expect("probe length fits isize")
            || &payload != direct
        {
            return Err(io::Error::other(
                "connected sendto fast path did not relay data",
            ));
        }

        let destination = libc::sockaddr_un {
            sun_family: libc::sa_family_t::try_from(libc::AF_UNIX)
                .expect("AF_UNIX fits sa_family_t"),
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
                    .expect("sockaddr family size fits socklen_t"),
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

    let listener = receiver
        .recv()
        .map_err(|_| io::Error::other("sendto launcher disappeared"))?;
    let destination = listener.receive()?;
    if i64::from(destination.syscall) != libc::SYS_sendto
        || destination.args[4] == 0
        || destination.args[5] == 0
    {
        return Err(io::Error::other(
            "destination-bearing sendto notification was malformed",
        ));
    }
    listener.respond_errno(destination.id, libc::EACCES)?;

    let fast_open = listener.receive()?;
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

fn install_listener_with_flags(
    syscalls: &[i64],
    wait_killable_recv: bool,
) -> io::Result<NotificationListener> {
    let mut program = build_filter(syscalls)?;
    let length = u16::try_from(program.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seccomp filter is too large"))?;
    let mut fprog = libc::sock_fprog {
        len: length,
        filter: program.as_mut_ptr(),
    };
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER
        | if wait_killable_recv {
            SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
        } else {
            0
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
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(result)
        .map_err(|_| io::Error::other("seccomp listener FD does not fit RawFd"))?;
    // SAFETY: successful NEW_LISTENER returns one newly owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(NotificationListener {
        fd,
        wait_killable_recv,
    })
}

fn build_filter(syscalls: &[i64]) -> io::Result<Vec<libc::sock_filter>> {
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

    let mut syscalls = syscalls.to_vec();
    syscalls.sort_unstable();
    syscalls.dedup();
    for syscall in syscalls {
        if syscall == libc::SYS_sendto {
            append_sendto_filter(&mut program)?;
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
    use super::*;

    #[test]
    fn filter_rejects_empty_syscall_set() {
        let error = install_listener(&[]).err().expect("empty filter must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn active_notification_probe_passes() {
        let report = probe_notification_api().expect("active notification probe");
        assert!(report.notification_round_trip());
        assert!(report.addfd_send());
        assert!(report.task_memory_copy());
        assert!(report.connected_send_fast_path());
    }

    #[test]
    fn errno_response_rejects_nonpositive_values() {
        // The input validation occurs before the listener FD is used.
        // SAFETY: dup takes one valid descriptor and returns a new descriptor
        // or a negative error without modifying memory.
        let duplicated = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(duplicated >= 0, "duplicate stderr for validation test");
        let listener = NotificationListener {
            // SAFETY: successful dup returned a new owned descriptor.
            fd: unsafe { OwnedFd::from_raw_fd(duplicated) },
            wait_killable_recv: false,
        };
        let error = listener
            .respond_errno(1, 0)
            .expect_err("zero errno must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
