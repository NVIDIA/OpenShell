// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, exact access to a notifying task's memory.
//!
//! Seccomp user-notification arguments contain addresses in the notifying
//! task. Callers must copy pointer-bearing inputs once into trusted memory and
//! must never treat a partial copy as valid.

#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt as _;

/// Maximum number of task-memory bytes copied by one operation.
pub const MAX_TASK_MEMORY_COPY: usize = 64 * 1024;

/// Read exactly `destination.len()` bytes from `address` in `tid`.
///
/// Empty and oversized requests, null addresses, and partial reads fail
/// closed. The caller must still revalidate the notification and task
/// generation after the copy.
pub fn read_exact(tid: u32, address: u64, destination: &mut [u8]) -> io::Result<()> {
    validate_request(tid, address, destination.len())?;
    let pid = libc::pid_t::try_from(tid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TID does not fit pid_t"))?;
    let remote_address = usize::try_from(address).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote address does not fit usize",
        )
    })?;
    let local = libc::iovec {
        iov_base: destination.as_mut_ptr().cast(),
        iov_len: destination.len(),
    };
    let remote = libc::iovec {
        iov_base: remote_address as *mut libc::c_void,
        iov_len: destination.len(),
    };

    // SAFETY: the local iovec spans the caller-provided live buffer. The
    // remote address is untrusted but bounded; the kernel validates it in the
    // target process and returns EFAULT or a short count when unavailable.
    let copied = retry_eintr(|| unsafe {
        libc::process_vm_readv(
            pid,
            std::ptr::addr_of!(local),
            1,
            std::ptr::addr_of!(remote),
            1,
            0,
        )
    });
    match copied {
        Ok(copied) => require_exact(copied, destination.len(), "task-memory read"),
        Err(error) if syscall_profile_denied(&error) => {
            read_exact_from_proc_mem(tid, address, destination)
        }
        Err(error) => Err(error),
    }
}

/// Write exactly all of `source` to `address` in `tid`.
///
/// This is used only for syscall outputs such as `getpeername` and
/// `sendmmsg.msg_len`. Revalidate the notification, task generation, and
/// destination layout immediately before calling it.
pub fn write_exact(tid: u32, address: u64, source: &[u8]) -> io::Result<()> {
    validate_request(tid, address, source.len())?;
    let pid = libc::pid_t::try_from(tid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TID does not fit pid_t"))?;
    let remote_address = usize::try_from(address).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote address does not fit usize",
        )
    })?;
    let local = libc::iovec {
        iov_base: source.as_ptr().cast_mut().cast(),
        iov_len: source.len(),
    };
    let remote = libc::iovec {
        iov_base: remote_address as *mut libc::c_void,
        iov_len: source.len(),
    };

    // SAFETY: the local iovec spans the caller-provided live buffer. The
    // remote address is untrusted but bounded; the kernel validates that it is
    // writable in the target process.
    let copied = retry_eintr(|| unsafe {
        libc::process_vm_writev(
            pid,
            std::ptr::addr_of!(local),
            1,
            std::ptr::addr_of!(remote),
            1,
            0,
        )
    });
    match copied {
        Ok(copied) => require_exact(copied, source.len(), "task-memory write"),
        Err(error) if syscall_profile_denied(&error) => {
            write_exact_to_proc_mem(tid, address, source)
        }
        Err(error) => Err(error),
    }
}

fn syscall_profile_denied(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
    )
}

fn read_exact_from_proc_mem(tid: u32, address: u64, destination: &mut [u8]) -> io::Result<()> {
    let file = std::fs::File::open(format!("/proc/{tid}/mem"))?;
    let copied = file.read_at(destination, address)?;
    require_exact(copied, destination.len(), "proc task-memory read")
}

fn write_exact_to_proc_mem(tid: u32, address: u64, source: &[u8]) -> io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{tid}/mem"))?;
    let copied = file.write_at(source, address)?;
    require_exact(copied, source.len(), "proc task-memory write")
}

/// Prove same-UID parent-to-child read and write access under the active Yama,
/// LSM, and outer seccomp posture.
///
/// Call this only from a single-threaded probe process. The child executes
/// raw, allocation-free syscalls between `fork` and `_exit`.
pub fn probe_child_access() -> io::Result<()> {
    const INITIAL: u64 = 0x1122_3344_5566_7788;
    const REPLACEMENT: u64 = 0xaabb_ccdd_eeff_0011;
    // SAFETY: mmap creates one private anonymous page owned by this process.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size_of::<u64>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mapping_address = mapping as u64;
    // SAFETY: mapping spans at least one aligned u64-sized region.
    unsafe { mapping.cast::<u64>().write(INITIAL) };

    // SAFETY: eventfd returns independently owned descriptors on success.
    let ready = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if ready < 0 {
        // SAFETY: mapping is the live region returned above.
        unsafe { libc::munmap(mapping, size_of::<u64>()) };
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful eventfd returned one owned descriptor.
    let ready = unsafe { OwnedFd::from_raw_fd(ready) };
    // SAFETY: eventfd returns independently owned descriptors on success.
    let proceed = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if proceed < 0 {
        // SAFETY: mapping is the live region returned above.
        unsafe { libc::munmap(mapping, size_of::<u64>()) };
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful eventfd returned one owned descriptor.
    let proceed = unsafe { OwnedFd::from_raw_fd(proceed) };

    // SAFETY: the caller promises this probe process is single-threaded. The
    // child performs only raw syscalls and memory operations before `_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
        // SAFETY: mapping is the live region returned above.
        unsafe { libc::munmap(mapping, size_of::<u64>()) };
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // The sandbox remains nondumpable, but an exec'd workload must be
        // observable by its same-UID ancestor. This child contains no trusted
        // parent address space secrets beyond this synthetic probe value.
        // SAFETY: these calls use live inherited eventfds and scalar prctl
        // arguments. No Rust cleanup runs in the child.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) < 0
                || write_eventfd(ready.as_raw_fd()).is_err()
                || read_eventfd(proceed.as_raw_fd()).is_err()
                || mapping.cast::<u64>().read() != REPLACEMENT
            {
                libc::_exit(1);
            }
            libc::_exit(0);
        }
    }

    let outcome = (|| {
        read_eventfd(ready.as_raw_fd())?;
        let mut observed = [0_u8; size_of::<u64>()];
        read_exact(
            u32::try_from(child).map_err(|_| io::Error::other("child PID does not fit u32"))?,
            mapping_address,
            &mut observed,
        )?;
        if u64::from_ne_bytes(observed) != INITIAL {
            return Err(io::Error::other(
                "cross-child memory read returned wrong data",
            ));
        }
        write_exact(
            u32::try_from(child).map_err(|_| io::Error::other("child PID does not fit u32"))?,
            mapping_address,
            &REPLACEMENT.to_ne_bytes(),
        )?;
        write_eventfd(proceed.as_raw_fd())?;
        let mut status = 0;
        // SAFETY: child is a live direct child and status points to storage.
        if unsafe { libc::waitpid(child, std::ptr::addr_of_mut!(status), 0) } != child {
            return Err(io::Error::last_os_error());
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(io::Error::other("cross-child memory probe failed in child"));
        }
        Ok(())
    })();

    if outcome.is_err() {
        // SAFETY: a failed parent-side operation may leave this direct child
        // blocked on eventfd. SIGKILL and waitpid guarantee cleanup.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
    }
    // SAFETY: mapping is the live region returned above and no child remains.
    unsafe { libc::munmap(mapping, size_of::<u64>()) };
    outcome
}

fn read_eventfd(fd: libc::c_int) -> io::Result<()> {
    let mut value = 0_u64;
    // SAFETY: eventfd reads exactly one u64 into live storage.
    let result = unsafe { libc::read(fd, std::ptr::addr_of_mut!(value).cast(), size_of::<u64>()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    require_exact(
        usize::try_from(result).map_err(|_| io::Error::other("eventfd read length invalid"))?,
        size_of::<u64>(),
        "eventfd read",
    )
}

fn write_eventfd(fd: libc::c_int) -> io::Result<()> {
    let value = 1_u64;
    // SAFETY: eventfd reads exactly one u64 from live storage.
    let result = unsafe { libc::write(fd, std::ptr::addr_of!(value).cast(), size_of::<u64>()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    require_exact(
        usize::try_from(result).map_err(|_| io::Error::other("eventfd write length invalid"))?,
        size_of::<u64>(),
        "eventfd write",
    )
}
fn validate_request(tid: u32, address: u64, length: usize) -> io::Result<()> {
    if tid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "task-memory TID must be nonzero",
        ));
    }
    if address == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "task-memory address must be nonzero",
        ));
    }
    if length == 0 || length > MAX_TASK_MEMORY_COPY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("task-memory copy length must be between 1 and {MAX_TASK_MEMORY_COPY} bytes"),
        ));
    }
    let start = usize::try_from(address)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "remote address is too large"))?;
    start.checked_add(length - 1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "task-memory address range overflows",
        )
    })?;
    Ok(())
}

fn retry_eintr(mut operation: impl FnMut() -> isize) -> io::Result<usize> {
    loop {
        let result = operation();
        if result >= 0 {
            return usize::try_from(result)
                .map_err(|_| io::Error::other("task-memory result does not fit usize"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn require_exact(copied: usize, expected: usize, operation: &str) -> io::Result<()> {
    if copied == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{operation} was partial: copied {copied} of {expected} bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_exact_same_process_memory() {
        let source = 0x1122_3344_5566_7788_u64;
        let mut destination = 0_u64;
        let mut bytes = [0_u8; size_of::<u64>()];

        read_exact(
            std::process::id(),
            std::ptr::addr_of!(source) as u64,
            &mut bytes,
        )
        .expect("read source");
        assert_eq!(u64::from_ne_bytes(bytes), source);

        let replacement = 0xaabb_ccdd_eeff_0011_u64;
        write_exact(
            std::process::id(),
            std::ptr::addr_of_mut!(destination) as u64,
            &replacement.to_ne_bytes(),
        )
        .expect("write destination");
        assert_eq!(destination, replacement);
    }

    #[test]
    fn proc_mem_fallback_reads_and_writes_exact_memory() {
        let source = 0x0102_0304_0506_0708_u64;
        let mut destination = 0_u64;
        let mut bytes = [0_u8; size_of::<u64>()];
        read_exact_from_proc_mem(
            std::process::id(),
            std::ptr::addr_of!(source) as u64,
            &mut bytes,
        )
        .expect("read through proc mem");
        assert_eq!(u64::from_ne_bytes(bytes), source);

        write_exact_to_proc_mem(
            std::process::id(),
            std::ptr::addr_of_mut!(destination) as u64,
            &source.to_ne_bytes(),
        )
        .expect("write through proc mem");
        assert_eq!(destination, source);
    }

    #[test]
    fn rejects_invalid_ranges_before_syscall() {
        let mut byte = [0_u8; 1];
        assert_eq!(
            read_exact(0, 1, &mut byte).expect_err("zero TID").kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_exact(std::process::id(), 0, &mut byte)
                .expect_err("null address")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_exact(std::process::id(), 1, &mut [])
                .expect_err("empty copy")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_request(std::process::id(), 1, MAX_TASK_MEMORY_COPY + 1)
                .expect_err("oversized copy")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_request(std::process::id(), u64::MAX, 2)
                .expect_err("overflowing range")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
