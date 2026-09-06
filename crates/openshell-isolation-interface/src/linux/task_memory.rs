// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, exact access to a notifying task's memory.
//!
//! Seccomp user-notification arguments contain addresses in the notifying
//! task. Callers must copy pointer-bearing inputs once into trusted memory and
//! must never treat a partial copy as valid.

#![allow(unsafe_code)]

use std::io;

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
    })?;
    require_exact(copied, destination.len(), "task-memory read")
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
    })?;
    require_exact(copied, source.len(), "task-memory write")
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

    use std::mem::size_of;
}
