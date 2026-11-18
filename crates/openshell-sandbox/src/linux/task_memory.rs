// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, exact access to a notifying task's memory.
//!
//! Seccomp user-notification arguments contain addresses in the notifying
//! task. Callers must copy pointer-bearing inputs once into trusted memory and
//! must never treat a partial copy as valid.
//!
//! Reads go through `process_vm_readv`, or `/proc/<tid>/mem` where a runtime
//! profile denies that syscall. Writes go through a [`PinnedMemory`] only:
//! an open `/proc/<tid>/mem` is bound to one address space for its lifetime,
//! so a write can never reach a task that reused the number, which
//! `process_vm_writev` resolves anew on every call.

#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::fd::AsFd;
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
                .map_err(|fallback| fallback_error("read", &error, fallback))
        }
        Err(error) => Err(error),
    }
}

/// One task's address space, pinned for writes.
///
/// `/proc/<tid>/mem` binds to the address space of the task that holds `tid`
/// when it is opened and never follows the number afterwards. The caller
/// proves which task that was: open the file, then validate the notification
/// it serves. A notification stays valid only while its task lives, so a
/// valid one after the open means the task never died, its number was never
/// freed or reused, and the pinned space is its own. A sibling thread's
/// `execve` kills every other thread before replacing the address space,
/// which also ends the notification. `process_vm_writev` offers no such
/// proof: it resolves the number again on every call.
///
/// Writes here use the kernel's `FOLL_FORCE`, which differs from the
/// `copy_to_user` behind a native `stat` in one case: a private copy-on-write
/// mapping the task holds read-only is written (a private copy is made)
/// instead of failing with `EFAULT`. The kernel refuses forced writes to
/// shared and non-`VM_MAYWRITE` mappings, so this reaches only memory the
/// task could already make writable with `mprotect`; the deviation is
/// confined to a task that passes its own read-only private memory as a
/// result buffer. Unmapped addresses still fail with `EFAULT` or a short
/// count, and a space already torn down accepts nothing.
#[derive(Debug)]
pub struct PinnedMemory {
    file: std::fs::File,
    tid: u32,
}

impl PinnedMemory {
    /// Pin the address space of the task currently holding `tid`, for
    /// writing. Fails with `ESRCH` when no such task exists and with
    /// `EACCES` or `EPERM` when the active Yama, LSM, or seccomp posture
    /// refuses the attach-mode access the write needs.
    pub fn open(tid: u32) -> io::Result<Self> {
        if tid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task-memory TID must be nonzero",
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{tid}/mem"))?;
        Ok(Self { file, tid })
    }

    /// Write exactly `source` at `address`. Empty and oversized requests and
    /// null addresses fail closed; a short write is
    /// [`io::ErrorKind::InvalidData`].
    pub fn write_exact(&self, address: u64, source: &[u8]) -> io::Result<()> {
        validate_request(self.tid, address, source.len())?;
        let written = self.file.write_at(source, address)?;
        require_exact(written, source.len(), "task-memory write")
    }
}

fn syscall_profile_denied(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
    )
}

fn fallback_error(operation: &str, process_vm: &io::Error, proc_mem: io::Error) -> io::Error {
    let process_vm = describe_error(process_vm);
    let proc_mem_description = describe_error(&proc_mem);
    io::Error::new(
        proc_mem.kind(),
        format!(
            "task-memory {operation} unavailable: process_vm_{operation}v failed: {process_vm}; /proc/<tid>/mem failed: {proc_mem_description}"
        ),
    )
}

fn describe_error(error: &io::Error) -> String {
    let name = match error.raw_os_error() {
        Some(libc::EACCES) => Some("EACCES"),
        Some(libc::ENOSYS) => Some("ENOSYS"),
        Some(libc::EPERM) => Some("EPERM"),
        _ => None,
    };
    name.map_or_else(|| error.to_string(), |name| format!("{name} ({error})"))
}

fn read_exact_from_proc_mem(tid: u32, address: u64, destination: &mut [u8]) -> io::Result<()> {
    let file = std::fs::File::open(format!("/proc/{tid}/mem"))?;
    let copied = file.read_at(destination, address)?;
    require_exact(copied, destination.len(), "proc task-memory read")
}

/// Prove same-UID parent-to-child read and write access under the active
/// Yama, LSM, and outer seccomp posture.
///
/// The parent reads a value the child stored, writes another through a
/// pinned `/proc/<pid>/mem`, and the child confirms it observed it.
///
/// Call this only from a single-threaded probe process. The child executes
/// raw, allocation-free syscalls between `fork` and `_exit`.
pub fn probe_child_access() -> io::Result<()> {
    const INITIAL: u64 = 0x1122_3344_5566_7788;
    const WRITTEN: u64 = 0x8877_6655_4433_2211;
    const CHILD_SAW_WRITE: i32 = 0;
    const CHILD_SETUP_FAILED: i32 = 1;
    const CHILD_MISSED_WRITE: i32 = 2;
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

    // Preserve descriptor creation errors across mapping cleanup.
    let descriptors = (|| -> io::Result<_> {
        let ready = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?;
        let proceed = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?;
        Ok((ready, proceed))
    })();
    let (ready, proceed) = match descriptors {
        Ok(descriptors) => descriptors,
        Err(error) => {
            // SAFETY: mapping is the live region returned above.
            unsafe { libc::munmap(mapping, size_of::<u64>()) };
            return Err(error);
        }
    };

    // SAFETY: the caller promises this probe process is single-threaded. The
    // child performs only raw syscalls and memory operations before `_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: mapping is the live region returned above.
        unsafe { libc::munmap(mapping, size_of::<u64>()) };
        return Err(error);
    }
    if child == 0 {
        // The sandbox remains nondumpable, but an exec'd workload must be
        // observable by its same-UID ancestor. This child contains no trusted
        // parent address space secrets beyond this synthetic probe value.
        // SAFETY: these calls use live inherited eventfds and scalar prctl
        // arguments. No Rust cleanup runs in the child.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) < 0
                || write_eventfd(&ready).is_err()
                || read_eventfd(&proceed).is_err()
            {
                libc::_exit(CHILD_SETUP_FAILED);
            }
            // A volatile read: the parent changed this through another
            // address space, which the compiler cannot see.
            if mapping.cast::<u64>().read_volatile() == WRITTEN {
                libc::_exit(CHILD_SAW_WRITE);
            }
            libc::_exit(CHILD_MISSED_WRITE);
        }
    }

    let outcome = (|| {
        read_eventfd(&ready)?;
        let child_tid =
            u32::try_from(child).map_err(|_| io::Error::other("child PID does not fit u32"))?;
        let mut observed = [0_u8; size_of::<u64>()];
        read_exact(child_tid, mapping_address, &mut observed)?;
        if u64::from_ne_bytes(observed) != INITIAL {
            return Err(io::Error::other(
                "cross-child memory read returned wrong data",
            ));
        }
        PinnedMemory::open(child_tid)
            .and_then(|memory| memory.write_exact(mapping_address, &WRITTEN.to_ne_bytes()))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cross-child memory write failed: {error}. The sandbox answers stat and access calls on its virtual provider and CA trust files by writing the result into the workload through /proc/<pid>/mem; the runtime's Yama, LSM, or mount posture must permit a same-UID ancestor to open a dumpable child's memory file for writing"
                    ),
                )
            })?;
        write_eventfd(&proceed)?;
        let mut status = 0;
        // SAFETY: child is a live direct child and status points to storage.
        if unsafe { libc::waitpid(child, std::ptr::addr_of_mut!(status), 0) } != child {
            return Err(io::Error::last_os_error());
        }
        if !libc::WIFEXITED(status) {
            return Err(io::Error::other("cross-child memory probe child died"));
        }
        match libc::WEXITSTATUS(status) {
            CHILD_SAW_WRITE => Ok(()),
            CHILD_MISSED_WRITE => Err(io::Error::other(
                "cross-child memory write reported success but the child did not observe the written value",
            )),
            _ => Err(io::Error::other("cross-child memory probe failed in child")),
        }
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

fn read_eventfd(fd: impl AsFd) -> io::Result<()> {
    let mut value = [0_u8; size_of::<u64>()];
    let copied = rustix::io::read(fd, &mut value[..])?;
    require_exact(copied, value.len(), "eventfd read")
}

fn write_eventfd(fd: impl AsFd) -> io::Result<()> {
    let value = 1_u64.to_ne_bytes();
    let copied = rustix::io::write(fd, &value)?;
    require_exact(copied, value.len(), "eventfd write")
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
    use std::os::fd::AsRawFd as _;
    use std::time::Duration;

    #[test]
    fn reads_exact_same_process_memory() {
        let source = 0x1122_3344_5566_7788_u64;
        let mut bytes = [0_u8; size_of::<u64>()];

        read_exact(
            std::process::id(),
            std::ptr::addr_of!(source) as u64,
            &mut bytes,
        )
        .expect("read source");
        assert_eq!(u64::from_ne_bytes(bytes), source);
    }

    #[test]
    fn pinned_memory_writes_exactly_and_refuses_what_is_not_mapped() {
        let memory = PinnedMemory::open(std::process::id()).expect("pin own memory");
        let mut target = 0_u64;
        let value = 0x0f0e_0d0c_0b0a_0908_u64;
        memory
            .write_exact(std::ptr::addr_of_mut!(target) as u64, &value.to_ne_bytes())
            .expect("write target");
        // SAFETY: target is a live, aligned u64 on this stack.
        assert_eq!(unsafe { std::ptr::addr_of!(target).read_volatile() }, value);

        // SAFETY: a fresh private page, unmapped again below.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        // SAFETY: the page is mapped and nothing else refers to it.
        assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
        let error = memory
            .write_exact(page as u64, &[1, 2, 3, 4])
            .expect_err("unmapped address must fail");
        assert!(
            error.raw_os_error() == Some(libc::EFAULT)
                || error.raw_os_error() == Some(libc::EIO)
                || error.kind() == io::ErrorKind::InvalidData,
            "{error}"
        );
        assert_eq!(
            memory.write_exact(0, &[1]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            memory.write_exact(8, &[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            PinnedMemory::open(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// Fork a child that stores `INITIAL` in a fresh page, reports ready on
    /// a pipe, waits on another, then runs `after`.
    fn pinned_child(after: unsafe fn()) -> (libc::pid_t, u64, std::fs::File, std::fs::File) {
        let (ready_read, ready_write) = nix::unistd::pipe().unwrap();
        let (go_read, go_write) = nix::unistd::pipe().unwrap();
        // SAFETY: a fresh private page shared by inheritance only.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        // SAFETY: the child runs only raw syscalls before exit or exec.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: inherited descriptors and page; nothing else runs here.
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
                page.cast::<u64>().write_volatile(0x1122_3344_5566_7788);
                libc::write(ready_write.as_raw_fd(), [1_u8].as_ptr().cast(), 1);
                let mut byte = 0_u8;
                libc::read(go_read.as_raw_fd(), std::ptr::addr_of_mut!(byte).cast(), 1);
                after();
                libc::_exit(0);
            }
        }
        let mut ready = std::fs::File::from(ready_read);
        io::Read::read_exact(&mut ready, &mut [0_u8; 1]).unwrap();
        (child, page as u64, std::fs::File::from(go_write), ready)
    }

    unsafe fn exit_child() {
        // SAFETY: ends the forked child only.
        unsafe { libc::_exit(0) }
    }

    unsafe fn exec_child() {
        // SAFETY: replaces the forked child's image with a short sleep.
        unsafe {
            libc::execl(
                c"/bin/sleep".as_ptr(),
                c"sleep".as_ptr(),
                c"5".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(9);
        }
    }

    #[test]
    fn pinned_memory_never_follows_the_task_number_after_exit_or_exec() {
        use std::os::fd::AsRawFd as _;
        // Exit: the pinned space goes away with the task; a write reaches
        // nothing, even though a new task may hold the number by now.
        let (child, page, mut go, _ready) = pinned_child(exit_child);
        let memory = PinnedMemory::open(u32::try_from(child).unwrap()).unwrap();
        io::Write::write_all(&mut go, &[1]).unwrap();
        let mut status = 0;
        // SAFETY: child is this test's direct child.
        assert_eq!(
            unsafe { libc::waitpid(child, std::ptr::addr_of_mut!(status), 0) },
            child
        );
        assert!(memory.write_exact(page, &[7; 8]).is_err());

        // Exec: the pinned space is the old image's, not the new one's.
        let (child, page, mut go, _ready) = pinned_child(exec_child);
        let memory = PinnedMemory::open(u32::try_from(child).unwrap()).unwrap();
        io::Write::write_all(&mut go, &[1]).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !matches!(
            std::fs::read_link(format!("/proc/{child}/exe")),
            Ok(exe) if exe.ends_with("sleep")
        ) {
            assert!(std::time::Instant::now() < deadline, "child did not exec");
            std::thread::sleep(Duration::from_millis(10));
        }
        let outcome = memory.write_exact(page, &[7; 8]);
        // SAFETY: child is this test's direct child.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::addr_of_mut!(status), 0);
        }
        assert!(outcome.is_err(), "write reached the replacement image");
        let _ = go.as_raw_fd();
    }

    #[test]
    fn pinned_write_into_read_only_private_memory_is_the_documented_deviation() {
        let memory = PinnedMemory::open(std::process::id()).unwrap();
        // SAFETY: a fresh private read-only page, unmapped below.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        match memory.write_exact(page as u64, &[5; 8]) {
            // FOLL_FORCE: a private copy is written where copy_to_user
            // would fail. Only memory this process could mprotect writable.
            // SAFETY: the page is mapped readable.
            Ok(()) => assert_eq!(
                unsafe { page.cast::<u64>().read_volatile() },
                0x0505_0505_0505_0505
            ),
            // A kernel with proc_mem.force_override=never behaves natively.
            Err(error) => assert!(
                matches!(error.raw_os_error(), Some(libc::EFAULT | libc::EIO)),
                "{error}"
            ),
        }
        // SAFETY: the page is mapped and nothing else refers to it.
        assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
    }

    #[test]
    fn proc_mem_fallback_reads_exact_memory() {
        let source = 0x0102_0304_0506_0708_u64;
        let mut bytes = [0_u8; size_of::<u64>()];
        read_exact_from_proc_mem(
            std::process::id(),
            std::ptr::addr_of!(source) as u64,
            &mut bytes,
        )
        .expect("read through proc mem");
        assert_eq!(u64::from_ne_bytes(bytes), source);
    }

    #[test]
    fn fallback_error_reports_both_memory_backends() {
        let error = fallback_error(
            "read",
            &io::Error::from_raw_os_error(libc::ENOSYS),
            io::Error::from_raw_os_error(libc::EACCES),
        );
        let message = error.to_string();
        assert!(message.contains("process_vm_readv failed"));
        assert!(message.contains("ENOSYS"));
        assert!(message.contains("/proc/<tid>/mem failed"));
        assert!(message.contains("EACCES"));
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
