// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prepared seccomp self-protection for same-UID workload children.
//!
//! The program is built before `fork` and installed by the workload launcher
//! after the child has inherited the network user-notification filter. It does
//! not allocate while installing and deliberately leaves mediated networking
//! syscalls alone so the older `USER_NOTIF` action can still win.

#![allow(unsafe_code)]

use std::io;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_FILTER_OPERATION: u32 = 1;
const PR_SET_SECCOMP_OPERATION: u32 = 22;
const CLOSE_RANGE_UNSHARE_FLAG: u32 = 1 << 1;
const F_SETOWN_COMMAND: u32 = 8;
const F_SETSIG_COMMAND: u32 = 10;
const F_SETOWN_EX_COMMAND: u32 = 15;
const FIOSETOWN_REQUEST: u32 = 0x8901;
const SIOCSPGRP_REQUEST: u32 = 0x8902;

/// A prebuilt child filter that can be installed without heap allocation.
pub struct ChildHardeningProgram {
    instructions: Vec<libc::sock_filter>,
}

impl ChildHardeningProgram {
    /// Install this filter on the calling thread only.
    ///
    /// The caller must invoke this from the post-fork child after all
    /// sandbox-wide TSYNC work and the launcher's `NEW_LISTENER` filter.
    pub fn install(&mut self) -> io::Result<()> {
        set_no_new_privileges()?;
        let len = u16::try_from(self.instructions.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "child seccomp filter is too large",
            )
        })?;
        let mut program = libc::sock_fprog {
            len,
            filter: self.instructions.as_mut_ptr(),
        };
        // SAFETY: `program` references the prebuilt cBPF instruction vector
        // for the complete syscall. No TSYNC flag is used.
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

    /// Number of cBPF instructions, exposed for admission diagnostics.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

/// Build the same-UID workload self-protection program before `fork`.
///
/// `sandbox_tgid` is the sandbox PID as visible from its workload namespace.
/// The filter blocks all direct thread-targeting through `tkill`, and blocks
/// process-directed operations that name the trusted sandbox leader. Worker
/// threads share that TGID and are therefore covered by `tgkill` and the
/// process-level APIs.
pub fn prepare(sandbox_tgid: u32) -> io::Result<ChildHardeningProgram> {
    if sandbox_tgid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox TGID must be nonzero",
        ));
    }

    let mut instructions = vec![
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, native_audit_arch(), 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    #[cfg(target_arch = "x86_64")]
    instructions.extend([
        jump(BPF_JMP_JSET_K, X32_SYSCALL_BIT, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
    ]);

    for syscall in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_kcmp,
        libc::SYS_process_madvise,
        libc::SYS_process_mrelease,
        libc::SYS_tkill,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_capset,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_setpriority,
        libc::SYS_ioprio_set,
        libc::SYS_clone3,
    ] {
        append_unconditional_deny(&mut instructions, syscall)?;
    }

    for (syscall, argument) in [
        (libc::SYS_kill, 0),
        (libc::SYS_tgkill, 0),
        (libc::SYS_rt_sigqueueinfo, 0),
        (libc::SYS_rt_tgsigqueueinfo, 0),
    ] {
        append_argument_equal_deny(&mut instructions, syscall, argument, sandbox_tgid)?;
    }
    append_argument_equal_deny(&mut instructions, libc::SYS_kill, 0, u32::MAX)?;
    append_argument_equal_deny(&mut instructions, libc::SYS_rt_sigqueueinfo, 0, u32::MAX)?;

    for syscall in [
        libc::SYS_prlimit64,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_setparam,
        libc::SYS_sched_setscheduler,
    ] {
        append_argument_nonzero_deny(&mut instructions, syscall, 0)?;
    }

    append_argument_equal_deny(
        &mut instructions,
        libc::SYS_seccomp,
        0,
        SECCOMP_FILTER_OPERATION,
    )?;
    append_argument_equal_deny(
        &mut instructions,
        libc::SYS_prctl,
        0,
        PR_SET_SECCOMP_OPERATION,
    )?;
    append_argument_masked_deny(
        &mut instructions,
        libc::SYS_close_range,
        2,
        CLOSE_RANGE_UNSHARE_FLAG,
    )?;

    for command in [F_SETOWN_COMMAND, F_SETSIG_COMMAND, F_SETOWN_EX_COMMAND] {
        append_argument_equal_deny(&mut instructions, libc::SYS_fcntl, 1, command)?;
    }
    for request in [FIOSETOWN_REQUEST, SIOCSPGRP_REQUEST] {
        append_argument_equal_deny(&mut instructions, libc::SYS_ioctl, 1, request)?;
    }

    instructions.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    Ok(ChildHardeningProgram { instructions })
}

fn append_unconditional_deny(
    instructions: &mut Vec<libc::sock_filter>,
    syscall: i64,
) -> io::Result<()> {
    let syscall = syscall_number(syscall)?;
    instructions.extend([
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, syscall, 0, 1),
        errno(libc::EPERM),
    ]);
    Ok(())
}

fn append_argument_equal_deny(
    instructions: &mut Vec<libc::sock_filter>,
    syscall: i64,
    argument: u32,
    value: u32,
) -> io::Result<()> {
    let syscall = syscall_number(syscall)?;
    instructions.extend([
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, syscall, 0, 3),
        stmt(BPF_LD_W_ABS, argument_word_offset(argument)),
        jump(BPF_JMP_JEQ_K, value, 0, 1),
        errno(libc::EPERM),
    ]);
    Ok(())
}

fn append_argument_nonzero_deny(
    instructions: &mut Vec<libc::sock_filter>,
    syscall: i64,
    argument: u32,
) -> io::Result<()> {
    let syscall = syscall_number(syscall)?;
    instructions.extend([
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, syscall, 0, 3),
        stmt(BPF_LD_W_ABS, argument_word_offset(argument)),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        errno(libc::EPERM),
    ]);
    Ok(())
}

fn append_argument_masked_deny(
    instructions: &mut Vec<libc::sock_filter>,
    syscall: i64,
    argument: u32,
    mask: u32,
) -> io::Result<()> {
    let syscall = syscall_number(syscall)?;
    instructions.extend([
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, syscall, 0, 3),
        stmt(BPF_LD_W_ABS, argument_word_offset(argument)),
        jump(BPF_JMP_JSET_K, mask, 0, 1),
        errno(libc::EPERM),
    ]);
    Ok(())
}

fn syscall_number(syscall: i64) -> io::Result<u32> {
    u32::try_from(syscall)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative syscall number"))
}

const fn argument_word_offset(argument: u32) -> u32 {
    SECCOMP_DATA_ARGS_OFFSET + argument * 8
}

const fn errno(value: i32) -> libc::sock_filter {
    stmt(BPF_RET_K, SECCOMP_RET_ERRNO | value.cast_unsigned())
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
    // SAFETY: PR_SET_NO_NEW_PRIVS is a one-way scalar transition.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_sandbox_tgid() {
        assert_eq!(
            prepare(0).err().expect("zero TGID must fail").kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn filter_blocks_same_uid_sandbox_control() {
        // SAFETY: the child uses only raw syscalls after fork and exits with
        // `_exit`, so it does not run copied Rust cleanup state.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", io::Error::last_os_error());
        if child == 0 {
            let sandbox_tgid = unsafe { libc::getppid() };
            let Ok(mut filter) = prepare(u32::try_from(sandbox_tgid).unwrap_or(0)) else {
                unsafe { libc::_exit(1) };
            };
            if filter.install().is_err() {
                unsafe { libc::_exit(2) };
            }
            let mut local = 0_u8;
            let mut remote = 0_u8;
            let local_iov = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(local).cast(),
                iov_len: 1,
            };
            let remote_iov = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(remote).cast(),
                iov_len: 1,
            };
            let process_vm = unsafe {
                libc::process_vm_readv(
                    sandbox_tgid,
                    std::ptr::addr_of!(local_iov),
                    1,
                    std::ptr::addr_of!(remote_iov),
                    1,
                    0,
                )
            };
            if process_vm != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                unsafe { libc::_exit(3) };
            }
            if unsafe { libc::kill(sandbox_tgid, 0) } != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                unsafe { libc::_exit(4) };
            }
            if unsafe { libc::syscall(libc::SYS_prlimit64, sandbox_tgid, libc::RLIMIT_CORE, 0, 0) }
                != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                unsafe { libc::_exit(5) };
            }
            if unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    0,
                    std::ptr::null::<libc::sock_fprog>(),
                )
            } != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                unsafe { libc::_exit(6) };
            }
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        // SAFETY: `child` names our live direct child and status is writable.
        assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
