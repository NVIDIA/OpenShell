// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Seccomp syscall filtering.
//!
//! The filter uses a default-allow policy with targeted blocks:
//!
//! 1. **Socket domain blocks** -- prevent raw/kernel sockets that bypass the proxy
//! 2. **Unconditional syscall blocks** -- block syscalls that enable sandbox escape
//!    (fileless exec, ptrace, BPF, cross-process memory access, io_uring, mount)
//! 3. **Conditional syscall blocks** -- block dangerous flag combinations on otherwise
//!    needed syscalls (execveat+AT_EMPTY_PATH, unshare+CLONE_NEWUSER,
//!    seccomp+SET_MODE_FILTER)

use crate::policy::{NetworkMode, SandboxPolicy};
use miette::{IntoDiagnostic, Result};
use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    apply_filter,
};
use std::collections::BTreeMap;
use std::convert::TryInto;
use tracing::debug;

/// Value of `SECCOMP_SET_MODE_FILTER` (linux/seccomp.h).
const SECCOMP_SET_MODE_FILTER: u64 = 1;

pub fn apply(policy: &SandboxPolicy) -> Result<()> {
    let allow_inet = matches!(policy.network.mode, NetworkMode::Proxy | NetworkMode::Allow);
    let main_filter = build_filter(allow_inet)?;
    let clone3_filter = build_clone3_filter()?;

    // Required before applying seccomp filters.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(miette::miette!(
            "Failed to set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }

    apply_runtime_filters(&main_filter, &clone3_filter)?;

    Ok(())
}

fn build_filter(allow_inet: bool) -> Result<seccompiler::BpfProgram> {
    let rules = build_filter_rules(allow_inet)?;

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| miette::miette!("Unsupported architecture for seccomp"))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .into_diagnostic()?;

    filter.try_into().into_diagnostic()
}

/// Build a minimal BPF filter that blocks clone3 with ENOSYS.
///
/// This is a separate filter from the main one because seccomp BPF cannot
/// dereference the `struct clone_args *` pointer that clone3 takes as arg 0,
/// so we cannot selectively block CLONE_NEWUSER. We block clone3
/// unconditionally with ENOSYS so glibc falls back to the older clone
/// syscall (where flags are a direct register argument and CAN be filtered).
///
/// glibc's clone3 wrapper checks for ENOSYS specifically — EPERM would be
/// treated as a hard failure and propagated to the caller instead of
/// triggering the clone fallback.
fn build_clone3_filter() -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.entry(libc::SYS_clone3).or_default();

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| miette::miette!("Unsupported architecture for seccomp"))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .into_diagnostic()?;

    filter.try_into().into_diagnostic()
}

/// Install the sandbox seccomp filters in the required order.
///
/// Order matters:
/// 1. Install the dedicated clone3 filter first so it can still call
///    `seccomp(SECCOMP_SET_MODE_FILTER)`.
/// 2. Install the main filter second. It blocks further seccomp filter
///    installation with `EPERM`, preserving the original hardening intent.
fn apply_runtime_filters(
    main_filter: seccompiler::BpfProgramRef,
    clone3_filter: seccompiler::BpfProgramRef,
) -> Result<()> {
    apply_filter(clone3_filter).into_diagnostic()?;
    apply_filter(main_filter).into_diagnostic()?;
    Ok(())
}

fn build_filter_rules(allow_inet: bool) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // --- Socket domain blocks ---
    let mut blocked_domains = vec![
        libc::AF_PACKET,
        libc::AF_BLUETOOTH,
        libc::AF_VSOCK,
        libc::AF_NETLINK,
    ];
    if !allow_inet {
        blocked_domains.push(libc::AF_INET);
        blocked_domains.push(libc::AF_INET6);
    }

    for domain in blocked_domains {
        debug!(domain, "Blocking socket domain via seccomp");
        add_socket_domain_rule(&mut rules, domain)?;
    }

    // --- Unconditional syscall blocks ---
    // These syscalls are blocked entirely (empty rule vec = unconditional EPERM).

    // Fileless binary execution via memfd bypasses Landlock filesystem restrictions.
    rules.entry(libc::SYS_memfd_create).or_default();
    // Cross-process memory inspection and code injection.
    rules.entry(libc::SYS_ptrace).or_default();
    // Kernel BPF program loading.
    rules.entry(libc::SYS_bpf).or_default();
    // Cross-process memory read.
    rules.entry(libc::SYS_process_vm_readv).or_default();
    // Cross-process memory write (symmetric with process_vm_readv).
    rules.entry(libc::SYS_process_vm_writev).or_default();
    // Process handle acquisition, fd theft, and signalling via pidfd.
    rules.entry(libc::SYS_pidfd_open).or_default();
    rules.entry(libc::SYS_pidfd_getfd).or_default();
    rules.entry(libc::SYS_pidfd_send_signal).or_default();
    // Async I/O subsystem with extensive CVE history.
    rules.entry(libc::SYS_io_uring_setup).or_default();
    // Filesystem mount could subvert Landlock or overlay writable paths.
    rules.entry(libc::SYS_mount).or_default();
    // New mount API syscalls (Linux 5.2+) bypass the SYS_mount block entirely.
    rules.entry(libc::SYS_fsopen).or_default();
    rules.entry(libc::SYS_fsconfig).or_default();
    rules.entry(libc::SYS_fsmount).or_default();
    rules.entry(libc::SYS_fspick).or_default();
    rules.entry(libc::SYS_move_mount).or_default();
    rules.entry(libc::SYS_open_tree).or_default();
    // Namespace manipulation — setns enters existing namespaces, pivot_root/umount2
    // change the filesystem root. The supervisor calls setns before seccomp is applied,
    // so blocking it here is safe.
    rules.entry(libc::SYS_setns).or_default();
    rules.entry(libc::SYS_umount2).or_default();
    rules.entry(libc::SYS_pivot_root).or_default();
    // Kernel exploit primitives: userfaultfd enables race-condition exploitation (multiple
    // CVEs), perf_event_open enables Spectre-class side channels. Both blocked by Docker's
    // default seccomp profile.
    rules.entry(libc::SYS_userfaultfd).or_default();
    rules.entry(libc::SYS_perf_event_open).or_default();

    // --- Conditional syscall blocks ---

    // execveat with AT_EMPTY_PATH enables fileless execution from an anonymous fd.
    add_masked_arg_rule(
        &mut rules,
        libc::SYS_execveat,
        4, // flags argument
        libc::AT_EMPTY_PATH as u64,
    )?;

    // unshare with CLONE_NEWUSER allows creating user namespaces to escalate privileges.
    add_masked_arg_rule(
        &mut rules,
        libc::SYS_unshare,
        0, // flags argument
        libc::CLONE_NEWUSER as u64,
    )?;

    // clone with CLONE_NEWUSER achieves the same as unshare via a different syscall.
    add_masked_arg_rule(
        &mut rules,
        libc::SYS_clone,
        0, // flags argument
        libc::CLONE_NEWUSER as u64,
    )?;
    // clone3 is handled by a separate filter — see build_clone3_filter().

    // seccomp(SECCOMP_SET_MODE_FILTER) would let sandboxed code replace the active filter.
    let condition = SeccompCondition::new(
        0, // operation argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        SECCOMP_SET_MODE_FILTER,
    )
    .into_diagnostic()?;
    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(libc::SYS_seccomp).or_default().push(rule);

    Ok(rules)
}

#[allow(clippy::cast_sign_loss)]
fn add_socket_domain_rule(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, domain: i32) -> Result<()> {
    let condition =
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain as u64)
            .into_diagnostic()?;

    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(libc::SYS_socket).or_default().push(rule);
    Ok(())
}

/// Block a syscall when a specific bit pattern is set in an argument.
///
/// Uses `MaskedEq` to check `(arg & flag_bit) == flag_bit`, which triggers
/// EPERM when the flag is present regardless of other bits in the argument.
fn add_masked_arg_rule(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    syscall: i64,
    arg_index: u8,
    flag_bit: u64,
) -> Result<()> {
    let condition = SeccompCondition::new(
        arg_index,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(flag_bit),
        flag_bit,
    )
    .into_diagnostic()?;
    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(syscall).or_default().push(rule);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests cover both filter construction (rule map shape and BPF
    // compilation) and selected runtime behavior on Linux via forked children.

    #[test]
    fn build_filter_proxy_mode_compiles() {
        let filter = build_filter(true);
        assert!(filter.is_ok(), "build_filter(true) should succeed");
    }

    #[test]
    fn build_filter_block_mode_compiles() {
        let filter = build_filter(false);
        assert!(filter.is_ok(), "build_filter(false) should succeed");
    }

    #[test]
    fn add_masked_arg_rule_creates_entry() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let result = add_masked_arg_rule(&mut rules, libc::SYS_execveat, 4, 0x1000);
        assert!(result.is_ok());
        assert!(
            rules.contains_key(&libc::SYS_execveat),
            "should have an entry for SYS_execveat"
        );
        assert_eq!(
            rules[&libc::SYS_execveat].len(),
            1,
            "should have exactly one rule"
        );
    }

    #[test]
    fn unconditional_blocks_present_in_filter() {
        // Build a real filter and verify all unconditional blocks are present.
        let filter_rules = build_filter_rules(true).unwrap();

        // Unconditional blocks have an empty Vec (no conditions = always match).
        let expected = [
            libc::SYS_memfd_create,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_pidfd_send_signal,
            libc::SYS_io_uring_setup,
            libc::SYS_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_setns,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
        ];

        for syscall in expected {
            assert!(
                filter_rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                filter_rules[&syscall].is_empty(),
                "syscall {syscall} should have empty rules (unconditional block)"
            );
        }
    }

    #[test]
    fn conditional_blocks_have_rules() {
        // Build a real filter and verify the conditional syscalls have rule entries
        // (non-empty Vec means conditional match).
        let filter_rules = build_filter_rules(true).unwrap();

        for syscall in [
            libc::SYS_execveat,
            libc::SYS_unshare,
            libc::SYS_clone,
            libc::SYS_seccomp,
        ] {
            assert!(
                filter_rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                !filter_rules[&syscall].is_empty(),
                "syscall {syscall} should have conditional rules"
            );
        }
    }

    #[test]
    fn clone3_filter_compiles_and_blocks_clone3() {
        let bpf = build_clone3_filter();
        assert!(bpf.is_ok(), "clone3 ENOSYS filter should compile");
    }

    #[test]
    fn clone3_not_in_main_filter() {
        // clone3 must NOT be in the main filter; it has its own ENOSYS filter.
        let filter_rules = build_filter_rules(true).unwrap();
        assert!(
            !filter_rules.contains_key(&libc::SYS_clone3),
            "clone3 should not be in the main filter — it uses a separate ENOSYS filter"
        );
    }

    // --- Behavioral tests ---
    //
    // These apply seccomp filters in a forked child and verify that blocked
    // syscalls actually return the expected errno. They only compile and run
    // on Linux (seccomp is a Linux kernel feature).

    /// Fork a child, apply the given filter, invoke `syscall_nr`, and return
    /// the errno observed by the child. The child exits 0 if the syscall
    /// returned the expected errno, 1 otherwise.
    unsafe fn assert_blocked_in_child(
        filter: &seccompiler::BpfProgram,
        syscall_nr: i64,
        expected_errno: i32,
    ) {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: apply filter and try the syscall.
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            apply_filter(filter).expect("apply_filter");
            let ret = libc::syscall(syscall_nr, 0 as libc::c_ulong, 0 as libc::c_ulong);
            let errno = *libc::__errno_location();
            if ret == -1 && errno == expected_errno {
                libc::_exit(0);
            } else {
                // Write diagnostic before exiting so test failures are debuggable.
                let msg = format!(
                    "syscall {syscall_nr}: expected errno={expected_errno}, got ret={ret} errno={errno}\n"
                );
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }
        }
        // Parent: wait for child.
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child failed: syscall {syscall_nr} was not blocked with errno {expected_errno}"
        );
    }

    unsafe fn install_runtime_filters_in_child(
        main_filter: &seccompiler::BpfProgram,
        clone3_filter: &seccompiler::BpfProgram,
    ) {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if let Err(err) = apply_runtime_filters(main_filter, clone3_filter) {
            let msg = format!("failed to install runtime seccomp filters: {err}\n");
            libc::write(2, msg.as_ptr().cast(), msg.len());
            libc::_exit(1);
        }
    }

    #[test]
    fn behavioral_memfd_create_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_memfd_create, libc::EPERM) };
    }

    #[test]
    fn behavioral_ptrace_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_ptrace, libc::EPERM) };
    }

    #[test]
    fn behavioral_process_vm_writev_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_process_vm_writev, libc::EPERM) };
    }

    #[test]
    fn behavioral_userfaultfd_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_userfaultfd, libc::EPERM) };
    }

    #[test]
    fn behavioral_perf_event_open_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_perf_event_open, libc::EPERM) };
    }

    #[test]
    fn behavioral_setns_blocked() {
        let filter = build_filter(true).unwrap();
        unsafe { assert_blocked_in_child(&filter, libc::SYS_setns, libc::EPERM) };
    }

    #[test]
    fn behavioral_clone3_returns_enosys() {
        // clone3 uses a separate filter that returns ENOSYS (not EPERM) so
        // glibc falls back to clone.
        let main_filter = build_filter(true).unwrap();
        let clone3_filter = build_clone3_filter().unwrap();
        // Apply in the same order as apply(): clone3 filter first, main filter second.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                install_runtime_filters_in_child(&main_filter, &clone3_filter);
                let ret = libc::syscall(libc::SYS_clone3, 0 as libc::c_ulong, 0 as libc::c_ulong);
                let errno = *libc::__errno_location();
                if ret == -1 && errno == libc::ENOSYS {
                    libc::_exit(0);
                } else {
                    let msg = format!("clone3: expected ENOSYS, got ret={ret} errno={errno}\n");
                    libc::write(2, msg.as_ptr().cast(), msg.len());
                    libc::_exit(1);
                }
            }
        }
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            unsafe { libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 },
            "clone3 should be blocked with ENOSYS, not EPERM"
        );
    }

    #[test]
    fn behavioral_third_filter_install_blocked_after_startup() {
        let main_filter = build_filter(true).unwrap();
        let clone3_filter = build_clone3_filter().unwrap();
        let third_filter = build_clone3_filter().unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                install_runtime_filters_in_child(&main_filter, &clone3_filter);
                match apply_filter(&third_filter) {
                    Err(seccompiler::Error::Seccomp(e))
                        if e.raw_os_error() == Some(libc::EPERM) =>
                    {
                        libc::_exit(0);
                    }
                    Err(err) => {
                        let msg =
                            format!("third filter install failed with unexpected error: {err}\n");
                        libc::write(2, msg.as_ptr().cast(), msg.len());
                        libc::_exit(1);
                    }
                    Ok(()) => {
                        let msg = "third filter unexpectedly installed\n";
                        libc::write(2, msg.as_ptr().cast(), msg.len());
                        libc::_exit(1);
                    }
                }
            }
        }

        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            unsafe { libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 },
            "additional seccomp filter installation should be blocked after startup"
        );
    }
}
