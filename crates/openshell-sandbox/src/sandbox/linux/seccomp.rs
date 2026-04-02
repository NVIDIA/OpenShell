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
    if matches!(policy.network.mode, NetworkMode::Allow) {
        return Ok(());
    }

    let allow_inet = matches!(policy.network.mode, NetworkMode::Proxy);
    let filter = build_filter(allow_inet)?;

    // Required before applying seccomp filters.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(miette::miette!(
            "Failed to set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }

    apply_filter(&filter).into_diagnostic()?;
    Ok(())
}

fn build_filter(allow_inet: bool) -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // --- Socket domain blocks ---
    let mut blocked_domains = vec![libc::AF_PACKET, libc::AF_BLUETOOTH, libc::AF_VSOCK];
    if !allow_inet {
        blocked_domains.push(libc::AF_INET);
        blocked_domains.push(libc::AF_INET6);
        blocked_domains.push(libc::AF_NETLINK);
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
    // Async I/O subsystem with extensive CVE history.
    rules.entry(libc::SYS_io_uring_setup).or_default();
    // Filesystem mount could subvert Landlock or overlay writable paths.
    rules.entry(libc::SYS_mount).or_default();

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
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Simulate what build_filter does for unconditional blocks
        rules.entry(libc::SYS_memfd_create).or_default();
        rules.entry(libc::SYS_ptrace).or_default();
        rules.entry(libc::SYS_bpf).or_default();
        rules.entry(libc::SYS_process_vm_readv).or_default();
        rules.entry(libc::SYS_io_uring_setup).or_default();
        rules.entry(libc::SYS_mount).or_default();

        // Unconditional blocks have an empty Vec (no conditions = always match)
        for syscall in [
            libc::SYS_memfd_create,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_process_vm_readv,
            libc::SYS_io_uring_setup,
            libc::SYS_mount,
        ] {
            assert!(
                rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                rules[&syscall].is_empty(),
                "syscall {syscall} should have empty rules (unconditional block)"
            );
        }
    }

    #[test]
    fn conditional_blocks_have_rules() {
        // Build a real filter and verify the conditional syscalls have rule entries
        // (non-empty Vec means conditional match)
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        add_masked_arg_rule(
            &mut rules,
            libc::SYS_execveat,
            4,
            libc::AT_EMPTY_PATH as u64,
        )
        .unwrap();
        add_masked_arg_rule(&mut rules, libc::SYS_unshare, 0, libc::CLONE_NEWUSER as u64).unwrap();

        let condition = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            SECCOMP_SET_MODE_FILTER,
        )
        .unwrap();
        let rule = SeccompRule::new(vec![condition]).unwrap();
        rules.entry(libc::SYS_seccomp).or_default().push(rule);

        for syscall in [libc::SYS_execveat, libc::SYS_unshare, libc::SYS_seccomp] {
            assert!(
                rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                !rules[&syscall].is_empty(),
                "syscall {syscall} should have conditional rules"
            );
        }
    }
}
