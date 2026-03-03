// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Seccomp syscall filtering.

use crate::policy::{NetworkMode, SandboxPolicy};
use miette::{IntoDiagnostic, Result};
use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    apply_filter,
};
use std::collections::BTreeMap;
use std::convert::TryInto;
use tracing::debug;

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
