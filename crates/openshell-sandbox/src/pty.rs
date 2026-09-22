// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-side PTY and audited pre-exec setup.

use std::os::fd::RawFd;
use std::process::Command;

use nix::pty::Winsize;
use nix::unistd::setsid;
use openshell_core::policy::SandboxPolicy;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

#[allow(unsafe_code)]
pub fn set_winsize(fd: RawFd, winsize: Winsize) -> std::io::Result<()> {
    // SAFETY: fd is the owned PTY master and winsize is initialized.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Install a pre-exec hook that gives the child a dedicated process group.
#[allow(unsafe_code)]
pub fn install_dedicated_process_group(command: &mut Command) {
    // SAFETY: the hook invokes only the async-signal-safe setpgid syscall.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[allow(unsafe_code, clippy::useless_conversion)]
fn set_controlling_tty(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fd is the slave PTY inherited by this pre-exec child.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    unsafe_code,
    clippy::unnecessary_wraps,
    reason = "pre-exec installation remains fallible as the prepared policy evolves"
)]
pub fn install_pre_exec(
    command: &mut Command,
    policy: SandboxPolicy,
    _workdir: Option<String>,
    slave_fd: RawFd,
    #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    #[cfg(target_os = "linux")]
    child_hardening: openshell_isolation_interface::linux::child_seccomp::ChildHardeningProgram,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let mut prepared = prepared;
    #[cfg(target_os = "linux")]
    let mut child_hardening = child_hardening;
    // SAFETY: all allocations and policy compilation happened before spawn;
    // the hook performs only the audited child transition.
    unsafe {
        command.pre_exec(move || {
            setsid().map_err(|error| std::io::Error::other(error.to_string()))?;
            set_controlling_tty(slave_fd)?;
            enter_sandbox(
                &policy,
                #[cfg(target_os = "linux")]
                prepared.take(),
                #[cfg(target_os = "linux")]
                &mut child_hardening,
            )
        });
    }
    Ok(())
}

#[allow(
    unsafe_code,
    clippy::unnecessary_wraps,
    reason = "pre-exec installation remains fallible as the prepared policy evolves"
)]
pub fn install_pre_exec_no_pty(
    command: &mut Command,
    policy: SandboxPolicy,
    _workdir: Option<String>,
    #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    #[cfg(target_os = "linux")]
    child_hardening: openshell_isolation_interface::linux::child_seccomp::ChildHardeningProgram,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let mut prepared = prepared;
    #[cfg(target_os = "linux")]
    let mut child_hardening = child_hardening;
    // SAFETY: all allocations and policy compilation happened before spawn;
    // the hook performs only the audited child transition.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            enter_sandbox(
                &policy,
                #[cfg(target_os = "linux")]
                prepared.take(),
                #[cfg(target_os = "linux")]
                &mut child_hardening,
            )
        });
    }
    Ok(())
}

fn enter_sandbox(
    policy: &SandboxPolicy,
    #[cfg(target_os = "linux")] prepared: Option<crate::sandbox::linux::PreparedSandbox>,
    #[cfg(target_os = "linux")]
    child_hardening: &mut openshell_isolation_interface::linux::child_seccomp::ChildHardeningProgram,
) -> std::io::Result<()> {
    crate::process::harden_child_process()
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    #[cfg(target_os = "linux")]
    if let Some(prepared) = prepared {
        crate::sandbox::linux::enforce_capability_free(prepared, child_hardening)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }

    #[cfg(not(target_os = "linux"))]
    crate::sandbox::apply(policy, None)
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    #[cfg(target_os = "linux")]
    let _ = policy;

    Ok(())
}
