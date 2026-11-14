// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-side PTY and audited pre-exec setup.

use std::os::fd::AsFd;
use std::os::fd::RawFd;
use std::process::Command;

use nix::pty::Winsize;
use nix::unistd::setsid;
use openshell_core::policy::SandboxPolicy;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

pub fn set_winsize(fd: impl AsFd, winsize: Winsize) -> std::io::Result<()> {
    rustix::termios::tcsetwinsize(
        fd,
        rustix::termios::Winsize {
            ws_row: winsize.ws_row,
            ws_col: winsize.ws_col,
            ws_xpixel: winsize.ws_xpixel,
            ws_ypixel: winsize.ws_ypixel,
        },
    )?;
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
    #[cfg(target_os = "linux")] install: crate::sandbox::linux::ChildSandboxInstall,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let mut install = install;
    // SAFETY: the hook runs after fork in the child of a multithreaded
    // process. It uses raw session/TTY syscalls and installs only
    // parent-prebuilt sandbox state (Landlock rulesets, seccomp filters);
    // a best-effort Landlock failure crosses to the parent as one
    // fixed-size pipe record. The success and degradation paths allocate
    // nothing and emit no tracing or OCSF; only a hard error return may
    // allocate, like std's own pre_exec error reporting.
    unsafe {
        command.pre_exec(move || {
            setsid().map_err(|error| std::io::Error::other(error.to_string()))?;
            set_controlling_tty(slave_fd)?;
            enter_sandbox(
                &policy,
                #[cfg(target_os = "linux")]
                &mut install,
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
    #[cfg(target_os = "linux")] install: crate::sandbox::linux::ChildSandboxInstall,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let mut install = install;
    // SAFETY: the hook runs after fork in the child of a multithreaded
    // process. It uses raw process-group syscalls and installs only
    // parent-prebuilt sandbox state (Landlock rulesets, seccomp filters);
    // a best-effort Landlock failure crosses to the parent as one
    // fixed-size pipe record. The success and degradation paths allocate
    // nothing and emit no tracing or OCSF; only a hard error return may
    // allocate, like std's own pre_exec error reporting.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            enter_sandbox(
                &policy,
                #[cfg(target_os = "linux")]
                &mut install,
            )
        });
    }
    Ok(())
}

fn enter_sandbox(
    policy: &SandboxPolicy,
    #[cfg(target_os = "linux")] install: &mut crate::sandbox::linux::ChildSandboxInstall,
) -> std::io::Result<()> {
    crate::process::harden_child_process()
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    #[cfg(target_os = "linux")]
    install
        .enforce()
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    #[cfg(not(target_os = "linux"))]
    crate::sandbox::apply(policy, None)
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    #[cfg(target_os = "linux")]
    let _ = policy;

    Ok(())
}
