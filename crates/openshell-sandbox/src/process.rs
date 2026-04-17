// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process management and signal handling.

use crate::child_env;
use crate::policy::{NetworkMode, SandboxPolicy};
use crate::sandbox;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::netns::NetworkNamespace;
#[cfg(target_os = "linux")]
use crate::{register_managed_child, unregister_managed_child};
use miette::{IntoDiagnostic, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::{Group, Pid, User};
use std::collections::HashMap;
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::debug;

const SSH_HANDSHAKE_SECRET_ENV: &str = "OPENSHELL_SSH_HANDSHAKE_SECRET";

fn inject_provider_env(cmd: &mut Command, provider_env: &HashMap<String, String>) {
    for (key, value) in provider_env {
        cmd.env(key, value);
    }
}

fn scrub_sensitive_env(cmd: &mut Command) {
    cmd.env_remove(SSH_HANDSHAKE_SECRET_ENV);
}

#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn harden_child_process() -> Result<()> {
    let core_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) };
    if rc != 0 {
        return Err(miette::miette!(
            "Failed to disable core dumps: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Limit process creation to prevent fork bombs. 512 processes per UID is
    // sufficient for typical agent workloads (shell, compilers, language servers)
    // while preventing runaway forking. Set as a hard limit so the sandbox user
    // cannot raise it after privilege drop.
    let nproc_limit = libc::rlimit {
        rlim_cur: 512,
        rlim_max: 512,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &nproc_limit) };
    if rc != 0 {
        return Err(miette::miette!(
            "Failed to set RLIMIT_NPROC: {}",
            std::io::Error::last_os_error()
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(miette::miette!(
                "Failed to set PR_SET_DUMPABLE=0: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

/// Handle to a running process.
pub struct ProcessHandle {
    child: Child,
    pid: u32,
}

impl ProcessHandle {
    /// Spawn a new process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process fails to start.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        netns: Option<&NetworkNamespace>,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            program,
            args,
            workdir,
            interactive,
            policy,
            netns.and_then(NetworkNamespace::ns_fd),
            ca_paths,
            provider_env,
        )
    }

    /// Spawn a new process (non-Linux platforms).
    ///
    /// # Errors
    ///
    /// Returns an error if the process fails to start.
    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            program,
            args,
            workdir,
            interactive,
            policy,
            ca_paths,
            provider_env,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn spawn_impl(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        netns_fd: Option<RawFd>,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .env("OPENSHELL_SANDBOX", "1");

        scrub_sensitive_env(&mut cmd);
        inject_provider_env(&mut cmd, provider_env);

        if let Some(dir) = workdir {
            cmd.current_dir(dir);
        }

        if matches!(policy.network.mode, NetworkMode::Proxy) {
            let proxy = policy.network.proxy.as_ref().ok_or_else(|| {
                miette::miette!(
                    "Network mode is set to proxy but no proxy configuration was provided"
                )
            })?;
            // When using network namespace, set proxy URL to the veth host IP
            if netns_fd.is_some() {
                // The proxy is on 10.200.0.1:3128 (or configured port)
                let port = proxy.http_addr.map_or(3128, |addr| addr.port());
                let proxy_url = format!("http://10.200.0.1:{port}");
                // Both uppercase and lowercase variants: curl/wget use uppercase,
                // gRPC C-core (libgrpc) checks lowercase http_proxy/https_proxy.
                for (key, value) in child_env::proxy_env_vars(&proxy_url) {
                    cmd.env(key, value);
                }
            } else if let Some(http_addr) = proxy.http_addr {
                let proxy_url = format!("http://{http_addr}");
                for (key, value) in child_env::proxy_env_vars(&proxy_url) {
                    cmd.env(key, value);
                }
            }
        }

        // Set TLS trust store env vars so sandbox processes trust the ephemeral CA
        if let Some((ca_cert_path, combined_bundle_path)) = ca_paths {
            for (key, value) in child_env::tls_env_vars(ca_cert_path, combined_bundle_path) {
                cmd.env(key, value);
            }
        }

        // Probe Landlock availability and emit OCSF logs from the parent
        // process where the tracing subscriber is functional. The child's
        // pre_exec context cannot reliably emit structured logs.
        #[cfg(target_os = "linux")]
        sandbox::linux::log_sandbox_readiness(policy, workdir);

        // Phase 1 (as root): Prepare Landlock ruleset by opening PathFds.
        // This MUST happen before drop_privileges() so that root-only paths
        // (e.g. mode 700 directories) can be opened. See issue #803.
        #[cfg(target_os = "linux")]
        let prepared_sandbox = sandbox::linux::prepare(policy, workdir)
            .map_err(|err| miette::miette!("Failed to prepare sandbox: {err}"))?;

        // Set up process group for signal handling (non-interactive mode only).
        // In interactive mode, we inherit the parent's process group to maintain
        // proper terminal control for shells and interactive programs.
        // SAFETY: pre_exec runs after fork but before exec in the child process.
        // setpgid and setns are async-signal-safe and safe to call in this context.
        {
            let policy = policy.clone();
            // Wrap in Option so we can .take() it out of the FnMut closure.
            // pre_exec is only called once (after fork, before exec).
            #[cfg(target_os = "linux")]
            let mut prepared_sandbox = Some(prepared_sandbox);
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if !interactive {
                        // Create new process group
                        libc::setpgid(0, 0);
                    }

                    // Enter network namespace before applying other restrictions
                    if let Some(fd) = netns_fd {
                        let result = libc::setns(fd, libc::CLONE_NEWNET);
                        if result != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }

                    // Drop privileges. initgroups/setgid/setuid need access to
                    // /etc/group and /etc/passwd which would be blocked if
                    // Landlock were already enforced.
                    drop_privileges(&policy)
                        .map_err(|err| std::io::Error::other(err.to_string()))?;

                    harden_child_process().map_err(|err| std::io::Error::other(err.to_string()))?;

                    // Phase 2 (as unprivileged user): Enforce the prepared
                    // Landlock ruleset via restrict_self() + apply seccomp.
                    // restrict_self() does not require root.
                    #[cfg(target_os = "linux")]
                    if let Some(prepared) = prepared_sandbox.take() {
                        sandbox::linux::enforce(prepared)
                            .map_err(|err| std::io::Error::other(err.to_string()))?;
                    }

                    Ok(())
                });
            }
        }

        let child = cmd.spawn().into_diagnostic()?;
        let pid = child.id().unwrap_or(0);
        register_managed_child(pid);

        debug!(pid, program, "Process spawned");

        Ok(Self { child, pid })
    }

    #[cfg(not(target_os = "linux"))]
    fn spawn_impl(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .env("OPENSHELL_SANDBOX", "1");

        scrub_sensitive_env(&mut cmd);
        inject_provider_env(&mut cmd, provider_env);

        if let Some(dir) = workdir {
            cmd.current_dir(dir);
        }

        if matches!(policy.network.mode, NetworkMode::Proxy) {
            let proxy = policy.network.proxy.as_ref().ok_or_else(|| {
                miette::miette!(
                    "Network mode is set to proxy but no proxy configuration was provided"
                )
            })?;
            if let Some(http_addr) = proxy.http_addr {
                let proxy_url = format!("http://{http_addr}");
                for (key, value) in child_env::proxy_env_vars(&proxy_url) {
                    cmd.env(key, value);
                }
            }
        }

        // Set TLS trust store env vars so sandbox processes trust the ephemeral CA
        if let Some((ca_cert_path, combined_bundle_path)) = ca_paths {
            for (key, value) in child_env::tls_env_vars(ca_cert_path, combined_bundle_path) {
                cmd.env(key, value);
            }
        }

        // Set up process group for signal handling (non-interactive mode only).
        // In interactive mode, we inherit the parent's process group to maintain
        // proper terminal control for shells and interactive programs.
        // SAFETY: pre_exec runs after fork but before exec in the child process.
        // setpgid is async-signal-safe and safe to call in this context.
        #[cfg(unix)]
        {
            let policy = policy.clone();
            let workdir = workdir.map(str::to_string);
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if !interactive {
                        // Create new process group
                        libc::setpgid(0, 0);
                    }

                    // Drop privileges before applying sandbox restrictions.
                    // initgroups/setgid/setuid need access to /etc/group and /etc/passwd
                    // which may be blocked by Landlock.
                    drop_privileges(&policy)
                        .map_err(|err| std::io::Error::other(err.to_string()))?;

                    harden_child_process().map_err(|err| std::io::Error::other(err.to_string()))?;

                    sandbox::apply(&policy, workdir.as_deref())
                        .map_err(|err| std::io::Error::other(err.to_string()))?;

                    Ok(())
                });
            }
        }

        let child = cmd.spawn().into_diagnostic()?;
        let pid = child.id().unwrap_or(0);
        #[cfg(target_os = "linux")]
        register_managed_child(pid);

        debug!(pid, program, "Process spawned");

        Ok(Self { child, pid })
    }

    /// Get the process ID.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting fails.
    pub async fn wait(&mut self) -> std::io::Result<ProcessStatus> {
        let status = self.child.wait().await;
        #[cfg(target_os = "linux")]
        unregister_managed_child(self.pid);
        let status = status?;
        Ok(ProcessStatus::from(status))
    }

    /// Send a signal to the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent.
    pub fn signal(&self, sig: Signal) -> Result<()> {
        let pid = i32::try_from(self.pid).unwrap_or(i32::MAX);
        signal::kill(Pid::from_raw(pid), sig).into_diagnostic()
    }

    /// Kill the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be killed.
    pub fn kill(&mut self) -> Result<()> {
        // First try SIGTERM
        if let Err(e) = self.signal(Signal::SIGTERM) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ProcessActivityBuilder::new(crate::ocsf_ctx())
                    .activity(openshell_ocsf::ActivityId::Close)
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .message(format!("Failed to send SIGTERM: {e}"))
                    .build()
            );
        }

        // Give the process a moment to terminate gracefully
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Force kill if still running
        if let Some(id) = self.child.id() {
            debug!(pid = id, "Sending SIGKILL");
            let pid = i32::try_from(id).unwrap_or(i32::MAX);
            let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
        }

        Ok(())
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unregister_managed_child(self.pid);
    }
}

#[cfg(unix)]
pub fn drop_privileges(policy: &SandboxPolicy) -> Result<()> {
    let user_name = match policy.process.run_as_user.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };
    let group_name = match policy.process.run_as_group.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };

    // If no user/group is configured and we are running as root, fall back to
    // "sandbox:sandbox" instead of silently keeping root.  This covers the
    // local/dev-mode path where policies are loaded from disk and never pass
    // through the server-side `ensure_sandbox_process_identity` normalization.
    // For non-root runtimes, the no-op is safe -- we are already unprivileged.
    if user_name.is_none() && group_name.is_none() {
        if nix::unistd::geteuid().is_root() {
            let mut fallback = policy.clone();
            fallback.process.run_as_user = Some("sandbox".into());
            fallback.process.run_as_group = Some("sandbox".into());
            return drop_privileges(&fallback);
        }
        return Ok(());
    }

    let user = if let Some(name) = user_name {
        User::from_name(name)
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("Sandbox user not found: {name}"))?
    } else {
        User::from_uid(nix::unistd::geteuid())
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("Failed to resolve current user"))?
    };

    let group = if let Some(name) = group_name {
        Group::from_name(name)
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("Sandbox group not found: {name}"))?
    } else {
        Group::from_gid(user.gid)
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("Failed to resolve user primary group"))?
    };

    if user_name.is_some() {
        let user_cstr =
            CString::new(user.name.clone()).map_err(|_| miette::miette!("Invalid user name"))?;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "haiku",
            target_os = "redox"
        ))]
        {
            let _ = user_cstr;
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "haiku",
            target_os = "redox"
        )))]
        {
            nix::unistd::initgroups(user_cstr.as_c_str(), group.gid).into_diagnostic()?;
        }
    }

    nix::unistd::setgid(group.gid).into_diagnostic()?;

    // Verify effective GID actually changed (defense-in-depth, CWE-250 / CERT POS37-C)
    let effective_gid = nix::unistd::getegid();
    if effective_gid != group.gid {
        return Err(miette::miette!(
            "Privilege drop verification failed: expected effective GID {}, got {}",
            group.gid,
            effective_gid
        ));
    }

    if user_name.is_some() {
        nix::unistd::setuid(user.uid).into_diagnostic()?;

        // Verify effective UID actually changed (defense-in-depth, CWE-250 / CERT POS37-C)
        let effective_uid = nix::unistd::geteuid();
        if effective_uid != user.uid {
            return Err(miette::miette!(
                "Privilege drop verification failed: expected effective UID {}, got {}",
                user.uid,
                effective_uid
            ));
        }

        // Verify root cannot be re-acquired (CERT POS37-C hardening).
        // If we dropped from root, setuid(0) must fail; success means privileges
        // were not fully relinquished.
        if nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).is_ok() && user.uid.as_raw() != 0 {
            return Err(miette::miette!(
                "Privilege drop verification failed: process can still re-acquire root (UID 0) \
                 after switching to UID {}",
                user.uid
            ));
        }
    }

    Ok(())
}

/// Process exit status.
#[derive(Debug, Clone, Copy)]
pub struct ProcessStatus {
    code: Option<i32>,
    signal: Option<i32>,
}

impl ProcessStatus {
    /// Get the exit code, or 128 + signal number if killed by signal.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
            .or_else(|| self.signal.map(|s| 128 + s))
            .unwrap_or(-1)
    }

    /// Check if the process exited successfully.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Get the signal that killed the process, if any.
    #[must_use]
    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }
}

impl From<std::process::ExitStatus> for ProcessStatus {
    fn from(status: std::process::ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }

        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };
    #[cfg(unix)]
    use nix::sys::wait::{WaitStatus, waitpid};
    #[cfg(unix)]
    use nix::unistd::{ForkResult, fork};
    #[cfg(unix)]
    use std::mem::size_of;
    use std::process::Stdio as StdStdio;

    /// Helper to create a minimal `SandboxPolicy` with the given process policy.
    fn policy_with_process(process: ProcessPolicy) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process,
        }
    }

    #[test]
    fn drop_privileges_noop_when_no_user_or_group() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: None,
            run_as_group: None,
        });
        if nix::unistd::geteuid().is_root() {
            // As root, drop_privileges falls back to "sandbox:sandbox".
            // If that user exists, it succeeds; if not (e.g. CI), it
            // must error rather than silently keep root.
            let has_sandbox = User::from_name("sandbox").ok().flatten().is_some();
            assert_eq!(drop_privileges(&policy).is_ok(), has_sandbox);
        } else {
            assert!(drop_privileges(&policy).is_ok());
        }
    }

    #[test]
    fn drop_privileges_noop_when_empty_strings() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(String::new()),
            run_as_group: Some(String::new()),
        });
        if nix::unistd::geteuid().is_root() {
            let has_sandbox = User::from_name("sandbox").ok().flatten().is_some();
            assert_eq!(drop_privileges(&policy).is_ok(), has_sandbox);
        } else {
            assert!(drop_privileges(&policy).is_ok());
        }
    }

    #[test]
    fn drop_privileges_succeeds_for_current_group() {
        // Set only run_as_group (no run_as_user) so that initgroups() is not
        // called.  initgroups(3) requires CAP_SETGID/root even when the target
        // is the current user, so it cannot be exercised without elevated
        // privileges.  This test covers the setgid() + GID post-condition
        // verification path without needing root.
        let current_group = Group::from_gid(nix::unistd::getegid())
            .expect("getgrgid")
            .expect("current group entry");

        let policy = policy_with_process(ProcessPolicy {
            run_as_user: None,
            run_as_group: Some(current_group.name),
        });

        assert!(drop_privileges(&policy).is_ok());
    }

    #[test]
    #[ignore = "initgroups(3) requires CAP_SETGID; run as root: sudo cargo test -- --ignored"]
    fn drop_privileges_succeeds_for_current_user() {
        // Exercises the full privilege-drop path including initgroups(),
        // setgid(), setuid(), and the root-reacquisition check.  Requires
        // CAP_SETGID (root) because initgroups(3) calls setgroups(2)
        // internally.  Fixes: https://github.com/NVIDIA/OpenShell/issues/622
        let current_user = User::from_uid(nix::unistd::geteuid())
            .expect("getpwuid")
            .expect("current user entry");
        let current_group = Group::from_gid(nix::unistd::getegid())
            .expect("getgrgid")
            .expect("current group entry");

        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(current_user.name),
            run_as_group: Some(current_group.name),
        });

        assert!(drop_privileges(&policy).is_ok());
    }

    #[test]
    fn drop_privileges_fails_for_nonexistent_user() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("__nonexistent_test_user_42__".to_string()),
            run_as_group: None,
        });

        let result = drop_privileges(&policy);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not found"),
            "expected 'not found' in error: {msg}"
        );
    }

    #[test]
    fn drop_privileges_fails_for_nonexistent_group() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: None,
            run_as_group: Some("__nonexistent_test_group_42__".to_string()),
        });

        let result = drop_privileges(&policy);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not found"),
            "expected 'not found' in error: {msg}"
        );
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn probe_hardened_child(probe: unsafe fn() -> i64) -> i64 {
        const HARDEN_FAILED: i64 = -2;

        let mut fds = [0; 2];
        let pipe_rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(
            pipe_rc,
            0,
            "pipe failed: {}",
            std::io::Error::last_os_error()
        );

        match unsafe { fork() }.expect("fork should succeed") {
            ForkResult::Child => {
                unsafe { libc::close(fds[0]) };
                let value = match harden_child_process() {
                    Ok(()) => unsafe { probe() },
                    Err(_) => HARDEN_FAILED,
                };
                let bytes = value.to_ne_bytes();
                let written = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), bytes.len()) };
                unsafe {
                    libc::close(fds[1]);
                    libc::_exit(if written == bytes.len() as isize {
                        0
                    } else {
                        1
                    });
                }
            }
            ForkResult::Parent { child } => {
                unsafe { libc::close(fds[1]) };
                let mut bytes = [0u8; size_of::<i64>()];
                let read = unsafe { libc::read(fds[0], bytes.as_mut_ptr().cast(), bytes.len()) };
                unsafe { libc::close(fds[0]) };
                assert_eq!(
                    read as usize,
                    bytes.len(),
                    "expected {} probe bytes, got {}",
                    bytes.len(),
                    read
                );

                match waitpid(child, None).expect("waitpid should succeed") {
                    WaitStatus::Exited(_, 0) => {}
                    status => panic!("probe child exited unexpectedly: {status:?}"),
                }

                i64::from_ne_bytes(bytes)
            }
        }
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    unsafe fn core_dump_limit_is_zero_probe() -> i64 {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, limit.as_mut_ptr()) };
        if rc != 0 {
            return -1;
        }
        let limit = unsafe { limit.assume_init() };
        i64::from(limit.rlim_cur == 0 && limit.rlim_max == 0)
    }

    #[test]
    #[cfg(unix)]
    fn harden_child_process_disables_core_dumps() {
        assert_eq!(probe_hardened_child(core_dump_limit_is_zero_probe), 1);
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    unsafe fn dumpable_flag_probe() -> i64 {
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) as i64 }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn harden_child_process_marks_process_nondumpable() {
        assert_eq!(probe_hardened_child(dumpable_flag_probe), 0);
    }

    #[tokio::test]
    async fn scrub_sensitive_env_removes_ssh_handshake_secret() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null())
            .env(SSH_HANDSHAKE_SECRET_ENV, "super-secret");

        scrub_sensitive_env(&mut cmd);

        let output = cmd.output().await.expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(!stdout.contains(SSH_HANDSHAKE_SECRET_ENV));
    }

    #[tokio::test]
    async fn inject_provider_env_sets_placeholder_values() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null());

        let provider_env = std::iter::once((
            "ANTHROPIC_API_KEY".to_string(),
            "openshell:resolve:env:ANTHROPIC_API_KEY".to_string(),
        ))
        .collect();

        inject_provider_env(&mut cmd, &provider_env);

        let output = cmd.output().await.expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(stdout.contains("ANTHROPIC_API_KEY=openshell:resolve:env:ANTHROPIC_API_KEY"));
    }
}
