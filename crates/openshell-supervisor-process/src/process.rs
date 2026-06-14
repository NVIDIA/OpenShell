// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process management and signal handling.

use crate::child_env;
#[cfg(target_os = "linux")]
use crate::managed_children;
#[cfg(target_os = "linux")]
use crate::netns::NetworkNamespace;
use crate::sandbox;
use miette::{IntoDiagnostic, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::{Group, Pid, User};
use openshell_core::policy::{NetworkMode, SandboxPolicy};
use std::collections::HashMap;
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(test, unix))]
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use tokio::process::{Child, Command};
use tracing::debug;

const SUPERVISOR_ONLY_ENV_VARS: &[&str] = &[
    openshell_core::sandbox_env::SANDBOX_TOKEN,
    openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
    openshell_core::sandbox_env::K8S_SA_TOKEN_FILE,
    openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
];

pub fn is_supervisor_only_env_var(key: &str) -> bool {
    SUPERVISOR_ONLY_ENV_VARS.contains(&key)
}

fn strip_supervisor_only_env(cmd: &mut Command) {
    for key in SUPERVISOR_ONLY_ENV_VARS {
        cmd.env_remove(key);
    }
}

fn inject_provider_env(cmd: &mut Command, provider_env: &HashMap<String, String>) {
    for (key, value) in provider_env {
        if is_supervisor_only_env_var(key) {
            continue;
        }
        cmd.env(key, value);
    }
}

#[cfg(unix)]
pub fn harden_child_process() -> Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| miette::miette!("Failed to disable core dumps: {e}"))?;

    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|e| miette::miette!("Failed to set PR_SET_DUMPABLE=0: {e}"))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
const CGROUP_PIDS_MAX_PATH: &str = "/sys/fs/cgroup/pids.max";

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimePidLimitStatus {
    Limited(u64),
    Unlimited,
    Unavailable(String),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePidLimitMode {
    Warn,
    Require,
}

#[cfg(target_os = "linux")]
pub fn check_runtime_pid_limit(mode: RuntimePidLimitMode) -> Result<()> {
    check_runtime_pid_limit_status(runtime_pid_limit_status(), mode)
}

#[cfg(target_os = "linux")]
fn check_runtime_pid_limit_status(
    status: RuntimePidLimitStatus,
    mode: RuntimePidLimitMode,
) -> Result<()> {
    match status {
        RuntimePidLimitStatus::Limited(limit) => {
            debug!(pids_max = limit, "runtime PID limit detected");
            Ok(())
        }
        RuntimePidLimitStatus::Unlimited => {
            let message = "runtime cgroup pids.max is unlimited; configure the compute driver or container runtime to enforce a PID limit";
            if matches!(mode, RuntimePidLimitMode::Require) {
                Err(miette::miette!(message))
            } else {
                tracing::warn!("{message}");
                Ok(())
            }
        }
        RuntimePidLimitStatus::Unavailable(reason) => {
            let message = format!(
                "runtime cgroup pids.max is unavailable ({reason}); configure the compute driver or container runtime to enforce a PID limit"
            );
            if matches!(mode, RuntimePidLimitMode::Require) {
                Err(miette::miette!(message))
            } else {
                tracing::warn!("{message}");
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn runtime_pid_limit_status() -> RuntimePidLimitStatus {
    match std::fs::read_to_string(CGROUP_PIDS_MAX_PATH) {
        Ok(contents) => parse_pids_max(&contents),
        Err(err) => RuntimePidLimitStatus::Unavailable(err.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn parse_pids_max(contents: &str) -> RuntimePidLimitStatus {
    let raw = contents.trim();
    if raw.eq_ignore_ascii_case("max") {
        return RuntimePidLimitStatus::Unlimited;
    }
    match raw.parse::<u64>() {
        Ok(limit) => RuntimePidLimitStatus::Limited(limit),
        Err(err) => {
            RuntimePidLimitStatus::Unavailable(format!("invalid pids.max value {raw:?}: {err}"))
        }
    }
}

// Pins the pre-seccomp child mount namespace where supervisor identity sockets
// are shadowed. Children enter it with setns before dropping privileges.
#[cfg(target_os = "linux")]
static SUPERVISOR_IDENTITY_MOUNT_NS: OnceLock<Option<SupervisorIdentityMountNamespace>> =
    OnceLock::new();

#[cfg(target_os = "linux")]
pub struct SupervisorIdentityMountNamespace {
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
type SupervisorIdentityNsRef = &'static SupervisorIdentityMountNamespace;

#[cfg(target_os = "linux")]
impl SupervisorIdentityMountNamespace {
    fn from_socket_path(socket_path: &str) -> Result<Option<Self>> {
        let Some(target) = supervisor_identity_mount_target(socket_path)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            fd: create_supervisor_identity_mount_namespace(&target)?,
        }))
    }

    pub fn enter_for_child(&self) -> std::io::Result<()> {
        set_mount_namespace(self.fd.as_raw_fd())
    }
}

#[cfg(target_os = "linux")]
pub fn prepare_supervisor_identity_mount_namespace_from_env() -> Result<()> {
    if SUPERVISOR_IDENTITY_MOUNT_NS.get().is_some() {
        return Ok(());
    }

    let Some((_env_name, socket_path)) = supervisor_identity_socket_path_from_env() else {
        let _ = SUPERVISOR_IDENTITY_MOUNT_NS.set(None);
        return Ok(());
    };
    let namespace = SupervisorIdentityMountNamespace::from_socket_path(&socket_path)?;
    let _ = SUPERVISOR_IDENTITY_MOUNT_NS.set(namespace);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn supervisor_identity_mount_from_env() -> Result<Option<SupervisorIdentityNsRef>> {
    let Some(namespace) = SUPERVISOR_IDENTITY_MOUNT_NS.get() else {
        if supervisor_identity_socket_path_from_env().is_some() {
            return Err(miette::miette!(
                "supervisor identity mount namespace was not prepared before startup hardening"
            ));
        }
        return Ok(None);
    };
    Ok(namespace.as_ref())
}

#[cfg(target_os = "linux")]
fn supervisor_identity_socket_path_from_env() -> Option<(&'static str, String)> {
    std::env::var(openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET)
        .ok()
        .filter(|socket_path| !socket_path.trim().is_empty())
        .map(|socket_path| {
            (
                openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
                socket_path,
            )
        })
}

#[cfg(any(test, target_os = "linux"))]
fn supervisor_identity_mount_target(socket_path: &str) -> Result<Option<PathBuf>> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with("tcp:") {
        return Err(miette::miette!(
            "{} must be a UNIX socket path so sandbox child processes can hide it",
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
        ));
    }
    let path = trimmed.strip_prefix("unix:").unwrap_or(trimmed);
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(miette::miette!(
            "{} must be an absolute UNIX socket path",
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(miette::miette!(
            "{} has no parent directory",
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
        ));
    };
    if parent == Path::new("/") {
        return Err(miette::miette!(
            "{} must live below a dedicated directory, not directly under /",
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
        ));
    }
    if is_shared_root_mount_shadow(parent) {
        return Err(miette::miette!(
            "{} must live below a dedicated subdirectory; refusing to hide shared directory {}",
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            parent.display()
        ));
    }
    Ok(Some(parent.to_path_buf()))
}

#[cfg(any(test, target_os = "linux"))]
fn is_shared_root_mount_shadow(parent: &Path) -> bool {
    matches!(parent.to_str(), Some("/run" | "/var" | "/tmp" | "/etc"))
}

#[cfg(target_os = "linux")]
fn cstring_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| miette::miette!("path contains an interior NUL byte: {}", path.display()))
}

#[cfg(target_os = "linux")]
fn create_supervisor_identity_mount_namespace(target: &Path) -> Result<OwnedFd> {
    let original_ns = open_current_mount_namespace()
        .map_err(|err| miette::miette!("failed to open original mount namespace: {err}"))?;

    private_mount_namespace()
        .map_err(|err| miette::miette!("failed to create supervisor identity namespace: {err}"))?;

    let target = cstring_path(target)?;
    let result = (|| -> Result<OwnedFd> {
        mount_empty_tmpfs(&target).map_err(|err| {
            miette::miette!("failed to hide supervisor identity mount from child namespace: {err}")
        })?;
        open_current_mount_namespace()
            .map_err(|err| miette::miette!("failed to open sanitized mount namespace: {err}"))
    })();

    set_mount_namespace(original_ns.as_raw_fd()).map_err(|restore_err| {
        let result_msg = result.as_ref().err().map_or_else(
            || "sanitized namespace was created".to_string(),
            ToString::to_string,
        );
        miette::miette!(
            "failed to restore original mount namespace after supervisor identity isolation setup: \
             {restore_err}; setup result: {result_msg}"
        )
    })?;

    result
}

#[cfg(target_os = "linux")]
fn open_current_mount_namespace() -> std::io::Result<OwnedFd> {
    let file = std::fs::File::open("/proc/thread-self/ns/mnt")?;
    Ok(file.into())
}

#[cfg(target_os = "linux")]
fn private_mount_namespace() -> std::io::Result<()> {
    #[allow(unsafe_code)]
    let rc = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if rc != 0 {
        return Err(std::io::Error::other(format!(
            "failed to create private mount namespace: {}",
            std::io::Error::last_os_error()
        )));
    }

    #[allow(unsafe_code)]
    let rc = unsafe {
        let flags: libc::c_ulong = libc::MS_REC | libc::MS_PRIVATE;
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::other(format!(
            "failed to mark mount namespace private: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_mount_namespace(fd: RawFd) -> std::io::Result<()> {
    #[allow(unsafe_code)]
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNS) };
    if rc != 0 {
        return Err(std::io::Error::other(format!(
            "failed to enter mount namespace: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_empty_tmpfs(target: &CString) -> std::io::Result<()> {
    #[allow(unsafe_code)]
    let rc = unsafe {
        let flags: libc::c_ulong =
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY;
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            flags,
            c"mode=0555,size=4k".as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::other(format!(
            "failed to hide supervisor identity mount from child process: {}",
            std::io::Error::last_os_error()
        )));
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
            .env(openshell_core::sandbox_env::SANDBOX, "1");

        // Strip supervisor-only identity material from the entrypoint's
        // inherited environment. The entrypoint drops to the sandbox user
        // before `exec`; without this strip, sandbox code could recover
        // supervisor credentials from its inherited environment.
        strip_supervisor_only_env(&mut cmd);

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
        #[cfg(target_os = "linux")]
        let supervisor_identity_mount = supervisor_identity_mount_from_env().map_err(|err| {
            miette::miette!("Failed to prepare supervisor identity isolation: {err}")
        })?;

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

                    #[cfg(target_os = "linux")]
                    if let Some(mount) = supervisor_identity_mount {
                        mount.enter_for_child()?;
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
        managed_children::register(pid);

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
            .env(openshell_core::sandbox_env::SANDBOX, "1");

        // Strip supervisor-only identity material from the entrypoint's
        // inherited environment.
        strip_supervisor_only_env(&mut cmd);

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
        managed_children::register(pid);

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
        managed_children::unregister(self.pid);
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
                openshell_ocsf::ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
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
        managed_children::unregister(self.pid);
    }
}

/// Validate that the `sandbox` user exists in this image.
///
/// All sandbox images must include a `sandbox` user for privilege dropping.
/// This check runs at supervisor startup (inside the container) where we can
/// inspect `/etc/passwd`. If the user is missing, the sandbox fails fast
/// with a clear error instead of silently running child processes as root.
#[cfg(unix)]
pub fn validate_sandbox_user(policy: &SandboxPolicy) -> Result<()> {
    let user_name = policy.process.run_as_user.as_deref().unwrap_or("sandbox");

    if user_name.is_empty() || user_name == "sandbox" {
        match User::from_name("sandbox") {
            Ok(Some(_)) => {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::Informational)
                        .status(openshell_ocsf::StatusId::Success)
                        .state(openshell_ocsf::StateId::Enabled, "validated")
                        .message("Validated 'sandbox' user exists in image")
                        .build()
                );
            }
            Ok(None) => {
                return Err(miette::miette!(
                    "sandbox user 'sandbox' not found in image; \
                     all sandbox images must include a 'sandbox' user and group"
                ));
            }
            Err(e) => {
                return Err(miette::miette!("failed to look up 'sandbox' user: {e}"));
            }
        }
    }

    Ok(())
}

/// Prepare a `read_write` path for the sandboxed process.
///
/// Returns `true` when the path was created by the supervisor and therefore
/// still needs to be chowned to the sandbox user/group. Existing paths keep
/// their image-defined ownership.
#[cfg(unix)]
fn prepare_read_write_path(path: &Path) -> Result<bool> {
    // SECURITY: use symlink_metadata (lstat) to inspect each path *before*
    // calling chown. chown follows symlinks, so a malicious container image
    // could place a symlink (e.g. /sandbox -> /etc/shadow) to trick the
    // root supervisor into transferring ownership of arbitrary files.
    // The TOCTOU window between lstat and chown is not exploitable because
    // no untrusted process is running yet (the child has not been forked).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(miette::miette!(
                "read_write path '{}' is a symlink — refusing to chown (potential privilege escalation)",
                path.display()
            ));
        }

        debug!(
            path = %path.display(),
            "Preserving ownership for existing read_write path"
        );
        Ok(false)
    } else {
        debug!(path = %path.display(), "Creating read_write directory");
        std::fs::create_dir_all(path).into_diagnostic()?;
        Ok(true)
    }
}

/// Prepare filesystem for the sandboxed process.
///
/// Creates `read_write` directories if they don't exist and sets ownership
/// on newly-created paths to the configured sandbox user/group. This runs as
/// the supervisor (root) before forking the child process.
#[cfg(unix)]
pub fn prepare_filesystem(policy: &SandboxPolicy) -> Result<()> {
    use nix::unistd::chown;

    let user_name = match policy.process.run_as_user.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };
    let group_name = match policy.process.run_as_group.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };

    // If no user/group configured, nothing to do
    if user_name.is_none() && group_name.is_none() {
        return Ok(());
    }

    // Resolve user and group
    let uid = if let Some(name) = user_name {
        Some(
            User::from_name(name)
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("Sandbox user not found: {name}"))?
                .uid,
        )
    } else {
        None
    };

    let gid = if let Some(name) = group_name {
        Some(
            Group::from_name(name)
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("Sandbox group not found: {name}"))?
                .gid,
        )
    } else {
        None
    };

    // Create missing read_write paths and only chown the ones we created.
    for path in &policy.filesystem.read_write {
        if prepare_read_write_path(path)? {
            debug!(
                path = %path.display(),
                ?uid,
                ?gid,
                "Setting ownership on newly created read_write path"
            );
            chown(path, uid, gid).into_diagnostic()?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn prepare_filesystem(_policy: &SandboxPolicy) -> Result<()> {
    Ok(())
}

// `effective_gid`/`effective_uid` are intentionally parallel names (same role
// for different identifiers) and the noise from renaming would obscure intent.
#[cfg(unix)]
#[allow(clippy::similar_names)]
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
    #[cfg(unix)]
    use nix::sys::wait::{WaitStatus, waitpid};
    #[cfg(unix)]
    use nix::unistd::{ForkResult, fork};
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };
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

    /// Unknown names may yield `Ok(None)` (`… not found …`) or `Err` when NSS fails first
    /// (e.g. `ENOENT: No such file or directory`).
    fn assert_unknown_identity_lookup_failed(msg: &str) {
        assert!(
            msg.contains("not found")
                || msg.contains("ENOENT")
                || msg.contains("No such file or directory"),
            "expected unknown user/group lookup failure (…not found… or ENOENT): {msg}"
        );
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
        assert_unknown_identity_lookup_failed(&msg);
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
        assert_unknown_identity_lookup_failed(&msg);
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
                    libc::_exit(i32::from(written != bytes.len().cast_signed()));
                }
            }
            ForkResult::Parent { child } => {
                unsafe { libc::close(fds[1]) };
                let mut bytes = [0u8; size_of::<i64>()];
                let read = unsafe { libc::read(fds[0], bytes.as_mut_ptr().cast(), bytes.len()) };
                unsafe { libc::close(fds[0]) };
                assert_eq!(
                    read.cast_unsigned(),
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
        unsafe { i64::from(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0)) }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn harden_child_process_marks_process_nondumpable() {
        assert_eq!(probe_hardened_child(dumpable_flag_probe), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parse_pids_max_detects_limited_runtime() {
        assert_eq!(
            parse_pids_max("2048\n"),
            RuntimePidLimitStatus::Limited(2048)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parse_pids_max_detects_unlimited_runtime() {
        assert_eq!(parse_pids_max("max\n"), RuntimePidLimitStatus::Unlimited);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parse_pids_max_reports_invalid_values() {
        let status = parse_pids_max("not-a-number\n");
        assert!(matches!(status, RuntimePidLimitStatus::Unavailable(_)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pid_limit_require_mode_rejects_missing_guardrail_statuses() {
        for status in [
            RuntimePidLimitStatus::Unlimited,
            RuntimePidLimitStatus::Unavailable("missing".to_string()),
        ] {
            let result = check_runtime_pid_limit_status(status, RuntimePidLimitMode::Require);
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pid_limit_warn_mode_accepts_missing_guardrail_statuses() {
        for status in [
            RuntimePidLimitStatus::Unlimited,
            RuntimePidLimitStatus::Unavailable("missing".to_string()),
        ] {
            let result = check_runtime_pid_limit_status(status, RuntimePidLimitMode::Warn);
            assert!(result.is_ok());
        }
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

    #[cfg(unix)]
    fn sandbox_policy_with_read_write(
        path: PathBuf,
        run_as_user: Option<String>,
        run_as_group: Option<String>,
    ) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![],
                read_write: vec![path],
                include_workdir: false,
            },
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user,
                run_as_group,
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_creates_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing").join("nested");

        assert!(prepare_read_write_path(&missing).unwrap());
        assert!(missing.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_preserves_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();

        assert!(!prepare_read_write_path(&existing).unwrap());
        assert!(existing.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = prepare_read_write_path(&link).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is a symlink — refusing to chown"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_filesystem_skips_chown_for_existing_read_write_paths() {
        use std::os::unix::fs::MetadataExt;

        if nix::unistd::geteuid().is_root() {
            return;
        }

        let current_user = User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .expect("current user entry");
        let restricted_group = Group::from_gid(nix::unistd::Gid::from_raw(0))
            .unwrap()
            .expect("gid 0 group entry");
        if restricted_group.gid == nix::unistd::getegid() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let before = std::fs::metadata(&existing).unwrap();

        let policy = sandbox_policy_with_read_write(
            existing.clone(),
            Some(current_user.name),
            Some(restricted_group.name),
        );

        prepare_filesystem(&policy).expect("existing path should not be re-owned");

        let after = std::fs::metadata(&existing).unwrap();
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }

    #[tokio::test]
    async fn inject_provider_env_skips_supervisor_identity_material() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env_clear()
            .stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null());

        let provider_env = HashMap::from([
            (
                "ANTHROPIC_API_KEY".to_string(),
                "openshell:resolve:env:ANTHROPIC_API_KEY".to_string(),
            ),
            (
                openshell_core::sandbox_env::SANDBOX_TOKEN.to_string(),
                "provider-token".to_string(),
            ),
            (
                openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET.to_string(),
                "/spiffe-workload-api/spire-agent.sock".to_string(),
            ),
        ]);

        inject_provider_env(&mut cmd, &provider_env);

        let output = cmd.output().await.expect("spawn env");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(stdout.contains("ANTHROPIC_API_KEY=openshell:resolve:env:ANTHROPIC_API_KEY"));
        assert!(!stdout.contains(openshell_core::sandbox_env::SANDBOX_TOKEN));
        assert!(!stdout.contains(openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET));
    }

    #[tokio::test]
    async fn strip_supervisor_only_env_removes_identity_material() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null())
            .env("OPENSHELL_ENDPOINT", "https://gateway.example.test");

        for key in SUPERVISOR_ONLY_ENV_VARS {
            cmd.env(key, format!("{key}-secret"));
        }

        strip_supervisor_only_env(&mut cmd);

        let output = cmd.output().await.expect("spawn env");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        for key in SUPERVISOR_ONLY_ENV_VARS {
            assert!(
                !stdout
                    .lines()
                    .any(|line| line.starts_with(&format!("{key}="))),
                "{key} must not be inherited by sandbox child processes"
            );
        }
        assert!(stdout.contains("OPENSHELL_ENDPOINT=https://gateway.example.test"));
    }

    #[test]
    fn supervisor_identity_mount_target_uses_socket_parent() {
        assert_eq!(
            supervisor_identity_mount_target("/spiffe-workload-api/spire-agent.sock")
                .expect("plain path should parse"),
            Some(PathBuf::from("/spiffe-workload-api"))
        );
        assert_eq!(
            supervisor_identity_mount_target("unix:/spiffe-workload-api/spire-agent.sock")
                .expect("unix path should parse"),
            Some(PathBuf::from("/spiffe-workload-api"))
        );
    }

    #[test]
    fn supervisor_identity_mount_target_ignores_empty_socket_path() {
        assert_eq!(
            supervisor_identity_mount_target("   ").expect("empty path should be ignored"),
            None
        );
    }

    #[test]
    fn supervisor_identity_mount_target_rejects_unhideable_endpoints() {
        assert!(supervisor_identity_mount_target("tcp:127.0.0.1:8081").is_err());
        assert!(supervisor_identity_mount_target("spiffe-workload-api/spire-agent.sock").is_err());
        assert!(supervisor_identity_mount_target("/spire-agent.sock").is_err());
    }

    #[test]
    fn supervisor_identity_mount_target_rejects_shared_root_shadowing() {
        for socket_path in [
            "/run/spire-agent.sock",
            "/var/spire-agent.sock",
            "/tmp/spire-agent.sock",
            "/etc/spire-agent.sock",
        ] {
            let err = supervisor_identity_mount_target(socket_path)
                .expect_err("shared root shadowing should be rejected");
            assert!(err.to_string().contains("dedicated subdirectory"));
        }

        assert_eq!(
            supervisor_identity_mount_target("/run/spire/spire-agent.sock")
                .expect("dedicated subdirectory should be accepted"),
            Some(PathBuf::from("/run/spire"))
        );
    }
}
