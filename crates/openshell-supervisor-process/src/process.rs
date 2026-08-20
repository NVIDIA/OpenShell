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
use nix::unistd::{Gid, Group, Pid, Uid, User};
use openshell_core::policy::{NetworkMode, SandboxPolicy};
use std::collections::HashMap;
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(any(test, unix))]
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tracing::{debug, info};

// `libc::TIOCSCTTY` and the request parameter accepted by `ioctl` vary across
// glibc, musl, and BSD targets. The conversion is a no-op on some targets but
// is required on others.
#[cfg(unix)]
#[allow(unsafe_code, clippy::useless_conversion)]
fn set_controlling_tty(fd: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY.into(), 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Process/filesystem enforcement performed by the process supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessEnforcementMode {
    /// Preserve the existing supervisor behavior: prepare filesystem policy,
    /// drop privileges, and apply Landlock/seccomp to workload processes.
    Full,
    /// Preserve process launch and SSH/session behavior, but skip controls
    /// that require root or extra Linux capabilities. Kubernetes sidecar mode
    /// uses this when network policy is enforced by the network sidecar.
    NetworkOnly,
}

/// Numeric identity components resolved once from driver-owned metadata.
///
/// A component is `None` when the corresponding policy field was explicit and
/// must continue through the existing policy identity path. OCI-derived
/// components are carried numerically so later filesystem setup and direct/SSH
/// privilege drops cannot resolve them differently through NSS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolvedProcessIdentity {
    uid: Option<u32>,
    gid: Option<u32>,
}

impl ResolvedProcessIdentity {
    #[must_use]
    pub const fn new(uid: Option<u32>, gid: Option<u32>) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub const fn uid(self) -> Option<u32> {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> Option<u32> {
        self.gid
    }

    /// Whether at least one process identity component came from OCI `USER`.
    ///
    /// Platform-resolved identities are written directly into the policy and
    /// return the default value, so this is specific to Docker/Podman OCI
    /// fallback without adding another driver contract.
    #[must_use]
    pub const fn uses_oci_user_fallback(self) -> bool {
        self.uid.is_some() || self.gid.is_some()
    }
}

/// Resolved process workspace and its child-environment semantics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedWorkspace {
    root: Option<String>,
    use_as_home: bool,
}

impl ResolvedWorkspace {
    #[must_use]
    pub fn new(root: Option<String>, use_as_home: bool) -> Self {
        Self { root, use_as_home }
    }

    #[must_use]
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    #[must_use]
    pub fn owned_root(&self) -> Option<String> {
        self.root.clone()
    }

    #[must_use]
    pub fn home(&self) -> Option<&str> {
        self.use_as_home.then(|| self.root()).flatten()
    }
}

impl ProcessEnforcementMode {
    #[must_use]
    pub const fn uses_privileged_process_setup(self) -> bool {
        matches!(self, Self::Full)
    }

    #[must_use]
    pub const fn enforces_child_sandbox(self) -> bool {
        matches!(self, Self::Full | Self::NetworkOnly)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_child_sandbox(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
    enforcement_mode: ProcessEnforcementMode,
) -> Result<Option<sandbox::linux::PreparedSandbox>> {
    if !enforcement_mode.enforces_child_sandbox() {
        return Ok(None);
    }

    let prepared = if enforcement_mode.uses_privileged_process_setup() {
        sandbox::linux::prepare(policy, workdir)
    } else {
        sandbox::linux::prepare_current_user(policy, workdir)
    }?;
    Ok(Some(prepared))
}

const SUPERVISOR_ONLY_ENV_VARS: &[&str] = &[
    openshell_core::sandbox_env::OCI_IMAGE_USER,
    openshell_core::sandbox_env::SANDBOX_UID,
    openshell_core::sandbox_env::SANDBOX_GID,
    openshell_core::sandbox_env::SANDBOX_TOKEN,
    openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
    openshell_core::sandbox_env::K8S_SA_TOKEN_FILE,
    openshell_core::sandbox_env::TLS_CA,
    openshell_core::sandbox_env::TLS_CERT,
    openshell_core::sandbox_env::TLS_KEY,
    openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
    openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
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

/// Derive the child USER and HOME from the policy's sandbox identity.
///
/// Name-based identities use their passwd entry. Numeric identities have no
/// reliable passwd entry, so their workspace remains the portable fallback.
pub(crate) fn session_user_and_home(
    policy: &SandboxPolicy,
    workdir_home: Option<&str>,
) -> (String, String) {
    let (user, default_home) = match policy.process.run_as_user.as_deref() {
        Some(user) if !user.is_empty() => {
            if user.parse::<u32>().is_ok() {
                (user.to_string(), "/sandbox".to_string())
            } else {
                let home = User::from_name(user).ok().flatten().map_or_else(
                    || format!("/home/{user}"),
                    |entry| entry.dir.to_string_lossy().into_owned(),
                );
                (user.to_string(), home)
            }
        }
        _ => ("sandbox".to_string(), "/sandbox".to_string()),
    };
    let home = workdir_home.map_or(default_home, str::to_string);
    (user, home)
}

fn apply_canonical_process_environment(
    cmd: &mut Command,
    policy: &SandboxPolicy,
    workspace: &ResolvedWorkspace,
    interactive: bool,
    user_environment: &HashMap<String, String>,
) {
    let (session_user, session_home) = session_user_and_home(policy, workspace.home());

    for (key, value) in [
        ("HOME", session_home.as_str()),
        ("USER", session_user.as_str()),
        ("SHELL", "/bin/bash"),
        (
            "TERM",
            if interactive {
                "xterm-256color"
            } else {
                "dumb"
            },
        ),
    ] {
        if !user_environment.contains_key(key) {
            cmd.env(key, value);
        }
    }
}

fn configured_user_environment() -> HashMap<String, String> {
    std::env::var(openshell_core::sandbox_env::USER_ENVIRONMENT)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
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

#[cfg(target_os = "linux")]
fn drop_capability_bounding_set() -> Result<()> {
    let clear_result = capctl::caps::bounding::clear();
    let remaining = capctl::caps::bounding::probe();

    validate_capability_bounding_set_clear(
        clear_result,
        remaining,
        capctl::caps::bounding::clear_unknown,
    )
}

#[cfg(target_os = "linux")]
fn validate_capability_bounding_set_clear(
    clear_result: capctl::Result<()>,
    remaining: capctl::caps::CapSet,
    clear_unknown: impl FnOnce() -> capctl::Result<()>,
) -> Result<()> {
    match clear_result {
        Ok(()) if remaining.is_empty() => Ok(()),
        Ok(()) => Err(miette::miette!(
            "Failed to clear child capability bounding set: capabilities remain raised: {remaining:?}"
        )),
        Err(err) if err.code() == libc::EPERM && remaining.is_empty() => match clear_unknown() {
            Ok(()) => {
                debug!(
                    "CAP_SETPCAP is unavailable, but the child capability bounding set is already empty"
                );
                Ok(())
            }
            Err(unknown_err) => Err(miette::miette!(
                "Failed to clear unknown child capability bounding set entries: {unknown_err}"
            )),
        },
        Err(err) => Err(miette::miette!(
            "Failed to clear child capability bounding set: {err}"
        )),
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
    io: Option<ProcessIo>,
}

/// Supervisor-owned canonical-process I/O. These handles outlive individual
/// SSH attachments and are consumed by the main-session multiplexer.
pub enum ProcessIo {
    Pty(std::fs::File),
    Pipes {
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
    },
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
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        netns: Option<&NetworkNamespace>,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            program,
            args,
            workspace,
            interactive,
            policy,
            resolved_identity,
            enforcement_mode,
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
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        program: &str,
        args: &[String],
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            program,
            args,
            workspace,
            interactive,
            policy,
            resolved_identity,
            enforcement_mode,
            ca_paths,
            provider_env,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn spawn_impl(
        program: &str,
        args: &[String],
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        netns_fd: Option<RawFd>,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .kill_on_drop(true)
            .env(openshell_core::sandbox_env::SANDBOX, "1");

        let mut pty_master = None;
        let mut terminal_slave_fd = None;
        if interactive {
            let winsize = nix::pty::Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let pty = nix::pty::openpty(Some(&winsize), None).into_diagnostic()?;
            let master = std::fs::File::from(pty.master);
            let slave = std::fs::File::from(pty.slave);
            terminal_slave_fd = Some(slave.as_raw_fd());
            cmd.stdin(slave.try_clone().into_diagnostic()?)
                .stdout(slave.try_clone().into_diagnostic()?)
                .stderr(slave);
            pty_master = Some(master);
        } else {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }

        // Strip supervisor-only identity material from the entrypoint's
        // inherited environment. The entrypoint drops to the sandbox user
        // before `exec`; without this strip, sandbox code could recover
        // supervisor credentials from its inherited environment.
        strip_supervisor_only_env(&mut cmd);

        inject_provider_env(&mut cmd, provider_env);
        apply_canonical_process_environment(
            &mut cmd,
            policy,
            workspace,
            interactive,
            &configured_user_environment(),
        );

        if let Some(dir) = workspace.root() {
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
        if enforcement_mode.enforces_child_sandbox() {
            sandbox::linux::log_sandbox_readiness(policy, workspace.root());
        }

        // Phase 1: Prepare Landlock ruleset by opening PathFds.
        // In full mode this runs before drop_privileges() so root-only paths
        // can be opened. In sidecar network-only mode the container already
        // runs as the sandbox UID, so inaccessible paths are unavailable to
        // the workload and best-effort compatibility skips them.
        #[cfg(target_os = "linux")]
        let prepared_sandbox = prepare_child_sandbox(policy, workspace.root(), enforcement_mode)
            .map_err(|err| miette::miette!("Failed to prepare sandbox: {err}"))?;
        #[cfg(target_os = "linux")]
        let supervisor_identity_mount = if enforcement_mode.uses_privileged_process_setup() {
            supervisor_identity_mount_from_env().map_err(|err| {
                miette::miette!("Failed to prepare supervisor identity isolation: {err}")
            })?
        } else {
            None
        };

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
            let mut prepared_sandbox = prepared_sandbox;
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(slave_fd) = terminal_slave_fd {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        set_controlling_tty(slave_fd)?;
                    } else if libc::setpgid(0, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
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
                    if enforcement_mode.uses_privileged_process_setup() {
                        drop_privileges_with_identity(&policy, resolved_identity)
                            .map_err(|err| std::io::Error::other(err.to_string()))?;
                    }

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

        let mut child = cmd.spawn().into_diagnostic()?;
        let pid = child.id().unwrap_or(0);
        managed_children::register(pid);

        let io = if let Some(master) = pty_master {
            ProcessIo::Pty(master)
        } else {
            ProcessIo::Pipes {
                stdin: child.stdin.take().expect("canonical stdin must be piped"),
                stdout: child.stdout.take().expect("canonical stdout must be piped"),
                stderr: child.stderr.take().expect("canonical stderr must be piped"),
            }
        };

        debug!(pid, program, "Process spawned");

        Ok(Self {
            child,
            pid,
            io: Some(io),
        })
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    fn spawn_impl(
        program: &str,
        args: &[String],
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .kill_on_drop(true)
            .env(openshell_core::sandbox_env::SANDBOX, "1");

        let mut pty_master = None;
        let mut terminal_slave_fd = None;
        #[cfg(unix)]
        if interactive {
            let winsize = nix::pty::Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let pty = nix::pty::openpty(Some(&winsize), None).into_diagnostic()?;
            let master = std::fs::File::from(pty.master);
            let slave = std::fs::File::from(pty.slave);
            terminal_slave_fd = Some(slave.as_raw_fd());
            cmd.stdin(slave.try_clone().into_diagnostic()?)
                .stdout(slave.try_clone().into_diagnostic()?)
                .stderr(slave);
            pty_master = Some(master);
        }
        if !interactive {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }

        // Strip supervisor-only identity material from the entrypoint's
        // inherited environment.
        strip_supervisor_only_env(&mut cmd);

        inject_provider_env(&mut cmd, provider_env);
        apply_canonical_process_environment(
            &mut cmd,
            policy,
            workspace,
            interactive,
            &configured_user_environment(),
        );

        if let Some(dir) = workspace.root() {
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

        // Create a dedicated session for PTY children and a dedicated process
        // group for pipe children so attachment signals target only the
        // canonical workload tree.
        // SAFETY: pre_exec runs after fork but before exec in the child process.
        // setpgid is async-signal-safe and safe to call in this context.
        #[cfg(unix)]
        {
            let policy = policy.clone();
            let workdir = workspace.owned_root();
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(slave_fd) = terminal_slave_fd {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        set_controlling_tty(slave_fd)?;
                    } else if libc::setpgid(0, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Drop privileges before applying sandbox restrictions.
                    // initgroups/setgid/setuid need access to /etc/group and /etc/passwd
                    // which may be blocked by Landlock.
                    if enforcement_mode.uses_privileged_process_setup() {
                        drop_privileges_with_identity(&policy, resolved_identity)
                            .map_err(|err| std::io::Error::other(err.to_string()))?;
                    }

                    harden_child_process().map_err(|err| std::io::Error::other(err.to_string()))?;

                    if enforcement_mode.enforces_child_sandbox() {
                        sandbox::apply(&policy, workdir.as_deref())
                            .map_err(|err| std::io::Error::other(err.to_string()))?;
                    }

                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn().into_diagnostic()?;
        let pid = child.id().unwrap_or(0);
        #[cfg(target_os = "linux")]
        managed_children::register(pid);

        debug!(pid, program, "Process spawned");

        let io = if let Some(master) = pty_master {
            ProcessIo::Pty(master)
        } else {
            ProcessIo::Pipes {
                stdin: child.stdin.take().expect("canonical stdin must be piped"),
                stdout: child.stdout.take().expect("canonical stdout must be piped"),
                stderr: child.stderr.take().expect("canonical stderr must be piped"),
            }
        };

        Ok(Self {
            child,
            pid,
            io: Some(io),
        })
    }

    /// Get the process ID.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Transfer retained stdio to the main-session multiplexer.
    pub fn take_io(&mut self) -> ProcessIo {
        self.io.take().expect("canonical process I/O already taken")
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

    /// Observe an already-terminated child without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ProcessStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            #[cfg(target_os = "linux")]
            managed_children::unregister(self.pid);
        }
        Ok(status.map(ProcessStatus::from))
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

/// Validate the configured process user.
///
/// Numeric identities do not require a passwd entry. The legacy explicit
/// `"sandbox"` identity and other names must resolve in `/etc/passwd`.
#[cfg(unix)]
pub fn validate_sandbox_user(policy: &SandboxPolicy) -> Result<()> {
    let identity = policy.process.run_as_user.as_deref().unwrap_or("sandbox");

    if let Ok(uid) = identity.parse::<u32>() {
        if !(MIN_SANDBOX_UID..=MAX_SANDBOX_UID).contains(&uid) {
            return Err(miette::miette!(
                "process user UID must be in range [{MIN_SANDBOX_UID}, {MAX_SANDBOX_UID}]"
            ));
        }
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "validated")
                .message(format!(
                    "Accepted numeric UID {identity} (no passwd entry required)"
                ))
                .build()
        );
        return Ok(());
    }

    // Legacy explicit "sandbox" name — must exist in /etc/passwd.
    if identity == "sandbox" {
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
                    "explicit process user 'sandbox' was not found in the image"
                ));
            }
            Err(e) => {
                return Err(miette::miette!("failed to look up 'sandbox' user: {e}"));
            }
        }
    } else if !identity.is_empty() {
        // Other names are supported by local/offline policy paths and must
        // resolve before privilege dropping.
        match User::from_name(identity) {
            Ok(Some(_)) => {
                tracing::warn!(identity, "named process user accepted via passwd entry");
            }
            Ok(None) => {
                return Err(miette::miette!(
                    "unrecognized sandbox identity '{identity}'; \
                     expected 'sandbox' or a numeric UID in range [{MIN_SANDBOX_UID}, {MAX_SANDBOX_UID}]"
                ));
            }
            Err(e) => {
                return Err(miette::miette!(
                    "failed to look up identity '{identity}': {e}"
                ));
            }
        }
    }

    Ok(())
}

/// Validate that the configured sandbox group identity is acceptable.
///
/// Mirrors [`validate_sandbox_user`] for the group dimension.
#[cfg(unix)]
pub fn validate_sandbox_group(policy: &SandboxPolicy) -> Result<()> {
    let identity = policy.process.run_as_group.as_deref().unwrap_or("sandbox");

    if let Ok(gid) = identity.parse::<u32>() {
        if !(MIN_SANDBOX_UID..=MAX_SANDBOX_UID).contains(&gid) {
            return Err(miette::miette!(
                "process group GID must be in range [{MIN_SANDBOX_UID}, {MAX_SANDBOX_UID}]"
            ));
        }
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "validated")
                .message(format!(
                    "Accepted numeric GID {identity} (no group entry required)"
                ))
                .build()
        );
        return Ok(());
    }

    if identity == "sandbox" {
        match Group::from_name("sandbox") {
            Ok(Some(_)) => {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::Informational)
                        .status(openshell_ocsf::StatusId::Success)
                        .state(openshell_ocsf::StateId::Enabled, "validated")
                        .message("Validated 'sandbox' group exists in image")
                        .build()
                );
            }
            Ok(None) => {
                return Err(miette::miette!(
                    "explicit process group 'sandbox' was not found in the image"
                ));
            }
            Err(e) => {
                return Err(miette::miette!("failed to look up 'sandbox' group: {e}"));
            }
        }
    } else if !identity.is_empty() {
        match Group::from_name(identity) {
            Ok(Some(_)) => {
                tracing::warn!(identity, "named process group accepted via group entry");
            }
            Ok(None) => {
                return Err(miette::miette!(
                    "unrecognized sandbox group identity '{identity}'; \
                     expected 'sandbox' or a numeric GID in range [{MIN_SANDBOX_UID}, {MAX_SANDBOX_UID}]"
                ));
            }
            Err(e) => {
                return Err(miette::miette!(
                    "failed to look up group identity '{identity}': {e}"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
pub fn validate_sandbox_user_with_identity(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
) -> Result<()> {
    let Some(uid) = resolved_identity.uid() else {
        return validate_sandbox_user(policy);
    };
    if uid == 0 {
        return Err(miette::miette!("process user must not select UID 0"));
    }
    Ok(())
}

#[cfg(unix)]
pub fn validate_sandbox_group_with_identity(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
) -> Result<()> {
    let Some(gid) = resolved_identity.gid() else {
        return validate_sandbox_group(policy);
    };
    if gid == 0 {
        return Err(miette::miette!("process group must not select GID 0"));
    }
    Ok(())
}

pub use openshell_policy::{MAX_SANDBOX_UID, MIN_SANDBOX_UID};

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

/// Update `/etc/passwd` and `/etc/group` so the "sandbox" user/group entries
/// match the driver-injected UID/GID from environment variables.
///
/// When `OPENSHELL_SANDBOX_UID` is set, the image-baked "sandbox" entry may
/// have a different UID. Updating the files ensures `whoami`, `id`, `ls -l`,
/// SSH sessions, and `initgroups` resolve the sandbox identity correctly.
/// If no "sandbox" entry exists, one is appended.
#[cfg(unix)]
pub fn update_sandbox_passwd_entries() -> Result<()> {
    let uid_str = match std::env::var(openshell_core::sandbox_env::SANDBOX_UID) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };
    let gid_str = match std::env::var(openshell_core::sandbox_env::SANDBOX_GID) {
        Ok(v) if !v.is_empty() => v,
        _ => uid_str.clone(),
    };

    let _: u32 = uid_str
        .parse()
        .map_err(|e| miette::miette!("invalid OPENSHELL_SANDBOX_UID '{uid_str}': {e}"))?;
    let _: u32 = gid_str
        .parse()
        .map_err(|e| miette::miette!("invalid OPENSHELL_SANDBOX_GID '{gid_str}': {e}"))?;

    update_passwd_file(&uid_str, &gid_str)?;
    update_group_file(&gid_str)?;

    info!(
        uid = %uid_str,
        gid = %gid_str,
        "Updated /etc/passwd and /etc/group for sandbox identity"
    );
    Ok(())
}

/// Rewrite the `sandbox` line in `/etc/passwd` with the given UID/GID,
/// or append a new entry if none exists.
#[cfg(unix)]
fn update_passwd_file(uid: &str, gid: &str) -> Result<()> {
    rewrite_passwd_at(Path::new("/etc/passwd"), uid, gid)
}

/// Rewrite the `sandbox` line in `/etc/group` with the given GID,
/// or append a new entry if none exists.
#[cfg(unix)]
fn update_group_file(gid: &str) -> Result<()> {
    rewrite_group_at(Path::new("/etc/group"), gid)
}

#[cfg(unix)]
fn rewrite_passwd_at(path: &Path, uid: &str, gid: &str) -> Result<()> {
    let content = std::fs::read_to_string(path).into_diagnostic()?;

    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with("sandbox:") {
                found = true;
                let fields: Vec<&str> = line.split(':').collect();
                if let [name, pass, _, _, gecos, home, shell, ..] = fields.as_slice() {
                    format!("{name}:{pass}:{uid}:{gid}:{gecos}:{home}:{shell}")
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("sandbox:x:{uid}:{gid}::/sandbox:/bin/sh"));
    }

    let mut output = lines.join("\n");
    if content.ends_with('\n') || !found {
        output.push('\n');
    }

    std::fs::write(path, output).into_diagnostic()?;
    Ok(())
}

#[cfg(unix)]
fn rewrite_group_at(path: &Path, gid: &str) -> Result<()> {
    let content = std::fs::read_to_string(path).into_diagnostic()?;

    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with("sandbox:") {
                found = true;
                let fields: Vec<&str> = line.split(':').collect();
                if let [name, pass, _, members, ..] = fields.as_slice() {
                    format!("{name}:{pass}:{gid}:{members}")
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("sandbox:x:{gid}:"));
    }

    let mut output = lines.join("\n");
    if content.ends_with('\n') || !found {
        output.push('\n');
    }

    std::fs::write(path, output).into_diagnostic()?;
    Ok(())
}

/// Recursively chown a directory tree to the given UID/GID.
///
/// This retains the Kubernetes/OpenShift workspace reconciliation from before
/// OCI image identity fallback. Symlinks are skipped, and read-only nested
/// mounts are not traversed.
#[cfg(unix)]
fn chown_sandbox_home(root: &Path, uid: Option<Uid>, gid: Option<Gid>) -> Result<()> {
    let meta = std::fs::symlink_metadata(root).into_diagnostic()?;
    if meta.file_type().is_symlink() {
        return Err(miette::miette!(
            "path '{}' is a symlink — refusing to chown (potential privilege escalation)",
            root.display()
        ));
    }

    nix::unistd::chown(root, uid, gid).into_diagnostic()?;

    if meta.is_dir() {
        chown_children(root, uid, gid, &nix::unistd::chown)?;
    }

    Ok(())
}

#[cfg(unix)]
fn prepare_oci_workspace(
    root: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
) -> Result<()> {
    prepare_oci_workspace_with(root, uid, gid, supplementary_gids, &nix::unistd::chown)
}

/// Validate that selecting an image-provided OCI workdir does not grant the
/// sandbox identity any filesystem authority it lacked in the immutable image.
///
/// Every path component must be a real directory (never a symlink), every
/// parent must already be traversable, and the final directory must already be
/// writable and traversable. No ownership or mode bits are changed.
#[cfg(unix)]
pub fn validate_oci_workspace(
    root: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
) -> Result<()> {
    let components = validated_workspace_components(root, false)?;
    let mut current = PathBuf::from("/");
    validate_workspace_component(&current, uid, gid, supplementary_gids, false)?;
    let last_component = components.len().saturating_sub(1);
    for (index, component) in components.into_iter().enumerate() {
        current.push(component);
        validate_workspace_component(
            &current,
            uid,
            gid,
            supplementary_gids,
            index == last_component,
        )?;
    }
    Ok(())
}

/// Validate an image-provided workdir in a clean copy of the supervisor so the
/// main process retains the root authority needed for subsequent setup.
#[cfg(target_os = "linux")]
fn validate_oci_workspace_in_subprocess(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
    workdir: &Path,
) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let (uid, gid, supplementary_gids) = resolve_filesystem_identity(policy, resolved_identity)?;
    let uid = uid.ok_or_else(|| miette::miette!("workspace validator UID is unresolved"))?;
    let gid = gid.ok_or_else(|| miette::miette!("workspace validator GID is unresolved"))?;
    let groups = supplementary_gids
        .iter()
        .map(|group| group.as_raw())
        .collect::<Vec<_>>();
    let executable = std::env::current_exe().into_diagnostic()?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("validate-workspace")
        .arg("--workdir")
        .arg(workdir)
        .arg("--expected-uid")
        .arg(uid.to_string())
        .arg("--expected-gid")
        .arg(gid.to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    // `pre_exec` runs after fork and before exec. These direct credential
    // syscalls are async-signal-safe and affect only the one-shot child.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid.as_raw()) != 0
                || libc::setuid(uid.as_raw()) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = command.output().into_diagnostic()?;
    if output.status.success() {
        return Ok(());
    }

    let diagnostic = String::from_utf8_lossy(&output.stderr);
    let diagnostic = diagnostic.trim();
    if diagnostic.is_empty() {
        return Err(miette::miette!(
            "image workspace validation failed with status {}",
            output.status
        ));
    }
    Err(miette::miette!(
        "image workspace validation failed: {diagnostic}"
    ))
}

#[cfg(unix)]
fn validate_workspace_component(
    path: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
    is_workspace: bool,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            miette::miette!(
                "image workspace path component '{}' does not exist",
                path.display()
            )
        } else {
            miette::miette!(
                "failed to inspect image workspace path component '{}': {error}",
                path.display()
            )
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(miette::miette!(
            "workspace path component '{}' is a symlink — refusing to follow it",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(miette::miette!(
            "workspace path component '{}' is not a directory",
            path.display()
        ));
    }
    let required = if is_workspace { 0o3 } else { 0o1 };
    if !identity_has_permissions(&metadata, uid, gid, supplementary_gids, required) {
        let requirement = if is_workspace {
            "writable and traversable"
        } else {
            "traversable"
        };
        return Err(miette::miette!(
            "workspace path component '{}' is not {requirement} by the sandbox identity in the image",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_oci_workspace_as_effective_identity(root: &Path) -> Result<()> {
    use rustix::fs::{Access, AtFlags, FileType, Mode, OFlags};

    let components = validated_workspace_components(root, false)?;
    let open_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current_path = PathBuf::from("/");
    let mut current_fd = rustix::fs::open("/", open_flags, Mode::empty()).into_diagnostic()?;
    rustix::fs::accessat(
        &current_fd,
        ".",
        Access::EXEC_OK,
        AtFlags::EACCESS | AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| {
        miette::miette!(
            "workspace path component '{}' is not traversable by the sandbox identity in the image: {error}",
            current_path.display()
        )
    })?;

    let last_component = components.len().saturating_sub(1);
    for (index, component) in components.into_iter().enumerate() {
        current_path.push(&component);
        let stat = rustix::fs::statat(&current_fd, &component, AtFlags::SYMLINK_NOFOLLOW).map_err(
            |error| {
                if error == rustix::io::Errno::NOENT {
                    miette::miette!(
                        "image workspace path component '{}' does not exist",
                        current_path.display()
                    )
                } else {
                    miette::miette!(
                        "failed to inspect image workspace path component '{}': {error}",
                        current_path.display()
                    )
                }
            },
        )?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if file_type.is_symlink() {
            return Err(miette::miette!(
                "workspace path component '{}' is a symlink — refusing to follow it",
                current_path.display()
            ));
        }
        if !file_type.is_dir() {
            return Err(miette::miette!(
                "workspace path component '{}' is not a directory",
                current_path.display()
            ));
        }

        let is_workspace = index == last_component;
        rustix::fs::accessat(
            &current_fd,
            &component,
            Access::EXEC_OK,
            AtFlags::EACCESS | AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| {
            miette::miette!(
                "workspace path component '{}' is not traversable by the sandbox identity in the image: {error}",
                current_path.display()
            )
        })?;

        let next_fd = rustix::fs::openat(&current_fd, &component, open_flags, Mode::empty())
            .map_err(|error| {
                miette::miette!(
                    "failed to open image workspace path component '{}': {error}",
                    current_path.display()
                )
            })?;
        if is_workspace {
            validate_effective_workspace_write(&next_fd, &current_path)?;
        }
        current_fd = next_fd;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_effective_workspace_write(fd: &impl std::os::fd::AsFd, path: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let mode = Mode::RUSR | Mode::WUSR;
    let tmpfile_flags = OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC;
    match rustix::fs::openat(fd, ".", tmpfile_flags, mode) {
        Ok(_probe) => return Ok(()),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::ISDIR | rustix::io::Errno::NOTSUP) => {}
        Err(error) => {
            return Err(miette::miette!(
                "workspace path component '{}' is not writable by the sandbox identity in the image: {error}",
                path.display()
            ));
        }
    }

    // Some filesystems do not implement O_TMPFILE. Fall back to a short-lived,
    // no-follow entry. A collision fails closed after bounded retries.
    let create_flags =
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for attempt in 0..16 {
        let name = format!(".openshell-workdir-probe-{}-{attempt}", std::process::id());
        match rustix::fs::openat(fd, &name, create_flags, mode) {
            Ok(_probe) => {
                rustix::fs::unlinkat(fd, &name, AtFlags::empty()).map_err(|error| {
                    miette::miette!(
                        "workspace write probe cleanup failed for '{}': {error}",
                        path.display()
                    )
                })?;
                return Ok(());
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => {
                return Err(miette::miette!(
                    "workspace path component '{}' is not writable by the sandbox identity in the image: {error}",
                    path.display()
                ));
            }
        }
    }

    Err(miette::miette!(
        "workspace write probe could not allocate a unique entry in '{}'",
        path.display()
    ))
}

/// Prepare only the resolved `OpenShell` workspace directory itself.
///
/// Image-provided children retain their declared ownership. This avoids
/// crossing symlinks or user-provided nested mounts.
#[cfg(unix)]
fn prepare_oci_workspace_with(
    root: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
    do_chown: &impl Fn(&Path, Option<Uid>, Option<Gid>) -> nix::Result<()>,
) -> Result<()> {
    let components = validated_workspace_components(root, true)?;

    let last_component = components.len().saturating_sub(1);
    let mut current = PathBuf::from("/");
    for (index, component) in components.into_iter().enumerate() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(miette::miette!(
                    "workspace path component '{}' is a symlink — refusing to follow it",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(miette::miette!(
                    "workspace path component '{}' is not a directory",
                    current.display()
                ));
            }
            Ok(metadata) => {
                if index != last_component
                    && !identity_can_traverse(&metadata, uid, gid, supplementary_gids)
                {
                    return Err(miette::miette!(
                        "workspace parent '{}' is not traversable by the sandbox identity",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).into_diagnostic()?;
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))
                    .into_diagnostic()?;
            }
            Err(error) => return Err(error).into_diagnostic(),
        }
    }

    do_chown(root, uid, gid).into_diagnostic()?;

    let metadata = std::fs::symlink_metadata(root).into_diagnostic()?;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o300 != 0o300 {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode | 0o300))
            .into_diagnostic()?;
    }
    Ok(())
}

#[cfg(unix)]
fn validated_workspace_components(
    root: &Path,
    allow_managed_fallback: bool,
) -> Result<Vec<std::ffi::OsString>> {
    let root_str = root
        .to_str()
        .ok_or_else(|| miette::miette!("workspace path must be valid UTF-8"))?;
    let validated_root = openshell_core::driver_mounts::resolve_oci_workspace_root(root_str)
        .map_err(|error| miette::miette!(error))?;
    if Path::new(&validated_root) != root
        || (!allow_managed_fallback
            && validated_root == openshell_core::driver_mounts::DEFAULT_WORKSPACE_ROOT)
    {
        return Err(miette::miette!(
            "workspace path '{}' must be a normalized absolute {}path",
            root.display(),
            if allow_managed_fallback {
                "non-root "
            } else {
                "non-fallback "
            }
        ));
    }

    root.components()
        .skip(1)
        .map(|component| match component {
            std::path::Component::Normal(component) => Ok(component.to_os_string()),
            _ => Err(miette::miette!(
                "workspace path '{}' must be normalized",
                root.display()
            )),
        })
        .collect()
}

#[cfg(unix)]
fn identity_can_traverse(
    metadata: &std::fs::Metadata,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
) -> bool {
    identity_has_permissions(metadata, uid, gid, supplementary_gids, 0o1)
}

#[cfg(unix)]
fn identity_has_permissions(
    metadata: &std::fs::Metadata,
    uid: Option<Uid>,
    gid: Option<Gid>,
    supplementary_gids: &[Gid],
    required: u32,
) -> bool {
    let user_id = uid.unwrap_or_else(nix::unistd::geteuid).as_raw();
    if user_id == 0 {
        return true;
    }

    let group_id = gid.unwrap_or_else(nix::unistd::getegid).as_raw();
    let mode = metadata.permissions().mode();
    if metadata.uid() == user_id {
        mode & (required << 6) == required << 6
    } else if metadata.gid() == group_id
        || supplementary_gids
            .iter()
            .any(|supplementary_gid| supplementary_gid.as_raw() == metadata.gid())
    {
        mode & (required << 3) == required << 3
    } else {
        mode & required == required
    }
}

#[cfg(not(any(
    target_os = "aix",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox",
    target_os = "solaris"
)))]
fn named_user_supplementary_groups(user_name: &str, primary_gid: Gid) -> Result<Vec<Gid>> {
    let user_name = CString::new(user_name).map_err(|_| miette::miette!("Invalid user name"))?;
    nix::unistd::getgrouplist(user_name.as_c_str(), primary_gid).into_diagnostic()
}

#[cfg(any(
    target_os = "aix",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox",
    target_os = "solaris"
))]
#[allow(clippy::unnecessary_wraps)]
fn named_user_supplementary_groups(_user_name: &str, _primary_gid: Gid) -> Result<Vec<Gid>> {
    // Privilege dropping does not call initgroups on these targets.
    Ok(Vec::new())
}

#[cfg(unix)]
fn chown_children(
    dir: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    do_chown: &impl Fn(&Path, Option<Uid>, Option<Gid>) -> nix::Result<()>,
) -> Result<()> {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.into_diagnostic()?;
                chown_recursive(&entry.path(), uid, gid, do_chown)?;
            }
        }
        Err(error) => {
            debug!(
                path = %dir.display(),
                %error,
                "Cannot list directory during sandbox home chown"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn chown_recursive(
    path: &Path,
    uid: Option<Uid>,
    gid: Option<Gid>,
    do_chown: &impl Fn(&Path, Option<Uid>, Option<Gid>) -> nix::Result<()>,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).into_diagnostic()?;
    if meta.file_type().is_symlink() {
        debug!(path = %path.display(), "Skipping symlink during sandbox home chown");
        return Ok(());
    }

    if let Err(error) = do_chown(path, uid, gid) {
        if error == nix::errno::Errno::EROFS {
            debug!(path = %path.display(), "Skipping read-only path during sandbox home chown");
            return Ok(());
        }
        return Err(error).into_diagnostic();
    }

    if meta.is_dir() {
        chown_children(path, uid, gid, do_chown)?;
    }

    Ok(())
}

/// Prepare filesystem for the sandboxed process.
///
/// Creates `read_write` directories if they don't exist and sets ownership
/// on newly-created paths to the configured sandbox user/group. This runs as
/// the supervisor (root) before forking the child process.
///
/// Accepts both name-based identities (resolved via `/etc/passwd`) and numeric
/// UIDs/GIDs (passed directly to `chown` without a passwd lookup).
#[cfg(unix)]
pub fn prepare_filesystem(policy: &SandboxPolicy) -> Result<()> {
    prepare_filesystem_with_identity(policy, ResolvedProcessIdentity::default(), None, false)
}

#[cfg(unix)]
pub fn prepare_filesystem_with_identity(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
    workdir: Option<&str>,
    prepare_workspace: bool,
) -> Result<()> {
    use nix::unistd::chown;

    // If no user/group configured, nothing to do
    if policy
        .process
        .run_as_user
        .as_deref()
        .is_none_or(str::is_empty)
        && policy
            .process
            .run_as_group
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Ok(());
    }

    let (uid, gid, supplementary_gids) = resolve_filesystem_identity(policy, resolved_identity)?;

    // Docker owns workspace resolution and must make the selected root usable
    // by the final effective identity, including when both policy identity
    // fields were explicit. Validate it before processing any user-authored
    // read-write paths so an unsafe image path fails first. Other drivers
    // retain their preparation.
    if prepare_workspace {
        let workspace = workdir.ok_or_else(|| {
            miette::miette!("local container driver did not supply a workspace workdir")
        })?;
        let workspace = Path::new(workspace);
        if workspace == Path::new(openshell_core::driver_mounts::DEFAULT_WORKSPACE_ROOT) {
            info!(path = %workspace.display(), ?uid, ?gid, "Preparing managed workspace");
            prepare_oci_workspace(workspace, uid, gid, &supplementary_gids)?;
        } else {
            info!(path = %workspace.display(), ?uid, ?gid, "Validating image workspace authority");
            #[cfg(target_os = "linux")]
            validate_oci_workspace_in_subprocess(policy, resolved_identity, workspace)?;
            #[cfg(not(target_os = "linux"))]
            validate_oci_workspace(workspace, uid, gid, &supplementary_gids)?;
        }
    }

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

    // Retain the existing Kubernetes/OpenShift behavior for driver-injected
    // numeric identities. Docker clears this variable and does not receive
    // identity-specific workspace preparation.
    if std::env::var(openshell_core::sandbox_env::SANDBOX_UID).is_ok_and(|uid| !uid.is_empty()) {
        let sandbox_home = Path::new("/sandbox");
        if sandbox_home.exists() {
            info!(?uid, ?gid, "Chowning /sandbox for driver-injected UID/GID");
            chown_sandbox_home(sandbox_home, uid, gid)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn resolve_filesystem_identity(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
) -> Result<(Option<Uid>, Option<Gid>, Vec<Gid>)> {
    let user_name = policy
        .process
        .run_as_user
        .as_deref()
        .filter(|name| !name.is_empty());
    let group_name = policy
        .process
        .run_as_group
        .as_deref()
        .filter(|name| !name.is_empty());

    let uid = match resolved_identity.uid() {
        Some(uid) => Some(Uid::from_raw(uid)),
        None => match user_name {
            Some(name) if name.parse::<u32>().is_ok() => {
                Some(Uid::from_raw(name.parse().into_diagnostic()?))
            }
            Some(name) => User::from_name(name).into_diagnostic()?.map(|u| u.uid),
            _ => None,
        },
    };

    // Resolve GID: numeric values are passed directly; names resolve via group.
    let gid = match resolved_identity.gid() {
        Some(gid) => Some(Gid::from_raw(gid)),
        None => match group_name {
            Some(name) if name.parse::<u32>().is_ok() => {
                Some(Gid::from_raw(name.parse().into_diagnostic()?))
            }
            Some(name) => Group::from_name(name).into_diagnostic()?.map(|g| g.gid),
            _ => None,
        },
    };

    let supplementary_gids = match user_name {
        Some(name) if name.parse::<u32>().is_err() => {
            let primary_gid = if let Some(gid) = gid {
                gid
            } else {
                let uid =
                    uid.ok_or_else(|| miette::miette!("Failed to resolve sandbox user '{name}'"))?;
                User::from_uid(uid)
                    .into_diagnostic()?
                    .ok_or_else(|| miette::miette!("Failed to resolve user from UID {uid}"))?
                    .gid
            };
            if resolved_identity.uid().is_some() {
                crate::identity::resolve_oci_supplementary_gids(name, primary_gid.as_raw())?
                    .into_iter()
                    .map(Gid::from_raw)
                    .collect()
            } else {
                named_user_supplementary_groups(name, primary_gid)?
            }
        }
        _ => Vec::new(),
    };

    Ok((uid, gid, supplementary_gids))
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
    drop_privileges_with_identity(policy, ResolvedProcessIdentity::default())
}

#[cfg(unix)]
#[allow(clippy::similar_names)]
pub fn drop_privileges_with_identity(
    policy: &SandboxPolicy,
    resolved_identity: ResolvedProcessIdentity,
) -> Result<()> {
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
    // local/dev-mode path for drivers that provide no identity metadata.
    // For non-root runtimes, the no-op is safe -- we are already unprivileged.
    if user_name.is_none() && group_name.is_none() {
        if nix::unistd::geteuid().is_root() {
            let mut fallback = policy.clone();
            fallback.process.run_as_user = Some("sandbox".into());
            fallback.process.run_as_group = Some("sandbox".into());
            return drop_privileges_with_identity(&fallback, resolved_identity);
        }
        return Ok(());
    }

    // Resolve UID: numeric values are used directly; names resolve via passwd.
    let target_uid = match resolved_identity.uid() {
        Some(uid) => Uid::from_raw(uid),
        None => match user_name {
            Some(name) if name.parse::<u32>().is_ok() => {
                Uid::from_raw(name.parse().into_diagnostic()?)
            }
            Some(name) => {
                User::from_name(name)
                    .into_diagnostic()?
                    .ok_or_else(|| miette::miette!("Sandbox user not found: {name}"))?
                    .uid
            }
            None => nix::unistd::geteuid(),
        },
    };

    // Resolve group: if a numeric GID is configured use it directly.
    // Otherwise try name resolution, then fall back to current user's primary group.
    let target_gid = match resolved_identity.gid() {
        Some(gid) => Gid::from_raw(gid),
        None => match group_name {
            Some(name) if name.parse::<u32>().is_ok() => {
                Gid::from_raw(name.parse().into_diagnostic()?)
            }
            Some(name) => {
                Group::from_name(name)
                    .into_diagnostic()?
                    .ok_or_else(|| miette::miette!("Sandbox group not found: {name}"))?
                    .gid
            }
            None => match target_uid.as_raw() {
                0 => nix::unistd::getegid(),
                _ => Group::from_gid(
                    User::from_uid(target_uid)
                        .into_diagnostic()?
                        .ok_or_else(|| {
                            miette::miette!("Failed to resolve user from UID {target_uid}")
                        })?
                        .gid,
                )
                .into_diagnostic()?
                .map_or_else(nix::unistd::getegid, |g| g.gid),
            },
        },
    };

    // Resolve the name for initgroups only for the existing explicit-policy
    // path. OCI-derived users carry a numeric UID from the bounded parser and
    // must not be looked up again through NSS.
    let user_name_is_numeric = user_name.is_some_and(|n| n.parse::<u32>().is_ok());
    let initgroups_name =
        if user_name.is_some() && !user_name_is_numeric && resolved_identity.uid().is_none() {
            Some(
                User::from_uid(target_uid)
                    .into_diagnostic()?
                    .ok_or_else(|| {
                        miette::miette!("Failed to resolve user record for UID {target_uid}")
                    })?
                    .name,
            )
        } else {
            None
        };

    if target_uid != nix::unistd::geteuid() {
        if resolved_identity.uses_oci_user_fallback() {
            // OCI named users use the bounded /etc/group parser shared with
            // workspace validation. Numeric OCI users resolve to an empty
            // list. Never retain the root supervisor's inherited groups.
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "haiku",
                target_os = "redox"
            )))]
            {
                let (_, _, supplementary_gids) =
                    resolve_filesystem_identity(policy, resolved_identity)?;
                nix::unistd::setgroups(&supplementary_gids).into_diagnostic()?;
            }
        } else if let Some(ref user_name) = initgroups_name {
            let user_cstr = CString::new(user_name.as_str())
                .map_err(|_| miette::miette!("Invalid user name"))?;
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
                nix::unistd::initgroups(user_cstr.as_c_str(), target_gid).into_diagnostic()?;
            }
        }
    }

    if target_gid != nix::unistd::getegid() {
        nix::unistd::setgid(target_gid).into_diagnostic()?;
    }

    // Verify effective GID actually changed (defense-in-depth, CWE-250 / CERT POS37-C)
    let effective_gid = nix::unistd::getegid();
    if effective_gid != target_gid {
        return Err(miette::miette!(
            "Privilege drop verification failed: expected effective GID {}, got {}",
            target_gid,
            effective_gid
        ));
    }

    #[cfg(target_os = "linux")]
    if nix::unistd::geteuid().is_root() {
        drop_capability_bounding_set()?;
    }

    if user_name.is_some() {
        if target_uid != nix::unistd::geteuid() {
            nix::unistd::setuid(target_uid).into_diagnostic()?;
        }

        // Verify effective UID actually changed (defense-in-depth, CWE-250 / CERT POS37-C)
        let effective_uid = nix::unistd::geteuid();
        if effective_uid != target_uid {
            return Err(miette::miette!(
                "Privilege drop verification failed: expected effective UID {}, got {}",
                target_uid,
                effective_uid
            ));
        }

        // Verify root cannot be re-acquired (CERT POS37-C hardening).
        // If we dropped from root, setuid(0) must fail; success means privileges
        // were not fully relinquished.
        if nix::unistd::setuid(Uid::from_raw(0)).is_ok() && target_uid.as_raw() != 0 {
            return Err(miette::miette!(
                "Privilege drop verification failed: process can still re-acquire root (UID 0) \
                 after switching to UID {}",
                target_uid
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
    /// Get the conventional exit code when the process exited normally.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.code
    }

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

    #[cfg(unix)]
    #[tokio::test]
    async fn canonical_tty_environment_replaces_supervisor_identity_defaults() {
        let current_user = User::from_uid(nix::unistd::geteuid())
            .expect("look up current user")
            .expect("current user entry");
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(current_user.name.clone()),
            run_as_group: None,
        });
        let workspace = ResolvedWorkspace::default();
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env_clear()
            .env("HOME", "/root")
            .env("TERM", "dumb")
            .stdout(StdStdio::piped());

        apply_canonical_process_environment(&mut cmd, &policy, &workspace, true, &HashMap::new());

        let output = cmd.output().await.expect("run environment probe");
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).expect("environment is UTF-8");
        let variables: HashMap<_, _> = environment
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();

        assert_eq!(
            variables.get("HOME"),
            Some(&current_user.dir.to_string_lossy().as_ref())
        );
        assert_eq!(variables.get("USER"), Some(&current_user.name.as_str()));
        assert_eq!(variables.get("SHELL"), Some(&"/bin/bash"));
        assert_eq!(variables.get("TERM"), Some(&"xterm-256color"));
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
    #[cfg(unix)]
    fn explicit_identity_accepts_non_root_system_ids() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("101".into()),
            run_as_group: Some("102".into()),
        });

        assert!(validate_sandbox_user(&policy).is_ok());
        assert!(validate_sandbox_group(&policy).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn resolved_oci_identity_accepts_non_root_system_ids() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("app".into()),
            run_as_group: Some("staff".into()),
        });
        let resolved = ResolvedProcessIdentity::new(Some(101), Some(102));

        assert!(validate_sandbox_user_with_identity(&policy, resolved).is_ok());
        assert!(validate_sandbox_group_with_identity(&policy, resolved).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn completed_runtime_identity_rejects_numeric_root() {
        let root_user = policy_with_process(ProcessPolicy {
            run_as_user: Some("0".into()),
            run_as_group: Some("102".into()),
        });
        let root_group = policy_with_process(ProcessPolicy {
            run_as_user: Some("101".into()),
            run_as_group: Some("0".into()),
        });

        assert!(validate_sandbox_user(&root_user).is_err());
        assert!(validate_sandbox_group(&root_group).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn resolved_oci_components_do_not_repeat_nss_validation() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("__oci_name_not_in_host_nss__".into()),
            run_as_group: Some("__oci_group_not_in_host_nss__".into()),
        });
        let resolved = ResolvedProcessIdentity::new(Some(1234), Some(1235));

        assert!(validate_sandbox_user_with_identity(&policy, resolved).is_ok());
        assert!(validate_sandbox_group_with_identity(&policy, resolved).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn explicit_policy_components_keep_existing_validation_path() {
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("__explicit_name_not_in_host_nss__".into()),
            run_as_group: Some("__oci_group_not_in_host_nss__".into()),
        });
        let resolved = ResolvedProcessIdentity::new(None, Some(1235));

        assert!(validate_sandbox_user_with_identity(&policy, resolved).is_err());
        assert!(validate_sandbox_group_with_identity(&policy, resolved).is_ok());
    }

    #[test]
    fn full_enforcement_uses_privileged_setup_and_child_sandbox() {
        assert!(ProcessEnforcementMode::Full.uses_privileged_process_setup());
        assert!(ProcessEnforcementMode::Full.enforces_child_sandbox());
    }

    #[test]
    fn network_only_enforcement_keeps_child_sandbox_without_privileged_setup() {
        assert!(!ProcessEnforcementMode::NetworkOnly.uses_privileged_process_setup());
        assert!(ProcessEnforcementMode::NetworkOnly.enforces_child_sandbox());
    }

    #[cfg(target_os = "linux")]
    fn capability_bounding_set_clear_available() -> bool {
        capctl::caps::CapState::get_current()
            .is_ok_and(|state| state.effective.has(capctl::caps::Cap::SETPCAP))
            || capctl::caps::bounding::probe().is_empty()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_bounding_set_clear_accepts_empty_eperm() {
        let remaining = capctl::caps::CapSet::empty();

        assert!(
            validate_capability_bounding_set_clear(
                Err(capctl::Error::from_code(libc::EPERM)),
                remaining,
                || Ok(()),
            )
            .is_ok()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_bounding_set_clear_rejects_nonempty_eperm() {
        let mut remaining = capctl::caps::CapSet::empty();
        remaining.add(capctl::caps::Cap::CHOWN);

        let result = validate_capability_bounding_set_clear(
            Err(capctl::Error::from_code(libc::EPERM)),
            remaining,
            || panic!("unknown capabilities should not be checked when known caps remain"),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to clear child capability bounding set")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_bounding_set_clear_rejects_nonempty_success() {
        let mut remaining = capctl::caps::CapSet::empty();
        remaining.add(capctl::caps::Cap::CHOWN);

        let result = validate_capability_bounding_set_clear(Ok(()), remaining, || {
            panic!("unknown capabilities should not be checked when known caps remain")
        });

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("capabilities remain raised")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_bounding_set_clear_rejects_unknown_eperm() {
        let remaining = capctl::caps::CapSet::empty();

        let result = validate_capability_bounding_set_clear(
            Err(capctl::Error::from_code(libc::EPERM)),
            remaining,
            || Err(capctl::Error::from_code(libc::EPERM)),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to clear unknown child capability bounding set entries")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn capability_probe_child() {
        if std::env::var_os("OPENSHELL_TEST_PROBE_CHILD_CAPS").is_none() {
            return;
        }

        assert!(
            capctl::caps::bounding::probe().is_empty(),
            "child CapBnd should be empty after exec"
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

        let result = drop_privileges(&policy);
        #[cfg(target_os = "linux")]
        {
            if nix::unistd::geteuid().is_root() && !capability_bounding_set_clear_available() {
                let msg = format!("{}", result.unwrap_err());
                assert!(
                    msg.contains("Failed to clear child capability bounding set"),
                    "unexpected failure: {msg}"
                );
                return;
            }
        }
        assert!(result.is_ok(), "drop_privileges failed: {result:?}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn drop_privileges_clears_bounding_set_for_spawned_child_when_permitted() {
        use std::os::unix::process::CommandExt;

        if !capability_bounding_set_clear_available() {
            eprintln!(
                "skipping: CAP_SETPCAP is not effective and the capability bounding set is nonempty"
            );
            return;
        }

        let current_group = Group::from_gid(nix::unistd::getegid())
            .expect("getgrgid")
            .expect("current group entry");

        let policy = policy_with_process(ProcessPolicy {
            run_as_user: None,
            run_as_group: Some(current_group.name),
        });

        let mut cmd = std::process::Command::new(std::env::current_exe().expect("current exe"));
        cmd.arg("capability_probe_child")
            .arg("--nocapture")
            .env("OPENSHELL_TEST_PROBE_CHILD_CAPS", "1")
            .stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::piped());

        unsafe {
            cmd.pre_exec(move || {
                drop_privileges(&policy).map_err(|err| std::io::Error::other(err.to_string()))
            });
        }

        let output = cmd.output().expect("spawn child status probe");
        assert!(
            output.status.success(),
            "status probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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

        let Ok(Some(current_user)) = User::from_uid(nix::unistd::geteuid()) else {
            eprintln!("skipping: current UID has no /etc/passwd entry");
            return;
        };
        let restricted_group = Group::from_gid(Gid::from_raw(0))
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

    #[cfg(unix)]
    #[test]
    #[allow(clippy::similar_names)]
    fn chown_sandbox_home_changes_ownership_recursively() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file.txt"), "hello").unwrap();
        std::fs::create_dir(root.join("subdir")).unwrap();
        std::fs::write(root.join("subdir").join("nested.txt"), "world").unwrap();

        let expected_uid = nix::unistd::geteuid();
        let expected_gid = nix::unistd::getegid();
        chown_sandbox_home(&root, Some(expected_uid), Some(expected_gid)).unwrap();

        for path in &[
            root.clone(),
            root.join("file.txt"),
            root.join("subdir"),
            root.join("subdir").join("nested.txt"),
        ] {
            let meta = std::fs::metadata(path).unwrap();
            assert_eq!(meta.uid(), expected_uid.as_raw());
            assert_eq!(meta.gid(), expected_gid.as_raw());
        }
    }

    #[cfg(unix)]
    #[test]
    fn chown_sandbox_home_rejects_symlink_root() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let err = chown_sandbox_home(
            &link,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn chown_sandbox_home_skips_symlink_children() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        let target = dir.path().join("outside");
        std::fs::write(&target, "secret").unwrap();
        symlink(&target, root.join("link")).unwrap();

        chown_sandbox_home(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
        )
        .expect("symlink children should be skipped");
    }

    #[cfg(unix)]
    #[test]
    fn chown_recursive_skips_erofs_subtree_but_continues_siblings() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sandbox");
        std::fs::create_dir(&root).unwrap();

        let readonly_dir = root.join("ro-mount");
        std::fs::create_dir(&readonly_dir).unwrap();
        std::fs::write(readonly_dir.join("child-under-ro.txt"), "data").unwrap();
        std::fs::write(root.join("writable-sibling.txt"), "data").unwrap();

        let chowned = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&chowned);
        let readonly_dir_for_chown = readonly_dir.clone();
        let fake_chown =
            move |path: &Path, _uid: Option<Uid>, _gid: Option<Gid>| -> nix::Result<()> {
                if path == readonly_dir_for_chown {
                    return Err(nix::errno::Errno::EROFS);
                }
                observed.lock().unwrap().push(path.to_path_buf());
                Ok(())
            };

        chown_children(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &fake_chown,
        )
        .expect("read-only subtree should be skipped");

        let chowned = chowned.lock().unwrap();
        assert!(
            !chowned.contains(&readonly_dir.join("child-under-ro.txt")),
            "children under EROFS directory must not be traversed"
        );
        assert!(
            chowned.contains(&root.join("writable-sibling.txt")),
            "writable sibling should still be chowned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn chown_recursive_propagates_non_erofs_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        let fake_chown = |_path: &Path, _uid: Option<Uid>, _gid: Option<Gid>| -> nix::Result<()> {
            Err(nix::errno::Errno::EPERM)
        };

        let result = chown_recursive(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &fake_chown,
        );
        assert!(result.is_err(), "non-EROFS errors should propagate");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_chowns_only_root() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        let child = root.join("image-content.txt");
        std::fs::write(&child, "image-owned").unwrap();

        let chowned = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&chowned);
        let fake_chown =
            move |path: &Path, _uid: Option<Uid>, _gid: Option<Gid>| -> nix::Result<()> {
                observed.lock().unwrap().push(path.to_path_buf());
                Ok(())
            };

        prepare_oci_workspace_with(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
            &fake_chown,
        )
        .expect("workspace root should be prepared");

        assert_eq!(*chowned.lock().unwrap(), vec![root]);
        assert!(child.exists(), "image-provided child should be untouched");
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_accepts_existing_owner_writable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        validate_oci_workspace(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .expect("image owner already has write and traverse authority");
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_accepts_supplementary_group_write_authority() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let root = dir.path().canonicalize().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o070)).unwrap();
        let metadata = std::fs::symlink_metadata(&root).unwrap();

        validate_oci_workspace(
            &root,
            Some(Uid::from_raw(metadata.uid().wrapping_add(1))),
            Some(Gid::from_raw(metadata.gid().wrapping_add(1))),
            &[Gid::from_raw(metadata.gid())],
        )
        .expect("supplementary group already has write and traverse authority");
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_rejects_unwritable_directory() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let root = dir.path().canonicalize().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = std::fs::symlink_metadata(&root).unwrap();

        let error = validate_oci_workspace(
            &root,
            Some(Uid::from_raw(metadata.uid().wrapping_add(1))),
            Some(Gid::from_raw(metadata.gid().wrapping_add(1))),
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("not writable and traversable"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_rejects_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("missing");

        let error = validate_oci_workspace(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn effective_identity_validation_honors_named_user_acl() {
        const TEST_UID: u32 = 42_234;
        const TEST_GID: u32 = 42_235;
        const ACL_XATTR_VERSION: u32 = 2;
        const ACL_USER_OBJ: u16 = 0x01;
        const ACL_USER: u16 = 0x02;
        const ACL_GROUP_OBJ: u16 = 0x04;
        const ACL_MASK: u16 = 0x10;
        const ACL_OTHER: u16 = 0x20;
        const ACL_UNDEFINED_ID: u32 = u32::MAX;

        if !nix::unistd::geteuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let root = dir.path().canonicalize().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut acl = ACL_XATTR_VERSION.to_ne_bytes().to_vec();
        for (tag, permissions, id) in [
            (ACL_USER_OBJ, 0o7_u16, ACL_UNDEFINED_ID),
            (ACL_USER, 0o7_u16, TEST_UID),
            (ACL_GROUP_OBJ, 0o0_u16, ACL_UNDEFINED_ID),
            (ACL_MASK, 0o7_u16, ACL_UNDEFINED_ID),
            (ACL_OTHER, 0o0_u16, ACL_UNDEFINED_ID),
        ] {
            acl.extend_from_slice(&tag.to_ne_bytes());
            acl.extend_from_slice(&permissions.to_ne_bytes());
            acl.extend_from_slice(&id.to_ne_bytes());
        }
        let path = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        let name = c"system.posix_acl_access";
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "setxattr failed: {}",
            std::io::Error::last_os_error()
        );

        match unsafe { fork() }.expect("fork should succeed") {
            ForkResult::Child => {
                let credentials_dropped = unsafe {
                    libc::setgroups(0, std::ptr::null()) == 0
                        && libc::setgid(TEST_GID) == 0
                        && libc::setuid(TEST_UID) == 0
                };
                let valid = credentials_dropped
                    && validate_oci_workspace_as_effective_identity(&root).is_ok();
                unsafe { libc::_exit(i32::from(!valid)) };
            }
            ForkResult::Parent { child } => {
                assert_eq!(
                    waitpid(child, None).expect("waitpid should succeed"),
                    WaitStatus::Exited(child, 0),
                    "named ACL user should retain workspace authority"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn effective_identity_validation_honors_landlock_denial() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let root = dir.path().canonicalize().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut policy = policy_with_process(ProcessPolicy::default());
        policy.filesystem = FilesystemPolicy {
            read_only: vec![root.clone()],
            read_write: Vec::new(),
            include_workdir: false,
        };
        policy.landlock = LandlockPolicy {
            compatibility: openshell_core::policy::LandlockCompatibility::HardRequirement,
        };
        let Ok(prepared) = sandbox::linux::prepare_current_user(&policy, None) else {
            return;
        };

        match unsafe { fork() }.expect("fork should succeed") {
            ForkResult::Child => {
                let denied = sandbox::linux::enforce(prepared).is_ok()
                    && validate_oci_workspace_as_effective_identity(&root).is_err();
                unsafe { libc::_exit(i32::from(!denied)) };
            }
            ForkResult::Parent { child } => {
                assert_eq!(
                    waitpid(child, None).expect("waitpid should succeed"),
                    WaitStatus::Exited(child, 0),
                    "kernel-effective validation should honor an enforced LSM denial"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_rejects_restrictive_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap().join("private");
        let root = parent.join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        let metadata = std::fs::symlink_metadata(&parent).unwrap();

        let error = validate_oci_workspace(
            &root,
            Some(Uid::from_raw(metadata.uid().wrapping_add(1))),
            Some(Gid::from_raw(metadata.gid().wrapping_add(1))),
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("not traversable"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_oci_workspace_rejects_symlink_component() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let target = base.join("target");
        let link = base.join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = validate_oci_workspace(
            &link,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_makes_existing_root_owner_writable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();

        prepare_oci_workspace_with(&root, None, None, &[], &|_, _, _| Ok(()))
            .expect("read-only workspace root should be prepared");

        let mode = std::fs::symlink_metadata(&root)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_rejects_symlink_root() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let target = base.join("real");
        let link = base.join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let err = prepare_oci_workspace(
            &link,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let target = base.join("real");
        let parent_link = base.join("parent-link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &parent_link).unwrap();

        let err = prepare_oci_workspace(
            &parent_link.join("workspace"),
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected parent symlink rejection: {err}"
        );
        assert!(
            !target.join("workspace").exists(),
            "workspace must not be created through a symlink parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_rejects_parent_traversal() {
        let err = prepare_oci_workspace(
            Path::new("/tmp/workspace/../escape"),
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("must be normalized"),
            "expected traversal rejection: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_rejects_inaccessible_existing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap().join("workspace");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::symlink_metadata(&parent).unwrap();
        let different_user = Uid::from_raw(metadata.uid().wrapping_add(1));
        let different_group = Gid::from_raw(metadata.gid().wrapping_add(1));
        let root = parent.join("project");

        let error = prepare_oci_workspace_with(
            &root,
            Some(different_user),
            Some(different_group),
            &[],
            &|_, _, _| Ok(()),
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("is not traversable"),
            "unexpected error: {error}"
        );
        assert!(
            !root.exists(),
            "workspace must not be created below an inaccessible parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_accepts_supplementary_group_parent() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o710)).unwrap();
        let parent = dir.path().canonicalize().unwrap().join("workspace");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o710)).unwrap();
        let metadata = std::fs::symlink_metadata(&parent).unwrap();
        let different_user = Uid::from_raw(metadata.uid().wrapping_add(1));
        let different_group = Gid::from_raw(metadata.gid().wrapping_add(1));
        let supplementary_group = Gid::from_raw(metadata.gid());
        let root = parent.join("project");

        prepare_oci_workspace_with(
            &root,
            Some(different_user),
            Some(different_group),
            &[supplementary_group],
            &|_, _, _| Ok(()),
        )
        .expect("supplementary group execute permission should allow traversal");

        assert!(root.is_dir());
    }

    #[cfg(not(any(
        target_os = "aix",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "redox",
        target_os = "solaris"
    )))]
    #[test]
    fn named_user_supplementary_groups_include_primary_group() {
        let user = User::from_uid(nix::unistd::geteuid())
            .expect("resolve current UID")
            .expect("current user exists");

        let groups = named_user_supplementary_groups(&user.name, user.gid)
            .expect("resolve named-user supplementary groups");

        assert!(groups.contains(&user.gid));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_rejects_non_directory_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("sandbox");
        std::fs::write(&root, "not a directory").unwrap();

        let error = prepare_oci_workspace(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("is not a directory"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_propagates_root_chown_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("sandbox");
        std::fs::create_dir(&root).unwrap();
        let fake_chown = |_path: &Path, _uid: Option<Uid>, _gid: Option<Gid>| -> nix::Result<()> {
            Err(nix::errno::Errno::EROFS)
        };

        let error = prepare_oci_workspace_with(
            &root,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
            &fake_chown,
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("Read-only file system"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_oci_workspace_creates_missing_root() {
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let missing = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("missing")
            .join("sandbox");
        let chowned = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&chowned);
        let fake_chown =
            move |path: &Path, _uid: Option<Uid>, _gid: Option<Gid>| -> nix::Result<()> {
                observed.lock().unwrap().push(path.to_path_buf());
                Ok(())
            };

        prepare_oci_workspace_with(
            &missing,
            Some(nix::unistd::geteuid()),
            Some(nix::unistd::getegid()),
            &[],
            &fake_chown,
        )
        .expect("missing OCI workspace should be created");

        assert!(missing.is_dir());
        assert_eq!(
            std::fs::symlink_metadata(missing.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(*chowned.lock().unwrap(), vec![missing]);
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_passwd_modifies_existing_sandbox_entry() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\nsandbox:x:1000:1000::/sandbox:/bin/bash\n",
        )
        .unwrap();

        rewrite_passwd_at(&passwd, "5000", "6000").unwrap();

        let content = std::fs::read_to_string(&passwd).unwrap();
        assert!(content.contains("sandbox:x:5000:6000::/sandbox:/bin/bash"));
        assert!(content.contains("root:x:0:0:root:/root:/bin/bash"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_passwd_appends_when_no_sandbox_entry() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, "root:x:0:0:root:/root:/bin/bash\n").unwrap();

        rewrite_passwd_at(&passwd, "5000", "6000").unwrap();

        let content = std::fs::read_to_string(&passwd).unwrap();
        assert!(content.contains("root:x:0:0:root:/root:/bin/bash"));
        assert!(content.contains("sandbox:x:5000:6000::/sandbox:/bin/sh"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_group_modifies_existing_sandbox_entry() {
        let dir = tempfile::tempdir().unwrap();
        let group = dir.path().join("group");
        std::fs::write(&group, "root:x:0:\nsandbox:x:1000:\n").unwrap();

        rewrite_group_at(&group, "6000").unwrap();

        let content = std::fs::read_to_string(&group).unwrap();
        assert!(content.contains("sandbox:x:6000:"));
        assert!(content.contains("root:x:0:"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_group_appends_when_no_sandbox_entry() {
        let dir = tempfile::tempdir().unwrap();
        let group = dir.path().join("group");
        std::fs::write(&group, "root:x:0:\n").unwrap();

        rewrite_group_at(&group, "6000").unwrap();

        let content = std::fs::read_to_string(&group).unwrap();
        assert!(content.contains("root:x:0:"));
        assert!(content.contains("sandbox:x:6000:"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_passwd_leaves_malformed_entry_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        // Only 3 fields — slice pattern should fall through instead of panic.
        std::fs::write(&passwd, "sandbox:x:1000\n").unwrap();
        rewrite_passwd_at(&passwd, "5000", "6000").unwrap();
        let content = std::fs::read_to_string(&passwd).unwrap();
        assert!(content.contains("sandbox:x:1000"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_group_leaves_malformed_entry_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let group = dir.path().join("group");
        // Only 2 fields — slice pattern should fall through instead of panic.
        std::fs::write(&group, "sandbox:x\n").unwrap();
        rewrite_group_at(&group, "6000").unwrap();
        let content = std::fs::read_to_string(&group).unwrap();
        assert!(content.contains("sandbox:x"));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_passwd_preserves_other_entries() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\nsandbox:x:1000:1000::/sandbox:/bin/bash\n",
        )
        .unwrap();

        rewrite_passwd_at(&passwd, "1234567", "1234567").unwrap();

        let content = std::fs::read_to_string(&passwd).unwrap();
        assert!(content.contains("root:x:0:0:root:/root:/bin/bash"));
        assert!(content.contains("nobody:x:65534:65534:nobody:/:/usr/sbin/nologin"));
        assert!(content.contains("sandbox:x:1234567:1234567::/sandbox:/bin/bash"));
        assert_eq!(content.lines().count(), 3);
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

    // ---- Numeric UID tests (Phase 2) ----

    #[test]
    fn drop_privileges_accepts_numeric_uid() {
        // When running as non-root, a numeric UID/GID that matches the
        // current process should succeed without any passwd lookup.
        if nix::unistd::geteuid().is_root() {
            return;
        }

        let uid_raw = nix::unistd::geteuid().as_raw();
        let gid_raw = nix::unistd::getegid().as_raw();

        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(uid_raw.to_string()),
            run_as_group: Some(gid_raw.to_string()),
        });

        assert!(
            drop_privileges(&policy).is_ok(),
            "should accept current process UID/GID as numeric strings"
        );
    }

    #[test]
    fn drop_privileges_numeric_uid_skips_initgroups() {
        // When running as non-root with a numeric user but group matches,
        // initgroups should not be called (guard: target_uid != geteuid()).
        if nix::unistd::geteuid().is_root() {
            return;
        }

        let current_uid = nix::unistd::geteuid().as_raw();

        // Use a different group name that exists (the current one).
        let current_group = Group::from_gid(nix::unistd::getegid())
            .expect("should resolve current group")
            .expect("current group should exist");

        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(current_uid.to_string()), // numeric UID, no passwd entry needed
            run_as_group: Some(current_group.name),     // name-based group
        });

        assert!(
            drop_privileges(&policy).is_ok(),
            "should accept numeric UID with name-based group (initgroups guarded)"
        );
    }

    #[test]
    fn numeric_uid_privilege_drop_child() {
        if std::env::var_os("OPENSHELL_TEST_NUMERIC_UID_CHILD").is_none() {
            return;
        }
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some("999999".into()),
            run_as_group: Some("999999".into()),
        });
        match drop_privileges(&policy) {
            Ok(()) => {}
            Err(e) => {
                assert!(
                    !e.to_string().contains("Failed to resolve user record"),
                    "unexpected error for numeric UID without passwd entry: {e}"
                );
            }
        }
    }

    #[test]
    fn drop_privileges_numeric_uid_without_passwd_entry_skips_lookup() {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("current exe"));
        cmd.arg("numeric_uid_privilege_drop_child")
            .arg("--nocapture")
            .env("OPENSHELL_TEST_NUMERIC_UID_CHILD", "1")
            .stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::piped());
        let output = cmd.output().expect("spawn child");
        assert!(
            output.status.success(),
            "numeric UID privilege drop child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
