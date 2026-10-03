// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process management and signal handling.

use crate::child_env;
#[cfg(target_os = "linux")]
use crate::managed_children;
use crate::sandbox;
#[cfg(target_os = "linux")]
use miette::WrapErr;
use miette::{IntoDiagnostic, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::{Pid, User};
use openshell_core::policy::SandboxPolicy;
use std::collections::HashMap;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tracing::debug;

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

#[cfg(target_os = "linux")]
pub(crate) fn prepare_child_sandbox(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
    runtime_read_only: &[PathBuf],
) -> Result<Option<sandbox::linux::PreparedSandbox>> {
    let effective_policy = policy_with_runtime_read_only(policy, runtime_read_only);
    let prepared = sandbox::linux::prepare_capability_free(&effective_policy, workdir)?;
    Ok(Some(prepared))
}

#[cfg(target_os = "linux")]
fn policy_with_runtime_read_only(
    policy: &SandboxPolicy,
    runtime_read_only: &[PathBuf],
) -> SandboxPolicy {
    let mut effective_policy = policy.clone();
    for path in runtime_read_only {
        if !effective_policy.filesystem.read_only.contains(path) {
            effective_policy.filesystem.read_only.push(path.clone());
        }
    }
    effective_policy
}

#[cfg(target_os = "linux")]
pub(crate) fn ca_runtime_read_only_paths(ca_paths: Option<&(PathBuf, PathBuf)>) -> Vec<PathBuf> {
    let Some((certificate, bundle)) = ca_paths else {
        return Vec::new();
    };
    let mut paths = Vec::with_capacity(3);
    if let Some(directory) = certificate.parent() {
        paths.push(directory.to_path_buf());
    }
    paths.push(certificate.clone());
    paths.push(bundle.clone());
    paths
}

/// Prefix of environment variable names reserved for `OpenShell`.
pub(crate) const RESERVED_ENV_PREFIX: &str = "OPENSHELL_";

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

const PROXY_ENV_VARS: &[&str] = &[
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "grpc_proxy",
    "NODE_USE_ENV_PROXY",
];

pub fn is_supervisor_only_env_var(key: &str) -> bool {
    SUPERVISOR_ONLY_ENV_VARS.contains(&key)
}

fn strip_supervisor_only_env(cmd: &mut Command) {
    for key in SUPERVISOR_ONLY_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// Remove ambient proxy routing from a transparently mediated child.
pub fn strip_proxy_env(cmd: &mut Command) {
    for key in PROXY_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// [`strip_proxy_env`] for synchronous exec commands.
pub fn strip_proxy_env_std(cmd: &mut std::process::Command) {
    for key in PROXY_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// Whether an environment key can redirect a child around transparent
/// network mediation.
#[must_use]
pub fn is_proxy_env_var(key: &str) -> bool {
    PROXY_ENV_VARS.contains(&key)
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
    // The canonical process inherits the sandbox's environment so the image's
    // own ENV (PATH, LANG, JAVA_HOME, ...) reaches the workload. Remove the
    // reserved OPENSHELL_ namespace inherited from the sandbox itself, which
    // carries its own control state (for example the serialized user
    // environment and log level), then restore the one marker the workload is
    // meant to see. The gateway rejects declared variables in this namespace.
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with(RESERVED_ENV_PREFIX))
        {
            cmd.env_remove(key);
        }
    }
    cmd.env(openshell_core::sandbox_env::SANDBOX, "1");
    cmd.envs(user_environment);
    let (session_user, session_home) = session_user_and_home(policy, workspace.home());
    // Resolve a shell present in the workload image. This code runs inside the
    // workload boundary, where the image filesystem is visible.
    let shell = openshell_core::shell::detect_login_shell();

    for (key, value) in [
        ("HOME", session_home.as_str()),
        ("USER", session_user.as_str()),
        ("SHELL", shell.as_str()),
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
pub fn spawn_command_with_workload_launcher(
    launcher: &openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
    mut cmd: Command,
) -> std::io::Result<Child> {
    let runtime = tokio::runtime::Handle::current();
    launcher.execute(move || {
        let _guard = runtime.enter();
        cmd.spawn()
    })?
}

#[cfg(target_os = "linux")]
pub fn spawn_std_command_with_workload_launcher(
    launcher: &openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
    mut cmd: std::process::Command,
) -> std::io::Result<std::process::Child> {
    launcher.execute(move || cmd.spawn())?
}

/// Handle to a running process.
pub struct ProcessHandle {
    child: Child,
    pid: u32,
    io: Option<ProcessIo>,
    terminal: Arc<AtomicBool>,
    signal_lock: Arc<std::sync::Mutex<()>>,
    #[cfg(target_os = "linux")]
    managed_child: Option<managed_children::ManagedChild>,
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
        launcher: &openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
        program: &str,
        args: &[String],
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            launcher,
            program,
            args,
            workspace,
            interactive,
            policy,
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
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::spawn_impl(
            program,
            args,
            workspace,
            interactive,
            policy,
            ca_paths,
            provider_env,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn spawn_impl(
        launcher: &openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
        program: &str,
        args: &[String],
        workspace: &ResolvedWorkspace,
        interactive: bool,
        policy: &SandboxPolicy,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args).kill_on_drop(true);

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
        apply_canonical_process_environment(
            &mut cmd,
            policy,
            workspace,
            interactive,
            &configured_user_environment(),
        );
        strip_supervisor_only_env(&mut cmd);

        inject_provider_env(&mut cmd, provider_env);

        if let Some(dir) = workspace.root() {
            cmd.current_dir(dir);
        }

        strip_proxy_env(&mut cmd);

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
        sandbox::linux::log_sandbox_readiness(policy, workspace.root());

        // Prepare the Landlock ruleset as the workload UID. Inaccessible paths
        // are already unavailable to the child and remain omitted.
        #[cfg(target_os = "linux")]
        let runtime_read_only = ca_runtime_read_only_paths(ca_paths);
        let prepared_sandbox = prepare_child_sandbox(policy, workspace.root(), &runtime_read_only)
            .map_err(|err| miette::miette!("Failed to prepare sandbox: {err}"))?;
        #[cfg(target_os = "linux")]
        let mut child_hardening =
            openshell_isolation_interface::linux::child_seccomp::prepare(std::process::id())
                .map_err(|error| {
                    miette::miette!("prepare child self-protection filter: {error}")
                })?;
        // Set up process group for signal handling (non-interactive mode only).
        // In interactive mode, we inherit the parent's process group to maintain
        // proper terminal control for shells and interactive programs.
        // SAFETY: pre_exec runs after fork but before exec in the child process.
        // setpgid and setns are async-signal-safe and safe to call in this context.
        {
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

                    harden_child_process().map_err(|err| std::io::Error::other(err.to_string()))?;

                    // Phase 2 (as unprivileged user): Enforce the prepared
                    // Landlock ruleset via restrict_self() + apply seccomp.
                    // restrict_self() does not require root.
                    #[cfg(target_os = "linux")]
                    if let Some(prepared) = prepared_sandbox.take() {
                        sandbox::linux::enforce_capability_free(prepared, &mut child_hardening)
                            .map_err(|err| std::io::Error::other(err.to_string()))?;
                    }

                    Ok(())
                });
            }
        }

        // Name the program in the error: a bare "No such file or directory"
        // here is otherwise indistinguishable from a missing working directory
        // or interpreter, and is a common failure on images that lack the
        // requested shell/binary (e.g. bash on Alpine).
        #[cfg(target_os = "linux")]
        let mut child_registry = managed_children::lock();
        #[cfg(target_os = "linux")]
        let mut child = spawn_command_with_workload_launcher(launcher, cmd)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to spawn sandbox entrypoint process '{program}'"))?;
        #[cfg(not(target_os = "linux"))]
        let mut child = cmd
            .spawn()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to spawn sandbox entrypoint process '{program}'"))?;
        let pid = child.id().unwrap_or(0);
        let managed_child = child_registry.register(pid);
        drop(child_registry);

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
            terminal: Arc::new(AtomicBool::new(false)),
            signal_lock: Arc::new(std::sync::Mutex::new(())),
            #[cfg(target_os = "linux")]
            managed_child,
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
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args).kill_on_drop(true);

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
        apply_canonical_process_environment(
            &mut cmd,
            policy,
            workspace,
            interactive,
            &configured_user_environment(),
        );
        strip_supervisor_only_env(&mut cmd);

        inject_provider_env(&mut cmd, provider_env);

        if let Some(dir) = workspace.root() {
            cmd.current_dir(dir);
        }

        strip_proxy_env(&mut cmd);

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

                    harden_child_process().map_err(|err| std::io::Error::other(err.to_string()))?;
                    sandbox::apply(&policy, workdir.as_deref())
                        .map_err(|err| std::io::Error::other(err.to_string()))?;

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
            terminal: Arc::new(AtomicBool::new(false)),
            signal_lock: Arc::new(std::sync::Mutex::new(())),
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

    /// Shared state used by an independent boundary signal handle.
    #[must_use]
    pub fn signaling_state(&self) -> (Arc<AtomicBool>, Arc<std::sync::Mutex<()>>) {
        (self.terminal.clone(), self.signal_lock.clone())
    }

    /// Wait for the process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting fails.
    pub async fn wait(&mut self) -> std::io::Result<ProcessStatus> {
        let status = self.child.wait().await;
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.terminal.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        if let Some(child) = self.managed_child.take() {
            managed_children::unregister(child);
        }
        let status = status?;
        Ok(ProcessStatus::from(status))
    }

    /// Observe an already-terminated child without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ProcessStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            let _signal_guard = self
                .signal_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.terminal.store(true, Ordering::Release);
            #[cfg(target_os = "linux")]
            if let Some(child) = self.managed_child.take() {
                managed_children::unregister(child);
            }
        }
        Ok(status.map(ProcessStatus::from))
    }

    /// Send a signal to the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent.
    pub fn signal(&self, sig: Signal) -> Result<()> {
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return Err(miette::miette!("process has exited"));
        }
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
        if let Some(child) = self.managed_child.take() {
            managed_children::unregister(child);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn validate_oci_workspace_as_effective_identity(root: &Path) -> Result<()> {
    use rustix::fs::{Access, AtFlags, FileType, Mode, OFlags};

    let components = validated_workspace_components(root)?;
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

#[cfg(target_os = "linux")]
fn validated_workspace_components(root: &Path) -> Result<Vec<std::ffi::OsString>> {
    let root_str = root
        .to_str()
        .ok_or_else(|| miette::miette!("workspace path must be valid UTF-8"))?;
    let validated_root = openshell_core::driver_mounts::resolve_oci_workspace_root(root_str)
        .map_err(|error| miette::miette!(error))?;
    if Path::new(&validated_root) != root
        || validated_root == openshell_core::driver_mounts::DEFAULT_WORKSPACE_ROOT
    {
        return Err(miette::miette!(
            "workspace path '{}' must be a normalized absolute non-fallback path",
            root.display()
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
    #[cfg(target_os = "linux")]
    use std::ffi::CString;
    #[cfg(unix)]
    use std::mem::size_of;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
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
        // SHELL is the shell detected in the current root filesystem, not a
        // hardcoded path (bash-less images resolve to /bin/sh).
        let expected_shell = openshell_core::shell::detect_login_shell();
        assert_eq!(variables.get("SHELL"), Some(&expected_shell.as_str()));
        assert_eq!(variables.get("TERM"), Some(&"xterm-256color"));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_process_drops_inherited_reserved_environment() {
        // The sandbox's own control variables live in the reserved
        // OPENSHELL_ namespace and must not reach the workload, while the
        // image's ordinary ENV must. Run in a fresh copy of the test binary
        // so the test harness environment is untouched.
        const CHILD_MARKER: &str = "OPENSHELL_TEST_RESERVED_ENV_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::tests::canonical_process_drops_inherited_reserved_environment",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .env(openshell_core::sandbox_env::LOG_LEVEL, "debug")
                .env(openshell_core::sandbox_env::USER_ENVIRONMENT, "{}")
                .env("IMAGE_LANG", "keep")
                .status()
                .expect("run isolated environment test");
            assert!(status.success(), "isolated environment test failed");
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let current_user = User::from_uid(nix::unistd::geteuid()).unwrap().unwrap();
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(current_user.name),
            run_as_group: None,
        });
        // Mirror production: inherit the sandbox environment, no env_clear.
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdout(StdStdio::piped());
        apply_canonical_process_environment(
            &mut cmd,
            &policy,
            &ResolvedWorkspace::default(),
            false,
            &HashMap::from([("DECLARED".into(), "yes".into())]),
        );
        let output = runtime
            .block_on(async { cmd.output().await })
            .expect("run environment probe");
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        let variables: HashMap<_, _> = environment
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        assert!(
            !variables
                .keys()
                .any(|key| key.starts_with(RESERVED_ENV_PREFIX)
                    && *key != openshell_core::sandbox_env::SANDBOX),
            "reserved variables reached the workload: {variables:?}"
        );
        assert_eq!(
            variables.get(openshell_core::sandbox_env::SANDBOX),
            Some(&"1")
        );
        assert_eq!(variables.get("IMAGE_LANG"), Some(&"keep"));
        assert_eq!(variables.get("DECLARED"), Some(&"yes"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canonical_process_receives_declared_environment_and_home() {
        let current_user = User::from_uid(nix::unistd::geteuid()).unwrap().unwrap();
        let policy = policy_with_process(ProcessPolicy {
            run_as_user: Some(current_user.name),
            run_as_group: None,
        });
        for interactive in [false, true] {
            let mut cmd = Command::new("/usr/bin/env");
            cmd.env_clear().stdout(StdStdio::piped());
            let declared = HashMap::from([
                ("APPLICATION_AGENT".into(), "researcher".into()),
                (
                    openshell_core::sandbox_env::SANDBOX_TOKEN.into(),
                    "must-not-reach-child".into(),
                ),
                ("ANTHROPIC_API_KEY".into(), "caller-value".into()),
                ("HOME".into(), "/sandbox".into()),
            ]);
            apply_canonical_process_environment(
                &mut cmd,
                &policy,
                &ResolvedWorkspace::default(),
                interactive,
                &declared,
            );
            strip_supervisor_only_env(&mut cmd);
            inject_provider_env(
                &mut cmd,
                &HashMap::from([(
                    "ANTHROPIC_API_KEY".into(),
                    "openshell:resolve:env:ANTHROPIC_API_KEY".into(),
                )]),
            );
            let output = cmd.output().await.expect("run environment probe");
            assert!(output.status.success());
            let environment = String::from_utf8(output.stdout).unwrap();
            let variables: HashMap<_, _> = environment
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            assert_eq!(variables.get("APPLICATION_AGENT"), Some(&"researcher"));
            assert!(!variables.contains_key(openshell_core::sandbox_env::SANDBOX_TOKEN));
            assert_eq!(
                variables.get("ANTHROPIC_API_KEY"),
                Some(&"openshell:resolve:env:ANTHROPIC_API_KEY")
            );
            assert_eq!(variables.get("HOME"), Some(&"/sandbox"));
        }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_ca_paths_are_added_to_the_effective_read_only_policy() {
        let mut policy = policy_with_process(ProcessPolicy::default());
        policy.filesystem.read_only = vec![PathBuf::from("/usr")];
        let certificate = PathBuf::from(format!(
            "{}/ca.crt",
            openshell_sandbox_backend::SUPERVISOR_CA_RUNTIME_DIR
        ));
        let bundle = PathBuf::from(format!(
            "{}/ca-bundle.crt",
            openshell_sandbox_backend::SUPERVISOR_CA_RUNTIME_DIR
        ));

        let effective = policy_with_runtime_read_only(
            &policy,
            &[certificate.clone(), bundle.clone(), certificate.clone()],
        );

        assert_eq!(policy.filesystem.read_only, vec![PathBuf::from("/usr")]);
        assert_eq!(
            effective.filesystem.read_only,
            vec![PathBuf::from("/usr"), certificate, bundle]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn runtime_ca_material_remains_readable_after_landlock_for_non_root_workload() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let ca_directory = root.path().join("openshell-supervisor-ca");
        std::fs::create_dir(&ca_directory).unwrap();
        std::fs::set_permissions(&ca_directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let certificate = ca_directory.join("ca.crt");
        let bundle = ca_directory.join("ca-bundle.crt");
        let denied = root.path().join("not-authorized");
        for path in [&certificate, &bundle, &denied] {
            std::fs::write(path, b"public certificate material").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }

        let mut policy = policy_with_process(ProcessPolicy::default());
        policy.landlock = LandlockPolicy {
            compatibility: openshell_core::policy::LandlockCompatibility::HardRequirement,
        };
        let runtime_paths =
            ca_runtime_read_only_paths(Some(&(certificate.clone(), bundle.clone())));
        let Ok(Some(prepared)) = prepare_child_sandbox(&policy, None, &runtime_paths) else {
            return;
        };

        match unsafe { fork() }.expect("fork should succeed") {
            ForkResult::Child => {
                let dropped = if nix::unistd::geteuid().is_root() {
                    unsafe {
                        libc::setgroups(0, std::ptr::null()) == 0
                            && libc::setgid(42_235) == 0
                            && libc::setuid(42_234) == 0
                    }
                } else {
                    true
                };
                let valid = dropped
                    && sandbox::linux::enforce(prepared).is_ok()
                    && std::fs::read(&certificate).is_ok()
                    && std::fs::read(&bundle).is_ok()
                    && std::fs::read(&denied).is_err();
                unsafe { libc::_exit(i32::from(!valid)) };
            }
            ForkResult::Parent { child } => assert_eq!(
                waitpid(child, None).expect("waitpid should succeed"),
                WaitStatus::Exited(child, 0),
                "Landlock must preserve non-root access only to admitted public CA material"
            ),
        }
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

    #[tokio::test]
    async fn transparent_mediation_removes_ambient_proxy_routing() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env_clear()
            .stdin(StdStdio::null())
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null())
            .env("PATH", "/usr/bin:/bin");
        for key in PROXY_ENV_VARS {
            cmd.env(key, "http://ambient-proxy.invalid:3128");
        }

        strip_proxy_env(&mut cmd);

        let output = cmd.output().await.expect("spawn env");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        for key in PROXY_ENV_VARS {
            assert!(
                !stdout
                    .lines()
                    .any(|line| line.starts_with(&format!("{key}="))),
                "{key} must not redirect a transparently mediated process"
            );
        }
        assert!(stdout.contains("PATH=/usr/bin:/bin"));
    }
}
