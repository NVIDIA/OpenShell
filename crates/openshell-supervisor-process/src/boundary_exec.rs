// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Co-located implementation of RFC 0012 in-boundary exec.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use async_trait::async_trait;
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use openshell_core::policy::SandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation::contract::{
    BackendError, BoundaryExec, BoundaryExitStatus, BoundaryInput, BoundaryOutput, BoundaryProcess,
    BoundarySignal, BoundaryTerminal, ExecSession, ExecSpec,
};

use crate::process::{ProcessEnforcementMode, ResolvedProcessIdentity};

/// The co-located executor. Every spawn reuses the same admitted policy and
/// execution-environment controls while taking a fresh provider credential
/// snapshot.
#[derive(Clone)]
pub struct LocalBoundaryExec {
    policy: SandboxPolicy,
    base_workdir: Option<String>,
    netns_fd: Option<Arc<OwnedFd>>,
    proxy_url: Option<String>,
    ca_file_paths: Option<Arc<(std::path::PathBuf, std::path::PathBuf)>>,
    provider_credentials: ProviderCredentialState,
    user_environment: HashMap<String, String>,
    resolved_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
    runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
}

impl LocalBoundaryExec {
    /// Construct one executor for an active co-located boundary.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        policy: SandboxPolicy,
        base_workdir: Option<String>,
        netns_fd: Option<Arc<OwnedFd>>,
        proxy_url: Option<String>,
        ca_file_paths: Option<Arc<(std::path::PathBuf, std::path::PathBuf)>>,
        provider_credentials: ProviderCredentialState,
        user_environment: HashMap<String, String>,
        resolved_identity: ResolvedProcessIdentity,
        enforcement_mode: ProcessEnforcementMode,
        runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
    ) -> Self {
        Self {
            policy,
            base_workdir,
            netns_fd,
            proxy_url,
            ca_file_paths,
            provider_credentials,
            user_environment,
            resolved_identity,
            enforcement_mode,
            runtime,
        }
    }

    fn command(&self, spec: &ExecSpec) -> Result<Command, BackendError> {
        if spec.program.is_empty() {
            return Err(BackendError::Process("exec program is empty".to_string()));
        }
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        let effective_workdir = spec.workdir.as_deref().or(self.base_workdir.as_deref());
        let (session_user, session_home) =
            crate::process::session_user_and_home(&self.policy, effective_workdir);
        crate::ssh::apply_child_env(
            &mut command,
            &session_home,
            &session_user,
            if spec.pty { "xterm-256color" } else { "dumb" },
            self.proxy_url.as_deref(),
            self.ca_file_paths.as_deref(),
            &self.provider_credentials.child_env_with_gcp_resolved(),
            &self.user_environment,
        );
        for (key, value) in &spec.env {
            if !key.starts_with("OPENSHELL_") {
                command.env(key, value);
            }
        }
        if let Some(workdir) = spec.workdir.as_deref().or(self.base_workdir.as_deref()) {
            command.current_dir(workdir);
        }
        Ok(command)
    }

    fn prepare_sandbox(
        &self,
        workdir: Option<&str>,
    ) -> Result<Option<crate::sandbox::linux::PreparedSandbox>, BackendError> {
        #[cfg(target_os = "linux")]
        {
            if self.enforcement_mode.enforces_child_sandbox() {
                crate::sandbox::linux::log_sandbox_readiness(&self.policy, workdir);
            }
            crate::process::prepare_child_sandbox(&self.policy, workdir, self.enforcement_mode)
                .map_err(|error| BackendError::Process(error.to_string()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = workdir;
            Ok(None)
        }
    }

    fn spawn_piped(&self, spec: &ExecSpec) -> Result<SpawnedExec, BackendError> {
        self.runtime.ensure_active()?;
        let mut command = self.command(spec)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let effective_workdir = spec.workdir.as_deref().or(self.base_workdir.as_deref());
        #[cfg(target_os = "linux")]
        let prepared = self.prepare_sandbox(effective_workdir)?;
        crate::ssh::unsafe_pty::install_pre_exec_no_pty(
            &mut command,
            self.policy.clone(),
            effective_workdir.map(str::to_string),
            self.netns_fd.as_deref().map(AsRawFd::as_raw_fd),
            self.resolved_identity,
            self.enforcement_mode,
            #[cfg(target_os = "linux")]
            prepared,
        );
        #[cfg(target_os = "linux")]
        let mut child_registry = crate::managed_children::lock();
        let mut child = command
            .spawn()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let pid = child.id();
        let process_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal_lock = Arc::new(std::sync::Mutex::new(()));
        if let Err(error) =
            self.runtime
                .register_process_group(pid, process_terminal.clone(), signal_lock.clone())
        {
            let _ = killpg(
                Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX)),
                Signal::SIGKILL,
            );
            let _ = child.wait();
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        let managed_child = child_registry.register(pid);
        #[cfg(target_os = "linux")]
        drop(child_registry);
        let stdin = child.stdin.take().map(|file| -> BoundaryInput {
            let fd: OwnedFd = file.into();
            Box::new(tokio::fs::File::from_std(std::fs::File::from(fd)))
        });
        let stdout = child
            .stdout
            .take()
            .map(|file| -> BoundaryOutput {
                let fd: OwnedFd = file.into();
                Box::new(tokio::fs::File::from_std(std::fs::File::from(fd)))
            })
            .ok_or_else(|| BackendError::Process("exec stdout pipe missing".to_string()))?;
        let stderr = child.stderr.take().map(|file| -> BoundaryOutput {
            let fd: OwnedFd = file.into();
            Box::new(tokio::fs::File::from_std(std::fs::File::from(fd)))
        });
        let process = Arc::new(LocalExecProcess::new(
            child,
            pid,
            self.runtime.clone(),
            process_terminal,
            signal_lock,
            #[cfg(target_os = "linux")]
            managed_child,
        ));
        Ok(SpawnedExec {
            session: Some(ExecSession {
                process: process.clone(),
                stdin,
                stdout,
                stderr,
                terminal: None,
            }),
            process,
            armed: true,
        })
    }

    fn spawn_pty(&self, spec: &ExecSpec) -> Result<SpawnedExec, BackendError> {
        self.runtime.ensure_active()?;
        let winsize = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = openpty(Some(&winsize), None)
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let master = std::fs::File::from(pty.master);
        let slave = std::fs::File::from(pty.slave);
        let slave_fd = slave.as_raw_fd();
        let input = master
            .try_clone()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let output = master
            .try_clone()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let stdin = slave
            .try_clone()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let stdout = slave
            .try_clone()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let mut command = self.command(spec)?;
        command.stdin(stdin).stdout(stdout).stderr(slave);
        let effective_workdir = spec.workdir.as_deref().or(self.base_workdir.as_deref());
        #[cfg(target_os = "linux")]
        let prepared = self.prepare_sandbox(effective_workdir)?;
        crate::ssh::unsafe_pty::install_pre_exec(
            &mut command,
            self.policy.clone(),
            effective_workdir.map(str::to_string),
            slave_fd,
            self.netns_fd.as_deref().map(AsRawFd::as_raw_fd),
            self.resolved_identity,
            self.enforcement_mode,
            #[cfg(target_os = "linux")]
            prepared,
        );
        #[cfg(target_os = "linux")]
        let mut child_registry = crate::managed_children::lock();
        let mut child = command
            .spawn()
            .map_err(|error| BackendError::Process(error.to_string()))?;
        let pid = child.id();
        let process_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal_lock = Arc::new(std::sync::Mutex::new(()));
        if let Err(error) =
            self.runtime
                .register_process_group(pid, process_terminal.clone(), signal_lock.clone())
        {
            let _ = killpg(
                Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX)),
                Signal::SIGKILL,
            );
            let _ = child.wait();
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        let managed_child = child_registry.register(pid);
        #[cfg(target_os = "linux")]
        drop(child_registry);
        let terminal: Arc<dyn BoundaryTerminal> = Arc::new(LocalTerminal { master });
        let process = Arc::new(LocalExecProcess::new(
            child,
            pid,
            self.runtime.clone(),
            process_terminal,
            signal_lock,
            #[cfg(target_os = "linux")]
            managed_child,
        ));
        Ok(SpawnedExec {
            session: Some(ExecSession {
                process: process.clone(),
                stdin: Some(Box::new(tokio::fs::File::from_std(input))),
                stdout: Box::new(tokio::fs::File::from_std(output)),
                stderr: None,
                terminal: Some(terminal),
            }),
            process,
            armed: true,
        })
    }
}

struct SpawnedExec {
    session: Option<ExecSession>,
    process: Arc<LocalExecProcess>,
    armed: bool,
}

impl SpawnedExec {
    fn into_session(mut self) -> ExecSession {
        self.armed = false;
        self.session.take().expect("spawned exec session")
    }
}

impl Drop for SpawnedExec {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.process.deliver(Signal::SIGKILL);
        }
    }
}

#[async_trait]
impl BoundaryExec for LocalBoundaryExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let executor = self.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let result = if spec.pty {
                executor.spawn_pty(&spec)
            } else {
                executor.spawn_piped(&spec)
            };
            // If the caller cancelled, either send fails and drops the armed
            // process guard here, or the queued guard is dropped with the
            // receiver. Both paths terminate an unobservable exec process.
            let _ = send.send(result);
        });
        receive
            .await
            .map_err(|_| BackendError::Process("exec spawn task failed".to_string()))?
            .map(SpawnedExec::into_session)
    }
}

struct LocalTerminal {
    master: std::fs::File,
}

#[async_trait]
impl BoundaryTerminal for LocalTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        crate::ssh::unsafe_pty::set_winsize(
            self.master.as_raw_fd(),
            Winsize {
                ws_row: rows.max(1),
                ws_col: cols.max(1),
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(|error| BackendError::Process(error.to_string()))
    }
}

struct LocalExecProcess {
    pid: u32,
    result: Arc<std::sync::Mutex<Option<Result<BoundaryExitStatus, String>>>>,
    exited: Arc<tokio::sync::Notify>,
    runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
    terminal: Arc<std::sync::atomic::AtomicBool>,
    signal_lock: Arc<std::sync::Mutex<()>>,
}

impl LocalExecProcess {
    fn new(
        child: Child,
        pid: u32,
        runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
        terminal: Arc<std::sync::atomic::AtomicBool>,
        signal_lock: Arc<std::sync::Mutex<()>>,
        #[cfg(target_os = "linux")] managed_child: Option<crate::managed_children::ManagedChild>,
    ) -> Self {
        let result = Arc::new(std::sync::Mutex::new(None));
        let exited = Arc::new(tokio::sync::Notify::new());
        let result_for_wait = result.clone();
        let exited_for_wait = exited.clone();
        let runtime_for_wait = runtime.clone();
        let terminal_for_wait = terminal.clone();
        let registration_terminal = terminal.clone();
        #[cfg(target_os = "linux")]
        let signal_lock_for_wait = signal_lock.clone();
        tokio::spawn(async move {
            let waited = tokio::task::spawn_blocking(move || {
                let mut child = child;
                #[cfg(target_os = "linux")]
                {
                    crate::managed_children::wait_until_terminal(pid)?;
                    let _signal_guard = signal_lock_for_wait
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    terminal_for_wait.store(true, std::sync::atomic::Ordering::Release);
                    let result = child.wait();
                    if let Some(managed_child) = managed_child {
                        crate::managed_children::unregister(managed_child);
                    }
                    result
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let result = child.wait();
                    terminal_for_wait.store(true, std::sync::atomic::Ordering::Release);
                    result
                }
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|status| status.map_err(|error| error.to_string()))
            .map(|status| {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(signal) = status.signal() {
                        return BoundaryExitStatus::Signaled(signal);
                    }
                }
                BoundaryExitStatus::Exited(status.code().unwrap_or(1))
            });
            runtime_for_wait.unregister_process_group(pid, &registration_terminal);
            if let Ok(mut slot) = result_for_wait.lock() {
                *slot = Some(waited);
            }
            exited_for_wait.notify_waiters();
        });
        Self {
            pid,
            result,
            exited,
            runtime,
            terminal,
            signal_lock,
        }
    }

    fn deliver(&self, signal: Signal) -> Result<(), BackendError> {
        self.runtime.ensure_active()?;
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            return Err(BackendError::Terminated("process has exited".to_string()));
        }
        let pid = i32::try_from(self.pid).unwrap_or(i32::MAX);
        killpg(Pid::from_raw(pid), signal).map_err(|error| BackendError::Process(error.to_string()))
    }
}

#[async_trait]
impl BoundaryProcess for LocalExecProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        loop {
            let notified = self.exited.notified();
            let result = self
                .result
                .lock()
                .map_err(|_| BackendError::Process("exec result lock poisoned".to_string()))?
                .clone();
            if let Some(result) = result {
                return result.map_err(BackendError::Process);
            }
            notified.await;
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.deliver(match signal {
            BoundarySignal::Term => Signal::SIGTERM,
            BoundarySignal::Kill => Signal::SIGKILL,
            BoundarySignal::Int => Signal::SIGINT,
            BoundarySignal::Hup => Signal::SIGHUP,
        })
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.deliver(Signal::SIGKILL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn executor() -> LocalBoundaryExec {
        LocalBoundaryExec::new(
            SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            },
            None,
            None,
            None,
            None,
            ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            HashMap::new(),
            ResolvedProcessIdentity::default(),
            ProcessEnforcementMode::NetworkOnly,
            crate::boundary_io::BoundaryRuntimeState::new(),
        )
    }

    #[tokio::test]
    async fn non_pty_exec_preserves_stdin_stdout_and_stderr() {
        let mut session = executor()
            .exec(ExecSpec {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "read line; printf 'out:%s' \"$line\"; printf 'err:%s' \"$line\" >&2"
                        .to_string(),
                ],
                env: vec![],
                workdir: None,
                pty: false,
            })
            .await
            .expect("spawn exec");
        let mut stdin = session.stdin.take().expect("stdin");
        stdin.write_all(b"value\n").await.expect("write stdin");
        drop(stdin);
        let mut stdout = String::new();
        let mut stderr = String::new();
        session
            .stdout
            .read_to_string(&mut stdout)
            .await
            .expect("read stdout");
        session
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut stderr)
            .await
            .expect("read stderr");
        assert_eq!(
            session.process.wait().await.unwrap(),
            BoundaryExitStatus::Exited(0)
        );
        assert_eq!(stdout, "out:value");
        assert_eq!(stderr, "err:value");
    }

    #[tokio::test]
    async fn exec_rejects_after_boundary_end() {
        let executor = executor();
        executor.runtime.deactivate();
        let result = executor
            .exec(ExecSpec {
                program: "/bin/true".to_string(),
                args: vec![],
                env: vec![],
                workdir: None,
                pty: false,
            })
            .await;
        assert!(matches!(result, Err(BackendError::Terminated(_))));
    }

    #[tokio::test]
    async fn failed_exec_leaves_boundary_active_without_registered_processes() {
        let executor = executor();
        let runtime = executor.runtime.clone();
        let result = executor
            .exec(ExecSpec {
                program: "/definitely/missing/openshell-exec".to_string(),
                args: vec![],
                env: vec![],
                workdir: None,
                pty: false,
            })
            .await;
        assert!(matches!(result, Err(BackendError::Process(_))));
        runtime.ensure_active().expect("boundary remains active");
        assert_eq!(runtime.registered_process_group_count(), 0);
    }

    #[tokio::test]
    async fn cancelled_exec_does_not_leave_a_registered_process() {
        let executor = executor();
        let runtime = executor.runtime.clone();
        let task = tokio::spawn(async move {
            executor
                .exec(ExecSpec {
                    program: "/bin/sleep".to_string(),
                    args: vec!["30".to_string()],
                    env: vec![],
                    workdir: None,
                    pty: false,
                })
                .await
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;

        // Give the detached blocking setup time to reach its cancelled
        // handoff, including the case where cancellation won before spawn.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while runtime.registered_process_group_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled exec process must be terminated and reaped");
        runtime.ensure_active().expect("boundary remains active");
    }

    #[tokio::test]
    async fn dropping_undelivered_exec_guard_terminates_process() {
        let executor = executor();
        let runtime = executor.runtime.clone();
        let spawned = tokio::task::spawn_blocking(move || {
            executor.spawn_piped(&ExecSpec {
                program: "/bin/sleep".to_string(),
                args: vec!["30".to_string()],
                env: vec![],
                workdir: None,
                pty: false,
            })
        })
        .await
        .expect("spawn task")
        .expect("spawn exec");
        assert_eq!(runtime.registered_process_group_count(), 1);

        // This is the post-send/pre-receive cancellation case: dropping the
        // queued ownership guard must kill the process before it is observable.
        drop(spawned);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while runtime.registered_process_group_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("undelivered exec process must be terminated and reaped");
        runtime.ensure_active().expect("boundary remains active");
    }

    #[tokio::test]
    async fn completed_exec_removes_its_process_group_registration() {
        let executor = executor();
        let runtime = executor.runtime.clone();
        let session = executor
            .exec(ExecSpec {
                program: "/bin/true".to_string(),
                args: vec![],
                env: vec![],
                workdir: None,
                pty: false,
            })
            .await
            .expect("spawn exec");
        assert_eq!(
            session.process.wait().await.unwrap(),
            BoundaryExitStatus::Exited(0)
        );
        assert_eq!(runtime.registered_process_group_count(), 0);
    }

    #[tokio::test]
    async fn pty_exec_exposes_resize_and_stable_wait() {
        let session = executor()
            .exec(ExecSpec {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "exit 7".to_string()],
                env: vec![],
                workdir: None,
                pty: true,
            })
            .await
            .expect("spawn pty exec");
        session
            .terminal
            .as_ref()
            .expect("terminal")
            .resize(120, 40)
            .await
            .expect("resize");
        assert_eq!(
            session.process.wait().await.unwrap(),
            BoundaryExitStatus::Exited(7)
        );
        assert_eq!(
            session.process.wait().await.unwrap(),
            BoundaryExitStatus::Exited(7)
        );
    }
}
