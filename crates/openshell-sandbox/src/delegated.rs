// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process and access-plane assembly for the capability-free sandbox boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use openshell_core::policy::SandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{BoundaryExec, BoundaryPortForward};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, LaunchTypeId, Process as OcsfProcess,
    ProcessActivityBuilder, SeverityId, StatusId, ocsf_emit,
};

use crate::process::{ProcessHandle, ProcessStatus, ResolvedWorkspace};

fn ocsf_ctx() -> &'static openshell_ocsf::SandboxContext {
    openshell_ocsf::ctx::ctx()
}

/// Spawn the admitted workload without placing the gateway or policy authority
/// inside its boundary.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn spawn_workload(
    program: &str,
    args: &[String],
    workdir: Option<&str>,
    timeout_secs: u64,
    interactive: bool,
    _sandbox_id: Option<&str>,
    _openshell_endpoint: Option<&str>,
    _ssh_socket_path: Option<String>,
    _shared_ssh_socket: bool,
    policy: &SandboxPolicy,
    entrypoint_pid: Arc<AtomicU32>,
    entrypoint_started_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    provider_credentials: ProviderCredentialState,
    provider_env: std::collections::HashMap<String, String>,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    boundary_runtime: Option<Arc<crate::boundary_io::BoundaryRuntimeState>>,
) -> Result<SpawnedAgent> {
    // Driver-selected workspaces are the sandbox identity's home. This keeps
    // canonical and later exec processes consistent for image WorkingDir and
    // the managed /sandbox fallback without consulting privileged account
    // setup inside the capability-free boundary.
    let workspace = ResolvedWorkspace::new(workdir.map(str::to_string), true);

    #[cfg(target_os = "linux")]
    {
        let mode = if std::env::var_os("OPENSHELL_REQUIRE_RUNTIME_PID_LIMIT").is_some() {
            crate::process::RuntimePidLimitMode::Require
        } else {
            crate::process::RuntimePidLimitMode::Warn
        };
        crate::process::check_runtime_pid_limit(mode).wrap_err("check runtime PID limit")?;
    }

    let boundary_runtime = boundary_runtime
        .unwrap_or_else(crate::boundary_io::BoundaryRuntimeState::new_exclusive_pid_namespace);
    let mut user_environment: std::collections::HashMap<String, String> =
        std::env::var(openshell_core::sandbox_env::USER_ENVIRONMENT)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
    user_environment.retain(|key, _value| !crate::process::is_proxy_env_var(key));
    let port_forward: Arc<dyn BoundaryPortForward> = Arc::new(
        crate::boundary_io::LocalPortForward::new(Some(boundary_runtime.clone())),
    );
    let boundary_exec: Arc<dyn BoundaryExec> =
        Arc::new(crate::boundary_exec::LocalBoundaryExec::new(
            policy.clone(),
            workspace.owned_root(),
            ca_file_paths.clone().map(Arc::new),
            provider_credentials,
            user_environment,
            boundary_runtime.clone(),
        ));

    #[cfg(target_os = "linux")]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        &workspace,
        interactive,
        policy,
        ca_file_paths.as_ref(),
        &provider_env,
    )
    .wrap_err("spawn delegated workload process")?;
    #[cfg(not(target_os = "linux"))]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        &workspace,
        interactive,
        policy,
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    entrypoint_pid.store(handle.pid(), Ordering::Release);
    if let Some(sender) = entrypoint_started_tx {
        let _ = sender.send(handle.pid());
    }
    let main_session = crate::main_session::MainSession::new(handle.take_io(), handle.pid());
    let (terminal, signal_lock) = handle.signaling_state();
    boundary_runtime
        .register_process_group(handle.pid(), terminal.clone(), signal_lock.clone())
        .map_err(|error| miette::miette!(error.to_string()))?;

    ocsf_emit!(
        ProcessActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .launch_type(LaunchTypeId::Spawn)
            .process(OcsfProcess::new(program, i64::from(handle.pid())))
            .message(format!("Process started: pid={}", handle.pid()))
            .build()
    );

    Ok(SpawnedAgent {
        handle,
        timeout_secs,
        terminal,
        signal_lock,
        main_session,
        boundary_exec,
        port_forward,
        boundary_runtime,
    })
}

/// Owned workload process and its live boundary capabilities.
pub struct SpawnedAgent {
    handle: ProcessHandle,
    timeout_secs: u64,
    terminal: Arc<AtomicBool>,
    signal_lock: Arc<std::sync::Mutex<()>>,
    main_session: Arc<crate::main_session::MainSession>,
    boundary_exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryPortForward>,
    boundary_runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
}

impl SpawnedAgent {
    #[must_use]
    pub fn signaler(&self) -> AgentSignaler {
        AgentSignaler {
            pid: self.handle.pid(),
            terminal: self.terminal.clone(),
            signal_lock: self.signal_lock.clone(),
        }
    }

    #[must_use]
    pub fn boundary_exec(&self) -> Arc<dyn BoundaryExec> {
        self.boundary_exec.clone()
    }

    #[must_use]
    pub fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }

    /// Retained canonical-process I/O owned by the boundary.
    #[must_use]
    pub fn main_session(&self) -> Arc<crate::main_session::MainSession> {
        self.main_session.clone()
    }

    /// Wait for the canonical process to exit, enforcing its admitted
    /// wall-clock timeout. Completion does not end the boundary: exec and
    /// loopback forwarding remain available until the boundary owner tears
    /// down the retained runtime.
    pub async fn wait(&mut self) -> Result<ProcessStatus> {
        let signaler = self.signaler();
        let status = if self.timeout_secs == 0 {
            self.handle.wait().await.into_diagnostic()?
        } else if let Ok(status) =
            tokio::time::timeout(Duration::from_secs(self.timeout_secs), self.handle.wait()).await
        {
            status.into_diagnostic()?
        } else {
            let _ = signaler.term();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = signaler.kill();
            self.handle.wait().await.into_diagnostic()?
        };
        self.boundary_runtime
            .unregister_process_group(self.handle.pid(), &self.terminal);
        let _ = self.main_session.finish(status.code(), false).await;
        self.main_session.mark_terminal_reported();
        Ok(status)
    }
}

/// Lock-free process-group signal handle used while another task owns `wait`.
#[derive(Clone)]
pub struct AgentSignaler {
    pid: u32,
    terminal: Arc<AtomicBool>,
    signal_lock: Arc<std::sync::Mutex<()>>,
}

#[cfg(unix)]
impl AgentSignaler {
    fn deliver(&self, signal: nix::sys::signal::Signal) -> Result<()> {
        let _guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return Err(miette::miette!("agent has exited"));
        }
        let pid = i32::try_from(self.pid).unwrap_or(i32::MAX);
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal).into_diagnostic()
    }

    pub fn term(&self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGTERM)
    }

    pub fn kill(&self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGKILL)
    }

    pub fn interrupt(&self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGINT)
    }

    pub fn hangup(&self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGHUP)
    }
}
