// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload supervision entry point.
//!
//! Spawns the SSH server, optional supervisor session, the entrypoint child
//! process, and waits for it to exit (with optional timeout). Long-running
//! background tasks that aren't strictly tied to the workload's lifetime
//! (policy poll loop, denial aggregator, symlink resolver) live in the
//! orchestrator, not here.

use miette::{IntoDiagnostic, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, DispositionId, LaunchTypeId, Process as OcsfProcess,
    ProcessActivityBuilder, SeverityId, StatusId, ocsf_emit,
};

#[cfg(target_os = "linux")]
use crate::netns::NetworkNamespace;
use openshell_core::policy::{NetworkMode, SandboxPolicy};
use openshell_core::proposals::AgentProposals;
use openshell_core::provider_credentials::ProviderCredentialState;

#[cfg(target_os = "linux")]
use openshell_core::activity::ActivitySender;
#[cfg(target_os = "linux")]
use openshell_core::denial::DenialEvent;

#[cfg(target_os = "linux")]
use crate::managed_children;
use crate::process::{
    ProcessEnforcementMode, ProcessHandle, ProcessStatus, ResolvedProcessIdentity,
};

fn ocsf_ctx() -> &'static openshell_ocsf::SandboxContext {
    openshell_ocsf::ctx::ctx()
}

/// Spawn the workload entrypoint behind the boundary, wire up SSH and the
/// supervisor session, and return an owned [`SpawnedAgent`] handle.
///
/// The agent keeps running after this returns; the caller drives it through
/// [`SpawnedAgent::wait`]/[`SpawnedAgent::signal`]. This is the placement-
/// sensitive spawn the in-pod backend's `RunningBoundary` owns (RFC 0012):
/// the returned handle, not an exit code, is the process control surface.
///
/// # Errors
///
/// Returns an error if SSH server startup fails or if the entrypoint child
/// fails to spawn.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn spawn_workload(
    program: &str,
    args: &[String],
    workdir: Option<&str>,
    timeout_secs: u64,
    interactive: bool,
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    ssh_socket_path: Option<String>,
    shared_ssh_socket: bool,
    policy: &SandboxPolicy,
    resolved_process_identity: ResolvedProcessIdentity,
    enforcement_mode: ProcessEnforcementMode,
    entrypoint_pid: Arc<AtomicU32>,
    entrypoint_started_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    provider_credentials: ProviderCredentialState,
    provider_env: std::collections::HashMap<String, String>,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    agent_proposals: AgentProposals,
    #[cfg(target_os = "linux")] netns: Option<&NetworkNamespace>,
    #[cfg(target_os = "linux")] bypass_denial_tx: Option<
        tokio::sync::mpsc::UnboundedSender<DenialEvent>,
    >,
    #[cfg(target_os = "linux")] bypass_activity_tx: Option<ActivitySender>,
) -> Result<SpawnedAgent> {
    // Platform drivers with a resolved numeric UID/GID retain the legacy
    // account-file update. OCI-image identity leaves those environment values
    // empty, so the image's account files remain unchanged.
    #[cfg(unix)]
    if enforcement_mode.uses_privileged_process_setup() {
        crate::process::update_sandbox_passwd_entries()?;
    }

    // Validate the completed process identity before exposing a child.
    #[cfg(unix)]
    if enforcement_mode.uses_privileged_process_setup() {
        crate::process::validate_sandbox_user_with_identity(policy, resolved_process_identity)?;
        crate::process::validate_sandbox_group_with_identity(policy, resolved_process_identity)?;
    }

    // Create read_write directories and chown newly-created ones to the
    // sandbox user/group. Runs as the supervisor (root) before the child
    // is forked so the workload sees writable paths it owns.
    #[cfg(unix)]
    if enforcement_mode.uses_privileged_process_setup() {
        crate::process::prepare_filesystem_with_identity(policy, resolved_process_identity)?;
    }

    // Eagerly fetch initial settings and install the agent skill if the
    // proposals flag is on at startup, rather than waiting for the policy
    // poll loop's first tick. In offline/file-mode there is no gateway, so
    // the flag stays at its default (false) and no skill is installed.
    install_initial_agent_skill(sandbox_id, openshell_endpoint, &agent_proposals).await;

    // Install the supervisor seccomp prelude before spawning any workload-side
    // tasks. By this point the orchestrator has finished privileged startup
    // helpers (network namespace setup, nftables probes via run_networking),
    // and the SSH listener and entrypoint child have not been exposed yet.
    crate::sandbox::apply_supervisor_startup_hardening()?;

    // Spawn the bypass detection monitor. It tails dmesg for nftables LOG
    // entries fired by rules installed on the workload's network namespace
    // and reports direct connection attempts that would have bypassed the
    // proxy. Spawn it before the entrypoint child so the first packets are
    // not missed. Best-effort: returns None when dmesg is unavailable.
    #[cfg(target_os = "linux")]
    let bypass_handle = netns.and_then(|ns| {
        crate::bypass_monitor::spawn(
            ns.name().to_string(),
            entrypoint_pid.clone(),
            bypass_denial_tx,
            bypass_activity_tx,
        )
    });

    // Verify the runtime PID limit can accommodate the policy's pid_max.
    #[cfg(target_os = "linux")]
    {
        let pid_limit_mode = if std::env::var_os("OPENSHELL_REQUIRE_RUNTIME_PID_LIMIT").is_some() {
            crate::process::RuntimePidLimitMode::Require
        } else {
            crate::process::RuntimePidLimitMode::Warn
        };
        crate::process::check_runtime_pid_limit(pid_limit_mode)?;
    }

    // Zombie reaper — openshell-sandbox may run as PID 1 in containers and
    // must reap orphaned grandchildren (e.g. background daemons started by
    // coding agents) to prevent zombie accumulation.
    //
    // Use waitid(..., WNOWAIT) so we can inspect exited children before
    // actually reaping them. This avoids racing explicit `child.wait()` calls
    // for managed children (entrypoint and SSH session processes).
    #[cfg(target_os = "linux")]
    tokio::spawn(async {
        use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
        use tokio::signal::unix::{SignalKind, signal};
        use tokio::time::MissedTickBehavior;

        let mut sigchld = match signal(SignalKind::child()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to register SIGCHLD handler for zombie reaping");
                return;
            }
        };
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        retry.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = sigchld.recv() => {}
                _ = retry.tick() => {}
            }

            loop {
                let status = match waitid(
                    Id::All,
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                ) {
                    Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
                    Ok(status) => status,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        tracing::debug!(error = %e, "waitid error during zombie reaping");
                        break;
                    }
                };

                let Some(pid) = status.pid() else {
                    break;
                };

                if managed_children::is_managed(pid.as_raw()) {
                    // Let the explicit waiter own this child status.
                    break;
                }

                match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive)
                    | Err(nix::errno::Errno::ECHILD | nix::errno::Errno::EINTR) => {}
                    Ok(reaped) => {
                        tracing::debug!(?reaped, "Reaped orphaned child process");
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "waitpid error during orphan reap");
                        break;
                    }
                }
            }
        }
    });

    // Hard network policy enforcement for SSH sessions and the persistent
    // supervisor session: each session's pre-exec hook calls setns(fd,
    // CLONE_NEWNET) so it lands inside the workload's network namespace.
    // Without this, SSH-spawned shells run in the host namespace and bypass
    // the proxy entirely.
    #[cfg(target_os = "linux")]
    let ssh_netns_fd = netns.and_then(NetworkNamespace::ns_fd);
    #[cfg(not(target_os = "linux"))]
    let ssh_netns_fd: Option<i32> = None;

    // SSH-spawned shells get http_proxy=http://<host_ip>:<port> exported into
    // their env so cooperative tools (curl, npm, Node) route through the
    // CONNECT proxy. Linux uses the netns host_ip; on other targets fall back
    // to the policy-declared http_addr directly.
    #[cfg(target_os = "linux")]
    let ssh_proxy_url = ssh_proxy_url_for_policy(policy, netns.map(NetworkNamespace::host_ip));
    #[cfg(not(target_os = "linux"))]
    let ssh_proxy_url = ssh_proxy_url_for_policy(policy, None);

    let ssh_socket_path: Option<std::path::PathBuf> = ssh_socket_path.map(std::path::PathBuf::from);
    if let Some(listen_path) = ssh_socket_path.clone() {
        let policy_clone = policy.clone();
        let workdir_clone = workdir.map(str::to_string);
        let proxy_url = ssh_proxy_url;
        let netns_fd = ssh_netns_fd;
        let ca_paths = ca_file_paths.clone();
        let provider_credentials_clone = provider_credentials.clone();
        let user_env_clone: std::collections::HashMap<String, String> =
            std::env::var(openshell_core::sandbox_env::USER_ENVIRONMENT)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default();

        let (ssh_ready_tx, ssh_ready_rx) = tokio::sync::oneshot::channel();

        // Inject the in-pod loopback port-forward (RFC 0012). The SSH server
        // drives it through the `BoundaryPortForward` interface, so a delegated
        // backend would supply a different implementation without the SSH
        // server changing.
        let port_forward: Arc<dyn openshell_isolation::contract::BoundaryPortForward> =
            Arc::new(crate::boundary_io::NetnsPortForward { netns_fd });

        tokio::spawn(async move {
            if let Err(err) = crate::ssh::run_ssh_server(
                listen_path,
                ssh_ready_tx,
                policy_clone,
                workdir_clone,
                netns_fd,
                proxy_url,
                ca_paths,
                provider_credentials_clone,
                user_env_clone,
                resolved_process_identity,
                enforcement_mode,
                shared_ssh_socket,
                port_forward,
            )
            .await
            {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Critical)
                        .status(StatusId::Failure)
                        .message(format!("SSH server failed: {err}"))
                        .build()
                );
            }
        });

        // Wait for the SSH server to bind its socket before spawning the
        // entrypoint process. This prevents exec requests from racing against
        // SSH server startup when Kubernetes marks the pod Ready.
        match timeout(Duration::from_secs(10), ssh_ready_rx).await {
            Ok(Ok(Ok(()))) => {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Open)
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .message("SSH server is ready to accept connections")
                        .build()
                );
            }
            Ok(Ok(Err(err))) => {
                return Err(err.context("SSH server failed during startup"));
            }
            Ok(Err(_)) => {
                return Err(miette::miette!(
                    "SSH server task panicked before signaling ready"
                ));
            }
            Err(_) => {
                return Err(miette::miette!(
                    "SSH server did not start within 10 seconds"
                ));
            }
        }
    }

    let supervisor_terminating = Arc::new(AtomicBool::new(false));

    // Spawn the persistent supervisor session if we have a gateway endpoint
    // and sandbox identity. The session provides relay channels for SSH
    // connect and ExecSandbox through the gateway.
    if let (Some(endpoint), Some(id), Some(socket)) =
        (openshell_endpoint, sandbox_id, ssh_socket_path.as_ref())
    {
        crate::supervisor_session::spawn(
            endpoint.to_string(),
            id.to_string(),
            socket.clone(),
            Arc::new(crate::boundary_io::NetnsPortForward {
                netns_fd: ssh_netns_fd,
            }),
            None,
            Arc::clone(&supervisor_terminating),
        );
        info!("supervisor session task spawned");
    }

    #[cfg(target_os = "linux")]
    let handle = ProcessHandle::spawn(
        program,
        args,
        workdir,
        interactive,
        policy,
        resolved_process_identity,
        enforcement_mode,
        netns,
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    #[cfg(not(target_os = "linux"))]
    let handle = ProcessHandle::spawn(
        program,
        args,
        workdir,
        interactive,
        policy,
        resolved_process_identity,
        enforcement_mode,
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    // Store the entrypoint PID so the proxy can resolve TCP peer identity
    entrypoint_pid.store(handle.pid(), Ordering::Release);
    if let Some(tx) = entrypoint_started_tx {
        let _ = tx.send(handle.pid());
    }
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
        supervisor_terminating,
        #[cfg(target_os = "linux")]
        _bypass_handle: bypass_handle,
    })
}

/// An owned, running workload entrypoint plus the background guards whose
/// lifetime is tied to it (the bypass monitor).
///
/// The in-pod `RunningBoundary` owns this; dropping it kills the child via the
/// handle's `kill_on_drop`.
pub struct SpawnedAgent {
    handle: ProcessHandle,
    timeout_secs: u64,
    supervisor_terminating: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    _bypass_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SpawnedAgent {
    /// The host PID of the entrypoint, for diagnostics only.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.handle.pid()
    }

    /// A lock-free signaling handle derived from the entrypoint's pid.
    ///
    /// Separated from the waitable [`SpawnedAgent`] so a signal can be delivered
    /// while another task holds the agent to await it: the running boundary
    /// keeps the agent behind a mutex for `wait`, but signals go through this
    /// pid-based handle and never contend for that lock.
    #[must_use]
    pub fn signaler(&self) -> AgentSignaler {
        AgentSignaler {
            pid: self.handle.pid(),
        }
    }

    /// Wait for the entrypoint to exit, applying the policy timeout. Returns the
    /// exit code (128 + signal if signaled, 124 on timeout-kill).
    ///
    /// # Errors
    ///
    /// Returns an error if waiting on the child returns an OS error.
    pub async fn wait(&mut self) -> Result<i32> {
        let outcome = wait_for_process_exit_or_shutdown(
            &mut self.handle,
            self.timeout_secs,
            &self.supervisor_terminating,
        )
        .await?;

        let status = match outcome {
            ProcessWaitOutcome::Exited(status) => status,
            ProcessWaitOutcome::TimedOut => {
                ocsf_emit!(
                    ProcessActivityBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Close)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Critical)
                        .status(StatusId::Failure)
                        .message("Process timed out, killing")
                        .build()
                );
                return Ok(124); // Standard timeout exit code
            }
            ProcessWaitOutcome::ShutdownSignal { signal, status } => {
                info!(
                    signal,
                    exit_code = status.code(),
                    "Entrypoint exited after supervisor shutdown signal"
                );
                status
            }
        };

        ocsf_emit!(
            ProcessActivityBuilder::new(ocsf_ctx())
                .activity(ActivityId::Close)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .exit_code(status.code())
                .message(format!("Process exited with code {}", status.code()))
                .build()
        );

        Ok(status.code())
    }

    /// Send a signal to the entrypoint process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be delivered.
    #[cfg(unix)]
    pub fn signal(&self, sig: nix::sys::signal::Signal) -> Result<()> {
        self.handle.signal(sig)
    }

    /// Terminate the entrypoint (SIGTERM, then SIGKILL).
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be killed.
    pub fn kill(&mut self) -> Result<()> {
        self.handle.kill()
    }
}

/// A lock-free, pid-based signaling handle to a spawned agent.
///
/// Delivers signals to the entrypoint process without holding the waitable
/// handle's lock, so a signal and an in-flight `wait` never deadlock.
/// Placement-neutral signal mapping (e.g. RFC 0012's `BoundarySignal`) is the
/// caller's job; this handle exposes only the concrete deliveries so `nix`
/// stays in this crate.
#[derive(Clone, Copy)]
pub struct AgentSignaler {
    pid: u32,
}

#[cfg(unix)]
impl AgentSignaler {
    fn deliver(self, sig: nix::sys::signal::Signal) -> Result<()> {
        use nix::unistd::Pid;
        let pid = i32::try_from(self.pid).unwrap_or(i32::MAX);
        nix::sys::signal::kill(Pid::from_raw(pid), sig).into_diagnostic()
    }

    /// Send `SIGTERM`.
    ///
    /// # Errors
    /// Returns an error if the signal cannot be delivered.
    pub fn term(self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGTERM)
    }

    /// Send `SIGKILL`.
    ///
    /// # Errors
    /// Returns an error if the signal cannot be delivered.
    pub fn kill(self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGKILL)
    }

    /// Send `SIGINT`.
    ///
    /// # Errors
    /// Returns an error if the signal cannot be delivered.
    pub fn interrupt(self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGINT)
    }

    /// Send `SIGHUP`.
    ///
    /// # Errors
    /// Returns an error if the signal cannot be delivered.
    pub fn hangup(self) -> Result<()> {
        self.deliver(nix::sys::signal::Signal::SIGHUP)
    }
}

enum ProcessWaitOutcome {
    Exited(ProcessStatus),
    TimedOut,
    ShutdownSignal {
        signal: &'static str,
        status: ProcessStatus,
    },
}

async fn wait_for_process_exit_or_shutdown(
    handle: &mut ProcessHandle,
    timeout_secs: u64,
    terminating: &AtomicBool,
) -> Result<ProcessWaitOutcome> {
    let pid = handle.pid();
    let wait = handle.wait();
    tokio::pin!(wait);

    if timeout_secs > 0 {
        let deadline = tokio::time::sleep(Duration::from_secs(timeout_secs));
        tokio::pin!(deadline);
        tokio::select! {
            result = &mut wait => {
                terminating.store(true, Ordering::Release);
                Ok(ProcessWaitOutcome::Exited(result.into_diagnostic()?))
            }
            () = &mut deadline => {
                terminating.store(true, Ordering::Release);
                terminate_then_kill_pid(pid).await;
                Ok(ProcessWaitOutcome::TimedOut)
            }
            signal = wait_for_supervisor_shutdown_signal() => {
                terminating.store(true, Ordering::Release);
                signal_entrypoint_for_shutdown(pid, signal);
                let status = (&mut wait).await.into_diagnostic()?;
                Ok(ProcessWaitOutcome::ShutdownSignal { signal, status })
            }
        }
    } else {
        tokio::select! {
            result = &mut wait => {
                terminating.store(true, Ordering::Release);
                Ok(ProcessWaitOutcome::Exited(result.into_diagnostic()?))
            }
            signal = wait_for_supervisor_shutdown_signal() => {
                terminating.store(true, Ordering::Release);
                signal_entrypoint_for_shutdown(pid, signal);
                let status = (&mut wait).await.into_diagnostic()?;
                Ok(ProcessWaitOutcome::ShutdownSignal { signal, status })
            }
        }
    }
}

#[cfg(unix)]
async fn terminate_then_kill_pid(pid: u32) {
    signal_pid(pid, nix::sys::signal::Signal::SIGTERM, "process timeout");
    tokio::time::sleep(Duration::from_millis(100)).await;
    signal_pid(pid, nix::sys::signal::Signal::SIGKILL, "process timeout");
}

#[cfg(not(unix))]
async fn terminate_then_kill_pid(_pid: u32) {}

#[cfg(unix)]
fn signal_entrypoint_for_shutdown(pid: u32, signal: &'static str) {
    signal_pid(pid, nix::sys::signal::Signal::SIGTERM, signal);
}

#[cfg(not(unix))]
fn signal_entrypoint_for_shutdown(_pid: u32, _signal: &'static str) {}

#[cfg(unix)]
fn signal_pid(pid: u32, signal: nix::sys::signal::Signal, reason: &'static str) {
    let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
    if let Err(error) = nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), signal) {
        tracing::warn!(
            pid,
            signal = ?signal,
            reason,
            error = %error,
            "failed to signal entrypoint process"
        );
    }
}

#[cfg(unix)]
async fn wait_for_supervisor_shutdown_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Failed to install SIGTERM handler; supervisor shutdown detection disabled"
            );
            return std::future::pending::<&'static str>().await;
        }
    };

    let _ = sigterm.recv().await;
    info!("Received SIGTERM, shutting down supervisor process");
    "SIGTERM"
}

#[cfg(not(unix))]
async fn wait_for_supervisor_shutdown_signal() -> &'static str {
    std::future::pending::<&'static str>().await
}

fn ssh_proxy_url_for_policy(
    policy: &SandboxPolicy,
    netns_proxy_host: Option<std::net::IpAddr>,
) -> Option<String> {
    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return None;
    }

    let proxy = policy.network.proxy.as_ref()?;
    if let Some(host) = netns_proxy_host {
        let port = proxy.http_addr.map_or(3128, |addr| addr.port());
        return Some(format!("http://{host}:{port}"));
    }

    proxy.http_addr.map(|addr| format!("http://{addr}"))
}

/// Eagerly fetch initial settings and install the agent-driven policy
/// proposal skill if the flag is on at startup.
///
/// Without this, the skill would only get installed on the policy poll
/// loop's first false→true transition, which can be ~10 s after launch —
/// long enough for an agent to start running without seeing it.
///
/// Best-effort: any failure (no gateway, RPC error, install failure) is
/// logged but does not fail sandbox startup.
async fn install_initial_agent_skill(
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    agent_proposals: &AgentProposals,
) {
    use openshell_core::proto::setting_value;

    if let (Some(id), Some(endpoint)) = (sandbox_id, openshell_endpoint)
        && let Ok(client) =
            openshell_core::grpc_client::CachedOpenShellClient::connect(endpoint).await
        && let Ok(result) = client.poll_settings(id).await
    {
        let initial = result
            .settings
            .get(openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY)
            .and_then(|es| es.value.as_ref())
            .and_then(|sv| sv.value.as_ref())
            .and_then(|v| match v {
                setting_value::Value::BoolValue(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);
        agent_proposals.set_enabled(initial);
    }

    if agent_proposals.enabled() {
        match crate::skills::install_static_skills() {
            Ok(installed) => info!(
                path = %installed.policy_advisor.display(),
                "Installed sandbox agent skill"
            ),
            Err(error) => tracing::warn!(
                error = %error,
                "Failed to install sandbox agent skill"
            ),
        }
    } else {
        tracing::debug!(
            "agent_policy_proposals_enabled is false at startup; skipping skill install"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkMode, NetworkPolicy, ProcessPolicy, ProxyPolicy,
    };

    fn policy(mode: NetworkMode, http_addr: Option<std::net::SocketAddr>) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy {
                mode,
                proxy: http_addr.map(|http_addr| ProxyPolicy {
                    http_addr: Some(http_addr),
                }),
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }

    #[test]
    fn ssh_proxy_url_uses_policy_addr_without_netns() {
        let policy = policy(NetworkMode::Proxy, Some(([127, 0, 0, 1], 3128).into()));

        assert_eq!(
            ssh_proxy_url_for_policy(&policy, None).as_deref(),
            Some("http://127.0.0.1:3128")
        );
    }

    #[test]
    fn ssh_proxy_url_prefers_netns_host_with_policy_port() {
        let policy = policy(NetworkMode::Proxy, Some(([127, 0, 0, 1], 8080).into()));

        assert_eq!(
            ssh_proxy_url_for_policy(&policy, Some([10, 200, 0, 1].into())).as_deref(),
            Some("http://10.200.0.1:8080")
        );
    }

    #[test]
    fn ssh_proxy_url_skips_non_proxy_mode() {
        let policy = policy(NetworkMode::Allow, Some(([127, 0, 0, 1], 3128).into()));

        assert_eq!(ssh_proxy_url_for_policy(&policy, None), None);
    }
}
