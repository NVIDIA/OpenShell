// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod isolation backend (RFC 0012 runtime-selectable contract).
//!
//! This is the co-located placement: the supervisor process hosts the
//! supervisor role, the mediation service, and the backend in the agent's
//! container. It implements the object-safe boxed state chain
//! (`attach -> Bound -> confirm -> Ready -> start_agent -> Running`) over the
//! existing supervisor primitives without changing their behavior:
//! `create_netns_for_proxy` (network), supervisor-owned proxy mediation,
//! the pre-exec ceiling in `spawn_workload` (filesystem/Landlock +
//! syscall/seccomp), and procfs (binary identity).
//!
//! `attach` validates the (empty) in-pod payload and atomically binds the
//! trusted [`SandboxContext`] to the boundary it establishes: the workload
//! network namespace and backend-owned connection source come up inside
//! `attach`. The supervisor connects that source to mediation before `confirm`, so
//! `Bound` means what the RFC says it means — descriptor and context bound to
//! the same resource, mediation source available, no untrusted workload code
//! running. Each transition consumes the prior state by value, so the call
//! order, and thus "no untrusted instruction before the boundary is ready", is
//! enforced by construction.
//!
//! Execution-domain note: the in-pod backend relies on container-runtime
//! inheritance — the supervisor and every child it spawns run in the pod's
//! cgroup with the device set the CRI granted the container — so every workload
//! descendant remains in the compute driver's provisioned execution
//! environment by construction.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use async_trait::async_trait;

use openshell_core::activity::ActivitySender;
use openshell_core::denial::DenialEvent;
use openshell_core::policy::NetworkMode;
use openshell_core::proposals::AgentProposals;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation::contract::{
    BackendError, BoundBoundary, BoundaryExec, BoundaryExitStatus, BoundaryPortForward,
    BoundaryProcess, BoundarySignal, INTERFACE_VERSION, IsolationBackend, MediatedConnection,
    NetworkMediationSource, ReadyBoundary, RunningBoundary, SandboxContext,
    VerifiedTopologyDescriptor,
};
use openshell_supervisor_network::identity_source::ProcfsIdentityResolver;
use openshell_supervisor_process::process::ProcessEnforcementMode;
use openshell_supervisor_process::process::ResolvedProcessIdentity;
use openshell_supervisor_process::run::{AgentSignaler, SpawnedAgent, spawn_workload};
use tokio::sync::mpsc::UnboundedSender;

#[cfg(target_os = "linux")]
use openshell_supervisor_process::netns::{NetworkNamespace, create_conformant_netns_for_proxy};

/// Stable name of the co-located backend implementation.
pub const IN_POD_BACKEND_NAME: &str = "in-pod";

// ============================================================================
// Config and backend
// ============================================================================

/// Runtime collaborators the in-pod lifecycle calls need, captured once when the
/// backend is built. Move-once values (the event senders) are held behind a
/// `Mutex<Option<_>>` so the `&self` backend/state methods can take them exactly
/// when the matching transition fires. Policy, workload, and sandbox identity
/// are *not* here; they arrive in the trusted [`SandboxContext`] at `attach`.
pub struct InPodConfig {
    /// Require the supervisor to own the execution environment's PID namespace.
    pub require_exclusive_pid_namespace: bool,
    pub network_enabled: bool,
    pub process_enabled: bool,
    pub entrypoint_pid: Arc<AtomicU32>,
    pub provider_credentials: ProviderCredentialState,
    /// Child environment for the agent, resolved at startup. Mutated in place by
    /// `attach` if the GCE metadata loopback server fails to come up.
    pub provider_env: Mutex<HashMap<String, String>>,
    /// Process launch-time enforcement level (full privileged setup vs.
    /// network-sidecar reduced mode), resolved by the supervisor at startup.
    pub process_enforcement_mode: ProcessEnforcementMode,
    pub resolved_process_identity: ResolvedProcessIdentity,
    pub agent_proposals: AgentProposals,
    pub openshell_endpoint: Option<String>,
    pub ssh_socket_path: Option<String>,
    /// Bypass-monitor denial / activity senders (consumed by `start_agent`).
    #[cfg(target_os = "linux")]
    pub bypass_denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    #[cfg(target_os = "linux")]
    pub bypass_activity_tx: Mutex<Option<ActivitySender>>,
    /// Co-located coordination set by supervisor-owned mediation after it has
    /// connected the source and before `confirm`.
    pub mediation_ready: Arc<AtomicBool>,
    pub ca_file_paths: Arc<Mutex<Option<(std::path::PathBuf, std::path::PathBuf)>>>,
    pub proxy_bind_ip: Arc<Mutex<Option<std::net::IpAddr>>>,
}

/// The backend for the in-pod backend. Holds the per-sandbox [`InPodConfig`] and
/// hands it to the boundary on the single `attach`.
pub struct InPodBackend {
    config: Mutex<Option<InPodConfig>>,
    /// Whether a prior `attach` consumed the config and then failed during
    /// establishment. The one-shot event senders are consumed with it, so the
    /// in-pod resource cannot be re-attached; this keeps the error truthful
    /// ("attempt failed", not "already bound").
    attach_failed: AtomicBool,
}

impl InPodBackend {
    /// Build the backend from its per-sandbox runtime collaborators.
    #[must_use]
    pub fn new(config: InPodConfig) -> Self {
        Self {
            config: Mutex::new(Some(config)),
            attach_failed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl IsolationBackend for InPodBackend {
    fn backend_name(&self) -> &'static str {
        IN_POD_BACKEND_NAME
    }

    fn version(&self) -> u32 {
        INTERFACE_VERSION
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        // Validate the in-pod payload: the supervisor process *is* the
        // resource, so the payload carries nothing.
        if !descriptor.payload().is_empty() {
            return Err(BackendError::Descriptor(
                "in-pod descriptor payload must be empty".to_string(),
            ));
        }
        // `attach` never binds a resource that is already bound to an active
        // boundary: the in-pod resource is this process, bindable exactly once.
        let config = self
            .config
            .lock()
            .expect("in-pod config lock")
            .take()
            .ok_or_else(|| {
                if self.attach_failed.load(Ordering::SeqCst) {
                    BackendError::Attach(
                        "a previous in-pod attach failed during establishment; \
                         the in-pod resource cannot be re-attached"
                            .to_string(),
                    )
                } else {
                    BackendError::Denied(
                        "in-pod resource is already bound to an active boundary".to_string(),
                    )
                }
            })?;

        match establish(config, sandbox).await {
            Ok(bound) => Ok(Box::new(bound)),
            Err(e) => {
                self.attach_failed.store(true, Ordering::SeqCst);
                Err(e)
            }
        }
    }
}

/// Establish the in-pod boundary: standing enforcement (the workload network
/// namespace) and the mediation service (the in-pod proxy), bound atomically to
/// the trusted sandbox context. Consumes the one-shot config; failure fails
/// closed with partial state released by RAII.
async fn establish(
    config: InPodConfig,
    sandbox: SandboxContext,
) -> Result<InPodBound, BackendError> {
    #[cfg(not(target_os = "linux"))]
    return Err(BackendError::Attach(
        "the in-pod RFC 0012 backend requires Linux enforcement primitives".to_string(),
    ));

    if matches!(sandbox.policy.network.mode, NetworkMode::Allow) {
        return Err(BackendError::Denied(
            "the in-pod RFC 0012 topology does not admit unrestricted network mode; workload egress must be mediated or blocked"
                .to_string(),
        ));
    }

    // Establish the network dimension of standing enforcement: create the
    // workload's network namespace and install the bypass-detection rules.
    // Filesystem and syscall are launch-time controls applied per process;
    // binary identity is resolved per accepted connection.
    #[cfg(target_os = "linux")]
    let netns = if config.network_enabled {
        create_conformant_netns_for_proxy(&sandbox.policy)
            .map_err(|e| BackendError::Attach(e.to_string()))?
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let proxy_bind_ip = netns.as_ref().map(NetworkNamespace::host_ip);
    #[cfg(not(target_os = "linux"))]
    let proxy_bind_ip: Option<std::net::IpAddr> = None;
    *config.proxy_bind_ip.lock().expect("proxy bind IP lock") = proxy_bind_ip;

    if config.require_exclusive_pid_namespace && std::process::id() != 1 {
        return Err(BackendError::Attach(
            "the in-pod topology requires the supervisor to be PID 1 in its execution environment"
                .to_string(),
        ));
    }
    let runtime = if config.require_exclusive_pid_namespace {
        openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new_exclusive_pid_namespace(
        )
    } else {
        openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new()
    };
    let network_mediation_source: Arc<dyn NetworkMediationSource> = if config.network_enabled
        && matches!(sandbox.policy.network.mode, NetworkMode::Proxy)
    {
        let proxy_policy = sandbox.policy.network.proxy.as_ref().ok_or_else(|| {
            BackendError::Attach("proxy mode requires a proxy configuration".to_string())
        })?;
        let default_ip = proxy_bind_ip.unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));
        let port = proxy_policy.http_addr.map_or(3128, |addr| addr.port());
        let listener = tokio::net::TcpListener::bind((default_ip, port))
            .await
            .map_err(|error| BackendError::Attach(error.to_string()))?;
        Arc::new(InPodNetworkMediationSource {
            listener,
            identity: ProcfsIdentityResolver {
                entrypoint_pid: config.entrypoint_pid.clone(),
            },
            runtime: runtime.clone(),
        })
    } else {
        Arc::new(InactiveNetworkMediationSource {
            runtime: runtime.clone(),
        })
    };

    // Start the GCE metadata loopback server inside the namespace so Go's
    // metadata client (which bypasses HTTP_PROXY) can reach it via direct
    // TCP. Must come up before start_agent; on failure the GCE env vars are
    // stripped so the SDK falls back cleanly.
    #[cfg(target_os = "linux")]
    if let Some(ns) = netns.as_ref() {
        ensure_gce_metadata_server(&config, ns).await;
    }

    Ok(InPodBound {
        config,
        sandbox,
        #[cfg(target_os = "linux")]
        netns,
        network_mediation_source,
        runtime,
    })
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Bound: the descriptor and trusted sandbox context are bound to this process's
/// boundary, and the mediation source is available. No untrusted workload code
/// is running.
struct InPodBound {
    config: InPodConfig,
    sandbox: SandboxContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
    network_mediation_source: Arc<dyn NetworkMediationSource>,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
}

#[async_trait]
impl BoundBoundary for InPodBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.network_mediation_source.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        if !self.config.process_enabled {
            return Err(BackendError::Confirm(
                "the co-located backend requires the process supervisor leaf".to_string(),
            ));
        }
        // Structural-mediation check (fail closed). The proxy listener must be
        // connected and the live default-deny ceiling must still be present
        // before the backend advances its lifecycle.
        if self.config.network_enabled
            && matches!(self.sandbox.policy.network.mode, NetworkMode::Proxy)
        {
            #[cfg(target_os = "linux")]
            if self.netns.is_none() {
                return Err(BackendError::Confirm(
                    "proxy mode requires a workload network namespace; none established"
                        .to_string(),
                ));
            }
            #[cfg(target_os = "linux")]
            if let Some(netns) = self.netns.as_ref() {
                let proxy_port = self
                    .sandbox
                    .policy
                    .network
                    .proxy
                    .as_ref()
                    .and_then(|proxy| proxy.http_addr)
                    .map_or(3128, |address| address.port());
                netns
                    .egress_ceiling_verifier()
                    .verify_bounded(proxy_port, std::time::Duration::from_secs(2))
                    .await
                    .map_err(|error| BackendError::Confirm(error.to_string()))?;
            }
            if !self.config.mediation_ready.load(Ordering::Acquire) {
                return Err(BackendError::Confirm(
                    "the supervisor has not connected network mediation to the boundary source"
                        .to_string(),
                ));
            }
        }

        Ok(Box::new(InPodReady {
            config: self.config,
            sandbox: self.sandbox,
            #[cfg(target_os = "linux")]
            netns: self.netns,
            runtime: self.runtime,
        }))
    }
}

/// Ready: standing enforcement and mediation are confirmed. Only agent
/// activation is possible.
struct InPodReady {
    config: InPodConfig,
    sandbox: SandboxContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
}

#[async_trait]
impl ReadyBoundary for InPodReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let this = *self;
        let config = this.config;
        let sandbox = this.sandbox;
        let runtime = this.runtime;
        #[cfg(target_os = "linux")]
        let netns = this.netns;

        #[cfg(target_os = "linux")]
        let enforcement_monitor = if let Some(netns) = netns.as_ref()
            && matches!(sandbox.policy.network.mode, NetworkMode::Proxy)
        {
            let proxy_port = sandbox
                .policy
                .network
                .proxy
                .as_ref()
                .and_then(|proxy| proxy.http_addr)
                .map_or(3128, |address| address.port());
            Some(
                start_egress_ceiling_monitor(
                    netns.egress_ceiling_verifier(),
                    proxy_port,
                    runtime.clone(),
                    config.require_exclusive_pid_namespace,
                )
                .await?,
            )
        } else {
            None
        };

        // The in-pod backend creates the agent process itself; the launch-time
        // controls (Landlock, seccomp, privilege drop) are applied inside
        // `spawn_workload`'s pre-exec ceiling, before the first untrusted
        // instruction.
        let (agent, exec, port_forward): (
            Arc<dyn BoundaryProcess>,
            Arc<dyn BoundaryExec>,
            Arc<dyn BoundaryPortForward>,
        ) = {
            let spec = &sandbox.agent;
            let ca_file_paths = config.ca_file_paths.lock().expect("ca paths lock").clone();
            let provider_env = config
                .provider_env
                .lock()
                .expect("provider_env lock")
                .clone();

            #[cfg(target_os = "linux")]
            let bypass_denial_tx = config
                .bypass_denial_tx
                .lock()
                .expect("bypass_denial_tx lock")
                .take();
            #[cfg(target_os = "linux")]
            let bypass_activity_tx = config
                .bypass_activity_tx
                .lock()
                .expect("bypass_activity_tx lock")
                .take();

            let spawned = spawn_workload(
                &spec.program,
                &spec.args,
                spec.workdir.as_deref(),
                spec.timeout_secs,
                spec.interactive,
                Some(sandbox.sandbox_id.as_str()),
                config.openshell_endpoint.as_deref(),
                config.ssh_socket_path.clone(),
                // In-pod co-locates the SSH socket with the workload; it is not
                // shared with a separate network-sidecar container.
                false,
                &sandbox.policy,
                config.resolved_process_identity,
                config.process_enforcement_mode,
                config.entrypoint_pid.clone(),
                // No sidecar control channel awaits the in-pod entrypoint PID.
                None,
                config.provider_credentials.clone(),
                provider_env,
                ca_file_paths,
                config.agent_proposals.clone(),
                #[cfg(target_os = "linux")]
                netns.as_ref(),
                #[cfg(target_os = "linux")]
                bypass_denial_tx,
                #[cfg(target_os = "linux")]
                bypass_activity_tx,
                Some(runtime.clone()),
            )
            .await
            .map_err(|error| {
                runtime.deactivate();
                BackendError::Process(error.to_string())
            })?;

            let exec = spawned.boundary_exec();
            let port_forward = spawned.port_forward();
            (
                Arc::new(InPodAgentProcess::running(spawned)),
                exec,
                port_forward,
            )
        };

        Ok(Box::new(InPodRunning {
            agent,
            exec,
            port_forward,
            runtime,
            #[cfg(target_os = "linux")]
            _enforcement_monitor: enforcement_monitor,
            #[cfg(target_os = "linux")]
            _netns: netns,
        }))
    }
}

/// Running: the agent is runnable behind the boundary. Exec, forwarding, wait,
/// and signal are available. The mediation source was retained by the
/// supervisor from the `Bound` state.
struct InPodRunning {
    agent: Arc<dyn BoundaryProcess>,
    exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryPortForward>,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
    #[cfg(target_os = "linux")]
    _enforcement_monitor: Option<EnforcementMonitorGuard>,
    /// Held to keep the network namespace alive for the boundary's life;
    /// dropping the running state tears it down (RAII), which is the
    /// backend reclaiming backend-private state — the contract defines no public
    /// cleanup transition.
    #[cfg(target_os = "linux")]
    _netns: Option<NetworkNamespace>,
}

#[cfg(target_os = "linux")]
async fn start_egress_ceiling_monitor(
    verifier: openshell_supervisor_process::netns::EgressCeilingVerifier,
    proxy_port: u16,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
    exit_execution_environment_on_loss: bool,
) -> Result<EnforcementMonitorGuard, BackendError> {
    let verify: EnforcementCheck = Arc::new(move || {
        let verifier = verifier.clone();
        Box::pin(async move {
            verifier
                .verify_bounded(proxy_port, std::time::Duration::from_secs(2))
                .await
                .map_err(|error| error.to_string())
        })
    });
    start_enforcement_monitor(
        runtime,
        std::time::Duration::from_millis(250),
        verify,
        exit_execution_environment_on_loss,
    )
    .await
}

#[cfg(target_os = "linux")]
type EnforcementCheck = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>
        + Send
        + Sync,
>;

#[cfg(target_os = "linux")]
async fn start_enforcement_monitor(
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
    period: std::time::Duration,
    verify: EnforcementCheck,
    exit_execution_environment_on_loss: bool,
) -> Result<EnforcementMonitorGuard, BackendError> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        if let Err(error) = verify().await {
            let _ = ready_tx.send(Err(error.clone()));
            if runtime.deactivate_for_enforcement_loss() {
                report_enforcement_loss(&error);
                exit_execution_environment(exit_execution_environment_on_loss);
            }
            return;
        }
        if ready_tx.send(Ok(())).is_err() {
            runtime.deactivate();
            return;
        }
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        while runtime.is_active() {
            interval.tick().await;
            if let Err(error) = verify().await {
                if runtime.deactivate_for_enforcement_loss() {
                    report_enforcement_loss(&error);
                    exit_execution_environment(exit_execution_environment_on_loss);
                }
                break;
            }
        }
    });
    ready_rx
        .await
        .map_err(|_| BackendError::Confirm("egress monitor failed to start".to_string()))?
        .map_err(BackendError::Confirm)?;
    Ok(EnforcementMonitorGuard { task })
}

#[cfg(target_os = "linux")]
fn exit_execution_environment(enabled: bool) {
    if enabled {
        // This backend admits only an exclusive workload PID namespace with
        // the supervisor as PID 1. Exiting its init process makes the kernel
        // terminate every remaining process in that execution environment,
        // including descendants that changed process group or session.
        std::process::exit(125);
    }
}

#[cfg(target_os = "linux")]
struct EnforcementMonitorGuard {
    task: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Drop for EnforcementMonitorGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(target_os = "linux")]
fn report_enforcement_loss(error: &str) {
    let message = format!(
        "Isolation boundary lost its default-deny egress ceiling; terminating workloads [error:{error}]"
    );
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::High)
            .status(openshell_ocsf::StatusId::Failure)
            .state(openshell_ocsf::StateId::Disabled, "enforcement_lost")
            .message(message.clone())
            .build()
    );
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::DetectionFindingBuilder::new(crate::ocsf_ctx())
            .activity(openshell_ocsf::ActivityId::Open)
            .action(openshell_ocsf::ActionId::Denied)
            .disposition(openshell_ocsf::DispositionId::Blocked)
            .severity(openshell_ocsf::SeverityId::High)
            .is_alert(true)
            .finding_info(openshell_ocsf::FindingInfo::new(
                "isolation-egress-enforcement-lost",
                "Isolation egress enforcement lost",
            ))
            .message(message)
            .build()
    );
}

impl Drop for InPodRunning {
    fn drop(&mut self) {
        self.runtime.deactivate();
    }
}

impl RunningBoundary for InPodRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.agent.clone()
    }
    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
}

// ============================================================================
// Agent process handle
// ============================================================================

/// The agent process running inside the in-pod boundary. `wait` returns a stable
/// terminal status across repeated calls; signals go through the lock-free
/// pid-based [`AgentSignaler`] so they never contend with an in-flight `wait`.
struct InPodAgentProcess {
    signaler: Option<AgentSignaler>,
    result: Arc<Mutex<Option<Result<BoundaryExitStatus, StableWaitError>>>>,
    exited: Arc<tokio::sync::Notify>,
    terminal: Arc<AtomicBool>,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
}

#[derive(Clone)]
enum StableWaitError {
    Process(String),
    EnforcementLost,
}

impl InPodAgentProcess {
    fn running(spawned: SpawnedAgent) -> Self {
        let signaler = spawned.signaler();
        let runtime = spawned.boundary_runtime();
        let result = Arc::new(Mutex::new(None));
        let exited = Arc::new(tokio::sync::Notify::new());
        let result_for_wait = result.clone();
        let exited_for_wait = exited.clone();
        let terminal = Arc::new(AtomicBool::new(false));
        let terminal_for_wait = terminal.clone();
        let runtime_for_wait = runtime.clone();
        tokio::spawn(async move {
            let mut spawned = spawned;
            let waited = spawned
                .wait()
                .await
                .map_err(|error| StableWaitError::Process(error.to_string()))
                .map(|process_status| {
                    process_status.signal().map_or_else(
                        || BoundaryExitStatus::Exited(process_status.code()),
                        BoundaryExitStatus::Signaled,
                    )
                });
            let waited = if runtime_for_wait.enforcement_was_lost() {
                Err(StableWaitError::EnforcementLost)
            } else {
                waited
            };
            terminal_for_wait.store(true, Ordering::Release);
            if let Ok(mut slot) = result_for_wait.lock() {
                *slot = Some(waited);
            }
            exited_for_wait.notify_waiters();
        });
        Self {
            signaler: Some(signaler),
            result,
            exited,
            terminal,
            runtime,
        }
    }
}

#[async_trait]
impl BoundaryProcess for InPodAgentProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        loop {
            let notified = self.exited.notified();
            let result = self
                .result
                .lock()
                .map_err(|_| BackendError::Process("agent result lock poisoned".to_string()))?
                .clone();
            if let Some(result) = result {
                self.terminal.store(true, Ordering::Release);
                return result.map_err(|error| match error {
                    StableWaitError::Process(message) => BackendError::Process(message),
                    StableWaitError::EnforcementLost => BackendError::Terminated(
                        "required isolation enforcement was lost".to_string(),
                    ),
                });
            }
            notified.await;
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.runtime.ensure_active()?;
        if self.terminal.load(Ordering::Acquire) {
            return Err(BackendError::Terminated("agent has exited".to_string()));
        }
        let Some(signaler) = self.signaler.as_ref() else {
            // Network-only hold-open: no workload process to signal.
            return Ok(());
        };
        let result = match signal {
            BoundarySignal::Term => signaler.term(),
            BoundarySignal::Kill => signaler.kill(),
            BoundarySignal::Int => signaler.interrupt(),
            BoundarySignal::Hup => signaler.hangup(),
        };
        result.map_err(|e| BackendError::Process(e.to_string()))
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.runtime.ensure_active()?;
        if self.terminal.load(Ordering::Acquire) {
            return Err(BackendError::Terminated("agent has exited".to_string()));
        }
        let Some(signaler) = self.signaler.as_ref() else {
            return Ok(());
        };
        signaler
            .kill()
            .map_err(|e| BackendError::Process(e.to_string()))
    }
}

// ============================================================================
/// In-pod mediation source: owns the listener and resolves trusted procfs
/// identity for each accepted TCP connection before handing it to mediation.
/// A stronger backend may use another resolution mechanism without changing
/// the mediation contract.
struct InPodNetworkMediationSource {
    listener: tokio::net::TcpListener,
    identity: ProcfsIdentityResolver,
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
}

#[async_trait]
impl NetworkMediationSource for InPodNetworkMediationSource {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        self.runtime.ensure_active()?;
        let (stream, workload_addr) = self
            .listener
            .accept()
            .await
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        self.runtime.ensure_active()?;
        let proxy_addr = stream
            .local_addr()
            .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        let resolver = self.identity.clone();
        let binary_identity = tokio::task::spawn_blocking(move || {
            resolver.resolve_connection(workload_addr, proxy_addr)
        })
        .await
        .map_err(|error| BackendError::Unavailable(error.to_string()))?;
        self.runtime.ensure_active()?;
        Ok(MediatedConnection {
            stream: Box::new(stream),
            binary_identity,
        })
    }
}

/// A topology with no proxy listener has no mediated connections. Calling
/// `accept` is an orchestration error, so fail closed rather than fabricating a
/// connection.
struct InactiveNetworkMediationSource {
    runtime: Arc<openshell_supervisor_process::boundary_io::BoundaryRuntimeState>,
}

#[async_trait]
impl NetworkMediationSource for InactiveNetworkMediationSource {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        self.runtime.ensure_active()?;
        Err(BackendError::Unavailable(
            "network mediation is inactive for this admitted network mode".to_string(),
        ))
    }
}

// ============================================================================
// GCE metadata loopback server
// ============================================================================

/// Bring up the GCE metadata loopback server inside the network namespace,
/// stripping the GCE env vars from the agent's environment if it fails so the
/// Go SDK falls back cleanly.
#[cfg(target_os = "linux")]
async fn ensure_gce_metadata_server(config: &InPodConfig, ns: &NetworkNamespace) {
    use std::time::Duration;
    use tokio::time::timeout;
    use tracing::{info, warn};

    if !config
        .provider_credentials
        .snapshot()
        .child_env
        .contains_key("GCE_METADATA_HOST")
    {
        return;
    }

    let ctx =
        crate::google_cloud_metadata::MetadataContext::new(config.provider_credentials.clone());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    match ns
        .bind_tcp_in_netns(openshell_core::google_cloud::METADATA_LOOPBACK_ADDR)
        .await
    {
        Ok(listener) => {
            tokio::spawn(crate::metadata_server::run(listener, ctx, ready_tx));
            if let Ok(Ok(addr)) = timeout(Duration::from_secs(5), ready_rx).await {
                info!(addr = %addr, "GCE metadata loopback server ready");
            } else {
                warn!("GCE metadata server failed to become ready, removing metadata env vars");
                strip_gce_env(config);
            }
        }
        Err(e) => {
            warn!(error = %e, "GCE metadata server bind failed, Go SDK may not discover credentials");
            strip_gce_env(config);
        }
    }
}

/// Remove the GCE metadata env vars from both the agent's child env and the
/// provider credential state.
#[cfg(target_os = "linux")]
fn strip_gce_env(config: &InPodConfig) {
    let mut env = config.provider_env.lock().expect("provider_env lock");
    env.remove("GCE_METADATA_HOST");
    env.remove("GCE_METADATA_IP");
    env.remove("METADATA_SERVER_DETECTION");
    drop(env);
    config
        .provider_credentials
        .remove_env_key("GCE_METADATA_HOST");
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };
    use openshell_isolation::AgentSpec;
    use openshell_isolation::contract::{BackendRegistry, TopologyDescriptor};

    /// A minimal in-pod config with networking disabled. The process leaf is
    /// declared available so `confirm` can certify launch readiness, but tests
    /// that use this fixture do not call `start_agent`.
    fn minimal_config() -> InPodConfig {
        InPodConfig {
            require_exclusive_pid_namespace: false,
            network_enabled: false,
            process_enabled: true,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            provider_credentials: ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            provider_env: Mutex::new(HashMap::new()),
            process_enforcement_mode: ProcessEnforcementMode::Full,
            resolved_process_identity: ResolvedProcessIdentity::new(
                Some(nix::unistd::geteuid().as_raw()),
                Some(nix::unistd::getegid().as_raw()),
            ),
            agent_proposals: AgentProposals::new(false),
            openshell_endpoint: None,
            ssh_socket_path: None,
            #[cfg(target_os = "linux")]
            bypass_denial_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_activity_tx: Mutex::new(None),
            mediation_ready: Arc::new(AtomicBool::new(true)),
            ca_file_paths: Arc::new(Mutex::new(None)),
            proxy_bind_ip: Arc::new(Mutex::new(None)),
        }
    }

    fn block_mode_policy() -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Block,
                proxy: None,
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }

    fn descriptor() -> TopologyDescriptor {
        TopologyDescriptor {
            version: INTERFACE_VERSION,
            backend_name: IN_POD_BACKEND_NAME.to_string(),
            payload: Vec::new(),
        }
    }

    fn sandbox_context() -> SandboxContext {
        SandboxContext {
            sandbox_id: "test-sandbox".to_string(),
            policy: block_mode_policy(),
            agent: AgentSpec {
                program: "true".to_string(),
                args: vec![],
                workdir: None,
                timeout_secs: 0,
                interactive: false,
            },
        }
    }

    // ----- Backend and registry -----

    #[test]
    fn backend_speaks_the_version() {
        let backend = InPodBackend::new(minimal_config());
        assert_eq!(backend.backend_name(), IN_POD_BACKEND_NAME);
        assert_eq!(backend.version(), INTERFACE_VERSION);
    }

    #[test]
    fn registry_selects_in_pod_backend() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        let (backend, _verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        assert_eq!(backend.backend_name(), IN_POD_BACKEND_NAME);
    }

    #[test]
    fn registry_rejects_duplicate_in_pod() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("first register");
        assert!(
            registry
                .register(Arc::new(InPodBackend::new(minimal_config())))
                .is_err()
        );
    }

    #[test]
    fn registry_rejects_admission_mismatch() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        // The descriptor names in-pod, but admission expects a different backend.
        assert!(
            registry
                .resolve(descriptor(), "some-other-backend")
                .map(|_| ())
                .is_err()
        );
    }

    // ----- Lifecycle (no root / no netns) -----

    /// Drive the real in-pod chain attach -> Bound -> confirm -> Ready and prove
    /// the retained mediation source survives the consuming transitions.
    #[tokio::test]
    async fn lifecycle_reaches_ready_and_retains_source() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        let (backend, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");

        let bound = backend
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let source = bound.network_mediation_source();
        let _ready = bound.confirm().await.expect("confirm");
        // Block mode has no connection source, so a retained accept fails
        // closed after `Bound` is consumed.
        assert!(source.accept().await.is_err());
    }

    #[tokio::test]
    async fn live_source_accepts_stream_and_carries_fail_closed_identity() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let source = Arc::new(InPodNetworkMediationSource {
            listener,
            identity: ProcfsIdentityResolver {
                entrypoint_pid: Arc::new(AtomicU32::new(0)),
            },
            runtime: openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new(),
        });
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
        });
        let mut connection = source.accept().await.expect("accept");
        assert!(connection.binary_identity.is_err());
        let mut bytes = [0_u8; 4];
        connection.stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        client.await.unwrap();
    }

    #[tokio::test]
    async fn pending_source_accept_rejects_connection_after_boundary_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
        let source = Arc::new(InPodNetworkMediationSource {
            listener,
            identity: ProcfsIdentityResolver {
                entrypoint_pid: Arc::new(AtomicU32::new(0)),
            },
            runtime: runtime.clone(),
        });
        let pending = tokio::spawn({
            let source = source.clone();
            async move { source.accept().await }
        });
        tokio::task::yield_now().await;
        runtime.deactivate();
        let _client = tokio::net::TcpStream::connect(address).await.unwrap();
        assert!(matches!(
            pending.await.unwrap(),
            Err(BackendError::Terminated(_))
        ));
    }

    #[tokio::test]
    async fn mediation_source_failure_is_fail_static_without_ending_the_boundary() {
        let runtime = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
        let source = InactiveNetworkMediationSource {
            runtime: runtime.clone(),
        };

        assert!(matches!(
            source.accept().await,
            Err(BackendError::Unavailable(_))
        ));
        runtime
            .ensure_active()
            .expect("network failure must leave Running active");
        assert!(matches!(
            source.accept().await,
            Err(BackendError::Unavailable(_))
        ));
    }

    /// `attach` is atomic and never binds a resource that is already bound to an
    /// active boundary: the in-pod resource binds exactly once.
    #[tokio::test]
    async fn second_attach_is_denied() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");

        let (backend, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        let _bound = backend
            .attach(verified, sandbox_context())
            .await
            .expect("first attach");

        let (_backend2, verified2) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("re-resolve");
        let err = backend
            .attach(verified2, sandbox_context())
            .await
            .map(|_| ())
            .expect_err("second attach must fail");
        assert!(matches!(err, BackendError::Denied(_)));
    }

    /// The in-pod payload is empty by construction; a non-empty payload is a
    /// descriptor error, validated by the backend at `attach`.
    #[tokio::test]
    async fn non_empty_payload_is_rejected() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        let bad = TopologyDescriptor {
            version: INTERFACE_VERSION,
            backend_name: IN_POD_BACKEND_NAME.to_string(),
            payload: vec![1, 2, 3],
        };
        let (backend, verified) = registry.resolve(bad, IN_POD_BACKEND_NAME).expect("resolve");
        let err = backend
            .attach(verified, sandbox_context())
            .await
            .map(|_| ())
            .expect_err("payload must be rejected");
        assert!(matches!(err, BackendError::Descriptor(_)));
    }

    #[tokio::test]
    async fn unrestricted_network_mode_is_not_admitted() {
        let backend = Arc::new(InPodBackend::new(minimal_config()));
        let mut registry = BackendRegistry::new();
        registry.register(backend.clone()).expect("register");
        let (_resolved, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        let mut sandbox = sandbox_context();
        sandbox.policy.network.mode = NetworkMode::Allow;
        let error = backend
            .attach(verified, sandbox)
            .await
            .map(|_| ())
            .expect_err("unrestricted egress cannot conform");
        assert_eq!(
            error.kind(),
            openshell_isolation::contract::BackendErrorKind::Denied
        );
    }

    #[tokio::test]
    async fn confirm_rejects_missing_launch_control_leaf() {
        let mut config = minimal_config();
        config.process_enabled = false;
        let backend = Arc::new(InPodBackend::new(config));
        let mut registry = BackendRegistry::new();
        registry.register(backend.clone()).expect("register");
        let (_resolved, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        let bound = backend
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let error = bound
            .confirm()
            .await
            .map(|_| ())
            .expect_err("Ready requires launch controls");
        assert!(matches!(error, BackendError::Confirm(_)));
    }

    #[tokio::test]
    async fn failed_agent_start_ends_boundary_and_invalidates_retained_source() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        let (backend, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        let mut sandbox = sandbox_context();
        sandbox.agent.program = "/definitely/missing/openshell-agent".to_string();
        let bound = backend.attach(verified, sandbox).await.expect("attach");
        let source = bound.network_mediation_source();
        let ready = bound.confirm().await.expect("confirm");
        assert!(matches!(
            ready.start_agent().await,
            Err(BackendError::Process(_))
        ));
        assert!(matches!(
            source.accept().await,
            Err(BackendError::Terminated(_))
        ));
    }

    #[tokio::test]
    async fn normal_agent_exit_invalidates_runtime_interfaces() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackend::new(minimal_config())))
            .expect("register");
        let (backend, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_NAME)
            .expect("resolve");
        let bound = backend
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let source = bound.network_mediation_source();
        let ready = bound.confirm().await.expect("confirm");
        let running = ready.start_agent().await.expect("start agent");
        let agent = running.agent();
        let exec = running.exec();
        let forward = running.port_forward();

        assert_eq!(
            agent.wait().await.expect("normal exit"),
            BoundaryExitStatus::Exited(0)
        );
        assert!(matches!(
            exec.exec(openshell_isolation::contract::ExecSpec {
                program: "/bin/true".to_string(),
                args: vec![],
                env: vec![],
                workdir: None,
                pty: false,
            })
            .await,
            Err(BackendError::Terminated(_))
        ));
        let target = openshell_isolation::contract::LoopbackTarget::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            1,
        )
        .expect("loopback target");
        assert!(matches!(
            forward.connect(target).await,
            Err(BackendError::Terminated(_))
        ));
        assert!(matches!(
            source.accept().await,
            Err(BackendError::Terminated(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enforcement_monitor_terminates_boundary_after_verification_loss() {
        let runtime = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
        let healthy = Arc::new(AtomicBool::new(true));
        let verify: EnforcementCheck = {
            let healthy = healthy.clone();
            Arc::new(move || {
                let healthy = healthy.clone();
                Box::pin(async move {
                    if healthy.load(Ordering::Acquire) {
                        Ok(())
                    } else {
                        Err("test enforcement loss".to_string())
                    }
                })
            })
        };
        let _monitor = start_enforcement_monitor(
            runtime.clone(),
            std::time::Duration::from_millis(5),
            verify,
            false,
        )
        .await
        .expect("initial enforcement verification");
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        runtime.ensure_active().expect("healthy enforcement");

        healthy.store(false, Ordering::Release);
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while runtime.is_active() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("monitor must terminate within its bound");
        assert!(runtime.ensure_active().is_err());
        assert!(runtime.enforcement_was_lost());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enforcement_loss_kills_registered_workload_within_bound() {
        use std::os::unix::process::CommandExt as _;

        let runtime = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        let mut child = command.spawn().expect("spawn workload process");
        runtime
            .register_process_group(
                child.id(),
                Arc::new(AtomicBool::new(false)),
                Arc::new(Mutex::new(())),
            )
            .expect("register workload process group");

        let healthy = Arc::new(AtomicBool::new(true));
        let verify: EnforcementCheck = {
            let healthy = healthy.clone();
            Arc::new(move || {
                let healthy = healthy.clone();
                Box::pin(async move {
                    healthy
                        .load(Ordering::Acquire)
                        .then_some(())
                        .ok_or_else(|| "test enforcement loss".to_string())
                })
            })
        };
        let _monitor = start_enforcement_monitor(
            runtime.clone(),
            std::time::Duration::from_millis(5),
            verify,
            false,
        )
        .await
        .expect("initial verification");
        healthy.store(false, Ordering::Release);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => break,
                    Err(error) => panic!("wait workload: {error}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("workload must terminate within the topology bound");
        assert!(runtime.enforcement_was_lost());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires privileged PID namespace creation"]
    #[allow(unsafe_code)]
    #[allow(
        clippy::zombie_processes,
        reason = "PID 1 exits to make the kernel reap this deliberately unregistered descendant"
    )]
    fn pid_namespace_exit_helper() {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;

        let Some(ready_path) = std::env::var_os("OPENSHELL_PIDNS_TEST_READY") else {
            return;
        };
        let trigger_path = std::env::var_os("OPENSHELL_PIDNS_TEST_TRIGGER")
            .expect("PID namespace helper trigger path");
        let identity_socket = std::env::var_os("OPENSHELL_PIDNS_TEST_SOCKET")
            .expect("PID namespace helper identity socket");
        assert_eq!(std::process::id(), 1, "helper must be PID 1");
        std::os::unix::net::UnixStream::connect(&identity_socket)
            .expect("connect PID 1 identity socket")
            .write_all(b"pid1")
            .expect("publish PID 1 identity");
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                "inpod::tests::pid_namespace_descendant_helper",
                "--nocapture",
            ])
            .env("OPENSHELL_PIDNS_TEST_SOCKET", &identity_socket);
        // SAFETY: `setsid` is async-signal-safe and has no captured state.
        unsafe {
            command.pre_exec(|| {
                if nix::libc::setsid() >= 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let _unregistered_descendant = command.spawn().expect("spawn setsid descendant");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build monitor runtime");
        runtime.block_on(async move {
            let boundary = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
            let healthy = Arc::new(AtomicBool::new(true));
            let verify: EnforcementCheck = {
                let healthy = healthy.clone();
                Arc::new(move || {
                    let healthy = healthy.clone();
                    Box::pin(async move {
                        healthy
                            .load(Ordering::Acquire)
                            .then_some(())
                            .ok_or_else(|| "privileged test enforcement loss".to_string())
                    })
                })
            };
            let _monitor = start_enforcement_monitor(
                boundary,
                std::time::Duration::from_millis(5),
                verify,
                true,
            )
            .await
            .expect("start enforcement monitor");
            std::fs::write(&ready_path, b"ready").expect("publish helper readiness");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !std::path::Path::new(&trigger_path).exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "parent did not trigger enforcement loss"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            healthy.store(false, Ordering::Release);
            std::future::pending::<()>().await;
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "helper for privileged PID namespace test"]
    fn pid_namespace_descendant_helper() {
        use std::io::Write as _;

        let Some(socket_path) = std::env::var_os("OPENSHELL_PIDNS_TEST_SOCKET") else {
            return;
        };
        std::os::unix::net::UnixStream::connect(socket_path)
            .expect("connect descendant identity socket")
            .write_all(b"descendant")
            .expect("publish descendant identity");
        loop {
            std::thread::park();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires privileged PID namespace creation"]
    fn pid_one_exit_kills_unregistered_setsid_descendant_within_bound() {
        fn process_is_running(pid: u32) -> bool {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                return false;
            };
            !matches!(fields.as_bytes().first(), Some(b'Z' | b'X'))
        }

        let tempdir = tempfile::tempdir().expect("tempdir");
        let ready = tempdir.path().join("ready");
        let trigger = tempdir.path().join("trigger");
        let identity_socket = tempdir.path().join("identity.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&identity_socket).expect("bind identity socket");
        listener
            .set_nonblocking(true)
            .expect("set identity socket nonblocking");
        let current_exe = std::env::current_exe().expect("current test executable");
        let mut namespace = std::process::Command::new("unshare")
            .args(["--mount", "--pid", "--fork", "--kill-child", "--mount-proc"])
            .arg(current_exe)
            .args([
                "--ignored",
                "--exact",
                "inpod::tests::pid_namespace_exit_helper",
                "--nocapture",
            ])
            .env("OPENSHELL_PIDNS_TEST_READY", &ready)
            .env("OPENSHELL_PIDNS_TEST_TRIGGER", &trigger)
            .env("OPENSHELL_PIDNS_TEST_SOCKET", &identity_socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start isolated PID namespace");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut isolated = Vec::new();
        while !ready.exists() || isolated.len() < 2 {
            match listener.accept() {
                Ok((stream, _)) => {
                    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

                    let credentials = getsockopt(&stream, PeerCredentials)
                        .expect("read namespaced process credentials");
                    isolated.push(u32::try_from(credentials.pid()).expect("positive peer PID"));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept identity connection: {error}"),
            }
            if let Some(status) = namespace.try_wait().expect("poll namespace") {
                let stderr = namespace
                    .stderr
                    .take()
                    .and_then(|mut stderr| {
                        use std::io::Read as _;
                        let mut output = String::new();
                        stderr.read_to_string(&mut output).ok()?;
                        Some(output)
                    })
                    .unwrap_or_default();
                panic!("PID namespace helper exited early ({status}): {stderr}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "helper readiness timeout"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(
            isolated.len(),
            2,
            "expected PID 1 and its setsid descendant"
        );
        std::fs::write(&trigger, b"exit").expect("trigger PID 1 exit");
        let status = namespace.wait().expect("wait for namespace exit");
        assert_eq!(status.code(), Some(125));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while isolated.iter().copied().any(process_is_running) {
            assert!(
                std::time::Instant::now() < deadline,
                "namespace descendant survived the documented termination bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn wait_reports_enforcement_loss_as_terminated() {
        let process = InPodAgentProcess {
            signaler: None,
            result: Arc::new(Mutex::new(Some(Err(StableWaitError::EnforcementLost)))),
            exited: Arc::new(tokio::sync::Notify::new()),
            terminal: Arc::new(AtomicBool::new(true)),
            runtime: openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new(),
        };

        let error = process
            .wait()
            .await
            .expect_err("enforcement loss is abnormal");
        assert_eq!(
            error.kind(),
            openshell_isolation::contract::BackendErrorKind::Terminated
        );
    }

    #[tokio::test]
    async fn normal_teardown_is_not_reclassified_by_inflight_verification() {
        let runtime = openshell_supervisor_process::boundary_io::BoundaryRuntimeState::new();
        let calls = Arc::new(AtomicU32::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let verify: EnforcementCheck = {
            let calls = calls.clone();
            let entered = entered.clone();
            let release = release.clone();
            Arc::new(move || {
                let calls = calls.clone();
                let entered = entered.clone();
                let release = release.clone();
                Box::pin(async move {
                    if calls.fetch_add(1, Ordering::AcqRel) == 0 {
                        return Ok(());
                    }
                    entered.notify_one();
                    release.notified().await;
                    Err("verification completed after teardown".to_string())
                })
            })
        };
        let _monitor = start_enforcement_monitor(
            runtime.clone(),
            std::time::Duration::from_millis(1),
            verify,
            false,
        )
        .await
        .expect("initial verification");
        entered.notified().await;
        runtime.deactivate();
        release.notify_one();
        tokio::task::yield_now().await;

        assert!(!runtime.enforcement_was_lost());
    }
}
