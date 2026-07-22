// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Kubernetes sidecar isolation backend (RFC 0012 runtime-selectable contract).
//!
//! This is the split placement: a separate *network* container hosts the
//! mediation service (the proxy) and the sidecar control server, while the
//! *agent* container runs the single logical supervisor plus this backend and
//! spawns the untrusted workload. Network mediation is remote (in the network
//! container), so this backend hosts no mediation ingress of its own; the agent
//! container is autonomous and self-provisions its workload, exactly as before.
//!
//! This backend wraps that existing agent/process path in the object-safe boxed
//! state chain (`attach -> Bound -> confirm -> Ready -> start_agent -> Running`)
//! without changing its behavior. Standing enforcement (network mediation) and
//! the control connection were established by the supervisor preamble before the
//! backend is attached, so `attach` and `confirm` are trivial here — there is no
//! local netns or proxy to bring up. `start_agent` replicates the workload spawn
//! (`spawn_workload`'s pre-exec ceiling applies filesystem/Landlock + syscall/
//! seccomp launch-time controls before the first untrusted instruction), wiring
//! the entrypoint-started event over the control writer and racing the workload
//! against the authoritative control-closed signal so a supervisor disconnect
//! fails the boundary closed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;

use async_trait::async_trait;

#[cfg(target_os = "linux")]
use openshell_core::activity::ActivitySender;
#[cfg(target_os = "linux")]
use openshell_core::denial::DenialEvent;
use openshell_core::policy::SandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation::contract::{
    BackendError, BoundBoundary, BoundaryExec, BoundaryExitStatus, BoundaryPortForward,
    BoundaryProcess, BoundarySignal, CONTRACT_VERSION, ExecSession, ExecSpec,
    IsolationBackendFactory, MediatedConnection, MediationIngress, ReadyBoundary, RunningBoundary,
    SandboxContext, VerifiedTopologyDescriptor,
};
use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, StatusId, ocsf_emit};
use openshell_supervisor_process::boundary_io::NetnsPortForward;
use openshell_supervisor_process::process::ProcessEnforcementMode;
use openshell_supervisor_process::run::{AgentSignaler, SpawnedAgent, spawn_workload};
use tokio::net::unix::OwnedWriteHalf;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};

/// The registered id for the sidecar backend (defined in the contract crate so
/// compute drivers can name it in the descriptors they create).
pub use openshell_isolation::contract::SIDECAR_BACKEND_ID;

// ============================================================================
// Config and factory
// ============================================================================

/// Runtime collaborators the sidecar agent/process lifecycle needs, captured
/// once when the factory is built. These are the pieces of the agent-container
/// process path that are *not* carried in the trusted [`SandboxContext`]:
/// launch-time enforcement inputs, provider material, the process-role policy
/// (already transformed by `process_policy_for_topology`), and the live sidecar
/// control connection established in the supervisor preamble. Move-once values
/// (the control-closed receiver and bypass senders) are held behind a
/// `Mutex<Option<_>>` so the `&self` state methods can take them exactly when
/// the matching transition fires.
pub struct SidecarConfig {
    /// Process launch-time enforcement level (typically `NetworkOnly` in the
    /// sidecar topology, since the network container owns egress mediation).
    pub process_enforcement_mode: ProcessEnforcementMode,
    pub provider_credentials: ProviderCredentialState,
    /// Child environment for the agent, resolved by the supervisor preamble.
    pub provider_env: HashMap<String, String>,
    /// The process-role policy, already transformed for the split topology by
    /// `process_policy_for_topology`.
    pub process_policy: SandboxPolicy,
    /// Proxy CA material for the workload's trust store, resolved by the
    /// supervisor preamble (sidecar bootstrap or the well-known mount).
    pub ca_file_paths: Option<(PathBuf, PathBuf)>,
    pub entrypoint_pid: Arc<AtomicU32>,
    pub ssh_socket_path: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub sandbox_id: Option<String>,
    /// The entrypoint-started writer half of the sidecar control connection.
    /// Cloneable (`Arc`), so it is not a move-once slot.
    pub process_control_writer: Option<Arc<tokio::sync::Mutex<OwnedWriteHalf>>>,
    /// The authoritative sidecar control-closed signal (move-once): consumed by
    /// `start_agent` and raced against the workload so a supervisor disconnect
    /// fails the boundary closed.
    pub process_control_closed: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    /// Bypass-monitor denial / activity senders (consumed by `start_agent`).
    #[cfg(target_os = "linux")]
    pub bypass_denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    #[cfg(target_os = "linux")]
    pub bypass_activity_tx: Mutex<Option<ActivitySender>>,
}

/// The factory for the sidecar backend. Holds the per-sandbox [`SidecarConfig`]
/// and hands it to the boundary on the single `attach`.
pub struct SidecarBackendFactory {
    config: Mutex<Option<SidecarConfig>>,
}

impl SidecarBackendFactory {
    /// Build the factory from its per-sandbox runtime collaborators.
    #[must_use]
    pub fn new(config: SidecarConfig) -> Self {
        Self {
            config: Mutex::new(Some(config)),
        }
    }
}

#[async_trait]
impl IsolationBackendFactory for SidecarBackendFactory {
    fn backend_id(&self) -> &'static str {
        SIDECAR_BACKEND_ID
    }

    fn contract_version(&self) -> u32 {
        CONTRACT_VERSION
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        // Validate the sidecar payload at the trust boundary: the agent-container
        // supervisor *is* the resource, so the payload carries nothing. Reject a
        // non-empty payload as a malformed/tampered descriptor before binding.
        if !descriptor.payload().is_empty() {
            return Err(BackendError::Descriptor(
                "sidecar descriptor payload must be empty".to_string(),
            ));
        }
        // `attach` never binds a resource that is already bound to an active
        // boundary: the agent-container supervisor is this process, bindable
        // exactly once. There is no fallible establishment step after the take
        // (mediation and the control connection were brought up by the preamble),
        // so a consumed slot always means "already bound".
        let config = self
            .config
            .lock()
            .expect("sidecar config lock")
            .take()
            .ok_or_else(|| {
                BackendError::Denied(
                    "sidecar resource is already bound to an active boundary".to_string(),
                )
            })?;

        // No local netns and no local proxy: mediation runs in the network
        // container and the control connection is already established. The
        // boundary is bound to the trusted sandbox context here.
        let mediation_ingress: Arc<dyn MediationIngress> = Arc::new(SidecarMediationIngress);

        Ok(Box::new(SidecarBound {
            config,
            sandbox,
            mediation_ingress,
        }))
    }
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Bound: the descriptor and trusted sandbox context are bound to this agent
/// container's supervisor. Network mediation is hosted remotely (network
/// container), so the ingress here is an inert stub. No untrusted workload code
/// is running.
struct SidecarBound {
    config: SidecarConfig,
    sandbox: SandboxContext,
    mediation_ingress: Arc<dyn MediationIngress>,
}

#[async_trait]
impl BoundBoundary for SidecarBound {
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress> {
        self.mediation_ingress.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        // Standing enforcement (egress mediation) is confirmed by the network
        // container that owns the proxy; the agent container cannot certify that
        // remote proxy. It can, and must, certify the one signal it owns: the
        // authoritative control link to the network container, established in the
        // supervisor preamble. If that link is already down at confirmation time,
        // fail closed rather than advance to `start_agent` and launch the
        // untrusted workload only to tear it down on the first `wait`.
        {
            let mut guard = self
                .config
                .process_control_closed
                .lock()
                .expect("process_control_closed lock");
            if let Some(rx) = guard.as_mut() {
                // The reader task sends `()` on close and drops the sender if it
                // is aborted, so both `Ok(())` and `Closed` mean the link is
                // gone; only `Empty` is still live.
                match rx.try_recv() {
                    Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        return Err(BackendError::Confirm(
                            "sidecar control channel already closed; refusing to start workload"
                                .to_string(),
                        ));
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                }
            }
        }
        Ok(Box::new(SidecarReady {
            config: self.config,
            sandbox: self.sandbox,
        }))
    }
}

/// Ready: standing enforcement is confirmed remotely and the control connection
/// is live. Only agent activation is possible.
struct SidecarReady {
    config: SidecarConfig,
    sandbox: SandboxContext,
}

#[async_trait]
impl ReadyBoundary for SidecarReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let this = *self;
        let config = this.config;
        let sandbox = this.sandbox;

        let port_forward: Arc<dyn BoundaryPortForward> =
            Arc::new(NetnsPortForward { netns_fd: None });
        let exec: Arc<dyn BoundaryExec> = Arc::new(SidecarExec);

        let spec = &sandbox.agent;

        // Wire the entrypoint-started oneshot to the sidecar control writer: when
        // the workload's entrypoint PID is known, forward it over the control
        // connection so the network container can attribute the workload.
        let entrypoint_started_tx = config.process_control_writer.clone().map(|writer| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                match rx.await {
                    Ok(pid) => {
                        if let Err(err) =
                            crate::sidecar_control::send_entrypoint_started(&writer, pid).await
                        {
                            warn!(error = %err, "Failed to send sidecar entrypoint event");
                        }
                    }
                    Err(_closed) => {
                        debug!("Entrypoint exited before sidecar entrypoint event was sent");
                    }
                }
            });
            tx
        });

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

        // The sidecar agent container creates the workload itself; the
        // launch-time controls (Landlock, seccomp, privilege drop as permitted
        // by the enforcement mode) are applied inside `spawn_workload`'s pre-exec
        // ceiling, before the first untrusted instruction.
        let spawned = spawn_workload(
            &spec.program,
            &spec.args,
            spec.workdir.as_deref(),
            spec.timeout_secs,
            spec.interactive,
            config.sandbox_id.as_deref(),
            config.openshell_endpoint.as_deref(),
            config.ssh_socket_path.clone(),
            // The agent container shares its SSH socket with the network sidecar
            // container.
            true,
            &config.process_policy,
            config.process_enforcement_mode,
            config.entrypoint_pid.clone(),
            entrypoint_started_tx,
            config.provider_credentials.clone(),
            config.provider_env.clone(),
            config.ca_file_paths.clone(),
            #[cfg(target_os = "linux")]
            None,
            #[cfg(target_os = "linux")]
            bypass_denial_tx,
            #[cfg(target_os = "linux")]
            bypass_activity_tx,
        )
        .await
        .map_err(|e| BackendError::Process(e.to_string()))?;

        let control_closed = config
            .process_control_closed
            .lock()
            .expect("process_control_closed lock")
            .take();

        let agent: Arc<dyn BoundaryProcess> =
            Arc::new(SidecarAgentProcess::running(spawned, control_closed));

        Ok(Box::new(SidecarRunning {
            agent,
            exec,
            port_forward,
        }))
    }
}

/// Running: the workload is runnable behind the boundary. Exec, forwarding,
/// wait, and signal are available. The mediation ingress was retained by the
/// supervisor from the `Bound` state.
struct SidecarRunning {
    agent: Arc<dyn BoundaryProcess>,
    exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryPortForward>,
}

impl RunningBoundary for SidecarRunning {
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

/// The workload process running inside the sidecar agent container. `wait`
/// returns a stable terminal status across repeated calls and races the workload
/// against the authoritative control-closed signal: if the network container's
/// control connection closes, the boundary fails closed (`Exited(1)`). Signals
/// go through the lock-free pid-based [`AgentSignaler`] so they never contend
/// with an in-flight `wait`.
struct SidecarAgentProcess {
    pid: Option<u32>,
    signaler: Option<AgentSignaler>,
    waiter: tokio::sync::Mutex<AgentWaitState>,
}

enum AgentWaitState {
    Pending {
        agent: SpawnedAgent,
        control_closed: Option<tokio::sync::oneshot::Receiver<()>>,
    },
    Done(BoundaryExitStatus),
}

impl SidecarAgentProcess {
    fn running(
        spawned: SpawnedAgent,
        control_closed: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Self {
        Self {
            pid: Some(spawned.pid()),
            signaler: Some(spawned.signaler()),
            waiter: tokio::sync::Mutex::new(AgentWaitState::Pending {
                agent: spawned,
                control_closed,
            }),
        }
    }
}

#[async_trait]
impl BoundaryProcess for SidecarAgentProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        // Holding the lock across the wait serializes repeated callers: the first
        // performs the wait and caches the status; later callers block on the
        // lock, then observe the cached `Done`. Signals never take this lock.
        //
        // `BackendError` is `!Clone`, so a fallible wait can never be cached as a
        // `Result`; on any wait/spawn error the status is cached as `Exited(1)`.
        let mut guard = self.waiter.lock().await;
        match &mut *guard {
            AgentWaitState::Done(status) => Ok(*status),
            AgentWaitState::Pending {
                agent,
                control_closed,
            } => {
                let status = if let Some(closed) = control_closed.take() {
                    tokio::select! {
                        result = agent.wait() => wait_result_to_status(result),
                        _ = closed => {
                            // The authoritative network-sidecar control channel
                            // closed: fail the boundary closed.
                            ocsf_emit!(
                                AppLifecycleBuilder::new(crate::ocsf_ctx())
                                    .activity(ActivityId::Fail)
                                    .severity(SeverityId::High)
                                    .status(StatusId::Failure)
                                    .message(
                                        "Authoritative network-sidecar control channel closed; terminating agent container"
                                    )
                                    .build()
                            );
                            BoundaryExitStatus::Exited(1)
                        }
                    }
                } else {
                    wait_result_to_status(agent.wait().await)
                };
                *guard = AgentWaitState::Done(status);
                Ok(status)
            }
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let Some(signaler) = self.signaler.as_ref() else {
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
        let Some(signaler) = self.signaler.as_ref() else {
            return Ok(());
        };
        signaler
            .term()
            .map_err(|e| BackendError::Process(e.to_string()))
    }

    fn diagnostic_pid(&self) -> Option<u32> {
        self.pid
    }
}

/// Map a `spawn_workload` wait result to a placement-neutral status. A wait
/// error fails the boundary closed (`Exited(1)`) — the error is logged, never
/// cached (`BackendError` is `!Clone`).
fn wait_result_to_status(result: miette::Result<i32>) -> BoundaryExitStatus {
    match result {
        Ok(code) => BoundaryExitStatus::Exited(code),
        Err(e) => {
            warn!(error = %e, "Sidecar workload wait failed; failing closed");
            BoundaryExitStatus::Exited(1)
        }
    }
}

// ============================================================================
// Exec and mediation ingress
// ============================================================================

/// Sidecar exec interface. As with the in-pod backend, the live SSH server still
/// spawns workload shells directly; routing those through an owned
/// [`ExecSession`] is the remaining live-adoption refactor, so this returns an
/// explicit error rather than a half-wired session.
struct SidecarExec;

#[async_trait]
impl BoundaryExec for SidecarExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Process(
            "sidecar BoundaryExec is not yet the live SSH exec path; SSH execs directly."
                .to_string(),
        ))
    }
}

/// Sidecar mediation ingress. Egress mediation is hosted remotely in the network
/// container, so this boundary hosts none: `accept` fails closed rather than
/// competing with the remote proxy's accept loop.
struct SidecarMediationIngress;

#[async_trait]
impl MediationIngress for SidecarMediationIngress {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        Err(BackendError::Process(
            "sidecar MediationIngress hosts no connections; mediation runs in the network container"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkMode, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };
    use openshell_isolation::AgentSpec;
    use openshell_isolation::contract::{BackendRegistry, TopologyDescriptor};

    fn minimal_config() -> SidecarConfig {
        SidecarConfig {
            process_enforcement_mode: ProcessEnforcementMode::NetworkOnly,
            provider_credentials: ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            provider_env: HashMap::new(),
            process_policy: block_mode_policy(),
            ca_file_paths: None,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            ssh_socket_path: None,
            openshell_endpoint: None,
            sandbox_id: None,
            process_control_writer: None,
            process_control_closed: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_denial_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_activity_tx: Mutex::new(None),
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
            contract_version: CONTRACT_VERSION,
            backend_id: SIDECAR_BACKEND_ID.to_string(),
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

    #[test]
    fn factory_speaks_the_contract_version() {
        let factory = SidecarBackendFactory::new(minimal_config());
        assert_eq!(factory.backend_id(), SIDECAR_BACKEND_ID);
        assert_eq!(factory.contract_version(), CONTRACT_VERSION);
    }

    #[test]
    fn registry_selects_sidecar_backend() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(SidecarBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, _verified) = registry
            .resolve(descriptor(), SIDECAR_BACKEND_ID)
            .expect("resolve");
        assert_eq!(factory.backend_id(), SIDECAR_BACKEND_ID);
    }

    /// Drive the sidecar chain attach -> Bound -> confirm -> Ready and prove the
    /// retained mediation ingress survives the consuming transitions.
    #[tokio::test]
    async fn lifecycle_reaches_ready_and_retains_ingress() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(SidecarBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, verified) = registry
            .resolve(descriptor(), SIDECAR_BACKEND_ID)
            .expect("resolve");

        let bound = factory
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let ingress = bound.mediation_ingress();
        let _ready = bound.confirm().await.expect("confirm");
        // Mediation is remote; the local ingress reports an explicit error.
        assert!(ingress.accept().await.is_err());
    }

    /// A descriptor that names the sidecar backend but carries an unexpected
    /// non-empty payload is a malformed/tampered value and must fail closed at
    /// the trust boundary (the payload is validated by the backend in `attach`).
    #[tokio::test]
    async fn attach_rejects_nonempty_payload() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(SidecarBackendFactory::new(minimal_config())))
            .expect("register");
        let tampered = TopologyDescriptor {
            contract_version: CONTRACT_VERSION,
            backend_id: SIDECAR_BACKEND_ID.to_string(),
            payload: vec![1, 2, 3],
        };
        let (factory, verified) = registry
            .resolve(tampered, SIDECAR_BACKEND_ID)
            .expect("resolve");
        let err = factory
            .attach(verified, sandbox_context())
            .await
            .map(|_| ())
            .expect_err("non-empty payload must be rejected");
        assert!(matches!(err, BackendError::Descriptor(_)));
    }

    /// `confirm` fails closed when the authoritative control link to the network
    /// container is already down: the workload must not be launched only to be
    /// torn down on the first `wait`.
    #[tokio::test]
    async fn confirm_fails_closed_when_control_channel_dead() {
        let mut config = minimal_config();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        // Sender dropped without sending: the control link is gone.
        drop(tx);
        config.process_control_closed = Mutex::new(Some(rx));

        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(SidecarBackendFactory::new(config)))
            .expect("register");
        let (factory, verified) = registry
            .resolve(descriptor(), SIDECAR_BACKEND_ID)
            .expect("resolve");
        let bound = factory
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let err = bound
            .confirm()
            .await
            .map(|_| ())
            .expect_err("confirm must fail closed on a dead control channel");
        assert!(matches!(err, BackendError::Confirm(_)));
    }

    /// `attach` is atomic and never binds a resource that is already bound to an
    /// active boundary: the sidecar resource binds exactly once.
    #[tokio::test]
    async fn second_attach_is_denied() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(SidecarBackendFactory::new(minimal_config())))
            .expect("register");

        let (factory, verified) = registry
            .resolve(descriptor(), SIDECAR_BACKEND_ID)
            .expect("resolve");
        let _bound = factory
            .attach(verified, sandbox_context())
            .await
            .expect("first attach");

        let (_factory2, verified2) = registry
            .resolve(descriptor(), SIDECAR_BACKEND_ID)
            .expect("re-resolve");
        let err = factory
            .attach(verified2, sandbox_context())
            .await
            .map(|_| ())
            .expect_err("second attach must fail");
        assert!(matches!(err, BackendError::Denied(_)));
    }
}
