// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod isolation backend (RFC 0012 runtime-selectable contract).
//!
//! This is the co-located placement: the supervisor process hosts the
//! supervisor role, the mediation service, and the backend in the agent's
//! container. It implements the object-safe boxed state chain
//! (`attach -> Bound -> confirm -> Ready -> start_agent -> Running`) over the
//! existing supervisor primitives without changing their behavior:
//! `create_netns_for_proxy` (network), `run_networking` (proxy mediation),
//! the pre-exec ceiling in `spawn_workload` (filesystem/Landlock +
//! syscall/seccomp), and procfs (binary identity).
//!
//! `attach` validates the (empty) in-pod payload and atomically binds the
//! trusted [`SandboxContext`] to the boundary it establishes: the workload
//! network namespace and the mediation service come up inside `attach`, so
//! `Bound` means what the RFC says it means — descriptor and context bound to
//! the same resource, mediation ingress available, no untrusted workload code
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
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use async_trait::async_trait;

use openshell_core::activity::ActivitySender;
use openshell_core::denial::DenialEvent;
use openshell_core::policy::NetworkMode;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation::contract::{
    BackendError, BoundBoundary, BoundaryExec, BoundaryExitStatus, BoundaryPortForward,
    BoundaryProcess, BoundarySignal, CONTRACT_VERSION, ExecSession, ExecSpec,
    IsolationBackendFactory, MediatedConnection, MediationIngress, ReadyBoundary, RunningBoundary,
    SandboxContext, VerifiedTopologyDescriptor,
};
use openshell_supervisor_network::identity_source::ProcfsIdentityResolver;
use openshell_supervisor_network::opa::OpaEngine;
use openshell_supervisor_network::run::{Networking, run_networking};
use openshell_supervisor_process::boundary_io::NetnsPortForward;
use openshell_supervisor_process::process::ProcessEnforcementMode;
use openshell_supervisor_process::run::{AgentSignaler, SpawnedAgent, spawn_workload};
use tokio::sync::mpsc::UnboundedSender;

#[cfg(target_os = "linux")]
use openshell_supervisor_process::netns::{NetworkNamespace, create_netns_for_proxy};

/// The registered id for the in-pod backend (defined in the contract crate so
/// compute drivers can name it in the descriptors they create).
pub use openshell_isolation::contract::IN_POD_BACKEND_ID;

// ============================================================================
// Config and factory
// ============================================================================

/// Runtime collaborators the in-pod lifecycle calls need, captured once when the
/// factory is built. Move-once values (the event senders) are held behind a
/// `Mutex<Option<_>>` so the `&self` factory/state methods can take them exactly
/// when the matching transition fires. Policy, workload, and sandbox identity
/// are *not* here; they arrive in the trusted [`SandboxContext`] at `attach`.
pub struct InPodConfig {
    pub network_enabled: bool,
    pub process_enabled: bool,
    pub opa_engine: Option<Arc<OpaEngine>>,
    pub retained_proto: Option<openshell_core::proto::SandboxPolicy>,
    pub entrypoint_pid: Arc<AtomicU32>,
    pub provider_credentials: ProviderCredentialState,
    /// Child environment for the agent, resolved at startup. Mutated in place by
    /// `attach` if the GCE metadata loopback server fails to come up.
    pub provider_env: Mutex<HashMap<String, String>>,
    /// Process launch-time enforcement level (full privileged setup vs.
    /// network-sidecar reduced mode), resolved by the supervisor at startup.
    pub process_enforcement_mode: ProcessEnforcementMode,
    pub sandbox_name: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub inference_routes: Option<String>,
    pub ssh_socket_path: Option<String>,
    /// Workspace watch receiver: handed to `run_networking` so the proxy's
    /// policy-local and activity paths observe the workspace the poll loop
    /// learns from `GetSandboxConfig`.
    pub workspace_rx: tokio::sync::watch::Receiver<String>,
    /// Proxy-side denial / activity senders (consumed by `attach`).
    pub denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    pub activity_tx: Mutex<Option<ActivitySender>>,
    /// Bypass-monitor denial / activity senders (consumed by `start_agent`).
    #[cfg(target_os = "linux")]
    pub bypass_denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    #[cfg(target_os = "linux")]
    pub bypass_activity_tx: Mutex<Option<ActivitySender>>,
    /// Output slot: `attach` publishes the proxy's policy-local route context
    /// here so the orchestrator's policy poll loop can pick it up without
    /// reaching into in-pod-specific state through the `dyn` boundary.
    pub policy_local_slot:
        Arc<Mutex<Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>>>,
}

/// The factory for the in-pod backend. Holds the per-sandbox [`InPodConfig`] and
/// hands it to the boundary on the single `attach`.
pub struct InPodBackendFactory {
    config: Mutex<Option<InPodConfig>>,
    /// Whether a prior `attach` consumed the config and then failed during
    /// establishment. The one-shot event senders are consumed with it, so the
    /// in-pod resource cannot be re-attached; this keeps the error truthful
    /// ("attempt failed", not "already bound").
    attach_failed: AtomicBool,
}

impl InPodBackendFactory {
    /// Build the factory from its per-sandbox runtime collaborators.
    #[must_use]
    pub fn new(config: InPodConfig) -> Self {
        Self {
            config: Mutex::new(Some(config)),
            attach_failed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl IsolationBackendFactory for InPodBackendFactory {
    fn backend_id(&self) -> &'static str {
        IN_POD_BACKEND_ID
    }

    fn contract_version(&self) -> u32 {
        CONTRACT_VERSION
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
    // Establish the network dimension of standing enforcement: create the
    // workload's network namespace and install the bypass-detection rules.
    // Filesystem and syscall are launch-time controls applied per process;
    // binary identity is resolved per accepted connection.
    #[cfg(target_os = "linux")]
    let netns = if config.network_enabled {
        create_netns_for_proxy(&sandbox.policy).map_err(|e| BackendError::Attach(e.to_string()))?
    } else {
        None
    };

    // Bring up the mediation service (the in-pod proxy) so the mediation
    // ingress is available at `Bound`.
    let networking = if config.network_enabled {
        #[cfg(target_os = "linux")]
        let proxy_bind_ip = netns.as_ref().map(NetworkNamespace::host_ip);
        #[cfg(not(target_os = "linux"))]
        let proxy_bind_ip: Option<std::net::IpAddr> = None;

        // Take the senders into locals so the Mutex guards drop before the
        // await (a guard held across an await would make the future !Send).
        let denial_tx = config.denial_tx.lock().expect("denial_tx lock").take();
        let activity_tx = config.activity_tx.lock().expect("activity_tx lock").take();
        let networking = run_networking(
            &sandbox.policy,
            proxy_bind_ip,
            config.opa_engine.as_ref(),
            config.retained_proto.as_ref(),
            config.entrypoint_pid.clone(),
            config.process_enabled,
            &config.provider_credentials,
            Some(sandbox.sandbox_id.as_str()),
            config.sandbox_name.as_deref(),
            config.openshell_endpoint.as_deref(),
            config.inference_routes.as_deref(),
            denial_tx,
            activity_tx,
            config.workspace_rx.clone(),
        )
        .await
        .map_err(|e| BackendError::Attach(e.to_string()))?;
        Some(networking)
    } else {
        None
    };

    // Start the GCE metadata loopback server inside the namespace so Go's
    // metadata client (which bypasses HTTP_PROXY) can reach it via direct
    // TCP. Must come up before start_agent; on failure the GCE env vars are
    // stripped so the SDK falls back cleanly.
    #[cfg(target_os = "linux")]
    if let Some(ns) = netns.as_ref() {
        ensure_gce_metadata_server(&config, ns).await;
    }

    // Publish the policy-local route context for the orchestrator's poll
    // loop (the mediation service's policy-update path: authorized
    // revisions apply there without a backend lifecycle transition).
    *config
        .policy_local_slot
        .lock()
        .expect("policy_local_slot lock") = networking.as_ref().map(|n| n.policy_local_ctx.clone());

    // The mediation service's backend-neutral connection source, carrying
    // the per-connection identity resolver. The live in-pod proxy still
    // accepts directly (see `InPodMediationIngress`); this satisfies the
    // contract shape, and a delegated backend supplies a transport-backed
    // version.
    let mediation_ingress: Arc<dyn MediationIngress> = Arc::new(InPodMediationIngress {
        _identity: ProcfsIdentityResolver {
            entrypoint_pid: config.entrypoint_pid.clone(),
        },
    });

    Ok(InPodBound {
        config,
        sandbox,
        #[cfg(target_os = "linux")]
        netns,
        networking,
        mediation_ingress,
    })
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Bound: the descriptor and trusted sandbox context are bound to this process's
/// boundary, and the mediation ingress is available. No untrusted workload code
/// is running.
struct InPodBound {
    config: InPodConfig,
    sandbox: SandboxContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
    networking: Option<Networking>,
    mediation_ingress: Arc<dyn MediationIngress>,
}

#[async_trait]
impl BoundBoundary for InPodBound {
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress> {
        self.mediation_ingress.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        // Effective-mediation check (fail closed). In proxy mode the only egress
        // is through the proxy bound inside the workload netns; if the namespace
        // or the proxy listener is absent, the boundary does not safely gate
        // egress, so we must not produce Ready.
        //
        // Note: this confirms mediation *structure*. The nftables bypass-
        // detection ruleset still uses `policy accept` with protocol-specific
        // rejects (see `netns/nft_ruleset.rs`); hardening it to a true
        // default-deny is tracked as remaining implementation work and is NOT
        // certified here.
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
            let proxy_up = self
                .networking
                .as_ref()
                .and_then(|n| n.proxy.as_ref())
                .is_some();
            if !proxy_up {
                return Err(BackendError::Confirm(
                    "proxy listener is not bound; egress mediation is not in effect".to_string(),
                ));
            }
        }

        Ok(Box::new(InPodReady {
            config: self.config,
            sandbox: self.sandbox,
            #[cfg(target_os = "linux")]
            netns: self.netns,
            networking: self.networking,
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
    networking: Option<Networking>,
}

#[async_trait]
impl ReadyBoundary for InPodReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let this = *self;
        let config = this.config;
        let sandbox = this.sandbox;
        #[cfg(target_os = "linux")]
        let netns = this.netns;
        let networking = this.networking;

        #[cfg(target_os = "linux")]
        let netns_fd = netns.as_ref().and_then(NetworkNamespace::ns_fd);
        #[cfg(not(target_os = "linux"))]
        let netns_fd: Option<std::os::unix::io::RawFd> = None;

        let port_forward: Arc<dyn BoundaryPortForward> = Arc::new(NetnsPortForward { netns_fd });
        let exec: Arc<dyn BoundaryExec> = Arc::new(InPodExec);

        // The in-pod backend creates the agent process itself; the launch-time
        // controls (Landlock, seccomp, privilege drop) are applied inside
        // `spawn_workload`'s pre-exec ceiling, before the first untrusted
        // instruction.
        let agent: Arc<dyn BoundaryProcess> = if config.process_enabled {
            let spec = &sandbox.agent;
            let ca_file_paths = networking.as_ref().and_then(|n| n.ca_file_paths.clone());
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
                config.process_enforcement_mode,
                config.entrypoint_pid.clone(),
                // No sidecar control channel awaits the in-pod entrypoint PID.
                None,
                config.provider_credentials.clone(),
                provider_env,
                ca_file_paths,
                #[cfg(target_os = "linux")]
                netns.as_ref(),
                #[cfg(target_os = "linux")]
                bypass_denial_tx,
                #[cfg(target_os = "linux")]
                bypass_activity_tx,
            )
            .await
            .map_err(|e| BackendError::Process(e.to_string()))?;

            Arc::new(InPodAgentProcess::running(spawned))
        } else {
            // Network-only (sidecar/legacy) mode: no workload in this pod. The
            // boundary is held open until a shutdown signal. This is a legacy
            // split mode, not a gated external workload.
            Arc::new(InPodAgentProcess::hold_open())
        };

        Ok(Box::new(InPodRunning {
            agent,
            exec,
            port_forward,
            _networking: networking,
            #[cfg(target_os = "linux")]
            _netns: netns,
        }))
    }
}

/// Running: the agent is runnable behind the boundary. Exec, forwarding, wait,
/// and signal are available. The mediation ingress was retained by the
/// supervisor from the `Bound` state.
struct InPodRunning {
    agent: Arc<dyn BoundaryProcess>,
    exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryPortForward>,
    /// Held to keep the proxy task and network namespace alive for the boundary's
    /// life; dropping the running state tears them down (RAII), which is the
    /// backend reclaiming backend-private state — the contract defines no public
    /// cleanup transition.
    _networking: Option<Networking>,
    #[cfg(target_os = "linux")]
    _netns: Option<NetworkNamespace>,
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
    pid: Option<u32>,
    signaler: Option<AgentSignaler>,
    waiter: tokio::sync::Mutex<AgentWaitState>,
}

enum AgentWaitState {
    Running(SpawnedAgent),
    HoldOpen,
    Done(BoundaryExitStatus),
}

impl InPodAgentProcess {
    fn running(spawned: SpawnedAgent) -> Self {
        Self {
            pid: Some(spawned.pid()),
            signaler: Some(spawned.signaler()),
            waiter: tokio::sync::Mutex::new(AgentWaitState::Running(spawned)),
        }
    }

    fn hold_open() -> Self {
        Self {
            pid: None,
            signaler: None,
            waiter: tokio::sync::Mutex::new(AgentWaitState::HoldOpen),
        }
    }
}

#[async_trait]
impl BoundaryProcess for InPodAgentProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        // Holding the lock across the wait serializes repeated callers: the first
        // performs the wait and caches the status; later callers block on the
        // lock, then observe the cached `Done`. Signals never take this lock.
        let mut guard = self.waiter.lock().await;
        match &mut *guard {
            AgentWaitState::Done(status) => Ok(*status),
            AgentWaitState::HoldOpen => {
                crate::wait_for_shutdown_signal().await;
                let status = BoundaryExitStatus::Exited(0);
                *guard = AgentWaitState::Done(status);
                Ok(status)
            }
            AgentWaitState::Running(agent) => {
                let code = agent
                    .wait()
                    .await
                    .map_err(|e| BackendError::Process(e.to_string()))?;
                let status = BoundaryExitStatus::Exited(code);
                *guard = AgentWaitState::Done(status);
                Ok(status)
            }
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
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

// ============================================================================
// Exec (SSH adoption pending)
// ============================================================================

/// In-pod exec interface. The live SSH server still spawns workload shells
/// directly (inside `spawn_workload`); routing those through an owned
/// [`ExecSession`] (stdio/PTY/wait) is the remaining live-adoption refactor, so
/// this returns an explicit error rather than a half-wired session.
struct InPodExec;

#[async_trait]
impl BoundaryExec for InPodExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Process(
            "in-pod BoundaryExec is not yet the live SSH exec path; SSH execs directly. \
             Wiring ExecSession stdio/PTY through this interface is pending (see POC handoff)."
                .to_string(),
        ))
    }
}

/// In-pod mediation ingress. The live in-pod proxy still accepts workload
/// connections on its own listener inside the netns and resolves identity
/// inline; routing those through `accept` — so every connection carries this
/// resolver's per-connection [`BinaryIdentity`] result, and a delegated backend
/// can deliver connections over its private transport instead — is the
/// remaining live-adoption refactor, so this returns an explicit error rather
/// than a competing accept loop.
///
/// [`BinaryIdentity`]: openshell_isolation::contract::BinaryIdentity
struct InPodMediationIngress {
    /// The per-connection resolver the adopted accept path will consult.
    _identity: ProcfsIdentityResolver,
}

#[async_trait]
impl MediationIngress for InPodMediationIngress {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        Err(BackendError::Process(
            "in-pod MediationIngress is not yet the live proxy connection source; \
             the proxy accepts directly (see POC handoff)."
                .to_string(),
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

    /// A minimal in-pod config with networking and the workload disabled, so the
    /// lifecycle runs without root, a network namespace, or a gateway.
    fn minimal_config() -> InPodConfig {
        InPodConfig {
            network_enabled: false,
            process_enabled: false,
            opa_engine: None,
            retained_proto: None,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            provider_credentials: ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            provider_env: Mutex::new(HashMap::new()),
            process_enforcement_mode: ProcessEnforcementMode::Full,
            sandbox_name: None,
            openshell_endpoint: None,
            inference_routes: None,
            ssh_socket_path: None,
            workspace_rx: tokio::sync::watch::channel(String::new()).1,
            denial_tx: Mutex::new(None),
            activity_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_denial_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_activity_tx: Mutex::new(None),
            policy_local_slot: Arc::new(Mutex::new(None)),
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
            backend_id: IN_POD_BACKEND_ID.to_string(),
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

    // ----- Factory and registry -----

    #[test]
    fn factory_speaks_the_contract_version() {
        let factory = InPodBackendFactory::new(minimal_config());
        assert_eq!(factory.backend_id(), IN_POD_BACKEND_ID);
        assert_eq!(factory.contract_version(), CONTRACT_VERSION);
    }

    #[test]
    fn registry_selects_in_pod_backend() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, _verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");
        assert_eq!(factory.backend_id(), IN_POD_BACKEND_ID);
    }

    #[test]
    fn registry_rejects_duplicate_in_pod() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("first register");
        assert!(
            registry
                .register(Arc::new(InPodBackendFactory::new(minimal_config())))
                .is_err()
        );
    }

    #[test]
    fn registry_rejects_admission_mismatch() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
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
    /// the retained mediation ingress survives the consuming transitions.
    #[tokio::test]
    async fn lifecycle_reaches_ready_and_retains_ingress() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");

        let bound = factory
            .attach(verified, sandbox_context())
            .await
            .expect("attach");
        let ingress = bound.mediation_ingress();
        let _ready = bound.confirm().await.expect("confirm");
        // The retained ingress remains usable after `Bound` is consumed; the
        // in-pod accept adoption is pending, so it reports an explicit error
        // rather than a half-wired connection.
        assert!(ingress.accept().await.is_err());
    }

    /// `attach` is atomic and never binds a resource that is already bound to an
    /// active boundary: the in-pod resource binds exactly once.
    #[tokio::test]
    async fn second_attach_is_denied() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");

        let (factory, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");
        let _bound = factory
            .attach(verified, sandbox_context())
            .await
            .expect("first attach");

        let (_factory2, verified2) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("re-resolve");
        let err = factory
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
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let bad = TopologyDescriptor {
            contract_version: CONTRACT_VERSION,
            backend_id: IN_POD_BACKEND_ID.to_string(),
            payload: vec![1, 2, 3],
        };
        let (factory, verified) = registry.resolve(bad, IN_POD_BACKEND_ID).expect("resolve");
        let err = factory
            .attach(verified, sandbox_context())
            .await
            .map(|_| ())
            .expect_err("payload must be rejected");
        assert!(matches!(err, BackendError::Descriptor(_)));
    }
}
