// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side RFC 0012 backend for an already-provisioned remote boundary.

#[cfg(test)]
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::backend_proto::{
    DescribeIsolationBackendRequest, OpenBoundaryRequest, ResumeBoundaryRequest,
    SuspendBoundaryRequest, isolation_backend_client::IsolationBackendClient,
    open_boundary_response::LaunchOutcome,
};
#[cfg(test)]
use crate::isolation_protocol::{chunk_data, data_chunk};
use crate::proto::{ExchangeFrame, MediateFrame, sandbox_protocol_client::SandboxProtocolClient};
use crate::stream_adapter::ProtocolFrame;
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use openshell_isolation_interface::AgentSpec;
use openshell_isolation_interface::contract::{
    BackendDescriptor, BackendError, BoundaryConfirmation, BoundaryDuplexStream,
    BoundaryExitStatus, BoundaryInput, BoundaryOutput, BoundarySignal, ExecSpec, LoopbackTarget,
    MediationTiming, PendingDnsQuery, PendingTcpOpen, ProviderEnvironmentInstallation,
    ResolvedWorkloadIdentity, SandboxContext, TcpOpenDecision, TcpOpenDenial,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;

use crate::boundary_protocol::{
    AgentSpecWire, DnsQueryResultWire, EXEC_REQUEST_RETRY_WINDOW, ExecSpecWire, ExitStatusWire,
    MAX_CONTROL_FRAME_BYTES, Request, RequestEnvelope, Response, ResponseEnvelope, STREAM_EXIT,
    STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED, STREAM_STDOUT, SandboxPolicyWire,
    SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport, SignalWire, decode_frame,
    encode_frame, read_stream_frame, validate_resource_claims, write_stream_frame,
};
use crate::mediation::{self, DnsQueryWire, MediationFrame, MediationFrameKind};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Initial attachment may include runtime image pulls and trusted bootstrap
/// work before the boundary begins listening. Keep this aligned with the
/// driver bootstrap grace period rather than the normal operation timeout.
const ATTACH_REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
/// How long one control call keeps retrying boundary connect attempts. Boot-time
/// callers retry whole calls above this; past boot, exhausting this window
/// means the remote boundary (or its launcher) is gone rather than still starting.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on a routed sandbox instance's first connection. The instance is
/// registered before its workload Pod is scheduled and its image pulled; the
/// driver reaps a bootstrap that is still incomplete after the same interval.
const ROUTED_FIRST_CONNECT_TIMEOUT: Duration = Duration::from_mins(5);
/// Bounds the liveness check that decides whether a stream failure lost the
/// whole connection.
const CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Relay and pending-accept streams share the boundary's concurrent stream
/// limit with exec and control exchanges; leave the remainder for those.
const MAX_NETWORK_STREAMS: usize = 96;
const _: () = assert!(
    MAX_NETWORK_STREAMS < crate::boundary_protocol::BOUNDARY_MAX_CONCURRENT_STREAMS as usize
);
const NETWORK_STREAM_WAIT_WARNING: Duration = Duration::from_secs(5);
/// Bound on waiting for a replaced owner's process attachment to be released
/// after a takeover retires its connection.
const ADOPTED_ATTACHMENT_RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

fn begin_recovery_window(
    deadline: &mut Option<tokio::time::Instant>,
    failure_time: tokio::time::Instant,
) -> tokio::time::Instant {
    *deadline.get_or_insert(failure_time + CONNECT_RETRY_TIMEOUT)
}

/// Internal raw transport establishment; shared code still authenticates
/// the resulting stream with generation-pinned TLS and Sandbox Protocol JWTs.
#[async_trait]
pub trait BoundaryTransportConnector: std::fmt::Debug + Send + Sync {
    async fn connect(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError>;
}

/// How the supervisor obtains each physical Sandbox Protocol connection.
///
/// Choose it once per runtime descriptor and share clones between policy
/// discovery and attachment. Every stream, whatever its source, completes the
/// descriptor's pinned TLS handshake in [`authenticate_boundary_stream`]
/// before it carries a request.
#[derive(Clone, Debug, Default)]
pub struct BoundaryTransport(TransportSource);

#[derive(Clone, Debug, Default)]
enum TransportSource {
    /// Dial the descriptor's endpoint.
    #[default]
    Dial,
    /// Obtain raw streams from a backend-owned connector.
    Connector(Arc<dyn BoundaryTransportConnector>),
    /// Accept streams the sandbox runtime opens to this supervisor.
    RuntimeInitiated(Arc<crate::runtime_initiated::RuntimeInitiatedListener>),
    /// Accept streams routed to this sandbox instance by a shared listener.
    Routed(Arc<crate::runtime_routed::RouteRegistration>),
}

impl BoundaryTransport {
    /// Select the transport the descriptor requires. A runtime-initiated
    /// descriptor binds its control listener, so call this inside the
    /// supervisor's Tokio runtime.
    pub fn for_descriptor(descriptor: &SandboxRuntimeDescriptor) -> Result<Self, BackendError> {
        Ok(Self(match descriptor.transport {
            SandboxTransport::RuntimeInitiatedTcp { .. }
            | SandboxTransport::RuntimeInitiatedUnix { .. }
            | SandboxTransport::RuntimeInitiatedVsock { .. } => TransportSource::RuntimeInitiated(
                crate::runtime_initiated::RuntimeInitiatedListener::bind(descriptor)?,
            ),
            SandboxTransport::RuntimeInitiatedRouted { .. } => {
                return Err(BackendError::Descriptor(
                    "a routed runtime-initiated transport requires a shared runtime listener"
                        .to_string(),
                ));
            }
            _ => TransportSource::Dial,
        }))
    }

    /// Accept the connections a shared listener routes to one sandbox
    /// instance. The registration's handle must be the descriptor's route.
    pub fn routed(
        descriptor: &SandboxRuntimeDescriptor,
        registration: Arc<crate::runtime_routed::RouteRegistration>,
    ) -> Result<Self, BackendError> {
        match &descriptor.transport {
            SandboxTransport::RuntimeInitiatedRouted { route, .. }
                if route == registration.handle() =>
            {
                Ok(Self(TransportSource::Routed(registration)))
            }
            _ => Err(BackendError::Descriptor(
                "runtime descriptor does not use this sandbox instance's route".to_string(),
            )),
        }
    }

    /// Establish raw streams through a backend-owned connector.
    #[must_use]
    pub fn connector(connector: Arc<dyn BoundaryTransportConnector>) -> Self {
        Self(TransportSource::Connector(connector))
    }

    /// Open one authenticated physical connection, retrying within the
    /// connect window while the remote boundary starts.
    async fn connect(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        let connector = match &self.0 {
            TransportSource::Dial => None,
            TransportSource::Connector(connector) => Some(connector.as_ref()),
            TransportSource::RuntimeInitiated(listener) => {
                return tokio::time::timeout(CONNECT_RETRY_TIMEOUT, listener.accept(descriptor))
                    .await
                    .map_err(|_| {
                        BackendError::Unavailable(
                            "timed out waiting for the sandbox runtime to connect".to_string(),
                        )
                    })?;
            }
            TransportSource::Routed(registration) => {
                let window = if registration.has_connected() {
                    CONNECT_RETRY_TIMEOUT
                } else {
                    ROUTED_FIRST_CONNECT_TIMEOUT
                };
                return tokio::time::timeout(window, registration.accept(&descriptor.tls))
                    .await
                    .map_err(|_| {
                        BackendError::Unavailable(
                            "timed out waiting for the sandbox runtime to connect".to_string(),
                        )
                    })?;
            }
        };
        let deadline = tokio::time::Instant::now() + CONNECT_RETRY_TIMEOUT;
        loop {
            match connect_boundary_using_connector(descriptor, connector).await {
                Ok(stream) => return Ok(stream),
                Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }
}

/// Largest restore reference the supervisor accepts from a backend or driver.
pub const MAX_RESTORE_REFERENCE_BYTES: usize = 64 * 1024;

/// Restore a suspended boundary instead of opening a fresh one.
///
/// Every boundary opening for this launch, including policy discovery and
/// transport recovery, replays the same `ResumeBoundary` request.
#[derive(Clone)]
pub struct ResumeLaunch {
    restore_reference: Vec<u8>,
    restart_if_restore_fails: bool,
}

impl ResumeLaunch {
    /// Reject empty or oversized references before any backend call.
    pub fn new(
        restore_reference: Vec<u8>,
        restart_if_restore_fails: bool,
    ) -> Result<Self, BackendError> {
        if restore_reference.is_empty() {
            return Err(BackendError::Descriptor(
                "restore reference is empty".to_string(),
            ));
        }
        if restore_reference.len() > MAX_RESTORE_REFERENCE_BYTES {
            return Err(BackendError::Descriptor(format!(
                "restore reference exceeds {MAX_RESTORE_REFERENCE_BYTES} bytes"
            )));
        }
        Ok(Self {
            restore_reference,
            restart_if_restore_fails,
        })
    }

    pub fn restart_if_restore_fails(&self) -> bool {
        self.restart_if_restore_fails
    }
}

impl std::fmt::Debug for ResumeLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeLaunch")
            .field("restore_reference", &"[REDACTED]")
            .field("restart_if_restore_fails", &self.restart_if_restore_fails)
            .finish()
    }
}

/// Authority for this supervisor process to replace the owner of a running
/// generation: the identity the gateway granted it and the signed grant.
///
/// The runtime stages the replacement at attach and promotes it at confirm;
/// a runtime that does not advertise
/// [`crate::isolation_protocol::SUPERVISOR_TAKEOVER_CAPABILITY`] is refused
/// before the grant is sent.
#[derive(Clone)]
pub struct BoundaryTakeover {
    pub supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    pub grant: openshell_core::jwt::SecretJwt,
}

impl std::fmt::Debug for BoundaryTakeover {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundaryTakeover")
            .field("supervisor_instance_id", &self.supervisor_instance_id)
            .field("grant", &self.grant)
            .finish()
    }
}

/// The selected launch path; restoration may still await `StartAgent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryLaunchOutcome {
    Fresh,
    Restored,
    ColdStartFallback,
}

impl BoundaryLaunchOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Restored => "restored",
            Self::ColdStartFallback => "cold_start_fallback",
        }
    }
}

/// Accept only the outcomes the requested launch mode permits.
fn validate_launch_outcome(
    outcome: i32,
    resume: Option<&ResumeLaunch>,
    driver_managed_restore: bool,
) -> Result<BoundaryLaunchOutcome, BackendError> {
    let outcome = LaunchOutcome::try_from(outcome).unwrap_or(LaunchOutcome::Unspecified);
    match (resume, outcome) {
        (None, LaunchOutcome::Fresh) => Ok(BoundaryLaunchOutcome::Fresh),
        (None, LaunchOutcome::Restored) if driver_managed_restore => {
            Ok(BoundaryLaunchOutcome::Restored)
        }
        (None, LaunchOutcome::ColdStartFallback) if driver_managed_restore => {
            Ok(BoundaryLaunchOutcome::ColdStartFallback)
        }
        (None, _) => Err(BackendError::Descriptor(
            "invalid fresh boundary opening response".to_string(),
        )),
        (Some(_), LaunchOutcome::Restored) => Ok(BoundaryLaunchOutcome::Restored),
        (Some(resume), LaunchOutcome::ColdStartFallback) if resume.restart_if_restore_fails => {
            Ok(BoundaryLaunchOutcome::ColdStartFallback)
        }
        (Some(_), LaunchOutcome::ColdStartFallback) => Err(BackendError::Descriptor(
            "backend reported a cold-start fallback that was not permitted".to_string(),
        )),
        (Some(_), _) => Err(BackendError::Descriptor(
            "invalid boundary resume response outcome".to_string(),
        )),
    }
}

/// Concrete RPC client used for both in-tree and endpoint-registered backends.
#[derive(Debug)]
pub struct OpenShellRuntimeBackend {
    transport: BoundaryTransport,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    delegated: Option<DelegatedRuntime>,
    resume: Option<ResumeLaunch>,
    takeover: Option<BoundaryTakeover>,
    recovery_timeout_secs: Option<u32>,
}

#[derive(Clone)]
struct DelegatedRuntime {
    backend_name: String,
    descriptor: SandboxRuntimeDescriptor,
    driver_descriptor: Vec<u8>,
}

impl std::fmt::Debug for DelegatedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedRuntime")
            .field("backend_name", &self.backend_name)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl OpenShellRuntimeBackend {
    /// Read the workload image policy over the authenticated boundary before admission.
    pub async fn discover_policy(
        descriptor: SandboxRuntimeDescriptor,
        bearer: openshell_core::jwt::SessionBearerTokenSlot,
        transport: BoundaryTransport,
    ) -> Result<(Option<String>, bool), BackendError> {
        let mut client = BoundaryClient::new(descriptor, bearer);
        client.transport = transport;
        client.discover_policy().await
    }

    pub fn new(
        ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Self {
        Self {
            transport: BoundaryTransport::default(),
            ca_file_paths,
            provider_credentials,
            sandbox_bearer,
            delegated: None,
            resume: None,
            takeover: None,
            recovery_timeout_secs: None,
        }
    }

    /// Restore a suspended boundary rather than opening a fresh one.
    #[must_use]
    pub fn with_resume(mut self, resume: Option<ResumeLaunch>) -> Self {
        self.resume = resume;
        self
    }

    /// Construct the same RPC client for an operator-registered backend.
    pub fn registered(
        backend_name: String,
        descriptor: SandboxRuntimeDescriptor,
        driver_descriptor: Vec<u8>,
        ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Result<Self, BackendError> {
        crate::delegated::validate_backend_name(&backend_name)?;
        validate_runtime_coordinates(&descriptor)?;
        let mut backend = Self::new(ca_file_paths, provider_credentials, sandbox_bearer);
        backend.delegated = Some(DelegatedRuntime {
            backend_name,
            descriptor,
            driver_descriptor,
        });
        Ok(backend)
    }

    /// Discover policy using the registered endpoint and opaque driver payload.
    pub async fn discover_registered_policy(
        backend_name: String,
        descriptor: SandboxRuntimeDescriptor,
        driver_descriptor: Vec<u8>,
        bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Result<(Option<String>, bool), BackendError> {
        Self::discover_registered_policy_with_resume(
            backend_name,
            descriptor,
            driver_descriptor,
            bearer,
            None,
        )
        .await
    }

    /// Discover policy for a launch that may restore a suspended boundary.
    pub async fn discover_registered_policy_with_resume(
        backend_name: String,
        descriptor: SandboxRuntimeDescriptor,
        driver_descriptor: Vec<u8>,
        bearer: openshell_core::jwt::SessionBearerTokenSlot,
        resume: Option<ResumeLaunch>,
    ) -> Result<(Option<String>, bool), BackendError> {
        crate::delegated::validate_backend_name(&backend_name)?;
        validate_runtime_coordinates(&descriptor)?;
        let mut client =
            BoundaryClient::with_backend(descriptor, bearer, backend_name, driver_descriptor);
        client.resume = resume;
        client.discover_policy().await
    }

    /// Use the transport selected for the descriptor this backend will attach.
    #[must_use]
    pub fn with_transport(mut self, transport: BoundaryTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Attach as the gateway-granted replacement of the generation's current
    /// owner. The runtime's process snapshot then decides whether the agent
    /// is adopted or, for a runtime that never started it, launched.
    #[must_use]
    pub fn with_takeover(mut self, takeover: BoundaryTakeover) -> Self {
        self.takeover = Some(takeover);
        self
    }

    /// Offer the runtime a recovery deadline on every attach: how long it
    /// keeps the workload frozen after losing this supervisor's connection
    /// (see [`crate::boundary_protocol::SUPERVISOR_RECOVERY_TIMEOUT_RANGE`]).
    /// `None` leaves the runtime's default.
    #[must_use]
    pub fn with_recovery_timeout_secs(mut self, seconds: Option<u32>) -> Self {
        self.recovery_timeout_secs = seconds;
        self
    }

    pub fn backend_name(&self) -> &str {
        self.delegated
            .as_ref()
            .map_or(crate::BACKEND_NAME, |backend| backend.backend_name.as_str())
    }

    pub async fn attach(
        &self,
        descriptor: BackendDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<BoundBoundary>, BackendError> {
        if descriptor.backend_name != self.backend_name() {
            return Err(BackendError::Descriptor(
                "backend descriptor name does not match selected backend".to_string(),
            ));
        }
        let runtime_descriptor = if let Some(delegated) = &self.delegated {
            if descriptor.payload != delegated.driver_descriptor {
                return Err(BackendError::Descriptor(
                    "backend payload changed after trusted selection".to_string(),
                ));
            }
            delegated.descriptor.clone()
        } else {
            serde_json::from_slice::<SandboxRuntimeDescriptor>(&descriptor.payload).map_err(
                |error| BackendError::Descriptor(format!("decode runtime descriptor: {error}")),
            )?
        };
        validate_runtime_descriptor(&runtime_descriptor, &sandbox)?;
        let host_gateway_ip = runtime_descriptor.host_gateway_ip;
        let resource_claims = runtime_descriptor.resource_claims.clone();
        let generation = runtime_descriptor.generation.clone();
        let session_id = runtime_descriptor.session_id;
        let provisioning_evidence = runtime_descriptor.provisioning_evidence.clone();
        let mut client = BoundaryClient::with_backend(
            runtime_descriptor,
            self.sandbox_bearer.clone(),
            self.backend_name().to_string(),
            descriptor.payload.clone(),
        );
        client.transport = self.transport.clone();
        client.resume.clone_from(&self.resume);
        if let Some(takeover) = &self.takeover {
            client.supervisor_instance_id = takeover.supervisor_instance_id;
            client.requires_takeover = true;
        }
        client.recovery_timeout_secs = self.recovery_timeout_secs;
        let client = Arc::new(client);
        let policy = Box::new(SandboxPolicyWire::from(sandbox.policy.clone()));
        let response = client
            .call_idempotent(Request::Attach {
                supervisor_instance_id: client.supervisor_instance_id,
                policy: policy.clone(),
                supervisor_takeover: self
                    .takeover
                    .as_ref()
                    .map(|takeover| takeover.grant.expose_secret().to_string()),
                supervisor_recovery_timeout_secs: client.recovery_timeout_secs,
            })
            .await?;
        let Response::Attached { snapshot } = response else {
            return Err(unexpected_response("attached", &response));
        };
        if snapshot.generation != generation {
            return Err(BackendError::Confirm(
                "sandbox session snapshot generation does not match runtime descriptor".to_string(),
            ));
        }
        let takeover = self.takeover.is_some().then(|| RecoveredSession {
            // Later reconnects reattach without the grant, with the launch
            // controls the runtime already enforces.
            reattach_policy: snapshot.bound_policy.clone().unwrap_or(policy),
            processes: RecoveredProcesses::from_snapshot(&snapshot),
        });
        Ok(Box::new(BoundBoundary {
            client: client.clone(),
            agent: sandbox.agent,
            sandbox_id: sandbox.sandbox_id,
            mediation: Arc::new(NetworkMediationSource { client }),
            host_gateway_ip,
            ca_file_paths: self.ca_file_paths.clone(),
            provider_credentials: self.provider_credentials.clone(),
            identity: sandbox.identity,
            generation,
            session_id,
            resource_claims,
            provisioning_evidence,
            takeover,
        }))
    }
}

/// Processes a replacement supervisor found running in the runtime's
/// snapshot. They belong to the generation, not to the supervisor that
/// started them, so the replacement adopts them instead of launching again.
#[derive(Clone, Debug, Default)]
struct RecoveredProcesses {
    /// The canonical process, when the previous owner started it.
    main: Option<String>,
    /// Exec processes that have not exited.
    execs: Vec<String>,
}

impl RecoveredProcesses {
    fn from_snapshot(snapshot: &crate::boundary_protocol::SessionSnapshotWire) -> Self {
        use crate::boundary_protocol::ProcessKindWire;
        let mut recovered = Self::default();
        for process in &snapshot.processes {
            match process.kind {
                ProcessKindWire::Main => recovered.main = Some(process.process_id.clone()),
                ProcessKindWire::Exec if process.status.is_none() => {
                    recovered.execs.push(process.process_id.clone());
                }
                ProcessKindWire::Exec => {}
            }
        }
        recovered
    }
}

/// What a takeover attach learned from the runtime.
struct RecoveredSession {
    reattach_policy: Box<SandboxPolicyWire>,
    processes: RecoveredProcesses,
}

fn validate_runtime_descriptor(
    runtime_descriptor: &SandboxRuntimeDescriptor,
    sandbox: &SandboxContext,
) -> Result<(), BackendError> {
    if runtime_descriptor.boundary_id != sandbox.sandbox_id {
        return Err(BackendError::Descriptor(format!(
            "boundary {:?} does not match sandbox {:?}",
            runtime_descriptor.boundary_id, sandbox.sandbox_id
        )));
    }
    if runtime_descriptor.session_id != sandbox.session_id {
        return Err(BackendError::Descriptor(
            "runtime descriptor session ID does not match admitted sandbox session".to_string(),
        ));
    }
    if runtime_descriptor.workload_identity != sandbox.identity {
        return Err(BackendError::Descriptor(
            "runtime descriptor workload identity does not match admitted sandbox identity"
                .to_string(),
        ));
    }
    validate_runtime_coordinates(runtime_descriptor)
}

pub fn validate_runtime_coordinates(
    runtime_descriptor: &SandboxRuntimeDescriptor,
) -> Result<(), BackendError> {
    if runtime_descriptor.boundary_id.is_empty() || runtime_descriptor.generation.is_empty() {
        return Err(BackendError::Descriptor(
            "sandbox identity and generation are required".to_string(),
        ));
    }
    let identity = &runtime_descriptor.workload_identity;
    let normalized = ResolvedWorkloadIdentity::new(
        identity.uid,
        identity.gid,
        identity.supplementary_gids.clone(),
        identity.source.clone(),
        identity.resource_digest.clone(),
    )?;
    if normalized != *identity {
        return Err(BackendError::Descriptor(
            "workload identity is not canonical".into(),
        ));
    }
    validate_resource_claims(&runtime_descriptor.resource_claims)?;
    runtime_descriptor
        .provisioning_evidence
        .validate(&runtime_descriptor.generation)?;
    runtime_descriptor
        .transport
        .validate()
        .map_err(|error| BackendError::Descriptor(error.into()))?;
    validate_client_tls(&runtime_descriptor.tls)?;
    Ok(())
}

pub fn validate_client_tls(tls: &SandboxTlsClientConfig) -> Result<(), BackendError> {
    rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|error| {
        BackendError::Descriptor(format!(
            "boundary TLS server name {:?} is invalid: {error}",
            tls.server_name
        ))
    })?;
    tls_client_config(tls).map(|_| ())
}

fn tls_client_config(tls: &SandboxTlsClientConfig) -> Result<rustls::ClientConfig, BackendError> {
    openshell_crypto::tls::ensure_default_provider();
    let certificates = rustls_pemfile::certs(&mut tls.trust_anchor_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            BackendError::Descriptor(format!("parse boundary TLS CA certificate: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(BackendError::Descriptor(
            "boundary TLS CA certificate PEM contains no certificates".to_string(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|error| {
            BackendError::Descriptor(format!("load boundary TLS CA certificate: {error}"))
        })?;
    }
    let mut config =
        openshell_crypto::tls::client_builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

pub struct BoundBoundary {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    sandbox_id: String,
    mediation: Arc<NetworkMediationSource>,
    host_gateway_ip: Option<std::net::IpAddr>,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    identity: ResolvedWorkloadIdentity,
    generation: String,
    session_id: openshell_core::SandboxSessionId,
    resource_claims: std::collections::BTreeMap<String, String>,
    provisioning_evidence: openshell_isolation_interface::contract::ProvisioningEvidence,
    takeover: Option<RecoveredSession>,
}

impl BoundBoundary {
    /// The runtime's network opens. A source taken before [`Self::confirm`]
    /// waits for confirmation before accepting any, so a replacement can
    /// load its enforcement before the frozen workload resumes.
    pub fn network_mediation_source(&self) -> Arc<NetworkMediationSource> {
        self.mediation.clone()
    }

    /// Whether this boundary was attached as a gateway-granted replacement.
    #[must_use]
    pub fn is_takeover(&self) -> bool {
        self.takeover.is_some()
    }

    /// Whether the runtime already runs the canonical process, which a
    /// replacement adopts instead of starting.
    #[must_use]
    pub fn adopts_running_agent(&self) -> bool {
        self.takeover
            .as_ref()
            .is_some_and(|takeover| takeover.processes.main.is_some())
    }

    pub fn host_gateway_ip(&self) -> Option<std::net::IpAddr> {
        self.host_gateway_ip
    }

    /// The selected launch path. Restoration may still be deferred until
    /// `StartAgent`; this value alone does not prove the workload was restored.
    pub fn launch_outcome(&self) -> Option<BoundaryLaunchOutcome> {
        self.client.launch_outcome.get().copied()
    }

    /// Whether the negotiated backend advertised suspend/resume support.
    pub fn supports_suspend(&self) -> bool {
        self.client.backend_supports_suspend.load(Ordering::Acquire)
    }

    pub async fn confirm(self: Box<Self>) -> Result<ConfirmedBoundary, BackendError> {
        let response = self.client.call_idempotent(Request::Confirm).await?;
        let Response::Confirmed { confirmation } = response else {
            return Err(unexpected_response("confirmed", &response));
        };
        // A confirmed takeover pins this process at the granted epoch. From
        // now on a reconnect reattaches without the grant, so its expiry
        // cannot break transport recovery while confirmation is validated.
        let reattach_policy = self
            .takeover
            .as_ref()
            .map(|takeover| takeover.reattach_policy.clone());
        if let Some(policy) = &reattach_policy {
            self.client.forget_takeover_grant(policy.clone())?;
        }
        if confirmation.generation != self.generation
            || confirmation.session_id != self.session_id
            || confirmation.resource_claims != self.resource_claims
            || confirmation.provisioning_evidence_digest
                != self.provisioning_evidence.evidence_digest
        {
            return Err(BackendError::Confirm(
                "sandbox confirmation generation, session, resource claims, or provisioning evidence do not match runtime descriptor"
                    .to_string(),
            ));
        }
        if self.client.backend_name == crate::BACKEND_NAME {
            crate::audit::validate_native_linux_audit(&confirmation.backend_audit)?;
        }
        let client = self.client.clone();
        // Adopt from a snapshot taken after the promotion: the replaced owner
        // may have started processes after the takeover attach, and it can
        // start none once this process is promoted.
        let recovered = match reattach_policy {
            Some(policy) => Some(client.refresh_recovered_processes(policy).await?),
            None => None,
        };
        let confirmed = ConfirmedBoundary::try_new(
            Box::new(ReadyBoundary {
                client: self.client,
                agent: self.agent,
                sandbox_id: self.sandbox_id,
                ca_file_paths: self.ca_file_paths,
                provider_credentials: self.provider_credentials,
                recovered,
            }),
            *confirmation,
            &self.identity,
        )?;
        client.start_credential_monitor();
        Ok(confirmed)
    }
}

pub struct ReadyBoundary {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    sandbox_id: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    /// Processes found running by a takeover attach.
    recovered: Option<RecoveredProcesses>,
}

impl ReadyBoundary {
    /// Start the canonical process, or, for a replacement supervisor whose
    /// runtime already runs it, adopt it and the running exec processes
    /// without launching anything.
    pub async fn start_agent(self: Box<Self>) -> Result<Box<RunningBoundary>, BackendError> {
        if let Some(RecoveredProcesses {
            main: Some(process_id),
            execs,
        }) = &self.recovered
        {
            let adopted = |process_id: &String| {
                Arc::new(BoundaryProcess {
                    exec: true,
                    adopted: true,
                    client: self.client.clone(),
                    process_id: process_id.clone(),
                })
            };
            return Ok(Box::new(RunningBoundary {
                process: Arc::new(BoundaryProcess {
                    exec: false,
                    adopted: true,
                    client: self.client.clone(),
                    process_id: process_id.clone(),
                }),
                adopted_execs: execs.iter().map(adopted).collect(),
                exec: Arc::new(BoundaryExec {
                    client: self.client.clone(),
                    provider_credentials: self.provider_credentials,
                    // Publication restarts from the runtime's installed
                    // generation, which the first reconciliation learns.
                    publication_generation: tokio::sync::Mutex::new(0),
                }),
                loopback_connector: Arc::new(BoundaryLoopbackConnector {
                    client: self.client,
                }),
            }));
        }
        let ca_paths = self
            .ca_file_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (ca_cert, ca_bundle) = if let Some((ca_cert, ca_bundle)) = ca_paths {
            let ca_cert = tokio::fs::read_to_string(&ca_cert).await.map_err(|error| {
                BackendError::Process(format!("read host proxy CA {}: {error}", ca_cert.display()))
            })?;
            let ca_bundle = tokio::fs::read_to_string(&ca_bundle)
                .await
                .map_err(|error| {
                    BackendError::Process(format!(
                        "read host proxy CA bundle {}: {error}",
                        ca_bundle.display()
                    ))
                })?;
            (Some(ca_cert), Some(ca_bundle))
        } else {
            (None, None)
        };
        let provider_snapshot = self
            .provider_credentials
            .child_environment_snapshot()
            .map_err(|error| {
                BackendError::Process(format!("snapshot provider environment: {error}"))
            })?;
        let response = self
            .client
            .call_idempotent(Request::StartAgent {
                sandbox_id: self.sandbox_id,
                spec: AgentSpecWire::from(self.agent),
                ca_cert,
                ca_bundle,
                provider_env_revision: provider_snapshot.revision,
                provider_env: provider_snapshot.environment,
                provider_files: provider_snapshot.files,
            })
            .await?;
        let Response::Started {
            process_id,
            provider_env_generation,
            ..
        } = response
        else {
            return Err(unexpected_response("started", &response));
        };
        let process = Arc::new(BoundaryProcess {
            exec: false,
            adopted: false,
            client: self.client.clone(),
            process_id,
        });
        Ok(Box::new(RunningBoundary {
            process,
            adopted_execs: Vec::new(),
            exec: Arc::new(BoundaryExec {
                client: self.client.clone(),
                provider_credentials: self.provider_credentials,
                publication_generation: tokio::sync::Mutex::new(provider_env_generation),
            }),
            loopback_connector: Arc::new(BoundaryLoopbackConnector {
                client: self.client,
            }),
        }))
    }
}

pub struct RunningBoundary {
    process: Arc<BoundaryProcess>,
    /// Exec processes a replacement supervisor adopted from the runtime.
    adopted_execs: Vec<Arc<BoundaryProcess>>,
    exec: Arc<BoundaryExec>,
    loopback_connector: Arc<BoundaryLoopbackConnector>,
}

impl RunningBoundary {
    /// The launch path completed by the successful `StartAgent` call.
    pub fn launch_outcome(&self) -> Option<BoundaryLaunchOutcome> {
        self.process.client.launch_outcome.get().copied()
    }

    pub fn agent(&self) -> Arc<BoundaryProcess> {
        self.process.clone()
    }

    /// Whether the canonical process was adopted from a previous owner
    /// rather than started by this supervisor.
    #[must_use]
    pub fn agent_adopted(&self) -> bool {
        self.process.adopted
    }

    /// Running exec processes adopted from a previous owner. Their original
    /// clients are gone; the replacement observes their exit.
    #[must_use]
    pub fn adopted_exec_processes(&self) -> &[Arc<BoundaryProcess>] {
        &self.adopted_execs
    }

    pub fn exec(&self) -> Arc<BoundaryExec> {
        self.exec.clone()
    }

    pub fn loopback_connector(&self) -> Arc<BoundaryLoopbackConnector> {
        self.loopback_connector.clone()
    }

    pub async fn terminate(&self) -> Result<(), BackendError> {
        let response = self
            .process
            .client
            .call_idempotent(Request::TerminateBoundary)
            .await?;
        expect_response(response, "boundary_terminated")
    }

    /// Whether the negotiated backend advertised suspend/resume support.
    pub fn supports_suspend(&self) -> bool {
        self.process
            .client
            .backend_supports_suspend
            .load(Ordering::Acquire)
    }

    /// Freeze and fence this generation, returning the backend's opaque
    /// restore reference. The caller must not terminate the boundary after a
    /// successful suspension.
    pub async fn suspend(&self) -> Result<Vec<u8>, BackendError> {
        self.process.client.suspend_boundary().await
    }
}

pub struct BoundaryProcess {
    exec: bool,
    /// Started by a previous owner of the generation.
    adopted: bool,
    client: Arc<BoundaryClient>,
    process_id: String,
}

impl BoundaryProcess {
    /// Generation-scoped process ID.
    #[must_use]
    pub fn process_id(&self) -> &str {
        &self.process_id
    }

    pub async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        if !self.adopted {
            return open_process_attachment(self.client.clone(), self.process_id.clone()).await;
        }
        // The replaced owner's attachment ends with its retired connection;
        // wait a bounded time for the runtime to release it.
        let deadline = tokio::time::Instant::now() + ADOPTED_ATTACHMENT_RELEASE_TIMEOUT;
        loop {
            match open_process_attachment(self.client.clone(), self.process_id.clone()).await {
                Err(BackendError::Denied(message))
                    if message.contains("already has a control attachment")
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                result => return result,
            }
        }
    }

    pub async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let response = self
            .client
            .call_wait(Request::Wait {
                process_id: self.process_id.clone(),
            })
            .await
            .map_err(|error| match error {
                // A wait that can no longer reach the boundary leaf means the
                // boundary is gone, not that a retry could still observe the
                // exit status; report boundary loss per the contract.
                BackendError::Unavailable(message) => {
                    BackendError::Terminated(format!("boundary lost during wait: {message}"))
                }
                error => error,
            })?;
        let Response::Exited { status } = response else {
            return Err(unexpected_response("exited", &response));
        };
        Ok(status.into())
    }

    pub async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Signal {
                process_id: self.process_id.clone(),
                signal: SignalWire::from(signal),
            })
            .await?;
        expect_response(response, "signaled")
    }

    pub async fn terminate(&self) -> Result<(), BackendError> {
        if self.exec {
            return self.signal(BoundarySignal::Kill).await;
        }
        let response = self
            .client
            .call_idempotent(Request::Terminate {
                process_id: self.process_id.clone(),
            })
            .await?;
        expect_response(response, "terminated")
    }
}

async fn open_process_attachment(
    client: Arc<BoundaryClient>,
    process_id: String,
) -> Result<ProcessAttachment, BackendError> {
    let (stream, response) = client
        .call_stream(Request::AttachProcess {
            process_id: process_id.clone(),
        })
        .await?;
    let Response::ProcessAttached {
        terminal: has_terminal,
    } = response
    else {
        return Err(unexpected_response("process_attached", &response));
    };
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
    let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_process_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
        None,
    ));
    let terminal: Option<Arc<BoundaryTerminal>> = if has_terminal {
        let terminal: Arc<BoundaryTerminal> = Arc::new(BoundaryTerminal { client, process_id });
        Some(terminal)
    } else {
        None
    };
    let stderr: Option<BoundaryOutput> = if has_terminal {
        None
    } else {
        let stderr: BoundaryOutput = Box::new(stderr);
        Some(stderr)
    };
    Ok(ProcessAttachment {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr,
        terminal,
    })
}

async fn pump_process_responses(
    mut network: tokio::io::ReadHalf<BoundaryDuplexStream>,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
    completion: Option<tokio::sync::oneshot::Sender<BoundaryExitStatus>>,
) {
    let status = loop {
        match read_stream_frame(&mut network).await {
            Ok(Some((STREAM_STDOUT, payload))) => {
                if stdout.write_all(&payload).await.is_err() {
                    break BoundaryExitStatus::Exited(74);
                }
            }
            Ok(Some((STREAM_STDERR, payload))) => {
                if stderr.write_all(&payload).await.is_err() {
                    break BoundaryExitStatus::Exited(74);
                }
            }
            Ok(Some((STREAM_EXIT, payload))) => {
                break crate::protobuf::decode::<ExitStatusWire>(&payload)
                    .map_or(BoundaryExitStatus::Exited(74), Into::into);
            }
            Ok(None | Some(_)) | Err(_) => break BoundaryExitStatus::Exited(74),
        }
    };
    if let Some(completion) = completion {
        let _ = completion.send(status);
    }
}

pub struct BoundaryExec {
    client: Arc<BoundaryClient>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    // Shared by proactive synchronization and exec. Reserve generations before
    // dispatch so a timed-out request cannot overwrite a newer publication.
    publication_generation: tokio::sync::Mutex<u64>,
}

impl BoundaryExec {
    async fn synchronize(
        &self,
        generation: &mut u64,
    ) -> Result<ProviderEnvironmentInstallation, BackendError> {
        for _ in 0..3 {
            let snapshot = self
                .provider_credentials
                .child_environment_snapshot()
                .map_err(|error| {
                    BackendError::Process(format!("snapshot provider environment: {error}"))
                })?;
            *generation = generation.checked_add(1).ok_or_else(|| {
                BackendError::Process("provider environment publication exhausted".to_string())
            })?;
            let requested_generation = *generation;
            let response = self
                .client
                .call_idempotent(Request::UpdateProviderEnvironment {
                    generation: requested_generation,
                    revision: snapshot.revision,
                    provider_env: snapshot.environment,
                    provider_files: snapshot.files,
                })
                .await?;
            let Response::ProviderEnvironmentUpdated {
                revision: effective_revision,
                generation: effective_generation,
                applied,
            } = response
            else {
                return Err(unexpected_response(
                    "provider_environment_updated",
                    &response,
                ));
            };
            *generation = (*generation).max(effective_generation);
            if applied
                && effective_generation == requested_generation
                && effective_revision == snapshot.revision
            {
                // The acknowledgment is for the exact request, including its
                // map, even when a repaired map reuses a provider fingerprint.
                return Ok(ProviderEnvironmentInstallation {
                    installation_id: snapshot.installation_id,
                    revision: snapshot.revision,
                    session_id: self.client.runtime_descriptor.session_id,
                });
            }
        }
        Err(BackendError::Process(
            "boundary provider environment changed concurrently during reconciliation".to_string(),
        ))
    }
}

impl BoundaryExec {
    pub async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let mut generation = self.publication_generation.lock().await;
        self.synchronize(&mut generation).await?;
        open_exec_session(self.client.clone(), spec).await
    }

    pub async fn synchronize_provider_environment(
        &self,
    ) -> Result<ProviderEnvironmentInstallation, BackendError> {
        let mut generation = self.publication_generation.lock().await;
        self.synchronize(&mut generation).await
    }
}

pub struct BoundaryLoopbackConnector {
    client: Arc<BoundaryClient>,
}

impl BoundaryLoopbackConnector {
    pub async fn connect(
        &self,
        target: LoopbackTarget,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        let (stream, response) = self
            .client
            .call_stream(Request::LoopbackConnect {
                host: target.host(),
                port: target.port(),
            })
            .await?;
        match response {
            Response::LoopbackConnected => Ok(stream),
            response => Err(unexpected_response("loopback_connected", &response)),
        }
    }
}

pub struct BoundaryTerminal {
    client: Arc<BoundaryClient>,
    process_id: String,
}

impl BoundaryTerminal {
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Resize {
                process_id: self.process_id.clone(),
                cols,
                rows,
            })
            .await?;
        if matches!(response, Response::Resized) {
            Ok(())
        } else {
            Err(unexpected_response("resized", &response))
        }
    }
}

async fn open_exec_session(
    client: Arc<BoundaryClient>,
    spec: ExecSpec,
) -> Result<ExecSession, BackendError> {
    let (stream, response) = client
        .call_stream_idempotent(Request::Exec {
            spec: ExecSpecWire::from(spec),
        })
        .await?;
    let Response::ExecStarted { process_id, pty } = response else {
        return Err(unexpected_response("exec_started", &response));
    };
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
    let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
    let (output_status_tx, output_status_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_process_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
        Some(output_status_tx),
    ));

    let process: Arc<BoundaryProcess> = Arc::new(BoundaryProcess {
        exec: true,
        adopted: false,
        client: client.clone(),
        process_id: process_id.clone(),
    });
    let terminal: Option<Arc<BoundaryTerminal>> = if pty {
        Some(Arc::new(BoundaryTerminal { client, process_id }))
    } else {
        None
    };
    let stdin: BoundaryInput = Box::new(stdin);
    let stdout: BoundaryOutput = Box::new(stdout);
    let stderr: Option<BoundaryOutput> = if pty { None } else { Some(Box::new(stderr)) };
    Ok(ExecSession {
        process,
        stdin: Some(stdin),
        stdout,
        stderr,
        terminal,
        output_status: Some(output_status_rx),
    })
}

async fn pump_exec_input(
    mut input: tokio::io::DuplexStream,
    mut network: tokio::io::WriteHalf<BoundaryDuplexStream>,
) {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        match input.read(&mut buffer).await {
            Ok(0) => {
                let _ = write_stream_frame(&mut network, STREAM_STDIN_CLOSED, &[]).await;
                return;
            }
            Ok(read) => {
                if write_stream_frame(&mut network, STREAM_STDIN, &buffer[..read])
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Pulls boundary proxy connections over independent HTTP/2 streams.
///
/// DNS control messages share the compact persistent mediation
/// session, but TCP byte streams use HTTP/2's native multiplexing. Nesting all
/// TCP connections inside one application-level writer creates avoidable
/// head-of-line blocking during concurrent TLS handshakes.
pub struct NetworkMediationSource {
    client: Arc<BoundaryClient>,
}

impl NetworkMediationSource {
    /// Accepts reach the runtime only from a confirmed connection.
    async fn wait_confirmed(&self) {
        let _ = self
            .client
            .confirmed
            .subscribe()
            .wait_for(|confirmed| *confirmed)
            .await;
    }

    pub async fn accept_tcp(&self) -> Result<PendingTcpOpen, BackendError> {
        self.wait_confirmed().await;
        // An idle accept has no deadline. Recover transport loss before exposing
        // a source error, which permanently stops the proxy. The boundary drops
        // the interrupted pending open; a retry never replays its decision.
        // Pending accepts and live relays each hold a stream until the relay ends.
        let permit = self.client.acquire_network_stream().await;
        let (stream, response) = self.client.call_wait_stream(Request::AcceptNetwork).await?;
        let Response::NetworkConnected {
            identity,
            destination,
            socket,
            policy_generation,
            timing,
        } = response
        else {
            return Err(unexpected_response("network_connected", &response));
        };
        let (decision, completion) = tokio::sync::oneshot::channel();
        let (proxy_stream, transport_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            complete_network_open(stream, transport_stream, completion).await;
            drop(permit);
        });
        Ok(PendingTcpOpen {
            stream: Box::new(proxy_stream),
            binary_identity: identity.into_result(),
            destination,
            socket,
            policy_generation,
            timing: MediationTiming {
                sandbox_notification_to_queue: Duration::from_micros(
                    timing.notification_to_queue_us,
                ),
                sandbox_queue_wait: Duration::from_micros(timing.queue_wait_us),
                supervisor_received_at: Instant::now(),
            },
            decision,
        })
    }

    pub async fn accept_dns(&self) -> Result<PendingDnsQuery, BackendError> {
        self.wait_confirmed().await;
        loop {
            let session = self.client.mediation_session().await?;
            match session.accept_dns().await {
                Ok(query) => return Ok(query),
                Err(BackendError::Unavailable(_)) if !session.is_healthy() => {}
                Err(error) => return Err(error),
            }
        }
    }
}

async fn complete_network_open(
    mut boundary: BoundaryDuplexStream,
    mut transport: tokio::io::DuplexStream,
    completion: tokio::sync::oneshot::Receiver<TcpOpenDecision>,
) {
    let decision = completion
        .await
        .unwrap_or(TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable));
    let Ok(payload) = crate::protobuf::encode(&decision) else {
        return;
    };
    if write_stream_frame(
        &mut boundary,
        crate::boundary_protocol::STREAM_NETWORK_DECISION,
        &payload,
    )
    .await
    .is_err()
    {
        return;
    }
    if matches!(decision, TcpOpenDecision::RelayReady) {
        let _ = tokio::io::copy_bidirectional(&mut boundary, &mut transport).await;
    } else {
        // The write only queues the decision for the request pump. Dropping the
        // response stream now cancels the RPC before that pump can deliver it.
        // Close the request direction and wait for the backend to finish.
        let _ = tokio::time::timeout(REQUEST_TIMEOUT, async {
            boundary.shutdown().await?;
            boundary.read_u8().await
        })
        .await;
    }
}

const MEDIATION_EVENT_QUEUE: usize = 256;
struct OutboundMediationFrame {
    kind: MediationFrameKind,
    stream_id: u64,
    payload: Vec<u8>,
}

struct ClientMediationSession {
    dns: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<PendingDnsQuery>>,
    healthy: Arc<AtomicBool>,
}

impl ClientMediationSession {
    fn start(stream: BoundaryDuplexStream) -> Arc<Self> {
        let (dns_tx, dns_rx) = tokio::sync::mpsc::channel(MEDIATION_EVENT_QUEUE);
        let healthy = Arc::new(AtomicBool::new(true));
        let session = Arc::new(Self {
            dns: tokio::sync::Mutex::new(dns_rx),
            healthy: healthy.clone(),
        });
        tokio::spawn(async move {
            if let Err(error) = run_client_mediation(stream, dns_tx).await {
                tracing::debug!(%error, "persistent mediation session ended");
            }
            healthy.store(false, Ordering::Release);
        });
        session
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    async fn accept_dns(&self) -> Result<PendingDnsQuery, BackendError> {
        self.dns.lock().await.recv().await.ok_or_else(|| {
            BackendError::Unavailable("persistent DNS mediation session ended".to_string())
        })
    }
}

async fn run_client_mediation(
    stream: BoundaryDuplexStream,
    dns_tx: tokio::sync::mpsc::Sender<PendingDnsQuery>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) =
        tokio::sync::mpsc::channel::<OutboundMediationFrame>(MEDIATION_EVENT_QUEUE);
    let writer_task = async {
        while let Some(frame) = outbound_rx.recv().await {
            mediation::write_frame(&mut writer, frame.kind, frame.stream_id, &frame.payload)
                .await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let reader_task = async {
        while let Some(frame) = mediation::read_frame(&mut reader).await? {
            dispatch_client_mediation_frame(frame, &dns_tx, &outbound_tx).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::pin!(writer_task);
    tokio::pin!(reader_task);
    let result = tokio::select! {
        result = &mut writer_task => result,
        result = &mut reader_task => result,
    };
    result
}

async fn dispatch_client_mediation_frame(
    frame: MediationFrame,
    dns_tx: &tokio::sync::mpsc::Sender<PendingDnsQuery>,
    outbound: &tokio::sync::mpsc::Sender<OutboundMediationFrame>,
) -> std::io::Result<()> {
    match frame.kind {
        MediationFrameKind::DnsQuery => {
            let query: DnsQueryWire = mediation::decode_message(&frame.payload)?;
            let (response, completion) =
                tokio::sync::oneshot::channel::<Result<Vec<u8>, BackendError>>();
            let outbound = outbound.clone();
            tokio::spawn(async move {
                let response = match completion.await {
                    Ok(Ok(response)) => DnsQueryResultWire::Response(response),
                    Ok(Err(error)) => DnsQueryResultWire::Error(error.to_string()),
                    Err(_) => DnsQueryResultWire::Error(
                        "supervisor dropped the mediated DNS query".to_string(),
                    ),
                };
                if let Ok(payload) = mediation::encode_message(&response) {
                    let _ = outbound
                        .send(OutboundMediationFrame {
                            kind: MediationFrameKind::DnsResponse,
                            stream_id: frame.stream_id,
                            payload,
                        })
                        .await;
                }
            });
            dns_tx
                .send(PendingDnsQuery {
                    message: query.request,
                    transport: query.transport,
                    binary_identity: query.identity.into_result(),
                    timing: MediationTiming {
                        sandbox_notification_to_queue: Duration::from_micros(
                            query.timing.notification_to_queue_us,
                        ),
                        sandbox_queue_wait: Duration::from_micros(query.timing.queue_wait_us),
                        supervisor_received_at: Instant::now(),
                    },
                    response,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "DNS mediation consumer stopped",
                    )
                })?;
        }
        MediationFrameKind::DnsResponse => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unexpected supervisor-bound mediation frame {:?}",
                    frame.kind
                ),
            ));
        }
    }
    Ok(())
}

struct BoundaryClient {
    transport: BoundaryTransport,
    runtime_descriptor: SandboxRuntimeDescriptor,
    backend_name: String,
    driver_descriptor: Vec<u8>,
    boundary_handle: std::sync::OnceLock<String>,
    resume: Option<ResumeLaunch>,
    launch_outcome: std::sync::OnceLock<BoundaryLaunchOutcome>,
    backend_supports_suspend: AtomicBool,
    supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    grpc_channel: tokio::sync::Mutex<Option<CachedGrpcChannel>>,
    mediation: tokio::sync::Mutex<Option<Arc<ClientMediationSession>>>,
    mediation_open: tokio::sync::Mutex<()>,
    attach_request: std::sync::Mutex<Option<RequestEnvelope>>,
    confirm_request: std::sync::Mutex<Option<RequestEnvelope>>,
    reconnect: tokio::sync::Mutex<()>,
    next_connection_generation: AtomicU64,
    credential_monitor_started: AtomicBool,
    network_streams: Arc<tokio::sync::Semaphore>,
    network_streams_exhausted: AtomicBool,
    /// This client attaches with a takeover grant; the runtime must
    /// advertise takeover support before any request is sent.
    requires_takeover: bool,
    /// Recovery deadline offered on every attach.
    recovery_timeout_secs: Option<u32>,
    /// True once a connection of this client was confirmed.
    confirmed: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone)]
struct CachedGrpcChannel {
    credential_epoch: openshell_core::jwt::CredentialEpoch,
    bearer_fingerprint: [u8; 32],
    generation: u64,
    channel: tonic::transport::Channel,
    transport: Arc<TransportAbort>,
}

/// Closes a channel's physical transport so the boundary observes the
/// disconnect even while abandoned streams still hold channel clones.
#[derive(Default)]
struct TransportAbort {
    connected: AtomicBool,
    aborted: AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

impl TransportAbort {
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    /// Register before checking so an abort between the two still wakes us.
    fn poll_aborted(&self, context: &std::task::Context<'_>) -> bool {
        {
            let mut waker = self
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(context.waker()))
            {
                *waker = Some(context.waker().clone());
            }
        }
        self.is_aborted()
    }
}

struct AbortableTransport {
    inner: BoundaryDuplexStream,
    abort: Arc<TransportAbort>,
}

impl AbortableTransport {
    fn aborted_error() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "boundary transport replaced",
        )
    }
}

impl tokio::io::AsyncRead for AbortableTransport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.abort.poll_aborted(context) {
            return std::task::Poll::Ready(Err(Self::aborted_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for AbortableTransport {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.abort.poll_aborted(context) {
            return std::task::Poll::Ready(Err(Self::aborted_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.abort.poll_aborted(context) {
            return std::task::Poll::Ready(Err(Self::aborted_error()));
        }
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

// Cache only a digest; authenticate with the exact captured header so a
// concurrent renewal cannot be recorded before its credential is sent.
struct BoundaryCredential {
    epoch: openshell_core::jwt::CredentialEpoch,
    authorization: tonic::metadata::AsciiMetadataValue,
    fingerprint: [u8; 32],
}

impl BoundaryCredential {
    fn capture(slot: &openshell_core::jwt::SessionBearerTokenSlot) -> Result<Self, BackendError> {
        loop {
            let epoch = slot.credential_epoch().ok_or_else(|| {
                BackendError::Unavailable("Sandbox Protocol credential unavailable".to_string())
            })?;
            let authorization = slot.authorization_metadata().map_err(|error| {
                BackendError::Unavailable(format!(
                    "Sandbox Protocol credential unavailable: {error}"
                ))
            })?;
            // Epochs are monotonic; retry if authorization crossed an epoch change.
            if slot.credential_epoch() == Some(epoch) {
                let fingerprint = openshell_crypto::sha256(authorization.as_encoded_bytes())
                    .map_err(|error| BackendError::Unavailable(error.to_string()))?;
                return Ok(Self {
                    epoch,
                    authorization,
                    fingerprint,
                });
            }
        }
    }
}

impl BoundaryClient {
    async fn discover_policy(&self) -> Result<(Option<String>, bool), BackendError> {
        match self.call_idempotent(Request::DiscoverPolicy).await? {
            Response::ImagePolicy { yaml, invalid } => Ok((yaml, invalid)),
            _ => Err(BackendError::Descriptor(
                "expected image policy discovery response".to_string(),
            )),
        }
    }

    fn new(
        runtime_descriptor: SandboxRuntimeDescriptor,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    ) -> Self {
        let payload =
            serde_json::to_vec(&runtime_descriptor).expect("serializable runtime descriptor");
        Self::with_backend(
            runtime_descriptor,
            sandbox_bearer,
            crate::BACKEND_NAME.to_string(),
            payload,
        )
    }

    fn with_backend(
        runtime_descriptor: SandboxRuntimeDescriptor,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
        backend_name: String,
        driver_descriptor: Vec<u8>,
    ) -> Self {
        Self {
            transport: BoundaryTransport::default(),
            runtime_descriptor,
            backend_name,
            driver_descriptor,
            boundary_handle: std::sync::OnceLock::new(),
            resume: None,
            launch_outcome: std::sync::OnceLock::new(),
            backend_supports_suspend: AtomicBool::new(false),
            supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId::new(),
            sandbox_bearer,
            grpc_channel: tokio::sync::Mutex::new(None),
            mediation: tokio::sync::Mutex::new(None),
            mediation_open: tokio::sync::Mutex::new(()),
            attach_request: std::sync::Mutex::new(None),
            confirm_request: std::sync::Mutex::new(None),
            reconnect: tokio::sync::Mutex::new(()),
            next_connection_generation: AtomicU64::new(1),
            credential_monitor_started: AtomicBool::new(false),
            network_streams: Arc::new(tokio::sync::Semaphore::new(MAX_NETWORK_STREAMS)),
            network_streams_exhausted: AtomicBool::new(false),
            requires_takeover: false,
            recovery_timeout_secs: None,
            confirmed: tokio::sync::watch::Sender::new(false),
        }
    }

    /// Reattach on the confirmed connection as the promoted owner and read the
    /// processes to adopt from that snapshot.
    async fn refresh_recovered_processes(
        &self,
        policy: Box<SandboxPolicyWire>,
    ) -> Result<RecoveredProcesses, BackendError> {
        let response = self
            .call_idempotent(Request::Attach {
                supervisor_instance_id: self.supervisor_instance_id,
                policy,
                supervisor_takeover: None,
                supervisor_recovery_timeout_secs: self.recovery_timeout_secs,
            })
            .await?;
        let Response::Attached { snapshot } = response else {
            return Err(unexpected_response("attached", &response));
        };
        if snapshot.generation != self.runtime_descriptor.generation {
            return Err(BackendError::Confirm(
                "sandbox session snapshot generation does not match runtime descriptor".to_string(),
            ));
        }
        Ok(RecoveredProcesses::from_snapshot(&snapshot))
    }

    /// Replace the remembered takeover attach with an ordinary attach of the
    /// now-pinned process, so transport recovery never depends on the
    /// grant's lifetime.
    fn forget_takeover_grant(&self, policy: Box<SandboxPolicyWire>) -> Result<(), BackendError> {
        let envelope = Self::prepare_request(Request::Attach {
            supervisor_instance_id: self.supervisor_instance_id,
            policy,
            supervisor_takeover: None,
            supervisor_recovery_timeout_secs: self.recovery_timeout_secs,
        })?;
        *self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(envelope);
        Ok(())
    }

    async fn acquire_network_stream(&self) -> tokio::sync::OwnedSemaphorePermit {
        let acquire = self.network_streams.clone().acquire_owned();
        tokio::pin!(acquire);
        // Bursty clients briefly exceed the budget; only report sustained waits.
        let permit = if let Ok(permit) =
            tokio::time::timeout(NETWORK_STREAM_WAIT_WARNING, &mut acquire).await
        {
            self.network_streams_exhausted
                .store(false, Ordering::Relaxed);
            permit
        } else {
            if !self.network_streams_exhausted.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    limit = MAX_NETWORK_STREAMS,
                    "Sandbox network relay streams exhausted; new sandbox TCP connections are waiting for a relay to close"
                );
            }
            acquire.await
        };
        permit.expect("network stream semaphore is never closed")
    }

    async fn call_idempotent(&self, request: Request) -> Result<Response, BackendError> {
        let remember_attach = matches!(request, Request::Attach { .. });
        let remember_confirm = matches!(request, Request::Confirm);
        let timeout = if remember_attach || matches!(request, Request::DiscoverPolicy) {
            ATTACH_REQUEST_TIMEOUT
        } else {
            REQUEST_TIMEOUT
        };
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(timeout, async {
            loop {
                let generation = self.connection_generation().await;
                match self.exchange_envelope(&envelope).await {
                    Ok(response) => {
                        if remember_attach {
                            *self
                                .attach_request
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(envelope.clone());
                        }
                        if remember_confirm {
                            *self
                                .confirm_request
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(envelope.clone());
                            self.confirmed.send_replace(true);
                        }
                        return Ok(response);
                    }
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable(generation).await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable(
                "boundary idempotent control request timed out while waiting for remote boundary boot".to_string(),
            )
        })?
    }

    async fn call_wait(&self, request: Request) -> Result<Response, BackendError> {
        let (_, response) = self.call_wait_stream(request).await?;
        Ok(response)
    }

    /// Wait without an idle timeout, retaining the stream for TCP mediation.
    /// Only transport failures enter recovery; boundary rejections stay terminal.
    async fn call_wait_stream(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        let mut recovery_deadline = None;
        loop {
            let generation = self.connection_generation().await;
            match self.open_exchange_envelope(&envelope).await {
                Ok(response) => return Ok(response),
                Err(BackendError::Unavailable(message)) if is_transport_unavailable(&message) => {
                    let deadline =
                        begin_recovery_window(&mut recovery_deadline, tokio::time::Instant::now());
                    if tokio::time::Instant::now() >= deadline {
                        return Err(BackendError::Unavailable(message));
                    }
                    self.recover_after_unavailable(generation).await?;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn call_stream(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                let generation = self.connection_generation().await;
                match self.open_exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable(generation).await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| BackendError::Unavailable("boundary stream request timed out".to_string()))?
    }

    async fn call_stream_idempotent(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(EXEC_REQUEST_RETRY_WINDOW, async {
            loop {
                let generation = self.connection_generation().await;
                match self.open_exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable(generation).await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable(
                "exec startup recovery deadline expired; execution outcome may be unknown"
                    .to_string(),
            )
        })?
    }

    #[cfg(test)]
    async fn exchange(&self, request: Request) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange(request).await?;
        Ok(response)
    }

    fn prepare_request(request: Request) -> Result<RequestEnvelope, BackendError> {
        RequestEnvelope::new(request)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))
    }

    #[cfg(test)]
    async fn open_exchange(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        self.open_exchange_envelope(&envelope).await
    }

    async fn exchange_envelope(
        &self,
        envelope: &RequestEnvelope,
    ) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange_envelope(envelope).await?;
        Ok(response)
    }

    async fn open_exchange_envelope(
        &self,
        envelope: &RequestEnvelope,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let request_id = envelope.request_id.clone();
        let mut stream = self.open_grpc_stream(GrpcStreamKind::Exchange).await?;
        let frame = encode_frame(envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write boundary control request: {error}"))
        })?;
        // `tokio-rustls` may retain part of a large plaintext frame in its
        // internal TLS buffer. Flush before waiting for the response so the
        // synchronous boundary reader can receive the complete request.
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush boundary control request: {error}"))
        })?;
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(control_read_error)?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > MAX_CONTROL_FRAME_BYTES {
            return Err(BackendError::Process(format!(
                "boundary control response is too large: {declared} bytes"
            )));
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&header);
        frame.resize(4 + declared, 0);
        stream
            .read_exact(&mut frame[4..])
            .await
            .map_err(control_read_error)?;
        let response: ResponseEnvelope = decode_frame(&frame)
            .map_err(|error| BackendError::Process(format!("decode control response: {error}")))?;
        if response.request_id != request_id {
            return Err(BackendError::Process(format!(
                "boundary response ID {} did not match request ID {request_id}",
                response.request_id
            )));
        }
        let response = match response.response {
            Response::Error { kind, message } => Err(guest_error(kind, message)),
            response => Ok(response),
        }?;
        Ok((stream, response))
    }

    async fn open_grpc_stream(
        &self,
        kind: GrpcStreamKind,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        self.ensure_current_credential_connection().await?;
        let channel = self.grpc_channel().await?;
        open_grpc_client_stream(channel, kind, &self.sandbox_bearer, self.boundary_handle()?).await
    }

    async fn ensure_current_credential_connection(&self) -> Result<(), BackendError> {
        let credential = BoundaryCredential::capture(&self.sandbox_bearer)?;
        if self
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .is_none_or(|cached| {
                cached.credential_epoch == credential.epoch
                    && cached.bearer_fingerprint == credential.fingerprint
            })
        {
            return Ok(());
        }
        let _reconnect = self.reconnect.lock().await;
        let credential = BoundaryCredential::capture(&self.sandbox_bearer)?;
        let Some(cached) = self.grpc_channel.lock().await.clone() else {
            return Ok(());
        };
        if cached.credential_epoch == credential.epoch
            && cached.bearer_fingerprint == credential.fingerprint
        {
            return Ok(());
        }
        let confirm = self
            .confirm_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(confirm) = confirm else {
            // Initial attach/confirm authenticates before the monitor runs.
            return if cached.credential_epoch == credential.epoch {
                Ok(())
            } else {
                Err(BackendError::Unavailable(
                    "cannot rotate Sandbox Protocol connection before confirmation".to_string(),
                ))
            };
        };
        if cached.credential_epoch == credential.epoch {
            // Renewal preserves the authorization epoch, but the boundary's
            // connection deadline advances only on a newly authenticated RPC.
            // Reconfirm on this channel to preserve pending accepts and streams.
            let response = tokio::time::timeout(
                REQUEST_TIMEOUT,
                self.exchange_on_channel(cached.channel.clone(), &confirm, &credential),
            )
            .await
            .map_err(|_| {
                BackendError::Unavailable("boundary credential renewal timed out".to_string())
            })??;
            expect_response(response, "confirmed")?;
            if let Some(current) = self.grpc_channel.lock().await.as_mut()
                && current.generation == cached.generation
            {
                current.bearer_fingerprint = credential.fingerprint;
            }
            return Ok(());
        }
        let attach = self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                BackendError::Unavailable(
                    "cannot rotate Sandbox Protocol connection before attach".to_string(),
                )
            })?;
        let (channel, transport) = self
            .attach_new_channel(&attach, Some(&confirm), &credential)
            .await?;
        *self.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch: credential.epoch,
            bearer_fingerprint: credential.fingerprint,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel,
            transport,
        });
        *self.mediation.lock().await = None;
        Ok(())
    }

    async fn connection_generation(&self) -> Option<u64> {
        self.grpc_channel
            .lock()
            .await
            .as_ref()
            .map(|cached| cached.generation)
    }

    /// Replace a failed physical transport and replay its authenticated lifecycle.
    /// Capture the generation before the attempt: a late failure from an old
    /// connection must not retire one another caller has already recovered.
    async fn recover_after_unavailable(
        &self,
        observed_generation: Option<u64>,
    ) -> Result<(), BackendError> {
        let _reconnect = self.reconnect.lock().await;
        let cached = self.grpc_channel.lock().await.clone();
        if cached.as_ref().map(|cached| cached.generation) != observed_generation {
            return Ok(());
        }
        let confirm = self
            .confirm_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(cached) = &cached {
            // One failed stream does not prove the connection is gone. Keep a
            // live connection: the boundary rejects a same-epoch replacement
            // while it still considers the current connection active.
            if let Some(confirm) = &confirm
                && self.connection_is_live(cached, confirm).await
            {
                return Ok(());
            }
            cached.transport.abort();
        }

        *self.mediation.lock().await = None;
        let attach = self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(attach) = attach else {
            *self.grpc_channel.lock().await = None;
            return Ok(());
        };
        // Keep the aborted channel cached until the confirmed replacement is
        // swapped in. Concurrent callers then fail fast and wait on this
        // recovery instead of caching a connection that never attached.
        let credential = BoundaryCredential::capture(&self.sandbox_bearer)?;
        let deadline = tokio::time::Instant::now() + CONNECT_RETRY_TIMEOUT;
        let (channel, transport) = loop {
            match self
                .attach_new_channel(&attach, confirm.as_ref(), &credential)
                .await
            {
                Ok(attached) => break attached,
                // The boundary may not have retired the aborted connection yet.
                Err(BackendError::Unavailable(message))
                    if tokio::time::Instant::now() < deadline =>
                {
                    tracing::debug!(%message, "boundary reattach not accepted yet; retrying");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        };
        *self.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch: credential.epoch,
            bearer_fingerprint: credential.fingerprint,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel,
            transport,
        });
        Ok(())
    }

    async fn connection_is_live(
        &self,
        cached: &CachedGrpcChannel,
        confirm: &RequestEnvelope,
    ) -> bool {
        let Ok(credential) = BoundaryCredential::capture(&self.sandbox_bearer) else {
            return false;
        };
        matches!(
            tokio::time::timeout(
                CONNECTION_PROBE_TIMEOUT,
                self.exchange_on_channel(cached.channel.clone(), confirm, &credential),
            )
            .await,
            Ok(Ok(Response::Confirmed { .. }))
        )
    }

    /// Open a new physical connection and replay the authenticated lifecycle,
    /// closing the connection again if the boundary does not accept it.
    async fn attach_new_channel(
        &self,
        attach: &RequestEnvelope,
        confirm: Option<&RequestEnvelope>,
        credential: &BoundaryCredential,
    ) -> Result<(tonic::transport::Channel, Arc<TransportAbort>), BackendError> {
        let (channel, transport) = self.build_grpc_channel(credential).await?;
        let result = async {
            self.exchange_on_channel(channel.clone(), attach, credential)
                .await?;
            if let Some(confirm) = confirm {
                self.exchange_on_channel(channel.clone(), confirm, credential)
                    .await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            transport.abort();
            return Err(error);
        }
        Ok((channel, transport))
    }

    fn start_credential_monitor(self: &Arc<Self>) {
        if self.credential_monitor_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let client = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(client) = client.upgrade() else {
                    return;
                };
                if let Err(error) = client.ensure_current_credential_connection().await {
                    tracing::warn!(%error, "failed to rotate Sandbox Protocol connection");
                }
            }
        });
    }

    async fn exchange_on_channel(
        &self,
        channel: tonic::transport::Channel,
        envelope: &RequestEnvelope,
        credential: &BoundaryCredential,
    ) -> Result<Response, BackendError> {
        let request_id = envelope.request_id.clone();
        let mut stream = open_grpc_client_stream_with_authorization(
            channel,
            GrpcStreamKind::Exchange,
            credential.authorization.clone(),
            self.boundary_handle()?,
        )
        .await?;
        let frame = encode_frame(envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write boundary control request: {error}"))
        })?;
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush boundary control request: {error}"))
        })?;
        let response =
            crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut stream)
                .await
                .map_err(|error| match error {
                    crate::boundary_protocol::FrameError::Io(error) => control_read_error(error),
                    error => BackendError::Descriptor(format!("decode control response: {error}")),
                })?;
        if response.request_id != request_id {
            return Err(BackendError::Process(
                "boundary response ID did not match request ID".to_string(),
            ));
        }
        match response.response {
            Response::Error { kind, message } => Err(guest_error(kind, message)),
            response => Ok(response),
        }
    }

    async fn mediation_session(&self) -> Result<Arc<ClientMediationSession>, BackendError> {
        if let Some(session) = self.healthy_mediation_session().await {
            return Ok(session);
        }

        // Serialize creation without holding the cached-session mutex. Opening
        // a stream may rotate credentials or recover the physical connection;
        // both paths clear the cache and must be free to acquire that mutex.
        let _opening = self.mediation_open.lock().await;
        if let Some(session) = self.healthy_mediation_session().await {
            return Ok(session);
        }

        // The boundary owns exclusive-lease retirement and bounds replacement
        // waiting. Never multiply that deadline with message-matching retries.
        let session = tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                let generation = self.connection_generation().await;
                match self.open_mediation_session().await {
                    Ok(session) => return Ok(session),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable(generation).await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable("boundary mediation attach timed out".to_string())
        })??;
        *self.mediation.lock().await = Some(session.clone());
        Ok(session)
    }

    async fn healthy_mediation_session(&self) -> Option<Arc<ClientMediationSession>> {
        self.mediation
            .lock()
            .await
            .as_ref()
            .filter(|session| session.is_healthy())
            .cloned()
    }

    async fn open_mediation_session(&self) -> Result<Arc<ClientMediationSession>, BackendError> {
        let mut stream = self.open_grpc_stream(GrpcStreamKind::Mediate).await?;
        let envelope = Self::prepare_request(Request::OpenMediation)?;
        let request_id = envelope.request_id.clone();
        let frame = encode_frame(&envelope)
            .map_err(|error| BackendError::Process(format!("encode mediation attach: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write mediation attach: {error}"))
        })?;
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush mediation attach: {error}"))
        })?;
        let response =
            crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut stream)
                .await
                .map_err(|error| {
                    BackendError::Unavailable(format!("read mediation attach: {error}"))
                })?;
        if response.request_id != request_id {
            return Err(BackendError::Process(
                "mediation attach response ID did not match request".to_string(),
            ));
        }
        match response.response {
            Response::MediationReady => {}
            Response::Error { kind, message } => return Err(guest_error(kind, message)),
            response => return Err(unexpected_response("mediation_ready", &response)),
        }
        Ok(ClientMediationSession::start(stream))
    }

    async fn grpc_channel(&self) -> Result<tonic::transport::Channel, BackendError> {
        let mut state = self.grpc_channel.lock().await;
        if let Some(cached) = state.as_ref() {
            return Ok(cached.channel.clone());
        }
        let credential = BoundaryCredential::capture(&self.sandbox_bearer)?;
        let (channel, transport) = self.build_grpc_channel(&credential).await?;
        *state = Some(CachedGrpcChannel {
            credential_epoch: credential.epoch,
            bearer_fingerprint: credential.fingerprint,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel: channel.clone(),
            transport,
        });
        Ok(channel)
    }

    async fn build_grpc_channel(
        &self,
        credential: &BoundaryCredential,
    ) -> Result<(tonic::transport::Channel, Arc<TransportAbort>), BackendError> {
        let runtime_descriptor = self.runtime_descriptor.clone();
        let source = self.transport.clone();
        let transport = Arc::new(TransportAbort::default());
        let connector_transport = transport.clone();
        let authority = match &runtime_descriptor.transport {
            SandboxTransport::Tcp { authority, .. }
            | SandboxTransport::RuntimeInitiatedTcp { authority, .. }
            | SandboxTransport::RuntimeInitiatedRouted { authority, .. } => authority.as_str(),
            SandboxTransport::Unix { .. }
            | SandboxTransport::Vsock { .. }
            | SandboxTransport::RuntimeInitiatedUnix { .. }
            | SandboxTransport::RuntimeInitiatedVsock { .. } => "boundary.openshell.internal",
        };
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{authority}"))
            .map_err(|error| {
                BackendError::Descriptor(format!("invalid boundary authority: {error}"))
            })?
            .initial_stream_window_size(crate::boundary_protocol::BOUNDARY_STREAM_WINDOW_BYTES)
            .initial_connection_window_size(
                crate::boundary_protocol::BOUNDARY_CONNECTION_WINDOW_BYTES,
            )
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_while_idle(true);
        let channel = endpoint
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let runtime_descriptor = runtime_descriptor.clone();
                let source = source.clone();
                let abort = connector_transport.clone();
                async move {
                    // A channel is one authenticated connection. Never let it
                    // silently reconnect without replaying attach and confirm.
                    if abort.is_aborted() || abort.connected.swap(true, Ordering::AcqRel) {
                        return Err(AbortableTransport::aborted_error());
                    }
                    source
                        .connect(&runtime_descriptor)
                        .await
                        .map(|inner| TokioIo::new(AbortableTransport { inner, abort }))
                        .map_err(|error| std::io::Error::other(error.to_string()))
                }
            }))
            .await
            .map_err(|error| {
                BackendError::Unavailable(format!("start boundary gRPC channel: {error}"))
            })?;
        let opening = tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.open_boundary(channel.clone(), credential),
        )
        .await
        .unwrap_or_else(|_| {
            Err(BackendError::Unavailable(
                "boundary opening timed out".to_string(),
            ))
        });
        if let Err(error) = opening {
            transport.abort();
            return Err(error);
        }
        Ok((channel, transport))
    }

    fn boundary_handle(&self) -> Result<&str, BackendError> {
        self.boundary_handle
            .get()
            .map(String::as_str)
            .ok_or_else(|| {
                BackendError::Descriptor(
                    "Sandbox Protocol boundary has not been opened".to_string(),
                )
            })
    }

    async fn open_boundary(
        &self,
        channel: tonic::transport::Channel,
        credential: &BoundaryCredential,
    ) -> Result<(), BackendError> {
        let mut client = IsolationBackendClient::new(channel)
            .max_decoding_message_size(64 * 1024 + MAX_RESTORE_REFERENCE_BYTES)
            .max_encoding_message_size(64 * 1024 + MAX_RESTORE_REFERENCE_BYTES);
        let supervisor = crate::isolation_protocol::supervisor_metadata("openshell/supervisor");
        let response = client
            .describe(DescribeIsolationBackendRequest {
                supervisor: Some(supervisor.clone()),
            })
            .await
            .map_err(control_rpc_error)?
            .into_inner();
        let backend = crate::isolation_protocol::negotiate_peer(&supervisor, response.backend)
            .map_err(control_rpc_error)?;
        if self.requires_takeover
            && !backend.supported_capabilities.iter().any(|capability| {
                capability == crate::isolation_protocol::SUPERVISOR_TAKEOVER_CAPABILITY
            })
        {
            return Err(BackendError::Unsupported(
                "the sandbox runtime does not support supervisor takeover; refusing to resume it"
                    .to_string(),
            ));
        }
        let supports_suspend = crate::isolation_protocol::supports_suspend_resume(&backend);
        let launch = OpenBoundaryRequest {
            session_id: self.runtime_descriptor.session_id.to_string(),
            backend_name: self.backend_name.clone(),
            driver_descriptor: self.driver_descriptor.clone(),
        };
        let response = if let Some(resume) = &self.resume {
            if !supports_suspend {
                return Err(BackendError::Unsupported(format!(
                    "isolation backend does not advertise {}; cannot resume a suspended boundary",
                    crate::isolation_protocol::SUSPEND_RESUME_CAPABILITY
                )));
            }
            let mut request = tonic::Request::new(ResumeBoundaryRequest {
                launch: Some(launch),
                restore_reference: resume.restore_reference.clone(),
                restart_if_restore_fails: resume.restart_if_restore_fails,
            });
            request
                .metadata_mut()
                .insert("authorization", credential.authorization.clone());
            client
                .resume_boundary(request)
                .await
                .map_err(control_rpc_error)?
                .into_inner()
        } else {
            let mut request = tonic::Request::new(launch);
            request
                .metadata_mut()
                .insert("authorization", credential.authorization.clone());
            client
                .open_boundary(request)
                .await
                .map_err(control_rpc_error)?
                .into_inner()
        };
        let outcome =
            validate_launch_outcome(response.outcome, self.resume.as_ref(), supports_suspend)?;
        if response.boundary_id.is_empty() || response.boundary_id.len() > 128 {
            return Err(BackendError::Descriptor(
                "invalid boundary opening response handle".to_string(),
            ));
        }
        let handle = self
            .boundary_handle
            .get_or_init(|| response.boundary_id.clone());
        if *handle != response.boundary_id {
            return Err(BackendError::Denied(
                "boundary handle changed during launch recovery".to_string(),
            ));
        }
        // Replays of the same launch must report the same outcome.
        if *self.launch_outcome.get_or_init(|| outcome) != outcome {
            return Err(BackendError::Denied(
                "boundary launch outcome changed during launch recovery".to_string(),
            ));
        }
        self.backend_supports_suspend
            .store(supports_suspend, Ordering::Release);
        Ok(())
    }

    /// Ask the backend to freeze and fence this generation. A single attempt:
    /// the compute driver retries by signalling the supervisor again.
    async fn suspend_boundary(&self) -> Result<Vec<u8>, BackendError> {
        if !self.backend_supports_suspend.load(Ordering::Acquire) {
            return Err(BackendError::Unsupported(format!(
                "isolation backend does not advertise {}",
                crate::isolation_protocol::SUSPEND_RESUME_CAPABILITY
            )));
        }
        let boundary_id = self.boundary_handle()?.to_string();
        self.ensure_current_credential_connection().await?;
        let credential = BoundaryCredential::capture(&self.sandbox_bearer)?;
        let channel = self.grpc_channel().await?;
        let mut client = IsolationBackendClient::new(channel)
            .max_decoding_message_size(64 * 1024 + MAX_RESTORE_REFERENCE_BYTES)
            .max_encoding_message_size(64 * 1024);
        let mut request = tonic::Request::new(SuspendBoundaryRequest {
            boundary_id,
            session_id: self.runtime_descriptor.session_id.to_string(),
            generation_id: self.runtime_descriptor.generation.clone(),
        });
        request
            .metadata_mut()
            .insert("authorization", credential.authorization);
        let response = tokio::time::timeout(REQUEST_TIMEOUT, client.suspend_boundary(request))
            .await
            .map_err(|_| BackendError::Unavailable("boundary suspension timed out".to_string()))?
            .map_err(control_rpc_error)?
            .into_inner();
        if response.restore_reference.is_empty()
            || response.restore_reference.len() > MAX_RESTORE_REFERENCE_BYTES
        {
            return Err(BackendError::Descriptor(format!(
                "backend restore reference must be 1 to {MAX_RESTORE_REFERENCE_BYTES} bytes"
            )));
        }
        Ok(response.restore_reference)
    }

    #[cfg(test)]
    async fn connect_boundary_once(&self) -> Result<BoundaryDuplexStream, BackendError> {
        connect_boundary_once(&self.runtime_descriptor).await
    }
}

#[cfg(test)]
async fn connect_boundary_once(
    runtime_descriptor: &SandboxRuntimeDescriptor,
) -> Result<BoundaryDuplexStream, BackendError> {
    connect_boundary_using_connector(runtime_descriptor, None).await
}

async fn connect_boundary_using_connector(
    runtime_descriptor: &SandboxRuntimeDescriptor,
    connector: Option<&dyn BoundaryTransportConnector>,
) -> Result<BoundaryDuplexStream, BackendError> {
    let stream: BoundaryDuplexStream = if let Some(connector) = connector {
        connector.connect(runtime_descriptor).await?
    } else {
        match &runtime_descriptor.transport {
            #[cfg(unix)]
            SandboxTransport::Unix { socket_path } => {
                let stream = UnixStream::connect(socket_path).await.map_err(|error| {
                    BackendError::Unavailable(format!(
                        "connect to mapped boundary control socket {}: {error}",
                        socket_path.display()
                    ))
                })?;
                Box::new(stream)
            }
            #[cfg(not(unix))]
            SandboxTransport::Unix { .. } => {
                return Err(BackendError::Unavailable(
                    "Unix boundary transport requires a Unix host".to_string(),
                ));
            }
            SandboxTransport::Tcp {
                authority,
                addresses,
            } => {
                let stream = openshell_core::net::connect_tcp_nodelay_best_effort(addresses)
                    .await
                    .map_err(|error| {
                        BackendError::Unavailable(format!(
                            "connect to boundary TLS endpoint {authority}: {error}"
                        ))
                    })?;
                enable_boundary_tcp_keepalive(&stream);
                Box::new(stream)
            }
            SandboxTransport::Vsock { guest_cid, port } => connect_host_vsock(*guest_cid, *port)?,
            SandboxTransport::RuntimeInitiatedTcp { .. }
            | SandboxTransport::RuntimeInitiatedUnix { .. }
            | SandboxTransport::RuntimeInitiatedVsock { .. }
            | SandboxTransport::RuntimeInitiatedRouted { .. } => {
                return Err(BackendError::Descriptor(
                    "a runtime-initiated transport cannot be dialed".to_string(),
                ));
            }
        }
    };
    authenticate_boundary_stream(&runtime_descriptor.tls, stream).await
}

/// The only Sandbox Protocol client handshake: verify the generation-pinned
/// server identity before a stream from any source can carry a request.
pub async fn authenticate_boundary_stream(
    tls: &SandboxTlsClientConfig,
    stream: BoundaryDuplexStream,
) -> Result<BoundaryDuplexStream, BackendError> {
    let server_name =
        rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|error| {
            BackendError::Descriptor(format!(
                "boundary TLS server name {:?} is invalid: {error}",
                tls.server_name
            ))
        })?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_client_config(tls)?));
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            BackendError::Unavailable(format!("authenticate sandbox channel: {error}"))
        })?;
    Ok(Box::new(stream))
}

#[derive(Clone, Copy)]
enum GrpcStreamKind {
    Exchange,
    Mediate,
}

fn control_rpc_error(error: tonic::Status) -> BackendError {
    match error.code() {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            BackendError::Denied(format!("isolation control authentication: {error}"))
        }
        tonic::Code::Unimplemented => BackendError::Unsupported(error.to_string()),
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => {
            BackendError::Descriptor(format!("isolation control contract: {error}"))
        }
        _ => BackendError::Unavailable(format!("isolation control RPC: {error}")),
    }
}

async fn open_grpc_client_stream(
    channel: tonic::transport::Channel,
    kind: GrpcStreamKind,
    sandbox_bearer: &openshell_core::jwt::SessionBearerTokenSlot,
    boundary_id: &str,
) -> Result<BoundaryDuplexStream, BackendError> {
    let authorization = sandbox_bearer.authorization_metadata().map_err(|error| {
        BackendError::Unavailable(format!("Sandbox Protocol credential unavailable: {error}"))
    })?;
    open_grpc_client_stream_with_authorization(channel, kind, authorization, boundary_id).await
}

async fn open_grpc_client_stream_with_authorization(
    channel: tonic::transport::Channel,
    kind: GrpcStreamKind,
    authorization: tonic::metadata::AsciiMetadataValue,
    boundary_id: &str,
) -> Result<BoundaryDuplexStream, BackendError> {
    let mut client = SandboxProtocolClient::new(channel)
        .max_decoding_message_size(crate::stream_adapter::MAX_MESSAGE_BYTES)
        .max_encoding_message_size(crate::stream_adapter::MAX_MESSAGE_BYTES);
    let error = |error: tonic::Status| match error.code() {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            BackendError::Denied(format!("authenticate Sandbox Protocol stream: {error}"))
        }
        tonic::Code::Unimplemented => BackendError::Unsupported(error.to_string()),
        _ => BackendError::Unavailable(format!("open boundary gRPC stream: {error}")),
    };
    match kind {
        GrpcStreamKind::Exchange => {
            let (application, request) =
                grpc_request::<ExchangeFrame>(boundary_id, authorization).await?;
            let response = client.exchange(request).await.map_err(error)?;
            Ok(Box::new(tokio::io::join(
                grpc_reader(response.into_inner(), crate::stream_adapter::Mode::Response),
                application,
            )))
        }
        GrpcStreamKind::Mediate => {
            let (application, request) =
                grpc_request::<MediateFrame>(boundary_id, authorization).await?;
            let response = client.mediate(request).await.map_err(error)?;
            Ok(Box::new(tokio::io::join(
                grpc_reader(response.into_inner(), crate::stream_adapter::Mode::Response),
                application,
            )))
        }
    }
}

async fn grpc_request<F: ProtocolFrame>(
    boundary_id: &str,
    authorization: tonic::metadata::AsciiMetadataValue,
) -> Result<(tokio::io::DuplexStream, tonic::Request<ReceiverStream<F>>), BackendError> {
    let (application, bridge) = tokio::io::duplex(256 * 1024);
    let (outbound, outbound_rx) = tokio::sync::mpsc::channel(64);
    outbound
        .send(F::bind(boundary_id))
        .await
        .map_err(|_| BackendError::Unavailable("queue boundary binding frame".into()))?;
    tokio::spawn(pump_to_grpc(bridge, outbound));
    let mut request = tonic::Request::new(ReceiverStream::new(outbound_rx));
    request
        .metadata_mut()
        .insert("authorization", authorization);
    Ok((application, request))
}

async fn pump_to_grpc<R, F: ProtocolFrame>(mut reader: R, sender: tokio::sync::mpsc::Sender<F>)
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let mut mode = crate::stream_adapter::Mode::Request;
    loop {
        match F::send(&mut reader, &mut mode).await {
            Ok(Some(chunk)) => {
                if sender.send(chunk).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(error) => {
                tracing::debug!(%error,"boundary request adapter ended");
                return;
            }
        }
    }
}

/// Read typed responses directly, preserving conversion failures as `InvalidData`.
/// The caller classifies these as terminal protocol errors rather than EOF.
fn grpc_reader<F: ProtocolFrame>(
    stream: tonic::Streaming<F>,
    mut mode: crate::stream_adapter::Mode,
) -> impl tokio::io::AsyncRead + Unpin + Send {
    use tokio_stream::StreamExt as _;
    tokio_util::io::StreamReader::new(stream.map(move |frame| {
        let frame = frame.map_err(|status| {
            let kind = match status.code() {
                tonic::Code::Unimplemented => std::io::ErrorKind::Unsupported,
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
                    std::io::ErrorKind::PermissionDenied
                }
                tonic::Code::InvalidArgument
                | tonic::Code::FailedPrecondition
                | tonic::Code::OutOfRange => std::io::ErrorKind::InvalidData,
                _ => std::io::ErrorKind::Other,
            };
            std::io::Error::new(kind, status)
        })?;
        frame.receive(&mut mode).map(bytes::Bytes::from)
    }))
}

fn control_read_error(error: std::io::Error) -> BackendError {
    let message = format!("read boundary control response: {error}");
    match error.kind() {
        std::io::ErrorKind::InvalidData => BackendError::Descriptor(message),
        std::io::ErrorKind::Unsupported => BackendError::Unsupported(message),
        std::io::ErrorKind::PermissionDenied => BackendError::Denied(message),
        _ => BackendError::Unavailable(message),
    }
}

pub fn enable_boundary_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

#[cfg(target_os = "linux")]
fn connect_host_vsock(
    guest_cid: u32,
    control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    let socket = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)
        .map_err(|error| BackendError::Unavailable(format!("create host vsock: {error}")))?;
    socket
        .connect(&socket2::SockAddr::vsock(guest_cid, control_port))
        .map_err(|error| {
            BackendError::Unavailable(format!(
                "connect host vsock CID {guest_cid} port {control_port}: {error}"
            ))
        })?;
    let stream = std::os::unix::net::UnixStream::from(socket);
    stream.set_nonblocking(true).map_err(|error| {
        BackendError::Unavailable(format!("set host vsock nonblocking: {error}"))
    })?;
    let stream = UnixStream::from_std(stream).map_err(|error| {
        BackendError::Unavailable(format!("register host vsock with Tokio: {error}"))
    })?;
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
fn connect_host_vsock(
    _guest_cid: u32,
    _control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    Err(BackendError::Unavailable(
        "host AF_VSOCK transport is supported only on Linux".to_string(),
    ))
}

fn expect_response(response: Response, expected: &str) -> Result<(), BackendError> {
    let matches = matches!(
        (&response, expected),
        (Response::Attached { .. }, "attached")
            | (Response::Confirmed { .. }, "confirmed")
            | (Response::Signaled, "signaled")
            | (Response::Terminated, "terminated")
            | (Response::BoundaryTerminated, "boundary_terminated")
    );
    if matches {
        Ok(())
    } else {
        Err(unexpected_response(expected, &response))
    }
}

fn unexpected_response(expected: &str, response: &Response) -> BackendError {
    BackendError::Process(format!(
        "expected boundary response {expected:?}, received {response:?}"
    ))
}

fn guest_error(kind: crate::boundary_protocol::BoundaryErrorKind, message: String) -> BackendError {
    use crate::boundary_protocol::BoundaryErrorKind;
    let message = format!("boundary process leaf: {message}");
    match kind {
        BoundaryErrorKind::Unsupported => BackendError::Unsupported(message),
        BoundaryErrorKind::Invalid => BackendError::Descriptor(message),
        BoundaryErrorKind::Denied => BackendError::Denied(message),
        BoundaryErrorKind::Unavailable => BackendError::Unavailable(message),
        BoundaryErrorKind::Terminated => BackendError::Terminated(message),
        BoundaryErrorKind::Process => BackendError::Process(message),
    }
}

fn is_transport_unavailable(message: &str) -> bool {
    !message.starts_with("boundary process leaf:")
}

pub struct ConfirmedBoundary {
    boundary: Box<ReadyBoundary>,
    confirmation: BoundaryConfirmation,
}
impl ConfirmedBoundary {
    /// Construct confirmation after checking backend-neutral properties and
    /// immutable identity binding.
    ///
    /// Validate common evidence before exposing the launch-capable RPC handle.
    ///
    /// # Errors
    ///
    /// Returns an error if confirmation is incomplete or the identity does not match.
    fn try_new(
        boundary: Box<ReadyBoundary>,
        confirmation: BoundaryConfirmation,
        expected: &ResolvedWorkloadIdentity,
    ) -> Result<Self, BackendError> {
        confirmation.validate(expected)?;
        Ok(Self {
            boundary,
            confirmation,
        })
    }

    /// Return the record carried by this confirmed state.
    pub fn confirmation(&self) -> &BoundaryConfirmation {
        &self.confirmation
    }

    /// Consume confirmation and advance to the sole launch-capable state.
    pub fn into_boundary(self) -> Box<ReadyBoundary> {
        self.boundary
    }
}
pub struct ProcessAttachment {
    /// Stdin writer.
    pub stdin: BoundaryInput,
    /// Stdout reader, or the PTY-merged output stream.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY processes.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when the admitted process owns a terminal.
    pub terminal: Option<Arc<BoundaryTerminal>>,
}

pub struct ExecSession {
    /// The spawned process.
    pub process: Arc<BoundaryProcess>,
    /// Stdin writer, if not a PTY-merged stream.
    pub stdin: Option<BoundaryInput>,
    /// Stdout reader.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY exec.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when a terminal was requested.
    pub terminal: Option<Arc<BoundaryTerminal>>,
    /// Final status of the attached output stream, including delivery failure.
    /// The process handle's stable wait status remains independent of attachment.
    pub output_status: Option<tokio::sync::oneshot::Receiver<BoundaryExitStatus>>,
}

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(test)]
mod tests {
    mod credential_renewal;
    mod delegated;
    mod flow_control;
    mod network_recovery;
    mod protocol_errors;

    use crate::isolation_protocol::exchange_frame;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::backend_proto::{
        DescribeIsolationBackendResponse, OpenBoundaryResponse, ResumeBoundaryRequest,
        SuspendBoundaryRequest, SuspendBoundaryResponse,
        isolation_backend_server::{IsolationBackend as ControlBackend, IsolationBackendServer},
    };
    use crate::boundary_protocol::{ExitStatusWire, generate_sandbox_tls_material};
    use crate::proto::{
        ExchangeFrame,
        sandbox_protocol_server::{SandboxProtocol, SandboxProtocolServer},
    };
    use openshell_core::jwt::{SecretJwt, SessionBearerTokenSlot};
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };

    const TEST_BOUNDARY_HANDLE: &str = "opaque-test-boundary";

    #[derive(Clone)]
    struct TestIsolationBackend {
        metadata: Option<openshell_core::proto::extension::v1::PeerMetadata>,
        outcome: i32,
        opens: Arc<std::sync::atomic::AtomicUsize>,
        backend_name: String,
        driver_descriptor: Option<Vec<u8>>,
        resumes: Arc<std::sync::Mutex<Vec<ResumeBoundaryRequest>>>,
        suspends: Arc<std::sync::Mutex<Vec<SuspendBoundaryRequest>>>,
        suspend_reference: Result<Vec<u8>, tonic::Code>,
    }

    impl Default for TestIsolationBackend {
        fn default() -> Self {
            Self {
                metadata: Some(crate::isolation_protocol::metadata("test/backend")),
                outcome: LaunchOutcome::Fresh as i32,
                opens: Arc::default(),
                backend_name: crate::BACKEND_NAME.to_string(),
                driver_descriptor: None,
                resumes: Arc::default(),
                suspends: Arc::default(),
                suspend_reference: Err(tonic::Code::Unimplemented),
            }
        }
    }

    impl TestIsolationBackend {
        /// A backend that advertises optional suspend/resume support.
        fn suspendable(outcome: LaunchOutcome) -> Self {
            let mut metadata = crate::isolation_protocol::metadata("test/backend");
            metadata
                .supported_capabilities
                .push(crate::isolation_protocol::SUSPEND_RESUME_CAPABILITY.to_string());
            Self {
                metadata: Some(metadata),
                outcome: outcome as i32,
                suspend_reference: Ok(b"opaque-restore-reference".to_vec()),
                ..Self::default()
            }
        }
    }

    #[tonic::async_trait]
    impl ControlBackend for TestIsolationBackend {
        async fn describe(
            &self,
            request: tonic::Request<DescribeIsolationBackendRequest>,
        ) -> Result<tonic::Response<DescribeIsolationBackendResponse>, tonic::Status> {
            assert!(
                request.metadata().get("authorization").is_none(),
                "capability request must not convey sandbox credentials"
            );
            assert!(request.into_inner().supervisor.is_some());
            Ok(tonic::Response::new(DescribeIsolationBackendResponse {
                backend: self.metadata.clone(),
            }))
        }

        async fn open_boundary(
            &self,
            request: tonic::Request<OpenBoundaryRequest>,
        ) -> Result<tonic::Response<OpenBoundaryResponse>, tonic::Status> {
            assert!(request.metadata().get("authorization").is_some());
            let request = request.into_inner();
            assert_eq!(request.backend_name, self.backend_name);
            if let Some(expected) = &self.driver_descriptor {
                assert_eq!(
                    &request.driver_descriptor, expected,
                    "opaque payload must be forwarded unchanged"
                );
            }
            assert!(!request.driver_descriptor.is_empty());
            assert!(!request.session_id.is_empty());
            self.opens.fetch_add(1, Ordering::AcqRel);
            Ok(tonic::Response::new(OpenBoundaryResponse {
                boundary_id: TEST_BOUNDARY_HANDLE.to_string(),
                outcome: self.outcome,
            }))
        }

        async fn suspend_boundary(
            &self,
            request: tonic::Request<SuspendBoundaryRequest>,
        ) -> Result<tonic::Response<SuspendBoundaryResponse>, tonic::Status> {
            assert!(request.metadata().get("authorization").is_some());
            self.suspends.lock().unwrap().push(request.into_inner());
            match &self.suspend_reference {
                Ok(reference) => Ok(tonic::Response::new(SuspendBoundaryResponse {
                    restore_reference: reference.clone(),
                })),
                Err(code) => Err(tonic::Status::new(*code, "test backend")),
            }
        }

        async fn resume_boundary(
            &self,
            request: tonic::Request<ResumeBoundaryRequest>,
        ) -> Result<tonic::Response<OpenBoundaryResponse>, tonic::Status> {
            assert!(request.metadata().get("authorization").is_some());
            let request = request.into_inner();
            let launch = request.launch.as_ref().expect("resume carries a launch");
            assert_eq!(launch.backend_name, self.backend_name);
            assert!(!launch.session_id.is_empty());
            self.resumes.lock().unwrap().push(request);
            Ok(tonic::Response::new(OpenBoundaryResponse {
                boundary_id: TEST_BOUNDARY_HANDLE.to_string(),
                outcome: self.outcome,
            }))
        }
    }

    /// Serve one TLS connection with `service` and return a client for it.
    async fn isolation_control_client(
        service: TestIsolationBackend,
        resume: Option<ResumeLaunch>,
    ) -> (BoundaryClient, tokio::task::JoinHandle<()>) {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_tls = certificate.client_tls.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                    Box::new(stream),
                ))]))
                .await
                .unwrap();
        });
        let mut client = BoundaryClient::new(
            tls_runtime_descriptor(address, client_tls),
            test_bearer(&"a".repeat(32)),
        );
        client.resume = resume;
        (client, server)
    }

    fn resume_launch(restart_if_restore_fails: bool) -> ResumeLaunch {
        ResumeLaunch::new(
            b"opaque-restore-reference".to_vec(),
            restart_if_restore_fails,
        )
        .unwrap()
    }

    #[test]
    fn launch_outcome_validation_matches_launch_mode() {
        let strict = resume_launch(false);
        let fallback = resume_launch(true);
        let cases = [
            (
                LaunchOutcome::Fresh,
                None,
                Some(BoundaryLaunchOutcome::Fresh),
            ),
            (LaunchOutcome::Restored, None, None),
            (LaunchOutcome::ColdStartFallback, None, None),
            (LaunchOutcome::Unspecified, None, None),
            (
                LaunchOutcome::Restored,
                Some(&strict),
                Some(BoundaryLaunchOutcome::Restored),
            ),
            (LaunchOutcome::ColdStartFallback, Some(&strict), None),
            (
                LaunchOutcome::ColdStartFallback,
                Some(&fallback),
                Some(BoundaryLaunchOutcome::ColdStartFallback),
            ),
            (LaunchOutcome::Fresh, Some(&fallback), None),
            (LaunchOutcome::Unspecified, Some(&fallback), None),
        ];
        for (outcome, resume, expected) in cases {
            let result = validate_launch_outcome(outcome as i32, resume, false);
            match expected {
                Some(expected) => assert_eq!(result.unwrap(), expected, "{outcome:?}"),
                None => assert!(
                    matches!(result, Err(BackendError::Descriptor(_))),
                    "{outcome:?} {resume:?}: {result:?}"
                ),
            }
        }
        assert!(validate_launch_outcome(99, Some(&fallback), true).is_err());
        assert_eq!(
            validate_launch_outcome(LaunchOutcome::Restored as i32, None, true).unwrap(),
            BoundaryLaunchOutcome::Restored
        );
        assert_eq!(
            validate_launch_outcome(LaunchOutcome::ColdStartFallback as i32, None, true).unwrap(),
            BoundaryLaunchOutcome::ColdStartFallback
        );
    }

    #[test]
    fn resume_launch_rejects_empty_and_oversized_references() {
        assert!(ResumeLaunch::new(Vec::new(), false).is_err());
        assert!(ResumeLaunch::new(vec![0; MAX_RESTORE_REFERENCE_BYTES + 1], false).is_err());
        assert!(ResumeLaunch::new(vec![0; MAX_RESTORE_REFERENCE_BYTES], false).is_ok());
        let debug = format!("{:?}", resume_launch(true));
        assert!(!debug.contains("opaque-restore-reference"), "{debug}");
    }

    #[tokio::test]
    async fn driver_provisioned_restore_uses_normal_boundary_opening() {
        let service = TestIsolationBackend::suspendable(LaunchOutcome::Restored);
        let resumes = service.resumes.clone();
        let opens = service.opens.clone();
        let (client, server) = isolation_control_client(service, None).await;
        client.grpc_channel().await.unwrap();
        assert_eq!(
            client.launch_outcome.get().copied(),
            Some(BoundaryLaunchOutcome::Restored)
        );
        assert_eq!(opens.load(Ordering::Acquire), 1);
        assert!(resumes.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn resume_sends_resume_boundary_and_records_restored_outcome() {
        let service = TestIsolationBackend::suspendable(LaunchOutcome::Restored);
        let resumes = service.resumes.clone();
        let opens = service.opens.clone();
        let (client, server) = isolation_control_client(service, Some(resume_launch(false))).await;
        client.grpc_channel().await.unwrap();
        assert_eq!(
            client.launch_outcome.get().copied(),
            Some(BoundaryLaunchOutcome::Restored)
        );
        assert!(client.backend_supports_suspend.load(Ordering::Acquire));
        assert_eq!(
            opens.load(Ordering::Acquire),
            0,
            "resume must not open fresh"
        );
        let resumes = resumes.lock().unwrap().clone();
        assert_eq!(resumes.len(), 1);
        assert_eq!(resumes[0].restore_reference, b"opaque-restore-reference");
        assert!(!resumes[0].restart_if_restore_fails);
        assert_eq!(
            resumes[0].launch.as_ref().unwrap().session_id,
            test_session_id().to_string()
        );
        server.abort();
    }

    #[tokio::test]
    async fn resume_accepts_cold_start_fallback_only_when_allowed() {
        let service = TestIsolationBackend::suspendable(LaunchOutcome::ColdStartFallback);
        let resumes = service.resumes.clone();
        let (client, server) = isolation_control_client(service, Some(resume_launch(true))).await;
        client.grpc_channel().await.unwrap();
        assert_eq!(
            client.launch_outcome.get().copied(),
            Some(BoundaryLaunchOutcome::ColdStartFallback)
        );
        assert!(resumes.lock().unwrap()[0].restart_if_restore_fails);
        server.abort();

        let service = TestIsolationBackend::suspendable(LaunchOutcome::ColdStartFallback);
        let (client, server) = isolation_control_client(service, Some(resume_launch(false))).await;
        let result = client.grpc_channel().await;
        assert!(
            matches!(result, Err(BackendError::Descriptor(_))),
            "{result:?}"
        );
        assert!(client.boundary_handle.get().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn resume_rejects_fresh_and_unspecified_outcomes() {
        for outcome in [LaunchOutcome::Fresh, LaunchOutcome::Unspecified] {
            let service = TestIsolationBackend::suspendable(outcome);
            let (client, server) =
                isolation_control_client(service, Some(resume_launch(true))).await;
            let result = client.grpc_channel().await;
            assert!(
                matches!(result, Err(BackendError::Descriptor(_))),
                "{outcome:?}: {result:?}"
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn resume_requires_backend_suspend_resume_capability() {
        let service = TestIsolationBackend {
            outcome: LaunchOutcome::Restored as i32,
            ..TestIsolationBackend::default()
        };
        let resumes = service.resumes.clone();
        let opens = service.opens.clone();
        let (client, server) = isolation_control_client(service, Some(resume_launch(true))).await;
        let result = client.grpc_channel().await;
        assert!(
            matches!(result, Err(BackendError::Unsupported(_))),
            "{result:?}"
        );
        assert!(resumes.lock().unwrap().is_empty());
        assert_eq!(opens.load(Ordering::Acquire), 0);
        server.abort();
    }

    #[tokio::test]
    async fn supervisor_advertises_suspend_resume_as_optional() {
        let metadata = crate::isolation_protocol::supervisor_metadata("openshell/supervisor");
        assert!(crate::isolation_protocol::supports_suspend_resume(
            &metadata
        ));
        assert!(
            !metadata.required_capabilities.iter().any(
                |capability| capability == crate::isolation_protocol::SUSPEND_RESUME_CAPABILITY
            )
        );
        // Backends that do not advertise the capability still negotiate.
        let (client, server) =
            isolation_control_client(TestIsolationBackend::default(), None).await;
        client.grpc_channel().await.unwrap();
        assert_eq!(
            client.launch_outcome.get().copied(),
            Some(BoundaryLaunchOutcome::Fresh)
        );
        assert!(!client.backend_supports_suspend.load(Ordering::Acquire));
        let result = client.suspend_boundary().await;
        assert!(
            matches!(result, Err(BackendError::Unsupported(_))),
            "{result:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn suspend_sends_boundary_coordinates_and_returns_reference() {
        let service = TestIsolationBackend::suspendable(LaunchOutcome::Fresh);
        let suspends = service.suspends.clone();
        let (client, server) = isolation_control_client(service, None).await;
        client.grpc_channel().await.unwrap();
        assert!(client.backend_supports_suspend.load(Ordering::Acquire));
        let reference = client.suspend_boundary().await.unwrap();
        assert_eq!(reference, b"opaque-restore-reference");
        let suspends = suspends.lock().unwrap().clone();
        assert_eq!(suspends.len(), 1);
        assert_eq!(suspends[0].boundary_id, TEST_BOUNDARY_HANDLE);
        assert_eq!(suspends[0].session_id, test_session_id().to_string());
        assert_eq!(suspends[0].generation_id, "test-generation");
        server.abort();
    }

    #[tokio::test]
    async fn suspend_rejects_backend_failures_and_invalid_references() {
        for reference in [
            Err(tonic::Code::FailedPrecondition),
            Err(tonic::Code::Unavailable),
            Ok(Vec::new()),
            Ok(vec![0; MAX_RESTORE_REFERENCE_BYTES + 1]),
        ] {
            let service = TestIsolationBackend {
                suspend_reference: reference.clone(),
                ..TestIsolationBackend::suspendable(LaunchOutcome::Fresh)
            };
            let (client, server) = isolation_control_client(service, None).await;
            client.grpc_channel().await.unwrap();
            let result = client.suspend_boundary().await;
            assert!(result.is_err(), "{:?}", reference.map(|bytes| bytes.len()));
            server.abort();
        }
    }

    async fn test_bind<F: ProtocolFrame>(inbound: &mut tonic::Streaming<F>) {
        let frame = inbound.message().await.unwrap().unwrap();
        assert_eq!(frame.boundary_id(), Some(TEST_BOUNDARY_HANDLE));
    }

    #[tokio::test]
    async fn incompatible_isolation_contract_never_opens_a_boundary() {
        let mut wrong_major = crate::isolation_protocol::metadata("test/backend");
        wrong_major.protocol_version.as_mut().unwrap().major += 1;
        let mut missing_contract = crate::isolation_protocol::metadata("test/backend");
        missing_contract
            .supported_capabilities
            .retain(|capability| {
                capability != crate::isolation_protocol::SANDBOX_PROTOCOL_CAPABILITY
            });
        let mut unsupported_requirement = crate::isolation_protocol::metadata("test/backend");
        unsupported_requirement
            .required_capabilities
            .push("openshell.sandbox.future-required".to_string());
        for metadata in [
            None,
            Some(wrong_major),
            Some(missing_contract),
            Some(unsupported_requirement),
        ] {
            let certificate = test_certificate();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let service = TestIsolationBackend {
                metadata,
                ..TestIsolationBackend::default()
            };
            let opens = service.opens.clone();
            let client_tls = certificate.client_tls.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                    .accept(stream)
                    .await
                    .unwrap();
                tonic::transport::Server::builder()
                    .add_service(IsolationBackendServer::new(service))
                    .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                        Box::new(stream),
                    ))]))
                    .await
                    .unwrap();
            });
            let result = OpenShellRuntimeBackend::discover_policy(
                tls_runtime_descriptor(address, client_tls),
                test_bearer(&"a".repeat(32)),
                BoundaryTransport::default(),
            )
            .await;
            assert!(
                matches!(result, Err(BackendError::Descriptor(_))),
                "{result:?}"
            );
            assert_eq!(opens.load(Ordering::Acquire), 0);
            server.abort();
        }
    }

    #[tokio::test]
    async fn fresh_launch_rejects_unspecified_restored_and_fallback_outcomes() {
        for outcome in [
            LaunchOutcome::Unspecified,
            LaunchOutcome::Restored,
            LaunchOutcome::ColdStartFallback,
        ] {
            let certificate = test_certificate();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client_tls = certificate.client_tls.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                    .accept(stream)
                    .await
                    .unwrap();
                tonic::transport::Server::builder()
                    .add_service(IsolationBackendServer::new(TestIsolationBackend {
                        outcome: outcome as i32,
                        ..TestIsolationBackend::default()
                    }))
                    .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                        Box::new(stream),
                    ))]))
                    .await
                    .unwrap();
            });
            let result = OpenShellRuntimeBackend::discover_policy(
                tls_runtime_descriptor(address, client_tls),
                test_bearer(&"a".repeat(32)),
                BoundaryTransport::default(),
            )
            .await;
            assert!(
                matches!(result, Err(BackendError::Descriptor(_))),
                "{result:?}"
            );
            server.abort();
        }
    }

    fn test_provisioning_evidence() -> openshell_isolation_interface::contract::ProvisioningEvidence
    {
        openshell_isolation_interface::contract::ProvisioningEvidence::from_enforcement_evidence(
            "test-generation",
            b"test-vm-fence",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn boundary_tcp_connections_enable_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connected = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (_server, _) = listener.accept().await.unwrap();
        let client = connected.await.unwrap().unwrap();

        enable_boundary_tcp_keepalive(&client);

        assert!(socket2::SockRef::from(&client).keepalive().unwrap());
    }

    #[derive(Clone)]
    struct TestGrpcBoundary {
        wait_for_half_close: bool,
        expected_token: String,
        requests: Arc<std::sync::atomic::AtomicUsize>,
        mediation_failures: Arc<std::sync::atomic::AtomicUsize>,
        mediation_ready: bool,
        provider_environment_generation: u64,
        confirmation: BoundaryConfirmation,
        /// Processes reported by successive attaches; empty once drained.
        attach_snapshots: Arc<
            std::sync::Mutex<
                std::collections::VecDeque<Vec<crate::boundary_protocol::ProcessSnapshotWire>>,
            >,
        >,
        /// Every request kind received, in order.
        received: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    type TestGrpcStream<F = ExchangeFrame> =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<F, tonic::Status>> + Send + 'static>>;

    impl TestGrpcBoundary {
        async fn serve<F: ProtocolFrame>(
            &self,
            request: tonic::Request<tonic::Streaming<F>>,
        ) -> Result<tonic::Response<TestGrpcStream<F>>, tonic::Status> {
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok());
            if authorization != Some(format!("Bearer {}", self.expected_token).as_str()) {
                return Err(tonic::Status::unauthenticated(
                    "Sandbox Protocol bearer token did not match",
                ));
            }
            let mut inbound = request.into_inner();
            test_bind(&mut inbound).await;
            let wait_for_half_close = self.wait_for_half_close;
            let requests = self.requests.clone();
            let mediation_ready = self.mediation_ready;
            let provider_environment_generation = self.provider_environment_generation;
            let confirmation = self.confirmation.clone();
            let attach_snapshots = self.attach_snapshots.clone();
            let received = self.received.clone();
            let (outbound, outbound_rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                let mut frame = Vec::new();
                loop {
                    match inbound.message().await {
                        Ok(Some(chunk)) => {
                            frame.extend_from_slice(
                                &chunk
                                    .receive(&mut crate::stream_adapter::Mode::Request)
                                    .expect("request frame"),
                            );
                            if !wait_for_half_close && complete_control_frame(&frame) {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = outbound.send(Err(error)).await;
                            return;
                        }
                    }
                }
                requests.fetch_add(1, Ordering::AcqRel);
                let response = if complete_control_frame(&frame) {
                    let envelope: RequestEnvelope = match decode_frame(&frame) {
                        Ok(envelope) => envelope,
                        Err(error) => {
                            let _ = outbound
                                .send(Err(tonic::Status::invalid_argument(error.to_string())))
                                .await;
                            return;
                        }
                    };
                    received.lock().unwrap().push(match &envelope.request {
                        Request::Attach {
                            supervisor_takeover: Some(_),
                            supervisor_recovery_timeout_secs: Some(_),
                            ..
                        } => "takeover-attach offering recovery",
                        Request::Attach {
                            supervisor_takeover: Some(_),
                            ..
                        } => "takeover-attach",
                        Request::Attach {
                            supervisor_recovery_timeout_secs: Some(_),
                            ..
                        } => "attach offering recovery",
                        Request::Attach { .. } => "attach",
                        Request::Confirm => "confirm",
                        Request::StartAgent { .. } => "start-agent",
                        _ => "other",
                    });
                    match encode_frame(&ResponseEnvelope {
                        request_id: envelope.request_id,
                        response: match envelope.request {
                            Request::DiscoverPolicy => Response::ImagePolicy {
                                yaml: None,
                                invalid: false,
                            },
                            Request::Attach { .. } => {
                                let processes = attach_snapshots
                                    .lock()
                                    .unwrap()
                                    .pop_front()
                                    .unwrap_or_default();
                                Response::Attached {
                                    snapshot: crate::boundary_protocol::SessionSnapshotWire {
                                        generation: "test-generation".to_string(),
                                        processes,
                                        bound_policy: None,
                                    },
                                }
                            }
                            Request::Confirm => Response::Confirmed {
                                confirmation: Box::new(confirmation),
                            },
                            Request::OpenMediation if mediation_ready => Response::MediationReady,
                            Request::OpenMediation => Response::Error {
                                kind: crate::boundary_protocol::BoundaryErrorKind::Denied,
                                message: "a mediation session is already active".to_string(),
                            },
                            Request::Wait { .. } => Response::Exited {
                                status: ExitStatusWire::Exited(23),
                            },
                            Request::Exec { .. } => Response::ExecStarted {
                                process_id: "test-generation:exec:1".to_string(),
                                pty: false,
                            },
                            Request::AttachProcess { .. } => {
                                Response::ProcessAttached { terminal: false }
                            }
                            Request::Signal { .. } => Response::Signaled,
                            Request::Terminate { .. } => Response::Terminated,
                            Request::TerminateBoundary => Response::BoundaryTerminated,
                            Request::UpdateProviderEnvironment {
                                revision,
                                generation,
                                ..
                            } => Response::ProviderEnvironmentUpdated {
                                revision,
                                generation: generation.max(provider_environment_generation),
                                applied: generation > provider_environment_generation,
                            },
                            Request::Resize { .. } => Response::Resized,
                            Request::LoopbackConnect { .. } => Response::LoopbackConnected,
                            Request::StartAgent {
                                provider_env_revision,
                                ..
                            } => Response::Started {
                                process_id: "test-generation:main:0".to_string(),
                                provider_env_revision,
                                provider_env_generation: provider_environment_generation,
                            },
                            Request::AcceptNetwork => Response::Error {
                                kind: crate::boundary_protocol::BoundaryErrorKind::Unavailable,
                                message: "no pending network request".to_string(),
                            },
                        },
                    }) {
                        Ok(response) => response,
                        Err(error) => {
                            let _ = outbound
                                .send(Err(tonic::Status::internal(error.to_string())))
                                .await;
                            return;
                        }
                    }
                } else {
                    b"complete response".to_vec()
                };
                let frame = F::send(
                    &mut response.as_slice(),
                    &mut crate::stream_adapter::Mode::Response,
                )
                .await
                .unwrap()
                .unwrap();
                let _ = outbound.send(Ok(frame)).await;
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
                outbound_rx,
            ))))
        }
    }

    #[tonic::async_trait]
    impl SandboxProtocol for TestGrpcBoundary {
        type ExchangeStream = TestGrpcStream;
        type MediateStream = TestGrpcStream<MediateFrame>;

        async fn exchange(
            &self,
            request: tonic::Request<tonic::Streaming<ExchangeFrame>>,
        ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
            self.serve(request).await
        }

        async fn mediate(
            &self,
            request: tonic::Request<tonic::Streaming<MediateFrame>>,
        ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
            if self
                .mediation_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(tonic::Status::unavailable(
                    "injected mediation transport failure",
                ));
            }
            self.serve(request).await
        }
    }

    fn test_response_chunk(bytes: Vec<u8>) -> ExchangeFrame {
        let response: ResponseEnvelope = decode_frame(&bytes).unwrap();
        crate::isolation_protocol::response_chunk(&response).unwrap()
    }

    fn complete_control_frame(frame: &[u8]) -> bool {
        frame.len() >= 4
            && frame.len()
                >= 4 + usize::try_from(u32::from_be_bytes(
                    frame[..4].try_into().expect("frame header"),
                ))
                .expect("frame length")
    }

    #[tokio::test]
    async fn mediation_denial_is_not_retried_or_cached_as_a_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: requests.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation: test_confirmation(),
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, test_certificate().client_tls),
            test_bearer(&"a".repeat(32)),
        );
        client
            .open_boundary(
                channel.clone(),
                &BoundaryCredential::capture(&client.sandbox_bearer).unwrap(),
            )
            .await
            .unwrap();
        *client.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch: openshell_core::jwt::CredentialEpoch::new(1).expect("test epoch"),
            bearer_fingerprint: BoundaryCredential::capture(&client.sandbox_bearer)
                .expect("test bearer")
                .fingerprint,
            generation: 1,
            channel,
            transport: Arc::default(),
        });
        // A caller may try again later, but each call makes exactly one
        // bounded attach attempt and preserves the server's typed denial.
        for expected_requests in 1..=2 {
            assert!(matches!(
                client.mediation_session().await,
                Err(BackendError::Denied(_))
            ));
            assert_eq!(requests.load(Ordering::Acquire), expected_requests);
            assert!(client.mediation.lock().await.is_none());
        }
        server.abort();
    }

    #[tokio::test]
    async fn recovery_replays_attach_and_confirm_on_a_new_physical_connection() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server_accepted = accepted.clone();
        let server_config = certificate.server_config.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                server_accepted.fetch_add(1, Ordering::AcqRel);
                let service = TestGrpcBoundary {
                    wait_for_half_close: false,
                    expected_token: "a".repeat(32),
                    requests: server_requests.clone(),
                    mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    mediation_ready: false,
                    provider_environment_generation: 0,
                    confirmation: test_confirmation(),
                    attach_snapshots: Arc::default(),
                    received: Arc::default(),
                };
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                        .add_service(SandboxProtocolServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .unwrap();
                });
            }
        });
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        );
        let attach = Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            supervisor_takeover: None,
            supervisor_recovery_timeout_secs: None,
        };
        assert!(matches!(
            client.call_idempotent(attach).await.unwrap(),
            Response::Attached { .. }
        ));
        assert!(matches!(
            client.call_idempotent(Request::Confirm).await.unwrap(),
            Response::Confirmed { .. }
        ));

        // A stream-level failure on a live connection keeps that connection.
        let failed_generation = client.connection_generation().await;
        client
            .recover_after_unavailable(failed_generation)
            .await
            .unwrap();
        assert_eq!(client.connection_generation().await, failed_generation);
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        assert_eq!(requests.load(Ordering::Acquire), 3);

        client
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .expect("cached channel")
            .transport
            .abort();
        client
            .recover_after_unavailable(failed_generation)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("replacement connection accepted")
            .unwrap();
        assert_eq!(accepted.load(Ordering::Acquire), 2);
        assert_eq!(requests.load(Ordering::Acquire), 5);

        // Another accept can report the same transport loss after recovery.
        // It must reuse the replacement without a third connection or replay.
        let recovered_generation = client.connection_generation().await;
        tokio::time::timeout(
            Duration::from_secs(1),
            client.recover_after_unavailable(failed_generation),
        )
        .await
        .expect("stale failure must reuse the recovered connection")
        .unwrap();
        assert_eq!(client.connection_generation().await, recovered_generation);
        assert_eq!(accepted.load(Ordering::Acquire), 2);
        assert_eq!(requests.load(Ordering::Acquire), 5);
    }

    #[test]
    fn wait_recovery_window_begins_at_transport_failure() {
        let wait_started = tokio::time::Instant::now();
        let failure_time = wait_started + CONNECT_RETRY_TIMEOUT + Duration::from_secs(5);
        let mut deadline = None;

        assert_eq!(
            begin_recovery_window(&mut deadline, failure_time),
            failure_time + CONNECT_RETRY_TIMEOUT
        );
    }

    #[tokio::test]
    async fn mediation_stream_failure_retries_without_deadlocking_the_cache() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mediation_failures = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let server_config = certificate.server_config.clone();
        let server_requests = requests.clone();
        let server_failures = mediation_failures.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                let service = TestGrpcBoundary {
                    wait_for_half_close: false,
                    expected_token: "a".repeat(32),
                    requests: server_requests.clone(),
                    mediation_failures: server_failures.clone(),
                    mediation_ready: true,
                    provider_environment_generation: 0,
                    confirmation: test_confirmation(),
                    attach_snapshots: Arc::default(),
                    received: Arc::default(),
                };
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                        .add_service(SandboxProtocolServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .unwrap();
                });
            }
        });
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        );
        let attach = Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            supervisor_takeover: None,
            supervisor_recovery_timeout_secs: None,
        };
        assert!(matches!(
            client.call_idempotent(attach).await.unwrap(),
            Response::Attached { .. }
        ));
        assert!(matches!(
            client.call_idempotent(Request::Confirm).await.unwrap(),
            Response::Confirmed { .. }
        ));

        tokio::time::timeout(Duration::from_secs(2), client.mediation_session())
            .await
            .expect("mediation recovery must not deadlock")
            .expect("mediation recovery must open a replacement session");
        // The liveness probe keeps the healthy physical connection.
        assert!(!server.is_finished(), "no replacement connection expected");
        server.abort();
        assert_eq!(mediation_failures.load(Ordering::Acquire), 0);
        // Attach, confirm, liveness confirm, then the successful mediation.
        assert_eq!(requests.load(Ordering::Acquire), 4);
    }

    #[tokio::test]
    async fn grpc_stream_preserves_response_after_request_half_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: true,
            expected_token: "a".repeat(32),
            requests,
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation: test_confirmation(),
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut stream = open_grpc_client_stream(
            channel,
            GrpcStreamKind::Exchange,
            &test_bearer(&"a".repeat(32)),
            TEST_BOUNDARY_HANDLE,
        )
        .await
        .unwrap();
        let request = RequestEnvelope::new(Request::DiscoverPolicy).unwrap();
        stream
            .write_all(&encode_frame(&request).unwrap())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let response: ResponseEnvelope = crate::boundary_protocol::read_frame_async(&mut stream)
            .await
            .unwrap();
        assert!(matches!(
            response.response,
            Response::ImagePolicy { invalid: false, .. }
        ));
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn persistent_dns_exchange_returns_supervisor_response() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let session = ClientMediationSession::start(Box::new(client_stream));
        let server = tokio::spawn(async move {
            let query = DnsQueryWire {
                request: vec![1, 2, 3],
                transport: openshell_isolation_interface::contract::DnsTransport::Udp,
                identity: crate::boundary_protocol::BinaryIdentityWire::Resolved {
                    executable: crate::boundary_protocol::ExecutableIdentityWire {
                        path: PathBuf::from("/usr/bin/dig"),
                        digest: Some("a".repeat(64).parse().unwrap()),
                    },
                    ancestors: Vec::new(),
                    cmdline_paths: Vec::new(),
                },
                timing: crate::boundary_protocol::MediationTimingWire::default(),
            };
            mediation::write_frame(
                &mut server_stream,
                MediationFrameKind::DnsQuery,
                42,
                &mediation::encode_message(&query).unwrap(),
            )
            .await
            .unwrap();
            let reply = mediation::read_frame(&mut server_stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.kind, MediationFrameKind::DnsResponse);
            assert_eq!(reply.stream_id, 42);
            assert_eq!(
                mediation::decode_message::<DnsQueryResultWire>(&reply.payload).unwrap(),
                DnsQueryResultWire::Response(vec![4, 5, 6])
            );
        });
        let query = session.accept_dns().await.unwrap();
        assert_eq!(query.message, [1, 2, 3]);
        assert_eq!(
            query.binary_identity.unwrap().executable.path,
            PathBuf::from("/usr/bin/dig")
        );
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        server.await.unwrap();
    }

    struct TestCertificate {
        client_tls: SandboxTlsClientConfig,
        server_config: Arc<rustls::ServerConfig>,
    }

    fn test_certificate() -> TestCertificate {
        test_certificate_with_protocol_versions(&[&rustls::version::TLS13])
    }

    fn test_certificate_with_protocol_versions(
        protocol_versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> TestCertificate {
        openshell_crypto::tls::ensure_default_provider();
        let material =
            generate_sandbox_tls_material(test_session_id()).expect("generate test material");
        let certificates = rustls_pemfile::certs(&mut material.certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server certificate");
        let private_key = rustls_pemfile::private_key(&mut material.private_key_pem.as_bytes())
            .expect("parse server private key")
            .expect("server private key");
        let mut server_config =
            openshell_crypto::tls::server_builder_with_protocol_versions(protocol_versions)
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)
                .expect("build test TLS server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        TestCertificate {
            client_tls: SandboxTlsClientConfig {
                server_name: material.server_name,
                trust_anchor_pem: material.trust_anchor_pem,
            },
            server_config: Arc::new(server_config),
        }
    }

    fn tls_runtime_descriptor(
        address: std::net::SocketAddr,
        tls: SandboxTlsClientConfig,
    ) -> SandboxRuntimeDescriptor {
        SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec![address],
            },
            tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence: test_provisioning_evidence(),
        }
    }

    fn test_session_id() -> openshell_core::SandboxSessionId {
        "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("test session ID")
    }

    fn test_bearer(token: &str) -> SessionBearerTokenSlot {
        SessionBearerTokenSlot::new(
            SecretJwt::parse(token).expect("test bearer"),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).expect("test epoch"),
        )
        .expect("test bearer slot")
    }

    async fn spawn_tls_boundary(
        certificate: Arc<rustls::ServerConfig>,
        expected_token: String,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(stream) = tokio_rustls::TlsAcceptor::from(certificate)
                .accept(stream)
                .await
            else {
                return;
            };
            serve_test_grpc_with_confirmation(
                Box::new(stream),
                expected_token,
                test_confirmation(),
            )
            .await;
        });
        (address, task)
    }

    async fn serve_test_grpc(stream: BoundaryDuplexStream, expected_token: String) {
        serve_test_grpc_with_confirmation(stream, expected_token, test_confirmation()).await;
    }

    async fn serve_test_grpc_with_confirmation(
        stream: BoundaryDuplexStream,
        expected_token: String,
        confirmation: BoundaryConfirmation,
    ) {
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token,
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation,
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        tonic::transport::Server::builder()
            .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
            .add_service(SandboxProtocolServer::new(service))
            .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                stream,
            ))]))
            .await
            .unwrap();
    }

    fn sandbox() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sandbox-1".to_string(),
            session_id: test_session_id(),
            policy: SandboxPolicy {
                version: 1,
                filesystem: FilesystemPolicy::default(),
                network: NetworkPolicy::default(),
                landlock: LandlockPolicy::default(),
                process: ProcessPolicy::default(),
            },
            agent: AgentSpec {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                workdir: Some("/sandbox".to_string()),
                timeout_secs: 5,
                interactive: false,
            },
            identity: ResolvedWorkloadIdentity::new(
                10_001,
                10_001,
                Vec::new(),
                "test".to_string(),
                "sha256:test".to_string(),
            )
            .expect("identity"),
        }
    }

    fn test_confirmation() -> BoundaryConfirmation {
        let audit = crate::boundary_protocol::NativeLinuxSandboxAuditEvidence {
            capabilities: crate::boundary_protocol::CapabilityEvidence {
                inheritable: 0,
                permitted: 0,
                effective: 0,
                bounding: 0,
                ambient: 0,
            },
            no_new_privileges: true,
            sandbox_dumpable: false,
            child_dumpable: true,
            core_limit_zero: true,
            native_architecture: std::env::consts::ARCH.to_string(),
            kernel_release: "test".to_string(),
            seccomp: crate::boundary_protocol::SeccompEvidence {
                new_listener: true,
                notification_round_trip: true,
                id_validation: true,
                addfd_send: true,
                retained_socket_operation: true,
                proc_fd_identity: true,
                task_memory_read: true,
            },
            landlock_abi: 3,
            landlock_allow_deny: true,
            udp_dns_round_trip: true,
            tcp_dns_round_trip: true,
            tcp_allow_round_trip: true,
            tcp_deny_round_trip: true,
            socket_loopback_confinement: true,
        };
        BoundaryConfirmation {
            generation: "test-generation".to_string(),
            identity: sandbox().identity,
            session_id: test_session_id(),
            provisioning_evidence_digest: test_provisioning_evidence().evidence_digest,
            resource_claims: std::collections::BTreeMap::new(),
            backend_audit: serde_json::to_value(audit).expect("serialize audit evidence"),
        }
    }

    async fn assert_remote_confirmation_rejected(confirmation: BoundaryConfirmation) {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind confirmation test server");
        let address = listener.local_addr().expect("confirmation test address");
        let expected_token = "a".repeat(32);
        let server_config = certificate.server_config;
        let server_token = expected_token.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept confirmation client");
            let stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .expect("accept confirmation TLS");
            serve_test_grpc_with_confirmation(Box::new(stream), server_token, confirmation).await;
        });

        let descriptor = tls_runtime_descriptor(address, certificate.client_tls);
        let provisioning_evidence = descriptor.provisioning_evidence.clone();
        let context = sandbox();
        let client = Arc::new(BoundaryClient::new(
            descriptor,
            test_bearer(&expected_token),
        ));
        let bound = BoundBoundary {
            client: client.clone(),
            agent: context.agent,
            sandbox_id: context.sandbox_id,
            mediation: Arc::new(NetworkMediationSource {
                client: client.clone(),
            }),
            host_gateway_ip: None,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials:
                openshell_core::provider_credentials::ProviderCredentialState::from_environment(
                    0,
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                ),
            identity: context.identity,
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence,
            takeover: None,
        };

        assert!(matches!(
            Box::new(bound).confirm().await,
            Err(BackendError::Confirm(_))
        ));
        assert!(
            !client.credential_monitor_started.load(Ordering::Acquire),
            "credential monitoring must start only after confirmation succeeds"
        );
        server.abort();
    }

    #[tokio::test]
    async fn remote_confirm_rejects_invalid_native_audit_before_monitoring() {
        let mut confirmation = test_confirmation();
        let mut audit: crate::boundary_protocol::NativeLinuxSandboxAuditEvidence =
            serde_json::from_value(confirmation.backend_audit.clone()).expect("decode test audit");
        audit.seccomp.notification_round_trip = false;
        confirmation.backend_audit = serde_json::to_value(audit).expect("encode test audit");

        assert_remote_confirmation_rejected(confirmation).await;
    }

    #[tokio::test]
    async fn remote_confirm_rejects_provisioning_evidence_mismatch_before_monitoring() {
        let mut confirmation = test_confirmation();
        let different_fence =
            openshell_isolation_interface::contract::ProvisioningEvidence::from_enforcement_evidence(
                "test-generation",
                b"different evidence",
            )
            .expect("construct different test evidence");
        confirmation.provisioning_evidence_digest = different_fence.evidence_digest;

        assert_remote_confirmation_rejected(confirmation).await;
    }

    #[test]
    fn runtime_descriptor_debug_redacts_trust_anchor() {
        let certificate = test_certificate();
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            tls: certificate.client_tls.clone(),
            host_gateway_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence: test_provisioning_evidence(),
        };
        let debug = format!("{runtime_descriptor:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&certificate.client_tls.trust_anchor_pem));
    }

    #[test]
    fn runtime_descriptor_must_match_sandbox() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "other".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence: test_provisioning_evidence(),
        };
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn runtime_descriptor_rejects_an_unspecified_tcp_target() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec!["0.0.0.0:5500".parse().expect("valid address")],
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence: test_provisioning_evidence(),
        };
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn runtime_descriptor_accepts_a_concrete_tcp_target() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec!["10.42.0.7:5500".parse().expect("valid address")],
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            provisioning_evidence: test_provisioning_evidence(),
        };
        validate_runtime_descriptor(&runtime_descriptor, &sandbox())
            .expect("TCP runtime descriptor should be valid");
    }

    #[test]
    fn runtime_descriptor_rejects_invalid_tls_configuration() {
        let runtime_descriptor = tls_runtime_descriptor(
            "127.0.0.1:5500".parse().expect("valid address"),
            SandboxTlsClientConfig {
                server_name: "not a dns name!".to_string(),
                trust_anchor_pem: "not a certificate".to_string(),
            },
        );
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[tokio::test]
    async fn tls_tcp_round_trip_verifies_server_certificate() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        );

        assert_eq!(
            client
                .exchange(Request::Confirm)
                .await
                .expect("TLS request"),
            Response::Confirmed {
                confirmation: Box::new(test_confirmation()),
            }
        );
        server.abort();
    }

    #[derive(Debug)]
    struct ReverseTestConnector(tokio::net::TcpListener);

    #[async_trait]
    impl BoundaryTransportConnector for ReverseTestConnector {
        async fn connect(
            &self,
            _: &SandboxRuntimeDescriptor,
        ) -> Result<BoundaryDuplexStream, BackendError> {
            let (stream, _) = self
                .0
                .accept()
                .await
                .map_err(|error| BackendError::Unavailable(error.to_string()))?;
            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn custom_reverse_transport_preserves_tls_and_bearer_authentication() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connector = Arc::new(ReverseTestConnector(listener));
        let server = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            serve_test_grpc(Box::new(stream), "a".repeat(32)).await;
        });
        let mut client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        );
        client.transport = BoundaryTransport::connector(connector);
        let response =
            tokio::time::timeout(Duration::from_secs(5), client.exchange(Request::Confirm))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            response,
            Response::Confirmed {
                confirmation: Box::new(test_confirmation())
            }
        );
        server.abort();
    }

    #[tokio::test]
    async fn custom_transport_cannot_bypass_tls_peer_verification() {
        let server_certificate = test_certificate();
        let different_trust = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connector = ReverseTestConnector(listener);
        let server = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(server_certificate.server_config)
                .accept(stream)
                .await;
        });
        let descriptor = tls_runtime_descriptor(address, different_trust.client_tls);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(5),
                connect_boundary_using_connector(&descriptor, Some(&connector))
            )
            .await
            .unwrap()
            .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_tcp_rejects_tls12_only_server() {
        let certificate = test_certificate_with_protocol_versions(&[&rustls::version::TLS12]);
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client_config = tls_client_config(&certificate.client_tls).expect("client TLS config");
        let server_name =
            rustls::pki_types::ServerName::try_from(certificate.client_tls.server_name.clone())
                .expect("server name");
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to TLS test server");

        assert!(
            tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name, stream)
                .await
                .is_err()
        );
        server.await.expect("TLS test server task");
    }

    #[tokio::test]
    async fn exec_wait_survives_output_loss_and_reattachment() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = Arc::new(BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        ));
        let mut session = open_exec_session(
            client,
            ExecSpec {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                shell: None,
                runtime_helper: None,
                env: Vec::new(),
                workdir: None,
                pty: false,
            },
        )
        .await
        .unwrap();
        // The test peer closes its I/O stream without an exit frame. Neither
        // that loss nor a dropped reader can invalidate the process handle.
        let output_status = session.output_status.take().unwrap();
        drop(session.stdin);
        drop(session.stdout);
        drop(session.stderr);
        assert_eq!(
            output_status.await.unwrap(),
            BoundaryExitStatus::Exited(74),
            "missing stream exit must fail even when the process exits cleanly"
        );
        let attachment = session.process.attach().await.unwrap();
        drop(attachment);
        for _ in 0..2 {
            assert_eq!(
                session.process.wait().await.unwrap(),
                BoundaryExitStatus::Exited(23)
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn exec_output_completion_preserves_failure_status() {
        let (network, mut peer) = tokio::io::duplex(1024);
        let network: BoundaryDuplexStream = Box::new(network);
        let (reader, _writer) = tokio::io::split(network);
        let (stdout, mut output) = tokio::io::duplex(1024);
        let (stderr, _error_output) = tokio::io::duplex(1024);
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let pump = tokio::spawn(pump_process_responses(
            reader,
            stdout,
            stderr,
            Some(completion_tx),
        ));
        write_stream_frame(&mut peer, STREAM_STDOUT, b"hello")
            .await
            .unwrap();
        let status = crate::protobuf::encode(&ExitStatusWire::Exited(74)).unwrap();
        write_stream_frame(&mut peer, STREAM_EXIT, &status)
            .await
            .unwrap();
        let mut bytes = [0; 5];
        output.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        assert_eq!(completion_rx.await.unwrap(), BoundaryExitStatus::Exited(74));
        pump.await.unwrap();
    }

    struct TestTlsIo(BoundaryDuplexStream);

    impl tokio::io::AsyncRead for TestTlsIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for TestTlsIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl tonic::transport::server::Connected for TestTlsIo {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    #[tokio::test]
    async fn grpc_session_reuses_one_tls_connection_for_concurrent_requests() {
        const REQUESTS: usize = 8;
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gRPC test boundary");
        let address = listener.local_addr().expect("gRPC listener address");
        let server_config = certificate.server_config;
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_by_server = accepted.clone();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: handled.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation: test_confirmation(),
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept TLS session");
                accepted_by_server.fetch_add(1, Ordering::AcqRel);
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .expect("authenticate gRPC TLS session");
                let service = service.clone();
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                        .add_service(SandboxProtocolServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .expect("serve test gRPC connection");
                });
            }
        });
        let client = Arc::new(BoundaryClient::new(
            SandboxRuntimeDescriptor {
                boundary_id: "sandbox-1".to_string(),
                generation: "test-generation".to_string(),
                session_id: test_session_id(),
                workload_identity: sandbox().identity,
                transport: SandboxTransport::Tcp {
                    authority: "sandbox.test".to_string(),
                    addresses: vec![address],
                },
                tls: certificate.client_tls,
                host_gateway_ip: None,
                resource_claims: std::collections::BTreeMap::new(),
                provisioning_evidence: test_provisioning_evidence(),
            },
            test_bearer(&"a".repeat(32)),
        ));
        let mut requests = Vec::new();
        for _ in 0..REQUESTS {
            let client = client.clone();
            requests.push(tokio::spawn(async move {
                let response = client
                    .exchange(Request::Confirm)
                    .await
                    .expect("gRPC confirm request");
                assert!(matches!(response, Response::Confirmed { .. }));
            }));
        }
        for request in requests {
            request.await.expect("gRPC client request");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(handled.load(Ordering::Acquire), REQUESTS);
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        server.abort();
    }

    #[tokio::test]
    async fn reconstructed_backend_resumes_the_running_boundary_publication_generation() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: requests.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 50,
            confirmation: test_confirmation(),
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                    Box::new(stream),
                ))]))
                .await
                .unwrap();
        });
        let credentials =
            openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
                6,
                HashMap::new(),
            );
        let context = sandbox();
        let ready = Box::new(ReadyBoundary {
            client: Arc::new(BoundaryClient::new(
                tls_runtime_descriptor(address, certificate.client_tls),
                test_bearer(&"a".repeat(32)),
            )),
            agent: context.agent,
            sandbox_id: context.sandbox_id,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials: credentials.clone(),
            recovered: None,
        });
        let running = ready.start_agent().await.unwrap();
        assert_eq!(requests.load(Ordering::Acquire), 1);
        let installed = running
            .exec()
            .synchronize_provider_environment()
            .await
            .unwrap();
        assert_eq!(
            requests.load(Ordering::Acquire),
            2,
            "the first update must advance the returned generation, without rejected catch-up calls"
        );
        assert_eq!(
            installed.installation_id,
            credentials.snapshot().installation_id
        );
        assert_eq!(installed.session_id, test_session_id());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn adopted_boundary_never_restarts_the_agent_and_catches_up_publication() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: requests.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 50,
            confirmation: test_confirmation(),
            attach_snapshots: Arc::default(),
            received: Arc::default(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                    Box::new(stream),
                ))]))
                .await
                .unwrap();
        });
        let snapshot = crate::boundary_protocol::SessionSnapshotWire {
            generation: "test-generation".to_string(),
            bound_policy: None,
            processes: vec![
                crate::boundary_protocol::ProcessSnapshotWire {
                    process_id: "test-generation:main:0".to_string(),
                    kind: crate::boundary_protocol::ProcessKindWire::Main,
                    terminal: false,
                    status: None,
                    retained_output: crate::boundary_protocol::OutputWindowWire {
                        first_sequence: 0,
                        next_sequence: 9,
                        truncated: false,
                    },
                },
                crate::boundary_protocol::ProcessSnapshotWire {
                    process_id: "test-generation:exec:3".to_string(),
                    kind: crate::boundary_protocol::ProcessKindWire::Exec,
                    terminal: false,
                    status: None,
                    retained_output: crate::boundary_protocol::OutputWindowWire {
                        first_sequence: 0,
                        next_sequence: 0,
                        truncated: false,
                    },
                },
                crate::boundary_protocol::ProcessSnapshotWire {
                    process_id: "test-generation:exec:1".to_string(),
                    kind: crate::boundary_protocol::ProcessKindWire::Exec,
                    terminal: false,
                    status: Some(ExitStatusWire::Exited(0)),
                    retained_output: crate::boundary_protocol::OutputWindowWire {
                        first_sequence: 0,
                        next_sequence: 4,
                        truncated: false,
                    },
                },
            ],
        };
        let context = sandbox();
        let ready = Box::new(ReadyBoundary {
            client: Arc::new(BoundaryClient::new(
                tls_runtime_descriptor(address, certificate.client_tls),
                test_bearer(&"a".repeat(32)),
            )),
            agent: context.agent,
            sandbox_id: context.sandbox_id,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials:
                openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
                    6,
                    HashMap::new(),
                ),
            recovered: Some(RecoveredProcesses::from_snapshot(&snapshot)),
        });
        let running = ready.start_agent().await.unwrap();
        // The running canonical process is adopted: nothing is started.
        assert_eq!(requests.load(Ordering::Acquire), 0);
        assert!(running.agent_adopted());
        assert_eq!(running.agent().process_id(), "test-generation:main:0");
        // Only the exec process that has not exited is adopted.
        assert_eq!(
            running
                .adopted_exec_processes()
                .iter()
                .map(|process| process.process_id())
                .collect::<Vec<_>>(),
            ["test-generation:exec:3"]
        );
        // Publication resumes above the runtime's installed generation.
        running
            .exec()
            .synchronize_provider_environment()
            .await
            .unwrap();
        assert_eq!(requests.load(Ordering::Acquire), 2);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn takeover_confirm_adopts_from_a_snapshot_taken_after_promotion() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let process = |process_id: &str, kind| crate::boundary_protocol::ProcessSnapshotWire {
            process_id: process_id.to_string(),
            kind,
            terminal: false,
            status: None,
            retained_output: crate::boundary_protocol::OutputWindowWire {
                first_sequence: 0,
                next_sequence: 0,
                truncated: false,
            },
        };
        // The staged snapshot predates an exec the previous owner started
        // before the promotion; only the refreshed snapshot shows it.
        let attach_snapshots = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from([
            vec![process(
                "test-generation:main:0",
                crate::boundary_protocol::ProcessKindWire::Main,
            )],
            vec![
                process(
                    "test-generation:main:0",
                    crate::boundary_protocol::ProcessKindWire::Main,
                ),
                process(
                    "test-generation:exec:4",
                    crate::boundary_protocol::ProcessKindWire::Exec,
                ),
            ],
        ])));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: Arc::default(),
            mediation_failures: Arc::default(),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation: test_confirmation(),
            attach_snapshots,
            received: received.clone(),
        };
        let server_config = certificate.server_config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                    Box::new(stream),
                ))]))
                .await
                .unwrap();
        });
        let descriptor = tls_runtime_descriptor(address, certificate.client_tls);
        let instance = crate::boundary_protocol::SupervisorInstanceId::new();
        let backend = OpenShellRuntimeBackend::new(
            Arc::new(std::sync::Mutex::new(None)),
            openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
                0,
                HashMap::new(),
            ),
            test_bearer(&"a".repeat(32)),
        )
        .with_takeover(BoundaryTakeover {
            supervisor_instance_id: instance,
            grant: SecretJwt::parse("test-grant").unwrap(),
        })
        .with_recovery_timeout_secs(Some(60));
        let bound = backend
            .attach(descriptor.backend_descriptor().unwrap(), sandbox())
            .await
            .unwrap();
        assert!(bound.is_takeover());
        assert!(bound.adopts_running_agent());
        let running = bound
            .confirm()
            .await
            .unwrap()
            .into_boundary()
            .start_agent()
            .await
            .unwrap();
        assert!(running.agent_adopted());
        assert_eq!(running.agent().process_id(), "test-generation:main:0");
        assert_eq!(
            running
                .adopted_exec_processes()
                .iter()
                .map(|process| process.process_id())
                .collect::<Vec<_>>(),
            ["test-generation:exec:4"]
        );
        // The grant goes out once; the refresh reattaches as the pinned
        // owner, and the agent is never started again. Every attach offers
        // the recovery deadline.
        assert_eq!(
            *received.lock().unwrap(),
            [
                "takeover-attach offering recovery",
                "confirm",
                "attach offering recovery"
            ]
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn takeover_grants_reach_only_runtimes_that_support_takeover() {
        async fn open(
            metadata: openshell_core::proto::extension::v1::PeerMetadata,
        ) -> (Result<(), BackendError>, usize, BoundaryClient) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let backend = TestIsolationBackend {
                metadata: Some(metadata),
                opens: opens.clone(),
                ..TestIsolationBackend::default()
            };
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                tonic::transport::Server::builder()
                    .add_service(IsolationBackendServer::new(backend))
                    .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                    .await
                    .unwrap();
            });
            let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect()
                .await
                .unwrap();
            let mut client = BoundaryClient::new(
                tls_runtime_descriptor(address, test_certificate().client_tls),
                test_bearer(&"a".repeat(32)),
            );
            client.requires_takeover = true;
            let credential = BoundaryCredential::capture(&client.sandbox_bearer).unwrap();
            let opened = client.open_boundary(channel, &credential).await;
            server.abort();
            (opened, opens.load(Ordering::Acquire), client)
        }

        // A runtime from before takeover support never sees the boundary
        // opened, let alone the grant.
        let mut legacy = crate::isolation_protocol::metadata("legacy/runtime");
        legacy.supported_capabilities.retain(|capability| {
            capability != crate::isolation_protocol::SUPERVISOR_TAKEOVER_CAPABILITY
        });
        let (opened, opens, _) = open(legacy).await;
        assert!(
            matches!(opened, Err(BackendError::Unsupported(_))),
            "{opened:?}"
        );
        assert_eq!(opens, 0);

        let (opened, opens, mut client) =
            open(crate::isolation_protocol::metadata("openshell/sandbox")).await;
        opened.expect("a takeover-capable runtime opens");
        assert_eq!(opens, 1);
        client.recovery_timeout_secs = Some(60);

        // Once confirmed, reconnects reattach as the pinned process without
        // the grant, so its expiry cannot break transport recovery.
        let policy = Box::new(SandboxPolicyWire::from(sandbox().policy));
        *client.attach_request.lock().unwrap() = Some(
            BoundaryClient::prepare_request(Request::Attach {
                supervisor_instance_id: client.supervisor_instance_id,
                policy: policy.clone(),
                supervisor_takeover: Some("grant".to_string()),
                supervisor_recovery_timeout_secs: Some(60),
            })
            .unwrap(),
        );
        client.forget_takeover_grant(policy).unwrap();
        let remembered = client.attach_request.lock().unwrap().clone().unwrap();
        // The pinned process keeps offering its recovery deadline.
        assert!(matches!(
            remembered.request,
            Request::Attach {
                supervisor_takeover: None,
                supervisor_instance_id,
                supervisor_recovery_timeout_secs: Some(60),
                ..
            } if supervisor_instance_id == client.supervisor_instance_id
        ));
    }

    #[tokio::test]
    async fn provider_environment_acknowledges_the_exact_local_snapshot_and_checked_generation() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let credentials =
            openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
                6,
                HashMap::new(),
            );
        let client = Arc::new(BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        ));
        let exec = BoundaryExec {
            client,
            provider_credentials: credentials.clone(),
            publication_generation: tokio::sync::Mutex::new(0),
        };
        let empty = exec.synchronize_provider_environment().await.unwrap();
        credentials
            .install_child_env_snapshot(6, HashMap::from([("TOKEN".into(), "restored".into())]));
        let repaired = exec.synchronize_provider_environment().await.unwrap();
        assert_eq!(empty.revision, repaired.revision);
        assert_ne!(empty.installation_id, repaired.installation_id);
        assert_eq!(
            repaired.installation_id,
            credentials.snapshot().installation_id
        );
        assert_eq!(*exec.publication_generation.lock().await, 2);
        *exec.publication_generation.lock().await = u64::MAX;
        assert!(
            exec.synchronize_provider_environment().await.is_err(),
            "publication exhaustion must fail before sending another request"
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn tls_tcp_flushes_large_control_requests_before_reading_response() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        );
        let context = sandbox();

        assert!(matches!(
            client
                .exchange(Request::StartAgent {
                    provider_files: HashMap::new(),
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    ca_cert: Some("c".repeat(16 * 1024)),
                    ca_bundle: Some("b".repeat(256 * 1024)),
                    provider_env_revision: 0,
                    provider_env: HashMap::new(),
                })
                .await
                .expect("large TLS request"),
            Response::Started { .. }
        ));
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_unix_flushes_large_control_requests_before_reading_response() {
        let socket_path = std::env::temp_dir().join(format!(
            "openshell-large-control-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let certificate = test_certificate();
        let server_config = certificate.server_config;
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind test socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            serve_test_grpc(Box::new(stream), "a".repeat(32)).await;
        });
        let context = sandbox();
        let client = BoundaryClient::new(
            SandboxRuntimeDescriptor {
                boundary_id: "sandbox-1".to_string(),
                generation: "test-generation".to_string(),
                session_id: test_session_id(),
                workload_identity: context.identity.clone(),
                transport: SandboxTransport::Unix {
                    socket_path: socket_path.clone(),
                },
                tls: certificate.client_tls,
                host_gateway_ip: None,
                resource_claims: std::collections::BTreeMap::new(),
                provisioning_evidence: test_provisioning_evidence(),
            },
            test_bearer(&"a".repeat(32)),
        );

        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                client.exchange(Request::StartAgent {
                    provider_files: HashMap::new(),
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    ca_cert: Some("c".repeat(16 * 1024)),
                    ca_bundle: Some("b".repeat(256 * 1024)),
                    provider_env_revision: 0,
                    provider_env: HashMap::new(),
                })
            )
            .await
            .expect("large Unix TLS request timed out")
            .expect("large Unix TLS request"),
            Response::Started { .. }
        ));
        server.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn tls_tcp_preserves_boundary_token_authentication() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(
            certificate.server_config,
            "expected-token-expected-token-12".to_string(),
        )
        .await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer("incorrect-token-incorrect-token"),
        );

        assert!(matches!(
            client.exchange(Request::Confirm).await,
            Err(BackendError::Denied(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn tls_tcp_rejects_an_untrusted_server_certificate() {
        let presented = test_certificate();
        let trusted = test_certificate();
        let (address, server) = spawn_tls_boundary(presented.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, trusted.client_tls),
            test_bearer(&"a".repeat(32)),
        );

        assert!(matches!(
            client.connect_boundary_once().await,
            Err(BackendError::Unavailable(_))
        ));
        // The server observes the client's fatal alert and may fail its accept;
        // completing the task is sufficient for this rejection test.
        let _ = server.await;
    }
}
