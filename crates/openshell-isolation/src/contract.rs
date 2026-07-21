// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-selectable Isolation Backend contract (RFC 0012).
//!
//! This module is the object-safe, runtime-selectable contract the supervisor
//! role drives. A backend registers an [`IsolationBackendFactory`] under a
//! `backend_id`; the supervisor resolves it from a [`BackendRegistry`] against
//! the admitted backend id and advances the boundary through a fixed chain of
//! boxed states:
//!
//! ```text
//! attach topology + sandbox context -> Bound -> confirm -> Ready
//!     -> start_agent -> Running
//! ```
//!
//! Each transition consumes the prior state by value (`self: Box<Self>`), and no
//! state type has a public constructor, so a stage cannot be skipped or
//! replayed. The supervisor holds no `match`/downcast on concrete backends: the
//! registry is the only lookup by `backend_id`, and everything past it is a
//! `Box<dyn _>` / `Arc<dyn _>`.
//!
//! `attach` is atomic from the caller's perspective: it returns `Bound` or fails
//! closed, and it never binds a resource that is already bound to an active
//! boundary. Binary identity travels on every [`MediatedConnection`], resolved
//! by the backend for that exact connection; an unresolved identity denies the
//! connection and never authorizes anything.
//!
//! The in-pod backend (`openshell-sandbox`) and the supervisor drive this
//! contract directly; two mock factories and the conformance tests below
//! exercise it against a second, heterogeneous backend.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub use openshell_core::policy::SandboxPolicy;

/// The Isolation Backend contract version. The descriptor and the resolved
/// factory must both equal the supervisor-supported version exactly.
pub const CONTRACT_VERSION: u32 = 1;

/// The well-known backend id of the co-located in-pod backend.
///
/// Lives in the contract crate because compute drivers create the
/// [`TopologyDescriptor`] naming it; the implementation lives in
/// `openshell-sandbox`.
pub const IN_POD_BACKEND_ID: &str = "in-pod";

// ============================================================================
// Errors
// ============================================================================

/// Classified failures at the common contract boundary.
///
/// Only [`BackendError::is_retryable`] cases may be retried by the supervisor,
/// and a retry must reuse the same backend and boundary; no error downgrades
/// isolation.
#[derive(Debug)]
pub enum BackendError {
    /// Descriptor missing, malformed, unsupported, or mismatched against admission.
    Descriptor(String),
    /// No factory registered for the resolved `backend_id`.
    NotRegistered(String),
    /// Authenticated attachment rejection (incompatible or already-bound resource).
    Denied(String),
    /// Boundary temporarily unavailable. The only retryable class.
    Unavailable(String),
    /// Attachment-phase failure (establishment or mediation bring-up).
    Attach(String),
    /// Readiness confirmation failed (do not start workload code).
    Confirm(String),
    /// Process start or exec failure.
    Process(String),
    /// Abnormal boundary or workload loss, or an operation against an inactive
    /// boundary.
    Terminated(String),
}

/// Coarse, machine-readable classification of a [`BackendError`] for supervisor
/// status mapping. The error's variant and message carry the structured context
/// (which operation failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    /// Descriptor, version, or backend mismatch.
    Invalid,
    /// Authenticated attachment rejection.
    Denied,
    /// Transient inability to serve an operation (the only retryable kind).
    Unavailable,
    /// Attachment, confirmation, start, or runtime operation failure.
    Failed,
    /// Abnormal boundary/workload loss, or an operation against an inactive
    /// boundary.
    Terminated,
}

impl BackendError {
    /// Whether the supervisor may retry, reusing the same backend and boundary.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    /// The machine-readable kind for this error.
    #[must_use]
    pub fn kind(&self) -> BackendErrorKind {
        match self {
            Self::Descriptor(_) | Self::NotRegistered(_) => BackendErrorKind::Invalid,
            Self::Denied(_) => BackendErrorKind::Denied,
            Self::Unavailable(_) => BackendErrorKind::Unavailable,
            Self::Attach(_) | Self::Confirm(_) | Self::Process(_) => BackendErrorKind::Failed,
            Self::Terminated(_) => BackendErrorKind::Terminated,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(m) => write!(f, "descriptor error: {m}"),
            Self::NotRegistered(m) => write!(f, "backend not registered: {m}"),
            Self::Denied(m) => write!(f, "attachment denied: {m}"),
            Self::Unavailable(m) => write!(f, "boundary unavailable: {m}"),
            Self::Attach(m) => write!(f, "attachment failed: {m}"),
            Self::Confirm(m) => write!(f, "confirmation failed: {m}"),
            Self::Process(m) => write!(f, "process error: {m}"),
            Self::Terminated(m) => write!(f, "boundary terminated: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Why an identity resolution failed. Resolution failure fails closed: the
/// mediation service denies and audits the connection; it never authorizes.
#[derive(Debug)]
pub enum ResolveError {
    /// No process owns the connection (stale or unknown attribution).
    NotFound,
    /// Resolution attempted but could not produce trustworthy identity.
    Failed(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "connection owner not found"),
            Self::Failed(m) => write!(f, "identity resolution failed: {m}"),
        }
    }
}

impl std::error::Error for ResolveError {}

// ============================================================================
// Descriptor and registry
// ============================================================================

/// The common topology descriptor envelope.
///
/// The compute driver supplies one for every provisioned topology, including
/// resources prepared before sandbox assignment. The opaque payload identifies,
/// or gives the backend enough information to resolve, the exact
/// driver-provisioned resource; its protection is backend-specific.
#[derive(Debug, Clone)]
pub struct TopologyDescriptor {
    /// The Isolation Backend contract version this descriptor targets.
    pub contract_version: u32,
    /// The backend the supervisor must instantiate.
    pub backend_id: String,
    /// Backend-specific attachment data.
    pub payload: Vec<u8>,
}

impl TopologyDescriptor {
    /// The descriptor for the co-located in-pod backend: the supervisor
    /// process is the provisioned resource, so the payload is empty.
    #[must_use]
    pub fn in_pod() -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            backend_id: IN_POD_BACKEND_ID.to_string(),
            payload: Vec::new(),
        }
    }

    /// Serialize for the driver-controlled environment transport
    /// (`OPENSHELL_TOPOLOGY_DESCRIPTOR`): `<version>:<backend_id>:<hex payload>`.
    /// Other transports deliver the same envelope with equivalent integrity.
    #[must_use]
    pub fn to_env_value(&self) -> String {
        format!(
            "{}:{}:{}",
            self.contract_version,
            self.backend_id,
            hex_encode(&self.payload)
        )
    }

    /// Parse the environment-transport serialization produced by
    /// [`Self::to_env_value`]. Missing or malformed input fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Descriptor`] for a malformed value: missing
    /// fields, a non-numeric version, an empty backend id, or a payload that
    /// is not valid hex.
    pub fn from_env_value(value: &str) -> Result<Self, BackendError> {
        let mut parts = value.splitn(3, ':');
        let (Some(version), Some(backend_id), Some(payload_hex)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(BackendError::Descriptor(
                "topology descriptor must be <version>:<backend_id>:<hex payload>".to_string(),
            ));
        };
        let contract_version: u32 = version.parse().map_err(|_| {
            BackendError::Descriptor(format!(
                "topology descriptor version {version:?} is not a number"
            ))
        })?;
        if backend_id.is_empty() {
            return Err(BackendError::Descriptor(
                "topology descriptor backend id is empty".to_string(),
            ));
        }
        let payload = hex_decode(payload_hex).ok_or_else(|| {
            BackendError::Descriptor("topology descriptor payload is not valid hex".to_string())
        })?;
        Ok(Self {
            contract_version,
            backend_id: backend_id.to_string(),
            payload,
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.is_ascii() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// A descriptor whose common envelope has passed registry verification.
///
/// Minted only by [`BackendRegistry::resolve`]; no public constructor, so an
/// unverified descriptor cannot reach a factory. The type does not imply that
/// the opaque payload has been validated: the backend validates the payload and
/// atomically binds it to the sandbox context during `attach`.
pub struct VerifiedTopologyDescriptor {
    descriptor: TopologyDescriptor,
}

impl VerifiedTopologyDescriptor {
    /// The verified backend id.
    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.descriptor.backend_id
    }
    /// The backend-specific payload (validated by the backend at `attach`).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.descriptor.payload
    }
    /// The contract version.
    #[must_use]
    pub fn contract_version(&self) -> u32 {
        self.descriptor.contract_version
    }
}

/// The trusted sandbox context, constructed by trusted common code after the
/// control plane assigns the resource to the admitted sandbox.
///
/// Carries the create-time policy baseline. Authorized revisions to
/// mediation-evaluated policy continue through the mediation service's
/// policy-update path after `Running`, without a backend lifecycle transition;
/// a revision that requires changing standing enforcement or launch-time
/// controls is rejected.
pub struct SandboxContext {
    /// Which sandbox this is.
    pub sandbox_id: String,
    /// The create-time policy baseline across all four dimensions.
    pub policy: SandboxPolicy,
    /// The admitted agent workload.
    pub agent: AgentSpec,
}

/// The agent workload to run inside the boundary.
pub use crate::AgentSpec;

/// Maps `backend_id` to its factory. The only lookup-by-id in the system; the
/// supervisor lifecycle never branches on a concrete backend, and resolution
/// never falls back to another backend.
#[derive(Default)]
pub struct BackendRegistry {
    factories: HashMap<String, Arc<dyn IsolationBackendFactory>>,
}

impl BackendRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a factory. Rejects a duplicate `backend_id` and a factory that
    /// does not speak the supervisor-supported contract version exactly.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Descriptor`] for a duplicate `backend_id` or a
    /// contract-version mismatch.
    pub fn register(
        &mut self,
        factory: Arc<dyn IsolationBackendFactory>,
    ) -> Result<(), BackendError> {
        let id = factory.backend_id().to_string();
        if self.factories.contains_key(&id) {
            return Err(BackendError::Descriptor(format!(
                "duplicate backend id {id:?}"
            )));
        }
        if factory.contract_version() != CONTRACT_VERSION {
            return Err(BackendError::Descriptor(format!(
                "backend {id:?} targets contract version {}, supervisor speaks {CONTRACT_VERSION}",
                factory.contract_version()
            )));
        }
        self.factories.insert(id, factory);
        Ok(())
    }

    /// Verify the descriptor's common envelope against the admitted backend id
    /// and resolve its factory. Fails closed and never falls back:
    ///
    /// - the descriptor's contract version must equal [`CONTRACT_VERSION`];
    /// - the descriptor's `backend_id` must equal the admitted id;
    /// - a factory must be registered for that id, agreeing on its id; and
    /// - the factory's contract version must equal [`CONTRACT_VERSION`] exactly.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Descriptor`] for a version or admission
    /// mismatch, and [`BackendError::NotRegistered`] when no factory is
    /// registered for the admitted id.
    pub fn resolve(
        &self,
        descriptor: TopologyDescriptor,
        admitted_backend_id: &str,
    ) -> Result<(Arc<dyn IsolationBackendFactory>, VerifiedTopologyDescriptor), BackendError> {
        if descriptor.contract_version != CONTRACT_VERSION {
            return Err(BackendError::Descriptor(format!(
                "descriptor contract version {} unsupported (expected {CONTRACT_VERSION})",
                descriptor.contract_version
            )));
        }
        if descriptor.backend_id != admitted_backend_id {
            return Err(BackendError::Descriptor(format!(
                "descriptor backend {:?} does not match admitted backend {admitted_backend_id:?}",
                descriptor.backend_id
            )));
        }
        let factory = self
            .factories
            .get(&descriptor.backend_id)
            .ok_or_else(|| BackendError::NotRegistered(descriptor.backend_id.clone()))?
            .clone();
        // Defense in depth: the resolved factory must agree on its id and version.
        if factory.backend_id() != descriptor.backend_id {
            return Err(BackendError::Descriptor(format!(
                "registry returned backend {:?} for id {:?}",
                factory.backend_id(),
                descriptor.backend_id
            )));
        }
        if factory.contract_version() != CONTRACT_VERSION {
            return Err(BackendError::Descriptor(format!(
                "backend {:?} speaks contract version {}, supervisor requires {CONTRACT_VERSION}",
                descriptor.backend_id,
                factory.contract_version()
            )));
        }
        Ok((factory, VerifiedTopologyDescriptor { descriptor }))
    }
}

/// Builds and attaches a concrete backend. Registered once per `backend_id`.
#[async_trait]
pub trait IsolationBackendFactory: Send + Sync {
    /// The backend this factory builds.
    fn backend_id(&self) -> &'static str;

    /// The Isolation Backend contract version this factory speaks. Matched
    /// exactly against [`CONTRACT_VERSION`]; there is no capability negotiation.
    fn contract_version(&self) -> u32;

    /// Validate the opaque payload and atomically bind it to the trusted
    /// sandbox context: returns `Bound` or fails closed. Never binds a resource
    /// that is already bound to an active boundary.
    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError>;
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Bound: the topology descriptor and trusted sandbox context are bound to the
/// same resource, and the mediation ingress is available. No untrusted workload
/// code is running.
#[async_trait]
pub trait BoundBoundary: Send {
    /// The mediation service's backend-neutral source of workload connections.
    /// Retained by the supervisor before consuming `Bound`.
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress>;

    /// Confirm standing enforcement. How a backend establishes confidence is
    /// private to that backend; confirmation fails closed.
    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError>;
}

/// Ready: mediation is initialized, standing enforcement is confirmed, and the
/// backend is prepared to ensure the admitted launch-time controls are in force
/// before untrusted execution. Only agent activation is possible from here.
#[async_trait]
pub trait ReadyBoundary: Send {
    /// Make the admitted agent runnable behind the boundary and return its
    /// handle. `start_agent` is the sole operation that may make the admitted
    /// agent runnable, and it fails closed if any `Ready` condition no longer
    /// holds. Whether the backend creates the agent process or releases a held,
    /// driver-provisioned execution object is backend-specific; every
    /// applicable launch-time control is in force before the first untrusted
    /// instruction.
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError>;
}

/// Running: the agent is runnable behind the boundary and the returned agent
/// handle owns the complete workload tree. Exec and forwarding are available.
/// All interface accessors return owned `Arc`s so a consumer can retain them
/// past any later state consumption.
pub trait RunningBoundary: Send + Sync {
    /// The agent process handle (owns the complete workload tree).
    fn agent(&self) -> Arc<dyn BoundaryProcess>;
    /// The in-boundary exec interface.
    fn exec(&self) -> Arc<dyn BoundaryExec>;
    /// The loopback port-forward interface.
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward>;
}

// ============================================================================
// Process and exec
// ============================================================================

/// Placement-neutral terminal status of a boundary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryExitStatus {
    /// Exited with a code.
    Exited(i32),
    /// Killed by a signal.
    Signaled(i32),
}

/// Placement-neutral signal to deliver to a boundary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundarySignal {
    /// Graceful terminate.
    Term,
    /// Forceful kill.
    Kill,
    /// Interrupt.
    Int,
    /// Hangup.
    Hup,
}

/// A process running inside the boundary, owned by its boundary state. `wait`
/// returns one stable status however many times it is called; a host PID, if
/// useful, is diagnostics-only and never the handle.
#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and its complete descendant tree.
    async fn terminate(&self) -> Result<(), BackendError>;
    /// Optional host PID, for diagnostics only.
    fn diagnostic_pid(&self) -> Option<u32> {
        None
    }
}

/// A boxed async writer into a boundary process's stdin.
pub type BoundaryInput = Box<dyn AsyncWrite + Send + Unpin>;
/// A boxed async reader from a boundary process's stdout or stderr.
pub type BoundaryOutput = Box<dyn AsyncRead + Send + Unpin>;

/// A PTY attached to an exec session.
#[async_trait]
pub trait BoundaryTerminal: Send + Sync {
    /// Resize the terminal.
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError>;
}

/// An owned exec session: the process handle plus its stdio and optional PTY.
/// Owning the process keeps it alive after `exec` returns.
pub struct ExecSession {
    /// The spawned process.
    pub process: Arc<dyn BoundaryProcess>,
    /// Stdin writer, if not a PTY-merged stream.
    pub stdin: Option<BoundaryInput>,
    /// Stdout reader.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY exec.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when a terminal was requested.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

/// What to run inside the boundary via [`BoundaryExec`].
#[derive(Debug, Clone)]
pub struct ExecSpec {
    /// Program to run.
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Extra environment over the boundary's base.
    pub env: Vec<(String, String)>,
    /// Working directory, if any.
    pub workdir: Option<String>,
    /// Whether to allocate a PTY.
    pub pty: bool,
}

/// In-boundary process entry, consumed by the SSH server and supervisor session.
/// Like `start_agent`, every exec ensures the applicable launch-time controls
/// are in force before the new process executes its first untrusted instruction
/// and preserves the provisioned execution environment.
#[async_trait]
pub trait BoundaryExec: Send + Sync {
    /// Spawn `spec` inside the boundary, returning an owned session.
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError>;
}

// ============================================================================
// Port forward
// ============================================================================

/// A loopback-only target inside the boundary, validated at construction.
#[derive(Debug, Clone)]
pub struct LoopbackTarget {
    host: IpAddr,
    port: u16,
}

impl LoopbackTarget {
    /// Build a loopback target, rejecting any non-loopback host.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Process`] when `host` is not a loopback address.
    pub fn new(host: IpAddr, port: u16) -> Result<Self, BackendError> {
        if !host.is_loopback() {
            return Err(BackendError::Process(format!(
                "port-forward target {host} is not loopback"
            )));
        }
        Ok(Self { host, port })
    }
    /// The loopback host.
    #[must_use]
    pub fn host(&self) -> IpAddr {
        self.host
    }
    /// The target port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A bidirectional byte stream into the boundary.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DuplexStream for T {}

/// An open connection into a boundary loopback target.
pub type BoundaryConn = Box<dyn DuplexStream>;

/// Loopback port-forward, consumed by the SSH server and supervisor session.
#[async_trait]
pub trait BoundaryPortForward: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryConn, BackendError>;
}

// ============================================================================
// Mediation and binary identity
// ============================================================================

/// Executable identity for one accepted connection, resolved by the backend and
/// delivered on [`MediatedConnection`] before the mediation service evaluates
/// policy.
///
/// A missing digest is `None`, never an empty value; policy that requires an
/// unavailable identity field cannot authorize the connection. How a backend
/// resolves identity is private to that backend; the shape and the fail-closed
/// semantics do not change.
#[derive(Debug, Clone)]
pub struct BinaryIdentity {
    /// Absolute path of the connecting binary.
    pub binary_path: PathBuf,
    /// SHA-256 of the connecting binary, hex-encoded. `None` when unavailable;
    /// never an empty string.
    pub binary_sha256: Option<String>,
    /// Ancestor process binaries, nearest first.
    pub ancestors: Vec<PathBuf>,
    /// Absolute script/interpreter paths drawn from the process cmdlines.
    /// Diagnostic context; never authorizes.
    pub cmdline_paths: Vec<PathBuf>,
}

/// A workload connection delivered to the mediation service, carrying the
/// identity-resolution result for that exact connection.
///
/// An `Err` identity denies the connection and is audited; it never authorizes
/// anything.
pub struct MediatedConnection {
    /// The workload connection stream.
    pub stream: BoundaryConn,
    /// Executable identity, resolved by the backend for this connection.
    pub binary_identity: Result<BinaryIdentity, ResolveError>,
}

/// A logical per-boundary stream of workload connections, consumed by the
/// mediation service wherever that service runs.
///
/// It may wrap a dedicated listener or a demultiplexed view over shared
/// transport; how it reaches a co-located proxy, a sidecar, or a shared
/// mediation service is backend-private. The backend authoritatively attributes
/// every returned connection to its active boundary without relying solely on a
/// workload-provided identifier. An `Err` from `accept` means the ingress
/// itself is unusable and fails the boundary closed.
#[async_trait]
pub trait MediationIngress: Send + Sync {
    /// Await the next mediated workload connection.
    async fn accept(&self) -> Result<MediatedConnection, BackendError>;
}

#[cfg(test)]
mod tests;
