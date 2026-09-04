// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-selectable Isolation Backend contract (RFC 0012).
//!
//! This module is the object-safe, runtime-selectable contract the supervisor
//! role drives. A backend registers an [`IsolationBackend`] under a
//! `backend_name`; the supervisor resolves it from a [`BackendRegistry`]
//! against the admitted backend name and advances the boundary through a fixed
//! chain of boxed states:
//!
//! ```text
//! attach topology + sandbox context -> Bound -> confirm -> Ready
//!     -> start_agent -> Running
//! ```
//!
//! Each transition consumes the prior state by value (`self: Box<Self>`), and no
//! state type has a public constructor, so a stage cannot be skipped or
//! replayed. The supervisor holds no `match`/downcast on concrete backends: the
//! registry is the only lookup by `backend_name`, and everything past it is a
//! `Box<dyn _>` / `Arc<dyn _>`.
//!
//! `attach` is atomic from the caller's perspective: it establishes and binds
//! the boundary, returns `Bound`, or fails closed. It never binds a resource
//! already bound to an active boundary. Binary identity travels on every
//! [`PendingNetworkOpen`], resolved for that exact socket and process
//! generation; an unresolved identity denies the open.
//!
//! The contract is transport-neutral. Concrete topology implementations keep
//! their placement and coordination details behind these interfaces.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

pub use openshell_core::policy::SandboxPolicy;

// ============================================================================
// Errors
// ============================================================================

/// Classified failures at the common contract boundary.
///
/// An error never advances the lifecycle or authorizes an operation.
#[derive(Debug)]
pub enum BackendError {
    /// Descriptor missing, malformed, unsupported, or mismatched against admission.
    Descriptor(String),
    /// No backend registered for the resolved `backend_name`.
    NotRegistered(String),
    /// Authenticated attachment rejection (incompatible or already-bound resource).
    Denied(String),
    /// Boundary temporarily unavailable.
    Unavailable(String),
    /// The selected backend does not implement an optional contract operation.
    Unsupported(String),
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
    /// Descriptor or backend mismatch.
    Invalid,
    /// Authenticated attachment rejection.
    Denied,
    /// Transient inability to serve an operation.
    Unavailable,
    /// The selected backend does not implement the requested optional operation.
    Unsupported,
    /// Attachment, confirmation, start, or runtime operation failure.
    Failed,
    /// Abnormal boundary/workload loss, or an operation against an inactive
    /// boundary.
    Terminated,
}

impl BackendError {
    /// The machine-readable kind for this error.
    #[must_use]
    pub fn kind(&self) -> BackendErrorKind {
        match self {
            Self::Descriptor(_) | Self::NotRegistered(_) => BackendErrorKind::Invalid,
            Self::Denied(_) => BackendErrorKind::Denied,
            Self::Unavailable(_) => BackendErrorKind::Unavailable,
            Self::Unsupported(_) => BackendErrorKind::Unsupported,
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
            Self::Unsupported(m) => write!(f, "operation unsupported: {m}"),
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
#[derive(Debug, Clone)]
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
/// The compute driver supplies one for every admitted topology. The opaque
/// payload identifies an existing resource or carries the trusted prepared
/// inputs the backend needs to establish one during `attach`; its protection
/// and resource lifecycle remain topology-specific.
#[derive(Debug, Clone)]
pub struct TopologyDescriptor {
    /// The backend the supervisor must instantiate.
    pub backend_name: String,
    /// Backend-specific attachment data.
    pub payload: Vec<u8>,
}

/// A descriptor whose common envelope has passed registry verification.
///
/// Minted only by [`BackendRegistry::resolve`]; no public constructor, so an
/// unverified descriptor cannot reach a backend. The type does not imply that
/// the opaque payload has been validated: the backend validates the payload and
/// atomically binds it to the sandbox context during `attach`.
pub struct VerifiedTopologyDescriptor {
    descriptor: TopologyDescriptor,
}

impl VerifiedTopologyDescriptor {
    /// The verified backend name.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.descriptor.backend_name
    }
    /// The backend-specific payload (validated by the backend at `attach`).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.descriptor.payload
    }
}

/// Exact non-root identity selected before the immutable workload is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorkloadIdentity {
    /// Effective and real user ID used by sandbox and all workload children.
    pub uid: u32,
    /// Primary group ID used by sandbox and all workload children.
    pub gid: u32,
    /// Sorted, unique supplementary groups inherited unchanged by children.
    pub supplementary_gids: Vec<u32>,
    /// Driver-defined resolution source (`policy`, `template`, or `image`).
    pub source: String,
    /// Digest of the immutable image/rootfs/config used for resolution.
    pub resource_digest: String,
}

impl ResolvedWorkloadIdentity {
    /// Validate and construct a final workload identity.
    pub fn new(
        uid: u32,
        gid: u32,
        mut supplementary_gids: Vec<u32>,
        source: String,
        resource_digest: String,
    ) -> Result<Self, BackendError> {
        if uid == 0 || gid == 0 || supplementary_gids.contains(&0) {
            return Err(BackendError::Descriptor(
                "workload identity must not contain UID or GID zero".to_string(),
            ));
        }
        if source.trim().is_empty() || resource_digest.trim().is_empty() {
            return Err(BackendError::Descriptor(
                "workload identity source and resource digest are required".to_string(),
            ));
        }
        supplementary_gids.sort_unstable();
        supplementary_gids.dedup();
        Ok(Self {
            uid,
            gid,
            supplementary_gids,
            source,
            resource_digest,
        })
    }
}

/// The trusted sandbox context, constructed by trusted common code after the
/// control plane assigns the resource to the admitted sandbox.
///
/// Carries the admitted launch-time policy. Approved network-policy revisions
/// are made effective by supervisor-owned network mediation, outside the
/// backend lifecycle.
pub struct SandboxContext {
    /// Which sandbox this is.
    pub sandbox_id: String,
    /// The admitted launch-time policy.
    pub policy: SandboxPolicy,
    /// The admitted agent workload.
    pub agent: AgentSpec,
    /// Immutable identity already applied by the driver to sandbox and agent.
    pub identity: ResolvedWorkloadIdentity,
}

/// The agent workload to run inside the boundary.
pub use crate::AgentSpec;

/// Maps backend name to its implementation. This is the only lookup by name;
/// supervisor lifecycle never branches on a concrete backend, and resolution
/// never falls back to another backend.
#[derive(Default)]
pub struct BackendRegistry {
    backends: HashMap<String, Arc<dyn IsolationBackend>>,
}

impl BackendRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Register a backend. Rejects a duplicate name.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Descriptor`] for a duplicate `backend_name`.
    pub fn register(&mut self, backend: Arc<dyn IsolationBackend>) -> Result<(), BackendError> {
        let name = backend.backend_name().to_string();
        if self.backends.contains_key(&name) {
            return Err(BackendError::Descriptor(format!(
                "duplicate backend name {name:?}"
            )));
        }
        self.backends.insert(name, backend);
        Ok(())
    }

    /// Verify the descriptor's common envelope against the admitted backend name
    /// and resolve its backend. Fails closed and never falls back:
    ///
    /// - the descriptor's `backend_name` must equal the admitted name;
    /// - a backend must be registered under that name.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Descriptor`] for an admission mismatch, and
    /// [`BackendError::NotRegistered`] when no backend is
    /// registered for the admitted name.
    pub fn resolve(
        &self,
        descriptor: TopologyDescriptor,
        admitted_backend_name: &str,
    ) -> Result<(Arc<dyn IsolationBackend>, VerifiedTopologyDescriptor), BackendError> {
        if descriptor.backend_name != admitted_backend_name {
            return Err(BackendError::Descriptor(format!(
                "descriptor backend {:?} does not match admitted backend {admitted_backend_name:?}",
                descriptor.backend_name
            )));
        }
        let backend = self
            .backends
            .get(&descriptor.backend_name)
            .ok_or_else(|| BackendError::NotRegistered(descriptor.backend_name.clone()))?
            .clone();
        if backend.backend_name() != descriptor.backend_name {
            return Err(BackendError::Descriptor(format!(
                "registry returned backend {:?} for name {:?}",
                backend.backend_name(),
                descriptor.backend_name
            )));
        }
        Ok((backend, VerifiedTopologyDescriptor { descriptor }))
    }
}

/// Establishes and operates boundaries for one admitted backend implementation.
#[async_trait]
pub trait IsolationBackend: Send + Sync {
    /// The stable registered backend name.
    fn backend_name(&self) -> &str;

    /// Validate the opaque payload, establish any boundary-local resources,
    /// and atomically bind them to the trusted sandbox context: returns `Bound`
    /// or fails closed. Never binds a resource already bound to an active
    /// boundary. Durable resource lifecycle remains owned by the compute driver
    /// or external orchestrator that supplied the descriptor.
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
/// same resource, and the mediation source is available. No untrusted workload
/// code is running.
#[async_trait]
pub trait BoundBoundary: Send {
    /// The mediation service's backend-neutral source of workload connections.
    /// Retained by the supervisor before consuming `Bound`.
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource>;

    /// Optional transport for workload DNS exchanges. Backends that expose
    /// this source keep DNS inside the supervisor-owned policy path rather
    /// than granting the workload access to a resolver socket.
    fn dns_mediation_source(&self) -> Option<Arc<dyn DnsMediationSource>> {
        None
    }

    /// Trusted host-side dial target for the well-known host-gateway aliases.
    ///
    /// Backends return this when the mediation service runs outside the
    /// workload boundary and therefore cannot use the boundary's resolver
    /// view. The supervisor preserves the original hostname for policy, HTTP,
    /// and TLS while dialing this backend-provided address. Returning `None`
    /// leaves host-gateway discovery to the supervisor's local environment.
    fn host_gateway_ip(&self) -> Option<IpAddr> {
        None
    }

    /// Confirm standing enforcement and return measured sandbox evidence.
    /// Confirmation fails closed and does not execute untrusted workload code.
    async fn confirm(self: Box<Self>) -> Result<ConfirmedBoundary, BackendError>;
}

/// Capability masks measured from `/proc/<pid>/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEvidence {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl CapabilityEvidence {
    /// True only when every Linux capability set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.inheritable == 0
            && self.permitted == 0
            && self.effective == 0
            && self.bounding == 0
            && self.ambient == 0
    }
}

/// Active seccomp notification and socket-broker evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each independently measured kernel operation is reported explicitly"
)]
pub struct SeccompEvidence {
    pub new_listener: bool,
    pub notification_round_trip: bool,
    pub id_validation: bool,
    pub addfd_send: bool,
    pub retained_socket_operation: bool,
    pub proc_fd_identity: bool,
    pub task_memory_read: bool,
    pub task_memory_write: bool,
    pub cancellation: bool,
}

/// Measured sandbox-owned evidence produced before agent launch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "confirmation preserves independently measured security results"
)]
pub struct SandboxConfirmEvidence {
    pub generation: String,
    pub identity: ResolvedWorkloadIdentity,
    pub capabilities: CapabilityEvidence,
    pub no_new_privileges: bool,
    pub sandbox_dumpable: bool,
    pub child_dumpable: bool,
    pub core_limit_zero: bool,
    pub native_architecture: String,
    pub kernel_release: String,
    pub seccomp: SeccompEvidence,
    pub landlock_abi: u32,
    pub landlock_allow_deny: bool,
    pub udp_dns_round_trip: bool,
    pub tcp_dns_round_trip: bool,
    pub tcp_allow_round_trip: bool,
    pub tcp_deny_round_trip: bool,
    pub authenticated_supervisor: bool,
    pub session_epoch: String,
    pub direct_egress_blocked: bool,
    pub resource_claims: BTreeMap<String, String>,
}

impl SandboxConfirmEvidence {
    /// Validate the security-critical evidence required before launch.
    pub fn validate(&self, expected: &ResolvedWorkloadIdentity) -> Result<(), BackendError> {
        let complete = &self.identity == expected
            && self.capabilities.is_empty()
            && self.no_new_privileges
            && !self.sandbox_dumpable
            && self.child_dumpable
            && self.core_limit_zero
            && self.seccomp.new_listener
            && self.seccomp.notification_round_trip
            && self.seccomp.id_validation
            && self.seccomp.addfd_send
            && self.seccomp.retained_socket_operation
            && self.seccomp.proc_fd_identity
            && self.seccomp.task_memory_read
            && self.seccomp.task_memory_write
            && self.seccomp.cancellation
            && self.landlock_abi > 0
            && self.landlock_allow_deny
            && self.udp_dns_round_trip
            && self.tcp_dns_round_trip
            && self.tcp_allow_round_trip
            && self.tcp_deny_round_trip
            && self.authenticated_supervisor
            && self.direct_egress_blocked
            && !self.generation.is_empty()
            && !self.session_epoch.is_empty();
        if complete {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "sandbox confirmation evidence is incomplete or mismatched".to_string(),
            ))
        }
    }
}

/// Ready boundary paired with the evidence measured by `confirm`.
pub struct ConfirmedBoundary {
    pub boundary: Box<dyn ReadyBoundary>,
    pub evidence: SandboxConfirmEvidence,
}

/// Ready: standing enforcement is confirmed, and the backend is prepared to
/// ensure the admitted launch-time controls are in force
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
/// handle represents the admitted agent process. Exec and forwarding are available.
///
/// All interface accessors return owned `Arc`s so a consumer can retain them
/// past any later state consumption.
pub trait RunningBoundary: Send + Sync {
    /// The admitted agent process handle.
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

/// A process running inside the boundary. `wait` returns one stable status
/// however many times it is called; a local PID is never the process handle.
#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and its backend-owned process group.
    async fn terminate(&self) -> Result<(), BackendError>;
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
///
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
pub type BoundaryDuplexStream = Box<dyn DuplexStream>;

/// Loopback port-forward, consumed by the SSH server and supervisor session.
#[async_trait]
pub trait BoundaryPortForward: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError>;
}

// ============================================================================
// Mediation and binary identity
// ============================================================================

/// Executable identity for one accepted connection, resolved by the backend and
/// delivered on [`PendingNetworkOpen`] before the mediation service evaluates
/// policy.
///
/// A missing digest is `None`, never an empty value; policy that requires an
/// unavailable identity field cannot authorize the connection. How a backend
/// resolves identity is private to that backend; the shape and the fail-closed
/// semantics do not change.
#[derive(Debug, Clone)]
pub struct BinaryIdentity {
    /// Absolute path of the executable resolved for the accepted connection.
    pub binary_path: PathBuf,
    /// Digest of the resolved executable object. `None` when unavailable.
    pub binary_digest: Option<Sha256Digest>,
    /// Ancestor process binaries, nearest first.
    pub ancestors: Vec<PathBuf>,
    /// Absolute script/interpreter paths drawn from the process cmdlines.
    /// Diagnostic context; never authorizes.
    pub cmdline_paths: Vec<PathBuf>,
}

/// A SHA-256 digest, kept typed so the identity field is not coupled to its
/// textual encoding or forced to repeat the algorithm in its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Return the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = ResolveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ResolveError::Failed(
                "SHA-256 digest must contain 64 hexadecimal characters".to_string(),
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
                ResolveError::Failed("SHA-256 digest contains non-hexadecimal data".to_string())
            })?;
        }
        Ok(Self(bytes))
    }
}

/// Immutable socket metadata supplied with a pending external TCP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkSocketMetadata {
    /// Kernel socket cookie captured for the exact open-file description.
    pub socket_cookie: u64,
    /// Whether the workload requested nonblocking operation.
    pub nonblocking: bool,
    /// Workload process generation that owns the open.
    pub process_generation: u64,
}

/// Typed supervisor decision for one pending TCP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOpenResult {
    /// L4 authorization and a bounded relay handler are ready. L7 policy still
    /// applies to bytes after the local connection commits.
    RelayReady,
    /// The socket remains unchanged and connect returns this positive errno.
    Denied { errno: i32 },
}

/// A staged workload TCP open delivered before its local relay is committed.
///
/// An `Err` identity must be denied and audited. The supervisor owns
/// `result`; dropping it cancels the open without changing the workload socket.
pub struct PendingNetworkOpen {
    /// Staged byte stream whose workload side is committed only after
    /// [`NetworkOpenResult::RelayReady`].
    pub stream: BoundaryDuplexStream,
    /// Executable identity, resolved by the backend for this connection.
    pub binary_identity: Result<BinaryIdentity, ResolveError>,
    /// Original external destination captured from the blocked syscall.
    pub destination: SocketAddr,
    /// Socket and process identity bound to this request.
    pub socket: NetworkSocketMetadata,
    /// Policy generation under which the request was created.
    pub policy_generation: u64,
    /// Single-use completion channel back to the sandbox broker.
    pub result: oneshot::Sender<NetworkOpenResult>,
}

/// A logical per-boundary stream of workload connections, consumed by the
/// mediation service wherever that service runs.
///
/// It may wrap a dedicated listener or a demultiplexed view over shared
/// transport; how it reaches a co-located proxy, a sidecar, or a shared
/// mediation service is backend-private. A trusted backend component associates
/// every returned connection with its active boundary without relying solely on
/// a transport tuple or workload-provided identifier. An `Err` from `accept`
/// means the source itself is unusable and fails the boundary closed.
#[async_trait]
pub trait NetworkMediationSource: Send + Sync {
    /// Await the next staged workload TCP open.
    async fn accept(&self) -> Result<PendingNetworkOpen, BackendError>;
}

/// DNS transport used by one workload exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    /// One DNS wire datagram without a TCP length prefix.
    Udp,
    /// One two-byte-length-prefixed DNS message.
    Tcp,
}

/// One workload DNS request and its fail-closed response channel.
pub struct MediatedDnsQuery {
    /// DNS request bytes in the framing selected by [`Self::transport`].
    pub request: Vec<u8>,
    /// Workload DNS transport.
    pub transport: DnsTransport,
    /// Identity of the process that issued the DNS request.
    pub binary_identity: Result<BinaryIdentity, ResolveError>,
    /// Single-use response channel owned by the backend adapter.
    pub response: oneshot::Sender<Result<Vec<u8>, BackendError>>,
}

/// Logical per-boundary stream of DNS exchanges. The backend handles syscall,
/// packet, or guest-agent transport details; the supervisor owns policy DNS.
#[async_trait]
pub trait DnsMediationSource: Send + Sync {
    /// Await the next DNS query from this boundary.
    async fn accept(&self) -> Result<MediatedDnsQuery, BackendError>;
}

#[cfg(test)]
mod tests;
