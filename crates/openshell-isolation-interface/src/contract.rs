// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validated data shared by the Isolation Backend RPC client and native server.
//!
//! Backend extension contracts live in `proto/isolation_backend.proto` and
//! `proto/sandbox_protocol.proto`. This module contains data and validation,
//! not a second trait-based backend interface.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

pub use openshell_core::SandboxSessionId;
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
            Self::Descriptor(_) => BackendErrorKind::Invalid,
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

/// The common isolation backend descriptor envelope.
///
/// The compute driver supplies one for the selected isolation backend. The opaque
/// payload identifies an existing resource or carries the trusted prepared
/// inputs the backend needs to establish one during `attach`; its protection
/// and resource lifecycle remain owned by the compute driver.
#[derive(Debug, Clone)]
pub struct BackendDescriptor {
    /// The backend the supervisor must instantiate.
    pub backend_name: String,
    /// Backend-specific attachment data.
    pub payload: Vec<u8>,
}

/// Exact non-root identity selected before the immutable workload is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        supplementary_gids.retain(|supplementary_gid| *supplementary_gid != gid);
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
    /// Which create or start-from-stopped launch this attachment belongs to.
    ///
    /// Retries of one durable launch reuse this identity. A later launch gets
    /// a new identity even when the compute platform reuses its outer resource.
    pub session_id: SandboxSessionId,
    /// The admitted launch-time policy.
    pub policy: SandboxPolicy,
    /// The admitted agent workload.
    pub agent: AgentSpec,
    /// Immutable identity already applied by the driver to sandbox and agent.
    pub identity: ResolvedWorkloadIdentity,
}

/// The agent workload to run inside the boundary.
use crate::AgentSpec;

// ============================================================================
// Lifecycle states
// ============================================================================

/// Commitment to provisioning facts validated by the trusted compute driver.
///
/// The driver validates its native placement and enforcement requirements before
/// constructing this binding. The digest includes the runtime generation, so
/// confirmation cannot reuse evidence from another launch. It is a binding,
/// not independent proof that the backend enforces policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningEvidence {
    pub generation: String,
    pub evidence_digest: Sha256Digest,
}

impl ProvisioningEvidence {
    /// Bind already-validated native provisioning evidence to one generation.
    pub fn from_enforcement_evidence(
        generation: impl Into<String>,
        native_evidence: &[u8],
    ) -> Result<Self, BackendError> {
        let generation = generation.into();
        if generation.is_empty() || native_evidence.is_empty() {
            return Err(BackendError::Descriptor(
                "provisioning generation and native evidence are required".to_string(),
            ));
        }
        let mut binding = Vec::with_capacity(8 + generation.len() + native_evidence.len());
        binding.extend_from_slice(&(generation.len() as u64).to_be_bytes());
        binding.extend_from_slice(generation.as_bytes());
        binding.extend_from_slice(native_evidence);
        Ok(Self {
            generation,
            evidence_digest: Sha256Digest::compute(&binding),
        })
    }

    /// Reject evidence bound to a different launch.
    pub fn validate(&self, expected_generation: &str) -> Result<(), BackendError> {
        if !self.generation.is_empty() && self.generation == expected_generation {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "provisioning evidence belongs to another generation".to_string(),
            ))
        }
    }
}

/// Successful policy-enforcement confirmation for one admitted launch.
///
/// The backend rejects unsupported policy before confirming. Mechanisms are
/// backend-specific; the common client checks identity and launch binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryConfirmation {
    pub generation: String,
    pub identity: ResolvedWorkloadIdentity,
    pub session_id: SandboxSessionId,
    pub resource_claims: BTreeMap<String, String>,
    pub provisioning_evidence_digest: Sha256Digest,
    /// Optional backend-owned audit data; native clients may validate its schema.
    #[serde(default)]
    pub backend_audit: serde_json::Value,
}

impl BoundaryConfirmation {
    /// Validate the admitted workload identity. The RPC client checks the
    /// session, generation, resource claims, and provisioning evidence binding.
    pub fn validate(&self, expected: &ResolvedWorkloadIdentity) -> Result<(), BackendError> {
        if &self.identity == expected && !self.generation.is_empty() {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "boundary confirmation is incomplete or mismatched".to_string(),
            ))
        }
    }
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

/// A boxed async writer into a boundary process's stdin.
pub type BoundaryInput = Box<dyn AsyncWrite + Send + Unpin>;
/// A boxed async reader from a boundary process's stdout or stderr.
pub type BoundaryOutput = Box<dyn AsyncRead + Send + Unpin>;

/// What to run inside the boundary via [`BoundaryExec`].
#[derive(Debug, Clone)]
pub struct ExecSpec {
    /// Program to run.
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Workload-local shell request. When present, the boundary resolves the
    /// concrete shell and ignores `program` and `args`.
    pub shell: Option<ShellSpec>,
    /// Trusted helper implemented by the sandbox runtime. This intent is set
    /// only by supervisor-owned protocol adapters, never by public exec APIs.
    pub runtime_helper: Option<RuntimeHelper>,
    /// Extra environment over the boundary's base.
    pub env: Vec<(String, String)>,
    /// Working directory, if any.
    pub workdir: Option<String>,
    /// Whether to allocate a PTY.
    pub pty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHelper {
    Sftp,
}

/// A shell invocation whose executable must be resolved inside the workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSpec {
    /// Command passed to the shell. `None` starts an interactive shell when a
    /// PTY is requested and a plain shell otherwise.
    pub command: Option<String>,
    /// Whether command execution should load the shell's login environment.
    pub login: bool,
}

/// Evidence that the running workload boundary installed one provider snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderEnvironmentInstallation {
    /// Local supervisor snapshot that produced the acknowledged environment.
    pub installation_id: String,
    /// Opaque provider content fingerprint.
    pub revision: u64,
    /// Authenticated and confirmed workload boundary session.
    pub session_id: SandboxSessionId,
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

// ============================================================================
// Mediation and binary identity
// ============================================================================

/// Path and digest evidence for one executable in a process identity chain.
///
/// Every instance is authorization-capable, whether it describes the process
/// that owns a connection or one of its executable ancestors. A missing digest
/// is `None`, never an empty value; binary-scoped policy cannot authorize an
/// executable whose digest is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    /// Absolute executable path in the workload filesystem namespace.
    pub path: PathBuf,
    /// Digest of the resolved executable object. `None` when unavailable.
    pub digest: Option<Sha256Digest>,
}

/// Executable identity for one accepted connection, resolved by the backend and
/// delivered on [`PendingTcpOpen`] before the mediation service evaluates
/// policy.
///
/// How a backend resolves identity is private to that backend; the shape and
/// fail-closed semantics do not change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentity {
    /// Executable that owns the accepted connection.
    pub executable: ExecutableIdentity,
    /// Ancestor process executables, nearest first.
    pub ancestors: Vec<ExecutableIdentity>,
    /// Absolute script/interpreter paths drawn from the process cmdlines.
    /// Diagnostic context; never authorizes.
    pub cmdline_paths: Vec<PathBuf>,
}

/// A SHA-256 digest, kept typed so the identity field is not coupled to its
/// textual encoding or forced to repeat the algorithm in its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl TryFrom<String> for Sha256Digest {
    type Error = ResolveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.to_string()
    }
}

impl Sha256Digest {
    fn compute(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};

        Self(Sha256::digest(bytes).into())
    }

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSocketMetadata {
    /// Kernel socket cookie captured for the exact open-file description.
    pub socket_cookie: u64,
    /// Whether the workload requested nonblocking operation.
    pub nonblocking: bool,
    /// Workload process generation that owns the open.
    pub process_generation: u64,
}

/// Typed supervisor decision for one pending TCP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpOpenDecision {
    /// L4 authorization and a bounded relay handler are ready. L7 policy still
    /// applies to bytes after the local connection commits.
    RelayReady,
    /// The socket remains unchanged and connect returns this positive errno.
    Denied(TcpOpenDenial),
}

/// Placement-neutral reason why a staged TCP open was not committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpOpenDenial {
    /// The admitted network policy rejected the request.
    PolicyDenied,
    /// The backend could not resolve authoritative executable identity.
    IdentityUnavailable,
    /// The requested destination could not be validated.
    InvalidDestination,
    /// A bounded mediation resource was exhausted.
    ResourceExhausted,
    /// The mediation path became unavailable before commit.
    MediationUnavailable,
}

/// Timing captured while one mediated operation crosses the sandbox boundary.
///
/// The durations are measured in the sandbox's monotonic clock. The supervisor
/// timestamp is local to the supervisor and is intentionally not serialized.
#[derive(Debug, Clone)]
pub struct MediationTiming {
    /// Time from receiving the sandbox syscall notification or guest host call
    /// to queueing it for the transport. Zero when unmeasured.
    pub sandbox_notification_to_queue: Duration,
    /// Time spent waiting in the sandbox-side mediation queue.
    pub sandbox_queue_wait: Duration,
    /// Time at which the supervisor received the operation.
    pub supervisor_received_at: Instant,
}

impl Default for MediationTiming {
    fn default() -> Self {
        Self {
            sandbox_notification_to_queue: Duration::ZERO,
            sandbox_queue_wait: Duration::ZERO,
            supervisor_received_at: Instant::now(),
        }
    }
}

/// A staged workload TCP open delivered before its local relay is committed.
///
/// An `Err` identity must be denied and audited. The supervisor owns
/// `result`; dropping it cancels the open without changing the workload socket.
pub struct PendingTcpOpen {
    /// Staged byte stream whose workload side is committed only after
    /// [`TcpOpenDecision::RelayReady`].
    pub stream: BoundaryDuplexStream,
    /// Executable identity, resolved by the backend for this connection.
    pub binary_identity: Result<BinaryIdentity, ResolveError>,
    /// Original external destination captured by the backend before mediation.
    pub destination: SocketAddr,
    /// Native socket evidence, when the backend mediates a kernel socket.
    /// Guests without native sockets supply authoritative executable identity
    /// above and leave this absent; never invent kernel cookies or host PIDs.
    pub socket: Option<NetworkSocketMetadata>,
    /// Policy generation under which the request was created.
    pub policy_generation: u64,
    /// Monotonic stage timing for performance diagnostics.
    pub timing: MediationTiming,
    /// Single-use completion channel back to the sandbox broker.
    pub decision: oneshot::Sender<TcpOpenDecision>,
}

/// DNS transport used by one workload exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsTransport {
    /// One DNS wire datagram without a TCP length prefix.
    Udp,
    /// One DNS message received over a TCP resolver connection.
    Tcp,
}

/// One workload DNS request and its fail-closed response channel.
pub struct PendingDnsQuery {
    /// Exactly one DNS wire message, without a DNS-over-TCP length prefix.
    /// The backend removes and restores transport framing.
    pub message: Vec<u8>,
    /// Workload DNS transport.
    pub transport: DnsTransport,
    /// Identity of the process that issued the DNS request when the backend
    /// can observe it authoritatively. Native socket-write adapters report a
    /// resolution error because the relay cannot prove which descriptor
    /// holder sent a datagram. Consumers must never treat unavailable
    /// identity as a binary-policy grant.
    pub binary_identity: Result<BinaryIdentity, ResolveError>,
    /// Monotonic stage timing for performance diagnostics.
    pub timing: MediationTiming,
    /// Single-use response channel owned by the backend adapter.
    pub response: oneshot::Sender<Result<Vec<u8>, BackendError>>,
}
