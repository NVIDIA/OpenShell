// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validated data shared by the Isolation Backend RPC client and native server.
//!
//! Backend extension contracts live in `proto/isolation_backend.proto` and
//! `proto/sandbox_protocol.proto`. This module contains data and validation,
//! not a second trait-based backend interface.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

pub use openshell_core::SandboxSessionId;
pub use openshell_core::policy::SandboxPolicy;
pub use openshell_driver_sdk::legacy_contract::{
    BackendDescriptor, BackendError, BackendErrorKind, ProvisioningEvidence, ResolveError,
    ResolvedWorkloadIdentity, Sha256Digest,
};

// ============================================================================
// Errors
// ============================================================================

// ============================================================================
// Descriptor and registry
// ============================================================================

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
    /// The supervisor may canonicalize IPv4-mapped IPv6 addresses before routing.
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
