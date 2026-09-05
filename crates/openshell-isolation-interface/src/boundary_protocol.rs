// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Versioned control protocol shared by every remote isolation boundary.
//!
//! Drivers choose and provision the transport, but they do not redefine the
//! process lifecycle, streaming, identity, or authentication messages.  The
//! control and boundary roles exchange these length-delimited JSON frames over
//! a private Unix socket, authenticated TCP connection, or virtio-vsock stream.

use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::AgentSpec;
use crate::contract::Sha256Digest;
use crate::contract::{
    BackendError, BinaryIdentity, BoundaryExitStatus, BoundarySignal, DriverFenceEvidence,
    ExecSpec, ResolveError, SandboxConfirmEvidence, TopologyDescriptor,
};
use openshell_core::policy::{
    FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkMode, NetworkPolicy,
    ProcessPolicy, ProxyPolicy, SandboxPolicy,
};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const STREAM_STDIN: u8 = 0;
pub const STREAM_STDOUT: u8 = 1;
pub const STREAM_STDERR: u8 = 2;
pub const STREAM_EXIT: u8 = 3;
pub const STREAM_STDIN_CLOSED: u8 = 4;
/// Supervisor decision for a staged seccomp-mediated TCP open.
pub const STREAM_NETWORK_DECISION: u8 = 5;
/// Supervisor response for one sandbox-local DNS relay exchange.
pub const STREAM_DNS_RESPONSE: u8 = 6;
/// Boundary acknowledgement that a mediated DNS response was committed.
pub const STREAM_DNS_ACK: u8 = 7;
pub const MAX_STREAM_FRAME_BYTES: usize = 64 * 1024;
/// Control-side endpoint for a driver-provisioned boundary.
/// Supervisor-side mutual-TLS identity for one sandbox generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryClientTls {
    /// DNS identity required from the sandbox certificate.
    pub server_name: String,
    /// Per-generation trust anchor for the sandbox certificate.
    pub ca_certificate_pem: String,
    /// Supervisor-only client certificate chain.
    pub certificate_chain_pem: String,
    /// Supervisor-only client private key.
    pub private_key_pem: String,
}

impl fmt::Debug for BoundaryClientTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryClientTls")
            .field("server_name", &self.server_name)
            .field("ca_certificate_pem", &"<redacted>")
            .field("certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// Sandbox-side mutual-TLS files staged by a compute driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryServerTls {
    /// Sandbox server certificate chain.
    pub certificate_chain_path: PathBuf,
    /// Sandbox server private key.
    pub private_key_path: PathBuf,
    /// Trust anchor used to require the generation-specific supervisor leaf.
    pub client_ca_certificate_path: PathBuf,
}

/// Complete per-generation material returned only to a trusted driver.
#[derive(Clone)]
pub struct BoundaryMutualTlsMaterial {
    pub server_name: String,
    pub ca_certificate_pem: String,
    pub sandbox_certificate_pem: String,
    pub sandbox_private_key_pem: String,
    pub supervisor_certificate_pem: String,
    pub supervisor_private_key_pem: String,
}

/// Generate distinct server- and client-authentication leaves under a fresh CA.
pub fn generate_boundary_mutual_tls_material() -> Result<BoundaryMutualTlsMaterial, BackendError> {
    const SERVER_NAME: &str = "sandbox.openshell.internal";
    let ca_key = KeyPair::generate()
        .map_err(|error| BackendError::Descriptor(format!("generate boundary CA key: {error}")))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox channel CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).map_err(|error| {
        BackendError::Descriptor(format!("generate boundary CA certificate: {error}"))
    })?;

    let sandbox_key = KeyPair::generate().map_err(|error| {
        BackendError::Descriptor(format!("generate sandbox channel key: {error}"))
    })?;
    let mut sandbox_params = CertificateParams::new(vec![SERVER_NAME.to_string()])
        .map_err(|error| BackendError::Descriptor(format!("build sandbox certificate: {error}")))?;
    sandbox_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox");
    sandbox_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let sandbox = sandbox_params
        .signed_by(&sandbox_key, &ca, &ca_key)
        .map_err(|error| {
            BackendError::Descriptor(format!("sign sandbox channel certificate: {error}"))
        })?;

    let supervisor_key = KeyPair::generate().map_err(|error| {
        BackendError::Descriptor(format!("generate supervisor channel key: {error}"))
    })?;
    let mut supervisor_params = CertificateParams::default();
    supervisor_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell supervisor");
    supervisor_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let supervisor = supervisor_params
        .signed_by(&supervisor_key, &ca, &ca_key)
        .map_err(|error| {
            BackendError::Descriptor(format!("sign supervisor channel certificate: {error}"))
        })?;

    Ok(BoundaryMutualTlsMaterial {
        server_name: SERVER_NAME.to_string(),
        ca_certificate_pem: ca.pem(),
        sandbox_certificate_pem: sandbox.pem(),
        sandbox_private_key_pem: sandbox_key.serialize_pem(),
        supervisor_certificate_pem: supervisor.pem(),
        supervisor_private_key_pem: supervisor_key.serialize_pem(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BoundaryTransport {
    /// Mutual TLS over a private Unix socket, including libkrun's host mapping.
    Unix {
        socket_path: PathBuf,
        tls: BoundaryClientTls,
    },
    /// Mutual TLS over a runtime-scoped TCP endpoint.
    TlsTcp {
        address: std::net::SocketAddr,
        tls: BoundaryClientTls,
    },
    /// Mutual TLS over Linux host `AF_VSOCK`.
    Vsock {
        guest_cid: u32,
        control_port: u32,
        tls: BoundaryClientTls,
    },
}

/// Boundary-side listener provisioned by a compute driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BoundaryListener {
    /// Mutual TLS over a private Unix socket shared with a companion.
    Unix {
        socket_path: PathBuf,
        tls: BoundaryServerTls,
    },
    /// Mutual TLS over TCP. An unspecified IP is valid for the sandbox bind.
    TlsTcp {
        address: std::net::SocketAddr,
        tls: BoundaryServerTls,
    },
    /// Mutual TLS over guest `AF_VSOCK`.
    Vsock {
        control_port: u32,
        tls: BoundaryServerTls,
    },
}

/// Protected descriptor consumed by `openshell-supervisor`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryTopology {
    /// Stable identity of the boundary, normally the sandbox ID.
    pub boundary_id: String,
    /// Immutable driver-owned workload generation.
    pub generation: String,
    /// Fresh session epoch shared with the sandbox bootstrap.
    pub session_epoch: String,
    /// Immutable numeric identity already applied to the sandbox workload.
    pub workload_identity: crate::contract::ResolvedWorkloadIdentity,
    /// Driver-provisioned control endpoint.
    pub transport: BoundaryTransport,
    /// Trusted dial target for well-known host-gateway aliases, when the
    /// network supervisor cannot use the boundary's resolver view.
    #[serde(default)]
    pub host_gateway_ip: Option<std::net::IpAddr>,
    /// Driver-specific immutable resource coordinates bound at attach (for
    /// example pod UID, VM generation, or container ID).
    #[serde(default)]
    pub resource_claims: std::collections::BTreeMap<String, String>,
    /// Concrete outer-fence evidence validated by the driver.
    pub driver_fence: DriverFenceEvidence,
    /// Per-boundary authentication secret; never exposed to workload code.
    pub bootstrap_token: String,
}

impl fmt::Debug for BoundaryTopology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryTopology")
            .field("boundary_id", &self.boundary_id)
            .field("generation", &self.generation)
            .field("session_epoch", &"<redacted>")
            .field("transport", &self.transport)
            .field("host_gateway_ip", &self.host_gateway_ip)
            .field("resource_claims", &self.resource_claims)
            .field("driver_fence", &self.driver_fence)
            .field("bootstrap_token", &"<redacted>")
            .finish()
    }
}

impl BoundaryTopology {
    /// Encode this topology as the shared RFC 0012 descriptor admitted for
    /// `backend_name`.
    pub fn descriptor(
        &self,
        backend_name: impl Into<String>,
    ) -> Result<TopologyDescriptor, BackendError> {
        let payload = serde_json::to_vec(self)
            .map_err(|error| BackendError::Descriptor(format!("encode topology: {error}")))?;
        Ok(TopologyDescriptor {
            backend_name: backend_name.into(),
            payload,
        })
    }
}

/// Protected bootstrap configuration consumed by `openshell-sandbox`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryConfig {
    /// Stable identity expected in every authenticated request.
    pub boundary_id: String,
    /// Immutable driver-owned workload generation.
    pub generation: String,
    /// Fresh session epoch for this sandbox/supervisor relationship.
    pub session_epoch: String,
    /// Per-boundary authentication secret.
    pub bootstrap_token: String,
    /// Driver-provisioned listener.
    pub listener: BoundaryListener,
    /// Immutable coordinates the boundary requires from the control-side
    /// topology descriptor before accepting attachment.
    #[serde(default)]
    pub resource_claims: std::collections::BTreeMap<String, String>,
    /// Driver-provisioned, read-only runtime evidence for resource claims.
    ///
    /// Each entry maps a claim key to an absolute file whose trimmed contents
    /// must equal the corresponding value in `resource_claims` before the
    /// boundary opens its listener. Kubernetes uses this to bind a one-use
    /// bootstrap bundle to the admitted workload Pod UID exposed by the
    /// Downward API. Other drivers may leave the map empty.
    #[serde(default)]
    pub resource_claim_files: std::collections::BTreeMap<String, PathBuf>,
    /// Exact identity already applied by the runtime to the sandbox process.
    pub workload_identity: crate::contract::ResolvedWorkloadIdentity,
    /// Concrete outer-fence evidence validated by the driver.
    pub driver_fence: DriverFenceEvidence,
    /// Driver-resolved environment exposed only to workload processes.
    #[serde(default)]
    pub child_env: std::collections::HashMap<String, String>,
}

impl fmt::Debug for BoundaryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryConfig")
            .field("boundary_id", &self.boundary_id)
            .field("generation", &self.generation)
            .field("session_epoch", &"<redacted>")
            .field("bootstrap_token", &"<redacted>")
            .field("listener", &self.listener)
            .field("resource_claims", &self.resource_claims)
            .field("resource_claim_files", &self.resource_claim_files)
            .field("workload_identity", &self.workload_identity)
            .field("driver_fence", &self.driver_fence)
            .field("child_env_keys", &self.child_env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BoundaryConfig {
    /// Serialize the protected driver-owned boundary configuration.
    pub fn encode(&self) -> Result<Vec<u8>, BackendError> {
        serde_json::to_vec(self)
            .map_err(|error| BackendError::Descriptor(format!("encode boundary config: {error}")))
    }
}

/// Validate driver-specific immutable coordinates before a boundary binds them.
///
/// Claim values are opaque to the common protocol, but empty or
/// whitespace-bearing identifiers cannot safely distinguish runtime objects.
pub fn validate_resource_claims(
    claims: &std::collections::BTreeMap<String, String>,
) -> Result<(), BackendError> {
    for (key, value) in claims {
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(
                "boundary resource-claim keys must be non-empty and contain no whitespace"
                    .to_string(),
            ));
        }
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(format!(
                "boundary resource claim {key:?} must be non-empty and contain no whitespace"
            )));
        }
    }
    Ok(())
}

pub async fn write_stream_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    channel: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_STREAM_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boundary stream frame exceeds limit",
        ));
    }
    writer.write_u8(channel).await?;
    writer
        .write_u32(payload.len().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "boundary stream frame length overflow",
            )
        })?)
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub async fn read_stream_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(u8, Vec<u8>)>> {
    let channel = match reader.read_u8().await {
        Ok(channel) => channel,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let declared = reader.read_u32().await? as usize;
    if declared > MAX_STREAM_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("boundary stream frame is too large: {declared} bytes"),
        ));
    }
    let mut payload = vec![0; declared];
    reader.read_exact(&mut payload).await?;
    Ok(Some((channel, payload)))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    /// Cryptographically random idempotency key scoped to one sandbox generation.
    pub request_id: String,
    /// SHA-256 of the canonically serialized request payload.
    pub payload_digest: String,
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub request: Request,
}

impl RequestEnvelope {
    /// Build a request envelope with a fresh idempotency key and normalized
    /// payload digest.
    pub fn new(
        boundary_id: String,
        bootstrap_token: String,
        request: Request,
    ) -> Result<Self, FrameError> {
        let payload_digest = request_payload_digest(&request)?;
        Ok(Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            payload_digest,
            boundary_id,
            bootstrap_token,
            request,
        })
    }

    /// Verify that the request body still matches the immutable digest bound
    /// to this idempotency key.
    pub fn validate_payload_digest(&self) -> Result<(), FrameError> {
        let actual = request_payload_digest(&self.request)?;
        if actual == self.payload_digest {
            Ok(())
        } else {
            Err(FrameError::PayloadDigestMismatch)
        }
    }
}

fn request_payload_digest(request: &Request) -> Result<String, FrameError> {
    // Round-tripping through Value canonicalizes every JSON object by key. In
    // particular, this makes HashMap-backed provider environments stable
    // across process restarts and independently serialized retries.
    let normalized = serde_json::to_value(request).map_err(FrameError::Serialize)?;
    let payload = serde_json::to_vec(&normalized).map_err(FrameError::Serialize)?;
    let digest = Sha256::digest(payload);
    Ok(format!("{digest:x}"))
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("request_id", &self.request_id)
            .field("boundary_id", &self.boundary_id)
            .field("bootstrap_token", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Attach {
        policy: Box<SandboxPolicyWire>,
        resource_claims: std::collections::BTreeMap<String, String>,
    },
    Confirm,
    StartAgent {
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: Box<SandboxPolicyWire>,
        ca_cert: Option<Vec<u8>>,
        ca_bundle: Option<Vec<u8>>,
        provider_env_revision: u64,
        provider_env: std::collections::HashMap<String, String>,
    },
    UpdateProviderEnvironment {
        expected_revision: u64,
        revision: u64,
        provider_env: std::collections::HashMap<String, String>,
    },
    AttachProcess {
        process_id: String,
    },
    Wait {
        process_id: String,
    },
    Signal {
        process_id: String,
        signal: SignalWire,
    },
    Terminate {
        process_id: String,
    },
    Exec {
        spec: ExecSpecWire,
    },
    ExecSignal {
        process_id: String,
        signal: SignalWire,
    },
    Resize {
        process_id: String,
        cols: u16,
        rows: u16,
    },
    PortForward {
        host: std::net::IpAddr,
        port: u16,
    },
    AcceptNetwork,
    AcceptDns,
}

impl Request {
    /// Whether this control-path request changes generation-owned sandbox
    /// state and therefore must be replayed from the idempotency ledger.
    #[must_use]
    pub const fn is_replayable_mutation(&self) -> bool {
        matches!(
            self,
            Self::Attach { .. }
                | Self::Confirm
                | Self::StartAgent { .. }
                | Self::UpdateProviderEnvironment { .. }
                | Self::Exec { .. }
                | Self::Signal { .. }
                | Self::Terminate { .. }
                | Self::ExecSignal { .. }
                | Self::Resize { .. }
        )
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attach {
                policy: _,
                resource_claims,
            } => formatter
                .debug_struct("Attach")
                .field("policy", &"<redacted>")
                .field("resource_claims", resource_claims)
                .finish(),
            Self::Confirm => formatter.write_str("Confirm"),
            Self::StartAgent {
                sandbox_id,
                spec,
                policy: _,
                ca_cert,
                ca_bundle,
                provider_env_revision,
                provider_env,
            } => formatter
                .debug_struct("StartAgent")
                .field("sandbox_id", sandbox_id)
                .field("spec", spec)
                .field("policy", &"<redacted>")
                .field("ca_cert_present", &ca_cert.is_some())
                .field("ca_bundle_present", &ca_bundle.is_some())
                .field("provider_env_revision", provider_env_revision)
                .field(
                    "provider_env_keys",
                    &provider_env.keys().collect::<Vec<_>>(),
                )
                .finish(),
            Self::UpdateProviderEnvironment {
                expected_revision,
                revision,
                provider_env,
            } => formatter
                .debug_struct("UpdateProviderEnvironment")
                .field("expected_revision", expected_revision)
                .field("revision", revision)
                .field(
                    "provider_env_keys",
                    &provider_env.keys().collect::<Vec<_>>(),
                )
                .finish(),
            Self::Wait { process_id } => formatter
                .debug_struct("Wait")
                .field("process_id", process_id)
                .finish(),
            Self::AttachProcess { process_id } => formatter
                .debug_struct("AttachProcess")
                .field("process_id", process_id)
                .finish(),
            Self::Signal { process_id, signal } => formatter
                .debug_struct("Signal")
                .field("process_id", process_id)
                .field("signal", signal)
                .finish(),
            Self::Terminate { process_id } => formatter
                .debug_struct("Terminate")
                .field("process_id", process_id)
                .finish(),
            Self::Exec { spec } => formatter.debug_tuple("Exec").field(spec).finish(),
            Self::ExecSignal { process_id, signal } => formatter
                .debug_struct("ExecSignal")
                .field("process_id", process_id)
                .field("signal", signal)
                .finish(),
            Self::Resize {
                process_id,
                cols,
                rows,
            } => formatter
                .debug_struct("Resize")
                .field("process_id", process_id)
                .field("cols", cols)
                .field("rows", rows)
                .finish(),
            Self::PortForward { host, port } => formatter
                .debug_struct("PortForward")
                .field("host", host)
                .field("port", port)
                .finish(),
            Self::AcceptNetwork => formatter.write_str("AcceptNetwork"),
            Self::AcceptDns => formatter.write_str("AcceptDns"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub request_id: String,
    pub response: Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Attached {
        snapshot: SessionSnapshotWire,
    },
    Confirmed {
        /// Measured capability-free posture produced before workload launch.
        evidence: Box<SandboxConfirmEvidence>,
    },
    Started {
        process_id: String,
        provider_env_revision: u64,
    },
    ProviderEnvironmentUpdated {
        revision: u64,
    },
    ProcessAttached {
        terminal: bool,
    },
    Exited {
        status: ExitStatusWire,
    },
    Signaled,
    Terminated,
    ExecStarted {
        process_id: String,
        pty: bool,
    },
    Resized,
    PortConnected,
    NetworkConnected {
        identity: BinaryIdentityWire,
        destination: std::net::SocketAddr,
        socket: crate::contract::NetworkSocketMetadata,
        policy_generation: u64,
    },
    DnsQuery {
        request: Vec<u8>,
        transport: crate::contract::DnsTransport,
        identity: BinaryIdentityWire,
    },
    Error {
        kind: String,
        message: String,
    },
}

/// Boundary-owned process/session state returned on every supervisor attach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshotWire {
    pub generation: String,
    pub processes: Vec<ProcessSnapshotWire>,
}

/// Stable generation-scoped process state available to a replacement supervisor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshotWire {
    pub process_id: String,
    pub kind: ProcessKindWire,
    pub terminal: bool,
    pub status: Option<ExitStatusWire>,
    pub retained_output: OutputWindowWire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessKindWire {
    Main,
    Exec,
}

/// Sequence range retained by the sandbox output ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputWindowWire {
    pub first_sequence: u64,
    pub next_sequence: u64,
    pub truncated: bool,
}

/// Completion of one sandbox-local DNS relay exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum DnsQueryResultWire {
    Response(Vec<u8>),
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentityWire {
    pub binary_path: Option<PathBuf>,
    pub binary_digest: Option<String>,
    pub ancestors: Vec<PathBuf>,
    pub cmdline_paths: Vec<PathBuf>,
    pub resolve_error: Option<String>,
}

impl From<Result<BinaryIdentity, ResolveError>> for BinaryIdentityWire {
    fn from(identity: Result<BinaryIdentity, ResolveError>) -> Self {
        match identity {
            Ok(identity) => Self {
                binary_path: Some(identity.binary_path),
                binary_digest: identity.binary_digest.map(|digest| digest.to_string()),
                ancestors: identity.ancestors,
                cmdline_paths: identity.cmdline_paths,
                resolve_error: None,
            },
            Err(error) => Self {
                binary_path: None,
                binary_digest: None,
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
                resolve_error: Some(error.to_string()),
            },
        }
    }
}

impl BinaryIdentityWire {
    pub fn into_result(self) -> Result<BinaryIdentity, ResolveError> {
        if let Some(error) = self.resolve_error {
            return Err(ResolveError::Failed(error));
        }
        let binary_path = self.binary_path.ok_or_else(|| {
            ResolveError::Failed("boundary identity omitted binary path".to_string())
        })?;
        let binary_digest = self
            .binary_digest
            .map(|digest| digest.parse::<Sha256Digest>())
            .transpose()?;
        Ok(BinaryIdentity {
            binary_path,
            binary_digest,
            ancestors: self.ancestors,
            cmdline_paths: self.cmdline_paths,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSpecWire {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub pty: bool,
}

impl From<ExecSpec> for ExecSpecWire {
    fn from(spec: ExecSpec) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            env: spec.env,
            workdir: spec.workdir,
            pty: spec.pty,
        }
    }
}

impl From<ExecSpecWire> for ExecSpec {
    fn from(spec: ExecSpecWire) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            env: spec.env,
            workdir: spec.workdir,
            pty: spec.pty,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpecWire {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub timeout_secs: u64,
    pub interactive: bool,
}

impl From<AgentSpec> for AgentSpecWire {
    fn from(spec: AgentSpec) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            workdir: spec.workdir,
            timeout_secs: spec.timeout_secs,
            interactive: spec.interactive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicyWire {
    pub version: u32,
    pub read_only: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub include_workdir: bool,
    pub network: NetworkModeWire,
    pub proxy_addr: Option<std::net::SocketAddr>,
    pub landlock: LandlockCompatibilityWire,
    pub run_as_user: Option<String>,
    pub run_as_group: Option<String>,
}

impl From<SandboxPolicy> for SandboxPolicyWire {
    fn from(policy: SandboxPolicy) -> Self {
        // Exhaustively destructure the policy so adding a `SandboxPolicy`
        // field is a compile error here instead of a silently dropped field
        // across the host-to-guest trust boundary.
        let SandboxPolicy {
            version,
            filesystem,
            network,
            landlock,
            process,
        } = policy;
        let FilesystemPolicy {
            read_only,
            read_write,
            include_workdir,
        } = filesystem;
        let NetworkPolicy { mode, proxy } = network;
        let LandlockPolicy { compatibility } = landlock;
        let ProcessPolicy {
            run_as_user,
            run_as_group,
        } = process;
        Self {
            version,
            read_only,
            read_write,
            include_workdir,
            network: NetworkModeWire::from(mode),
            proxy_addr: proxy.and_then(|proxy| proxy.http_addr),
            landlock: LandlockCompatibilityWire::from(compatibility),
            run_as_user,
            run_as_group,
        }
    }
}

impl From<SandboxPolicyWire> for SandboxPolicy {
    fn from(policy: SandboxPolicyWire) -> Self {
        let proxy = matches!(policy.network, NetworkModeWire::Proxy).then_some(ProxyPolicy {
            http_addr: policy.proxy_addr,
        });
        Self {
            version: policy.version,
            filesystem: FilesystemPolicy {
                read_only: policy.read_only,
                read_write: policy.read_write,
                include_workdir: policy.include_workdir,
            },
            network: NetworkPolicy {
                mode: policy.network.into(),
                proxy,
            },
            landlock: LandlockPolicy {
                compatibility: policy.landlock.into(),
            },
            process: ProcessPolicy {
                run_as_user: policy.run_as_user,
                run_as_group: policy.run_as_group,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkModeWire {
    Block,
    Proxy,
    Allow,
}

impl From<NetworkMode> for NetworkModeWire {
    fn from(mode: NetworkMode) -> Self {
        match mode {
            NetworkMode::Block => Self::Block,
            NetworkMode::Proxy => Self::Proxy,
            NetworkMode::Allow => Self::Allow,
        }
    }
}

impl From<NetworkModeWire> for NetworkMode {
    fn from(mode: NetworkModeWire) -> Self {
        match mode {
            NetworkModeWire::Block => Self::Block,
            NetworkModeWire::Proxy => Self::Proxy,
            NetworkModeWire::Allow => Self::Allow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibilityWire {
    BestEffort,
    HardRequirement,
}

impl From<LandlockCompatibility> for LandlockCompatibilityWire {
    fn from(compatibility: LandlockCompatibility) -> Self {
        match compatibility {
            LandlockCompatibility::BestEffort => Self::BestEffort,
            LandlockCompatibility::HardRequirement => Self::HardRequirement,
        }
    }
}

impl From<LandlockCompatibilityWire> for LandlockCompatibility {
    fn from(compatibility: LandlockCompatibilityWire) -> Self {
        match compatibility {
            LandlockCompatibilityWire::BestEffort => Self::BestEffort,
            LandlockCompatibilityWire::HardRequirement => Self::HardRequirement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalWire {
    Term,
    Kill,
    Int,
    Hup,
}

impl From<BoundarySignal> for SignalWire {
    fn from(signal: BoundarySignal) -> Self {
        match signal {
            BoundarySignal::Term => Self::Term,
            BoundarySignal::Kill => Self::Kill,
            BoundarySignal::Int => Self::Int,
            BoundarySignal::Hup => Self::Hup,
        }
    }
}

impl From<SignalWire> for BoundarySignal {
    fn from(signal: SignalWire) -> Self {
        match signal {
            SignalWire::Term => Self::Term,
            SignalWire::Kill => Self::Kill,
            SignalWire::Int => Self::Int,
            SignalWire::Hup => Self::Hup,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExitStatusWire {
    Exited(i32),
    Signaled(i32),
}

impl From<ExitStatusWire> for BoundaryExitStatus {
    fn from(status: ExitStatusWire) -> Self {
        match status {
            ExitStatusWire::Exited(code) => Self::Exited(code),
            ExitStatusWire::Signaled(signal) => Self::Signaled(signal),
        }
    }
}

impl From<BoundaryExitStatus> for ExitStatusWire {
    fn from(status: BoundaryExitStatus) -> Self {
        match status {
            BoundaryExitStatus::Exited(code) => Self::Exited(code),
            BoundaryExitStatus::Signaled(signal) => Self::Signaled(signal),
        }
    }
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(message).map_err(FrameError::Serialize)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    let header: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let payload = frame.get(4..).ok_or(FrameError::Truncated)?;
    if payload.len() != declared {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }
    serde_json::from_slice(payload).map_err(FrameError::Deserialize)
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let mut frame = Vec::with_capacity(4 + declared);
    frame.extend_from_slice(&header);
    frame.resize(4 + declared, 0);
    reader.read_exact(&mut frame[4..])?;
    decode_frame(&frame)
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<(), FrameError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("control frame is truncated")]
    Truncated,
    #[error("control frame is too large: {0} bytes")]
    TooLarge(usize),
    #[error("control frame declared {declared} bytes but contained {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("serialize control frame: {0}")]
    Serialize(serde_json::Error),
    #[error("deserialize control frame: {0}")]
    Deserialize(serde_json::Error),
    #[error("control request payload digest does not match its envelope")]
    PayloadDigestMismatch,
    #[error("read or write control frame: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_redacts_token() {
        let request = RequestEnvelope {
            request_id: "4e94636d-54f8-4d85-8e4e-58954fb5af0a".to_string(),
            payload_digest: String::new(),
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "never-log-this".to_string(),
            request: Request::StartAgent {
                sandbox_id: "sandbox-1".to_string(),
                spec: AgentSpecWire {
                    program: "/bin/true".to_string(),
                    args: Vec::new(),
                    workdir: Some("/sandbox".to_string()),
                    timeout_secs: 5,
                    interactive: false,
                },
                policy: Box::new(SandboxPolicyWire::from(SandboxPolicy {
                    version: 1,
                    filesystem: FilesystemPolicy::default(),
                    network: NetworkPolicy::default(),
                    landlock: LandlockPolicy::default(),
                    process: ProcessPolicy::default(),
                })),
                ca_cert: Some(b"test certificate".to_vec()),
                ca_bundle: Some(b"test bundle".to_vec()),
                provider_env_revision: 7,
                provider_env: std::collections::HashMap::from([(
                    "OPENAI_API_KEY".to_string(),
                    "test credential".to_string(),
                )]),
            },
        };
        let request = RequestEnvelope {
            payload_digest: request_payload_digest(&request.request).expect("request digest"),
            ..request
        };
        let frame = encode_frame(&request).expect("encode request");
        let decoded: RequestEnvelope = decode_frame(&frame).expect("decode request");
        assert_eq!(decoded, request);
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
        assert!(!debug.contains("test credential"));
        assert!(!debug.contains("test certificate"));
        assert!(!debug.contains("test bundle"));
        assert!(debug.contains("OPENAI_API_KEY"));
        assert!(request.validate_payload_digest().is_ok());
    }

    #[test]
    fn request_digest_is_stable_across_map_order_and_detects_mutation() {
        let mut first = std::collections::HashMap::new();
        first.insert("B".to_string(), "2".to_string());
        first.insert("A".to_string(), "1".to_string());
        let mut second = std::collections::HashMap::new();
        second.insert("A".to_string(), "1".to_string());
        second.insert("B".to_string(), "2".to_string());
        let build = |provider_env| Request::UpdateProviderEnvironment {
            expected_revision: 1,
            revision: 2,
            provider_env,
        };
        assert_eq!(
            request_payload_digest(&build(first)).expect("first digest"),
            request_payload_digest(&build(second)).expect("second digest")
        );

        let mut envelope = RequestEnvelope::new(
            "sandbox-1".to_string(),
            "token".to_string(),
            build(std::collections::HashMap::new()),
        )
        .expect("request envelope");
        envelope.request = Request::Terminate {
            process_id: "different".to_string(),
        };
        assert!(matches!(
            envelope.validate_payload_digest(),
            Err(FrameError::PayloadDigestMismatch)
        ));
    }

    #[test]
    fn rejects_declared_oversize() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).expect("test size fits u32");
        let mut frame = Vec::from(oversized.to_be_bytes());
        frame.extend_from_slice(b"{}");
        assert!(matches!(
            decode_frame::<RequestEnvelope>(&frame),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn resource_claims_reject_empty_or_ambiguous_identities() {
        assert!(
            validate_resource_claims(&std::collections::BTreeMap::from([(
                "kubernetes.pod_uid".to_string(),
                String::new()
            ),]))
            .is_err()
        );
        assert!(
            validate_resource_claims(&std::collections::BTreeMap::from([(
                "kubernetes.pod uid".to_string(),
                "uid-1".to_string()
            ),]))
            .is_err()
        );
        validate_resource_claims(&std::collections::BTreeMap::from([(
            "kubernetes.pod_uid".to_string(),
            "uid-1".to_string(),
        )]))
        .expect("opaque resource identity should be valid");
    }
}
