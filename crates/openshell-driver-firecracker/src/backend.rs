// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side RFC 0012 backend for an already-provisioned Firecracker VM.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{
    BackendError, BoundBoundary, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryPortForward, BoundaryProcess, BoundarySignal, ExecSession, ExecSpec, INTERFACE_VERSION,
    IsolationBackend, LoopbackTarget, MediatedConnection, NetworkMediationSource, ReadyBoundary,
    RunningBoundary, SandboxContext, VerifiedTopologyDescriptor,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::protocol::{
    AgentSpecWire, MAX_CONTROL_FRAME_BYTES, Request, RequestEnvelope, Response, ResponseEnvelope,
    SandboxPolicyWire, SignalWire, decode_frame, encode_frame,
};

pub const BACKEND_NAME: &str = "firecracker";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;
const MAX_VSOCK_ACK_BYTES: usize = 64;

/// Backend-private provisioned topology payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerTopology {
    pub boundary_id: String,
    pub vsock_uds_path: PathBuf,
    pub control_port: u32,
    pub bootstrap_token: String,
}

impl fmt::Debug for FirecrackerTopology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrackerTopology")
            .field("boundary_id", &self.boundary_id)
            .field("vsock_uds_path", &self.vsock_uds_path)
            .field("control_port", &self.control_port)
            .field("bootstrap_token", &"<redacted>")
            .finish()
    }
}

impl FirecrackerTopology {
    pub fn encode(&self) -> Result<Vec<u8>, BackendError> {
        serde_json::to_vec(self)
            .map_err(|error| BackendError::Descriptor(format!("encode topology: {error}")))
    }
}

/// Host-side Firecracker implementation registered with the supervisor.
#[derive(Debug, Default)]
pub struct FirecrackerHostBackend;

#[async_trait]
impl IsolationBackend for FirecrackerHostBackend {
    fn backend_name(&self) -> &str {
        BACKEND_NAME
    }

    fn version(&self) -> u32 {
        INTERFACE_VERSION
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let topology: FirecrackerTopology = serde_json::from_slice(descriptor.payload())
            .map_err(|error| BackendError::Descriptor(format!("decode topology: {error}")))?;
        validate_topology(&topology, &sandbox)?;
        let client = Arc::new(GuestClient::new(topology));
        expect_response(client.call(Request::Attach).await?, "attached")?;
        Ok(Box::new(FirecrackerBound {
            client,
            agent: sandbox.agent,
            policy: sandbox.policy,
            sandbox_id: sandbox.sandbox_id,
            mediation: Arc::new(NoGuestNetwork),
        }))
    }
}

fn validate_topology(
    topology: &FirecrackerTopology,
    sandbox: &SandboxContext,
) -> Result<(), BackendError> {
    if topology.boundary_id != sandbox.sandbox_id {
        return Err(BackendError::Descriptor(format!(
            "Firecracker boundary {:?} does not match sandbox {:?}",
            topology.boundary_id, sandbox.sandbox_id
        )));
    }
    if topology.bootstrap_token.len() < MIN_BOOTSTRAP_TOKEN_BYTES {
        return Err(BackendError::Descriptor(format!(
            "Firecracker bootstrap token must be at least {MIN_BOOTSTRAP_TOKEN_BYTES} bytes"
        )));
    }
    if !topology.vsock_uds_path.is_absolute() {
        return Err(BackendError::Descriptor(
            "Firecracker vsock UDS path must be absolute".to_string(),
        ));
    }
    if topology.control_port == 0 {
        return Err(BackendError::Descriptor(
            "Firecracker guest control port must be nonzero".to_string(),
        ));
    }
    Ok(())
}

struct FirecrackerBound {
    client: Arc<GuestClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    mediation: Arc<NoGuestNetwork>,
}

#[async_trait]
impl BoundBoundary for FirecrackerBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.mediation.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        expect_response(self.client.call(Request::Confirm).await?, "confirmed")?;
        Ok(Box::new(FirecrackerReady {
            client: self.client,
            agent: self.agent,
            policy: self.policy,
            sandbox_id: self.sandbox_id,
        }))
    }
}

struct FirecrackerReady {
    client: Arc<GuestClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
}

#[async_trait]
impl ReadyBoundary for FirecrackerReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let response = self
            .client
            .call(Request::StartAgent {
                sandbox_id: self.sandbox_id,
                spec: AgentSpecWire::from(self.agent),
                policy: Box::new(SandboxPolicyWire::from(self.policy)),
            })
            .await?;
        let Response::Started { process_id } = response else {
            return Err(unexpected_response("started", &response));
        };
        let process = Arc::new(FirecrackerProcess {
            client: self.client,
            process_id,
        });
        Ok(Box::new(FirecrackerRunning {
            process,
            exec: Arc::new(UnsupportedExec),
            port_forward: Arc::new(UnsupportedPortForward),
        }))
    }
}

struct FirecrackerRunning {
    process: Arc<FirecrackerProcess>,
    exec: Arc<UnsupportedExec>,
    port_forward: Arc<UnsupportedPortForward>,
}

impl RunningBoundary for FirecrackerRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }

    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }

    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
}

struct FirecrackerProcess {
    client: Arc<GuestClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryProcess for FirecrackerProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let response = self
            .client
            .call_wait(Request::Wait {
                process_id: self.process_id.clone(),
            })
            .await?;
        let Response::Exited { status } = response else {
            return Err(unexpected_response("exited", &response));
        };
        Ok(status.into())
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let response = self
            .client
            .call(Request::Signal {
                process_id: self.process_id.clone(),
                signal: SignalWire::from(signal),
            })
            .await?;
        expect_response(response, "signaled")
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        let response = self
            .client
            .call(Request::Terminate {
                process_id: self.process_id.clone(),
            })
            .await?;
        expect_response(response, "terminated")
    }
}

struct UnsupportedExec;

#[async_trait]
impl BoundaryExec for UnsupportedExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Unavailable(
            "Firecracker exec and PTY transport are not implemented in this prototype".to_string(),
        ))
    }
}

struct UnsupportedPortForward;

#[async_trait]
impl BoundaryPortForward for UnsupportedPortForward {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        Err(BackendError::Unavailable(
            "Firecracker loopback forwarding is not implemented in this prototype".to_string(),
        ))
    }
}

/// The prototype provisions no guest NIC. There can be no workload egress to
/// accept, and attempting to consume the source fails the boundary closed.
struct NoGuestNetwork;

#[async_trait]
impl NetworkMediationSource for NoGuestNetwork {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        // No NIC means there is no connection source to drain. Keeping the
        // accept future pending lets the host network supervisor remain alive
        // without treating the structurally closed boundary as a transport
        // failure.
        std::future::pending().await
    }
}

struct GuestClient {
    topology: FirecrackerTopology,
    next_request_id: AtomicU64,
}

impl GuestClient {
    fn new(topology: FirecrackerTopology) -> Self {
        Self {
            topology,
            next_request_id: AtomicU64::new(1),
        }
    }

    async fn call(&self, request: Request) -> Result<Response, BackendError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| BackendError::Unavailable("guest control request timed out".to_string()))?
    }

    async fn call_wait(&self, request: Request) -> Result<Response, BackendError> {
        self.exchange(request).await
    }

    async fn exchange(&self, request: Request) -> Result<Response, BackendError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let envelope = RequestEnvelope {
            request_id,
            boundary_id: self.topology.boundary_id.clone(),
            bootstrap_token: self.topology.bootstrap_token.clone(),
            request,
        };
        let mut stream = self.connect_vsock().await?;
        let frame = encode_frame(&envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write guest control request: {error}"))
        })?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.map_err(|error| {
            BackendError::Unavailable(format!("read guest control response header: {error}"))
        })?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > MAX_CONTROL_FRAME_BYTES {
            return Err(BackendError::Process(format!(
                "guest control response is too large: {declared} bytes"
            )));
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&header);
        frame.resize(4 + declared, 0);
        stream.read_exact(&mut frame[4..]).await.map_err(|error| {
            BackendError::Unavailable(format!("read guest control response: {error}"))
        })?;
        let response: ResponseEnvelope = decode_frame(&frame)
            .map_err(|error| BackendError::Process(format!("decode control response: {error}")))?;
        if response.request_id != request_id {
            return Err(BackendError::Process(format!(
                "guest response ID {} did not match request ID {request_id}",
                response.request_id
            )));
        }
        match response.response {
            Response::Error { kind, message } => Err(guest_error(&kind, message)),
            response => Ok(response),
        }
    }

    async fn connect_vsock(&self) -> Result<UnixStream, BackendError> {
        let mut stream = UnixStream::connect(&self.topology.vsock_uds_path)
            .await
            .map_err(|error| {
                BackendError::Unavailable(format!("connect to Firecracker vsock UDS: {error}"))
            })?;
        stream
            .write_all(format!("CONNECT {}\n", self.topology.control_port).as_bytes())
            .await
            .map_err(|error| {
                BackendError::Unavailable(format!("write Firecracker vsock handshake: {error}"))
            })?;
        let acknowledgment = read_vsock_acknowledgment(&mut stream).await?;
        validate_vsock_acknowledgment(&acknowledgment)?;
        Ok(stream)
    }
}

async fn read_vsock_acknowledgment(stream: &mut UnixStream) -> Result<Vec<u8>, BackendError> {
    let mut acknowledgment = Vec::with_capacity(24);
    loop {
        if acknowledgment.len() == MAX_VSOCK_ACK_BYTES {
            return Err(BackendError::Process(
                "Firecracker vsock acknowledgment is too long".to_string(),
            ));
        }
        let byte = stream.read_u8().await.map_err(|error| {
            BackendError::Unavailable(format!("read Firecracker vsock acknowledgment: {error}"))
        })?;
        acknowledgment.push(byte);
        if byte == b'\n' {
            return Ok(acknowledgment);
        }
    }
}

fn validate_vsock_acknowledgment(acknowledgment: &[u8]) -> Result<(), BackendError> {
    let acknowledgment = std::str::from_utf8(acknowledgment).map_err(|_| {
        BackendError::Process("Firecracker vsock acknowledgment is not UTF-8".to_string())
    })?;
    let mut fields = acknowledgment
        .trim_end_matches('\n')
        .split_ascii_whitespace();
    let status = fields.next();
    let assigned_port = fields.next().and_then(|port| port.parse::<u32>().ok());
    if status != Some("OK") || assigned_port.is_none() || fields.next().is_some() {
        return Err(BackendError::Process(format!(
            "invalid Firecracker vsock acknowledgment: {acknowledgment:?}"
        )));
    }
    Ok(())
}

fn expect_response(response: Response, expected: &str) -> Result<(), BackendError> {
    let matches = matches!(
        (&response, expected),
        (Response::Attached, "attached")
            | (Response::Confirmed, "confirmed")
            | (Response::Signaled, "signaled")
            | (Response::Terminated, "terminated")
    );
    if matches {
        Ok(())
    } else {
        Err(unexpected_response(expected, &response))
    }
}

fn unexpected_response(expected: &str, response: &Response) -> BackendError {
    BackendError::Process(format!(
        "expected guest response {expected:?}, received {response:?}"
    ))
}

fn guest_error(kind: &str, message: String) -> BackendError {
    let message = format!("Firecracker guest process leaf: {message}");
    match kind {
        "invalid" => BackendError::Descriptor(message),
        "denied" => BackendError::Denied(message),
        "unavailable" => BackendError::Unavailable(message),
        "terminated" => BackendError::Terminated(message),
        _ => BackendError::Process(message),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };

    use super::*;

    fn sandbox() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sandbox-1".to_string(),
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
        }
    }

    #[test]
    fn topology_debug_redacts_token() {
        let topology = FirecrackerTopology {
            boundary_id: "sandbox-1".to_string(),
            vsock_uds_path: PathBuf::from("/tmp/vsock.sock"),
            control_port: 5500,
            bootstrap_token: "never-log-this-never-log-this".to_string(),
        };
        let debug = format!("{topology:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
    }

    #[test]
    fn topology_must_match_sandbox() {
        let topology = FirecrackerTopology {
            boundary_id: "other".to_string(),
            vsock_uds_path: PathBuf::from("/tmp/vsock.sock"),
            control_port: 5500,
            bootstrap_token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        assert!(matches!(
            validate_topology(&topology, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn validates_firecracker_acknowledgment() {
        assert!(validate_vsock_acknowledgment(b"OK 1234\n").is_ok());
        assert!(validate_vsock_acknowledgment(b"ERR\n").is_err());
    }
}
