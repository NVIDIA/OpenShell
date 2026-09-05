// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side RFC 0012 backend for an already-provisioned remote boundary.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd as _, IntoRawFd as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::AgentSpec;
use crate::contract::{
    BackendError, BoundBoundary, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryInput, BoundaryOutput, BoundaryPortForward, BoundaryProcess, BoundarySignal,
    BoundaryTerminal, ConfirmedBoundary, DnsMediationSource, ExecSession, ExecSpec,
    IsolationBackend, LoopbackTarget, MediatedDnsQuery, NetworkMediationSource, NetworkOpenResult,
    PendingNetworkOpen, ProcessAttachment, ReadyBoundary, RunningBoundary, SandboxContext,
    VerifiedTopologyDescriptor,
};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;

use crate::boundary_protocol::{
    AgentSpecWire, BoundaryClientTls, BoundaryTopology, BoundaryTransport, DnsQueryResultWire,
    ExecSpecWire, ExitStatusWire, MAX_CONTROL_FRAME_BYTES, Request, RequestEnvelope, Response,
    ResponseEnvelope, STREAM_DNS_ACK, STREAM_DNS_RESPONSE, STREAM_EXIT, STREAM_STDERR,
    STREAM_STDIN, STREAM_STDIN_CLOSED, STREAM_STDOUT, SandboxPolicyWire, SignalWire, decode_frame,
    encode_frame, read_stream_frame, validate_resource_claims, write_stream_frame,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one control call keeps retrying boundary connect attempts. Boot-time
/// callers retry whole calls above this; past boot, exhausting this window
/// means the remote boundary (or its launcher) is gone rather than still starting.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;

/// Host-side remote boundary implementation registered with the supervisor.
#[derive(Debug)]
pub struct RemoteIsolationBackend {
    backend_name: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
}

impl RemoteIsolationBackend {
    pub fn new(
        backend_name: impl Into<String>,
        ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    ) -> Self {
        Self {
            backend_name: backend_name.into(),
            ca_file_paths,
            provider_credentials,
        }
    }
}

#[async_trait]
impl IsolationBackend for RemoteIsolationBackend {
    fn backend_name(&self) -> &str {
        &self.backend_name
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let topology: BoundaryTopology = serde_json::from_slice(descriptor.payload())
            .map_err(|error| BackendError::Descriptor(format!("decode topology: {error}")))?;
        validate_topology(&topology, &sandbox, &self.backend_name)?;
        let host_gateway_ip = topology.host_gateway_ip;
        let resource_claims = topology.resource_claims.clone();
        let generation = topology.generation.clone();
        let session_epoch = topology.session_epoch.clone();
        let driver_fence = topology.driver_fence.clone();
        let client = Arc::new(BoundaryClient::new(topology));
        let response = client
            .call_idempotent(Request::Attach {
                policy: Box::new(SandboxPolicyWire::from(sandbox.policy.clone())),
                resource_claims: resource_claims.clone(),
            })
            .await?;
        let Response::Attached { snapshot } = response else {
            return Err(unexpected_response("attached", &response));
        };
        if snapshot.generation != generation {
            return Err(BackendError::Confirm(
                "sandbox session snapshot generation does not match topology".to_string(),
            ));
        }
        Ok(Box::new(RemoteBound {
            client: client.clone(),
            agent: sandbox.agent,
            policy: sandbox.policy,
            sandbox_id: sandbox.sandbox_id,
            mediation: Arc::new(RemoteNetworkMediation {
                client: client.clone(),
            }),
            dns_mediation: Arc::new(RemoteDnsMediation { client }),
            host_gateway_ip,
            ca_file_paths: self.ca_file_paths.clone(),
            provider_credentials: self.provider_credentials.clone(),
            identity: sandbox.identity,
            generation,
            session_epoch,
            resource_claims,
            driver_fence,
        }))
    }
}

fn validate_topology(
    topology: &BoundaryTopology,
    sandbox: &SandboxContext,
    backend_name: &str,
) -> Result<(), BackendError> {
    if topology.boundary_id != sandbox.sandbox_id {
        return Err(BackendError::Descriptor(format!(
            "boundary {:?} does not match sandbox {:?}",
            topology.boundary_id, sandbox.sandbox_id
        )));
    }
    if topology.generation.is_empty() || topology.session_epoch.is_empty() {
        return Err(BackendError::Descriptor(
            "boundary generation and session epoch must not be empty".to_string(),
        ));
    }
    if topology.workload_identity != sandbox.identity {
        return Err(BackendError::Descriptor(
            "topology workload identity does not match admitted sandbox identity".to_string(),
        ));
    }
    if topology.bootstrap_token.len() < MIN_BOOTSTRAP_TOKEN_BYTES {
        return Err(BackendError::Descriptor(format!(
            "boundary bootstrap token must be at least {MIN_BOOTSTRAP_TOKEN_BYTES} bytes"
        )));
    }
    validate_resource_claims(&topology.resource_claims)?;
    topology.driver_fence.validate_for_backend(backend_name)?;
    let tls = match &topology.transport {
        BoundaryTransport::Unix { socket_path, tls } => {
            validate_socket_path(socket_path)?;
            tls
        }
        BoundaryTransport::TlsTcp { address, tls } => {
            validate_tcp_address(*address)?;
            tls
        }
        BoundaryTransport::Vsock {
            guest_cid,
            control_port,
            tls,
        } => {
            if *guest_cid < 3 {
                return Err(BackendError::Descriptor(
                    "boundary CID must be at least 3".to_string(),
                ));
            }
            validate_control_port(*control_port)?;
            tls
        }
    };
    validate_client_tls(tls)?;
    Ok(())
}

fn validate_tcp_address(address: std::net::SocketAddr) -> Result<(), BackendError> {
    if address.port() == 0 || address.ip().is_unspecified() {
        Err(BackendError::Descriptor(
            "boundary TCP address must have a concrete IP and nonzero port".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn validate_client_tls(tls: &BoundaryClientTls) -> Result<(), BackendError> {
    rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|error| {
        BackendError::Descriptor(format!(
            "boundary TLS server name {:?} is invalid: {error}",
            tls.server_name
        ))
    })?;
    tls_client_config(tls).map(|_| ())
}

fn tls_client_config(tls: &BoundaryClientTls) -> Result<rustls::ClientConfig, BackendError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = rustls_pemfile::certs(&mut tls.ca_certificate_pem.as_bytes())
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
    let certificate_chain = rustls_pemfile::certs(&mut tls.certificate_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            BackendError::Descriptor(format!("parse supervisor TLS certificate: {error}"))
        })?;
    if certificate_chain.is_empty() {
        return Err(BackendError::Descriptor(
            "supervisor TLS certificate PEM contains no certificates".to_string(),
        ));
    }
    let private_key = rustls_pemfile::private_key(&mut tls.private_key_pem.as_bytes())
        .map_err(|error| {
            BackendError::Descriptor(format!("parse supervisor TLS private key: {error}"))
        })?
        .ok_or_else(|| {
            BackendError::Descriptor(
                "supervisor TLS private-key PEM contains no private key".to_string(),
            )
        })?;
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(|error| {
            BackendError::Descriptor(format!("build supervisor mutual-TLS config: {error}"))
        })
}

fn validate_socket_path(path: &std::path::Path) -> Result<(), BackendError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(BackendError::Descriptor(
            "boundary control Unix socket path must be absolute".to_string(),
        ))
    }
}

fn validate_control_port(port: u32) -> Result<(), BackendError> {
    if port == 0 {
        Err(BackendError::Descriptor(
            "boundary control port must be nonzero".to_string(),
        ))
    } else {
        Ok(())
    }
}

struct RemoteBound {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    mediation: Arc<RemoteNetworkMediation>,
    dns_mediation: Arc<RemoteDnsMediation>,
    host_gateway_ip: Option<std::net::IpAddr>,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    identity: crate::contract::ResolvedWorkloadIdentity,
    generation: String,
    session_epoch: String,
    resource_claims: std::collections::BTreeMap<String, String>,
    driver_fence: crate::contract::DriverFenceEvidence,
}

#[async_trait]
impl BoundBoundary for RemoteBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.mediation.clone()
    }

    fn dns_mediation_source(&self) -> Option<Arc<dyn DnsMediationSource>> {
        Some(self.dns_mediation.clone())
    }

    fn host_gateway_ip(&self) -> Option<std::net::IpAddr> {
        self.host_gateway_ip
    }

    async fn confirm(self: Box<Self>) -> Result<ConfirmedBoundary, BackendError> {
        let response = self.client.call_idempotent(Request::Confirm).await?;
        let Response::Confirmed { evidence } = response else {
            return Err(unexpected_response("confirmed_with_evidence", &response));
        };
        evidence.validate(&self.identity)?;
        if evidence.generation != self.generation
            || evidence.session_epoch != self.session_epoch
            || evidence.resource_claims != self.resource_claims
            || evidence.driver_fence != self.driver_fence
        {
            return Err(BackendError::Confirm(
                "sandbox confirmation generation, session, resource claims, or driver fence do not match topology"
                    .to_string(),
            ));
        }
        Ok(ConfirmedBoundary::new(
            Box::new(RemoteReady {
                client: self.client,
                agent: self.agent,
                policy: self.policy,
                sandbox_id: self.sandbox_id,
                ca_file_paths: self.ca_file_paths,
                provider_credentials: self.provider_credentials,
            }),
            *evidence,
        ))
    }
}

struct RemoteReady {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
}

#[async_trait]
impl ReadyBoundary for RemoteReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let ca_paths = self
            .ca_file_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (ca_cert, ca_bundle) = if let Some((ca_cert, ca_bundle)) = ca_paths {
            let ca_cert = tokio::fs::read(&ca_cert).await.map_err(|error| {
                BackendError::Process(format!("read host proxy CA {}: {error}", ca_cert.display()))
            })?;
            let ca_bundle = tokio::fs::read(&ca_bundle).await.map_err(|error| {
                BackendError::Process(format!(
                    "read host proxy CA bundle {}: {error}",
                    ca_bundle.display()
                ))
            })?;
            (Some(ca_cert), Some(ca_bundle))
        } else {
            (None, None)
        };
        let (provider_env_revision, provider_env) = self
            .provider_credentials
            .child_env_snapshot_with_gcp_resolved();
        let response = self
            .client
            .call_idempotent(Request::StartAgent {
                sandbox_id: self.sandbox_id,
                spec: AgentSpecWire::from(self.agent),
                policy: Box::new(SandboxPolicyWire::from(self.policy)),
                ca_cert,
                ca_bundle,
                provider_env_revision,
                provider_env,
            })
            .await?;
        let Response::Started {
            process_id,
            provider_env_revision,
        } = response
        else {
            return Err(unexpected_response("started", &response));
        };
        let process = Arc::new(RemoteProcess {
            client: self.client.clone(),
            process_id,
        });
        Ok(Box::new(RemoteRunning {
            process,
            exec: Arc::new(RemoteExec {
                client: self.client.clone(),
                provider_credentials: self.provider_credentials,
                boundary_revision: tokio::sync::Mutex::new(provider_env_revision),
            }),
            port_forward: Arc::new(RemotePortForward {
                client: self.client,
            }),
        }))
    }
}

struct RemoteRunning {
    process: Arc<RemoteProcess>,
    exec: Arc<RemoteExec>,
    port_forward: Arc<RemotePortForward>,
}

impl RunningBoundary for RemoteRunning {
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

struct RemoteProcess {
    client: Arc<BoundaryClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryProcess for RemoteProcess {
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        open_process_attachment(self.client.clone(), self.process_id.clone()).await
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
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

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Signal {
                process_id: self.process_id.clone(),
                signal: SignalWire::from(signal),
            })
            .await?;
        expect_response(response, "signaled")
    }

    async fn terminate(&self) -> Result<(), BackendError> {
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
    ));
    let terminal: Option<Arc<dyn BoundaryTerminal>> = if has_terminal {
        let terminal: Arc<dyn BoundaryTerminal> = Arc::new(RemoteTerminal { client, process_id });
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
) {
    loop {
        match read_stream_frame(&mut network).await {
            Ok(Some((STREAM_STDOUT, payload))) => {
                if stdout.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(Some((STREAM_STDERR, payload))) => {
                if stderr.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(Some((STREAM_EXIT, _)) | None) | Err(_) => return,
            Ok(Some((_channel, _))) => return,
        }
    }
}

struct RemoteExec {
    client: Arc<BoundaryClient>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    boundary_revision: tokio::sync::Mutex<u64>,
}

#[async_trait]
impl BoundaryExec for RemoteExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let mut boundary_revision = self.boundary_revision.lock().await;
        for _ in 0..3 {
            let (revision, provider_env) = self
                .provider_credentials
                .child_env_snapshot_with_gcp_resolved();
            let response = self
                .client
                .call_idempotent(Request::UpdateProviderEnvironment {
                    expected_revision: *boundary_revision,
                    revision,
                    provider_env,
                })
                .await?;
            let Response::ProviderEnvironmentUpdated {
                revision: effective_revision,
            } = response
            else {
                return Err(unexpected_response(
                    "provider_environment_updated",
                    &response,
                ));
            };
            *boundary_revision = effective_revision;
            if effective_revision == revision {
                return open_exec_session(self.client.clone(), spec).await;
            }
        }
        Err(BackendError::Process(
            "boundary provider environment changed concurrently during reconciliation".to_string(),
        ))
    }
}

struct RemotePortForward {
    client: Arc<BoundaryClient>,
}

#[async_trait]
impl BoundaryPortForward for RemotePortForward {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        let (stream, response) = self
            .client
            .call_stream(Request::PortForward {
                host: target.host(),
                port: target.port(),
            })
            .await?;
        match response {
            Response::PortConnected => Ok(stream),
            response => Err(unexpected_response("port_connected", &response)),
        }
    }
}

struct RemoteExecProcess {
    client: Arc<BoundaryClient>,
    process_id: String,
    exit: Arc<RemoteExit>,
}

struct RemoteExit {
    result: std::sync::Mutex<Option<Result<BoundaryExitStatus, String>>>,
    changed: Notify,
}

impl RemoteExit {
    fn new() -> Self {
        Self {
            result: std::sync::Mutex::new(None),
            changed: Notify::new(),
        }
    }

    fn set(&self, result: Result<BoundaryExitStatus, String>) {
        let mut current = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_none() {
            *current = Some(result);
            self.changed.notify_waiters();
        }
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        loop {
            let changed = self.changed.notified();
            let result = self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(result) = result {
                return result.map_err(BackendError::Terminated);
            }
            changed.await;
        }
    }
}

#[async_trait]
impl BoundaryProcess for RemoteExecProcess {
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        open_process_attachment(self.client.clone(), self.process_id.clone()).await
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        self.exit.wait().await
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        expect_response(
            self.client
                .call_idempotent(Request::ExecSignal {
                    process_id: self.process_id.clone(),
                    signal: SignalWire::from(signal),
                })
                .await?,
            "signaled",
        )
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.signal(BoundarySignal::Kill).await
    }
}

struct RemoteTerminal {
    client: Arc<BoundaryClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryTerminal for RemoteTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
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
    let exit = Arc::new(RemoteExit::new());
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_exec_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
        exit.clone(),
    ));

    let process: Arc<dyn BoundaryProcess> = Arc::new(RemoteExecProcess {
        client: client.clone(),
        process_id: process_id.clone(),
        exit,
    });
    let terminal: Option<Arc<dyn BoundaryTerminal>> = if pty {
        Some(Arc::new(RemoteTerminal { client, process_id }))
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

async fn pump_exec_responses(
    mut network: tokio::io::ReadHalf<BoundaryDuplexStream>,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
    exit: Arc<RemoteExit>,
) {
    loop {
        match read_stream_frame(&mut network).await {
            Ok(Some((STREAM_STDOUT, payload))) => {
                if stdout.write_all(&payload).await.is_err() {
                    exit.set(Err("boundary exec stdout consumer closed".to_string()));
                    return;
                }
            }
            Ok(Some((STREAM_STDERR, payload))) => {
                if stderr.write_all(&payload).await.is_err() {
                    exit.set(Err("boundary exec stderr consumer closed".to_string()));
                    return;
                }
            }
            Ok(Some((STREAM_EXIT, payload))) => {
                let result = serde_json::from_slice::<ExitStatusWire>(&payload)
                    .map(BoundaryExitStatus::from)
                    .map_err(|error| format!("decode boundary exec exit: {error}"));
                exit.set(result);
                return;
            }
            Ok(Some((channel, _))) => {
                exit.set(Err(format!(
                    "boundary exec returned unexpected stream channel {channel}"
                )));
                return;
            }
            Ok(None) => {
                exit.set(Err(
                    "boundary exec stream closed before exit status".to_string()
                ));
                return;
            }
            Err(error) => {
                exit.set(Err(format!("read boundary exec stream: {error}")));
                return;
            }
        }
    }
}

/// Pulls boundary proxy connections over one authenticated vsock stream each.
struct RemoteNetworkMediation {
    client: Arc<BoundaryClient>,
}

#[async_trait]
impl NetworkMediationSource for RemoteNetworkMediation {
    async fn accept(&self) -> Result<PendingNetworkOpen, BackendError> {
        let (stream, response) = self.client.open_exchange(Request::AcceptNetwork).await?;
        let Response::NetworkConnected {
            identity,
            destination,
            socket,
            policy_generation,
        } = response
        else {
            return Err(unexpected_response("network_connected", &response));
        };
        let (result, completion) = tokio::sync::oneshot::channel();
        let (proxy_stream, transport_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(complete_network_open(stream, transport_stream, completion));
        Ok(PendingNetworkOpen {
            stream: Box::new(proxy_stream),
            binary_identity: identity.into_result(),
            destination,
            socket,
            policy_generation,
            result,
        })
    }
}

/// Pulls sandbox DNS wire exchanges over authenticated control streams.
struct RemoteDnsMediation {
    client: Arc<BoundaryClient>,
}

#[async_trait]
impl DnsMediationSource for RemoteDnsMediation {
    async fn accept(&self) -> Result<MediatedDnsQuery, BackendError> {
        let (stream, response) = self.client.open_exchange(Request::AcceptDns).await?;
        let Response::DnsQuery {
            request,
            transport,
            identity,
        } = response
        else {
            return Err(unexpected_response("dns_query", &response));
        };
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(complete_dns_query(stream, response_rx));
        Ok(MediatedDnsQuery {
            request,
            transport,
            binary_identity: identity.into_result(),
            response: response_tx,
        })
    }
}

async fn complete_dns_query(
    mut boundary: BoundaryDuplexStream,
    response: tokio::sync::oneshot::Receiver<Result<Vec<u8>, BackendError>>,
) {
    let result = match response.await {
        Ok(Ok(response)) => DnsQueryResultWire::Response(response),
        Ok(Err(error)) => DnsQueryResultWire::Error(error.to_string()),
        Err(_) => DnsQueryResultWire::Error("DNS mediation was cancelled".to_string()),
    };
    let payload = match serde_json::to_vec(&result) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "encode mediated DNS response failed: {error}");
            return;
        }
    };
    if let Err(error) = write_stream_frame(&mut boundary, STREAM_DNS_RESPONSE, &payload).await {
        tracing::warn!(%error, "write mediated DNS response failed: {error}");
        return;
    }
    match tokio::time::timeout(REQUEST_TIMEOUT, read_stream_frame(&mut boundary)).await {
        Ok(Ok(Some((STREAM_DNS_ACK, payload)))) if payload.is_empty() => {}
        Ok(Ok(Some((channel, _)))) => {
            tracing::warn!(channel, "unexpected mediated DNS acknowledgement channel");
        }
        Ok(Ok(None)) => tracing::warn!("boundary closed before acknowledging DNS response"),
        Ok(Err(error)) => {
            tracing::warn!(%error, "read mediated DNS acknowledgement failed: {error}");
        }
        Err(_) => tracing::warn!("timed out waiting for mediated DNS acknowledgement"),
    }
}

async fn complete_network_open(
    mut boundary: BoundaryDuplexStream,
    mut transport: tokio::io::DuplexStream,
    completion: tokio::sync::oneshot::Receiver<NetworkOpenResult>,
) {
    let decision = completion.await.unwrap_or(NetworkOpenResult::Denied {
        errno: cancellation_errno(),
    });
    let Ok(payload) = serde_json::to_vec(&decision) else {
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
    if matches!(decision, NetworkOpenResult::RelayReady) {
        let _ = tokio::io::copy_bidirectional(&mut boundary, &mut transport).await;
    }
}

const fn cancellation_errno() -> i32 {
    #[cfg(unix)]
    {
        libc::ECANCELED
    }
    #[cfg(not(unix))]
    {
        125
    }
}

struct BoundaryClient {
    topology: BoundaryTopology,
}

impl BoundaryClient {
    fn new(topology: BoundaryTopology) -> Self {
        Self { topology }
    }

    async fn call_idempotent(&self, request: Request) -> Result<Response, BackendError> {
        let envelope = self.prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(_)) => {
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
        const WAIT_RECONNECT_ATTEMPTS: usize = 3;
        let envelope = self.prepare_request(request)?;
        for attempt in 1..=WAIT_RECONNECT_ATTEMPTS {
            match self.exchange_envelope(&envelope).await {
                Ok(response) => return Ok(response),
                Err(BackendError::Unavailable(_)) if attempt < WAIT_RECONNECT_ATTEMPTS => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded wait reconnect loop always returns")
    }

    async fn call_stream(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.open_exchange(request))
            .await
            .map_err(|_| {
                BackendError::Unavailable("boundary stream request timed out".to_string())
            })?
    }

    async fn call_stream_idempotent(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = self.prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.open_exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(_)) => {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable("boundary idempotent stream request timed out".to_string())
        })?
    }

    #[cfg(test)]
    async fn exchange(&self, request: Request) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange(request).await?;
        Ok(response)
    }

    fn prepare_request(&self, request: Request) -> Result<RequestEnvelope, BackendError> {
        RequestEnvelope::new(
            self.topology.boundary_id.clone(),
            self.topology.bootstrap_token.clone(),
            request,
        )
        .map_err(|error| BackendError::Process(format!("encode control request: {error}")))
    }

    async fn open_exchange(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = self.prepare_request(request)?;
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
        let mut stream = self.connect_boundary().await?;
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
        stream.read_exact(&mut header).await.map_err(|error| {
            BackendError::Unavailable(format!("read boundary control response header: {error}"))
        })?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > MAX_CONTROL_FRAME_BYTES {
            return Err(BackendError::Process(format!(
                "boundary control response is too large: {declared} bytes"
            )));
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&header);
        frame.resize(4 + declared, 0);
        stream.read_exact(&mut frame[4..]).await.map_err(|error| {
            BackendError::Unavailable(format!("read boundary control response: {error}"))
        })?;
        let response: ResponseEnvelope = decode_frame(&frame)
            .map_err(|error| BackendError::Process(format!("decode control response: {error}")))?;
        if response.request_id != request_id {
            return Err(BackendError::Process(format!(
                "boundary response ID {} did not match request ID {request_id}",
                response.request_id
            )));
        }
        let response = match response.response {
            Response::Error { kind, message } => Err(guest_error(&kind, message)),
            response => Ok(response),
        }?;
        Ok((stream, response))
    }

    async fn connect_boundary(&self) -> Result<BoundaryDuplexStream, BackendError> {
        let deadline = tokio::time::Instant::now() + CONNECT_RETRY_TIMEOUT;
        loop {
            match self.connect_boundary_once().await {
                Ok(stream) => return Ok(stream),
                Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }

    async fn connect_boundary_once(&self) -> Result<BoundaryDuplexStream, BackendError> {
        let (stream, tls): (BoundaryDuplexStream, &BoundaryClientTls) =
            match &self.topology.transport {
                BoundaryTransport::Unix { socket_path, tls } => {
                    let stream = UnixStream::connect(socket_path).await.map_err(|error| {
                        BackendError::Unavailable(format!(
                            "connect to mapped boundary control socket {}: {error}",
                            socket_path.display()
                        ))
                    })?;
                    (Box::new(stream), tls)
                }
                BoundaryTransport::TlsTcp { address, tls } => {
                    let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[*address])
                        .await
                        .map_err(|error| {
                            BackendError::Unavailable(format!(
                                "connect to boundary TLS endpoint {address}: {error}"
                            ))
                        })?;
                    enable_boundary_tcp_keepalive(&stream);
                    (Box::new(stream), tls)
                }
                BoundaryTransport::Vsock {
                    guest_cid,
                    control_port,
                    tls,
                } => (connect_host_vsock(*guest_cid, *control_port)?, tls),
            };
        let server_name = rustls::pki_types::ServerName::try_from(tls.server_name.clone())
            .map_err(|error| {
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
}

fn enable_boundary_tcp_keepalive(stream: &tokio::net::TcpStream) {
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
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(BackendError::Unavailable(format!(
            "create host vsock: {}",
            std::io::Error::last_os_error()
        )));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|error| {
        BackendError::Unavailable(format!("convert host vsock address family: {error}"))
    })?;
    let address = libc::sockaddr_vm {
        svm_family: family,
        svm_reserved1: 0,
        svm_port: control_port,
        svm_cid: guest_cid,
        svm_zero: [0; 4],
    };
    let address_length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).map_err(|error| {
            BackendError::Unavailable(format!("convert host vsock address length: {error}"))
        })?;
    let result = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if result != 0 {
        return Err(BackendError::Unavailable(format!(
            "connect host vsock CID {guest_cid} port {control_port}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
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

fn guest_error(kind: &str, message: String) -> BackendError {
    let message = format!("boundary process leaf: {message}");
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

    use super::*;
    use crate::boundary_protocol::generate_boundary_mutual_tls_material;
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };

    fn test_driver_fence() -> crate::contract::DriverFenceEvidence {
        crate::contract::DriverFenceEvidence::Vm {
            generation: "test-generation".to_string(),
            network_device_count: 0,
        }
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

    #[tokio::test]
    async fn remote_dns_exchange_returns_supervisor_response() {
        let socket_path = std::env::temp_dir().join(format!(
            "openshell-dns-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let certificate = test_certificate();
        let server_config = certificate.server_config.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let declared = stream.read_u32().await.unwrap() as usize;
            let mut frame = vec![0_u8; 4 + declared];
            frame[..4].copy_from_slice(&u32::try_from(declared).unwrap().to_be_bytes());
            stream.read_exact(&mut frame[4..]).await.unwrap();
            let request: RequestEnvelope = decode_frame(&frame).unwrap();
            assert_eq!(request.request, Request::AcceptDns);
            let response = encode_frame(&ResponseEnvelope {
                request_id: request.request_id,
                response: Response::DnsQuery {
                    request: vec![1, 2, 3],
                    transport: crate::contract::DnsTransport::Udp,
                    identity: crate::boundary_protocol::BinaryIdentityWire {
                        binary_path: Some(PathBuf::from("/usr/bin/dig")),
                        binary_digest: Some("a".repeat(64)),
                        ancestors: Vec::new(),
                        cmdline_paths: Vec::new(),
                        resolve_error: None,
                    },
                },
            })
            .unwrap();
            stream.write_all(&response).await.unwrap();
            let (channel, payload) = read_stream_frame(&mut stream).await.unwrap().unwrap();
            assert_eq!(channel, STREAM_DNS_RESPONSE);
            assert_eq!(
                serde_json::from_slice::<DnsQueryResultWire>(&payload).unwrap(),
                DnsQueryResultWire::Response(vec![4, 5, 6])
            );
            write_stream_frame(&mut stream, STREAM_DNS_ACK, &[])
                .await
                .unwrap();
        });
        let client = Arc::new(BoundaryClient::new(BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::Unix {
                socket_path: socket_path.clone(),
                tls: certificate.client_tls,
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "a".repeat(32),
        }));
        let source = RemoteDnsMediation { client };
        let query = source.accept().await.unwrap();
        assert_eq!(query.request, [1, 2, 3]);
        assert_eq!(query.transport, crate::contract::DnsTransport::Udp);
        assert_eq!(
            query.binary_identity.unwrap().binary_path,
            PathBuf::from("/usr/bin/dig")
        );
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_file(socket_path);
    }

    struct TestCertificate {
        client_tls: BoundaryClientTls,
        server_config: Arc<rustls::ServerConfig>,
    }

    fn test_certificate() -> TestCertificate {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let material = generate_boundary_mutual_tls_material().expect("generate test material");
        let certificates = rustls_pemfile::certs(&mut material.sandbox_certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server certificate");
        let private_key =
            rustls_pemfile::private_key(&mut material.sandbox_private_key_pem.as_bytes())
                .expect("parse server private key")
                .expect("server private key");
        let client_ca = rustls_pemfile::certs(&mut material.ca_certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client CA");
        let mut client_roots = rustls::RootCertStore::empty();
        for certificate in client_ca {
            client_roots.add(certificate).expect("add client CA");
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .expect("build client verifier");
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .expect("build test TLS server config");
        TestCertificate {
            client_tls: BoundaryClientTls {
                server_name: material.server_name,
                ca_certificate_pem: material.ca_certificate_pem,
                certificate_chain_pem: material.supervisor_certificate_pem,
                private_key_pem: material.supervisor_private_key_pem,
            },
            server_config: Arc::new(server_config),
        }
    }

    fn tls_topology(
        address: std::net::SocketAddr,
        tls: BoundaryClientTls,
        token: &str,
    ) -> BoundaryTopology {
        BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::TlsTcp { address, tls },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: token.to_string(),
        }
    }

    async fn spawn_tls_boundary(
        certificate: Arc<rustls::ServerConfig>,
        expected_token: String,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test TLS boundary");
        let address = listener.local_addr().expect("read test listener address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS control client");
            let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(certificate)
                .accept(stream)
                .await
            else {
                return;
            };
            let declared_u32 = stream.read_u32().await.expect("read request length");
            let declared = declared_u32 as usize;
            let mut frame = vec![0_u8; 4 + declared];
            frame[..4].copy_from_slice(&declared_u32.to_be_bytes());
            stream
                .read_exact(&mut frame[4..])
                .await
                .expect("read request frame");
            let request: RequestEnvelope = decode_frame(&frame).expect("decode request");
            let response = if request.boundary_id == "sandbox-1"
                && request.bootstrap_token == expected_token
            {
                Response::Confirmed {
                    evidence: Box::new(test_confirmation_evidence()),
                }
            } else {
                Response::Error {
                    kind: "denied".to_string(),
                    message: "control authentication failed".to_string(),
                }
            };
            let frame = encode_frame(&ResponseEnvelope {
                request_id: request.request_id,
                response,
            })
            .expect("encode response");
            stream.write_all(&frame).await.expect("write response");
        });
        (address, task)
    }

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
            identity: crate::contract::ResolvedWorkloadIdentity::new(
                10_001,
                10_001,
                Vec::new(),
                "test".to_string(),
                "sha256:test".to_string(),
            )
            .expect("identity"),
        }
    }

    fn test_confirmation_evidence() -> crate::contract::SandboxConfirmEvidence {
        crate::contract::SandboxConfirmEvidence {
            generation: "test-generation".to_string(),
            identity: sandbox().identity,
            capabilities: crate::contract::CapabilityEvidence {
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
            seccomp: crate::contract::SeccompEvidence {
                new_listener: true,
                notification_round_trip: true,
                id_validation: true,
                addfd_send: true,
                retained_socket_operation: true,
                proc_fd_identity: true,
                task_memory_read: true,
                task_memory_write: true,
                cancellation: true,
            },
            landlock_abi: 1,
            landlock_allow_deny: true,
            udp_dns_round_trip: true,
            tcp_dns_round_trip: true,
            tcp_allow_round_trip: true,
            tcp_deny_round_trip: true,
            authenticated_supervisor: true,
            session_epoch: "test-session".to_string(),
            driver_fence: test_driver_fence(),
            resource_claims: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn topology_debug_redacts_token() {
        let topology = BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
                tls: test_certificate().client_tls,
            },
            host_gateway_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "never-log-this-never-log-this".to_string(),
        };
        let debug = format!("{topology:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
    }

    #[test]
    fn topology_must_match_sandbox() {
        let topology = BoundaryTopology {
            boundary_id: "other".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
                tls: test_certificate().client_tls,
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        assert!(matches!(
            validate_topology(&topology, &sandbox(), "vm"),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn topology_rejects_an_unspecified_tcp_target() {
        let topology = BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::TlsTcp {
                address: "0.0.0.0:5500".parse().expect("valid address"),
                tls: test_certificate().client_tls,
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        assert!(matches!(
            validate_topology(&topology, &sandbox(), "vm"),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn topology_accepts_a_concrete_tcp_target() {
        let topology = BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: sandbox().identity,
            transport: BoundaryTransport::TlsTcp {
                address: "10.42.0.7:5500".parse().expect("valid address"),
                tls: test_certificate().client_tls,
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        validate_topology(&topology, &sandbox(), "vm").expect("TCP topology should be valid");
    }

    #[test]
    fn topology_rejects_invalid_tls_configuration() {
        let topology = tls_topology(
            "127.0.0.1:5500".parse().expect("valid address"),
            BoundaryClientTls {
                server_name: "not a dns name!".to_string(),
                ca_certificate_pem: "not a certificate".to_string(),
                certificate_chain_pem: "not a certificate".to_string(),
                private_key_pem: "not a key".to_string(),
            },
            "0123456789abcdef0123456789abcdef",
        );
        assert!(matches!(
            validate_topology(&topology, &sandbox(), "vm"),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[tokio::test]
    async fn tls_tcp_round_trip_verifies_server_certificate() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(tls_topology(
            address,
            certificate.client_tls,
            &"a".repeat(32),
        ));

        assert_eq!(
            client
                .exchange(Request::Confirm)
                .await
                .expect("TLS request"),
            Response::Confirmed {
                evidence: Box::new(test_confirmation_evidence()),
            }
        );
        server.await.expect("TLS test server");
    }

    #[tokio::test]
    async fn tls_tcp_flushes_large_control_requests_before_reading_response() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(tls_topology(
            address,
            certificate.client_tls,
            &"a".repeat(32),
        ));
        let context = sandbox();

        assert!(matches!(
            client
                .exchange(Request::StartAgent {
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    policy: Box::new(SandboxPolicyWire::from(context.policy)),
                    ca_cert: Some(vec![b'c'; 16 * 1024]),
                    ca_bundle: Some(vec![b'b'; 256 * 1024]),
                    provider_env_revision: 0,
                    provider_env: std::collections::HashMap::new(),
                })
                .await
                .expect("large TLS request"),
            Response::Confirmed { .. }
        ));
        server.await.expect("TLS test server");
    }

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
            let (stream, _) = listener.accept().await.expect("accept TLS control client");
            let mut stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .expect("accept TLS session");
            let declared_u32 = stream.read_u32().await.expect("read request length");
            let declared = declared_u32 as usize;
            let mut frame = vec![0_u8; 4 + declared];
            frame[..4].copy_from_slice(&declared_u32.to_be_bytes());
            stream
                .read_exact(&mut frame[4..])
                .await
                .expect("read request frame");
            let request: RequestEnvelope = decode_frame(&frame).expect("decode request");
            let frame = encode_frame(&ResponseEnvelope {
                request_id: request.request_id,
                response: Response::Confirmed {
                    evidence: Box::new(test_confirmation_evidence()),
                },
            })
            .expect("encode response");
            stream.write_all(&frame).await.expect("write response");
        });
        let context = sandbox();
        let client = BoundaryClient::new(BoundaryTopology {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_epoch: "test-session".to_string(),
            workload_identity: context.identity.clone(),
            transport: BoundaryTransport::Unix {
                socket_path: socket_path.clone(),
                tls: certificate.client_tls,
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
            bootstrap_token: "a".repeat(32),
        });

        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                client.exchange(Request::StartAgent {
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    policy: Box::new(SandboxPolicyWire::from(context.policy)),
                    ca_cert: Some(vec![b'c'; 16 * 1024]),
                    ca_bundle: Some(vec![b'b'; 256 * 1024]),
                    provider_env_revision: 0,
                    provider_env: std::collections::HashMap::new(),
                })
            )
            .await
            .expect("large Unix TLS request timed out")
            .expect("large Unix TLS request"),
            Response::Confirmed { .. }
        ));
        server.await.expect("TLS test server");
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
        let client = BoundaryClient::new(tls_topology(
            address,
            certificate.client_tls,
            "incorrect-token-incorrect-token",
        ));

        assert!(matches!(
            client.exchange(Request::Confirm).await,
            Err(BackendError::Denied(_))
        ));
        server.await.expect("TLS test server");
    }

    #[tokio::test]
    async fn tls_tcp_rejects_an_untrusted_server_certificate() {
        let presented = test_certificate();
        let trusted = test_certificate();
        let (address, server) = spawn_tls_boundary(presented.server_config, "a".repeat(32)).await;
        let client =
            BoundaryClient::new(tls_topology(address, trusted.client_tls, &"a".repeat(32)));

        assert!(matches!(
            client.connect_boundary_once().await,
            Err(BackendError::Unavailable(_))
        ));
        // The server observes the client's fatal alert and may fail its accept;
        // completing the task is sufficient for this rejection test.
        let _ = server.await;
    }
}
