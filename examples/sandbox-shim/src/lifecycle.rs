// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-guest Isolation Backend and Sandbox Protocol server.
use crate::{
    egress::{self, Egress},
    launch::{self, Launch, Privilege, Substrate},
    native::NativeNetwork,
    process::{self, Process, SpawnSpec},
    protocol::{self, BACKEND, boundary::*, control::*},
    transport::{Connection, Io},
};
use anyhow::{Context, Result, ensure};
use openshell_core::jwt::{SandboxId, SessionJwtVerifier, SessionTokenProfile, SystemJwtClock};
use openshell_isolation_interface::contract::{
    BoundaryConfirmation, ProvisioningEvidence, TcpOpenDecision as OpenDecision,
    TcpOpenDenial as OpenDenial,
};
use openshell_sandbox_backend::{boundary_protocol as wire, sandbox_auth::*};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, watch},
};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

type Chunks =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ExchangeFrame, Status>> + Send>>;
type MediateChunks =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<MediateFrame, Status>> + Send>>;

const RELAY_CHUNK: usize = 16 * 1024;

struct State {
    policy: Option<wire::SandboxPolicyWire>,
    ledger: HashMap<String, (String, wire::Response)>,
    publications: (u64, u64),
    provider_env: HashMap<String, String>,
    tls_env: Vec<(String, String)>,
    main: Option<String>,
    terminal: bool,
}

/// How workload egress reaches the supervisor.
pub enum Network {
    /// gVisor: a loopback HTTP CONNECT proxy and proxy environment variables.
    Proxy(Arc<Egress>),
    /// Firecracker: every socket syscall is mediated; no proxy settings.
    Native(Arc<NativeNetwork>),
}

impl Network {
    fn native(&self) -> Option<&Arc<NativeNetwork>> {
        match self {
            Self::Native(native) => Some(native),
            Self::Proxy(_) => None,
        }
    }

    /// Fail closed when native mediation has stopped.
    fn require_healthy(&self) -> Result<(), Status> {
        match self {
            Self::Native(native) => native
                .healthy()
                .map_err(|error| Status::unavailable(format!("network mediation: {error:#}"))),
            Self::Proxy(_) => Ok(()),
        }
    }
}

pub struct Runtime {
    launch: Launch,
    authenticator: SandboxProtocolAuthenticator,
    pub registry: Arc<SandboxConnectionRegistry>,
    opened: Mutex<HashSet<SandboxConnectionId>>,
    state: Mutex<State>,
    mutation: Mutex<()>,
    processes: std::sync::Mutex<HashMap<String, Arc<Process>>>,
    pub network: Network,
    pub ended: watch::Sender<bool>,
    pub lost: watch::Sender<bool>,
    delegation: Option<process::Delegation>,
    namespaces: tokio::sync::OnceCell<process::Namespaces>,
}

fn status_from(error: impl std::fmt::Display) -> Status {
    Status::failed_precondition(error.to_string())
}

impl Runtime {
    pub fn new(launch: Launch, network: Network) -> Result<Arc<Self>> {
        let (substrate, privilege, image) = (launch.substrate, launch.privilege, &launch.image);
        image.validate()?;
        ensure!(
            image.shim_sha256 == launch::file_sha256(std::path::Path::new("/proc/self/exe"))?,
            "running shim differs from the shim digest in the launch descriptor"
        );
        ensure!(
            launch.descriptor == launch::descriptor(substrate, privilege, image),
            "descriptor differs from the launch substrate, privilege, and image"
        );
        ensure!(
            launch.boundary.workload_identity == launch::identity(substrate, privilege, image)?,
            "admitted identity differs from the privilege setting"
        );
        let fence = ProvisioningEvidence::from_enforcement_evidence(
            launch.boundary.generation.clone(),
            &launch::evidence(substrate, privilege, image),
        )?;
        ensure!(
            fence == launch.boundary.provisioning_evidence,
            "shim evidence differs from the driver fence"
        );
        let delegation = match privilege {
            Privilege::Privileged => match process::Delegation::create() {
                Ok(delegation) => Some(delegation),
                Err(error) => {
                    println!("sandbox-shim: no delegated cgroup for nested runtimes: {error:#}");
                    None
                }
            },
            Privilege::Nonprivileged => None,
        };
        let verifier = SessionJwtVerifier::new(
            &launch.gateway_id,
            SessionTokenProfile::Sandbox,
            launch.keys.clone(),
            Arc::new(SystemJwtClock),
        )?;
        let authenticator = SandboxProtocolAuthenticator::new(
            verifier,
            SandboxId::parse(launch.boundary.sandbox_id.clone())?,
            openshell_core::sandbox_generation::SandboxGenerationId::parse(
                launch.boundary.generation.clone(),
            )?,
            launch.epoch,
        );
        let registry = Arc::new(SandboxConnectionRegistry::new(
            launch.boundary.session_id,
            launch.rotation,
            launch.epoch,
        ));
        Ok(Arc::new(Self {
            launch,
            authenticator,
            registry,
            opened: Mutex::new(HashSet::new()),
            mutation: Mutex::new(()),
            state: Mutex::new(State {
                policy: None,
                ledger: HashMap::new(),
                publications: (0, 0),
                provider_env: HashMap::new(),
                tls_env: Vec::new(),
                main: None,
                terminal: false,
            }),
            processes: std::sync::Mutex::new(HashMap::new()),
            network,
            ended: watch::channel(false).0,
            delegation,
            namespaces: tokio::sync::OnceCell::new(),
            lost: watch::channel(false).0,
        }))
    }

    fn privilege(&self) -> Privilege {
        self.launch.privilege
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<SandboxProtocolPrincipal, Status> {
        let id = *request
            .extensions()
            .get::<SandboxConnectionId>()
            .ok_or_else(|| Status::unauthenticated("TLS connection identity missing"))?;
        self.authenticator
            .authenticate(id, request.metadata())
            .map_err(|_| Status::unauthenticated("invalid sandbox launch credential"))
    }

    async fn route<F: prost::Message + Default>(
        &self,
        mut request: Request<Streaming<F>>,
        binding: fn(F) -> Option<String>,
    ) -> Result<(SandboxProtocolPrincipal, Streaming<F>), Status> {
        let principal = self.authenticate(&request)?;
        if !self
            .opened
            .lock()
            .await
            .contains(&principal.connection_id())
        {
            return Err(Status::failed_precondition(
                "OpenBoundary required on this connection",
            ));
        }
        let first = request.get_mut().message().await?;
        if first.and_then(binding) != Some(self.launch.boundary.generation.clone()) {
            return Err(Status::permission_denied("wrong boundary handle"));
        }
        Ok((principal, request.into_inner()))
    }

    fn process(&self, id: &str) -> Result<Arc<Process>, Status> {
        self.processes
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Status::not_found("unknown guest process"))
    }

    /// Kill every workload process and end the boundary. Used for
    /// TerminateBoundary and when the confirmed supervisor disappears.
    pub async fn end(&self, reason: &str) {
        if self
            .delegation
            .as_ref()
            .is_some_and(process::Delegation::kill_all)
        {
            println!("sandbox-shim: killed the delegated workload cgroup");
        }
        let killed = process::kill_workload(self.privilege());
        println!("sandbox-shim: boundary ending ({reason}); signalled {killed} workload processes");
        let processes: Vec<_> = self.processes.lock().unwrap().values().cloned().collect();
        for process in processes {
            let _ = tokio::time::timeout(Duration::from_secs(5), process.wait()).await;
        }
        self.state.lock().await.terminal = true;
        self.registry.mark_terminal();
        self.ended.send_replace(true);
    }

    /// The backend applies no filesystem confinement (no Landlock) and has no
    /// unmediated network path. Policies that require either are rejected;
    /// best-effort filesystem paths are accepted and reported unenforced.
    fn validate_policy(&self, policy: &wire::SandboxPolicyWire) -> Result<(), Status> {
        if matches!(policy.network, wire::NetworkModeWire::Allow) {
            return Err(Status::unimplemented(
                "sandbox-shim has no unmediated network; use proxy (network_policies) or block",
            ));
        }
        if matches!(
            policy.landlock,
            wire::LandlockCompatibilityWire::HardRequirement
        ) {
            return Err(Status::unimplemented(
                "sandbox-shim does not apply Landlock; landlock hard_requirement is unsupported",
            ));
        }
        if !policy.read_only.is_empty() || !policy.read_write.is_empty() {
            // best_effort: production proceeds without Landlock when it is
            // unavailable. Here it is never applied; say so loudly.
            println!(
                "sandbox-shim: WARNING filesystem_policy is NOT enforced ({} read-only, {} read-write paths; landlock best_effort)",
                policy.read_only.len(),
                policy.read_write.len()
            );
        }
        let identity = &self.launch.boundary.workload_identity;
        for (selector, expected) in [
            (&policy.run_as_user, identity.uid),
            (&policy.run_as_group, identity.gid),
        ] {
            if selector
                .as_ref()
                .is_some_and(|value| value != &expected.to_string())
            {
                return Err(Status::permission_denied(
                    "process identity differs from the admitted workload identity",
                ));
            }
        }
        Ok(())
    }

    fn base_env(&self, state: &State, pty: bool) -> Vec<(String, String)> {
        let user = match self.privilege() {
            Privilege::Privileged => "root",
            Privilege::Nonprivileged => "sandbox",
        };
        let mut env: Vec<(String, String)> = [
            (
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            ("HOME", launch::WORKDIR),
            ("USER", user),
            ("LOGNAME", user),
            ("SHELL", "/bin/bash"),
            ("LANG", "C.UTF-8"),
            ("TERM", if pty { "xterm-256color" } else { "dumb" }),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        if matches!(self.network, Network::Proxy(_))
            && matches!(
                state.policy.as_ref().map(|policy| policy.network),
                Some(wire::NetworkModeWire::Proxy)
            )
        {
            let proxy = format!("http://{}", launch::PROXY_ADDR);
            for key in [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
                "grpc_proxy",
            ] {
                env.push((key.into(), proxy.clone()));
            }
            for key in ["NO_PROXY", "no_proxy"] {
                env.push((key.into(), "localhost,127.0.0.1,::1".into()));
            }
            env.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
        }
        env.extend(state.tls_env.iter().cloned());
        env.extend(
            state
                .provider_env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        env
    }

    fn install_ca(
        state: &mut State,
        ca_cert: Option<&String>,
        ca_bundle: Option<&String>,
    ) -> Result<()> {
        let (Some(ca_cert), Some(ca_bundle)) = (ca_cert, ca_bundle) else {
            return Ok(());
        };
        use std::os::unix::fs::PermissionsExt;
        // Written only in the shim's own root; the workload sees this
        // directory through a read-only bind mount in its namespace.
        let source = Path::new(launch::SHIM_TLS_DIR);
        std::fs::write(source.join("openshell-ca.pem"), ca_cert)?;
        std::fs::write(source.join("ca-bundle.pem"), ca_bundle)?;
        for path in [
            source.join("openshell-ca.pem"),
            source.join("ca-bundle.pem"),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        }
        let visible = Path::new(launch::WORKLOAD_TLS_DIR);
        let cert = visible.join("openshell-ca.pem").display().to_string();
        let bundle = visible.join("ca-bundle.pem").display().to_string();
        state.tls_env = vec![
            ("NODE_EXTRA_CA_CERTS".into(), cert.clone()),
            ("DENO_CERT".into(), cert),
            ("SSL_CERT_FILE".into(), bundle.clone()),
            ("REQUESTS_CA_BUNDLE".into(), bundle.clone()),
            ("CURL_CA_BUNDLE".into(), bundle.clone()),
            ("GIT_SSL_CAINFO".into(), bundle),
        ];
        Ok(())
    }

    async fn spawn(&self, id: String, spec: SpawnSpec) -> Result<Arc<Process>, Status> {
        self.network.require_healthy()?;
        let launcher = self.network.native().map(|native| &native.launcher);
        let placement = match self.privilege() {
            Privilege::Nonprivileged => process::Placement::Nonprivileged,
            Privilege::Privileged => process::Placement::Privileged(
                self.namespaces
                    .get_or_try_init(|| {
                        process::Namespaces::create(self.delegation.as_ref(), launcher)
                    })
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(format!("workload namespaces: {error:#}"))
                    })?,
            ),
        };
        let process = process::spawn(id.clone(), spec, placement, launcher)
            .await
            .map_err(|error| Status::failed_precondition(format!("spawn failed: {error:#}")))?;
        self.processes.lock().unwrap().insert(id, process.clone());
        Ok(process)
    }

    async fn control(
        self: &Arc<Self>,
        principal: &SandboxProtocolPrincipal,
        envelope: &wire::RequestEnvelope,
    ) -> Result<wire::Response, Status> {
        use wire::{Request as Q, Response as R};
        envelope
            .validate_payload_digest()
            .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
        // Serialize mutations through validation, effects, and ledger commit.
        let _mutation = if envelope.request.is_replayable_mutation() {
            Some(self.mutation.lock().await)
        } else {
            None
        };
        let cached = {
            let state = self.state.lock().await;
            if let Some((digest, response)) = state.ledger.get(&envelope.request_id) {
                if digest != &envelope.payload_digest {
                    return Err(Status::invalid_argument(
                        "request ID reused with different payload",
                    ));
                }
                Some(response.clone())
            } else {
                if state.terminal
                    && !matches!(envelope.request, Q::Wait { .. } | Q::AttachProcess { .. })
                {
                    return Err(Status::failed_precondition("boundary is terminal"));
                }
                if envelope.request.is_replayable_mutation() && state.ledger.len() >= 4096 {
                    return Err(Status::resource_exhausted("replay ledger full"));
                }
                None
            }
        };
        match &envelope.request {
            Q::DiscoverPolicy => {
                return Ok(R::ImagePolicy {
                    yaml: None,
                    invalid: false,
                });
            }
            Q::Attach {
                supervisor_instance_id,
                ..
            } => {
                // No supervisor takeover: a replacement supervisor is refused.
                self.registry
                    .attach(principal, *supervisor_instance_id, None)
                    .map_err(status_from)?;
            }
            Q::Confirm => self
                .registry
                .require_attached(principal)
                .map_err(status_from)?,
            _ => self
                .registry
                .require_active(principal)
                .map_err(status_from)?,
        }
        if let Some(response) = cached {
            if matches!(envelope.request, Q::Confirm) {
                self.registry.confirm(principal).map_err(status_from)?;
            }
            return Ok(response);
        }
        // Requests that wait or act on a live process run without the state lock.
        match &envelope.request {
            Q::Wait { process_id } => {
                let process = self.process(process_id)?;
                return Ok(R::Exited {
                    status: process.wait().await,
                });
            }
            Q::AttachProcess { process_id } => {
                let process = self.process(process_id)?;
                return Ok(R::ProcessAttached {
                    terminal: process.pty,
                });
            }
            Q::OpenMediation => return Ok(R::MediationReady),
            _ => {}
        }
        let mut state = self.state.lock().await;
        let response = match &envelope.request {
            Q::Attach { policy, .. } => {
                self.validate_policy(policy)?;
                if state
                    .policy
                    .as_ref()
                    .is_some_and(|old| old != policy.as_ref())
                {
                    return Err(Status::failed_precondition(
                        "policy changed during attachment",
                    ));
                }
                state.policy = Some(*policy.clone());
                if let Network::Proxy(egress) = &self.network {
                    egress.mode.send_replace(Some(policy.network));
                }
                R::Attached {
                    snapshot: wire::SessionSnapshotWire {
                        generation: self.launch.boundary.generation.clone(),
                        processes: vec![],
                        bound_policy: state.policy.clone().map(Box::new),
                    },
                }
            }
            Q::Confirm => {
                if state.policy.is_none() {
                    return Err(Status::failed_precondition("attach required"));
                }
                self.network.require_healthy()?;
                self.registry.confirm(principal).map_err(status_from)?;
                R::Confirmed {
                    confirmation: Box::new(BoundaryConfirmation {
                        generation: self.launch.boundary.generation.clone(),
                        session_id: self.launch.boundary.session_id,
                        identity: self.launch.boundary.workload_identity.clone(),
                        resource_claims: self.launch.boundary.resource_claims.clone(),
                        provisioning_evidence_digest: self
                            .launch
                            .boundary
                            .provisioning_evidence
                            .evidence_digest,
                        backend_audit: launch::audit(
                            self.launch.substrate,
                            self.launch.privilege,
                            &self.launch.image,
                        ),
                    }),
                }
            }
            Q::StartAgent {
                sandbox_id,
                spec,
                ca_cert,
                ca_bundle,
                provider_env_revision,
                provider_env,
                provider_files,
            } => {
                if sandbox_id != &self.launch.boundary.sandbox_id || state.policy.is_none() {
                    return Err(Status::permission_denied("admitted launch changed"));
                }
                if !provider_files.is_empty() {
                    return Err(Status::unimplemented(
                        "provider files are not supported by sandbox-shim",
                    ));
                }
                if state.main.is_some() {
                    return Err(Status::failed_precondition("main process already started"));
                }
                Self::install_ca(&mut state, ca_cert.as_ref(), ca_bundle.as_ref())
                    .map_err(|error| Status::internal(format!("install CA: {error:#}")))?;
                state.provider_env = provider_env.clone();
                state.publications = (*provider_env_revision, 1);
                let pty = spec.interactive.then_some((80, 24));
                let id = format!("{}:main", self.launch.boundary.generation);
                let (program, args) = if spec.program.is_empty() {
                    ("/bin/bash".to_string(), vec!["-l".to_string()])
                } else {
                    (spec.program.clone(), spec.args.clone())
                };
                let process = self
                    .spawn(
                        id.clone(),
                        SpawnSpec {
                            program,
                            args,
                            env: self.base_env(&state, pty.is_some()),
                            workdir: spec.workdir.clone().unwrap_or(launch::WORKDIR.into()),
                            pty,
                        },
                    )
                    .await?;
                println!("sandbox-shim: main process started pid={}", process.pid);
                if spec.timeout_secs > 0 {
                    let timeout = Duration::from_secs(spec.timeout_secs);
                    let process = process.clone();
                    tokio::spawn(async move {
                        if tokio::time::timeout(timeout, process.wait()).await.is_err() {
                            process.signal(libc::SIGKILL);
                        }
                    });
                }
                state.main = Some(id.clone());
                R::Started {
                    process_id: id,
                    provider_env_revision: *provider_env_revision,
                    provider_env_generation: 1,
                }
            }
            Q::Exec { spec } => {
                if spec.runtime_helper.is_some() {
                    return Err(Status::unimplemented("runtime helpers are not supported"));
                }
                let (program, args) = match &spec.shell {
                    Some(shell) => {
                        let mut args = Vec::new();
                        if shell.login {
                            args.push("-l".to_string());
                        }
                        if let Some(command) = &shell.command {
                            args.extend(["-c".to_string(), command.clone()]);
                        }
                        ("/bin/bash".to_string(), args)
                    }
                    None => (spec.program.clone(), spec.args.clone()),
                };
                let pty = spec.pty.then_some((80, 24));
                let mut env = self.base_env(&state, spec.pty);
                env.extend(spec.env.iter().cloned());
                let id = format!("exec-{}", uuid::Uuid::new_v4());
                self.spawn(
                    id.clone(),
                    SpawnSpec {
                        program,
                        args,
                        env,
                        workdir: spec.workdir.clone().unwrap_or(launch::WORKDIR.into()),
                        pty,
                    },
                )
                .await?;
                R::ExecStarted {
                    process_id: id,
                    pty: spec.pty,
                }
            }
            Q::UpdateProviderEnvironment {
                revision,
                generation,
                provider_env,
                provider_files,
            } => {
                if !provider_files.is_empty() {
                    return Err(Status::unimplemented(
                        "provider files are not supported by sandbox-shim",
                    ));
                }
                if *generation <= state.publications.1 || *revision < state.publications.0 {
                    return Err(Status::failed_precondition("stale publication"));
                }
                // Applies to processes started from now on.
                state.provider_env = provider_env.clone();
                state.publications = (*revision, *generation);
                R::ProviderEnvironmentUpdated {
                    revision: *revision,
                    generation: *generation,
                    applied: true,
                }
            }
            Q::Signal { process_id, signal } => {
                let process = self.process(process_id)?;
                process.signal(match signal {
                    wire::SignalWire::Term => libc::SIGTERM,
                    wire::SignalWire::Kill => libc::SIGKILL,
                    wire::SignalWire::Int => libc::SIGINT,
                    wire::SignalWire::Hup => libc::SIGHUP,
                });
                R::Signaled
            }
            Q::Terminate { process_id } => {
                self.process(process_id)?.terminate();
                R::Terminated
            }
            Q::Resize {
                process_id,
                cols,
                rows,
            } => {
                self.process(process_id)?
                    .resize(*cols, *rows)
                    .map_err(status_from)?;
                R::Resized
            }
            Q::TerminateBoundary => {
                drop(state);
                self.end("TerminateBoundary").await;
                state = self.state.lock().await;
                R::BoundaryTerminated
            }
            _ => {
                return Err(Status::unimplemented(
                    "operation is not supported by sandbox-shim",
                ));
            }
        };
        if envelope.request.is_replayable_mutation() {
            state.ledger.insert(
                envelope.request_id.clone(),
                (envelope.payload_digest.clone(), response.clone()),
            );
        }
        Ok(response)
    }

    /// Stream retained and live output, then the exit status.
    fn process_output(process: Arc<Process>) -> Chunks {
        Box::pin(async_stream::try_stream! {
            use exchange_frame::Payload;
            let mut next = 0;
            let mut changed = process.output.subscribe();
            loop {
                changed.borrow_and_update();
                let (chunks, after, closed) = process.output.read_from(next);
                for chunk in chunks {
                    for piece in chunk.bytes.chunks(wire::MAX_STREAM_FRAME_BYTES) {
                        let payload = if chunk.channel == wire::STREAM_STDERR {
                            Payload::Stderr(piece.to_vec())
                        } else {
                            Payload::Stdout(piece.to_vec())
                        };
                        yield ExchangeFrame { payload: Some(payload) };
                    }
                }
                next = after;
                if closed || changed.changed().await.is_err() {
                    break;
                }
            }
            yield protocol::exit_frame(process.wait().await)?;
        })
    }

    fn pump_stdin(process: Arc<Process>, mut input: Streaming<ExchangeFrame>) {
        tokio::spawn(async move {
            while let Ok(Some(frame)) = input.message().await {
                match frame.payload {
                    Some(exchange_frame::Payload::Stdin(bytes)) => {
                        process.write_stdin(&bytes).await
                    }
                    Some(exchange_frame::Payload::StdinClosed(_)) => process.close_stdin().await,
                    _ => break,
                }
            }
        });
    }

    async fn next_open(&self, egress: &Egress) -> Option<egress::PendingOpen> {
        let mut ended = self.ended.subscribe();
        let mut opens = tokio::select! {
            opens = egress.opens.lock() => opens,
            _ = until_true(&mut ended) => return None,
        };
        tokio::select! {
            open = opens.recv() => open,
            _ = until_true(&mut ended) => None,
        }
    }
}

/// Bytes between a guest TCP stream and an Exchange relay.
fn relay(
    stream: tokio::net::TcpStream,
    early: Vec<u8>,
    mut input: Streaming<ExchangeFrame>,
) -> Chunks {
    Box::pin(async_stream::try_stream! {
        use exchange_frame::Payload;
        let (mut reader, mut writer) = stream.into_split();
        let downstream = tokio::spawn(async move {
            while let Ok(Some(frame)) = input.message().await {
                let Some(Payload::RelayData(bytes)) = frame.payload else { break };
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        if !early.is_empty() {
            yield ExchangeFrame { payload: Some(Payload::RelayData(early)) };
        }
        let mut buffer = vec![0; RELAY_CHUNK];
        loop {
            let read = reader.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            yield ExchangeFrame { payload: Some(Payload::RelayData(buffer[..read].to_vec())) };
        }
        // Keep the RPC open until the supervisor finishes its direction too.
        let _ = downstream.await;
    })
}

/// A DNS query bound for the supervisor, and where its answer goes.
struct OutgoingDns {
    request: Vec<u8>,
    transport: DnsTransport,
    identity: BinaryIdentity,
    timing: Option<MediationTiming>,
    reply: DnsReply,
}

enum DnsReply {
    Proxy(tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>),
    Native(openshell_sandbox::network_broker::PendingDnsQuery),
}

impl DnsReply {
    fn send(self, result: Result<Vec<u8>, String>) {
        match self {
            Self::Proxy(sender) => {
                let _ = sender.send(result);
            }
            Self::Native(query) => {
                let _ = query.complete(result.map_err(std::io::Error::other));
            }
        }
    }
}

impl OutgoingDns {
    fn proxy(query: egress::DnsRequest) -> Self {
        Self {
            request: query.message,
            transport: DnsTransport::Udp,
            identity: query.identity,
            timing: None,
            reply: DnsReply::Proxy(query.reply),
        }
    }

    /// TCP queries keep their length prefix, as the production runtime sends
    /// them; the supervisor answers in the same framing.
    fn native(query: openshell_sandbox::network_broker::PendingDnsQuery) -> Self {
        use openshell_isolation_interface::contract::DnsTransport as Transport;
        Self {
            request: query.request().to_vec(),
            transport: match query.transport() {
                Transport::Udp => DnsTransport::Udp,
                Transport::Tcp => DnsTransport::Tcp,
            },
            identity: protocol::binary_identity(query.identity()),
            timing: Some(MediationTiming {
                notification_to_queue: wire_duration(query.notification_to_queue()),
                queue_wait: wire_duration(query.queue_wait()),
            }),
            reply: DnsReply::Native(query),
        }
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// The wire carries whole microseconds; the supervisor rejects finer ones.
fn wire_duration(duration: Duration) -> Option<prost_types::Duration> {
    prost_types::Duration::try_from(Duration::from_micros(micros(duration))).ok()
}

fn decision_from(decision: Option<tcp_open_decision::Decision>) -> OpenDecision {
    match decision {
        Some(tcp_open_decision::Decision::RelayReady(_)) => OpenDecision::RelayReady,
        Some(tcp_open_decision::Decision::Denied(code)) => {
            OpenDecision::Denied(match TcpOpenDenial::try_from(code) {
                Ok(TcpOpenDenial::PolicyDenied) => OpenDenial::PolicyDenied,
                Ok(TcpOpenDenial::IdentityUnavailable) => OpenDenial::IdentityUnavailable,
                Ok(TcpOpenDenial::InvalidDestination) => OpenDenial::InvalidDestination,
                Ok(TcpOpenDenial::ResourceExhausted) => OpenDenial::ResourceExhausted,
                _ => OpenDenial::MediationUnavailable,
            })
        }
        None => OpenDecision::Denied(OpenDenial::MediationUnavailable),
    }
}

/// Resolve once the flag is set (or its sender is gone), without holding the
/// watch guard across an await.
async fn until_true(flag: &mut watch::Receiver<bool>) {
    let _ = flag.wait_for(|value| *value).await.map(|_| ());
}

fn error_response(error: &Status) -> wire::Response {
    wire::Response::Error {
        kind: match error.code() {
            tonic::Code::InvalidArgument => wire::BoundaryErrorKind::Invalid,
            tonic::Code::Unavailable => wire::BoundaryErrorKind::Unavailable,
            tonic::Code::Unimplemented => wire::BoundaryErrorKind::Unsupported,
            tonic::Code::NotFound => wire::BoundaryErrorKind::Process,
            _ => wire::BoundaryErrorKind::Denied,
        },
        message: error.message().to_string(),
    }
}

#[tonic::async_trait]
impl isolation_backend_server::IsolationBackend for Arc<Runtime> {
    async fn describe(
        &self,
        request: Request<DescribeIsolationBackendRequest>,
    ) -> Result<Response<DescribeIsolationBackendResponse>, Status> {
        let peer = request
            .into_inner()
            .supervisor
            .ok_or_else(|| Status::failed_precondition("peer metadata required"))?;
        let capability = protocol::CAPABILITY.to_string();
        if peer.protocol_version.map(|v| v.major) != Some(1)
            || !peer.supported_capabilities.contains(&capability)
            || peer.required_capabilities.iter().any(|c| c != &capability)
        {
            return Err(Status::failed_precondition(
                "incompatible Sandbox Protocol peer",
            ));
        }
        Ok(Response::new(DescribeIsolationBackendResponse {
            backend: Some(protocol::metadata(self.launch.substrate.as_str())),
        }))
    }

    async fn open_boundary(
        &self,
        request: Request<OpenBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        let principal = self.authenticate(&request)?;
        let q = request.into_inner();
        let b = &self.launch.boundary;
        if q.session_id != b.session_id.to_string()
            || q.backend_name != BACKEND
            || q.driver_descriptor != self.launch.descriptor
        {
            return Err(Status::permission_denied(
                "immutable launch binding changed",
            ));
        }
        self.opened.lock().await.insert(principal.connection_id());
        Ok(Response::new(OpenBoundaryResponse {
            boundary_id: b.generation.clone(),
            outcome: 1,
        }))
    }

    async fn suspend_boundary(
        &self,
        request: Request<SuspendBoundaryRequest>,
    ) -> Result<Response<SuspendBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented("suspend is unsupported"))
    }

    async fn resume_boundary(
        &self,
        request: Request<ResumeBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented("resume is unsupported"))
    }
}

#[tonic::async_trait]
impl sandbox_protocol_server::SandboxProtocol for Arc<Runtime> {
    type ExchangeStream = Chunks;
    type MediateStream = MediateChunks;

    async fn mediate(
        &self,
        request: Request<Streaming<MediateFrame>>,
    ) -> Result<Response<Self::MediateStream>, Status> {
        let (principal, mut input) = self
            .route(request, |f| match f.payload {
                Some(mediate_frame::Payload::BoundaryId(id)) => Some(id),
                _ => None,
            })
            .await?;
        let runtime = self.clone();
        let stream = async_stream::try_stream! {
            let envelope = protocol::read_mediation_request(&mut input).await?;
            let response = runtime.control(&principal, &envelope).await?;
            yield protocol::mediation_response(envelope.request_id, response)?;
            let pending = Arc::new(std::sync::Mutex::new(HashMap::<u64, DnsReply>::new()));
            let replies = pending.clone();
            let mut reader = tokio::spawn(async move {
                while let Ok(Some(frame)) = input.message().await {
                    let Some(mediate_frame::Payload::DnsResponse(reply)) = frame.payload else {
                        break;
                    };
                    let result = match reply.result {
                        Some(dns_response::Result::Response(bytes)) => Ok(bytes),
                        Some(dns_response::Result::Error(error)) => Err(error),
                        None => Err("empty DNS response".to_string()),
                    };
                    if let Err(error) = &result {
                        eprintln!("sandbox-shim: supervisor DNS error: {error}");
                    }
                    if let Some(sender) = replies.lock().unwrap().remove(&reply.stream_id) {
                        sender.send(result);
                    }
                }
            });
            // One Mediate stream at a time carries the proxy's DNS queries;
            // the native broker hands each query to one caller.
            let mut proxy_queries = match &runtime.network {
                Network::Proxy(egress) => Some(egress.dns.lock().await),
                Network::Native(_) => None,
            };
            let native = runtime.network.native().cloned();
            let mut ended = runtime.ended.subscribe();
            let mut stream_id = 0u64;
            loop {
                let next = async {
                    match (&mut proxy_queries, &native) {
                        (Some(queries), _) => queries.recv().await.map(OutgoingDns::proxy),
                        (None, Some(native)) => native.broker.accept_dns().await.ok().map(OutgoingDns::native),
                        (None, None) => None,
                    }
                };
                tokio::select! {
                    query = next => {
                        let Some(query) = query else { break };
                        stream_id += 1;
                        pending.lock().unwrap().insert(stream_id, query.reply);
                        yield MediateFrame {
                            payload: Some(mediate_frame::Payload::DnsQuery(DnsQuery {
                                stream_id,
                                request: query.request,
                                transport: query.transport as i32,
                                identity: Some(query.identity),
                                timing: query.timing,
                            })),
                        };
                    }
                    _ = until_true(&mut ended) => break,
                    _ = &mut reader => break,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn exchange(
        &self,
        request: Request<Streaming<ExchangeFrame>>,
    ) -> Result<Response<Chunks>, Status> {
        let (principal, mut input) = self
            .route(request, |f| match f.payload {
                Some(exchange_frame::Payload::BoundaryId(id)) => Some(id),
                _ => None,
            })
            .await?;
        let runtime = self.clone();
        let stream = async_stream::try_stream! {
            let envelope = protocol::read_request(&mut input).await?;
            match &envelope.request {
                wire::Request::AcceptNetwork if runtime.network.native().is_some() => {
                    envelope.validate_payload_digest()
                        .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
                    runtime.registry.require_active(&principal).map_err(status_from)?;
                    let native = runtime.network.native().cloned().expect("native network");
                    let mut ended = runtime.ended.subscribe();
                    // Never take an open for a supervisor that went away.
                    let pending = tokio::select! {
                        biased;
                        _ = input.message() => None,
                        _ = until_true(&mut ended) => None,
                        pending = native.broker.accept() => Some(pending),
                    };
                    let Some(pending) = pending else { return; };
                    let pending = pending.map_err(|error| Status::unavailable(format!("network broker: {error}")))?;
                    // Executables keep their first offered digest for the
                    // generation; a contradiction is offered as a failure.
                    let identity = native.pins.admit(pending.identity().clone());
                    let destination = pending.destination();
                    yield protocol::response(envelope.request_id.clone(), wire::Response::NetworkConnected {
                        identity: wire::BinaryIdentityWire::from(identity),
                        destination,
                        socket: Some(pending.socket()),
                        policy_generation: 0,
                        timing: wire::MediationTimingWire {
                            notification_to_queue_us: micros(pending.notification_to_queue()),
                            queue_wait_us: micros(pending.queue_wait()),
                        },
                    })?;
                    let decision = match input.message().await {
                        Ok(Some(ExchangeFrame { payload: Some(exchange_frame::Payload::TcpOpenDecision(decision)) })) => decision_from(decision.decision),
                        _ => OpenDecision::Denied(OpenDenial::MediationUnavailable),
                    };
                    if let OpenDecision::Denied(reason) = decision {
                        println!("sandbox-shim: supervisor denied {destination}: {reason:?}");
                    }
                    let decided = pending.decide(decision)
                        .map_err(|error| Status::unavailable(format!("network broker: {error}")))?;
                    let target = decided.established().await
                        .map_err(|error| Status::unavailable(format!("network relay: {error}")))?;
                    let Some(target) = target else { return; };
                    target.set_nonblocking(true).map_err(|error| Status::internal(error.to_string()))?;
                    let target = tokio::net::TcpStream::from_std(target).map_err(|error| Status::internal(error.to_string()))?;
                    openshell_core::net::set_tcp_nodelay_best_effort(&target);
                    let mut relayed = relay(target, Vec::new(), input);
                    while let Some(frame) = relayed.next().await {
                        yield frame?;
                    }
                    return;
                }
                wire::Request::AcceptNetwork => {
                    envelope.validate_payload_digest()
                        .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
                    runtime.registry.require_active(&principal).map_err(status_from)?;
                    let Network::Proxy(egress) = &runtime.network else { return; };
                    let Some(open) = runtime.next_open(egress).await else { return; };
                    yield protocol::response(envelope.request_id.clone(), wire::Response::NetworkConnected {
                        identity: wire::BinaryIdentityWire::from(open.identity),
                        destination: open.destination,
                        // No kernel socket evidence crosses the guest boundary.
                        socket: None,
                        policy_generation: 0,
                        timing: wire::MediationTimingWire::default(),
                    })?;
                    let decision = input.message().await?.and_then(|frame| match frame.payload {
                        Some(exchange_frame::Payload::TcpOpenDecision(decision)) => decision.decision,
                        _ => None,
                    });
                    let mut client = open.client;
                    match decision {
                        Some(tcp_open_decision::Decision::RelayReady(_)) => {
                            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await
                                .map_err(|error| Status::unavailable(error.to_string()))?;
                            let mut relayed = relay(client, open.early, input);
                            while let Some(frame) = relayed.next().await {
                                yield frame?;
                            }
                        }
                        other => {
                            let reason = match other {
                                Some(tcp_open_decision::Decision::Denied(code)) => {
                                    TcpOpenDenial::try_from(code).map_or("denied".to_string(), |d| d.as_str_name().to_lowercase())
                                }
                                _ => "mediation unavailable".to_string(),
                            };
                            println!("sandbox-shim: supervisor denied {}: {reason}", open.destination);
                            egress::deny(client, &format!("denied by OpenShell policy: {reason}")).await;
                        }
                    }
                    return;
                }
                wire::Request::LoopbackConnect { host, port } => {
                    envelope.validate_payload_digest()
                        .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
                    let connected = if host.is_loopback() {
                        match runtime.registry.require_active(&principal) {
                            Ok(()) => openshell_core::net::connect_tcp_nodelay_best_effort((*host, *port))
                                .await
                                .map_err(|error| Status::unavailable(format!("connect loopback port: {error}"))),
                            Err(error) => Err(status_from(error)),
                        }
                    } else {
                        Err(Status::invalid_argument("loopback target required"))
                    };
                    match connected {
                        Ok(stream) => {
                            yield protocol::response(envelope.request_id.clone(), wire::Response::LoopbackConnected)?;
                            let mut relayed = relay(stream, Vec::new(), input);
                            while let Some(frame) = relayed.next().await {
                                yield frame?;
                            }
                        }
                        Err(error) => yield protocol::response(envelope.request_id.clone(), error_response(&error))?,
                    }
                    return;
                }
                _ => {}
            }
            let response = match runtime.control(&principal, &envelope).await {
                Ok(response) => response,
                Err(error) => error_response(&error),
            };
            let attached = match &response {
                wire::Response::ProcessAttached { .. } => match &envelope.request {
                    wire::Request::AttachProcess { process_id } => Some(process_id.clone()),
                    _ => None,
                },
                wire::Response::ExecStarted { process_id, .. } => Some(process_id.clone()),
                _ => None,
            };
            let mediation = matches!(response, wire::Response::MediationReady);
            yield protocol::response(envelope.request_id, response)?;
            if let Some(process_id) = attached {
                let process = runtime.process(&process_id)?;
                Runtime::pump_stdin(process.clone(), input);
                let mut output = Runtime::process_output(process);
                while let Some(chunk) = output.next().await {
                    yield chunk?;
                }
            } else if mediation {
                let mut ended = runtime.ended.subscribe();
                until_true(&mut ended).await;
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Where the guest serves the backend channel.
pub enum Listen {
    Vsock(u32),
    Unix(PathBuf),
}

/// Create the shim-owned CA directory. The driver already prepared
/// `/sandbox`, `/tmp` and the `/etc/openshell-tls` mountpoint in the
/// workload rootfs; the serving shim writes nothing there.
fn prepare_guest() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(launch::SHIM_TLS_DIR)?;
    std::fs::set_permissions(launch::SHIM_TLS_DIR, std::fs::Permissions::from_mode(0o755))?;
    let root = std::fs::metadata(launch::WORKLOAD_ROOT).context("workload rootfs missing")?;
    ensure!(root.is_dir(), "workload rootfs is not a directory");
    Ok(())
}

fn tls_acceptor(launch: &Launch) -> Result<tokio_rustls::TlsAcceptor> {
    let certs = CertificateDer::pem_reader_iter(&mut launch.certificate.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::pem_reader_iter(&mut launch.private_key.as_bytes())
        .next()
        .transpose()?
        .context("missing TLS key")?;
    let mut tls =
        openshell_crypto::tls::server_builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls)))
}

pub async fn serve(launch: Launch, listen: Listen) -> Result<()> {
    let acceptor = tls_acceptor(&launch)?;
    let privilege = launch.privilege;
    let substrate: Substrate = launch.substrate;
    prepare_guest()?;
    let network = match substrate {
        // No fallback: without working mediation the guest does not serve.
        Substrate::Firecracker => {
            Network::Native(NativeNetwork::start().context("native network mediation unavailable")?)
        }
        Substrate::Gvisor => Network::Proxy(Arc::new(Egress::default())),
    };
    let runtime = Runtime::new(launch, network)?;
    println!(
        "sandbox-shim: serving sandbox {} on {} as {}",
        runtime.launch.boundary.sandbox_id,
        substrate.as_str(),
        privilege.as_str()
    );
    match &runtime.network {
        Network::Proxy(egress) => {
            let egress = egress.clone();
            tokio::spawn(async move {
                if let Err(error) = egress.serve(launch::PROXY_ADDR).await {
                    eprintln!("sandbox-shim: egress proxy stopped: {error:#}");
                }
            });
        }
        Network::Native(native) => {
            println!("sandbox-shim: native socket and DNS mediation ready");
            let native = native.clone();
            let watcher = runtime.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    if let Err(error) = native.healthy() {
                        eprintln!("sandbox-shim: network mediation failed: {error:#}");
                        watcher.end("network mediation failed").await;
                        return;
                    }
                }
            });
        }
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Box<dyn Io>>(16);
    match listen {
        Listen::Vsock(port) => {
            let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
                tokio_vsock::VMADDR_CID_ANY,
                port,
            ))
            .context("bind vsock listener")?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    if tx.send(Box::new(stream)).await.is_err() {
                        break;
                    }
                }
            });
        }
        Listen::Unix(path) => {
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path).context("bind backend socket")?;
            use std::os::unix::fs::PermissionsExt;
            // The host-side socket is reachable only through the driver's
            // private state directory; TLS and the launch JWT authenticate.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    if tx.send(Box::new(stream)).await.is_err() {
                        break;
                    }
                }
            });
        }
    }
    println!("sandbox-shim: backend channel ready");
    let registry = runtime.registry.clone();
    let lost = runtime.lost.clone();
    let incoming = async_stream::stream! {
        let mut rx = rx;
        while let Some(socket) = rx.recv().await {
            match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await {
                Ok(Ok(stream)) => yield Ok::<_, std::io::Error>(Connection {
                    stream,
                    id: SandboxConnectionId::new(),
                    registry: registry.clone(),
                    lost: lost.clone(),
                }),
                _ => continue,
            }
        }
    };
    let watcher = runtime.clone();
    tokio::spawn(async move {
        let mut lost = watcher.lost.subscribe();
        if lost.wait_for(|value| *value).await.is_ok() && !*watcher.ended.borrow() {
            // No supervisor recovery: losing the confirmed supervisor ends the
            // workload rather than leaving it running unmediated.
            watcher.end("supervisor connection lost").await;
        }
    });
    let mut ended = runtime.ended.subscribe();
    let server = tonic::transport::Server::builder()
        .add_service(
            isolation_backend_server::IsolationBackendServer::new(runtime.clone())
                .max_decoding_message_size(64 * 1024)
                .max_encoding_message_size(64 * 1024),
        )
        .add_service(
            sandbox_protocol_server::SandboxProtocolServer::new(runtime.clone())
                .max_decoding_message_size(
                    openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                )
                .max_encoding_message_size(
                    openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                ),
        )
        .serve_with_incoming(incoming);
    tokio::select! {
        result = server => result?,
        _ = async {
            until_true(&mut ended).await;
            // Let final responses flush before the guest goes away.
            tokio::time::sleep(Duration::from_secs(2)).await;
        } => {}
    }
    process::kill_workload(privilege);
    println!("sandbox-shim: boundary ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_durations_are_whole_microseconds() {
        let value = wire_duration(Duration::new(2, 123_456_789)).unwrap();
        assert_eq!((value.seconds, value.nanos), (2, 123_456_000));
    }

    #[test]
    fn decisions_map_every_denial() {
        use tcp_open_decision::Decision;
        assert_eq!(
            decision_from(Some(Decision::RelayReady(RelayReady {}))),
            OpenDecision::RelayReady
        );
        assert_eq!(
            decision_from(Some(Decision::Denied(TcpOpenDenial::PolicyDenied as i32))),
            OpenDecision::Denied(OpenDenial::PolicyDenied)
        );
        assert_eq!(
            decision_from(Some(Decision::Denied(99))),
            OpenDecision::Denied(OpenDenial::MediationUnavailable)
        );
        assert_eq!(
            decision_from(None),
            OpenDecision::Denied(OpenDenial::MediationUnavailable)
        );
    }
}
