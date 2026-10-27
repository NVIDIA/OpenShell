// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-facing lifecycle for the network-disabled JavaScript runtime.
use crate::{
    guest::{Guest, GuestResult, GuestStatus, read_script},
    launch::Launch,
    protocol::{self, BACKEND, boundary::*, control::*},
};
use anyhow::{Result, ensure};
use openshell_core::jwt::{SandboxId, SessionJwtVerifier, SessionTokenProfile, SystemJwtClock};
use openshell_isolation_interface::contract::BoundaryConfirmation;
use openshell_sandbox_backend::{boundary_protocol as wire, sandbox_auth::*};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, watch};
use tonic::{Request, Response, Status, Streaming};

type Chunks =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ExchangeFrame, Status>> + Send>>;
struct State {
    policy: Option<wire::SandboxPolicyWire>,
    ledger: HashMap<String, (String, wire::Response)>,
    publications: (u64, u64),
    running: bool,
    terminal: bool,
    /// How this generation was opened; replays must use the same RPC.
    opened_as: Option<i32>,
    /// Restore reference returned once this generation was suspended.
    suspended: Option<Vec<u8>>,
    /// Borrowed retained state until the driver acknowledges readiness.
    restoring: Option<Vec<u8>>,
}

/// The guest and its output. It outlives a runtime generation while suspended.
pub struct Workload {
    guest: Arc<Guest>,
    output: Arc<std::sync::Mutex<Option<(crate::guest::Output, crate::guest::Output)>>>,
    result: watch::Sender<Option<Arc<GuestResult>>>,
    started: AtomicBool,
}

impl Workload {
    fn new(script: &[u8]) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            guest: Arc::new(Guest::new(script)?),
            output: Arc::new(std::sync::Mutex::new(None)),
            result: watch::channel(None).0,
            started: AtomicBool::new(false),
        }))
    }
    fn output_lengths(&self) -> [usize; 2] {
        if let Some(result) = self.result.borrow().as_ref() {
            return [result.stdout.len(), result.stderr.len()];
        }
        self.output
            .lock()
            .unwrap()
            .as_ref()
            .map(|(out, err)| [out.contents().len(), err.contents().len()])
            .unwrap_or_default()
    }
}

/// A frozen workload waiting for ResumeBoundary.
struct Retained {
    sandbox_id: String,
    nonce: [u8; NONCE_BYTES],
    workload: Arc<Workload>,
    /// Output already streamed to an earlier generation.
    offsets: [usize; 2],
}

/// Backend-owned retained state. It lives for the whole `serve` process, so
/// it survives the runtime generation that suspended the guest.
pub struct Retention {
    key: [u8; 32],
    slot: std::sync::Mutex<Option<Retained>>,
}

const NONCE_BYTES: usize = 16;

impl Retention {
    /// Load or create the key that authenticates restore references. The key
    /// persists so a restarted backend can tell lost state from a forged
    /// or superseded reference.
    pub fn open(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("retention.key");
        if !path.exists() {
            crate::launch::write_private(&path, &random::<32>()?)?;
        }
        let key = std::fs::read(&path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("retention key must be 32 bytes"))?;
        Ok(Self {
            key,
            slot: std::sync::Mutex::new(None),
        })
    }
    fn reference(&self, sandbox_id: &str, nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
        use hmac::Mac;
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&self.key).expect("any key length");
        mac.update(sandbox_id.as_bytes());
        mac.update(nonce);
        let mut reference = nonce.to_vec();
        reference.extend_from_slice(&mac.finalize().into_bytes());
        reference
    }
    /// Return the nonce of an authentic reference for this sandbox.
    fn verify(&self, sandbox_id: &str, reference: &[u8]) -> Option<[u8; NONCE_BYTES]> {
        use hmac::Mac;
        let (nonce, tag) = reference.split_at_checked(NONCE_BYTES)?;
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&self.key).expect("any key length");
        mac.update(sandbox_id.as_bytes());
        mac.update(nonce);
        mac.verify_slice(tag).ok()?;
        nonce.try_into().ok()
    }
    /// Drop retained state; a frozen guest is terminated.
    pub fn discard(&self) {
        if let Some(retained) = self.slot.lock().unwrap().take() {
            retained.workload.guest.terminate();
            println!("Discarded retained state: {}", retained.sandbox_id);
        }
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    use std::io::Read;
    let mut bytes = [0; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub struct Runtime {
    launch: Launch,
    workload: std::sync::Mutex<Arc<Workload>>,
    retention: Arc<Retention>,
    restore_reference_path: PathBuf,
    output_start: std::sync::Mutex<[usize; 2]>,
    authenticator: SandboxProtocolAuthenticator,
    pub registry: Arc<SandboxConnectionRegistry>,
    opened: Mutex<HashSet<SandboxConnectionId>>,
    state: Mutex<State>,
    mutation: Mutex<()>,
    ended: watch::Sender<bool>,
}

impl Runtime {
    pub fn new(
        launch: Launch,
        retention: Arc<Retention>,
        restore_reference_path: PathBuf,
    ) -> Result<Arc<Self>> {
        let bytes = read_script(&launch.script)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        ensure!(
            serde_json::from_slice::<serde_json::Value>(&launch.descriptor)?["script_sha256"]
                == digest,
            "script binding changed"
        );
        ensure!(
            launch.boundary.workload_identity.resource_digest == digest,
            "script identity changed"
        );
        ensure!(
            launch.boundary.workload_identity == crate::launch::host_identity(digest.clone())?,
            "backend identity differs from the admitted host identity"
        );
        use openshell_isolation_interface::contract::ProvisioningEvidence;
        let fence = ProvisioningEvidence::from_enforcement_evidence(
            launch.boundary.generation.clone(),
            &crate::launch::capability_evidence(&digest),
        )?;
        ensure!(
            fence == launch.boundary.provisioning_evidence,
            "native V8 capability evidence differs from driver fence"
        );
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
        ));
        Ok(Arc::new(Self {
            launch,
            workload: std::sync::Mutex::new(Workload::new(&bytes)?),
            retention,
            restore_reference_path,
            output_start: std::sync::Mutex::new([0, 0]),
            authenticator,
            registry,
            opened: Mutex::new(HashSet::new()),
            mutation: Mutex::new(()),
            state: Mutex::new(State {
                policy: None,
                ledger: HashMap::new(),
                publications: (0, 0),
                running: false,
                terminal: false,
                opened_as: None,
                suspended: None,
                restoring: None,
            }),
            ended: watch::channel(false).0,
        }))
    }
    fn workload(&self) -> Arc<Workload> {
        self.workload.lock().unwrap().clone()
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
    async fn result(&self) -> Result<Arc<GuestResult>, Status> {
        let mut receiver = self.workload().result.subscribe();
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return Ok(result);
            }
            receiver
                .changed()
                .await
                .map_err(|_| Status::unavailable("guest completion lost"))?;
        }
    }
    fn exit(result: &GuestResult) -> wire::ExitStatusWire {
        match result.status {
            GuestStatus::Terminated => wire::ExitStatusWire::Signaled(15),
            _ => wire::ExitStatusWire::Exited(result.exit_code.unwrap_or(1)),
        }
    }
    pub async fn stop(&self) {
        let _mutation = self.mutation.lock().await;
        let mut state = self.state.lock().await;
        if let Err(error) = self.preserve_restore(&mut state).await {
            eprintln!("Could not retain failed restore: {error}");
            // Never leave a running guest behind after failed cleanup.
            self.retention.discard();
            let _ = std::fs::remove_file(&self.restore_reference_path);
        }
        // A suspended guest now belongs to the retention slot.
        if state.suspended.is_none() {
            self.workload().guest.terminate();
            if state.running {
                let _ = self.result().await;
            }
        }
        state.terminal = true;
        self.ended.send_replace(true);
        self.registry.mark_terminal();
    }
    /// A reference remains present until the driver observes readiness. A failed
    /// launch may already have thawed the guest, so freeze it again before the
    /// generation retires. The original reference stays valid for a retry.
    async fn preserve_restore(&self, state: &mut State) -> Result<bool, Status> {
        if state.suspended.is_some() {
            return Ok(true);
        }
        let Some(reference) = &state.restoring else {
            return Ok(false);
        };
        let pending = match std::fs::read(&self.restore_reference_path) {
            Ok(bytes) => bytes == *reference,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(Status::internal("read restore acknowledgement")),
        };
        if pending {
            let guest = self.workload().guest.clone();
            tokio::task::spawn_blocking(move || guest.freeze(Duration::from_secs(5)))
                .await
                .map_err(|_| Status::internal("freeze task failed"))?
                .map_err(|error| Status::unavailable(error.to_string()))?;
            state.suspended = Some(reference.clone());
            self.registry.mark_terminal();
        } else {
            // Readiness consumed the reference; this generation now owns the
            // guest. Retiring it must terminate rather than retain the guest.
            let workload = self.workload();
            let mut slot = self.retention.slot.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|retained| Arc::ptr_eq(&retained.workload, &workload))
            {
                slot.take();
            }
            state.restoring = None;
        }
        Ok(pending)
    }
    fn validate_policy(&self, policy: &wire::SandboxPolicyWire) -> Result<(), Status> {
        for (selector, expected) in [
            (
                &policy.run_as_user,
                self.launch.boundary.workload_identity.uid,
            ),
            (
                &policy.run_as_group,
                self.launch.boundary.workload_identity.gid,
            ),
        ] {
            if selector
                .as_ref()
                .is_some_and(|value| value != &expected.to_string())
            {
                return Err(Status::permission_denied(
                    "process identity differs from admitted host identity",
                ));
            }
        }
        Ok(())
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
                if state.suspended.is_some() {
                    return Err(Status::failed_precondition("boundary is suspended"));
                }
                if state.terminal
                    && !matches!(envelope.request, Q::Wait { .. } | Q::AttachProcess { .. })
                {
                    return Err(Status::failed_precondition("boundary is terminal"));
                }
                if envelope.request.is_replayable_mutation() && state.ledger.len() >= 1024 {
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
                self.registry
                    .attach(principal, *supervisor_instance_id)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
            }
            Q::Confirm => self
                .registry
                .require_attached(principal)
                .map_err(|e| Status::failed_precondition(e.to_string()))?,
            _ => self
                .registry
                .require_active(principal)
                .map_err(|e| Status::failed_precondition(e.to_string()))?,
        }
        if let Some(response) = cached {
            if matches!(envelope.request, Q::Confirm) {
                self.registry
                    .confirm(principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
            }
            return Ok(response);
        }
        match &envelope.request {
            Q::Wait { process_id } | Q::Signal { process_id, .. } | Q::Terminate { process_id } => {
                self.check_process(process_id)?
            }
            _ => {}
        }
        if matches!(envelope.request, Q::Wait { .. }) {
            return Ok(R::Exited {
                status: Self::exit(self.result().await?.as_ref()),
            });
        }
        if let Q::Signal { signal, .. } = &envelope.request
            && !matches!(signal, wire::SignalWire::Term)
        {
            return Err(Status::unimplemented("js-sbx supports TERM only"));
        }
        if matches!(
            envelope.request,
            Q::TerminateBoundary | Q::Terminate { .. } | Q::Signal { .. }
        ) {
            let mut state = self.state.lock().await;
            if !self.preserve_restore(&mut state).await? {
                self.workload().guest.terminate();
                if state.running {
                    let _ = self.result().await?;
                }
            }
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
                R::Attached {
                    snapshot: wire::SessionSnapshotWire {
                        generation: self.launch.boundary.generation.clone(),
                        processes: vec![],
                    },
                }
            }
            Q::Confirm => {
                if state.policy.is_none() {
                    return Err(Status::failed_precondition("attach required"));
                }
                self.registry
                    .confirm(principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
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
                        backend_audit: serde_json::json!({"script_sha256": self.launch.boundary.workload_identity.resource_digest, "network": "disabled", "filesystem": "no-host-access"}),
                    }),
                }
            }
            Q::StartAgent {
                sandbox_id,
                spec,
                provider_env_revision,
                provider_env,
                provider_files,
                ..
            } => {
                if sandbox_id != &self.launch.boundary.sandbox_id || state.policy.is_none() {
                    return Err(Status::permission_denied("admitted launch changed"));
                }
                if spec.timeout_secs != 0
                    || spec.workdir.as_deref().is_some_and(|path| path != "/work")
                    || spec.program != "/work/guest.js"
                    || !spec.args.is_empty()
                    || spec.interactive
                    || !provider_env.is_empty()
                    || !provider_files.is_empty()
                {
                    return Err(Status::unimplemented(
                        "this example accepts only the provisioned script, without args, providers or PTY",
                    ));
                }
                if state.running {
                    return Err(Status::failed_precondition("main process already started"));
                }
                state.running = true;
                state.publications = (*provider_env_revision, 1);
                let workload = self.workload();
                // A restored guest stays frozen until this generation starts it.
                if workload.started.swap(true, Ordering::SeqCst) {
                    workload.guest.thaw();
                    println!("Guest resumed: {}", self.launch.boundary.generation);
                    return Ok(self.commit(
                        envelope,
                        &mut state,
                        R::Started {
                            process_id: self.process_id(),
                            provider_env_revision: *provider_env_revision,
                            provider_env_generation: 1,
                        },
                    ));
                }
                let guest = workload.guest.clone();
                let output = workload.output.clone();
                tokio::spawn(async move {
                    let result = tokio::task::spawn_blocking(move || {
                        guest.run(|stdout, stderr| {
                            *output.lock().unwrap() = Some((stdout, stderr));
                        })
                    })
                    .await;
                    let result = match result {
                        Ok(Ok(result)) => result,
                        error => GuestResult {
                            status: GuestStatus::Failed,
                            exit_code: None,
                            stdout: vec![],
                            stderr: format!("guest failed: {error:?}").into_bytes(),
                            script_sha256: String::new(),
                        },
                    };
                    println!(
                        "Guest completed: {:?}, exit code {:?}",
                        result.status, result.exit_code
                    );
                    for line in String::from_utf8_lossy(&result.stdout).lines() {
                        println!("guest: {line}");
                    }
                    for line in String::from_utf8_lossy(&result.stderr).lines() {
                        eprintln!("guest: {line}");
                    }
                    workload.result.send_replace(Some(Arc::new(result)));
                });
                R::Started {
                    process_id: self.process_id(),
                    provider_env_revision: *provider_env_revision,
                    provider_env_generation: 1,
                }
            }
            Q::AttachProcess { process_id } => {
                self.check_process(process_id)?;
                R::ProcessAttached { terminal: false }
            }
            Q::UpdateProviderEnvironment {
                revision,
                generation,
                provider_env,
                provider_files,
            } => {
                if !provider_env.is_empty() || !provider_files.is_empty() {
                    return Err(Status::unimplemented(
                        "provider injection is not supported in this example",
                    ));
                }
                if *generation <= state.publications.1 || *revision < state.publications.0 {
                    return Err(Status::failed_precondition("stale publication"));
                }
                state.publications = (*revision, *generation);
                R::ProviderEnvironmentUpdated {
                    revision: *revision,
                    generation: *generation,
                    applied: true,
                }
            }
            Q::Signal { process_id, .. } => {
                self.check_process(process_id)?;
                R::Signaled
            }
            Q::Terminate { process_id } => {
                self.check_process(process_id)?;
                R::Terminated
            }
            Q::TerminateBoundary => {
                state.terminal = true;
                self.ended.send_replace(true);
                R::BoundaryTerminated
            }
            Q::OpenMediation => R::MediationReady,
            _ => {
                return Err(Status::unimplemented(
                    "operation is not supported by js-sbx",
                ));
            }
        };
        Ok(self.commit(envelope, &mut state, response))
    }
    fn commit(
        &self,
        envelope: &wire::RequestEnvelope,
        state: &mut State,
        response: wire::Response,
    ) -> wire::Response {
        if envelope.request.is_replayable_mutation() {
            state.ledger.insert(
                envelope.request_id.clone(),
                (envelope.payload_digest.clone(), response.clone()),
            );
        }
        response
    }
    fn process_output(self: Arc<Self>) -> Chunks {
        Box::pin(async_stream::try_stream! {
            let workload = self.workload();
            // A restored generation streams only output it has not seen.
            let mut offsets = *self.output_start.lock().unwrap();
            loop {
                let complete = workload.result.borrow().clone();
                let buffers = if let Some(result) = &complete {
                    [result.stdout.clone(), result.stderr.clone()]
                } else {
                    workload.output.lock().unwrap().as_ref()
                        .map(|(out, err)| [out.contents(), err.contents()])
                        .unwrap_or_default()
                };
                for (index, data) in buffers.into_iter().enumerate() {
                    let channel = if index == 0 {
                        wire::STREAM_STDOUT
                    } else {
                        wire::STREAM_STDERR
                    };
                    let pending = data.get(offsets[index]..)
                        .ok_or_else(|| Status::internal("guest output was truncated"))?;
                    for piece in pending.chunks(wire::MAX_STREAM_FRAME_BYTES) {
                        yield protocol::stream_frame(channel, piece)?;
                    }
                    offsets[index] = data.len();
                }
                if let Some(result) = complete {
                    let bytes = openshell_sandbox_backend::protobuf::encode(&Runtime::exit(&result))
                        .map_err(|_| Status::internal("encode exit status"))?;
                    yield protocol::stream_frame(wire::STREAM_EXIT, &bytes)?;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }
    fn process_id(&self) -> String {
        format!("{}:main", self.launch.boundary.generation)
    }
    fn check_process(&self, id: &str) -> Result<(), Status> {
        if id == self.process_id() {
            Ok(())
        } else {
            Err(Status::not_found("unknown guest process"))
        }
    }
    fn validate_launch(&self, launch: &OpenBoundaryRequest) -> Result<(), Status> {
        let b = &self.launch.boundary;
        if launch.session_id != b.session_id.to_string()
            || launch.backend_name != BACKEND
            || launch.driver_descriptor != self.launch.descriptor
        {
            return Err(Status::permission_denied(
                "immutable launch binding changed",
            ));
        }
        Ok(())
    }
    /// Record how this generation opened. Replays get the same outcome.
    async fn open_as(
        &self,
        principal: &SandboxProtocolPrincipal,
        outcome: i32,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        self.opened.lock().await.insert(principal.connection_id());
        Ok(Response::new(OpenBoundaryResponse {
            boundary_id: self.launch.boundary.generation.clone(),
            outcome,
        }))
    }
    /// Adopt the retained guest named by an authentic reference.
    fn restore(&self, reference: &[u8], restart_if_restore_fails: bool) -> Result<i32, Status> {
        use open_boundary_response::LaunchOutcome;
        let sandbox_id = &self.launch.boundary.sandbox_id;
        let nonce = self
            .retention
            .verify(sandbox_id, reference)
            .ok_or_else(|| Status::failed_precondition("restore reference is not valid"))?;
        let slot = self.retention.slot.lock().unwrap();
        match slot.as_ref() {
            Some(retained) if retained.sandbox_id == *sandbox_id && retained.nonce == nonce => {
                // Borrow the retained guest until readiness is acknowledged.
                // Opening a boundary must not consume the only retryable state.
                *self.workload.lock().unwrap() = retained.workload.clone();
                *self.output_start.lock().unwrap() = retained.offsets;
                Ok(LaunchOutcome::Restored as i32)
            }
            Some(retained) if retained.sandbox_id == *sandbox_id => Err(
                Status::failed_precondition("restore reference was superseded"),
            ),
            // The reference is authentic, but this backend no longer holds the
            // state, for example after the backend process restarted.
            _ if restart_if_restore_fails => Ok(LaunchOutcome::ColdStartFallback as i32),
            _ => Err(Status::failed_precondition("retained state is unavailable")),
        }
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
            backend: Some(protocol::metadata()),
        }))
    }
    async fn open_boundary(
        &self,
        request: Request<OpenBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        use open_boundary_response::LaunchOutcome;
        let principal = self.authenticate(&request)?;
        self.validate_launch(request.get_ref())?;
        let mut state = self.state.lock().await;
        let outcome = match state.opened_as {
            Some(outcome) => outcome,
            None => {
                if let Some(restore) = &self.launch.restore {
                    let outcome =
                        self.restore(&restore.reference, restore.restart_if_restore_fails)?;
                    if outcome == LaunchOutcome::Restored as i32 {
                        state.restoring = Some(restore.reference.clone());
                    }
                    println!(
                        "Boundary resumed: {} ({})",
                        self.launch.boundary.generation,
                        if outcome == LaunchOutcome::Restored as i32 {
                            "restored"
                        } else {
                            "cold start"
                        }
                    );
                    state.opened_as = Some(outcome);
                    outcome
                } else {
                    // A fresh launch supersedes any state retained for this sandbox.
                    self.retention.discard();
                    state.opened_as = Some(LaunchOutcome::Fresh as i32);
                    LaunchOutcome::Fresh as i32
                }
            }
        };
        drop(state);
        self.open_as(&principal, outcome).await
    }
    async fn suspend_boundary(
        &self,
        request: Request<SuspendBoundaryRequest>,
    ) -> Result<Response<SuspendBoundaryResponse>, Status> {
        let principal = self.authenticate(&request)?;
        let q = request.into_inner();
        let b = &self.launch.boundary;
        if q.boundary_id != b.generation
            || q.generation_id != b.generation
            || q.session_id != b.session_id.to_string()
        {
            return Err(Status::permission_denied("not the active boundary"));
        }
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
        // Wait for in-flight mutations so none lands after the fence.
        let _mutation = self.mutation.lock().await;
        let mut state = self.state.lock().await;
        if let Some(reference) = &state.suspended {
            return Ok(Response::new(SuspendBoundaryResponse {
                restore_reference: reference.clone(),
            }));
        }
        if state.terminal {
            return Err(Status::failed_precondition("boundary is terminal"));
        }
        let workload = self.workload();
        let nonce = random::<NONCE_BYTES>().map_err(|_| Status::internal("entropy"))?;
        let reference = self.retention.reference(&b.sandbox_id, &nonce);
        let guest = workload.guest.clone();
        tokio::task::spawn_blocking(move || guest.freeze(Duration::from_secs(5)))
            .await
            .map_err(|_| Status::internal("freeze task failed"))?
            .map_err(|error| Status::unavailable(error.to_string()))?;
        if crate::launch::write_private(&self.restore_reference_path, &reference).is_err() {
            workload.guest.thaw();
            return Err(Status::internal("persist retained state reference"));
        }
        *self.retention.slot.lock().unwrap() = Some(Retained {
            sandbox_id: b.sandbox_id.clone(),
            nonce,
            offsets: workload.output_lengths(),
            workload,
        });
        // Fence: every later control call on this generation is rejected.
        state.suspended = Some(reference.clone());
        self.registry.mark_terminal();
        println!("Guest suspended: {}", b.generation);
        Ok(Response::new(SuspendBoundaryResponse {
            restore_reference: reference,
        }))
    }
    async fn resume_boundary(
        &self,
        request: Request<ResumeBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        let principal = self.authenticate(&request)?;
        let q = request.into_inner();
        self.validate_launch(
            q.launch
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("launch required"))?,
        )?;
        let mut state = self.state.lock().await;
        let outcome = match state.opened_as {
            Some(outcome) if outcome != open_boundary_response::LaunchOutcome::Fresh as i32 => {
                outcome
            }
            Some(_) => {
                return Err(Status::failed_precondition(
                    "this generation was opened with OpenBoundary",
                ));
            }
            None => {
                let outcome = self.restore(&q.restore_reference, q.restart_if_restore_fails)?;
                if outcome == open_boundary_response::LaunchOutcome::Restored as i32 {
                    state.restoring = Some(q.restore_reference.clone());
                }
                println!(
                    "Boundary resumed: {} ({})",
                    self.launch.boundary.generation,
                    if outcome == open_boundary_response::LaunchOutcome::Restored as i32 {
                        "restored"
                    } else {
                        "cold start"
                    }
                );
                state.opened_as = Some(outcome);
                outcome
            }
        };
        drop(state);
        self.open_as(&principal, outcome).await
    }
}

#[tonic::async_trait]
impl sandbox_protocol_server::SandboxProtocol for Arc<Runtime> {
    type ExchangeStream = Chunks;
    type MediateStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<MediateFrame, Status>> + Send>>;
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
            let mut ended = runtime.ended.subscribe();
            while !*ended.borrow_and_update() {
                ended.changed().await.map_err(|_| Status::unavailable("boundary closed"))?;
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
            if matches!(envelope.request, wire::Request::AcceptNetwork) {
                envelope.validate_payload_digest()
                    .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
                runtime.registry.require_active(&principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
                let mut ended = runtime.ended.subscribe();
                // The guest has no socket bindings. Keep the network accept
                // pending until shutdown or the supervisor disconnects.
                tokio::select! {
                    _ = ended.wait_for(|value| *value) => {},
                    _ = input.message() => {},
                }
                return;
            }
            let response = match runtime.control(&principal, &envelope).await {
                Ok(response) => response,
                Err(error) => wire::Response::Error {
                    kind: match error.code() {
                        tonic::Code::InvalidArgument => wire::BoundaryErrorKind::Invalid,
                        tonic::Code::Unavailable => wire::BoundaryErrorKind::Unavailable,
                        tonic::Code::Unimplemented => wire::BoundaryErrorKind::Unsupported,
                        _ => wire::BoundaryErrorKind::Denied,
                    },
                    message: error.message().to_string(),
                },
            };
            let attached = matches!(response, wire::Response::ProcessAttached { .. });
            let mediation = matches!(response, wire::Response::MediationReady);
            yield protocol::response(envelope.request_id, response)?;
            if attached {
                use tokio_stream::StreamExt;
                let mut output = runtime.clone().process_output();
                while let Some(chunk) = output.next().await {
                    yield chunk?;
                }
            }
            if mediation {
                let mut ended = runtime.ended.subscribe();
                while !*ended.borrow_and_update() {
                    ended.changed().await
                        .map_err(|_| Status::unavailable("boundary closed"))?;
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

pub async fn serve(state_dir: PathBuf) -> Result<()> {
    let state_dir = state_dir.canonicalize()?;
    let socket_path = state_dir.join("backend.sock");
    let retention = Arc::new(Retention::open(&state_dir)?);
    println!(
        "js-sbx waiting for driver provisioning in {} on {}",
        state_dir.display(),
        socket_path.display()
    );
    loop {
        let path = state_dir.join("launch.json");
        let discard = state_dir.join("discard-retained");
        loop {
            // The driver asks for retained state to be dropped on stop and delete.
            if discard.exists() {
                retention.discard();
                std::fs::remove_file(&discard)?;
            }
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let launch: Launch = serde_json::from_slice(&std::fs::read(&path)?)?;
        let certs = rustls_pemfile::certs(&mut launch.certificate.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut launch.private_key.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("missing TLS key"))?;
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let runtime = Runtime::new(
            launch,
            retention.clone(),
            state_dir.join("restore-reference"),
        )?;
        println!(
            "JavaScript runtime provisioned: {}",
            runtime.launch.boundary.sandbox_id
        );
        let registry = runtime.registry.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        crate::launch::write_private(&state_dir.join("active"), b"ready")?;
        let incoming = async_stream::stream! { loop {
            let (socket,_)=match listener.accept().await { Ok(v)=>v,Err(e)=>{yield Err(e);continue} };
            match tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await {
                Ok(Ok(stream))=>yield Ok(crate::transport::Connection {stream,id:SandboxConnectionId::new(),registry:registry.clone()}),
                _=>continue,
            }
        }};
        let shutdown = async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            runtime.stop().await;
        };
        tonic::transport::Server::builder()
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
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await?;
        std::fs::remove_file(&socket_path)?;
        std::fs::remove_file(state_dir.join("active"))?;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn launch(directory: &Path, generation: &str) -> Launch {
        use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
        use openshell_isolation_interface::contract::ProvisioningEvidence;
        use openshell_sandbox_backend::delegated::DelegatedLaunch;
        let bytes = read_script(&directory.join("guest.js")).unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Launch {
            boundary: DelegatedLaunch {
                backend_name: BACKEND.into(),
                sandbox_id: "sandbox-a".into(),
                generation: generation.into(),
                session_id: uuid::Uuid::new_v4().to_string().parse().unwrap(),
                workload_identity: crate::launch::host_identity(digest.clone()).unwrap(),
                tls: wire::SandboxTlsClientConfig {
                    server_name: "test".into(),
                    trust_anchor_pem: String::new(),
                },
                host_gateway_ip: None,
                resource_claims: Default::default(),
                provisioning_evidence: ProvisioningEvidence::from_enforcement_evidence(
                    generation,
                    &crate::launch::capability_evidence(&digest),
                )
                .unwrap(),
            },
            script: directory.join("guest.js"),
            descriptor: serde_json::to_vec(&serde_json::json!({"script_sha256": digest})).unwrap(),
            gateway_id: "test".into(),
            keys: vec![SessionVerificationKey {
                key_id: "test".into(),
                public_key_pem: key.public_key_pem().into_bytes(),
            }],
            epoch: CredentialEpoch::new(1).unwrap(),
            rotation: SessionRotation::new(1).unwrap(),
            certificate: String::new(),
            private_key: String::new(),
            restore: None,
        }
    }

    async fn restoring_runtime(
        directory: &Path,
        retention: Arc<Retention>,
        reference: &[u8],
        generation: &str,
    ) -> Arc<Runtime> {
        let runtime = Runtime::new(
            launch(directory, generation),
            retention,
            directory.join("restore-reference"),
        )
        .unwrap();
        assert_eq!(
            runtime.restore(reference, false).unwrap(),
            open_boundary_response::LaunchOutcome::Restored as i32
        );
        runtime.state.lock().await.restoring = Some(reference.to_vec());
        runtime
    }

    #[tokio::test]
    async fn failed_restore_before_start_keeps_the_guest_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("guest.js"),
            b"console.log('retained')",
        )
        .unwrap();
        let retention = Arc::new(retention());
        let workload = Workload::new(b"console.log('retained')").unwrap();
        workload.guest.freeze(Duration::from_secs(1)).unwrap();
        let nonce = [3; NONCE_BYTES];
        let reference = retention.reference("sandbox-a", &nonce);
        crate::launch::write_private(&directory.path().join("restore-reference"), &reference)
            .unwrap();
        *retention.slot.lock().unwrap() = Some(Retained {
            sandbox_id: "sandbox-a".into(),
            nonce,
            workload: workload.clone(),
            offsets: [0, 0],
        });
        let failed = restoring_runtime(directory.path(), retention.clone(), &reference, "g1").await;
        failed.stop().await;
        let retry = restoring_runtime(directory.path(), retention.clone(), &reference, "g2").await;
        assert!(Arc::ptr_eq(&retry.workload(), &workload));
        workload.guest.thaw();
        let result = tokio::task::spawn_blocking(move || workload.guest.run(|_, _| {}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.status, GuestStatus::Exited);
        assert_eq!(result.stdout, b"retained\n");
    }

    #[tokio::test]
    async fn failed_restore_after_thaw_refreezes_until_retry() {
        let directory = tempfile::tempdir().unwrap();
        let script = b"let n = 0; let next = Date.now(); while (n < 6) { if (Date.now() >= next) { console.log(++n); next = Date.now() + 100; } }";
        std::fs::write(directory.path().join("guest.js"), script).unwrap();
        let retention = Arc::new(retention());
        let workload = Workload::new(script).unwrap();
        let nonce = [3; NONCE_BYTES];
        let reference = retention.reference("sandbox-a", &nonce);
        crate::launch::write_private(&directory.path().join("restore-reference"), &reference)
            .unwrap();
        *retention.slot.lock().unwrap() = Some(Retained {
            sandbox_id: "sandbox-a".into(),
            nonce,
            workload: workload.clone(),
            offsets: [0, 0],
        });
        let failed = restoring_runtime(directory.path(), retention.clone(), &reference, "g1").await;
        failed.state.lock().await.running = true;
        workload.started.store(true, Ordering::SeqCst);
        let runner = workload.clone();
        let (sent, received) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let result = runner
                .guest
                .run(|stdout, stderr| {
                    *runner.output.lock().unwrap() = Some((stdout.clone(), stderr));
                    assert!(sent.send(stdout).is_ok());
                })
                .unwrap();
            runner.result.send_replace(Some(Arc::new(result)));
        });
        let output = received.await.unwrap();
        while output.contents().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        failed.stop().await;
        let frozen = output.contents();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(output.contents(), frozen);
        let retry = restoring_runtime(directory.path(), retention.clone(), &reference, "g2").await;
        assert!(Arc::ptr_eq(&retry.workload(), &workload));
        workload.guest.thaw();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            workload.result.borrow().as_ref().unwrap().status,
            GuestStatus::Exited
        );
        assert_eq!(output.contents(), b"1\n2\n3\n4\n5\n6\n");
        // Once readiness consumes the reference, retirement must not keep state.
        std::fs::remove_file(directory.path().join("restore-reference")).unwrap();
        retry.stop().await;
        assert!(retention.slot.lock().unwrap().is_none());
    }

    fn retention() -> Retention {
        Retention {
            key: [7; 32],
            slot: std::sync::Mutex::new(None),
        }
    }

    #[test]
    fn restore_reference_is_bound_to_the_sandbox_and_key() {
        let retention = retention();
        let nonce = [3; NONCE_BYTES];
        let reference = retention.reference("sandbox-a", &nonce);
        assert_eq!(retention.verify("sandbox-a", &reference), Some(nonce));
        assert_eq!(retention.verify("sandbox-b", &reference), None);
        let mut forged = reference.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(retention.verify("sandbox-a", &forged), None);
        assert_eq!(retention.verify("sandbox-a", &reference[..4]), None);
        let other = Retention {
            key: [8; 32],
            ..retention
        };
        assert_eq!(other.verify("sandbox-a", &reference), None);
    }
}
