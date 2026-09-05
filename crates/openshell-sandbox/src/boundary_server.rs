// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared implementation of the capability-free `openshell-sandbox` runtime.
//!
//! This is transport and lifecycle glue, not another supervisor model. When
//! the control role authorizes `start_agent`, it invokes the existing process
//! supervisor inside the driver-provisioned boundary.

#![allow(unsafe_code)]

use std::path::Path;

#[cfg(target_os = "linux")]
mod linux {
    use super::Path;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd as _, OwnedFd};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use crate::boundary_io::BoundaryRuntimeState;
    use crate::delegated::{AgentSignaler, spawn_workload};
    use crate::identity::{DriverIdentity, resolve_process_identity};
    use crate::main_session::{MainOutput, MainSession};
    use crate::network_broker::NetworkBroker;
    use crate::process::ProcessStatus;
    use openshell_core::provider_credentials::ProviderCredentialState;
    use openshell_isolation_interface::contract::{
        BoundaryExec, BoundaryPortForward, BoundaryProcess, BoundaryTerminal, CapabilityEvidence,
        ExecSession, LoopbackTarget, ResolvedWorkloadIdentity, SandboxConfirmEvidence,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use openshell_isolation_interface::boundary_protocol::{
        AgentSpecWire, BinaryIdentityWire, BoundaryConfig,
        BoundaryListener as BoundaryListenerConfig, DnsQueryResultWire, ExecSpecWire,
        ExitStatusWire, OutputWindowWire, ProcessKindWire, ProcessSnapshotWire, Request,
        RequestEnvelope, Response, ResponseEnvelope, STREAM_DNS_ACK, STREAM_DNS_RESPONSE,
        STREAM_EXIT, STREAM_NETWORK_DECISION, STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED,
        STREAM_STDOUT, SandboxPolicyWire, SessionSnapshotWire, SignalWire, encode_frame,
        read_frame, read_stream_frame, validate_resource_claims, write_frame, write_stream_frame,
    };

    const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);
    const MAX_CONTROL_CONNECTIONS: usize = 128;
    const MAX_REPLAY_LEDGER_ENTRIES: usize = 4096;
    const MAX_RETAINED_EXEC_PROCESSES: usize = 64;

    struct ControlConnectionSlot(Arc<AtomicUsize>);

    impl Drop for ControlConnectionSlot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn acquire_control_connection_slot(active: &Arc<AtomicUsize>) -> Option<ControlConnectionSlot> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CONTROL_CONNECTIONS).then_some(current + 1)
            })
            .ok()
            .map(|_| ControlConnectionSlot(active.clone()))
    }
    static BOUNDARY_TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);

    extern "C" fn request_boundary_termination(_signal: libc::c_int) {
        BOUNDARY_TERMINATION_REQUESTED.store(true, Ordering::Release);
    }

    pub fn run_boundary(
        config_path: &Path,
        qualification: crate::RuntimeQualification,
    ) -> Result<(), String> {
        install_boundary_signal_handlers()?;
        make_boundary_nondumpable()?;
        disable_core_dumps()?;
        let bytes = std::fs::read(config_path)
            .map_err(|error| format!("read boundary config {}: {error}", config_path.display()))?;
        let config: BoundaryConfig = serde_json::from_slice(&bytes).map_err(|error| {
            format!("decode boundary config {}: {error}", config_path.display())
        })?;
        validate_config(&config)?;
        validate_runtime_resource_claims(&config)?;
        validate_running_identity(&config.workload_identity)?;
        std::fs::remove_file(config_path).map_err(|error| {
            format!("consume boundary config {}: {error}", config_path.display())
        })?;
        let child_env = serde_json::to_string(&config.child_env)
            .map_err(|error| format!("encode boundary workload environment: {error}"))?;
        // This runs before the Tokio runtime or control threads exist. The process
        // supervisor consumes the serialized map and applies values only to
        // workload children.
        unsafe {
            std::env::set_var(openshell_core::sandbox_env::USER_ENVIRONMENT, child_env);
        }
        crate::sandbox::apply_supervisor_startup_hardening()
            .map_err(|error| format!("install sandbox process prelude: {error}"))?;
        let (launcher, listener) = openshell_isolation_interface::linux::workload_launcher::start()
            .map_err(|error| format!("start sandbox workload launcher: {error}"))?;
        crate::process::configure_workload_launcher(launcher.clone())
            .map_err(|error| format!("configure sandbox workload launcher: {error}"))?;
        let network_broker = NetworkBroker::start(listener)
            .map_err(|error| format!("start sandbox network broker: {error}"))?;
        let process_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("create boundary process runtime: {error}"))?;
        let runtime = Arc::new(BoundaryRuntime::new(
            config.clone(),
            process_runtime.handle().clone(),
            network_broker,
            launcher,
            qualification,
        ));
        serve(&config.listener, runtime)
    }

    fn make_boundary_nondumpable() -> Result<(), String> {
        // SAFETY: PR_SET_DUMPABLE accepts one scalar flag. The sandbox keeps
        // bootstrap and protected-channel keys in memory after this point.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(format!(
                "make sandbox process nondumpable: {}",
                io::Error::last_os_error()
            ))
        }
    }

    fn disable_core_dumps() -> Result<(), String> {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid immutable rlimit value.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } == 0 {
            Ok(())
        } else {
            Err(format!(
                "disable sandbox core dumps: {}",
                io::Error::last_os_error()
            ))
        }
    }

    fn install_boundary_signal_handlers() -> Result<(), String> {
        BOUNDARY_TERMINATION_REQUESTED.store(false, Ordering::Release);
        let action = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::Handler(request_boundary_termination),
            nix::sys::signal::SaFlags::empty(),
            nix::sys::signal::SigSet::empty(),
        );
        for signal in [
            nix::sys::signal::Signal::SIGTERM,
            nix::sys::signal::Signal::SIGINT,
        ] {
            // SAFETY: the installed handler only performs a lock-free atomic
            // store, which is async-signal-safe, and remains valid for the
            // lifetime of the boundary process.
            unsafe { nix::sys::signal::sigaction(signal, &action) }
                .map_err(|error| format!("install boundary {signal:?} handler: {error}"))?;
        }
        Ok(())
    }

    fn validate_config(config: &BoundaryConfig) -> Result<(), String> {
        if config.boundary_id.is_empty() {
            return Err("boundary ID must not be empty".to_string());
        }
        if config.generation.is_empty() || config.session_epoch.is_empty() {
            return Err("boundary generation and session epoch must not be empty".to_string());
        }
        if config.bootstrap_token.len() < 32 {
            return Err("boundary bootstrap token must contain at least 32 bytes".to_string());
        }
        validate_resource_claims(&config.resource_claims).map_err(|error| error.to_string())?;
        config
            .driver_fence
            .validate_for_backend(config.driver_fence.backend_name())
            .map_err(|error| error.to_string())?;
        for (claim, path) in &config.resource_claim_files {
            if !config.resource_claims.contains_key(claim) {
                return Err(format!(
                    "runtime resource-claim file refers to unknown claim {claim}"
                ));
            }
            if !path.is_absolute() {
                return Err(format!(
                    "runtime resource-claim file for {claim} must be absolute"
                ));
            }
        }
        match &config.listener {
            BoundaryListenerConfig::Unix { socket_path, tls }
                if !socket_path.is_absolute() || !tls_paths_are_absolute(tls) =>
            {
                return Err("boundary Unix socket path must be absolute".to_string());
            }
            BoundaryListenerConfig::TlsTcp { address, tls }
                if address.port() == 0 || !tls_paths_are_absolute(tls) =>
            {
                return Err(
                    "boundary TLS listener requires a nonzero port and absolute certificate paths"
                        .to_string(),
                );
            }
            BoundaryListenerConfig::Vsock {
                control_port: 0, ..
            } => {
                return Err("boundary control port must be nonzero".to_string());
            }
            BoundaryListenerConfig::Unix { .. }
            | BoundaryListenerConfig::TlsTcp { .. }
            | BoundaryListenerConfig::Vsock { .. } => {}
        }
        if config.workload_identity.uid == 0 || config.workload_identity.gid == 0 {
            return Err("sandbox workload UID and GID must be nonzero".to_string());
        }
        Ok(())
    }

    fn tls_paths_are_absolute(
        tls: &openshell_isolation_interface::boundary_protocol::BoundaryServerTls,
    ) -> bool {
        tls.certificate_chain_path.is_absolute()
            && tls.private_key_path.is_absolute()
            && tls.client_ca_certificate_path.is_absolute()
    }

    fn validate_runtime_resource_claims(config: &BoundaryConfig) -> Result<(), String> {
        for (claim, path) in &config.resource_claim_files {
            let expected = config
                .resource_claims
                .get(claim)
                .expect("validated resource-claim file key");
            let observed = std::fs::read_to_string(path).map_err(|error| {
                format!(
                    "read runtime resource claim {claim} from {}: {error}",
                    path.display()
                )
            })?;
            if observed.trim() != expected {
                return Err(format!(
                    "runtime resource claim {claim} does not match the admitted resource"
                ));
            }
        }
        Ok(())
    }

    fn normalized_supplementary_groups(mut groups: Vec<u32>, primary_gid: u32) -> Vec<u32> {
        groups.retain(|gid| *gid != primary_gid);
        groups.sort_unstable();
        groups.dedup();
        groups
    }

    #[allow(clippy::similar_names)]
    fn validate_running_identity(expected: &ResolvedWorkloadIdentity) -> Result<(), String> {
        let mut real_uid = 0;
        let mut effective_uid = 0;
        let mut saved_uid = 0;
        let mut real_gid = 0;
        let mut effective_gid = 0;
        let mut saved_gid = 0;
        // SAFETY: all pointers refer to live scalar output storage.
        if unsafe {
            libc::getresuid(
                &raw mut real_uid,
                &raw mut effective_uid,
                &raw mut saved_uid,
            )
        } != 0
            || unsafe {
                libc::getresgid(
                    &raw mut real_gid,
                    &raw mut effective_gid,
                    &raw mut saved_gid,
                )
            } != 0
        {
            return Err(format!(
                "measure sandbox identity: {}",
                io::Error::last_os_error()
            ));
        }
        if [real_uid, effective_uid, saved_uid]
            .iter()
            .any(|uid| *uid != expected.uid)
            || [real_gid, effective_gid, saved_gid]
                .iter()
                .any(|gid| *gid != expected.gid)
        {
            return Err(format!(
                "sandbox identity does not match resolved workload {}:{}",
                expected.uid, expected.gid
            ));
        }
        // SAFETY: a null buffer with size zero queries the group count.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(format!(
                "measure sandbox supplementary groups: {}",
                io::Error::last_os_error()
            ));
        }
        let mut groups = vec![0_u32; usize::try_from(count).unwrap_or(0)];
        if count > 0 {
            // SAFETY: groups has capacity for exactly `count` gid_t values.
            if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
                return Err(format!(
                    "read sandbox supplementary groups: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        let groups = normalized_supplementary_groups(groups, expected.gid);
        if groups != expected.supplementary_gids {
            return Err(format!(
                "sandbox supplementary groups {groups:?} do not match resolved workload {:?}",
                expected.supplementary_gids
            ));
        }
        Ok(())
    }

    fn serve(config: &BoundaryListenerConfig, runtime: Arc<BoundaryRuntime>) -> Result<(), String> {
        let listener = ControlListener::bind(config)
            .map_err(|error| format!("bind boundary control listener: {error}"))?;
        let active_connections = Arc::new(AtomicUsize::new(0));
        tracing::info!(?config, "Boundary control listener ready");
        loop {
            if BOUNDARY_TERMINATION_REQUESTED.load(Ordering::Acquire) {
                runtime.shutdown();
                return Ok(());
            }
            match listener.accept() {
                Ok(stream) => {
                    let Some(slot) = acquire_control_connection_slot(&active_connections) else {
                        tracing::warn!(
                            limit = MAX_CONTROL_CONNECTIONS,
                            "Boundary control connection limit reached"
                        );
                        continue;
                    };
                    let runtime = runtime.clone();
                    std::thread::spawn(move || {
                        let _slot = slot;
                        let stream = match stream.establish(&runtime.process_runtime) {
                            Ok(stream) => stream,
                            Err(error) => {
                                tracing::warn!(%error, "Boundary control transport handshake failed");
                                return;
                            }
                        };
                        if let Err(error) = serve_one(stream, &runtime) {
                            tracing::warn!(%error, "Boundary control request failed: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("accept boundary control connection: {error}")),
            }
        }
    }

    fn serve_one(mut stream: ControlStream, runtime: &BoundaryRuntime) -> Result<(), String> {
        stream
            .set_timeout(CONTROL_IO_TIMEOUT)
            .map_err(|error| format!("set control timeout: {error}"))?;
        let request: RequestEnvelope =
            read_frame(&mut stream).map_err(|error| format!("read control frame: {error}"))?;
        if !runtime.authenticate(&request) {
            let response = ResponseEnvelope {
                request_id: request.request_id,
                response: guest_error("denied", "control authentication failed"),
            };
            return write_frame(&mut stream, &response)
                .map_err(|error| format!("write control frame: {error}"));
        }
        if request.validate_payload_digest().is_err() {
            let response = ResponseEnvelope {
                request_id: request.request_id,
                response: guest_error("denied", "control request payload digest mismatch"),
            };
            return write_frame(&mut stream, &response)
                .map_err(|error| format!("write control frame: {error}"));
        }
        match request.request.clone() {
            Request::Exec { spec } => {
                let started =
                    match runtime.start_exec(&request.request_id, &request.payload_digest, spec) {
                        Ok(started) => started,
                        Err(response) => {
                            return write_frame(
                                &mut stream,
                                &ResponseEnvelope {
                                    request_id: request.request_id,
                                    response,
                                },
                            )
                            .map_err(|error| format!("write exec error response: {error}"));
                        }
                    };
                if let Err(error) = write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::ExecStarted {
                            process_id: started.process_id.clone(),
                            pty: started.terminal,
                        },
                    },
                ) {
                    return Err(format!("write exec start response: {error}"));
                }
                return runtime.stream_process(stream, started.attachment);
            }
            Request::AttachProcess { process_id } => {
                let (attachment, terminal) = match runtime.attach_process(&process_id) {
                    Ok(attachment) => attachment,
                    Err(response) => {
                        return write_frame(
                            &mut stream,
                            &ResponseEnvelope {
                                request_id: request.request_id,
                                response,
                            },
                        )
                        .map_err(|error| format!("write process attachment error: {error}"));
                    }
                };
                write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::ProcessAttached { terminal },
                    },
                )
                .map_err(|error| format!("write process attachment response: {error}"))?;
                return runtime.stream_process(stream, attachment);
            }
            Request::PortForward { host, port } => {
                let target = match LoopbackTarget::new(host, port)
                    .map_err(|error| format!("validate port-forward target: {error}"))
                    .and_then(|target| {
                        runtime
                            .connect_port(target)
                            .map_err(|error| format!("connect boundary loopback port: {error}"))
                    }) {
                    Ok(target) => target,
                    Err(error) => {
                        write_frame(
                            &mut stream,
                            &ResponseEnvelope {
                                request_id: request.request_id,
                                response: guest_error("failed", error),
                            },
                        )
                        .map_err(|error| format!("write port-forward error response: {error}"))?;
                        return Ok(());
                    }
                };
                let mut target = target;
                write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::PortConnected,
                    },
                )
                .map_err(|error| format!("write port-forward response: {error}"))?;
                runtime.process_runtime.block_on(async move {
                    let mut stream = stream.into_tokio()?;
                    tokio::io::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .map_err(|error| format!("bridge boundary loopback stream: {error}"))
                })?;
                return Ok(());
            }
            Request::AcceptNetwork => {
                let broker = runtime.network_accept_context()?;
                let request_id = request.request_id;
                runtime.process_runtime.block_on(async move {
                    let mut stream = stream.into_tokio()?;
                    let mut disconnect_probe = [0_u8; 1];
                    let pending = tokio::select! {
                        biased;
                        read = stream.read(&mut disconnect_probe) => {
                            match read {
                                Ok(0) => return Ok(()),
                                Ok(_) => return Err("control sent data before network mediation response".to_string()),
                                Err(error) => return Err(format!("watch network mediation control stream: {error}")),
                            }
                        }
                        pending = broker.accept() => pending
                            .map_err(|error| format!("accept sandbox network open: {error}"))?,
                    };
                    let response = encode_frame(&ResponseEnvelope {
                        request_id,
                        response: Response::NetworkConnected {
                            identity: BinaryIdentityWire::from(pending.identity.clone()),
                            destination: pending.destination,
                            socket: pending.socket,
                            policy_generation: 0,
                        },
                    })
                    .map_err(|error| format!("encode network mediation response: {error}"))?;
                    stream
                        .write_all(&response)
                        .await
                        .map_err(|error| format!("write network mediation response: {error}"))?;
                    let Some((channel, payload)) = read_stream_frame(&mut stream)
                        .await
                        .map_err(|error| format!("read network-open decision: {error}"))?
                    else {
                        return Err("control disconnected before network-open decision".to_string());
                    };
                    if channel != STREAM_NETWORK_DECISION {
                        return Err(format!(
                            "unexpected network-open decision channel {channel}"
                        ));
                    }
                    let decision = serde_json::from_slice(&payload)
                        .map_err(|error| format!("decode network-open decision: {error}"))?;
                    let Some(target) = pending
                        .complete(decision)
                        .await
                        .map_err(|error| format!("complete sandbox network open: {error}"))?
                    else {
                        return Ok(());
                    };
                    target
                        .set_nonblocking(true)
                        .map_err(|error| format!("set sandbox relay nonblocking: {error}"))?;
                    let mut target = tokio::net::TcpStream::from_std(target)
                        .map_err(|error| format!("register sandbox relay: {error}"))?;
                    openshell_core::net::set_tcp_nodelay_best_effort(&target);
                    tokio::io::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .map(|_| ())
                        .map_err(|error| format!("bridge sandbox network stream: {error}"))
                })?;
                return Ok(());
            }
            Request::AcceptDns => {
                let broker = runtime.network_accept_context()?;
                let request_id = request.request_id;
                runtime.process_runtime.block_on(async move {
                    let mut stream = stream.into_tokio()?;
                    let mut disconnect_probe = [0_u8; 1];
                    let pending = tokio::select! {
                        biased;
                        read = stream.read(&mut disconnect_probe) => {
                            match read {
                                Ok(0) => return Ok(()),
                                Ok(_) => return Err("control sent data before DNS mediation response".to_string()),
                                Err(error) => return Err(format!("watch DNS mediation control stream: {error}")),
                            }
                        }
                        pending = broker.accept_dns() => pending
                            .map_err(|error| format!("accept sandbox DNS query: {error}"))?,
                    };
                    let response = encode_frame(&ResponseEnvelope {
                        request_id,
                        response: Response::DnsQuery {
                            request: pending.request.clone(),
                            transport: pending.transport,
                            identity: BinaryIdentityWire::from(pending.identity.clone()),
                        },
                    })
                    .map_err(|error| format!("encode DNS mediation response: {error}"))?;
                    stream
                        .write_all(&response)
                        .await
                        .map_err(|error| format!("write DNS mediation response: {error}"))?;
                    let Some((channel, payload)) = read_stream_frame(&mut stream)
                        .await
                        .map_err(|error| format!("read DNS mediation result: {error}"))?
                    else {
                        return Err("control disconnected before DNS response".to_string());
                    };
                    if channel != STREAM_DNS_RESPONSE {
                        return Err(format!("unexpected DNS response channel {channel}"));
                    }
                    let result: DnsQueryResultWire = serde_json::from_slice(&payload)
                        .map_err(|error| format!("decode DNS mediation result: {error}"))?;
                    let result = match result {
                        DnsQueryResultWire::Response(response) => Ok(response),
                        DnsQueryResultWire::Error(error) => Err(io::Error::other(error)),
                    };
                    pending
                        .complete(result)
                        .map_err(|error| format!("complete sandbox DNS query: {error}"))?;
                    write_stream_frame(&mut stream, STREAM_DNS_ACK, &[])
                        .await
                        .map_err(|error| format!("acknowledge sandbox DNS response: {error}"))
                })?;
                return Ok(());
            }
            _ => {}
        }
        let response = ResponseEnvelope {
            request_id: request.request_id.clone(),
            response: runtime.dispatch(request),
        };
        write_frame(&mut stream, &response)
            .map_err(|error| format!("write control frame: {error}"))?;
        Ok(())
    }

    struct BoundaryRuntime {
        config: BoundaryConfig,
        process_runtime: tokio::runtime::Handle,
        state: Mutex<RuntimeState>,
        /// The wire policy bound at first attach, so an idempotent attach retry
        /// carrying a different policy is denied instead of silently keeping
        /// the first policy.
        attached_policy: Mutex<Option<SandboxPolicyWire>>,
        /// The complete launch request accepted by the boundary. A replacement
        /// control process may replay it after reconnecting, but may not change
        /// any launch input or start a second workload.
        started_agent: Mutex<Option<StartedAgent>>,
        next_exec_id: AtomicU64,
        exec_handles: Mutex<std::collections::HashMap<String, ExecHandle>>,
        replay_ledger: Mutex<ReplayLedger>,
        network_broker: NetworkBroker,
        workload_launcher:
            openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
        qualification: crate::RuntimeQualification,
    }

    #[derive(Clone)]
    struct ExecHandle {
        request_id: String,
        payload_digest: String,
        process: Arc<dyn BoundaryProcess>,
        terminal: Option<Arc<dyn BoundaryTerminal>>,
        session: Arc<MainSession>,
        attached: Arc<AtomicBool>,
        status: Arc<Mutex<Option<ExitStatusWire>>>,
    }

    struct StartedExec {
        process_id: String,
        terminal: bool,
        attachment: MainAttachment,
    }

    #[derive(Clone)]
    struct ReplayRecord {
        payload_digest: String,
        response: Response,
    }

    #[derive(Default)]
    struct ReplayLedger {
        entries: std::collections::HashMap<String, ReplayRecord>,
        order: std::collections::VecDeque<String>,
    }

    impl ReplayLedger {
        fn get(&self, request_id: &str) -> Option<&ReplayRecord> {
            self.entries.get(request_id)
        }

        fn insert(&mut self, request_id: String, record: ReplayRecord) {
            if let Some(existing) = self.entries.get_mut(&request_id) {
                *existing = record;
                return;
            }
            while self.entries.len() >= MAX_REPLAY_LEDGER_ENTRIES {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
            self.order.push_back(request_id.clone());
            self.entries.insert(request_id, record);
        }
    }

    #[derive(Clone, PartialEq, Eq)]
    struct StartedAgent {
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: SandboxPolicyWire,
        ca_cert: Option<Vec<u8>>,
        ca_bundle: Option<Vec<u8>>,
        provider_env_revision: u64,
        provider_env: std::collections::HashMap<String, String>,
    }

    impl StartedAgent {
        /// Provider environment is mutable runtime state. A replacement
        /// control must replay every immutable launch input exactly, then
        /// reconcile the current provider snapshot through the CAS update.
        fn matches_replay(&self, other: &Self) -> bool {
            self.sandbox_id == other.sandbox_id
                && self.spec == other.spec
                && self.policy == other.policy
                && self.ca_cert == other.ca_cert
                && self.ca_bundle == other.ca_bundle
        }
    }

    struct MainAttachment {
        session: Arc<MainSession>,
        attached: Arc<AtomicBool>,
        status: AttachmentStatus,
    }

    enum AttachmentStatus {
        Main(Arc<ManagedProcess>),
        Exec(Arc<Mutex<Option<ExitStatusWire>>>),
    }

    impl MainAttachment {
        fn exit_status(&self, fallback_code: i32) -> ExitStatusWire {
            match &self.status {
                AttachmentStatus::Main(process) => process
                    .exit_status()
                    .unwrap_or(ExitStatusWire::Exited(fallback_code)),
                AttachmentStatus::Exec(status) => {
                    (*lock(status)).unwrap_or(ExitStatusWire::Exited(fallback_code))
                }
            }
        }
    }

    impl Drop for MainAttachment {
        fn drop(&mut self) {
            self.attached.store(false, Ordering::Release);
        }
    }

    #[allow(clippy::result_large_err)]
    fn acquire_exec_attachment(handle: &ExecHandle) -> Result<MainAttachment, Response> {
        acquire_attachment(
            handle.session.clone(),
            handle.attached.clone(),
            AttachmentStatus::Exec(handle.status.clone()),
        )
    }

    #[allow(clippy::result_large_err)]
    fn acquire_attachment(
        session: Arc<MainSession>,
        attached: Arc<AtomicBool>,
        status: AttachmentStatus,
    ) -> Result<MainAttachment, Response> {
        if attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(guest_error(
                "denied",
                "process already has a control attachment",
            ));
        }
        Ok(MainAttachment {
            session,
            attached,
            status,
        })
    }

    enum RuntimeState {
        AwaitingAttach,
        Bound(PreparedBoundary),
        Ready(PreparedBoundary),
        Running(Arc<ManagedProcess>),
    }

    #[derive(Clone)]
    struct PreparedBoundary {
        network_broker: NetworkBroker,
    }

    impl BoundaryRuntime {
        fn new(
            config: BoundaryConfig,
            process_runtime: tokio::runtime::Handle,
            network_broker: NetworkBroker,
            workload_launcher: openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
            qualification: crate::RuntimeQualification,
        ) -> Self {
            Self {
                config,
                process_runtime,
                state: Mutex::new(RuntimeState::AwaitingAttach),
                attached_policy: Mutex::new(None),
                started_agent: Mutex::new(None),
                next_exec_id: AtomicU64::new(1),
                exec_handles: Mutex::new(std::collections::HashMap::new()),
                replay_ledger: Mutex::new(ReplayLedger::default()),
                network_broker,
                workload_launcher,
                qualification,
            }
        }

        fn shutdown(&self) {
            let process = {
                let state = lock(&self.state);
                match &*state {
                    RuntimeState::Running(process) => Some(process.clone()),
                    RuntimeState::AwaitingAttach
                    | RuntimeState::Bound(_)
                    | RuntimeState::Ready(_) => None,
                }
            };
            if let Some(process) = process {
                process.boundary_runtime.deactivate();
            }
        }

        fn dispatch(&self, envelope: RequestEnvelope) -> Response {
            if !self.authenticate(&envelope) {
                return guest_error("denied", "control authentication failed");
            }
            if envelope.validate_payload_digest().is_err() {
                return guest_error("denied", "control request payload digest mismatch");
            }
            let replayable = envelope.request.is_replayable_mutation();
            let mut replay_ledger = replayable.then(|| lock(&self.replay_ledger));
            if let Some(record) = replay_ledger
                .as_ref()
                .and_then(|ledger| ledger.get(&envelope.request_id))
            {
                return if record.payload_digest == envelope.payload_digest {
                    record.response.clone()
                } else {
                    guest_error(
                        "denied",
                        "control request ID was reused with a different payload",
                    )
                };
            }
            let request_id = envelope.request_id;
            let payload_digest = envelope.payload_digest;
            let response = match envelope.request {
                Request::Attach {
                    policy,
                    resource_claims,
                } => {
                    if resource_claims == self.config.resource_claims {
                        self.attach(*policy)
                    } else {
                        guest_error(
                            "denied",
                            "topology resource claims do not match the boundary configuration",
                        )
                    }
                }
                Request::Confirm => self.confirm(),
                Request::StartAgent {
                    sandbox_id,
                    spec,
                    policy,
                    ca_cert,
                    ca_bundle,
                    provider_env_revision,
                    provider_env,
                } => self.start_agent(
                    sandbox_id,
                    spec,
                    *policy,
                    ca_cert,
                    ca_bundle,
                    provider_env_revision,
                    provider_env,
                ),
                Request::UpdateProviderEnvironment {
                    expected_revision,
                    revision,
                    provider_env,
                } => self.update_provider_environment(expected_revision, revision, provider_env),
                Request::Wait { process_id } => self.wait(&process_id),
                Request::Signal { process_id, signal } => self.signal(&process_id, signal),
                Request::Terminate { process_id } => self.terminate(&process_id),
                Request::ExecSignal { process_id, signal } => self.signal_exec(&process_id, signal),
                Request::Resize {
                    process_id,
                    cols,
                    rows,
                } => self.resize_process(&process_id, cols, rows),
                Request::Exec { .. }
                | Request::AttachProcess { .. }
                | Request::PortForward { .. }
                | Request::AcceptNetwork
                | Request::AcceptDns => {
                    guest_error("invalid", "streaming request used on control path")
                }
            };
            if let Some(ledger) = replay_ledger.as_mut() {
                ledger.insert(
                    request_id,
                    ReplayRecord {
                        payload_digest,
                        response: response.clone(),
                    },
                );
            }
            response
        }

        fn authenticate(&self, envelope: &RequestEnvelope) -> bool {
            constant_time_eq(
                envelope.boundary_id.as_bytes(),
                self.config.boundary_id.as_bytes(),
            ) && constant_time_eq(
                envelope.bootstrap_token.as_bytes(),
                self.config.bootstrap_token.as_bytes(),
            )
        }

        #[allow(
            clippy::result_large_err,
            reason = "protocol errors are returned directly as complete response frames"
        )]
        fn start_exec(
            &self,
            request_id: &str,
            payload_digest: &str,
            spec: ExecSpecWire,
        ) -> Result<StartedExec, Response> {
            let executor = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err(guest_error("invalid", "agent process has not been started"));
                };
                process.boundary_exec()
            };
            let mut handles = lock(&self.exec_handles);
            if let Some((process_id, handle)) = handles
                .iter()
                .find(|(_, handle)| handle.request_id == request_id)
            {
                if handle.payload_digest != payload_digest {
                    return Err(guest_error(
                        "denied",
                        "exec request ID was reused with a different payload",
                    ));
                }
                if handle.attached.load(Ordering::Acquire) {
                    return Err(guest_error(
                        "unavailable",
                        "prior exec attachment is still being released",
                    ));
                }
                return Ok(StartedExec {
                    process_id: process_id.clone(),
                    terminal: handle.terminal.is_some(),
                    attachment: acquire_exec_attachment(handle)?,
                });
            }
            if handles.len() >= MAX_RETAINED_EXEC_PROCESSES {
                let exited = handles
                    .iter()
                    .find(|(_, handle)| {
                        lock(&handle.status).is_some() && !handle.attached.load(Ordering::Acquire)
                    })
                    .map(|(process_id, _)| process_id.clone());
                if let Some(process_id) = exited {
                    handles.remove(&process_id);
                } else {
                    return Err(guest_error(
                        "unavailable",
                        "retained exec process limit reached",
                    ));
                }
            }
            let session = self
                .process_runtime
                .block_on(executor.exec(spec.into()))
                .map_err(|error| guest_error("failed", error.to_string()))?;
            let process_id = format!(
                "{}:exec:{}",
                self.config.generation,
                self.next_exec_id.fetch_add(1, Ordering::Relaxed)
            );
            let ExecSession {
                process,
                stdin,
                stdout,
                stderr,
                terminal,
            } = session;
            let Some(stdin) = stdin else {
                return Err(guest_error(
                    "failed",
                    "exec process stdin pipe is unavailable",
                ));
            };
            let retained = {
                let _runtime = self.process_runtime.enter();
                MainSession::from_boundary(
                    openshell_isolation_interface::contract::ProcessAttachment {
                        stdin,
                        stdout,
                        stderr,
                        terminal: terminal.clone(),
                    },
                    process.clone(),
                )
            };
            let status = Arc::new(Mutex::new(None));
            let wait_process = process.clone();
            let wait_session = retained.clone();
            let wait_status = status.clone();
            self.process_runtime.spawn(async move {
                if let Ok(exit_status) = wait_process.wait().await {
                    *lock(&wait_status) = Some(ExitStatusWire::from(exit_status));
                    let exit_code = match exit_status {
                        openshell_isolation_interface::contract::BoundaryExitStatus::Exited(
                            code,
                        ) => code,
                        openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(
                            signal,
                        ) => 128 + signal,
                    };
                    let _ = wait_session.finish_remote(exit_code, false).await;
                }
            });
            let handle = ExecHandle {
                request_id: request_id.to_string(),
                payload_digest: payload_digest.to_string(),
                process,
                terminal,
                session: retained,
                attached: Arc::new(AtomicBool::new(false)),
                status,
            };
            let terminal = handle.terminal.is_some();
            let attachment = acquire_exec_attachment(&handle)?;
            handles.insert(process_id.clone(), handle);
            Ok(StartedExec {
                process_id,
                terminal,
                attachment,
            })
        }

        fn signal_exec(&self, process_id: &str, signal: SignalWire) -> Response {
            let process = lock(&self.exec_handles)
                .get(process_id)
                .map(|handle| handle.process.clone());
            let Some(process) = process else {
                return guest_error("invalid", "unknown exec process ID");
            };
            match self.process_runtime.block_on(process.signal(signal.into())) {
                Ok(()) => Response::Signaled,
                Err(error) => guest_error("failed", error.to_string()),
            }
        }

        fn resize_process(&self, process_id: &str, cols: u16, rows: u16) -> Response {
            if let Ok(process) = self.running_process(process_id) {
                let session = process.main_session();
                if !session.terminal() {
                    return guest_error("invalid", "agent process has no terminal");
                }
                self.process_runtime.block_on(session.resize(
                    u32::from(cols),
                    u32::from(rows),
                    0,
                    0,
                ));
                return Response::Resized;
            }
            let terminal = lock(&self.exec_handles)
                .get(process_id)
                .and_then(|handle| handle.terminal.clone());
            let Some(terminal) = terminal else {
                return guest_error("invalid", "exec process has no terminal");
            };
            match self.process_runtime.block_on(terminal.resize(cols, rows)) {
                Ok(()) => Response::Resized,
                Err(error) => guest_error("failed", error.to_string()),
            }
        }

        fn connect_port(
            &self,
            target: LoopbackTarget,
        ) -> Result<openshell_isolation_interface::contract::BoundaryDuplexStream, String> {
            let port_forward = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err("agent process has not been started".to_string());
                };
                process.port_forward()
            };
            self.process_runtime
                .block_on(port_forward.connect(target))
                .map_err(|error| error.to_string())
        }

        fn network_accept_context(&self) -> Result<NetworkBroker, String> {
            self.network_broker
                .confirm_healthy()
                .map_err(|error| format!("sandbox network broker unavailable: {error}"))?;
            Ok(self.network_broker.clone())
        }

        #[allow(
            clippy::result_large_err,
            reason = "protocol errors are returned directly as complete response frames"
        )]
        fn attach_process(&self, process_id: &str) -> Result<(MainAttachment, bool), Response> {
            if let Ok(process) = self.running_process(process_id) {
                let session = process.main_session();
                let terminal = session.terminal();
                let attachment = acquire_attachment(
                    session,
                    process.attached.clone(),
                    AttachmentStatus::Main(process),
                )?;
                return Ok((attachment, terminal));
            }
            let handles = lock(&self.exec_handles);
            let handle = handles
                .get(process_id)
                .ok_or_else(|| guest_error("invalid", "unknown process ID"))?;
            Ok((acquire_exec_attachment(handle)?, handle.terminal.is_some()))
        }

        fn stream_process(
            &self,
            stream: ControlStream,
            attachment: MainAttachment,
        ) -> Result<(), String> {
            self.process_runtime.block_on(async move {
                let stream = stream.into_tokio()?;
                bridge_main_stream(stream, attachment).await
            })
        }

        fn attach(&self, policy: SandboxPolicyWire) -> Response {
            let mut state = lock(&self.state);
            let accepted = match &*state {
                RuntimeState::AwaitingAttach => {
                    let prepared = match PreparedBoundary::establish(self.network_broker.clone()) {
                        Ok(prepared) => prepared,
                        Err(error) => return guest_error("failed", error),
                    };
                    *lock(&self.attached_policy) = Some(policy);
                    *state = RuntimeState::Bound(prepared);
                    true
                }
                RuntimeState::Bound(_) | RuntimeState::Ready(_) | RuntimeState::Running(_) => {
                    // Idempotent retry of the same attach; a different policy
                    // must not be silently coalesced onto the bound boundary.
                    lock(&self.attached_policy).as_ref() == Some(&policy)
                }
            };
            drop(state);
            if accepted {
                Response::Attached {
                    snapshot: self.session_snapshot(),
                }
            } else {
                guest_error("denied", "attach policy does not match the bound boundary")
            }
        }

        fn session_snapshot(&self) -> SessionSnapshotWire {
            let process = {
                let state = lock(&self.state);
                match &*state {
                    RuntimeState::Running(process) => Some(process.clone()),
                    RuntimeState::AwaitingAttach
                    | RuntimeState::Bound(_)
                    | RuntimeState::Ready(_) => None,
                }
            };
            let mut processes = process
                .into_iter()
                .map(|process| {
                    let (first_sequence, next_sequence, truncated) =
                        process.main_session().output_window();
                    ProcessSnapshotWire {
                        process_id: process.process_id(),
                        kind: ProcessKindWire::Main,
                        terminal: process.main_session().terminal(),
                        status: process.exit_status(),
                        retained_output: OutputWindowWire {
                            first_sequence,
                            next_sequence,
                            truncated,
                        },
                    }
                })
                .collect::<Vec<_>>();
            processes.extend(lock(&self.exec_handles).iter().map(|(process_id, handle)| {
                let (first_sequence, next_sequence, truncated) = handle.session.output_window();
                ProcessSnapshotWire {
                    process_id: process_id.clone(),
                    kind: ProcessKindWire::Exec,
                    terminal: handle.terminal.is_some(),
                    status: *lock(&handle.status),
                    retained_output: OutputWindowWire {
                        first_sequence,
                        next_sequence,
                        truncated,
                    },
                }
            }));
            processes.sort_by(|left, right| left.process_id.cmp(&right.process_id));
            SessionSnapshotWire {
                generation: self.config.generation.clone(),
                processes,
            }
        }

        fn confirm(&self) -> Response {
            let mut state = lock(&self.state);
            match &*state {
                RuntimeState::Bound(prepared) => {
                    if let Err(error) = prepared.confirm(&self.process_runtime) {
                        return guest_error("failed", error);
                    }
                    let evidence = match self.measure_confirmation_evidence() {
                        Ok(evidence) => evidence,
                        Err(error) => return guest_error("failed", error),
                    };
                    *state = RuntimeState::Ready(prepared.clone());
                    Response::Confirmed {
                        evidence: Box::new(evidence),
                    }
                }
                RuntimeState::Ready(_) | RuntimeState::Running(_) => {
                    self.measure_confirmation_evidence().map_or_else(
                        |error| guest_error("failed", error),
                        |evidence| Response::Confirmed {
                            evidence: Box::new(evidence),
                        },
                    )
                }
                RuntimeState::AwaitingAttach => {
                    guest_error("invalid", "boundary must be attached before confirm")
                }
            }
        }

        fn measure_confirmation_evidence(&self) -> Result<SandboxConfirmEvidence, String> {
            validate_running_identity(&self.config.workload_identity)?;
            self.network_broker
                .confirm_healthy()
                .map_err(|error| format!("verify sandbox network broker: {error}"))?;
            if !self.workload_launcher.is_alive() {
                return Err("sandbox workload launcher is not running".to_string());
            }
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|error| format!("read sandbox process status: {error}"))?;
            let capabilities = CapabilityEvidence {
                inheritable: parse_status_hex(&status, "CapInh")?,
                permitted: parse_status_hex(&status, "CapPrm")?,
                effective: parse_status_hex(&status, "CapEff")?,
                bounding: parse_status_hex(&status, "CapBnd")?,
                ambient: parse_status_hex(&status, "CapAmb")?,
            };
            let no_new_privileges = parse_status_decimal(&status, "NoNewPrivs")? == 1;
            // SAFETY: PR_GET_DUMPABLE reads one scalar process property.
            let sandbox_dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
            let mut core_limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            // SAFETY: getrlimit initializes the supplied output value on success.
            if unsafe { libc::getrlimit(libc::RLIMIT_CORE, core_limit.as_mut_ptr()) } != 0 {
                return Err(format!(
                    "read sandbox core limit: {}",
                    io::Error::last_os_error()
                ));
            }
            // SAFETY: successful getrlimit initialized the value.
            let core_limit = unsafe { core_limit.assume_init() };
            let (native_architecture, kernel_release) = uname_values()?;
            Ok(SandboxConfirmEvidence {
                generation: self.config.generation.clone(),
                identity: self.config.workload_identity.clone(),
                capabilities,
                no_new_privileges,
                sandbox_dumpable,
                child_dumpable: true,
                core_limit_zero: core_limit.rlim_cur == 0 && core_limit.rlim_max == 0,
                native_architecture,
                kernel_release,
                seccomp: self.qualification.seccomp,
                landlock_abi: self.qualification.landlock_abi,
                landlock_allow_deny: self.qualification.landlock_allow_deny,
                udp_dns_round_trip: self.qualification.udp_dns_round_trip,
                tcp_dns_round_trip: self.qualification.tcp_dns_round_trip,
                tcp_allow_round_trip: self.qualification.tcp_allow_round_trip,
                tcp_deny_round_trip: self.qualification.tcp_deny_round_trip,
                authenticated_supervisor: true,
                session_epoch: self.config.session_epoch.clone(),
                driver_fence: self.config.driver_fence.clone(),
                resource_claims: self.config.resource_claims.clone(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn start_agent(
            &self,
            sandbox_id: String,
            spec: AgentSpecWire,
            policy: SandboxPolicyWire,
            ca_cert: Option<Vec<u8>>,
            ca_bundle: Option<Vec<u8>>,
            provider_env_revision: u64,
            provider_env: std::collections::HashMap<String, String>,
        ) -> Response {
            let spec = match resolve_agent_spec(spec) {
                Ok(spec) => spec,
                Err(error) => return guest_error("failed", error),
            };
            let mut state = lock(&self.state);
            let requested = StartedAgent {
                sandbox_id: sandbox_id.clone(),
                spec: spec.clone(),
                policy: policy.clone(),
                ca_cert: ca_cert.clone(),
                ca_bundle: ca_bundle.clone(),
                provider_env_revision,
                provider_env: provider_env.clone(),
            };
            if let RuntimeState::Running(process) = &*state {
                return if lock(&self.started_agent)
                    .as_ref()
                    .is_some_and(|accepted| accepted.matches_replay(&requested))
                {
                    Response::Started {
                        process_id: process.process_id(),
                        provider_env_revision: process.provider_credentials.snapshot().revision,
                    }
                } else {
                    guest_error(
                        "denied",
                        "start_agent inputs do not match the running boundary",
                    )
                };
            }
            let RuntimeState::Ready(prepared) = &*state else {
                return guest_error("invalid", "boundary must be confirmed before start_agent");
            };
            let ca_file_paths = match install_ca_material(ca_cert, ca_bundle) {
                Ok(paths) => paths,
                Err(error) => return guest_error("failed", error),
            };
            let mut policy = policy.into();
            let driver_identity = DriverIdentity::Resolved {
                uid: self.config.workload_identity.uid,
                gid: self.config.workload_identity.gid,
            };
            if let Err(error) = resolve_process_identity(&mut policy, &driver_identity) {
                return guest_error("failed", error.to_string());
            }
            let launch = ManagedProcessLaunch {
                process_id: format!("{}:main:0", self.config.generation),
                sandbox_id,
                spec,
                policy,
                provider_env_revision,
                provider_env,
                ca_file_paths,
            };
            let process =
                match ManagedProcess::spawn(&self.process_runtime, launch, prepared.clone()) {
                    Ok(process) => Arc::new(process),
                    Err(error) => return guest_error("failed", error),
                };
            let process_id = process.process_id();
            *lock(&self.started_agent) = Some(requested);
            *state = RuntimeState::Running(process);
            Response::Started {
                process_id,
                provider_env_revision,
            }
        }

        fn update_provider_environment(
            &self,
            expected_revision: u64,
            revision: u64,
            provider_env: std::collections::HashMap<String, String>,
        ) -> Response {
            let process = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return guest_error(
                        "invalid",
                        "agent process must be running before provider environment updates",
                    );
                };
                process.clone()
            };
            let revision = process
                .provider_credentials
                .compare_and_install_child_env_snapshot(expected_revision, revision, provider_env);
            Response::ProviderEnvironmentUpdated { revision }
        }

        fn wait(&self, process_id: &str) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.wait() {
                Ok(status) => Response::Exited { status },
                Err(error) => guest_error("failed", error),
            }
        }

        fn signal(&self, process_id: &str, signal: SignalWire) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.signal(signal) {
                Ok(()) => Response::Signaled,
                Err(error) => guest_error("terminated", error),
            }
        }

        fn terminate(&self, process_id: &str) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.signal(SignalWire::Kill) {
                Ok(()) => Response::Terminated,
                Err(_) if process.has_exited() => Response::Terminated,
                Err(error) => guest_error("failed", error),
            }
        }

        #[allow(
            clippy::result_large_err,
            reason = "protocol errors are returned directly as complete response frames"
        )]
        fn running_process(&self, process_id: &str) -> Result<Arc<ManagedProcess>, Response> {
            let state = lock(&self.state);
            let RuntimeState::Running(process) = &*state else {
                return Err(guest_error("invalid", "agent process has not been started"));
            };
            if process.process_id() != process_id {
                return Err(guest_error("invalid", "unknown process ID"));
            }
            Ok(process.clone())
        }
    }

    fn parse_status_hex(status: &str, name: &str) -> Result<u64, String> {
        let value = status
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|value| value.strip_prefix(':'))
            })
            .map(str::trim)
            .ok_or_else(|| format!("sandbox process status omitted {name}"))?;
        u64::from_str_radix(value, 16)
            .map_err(|error| format!("parse sandbox process status {name}: {error}"))
    }

    fn parse_status_decimal(status: &str, name: &str) -> Result<u64, String> {
        let value = status
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|value| value.strip_prefix(':'))
            })
            .map(str::trim)
            .ok_or_else(|| format!("sandbox process status omitted {name}"))?;
        value
            .parse::<u64>()
            .map_err(|error| format!("parse sandbox process status {name}: {error}"))
    }

    fn uname_values() -> Result<(String, String), String> {
        let mut value = std::mem::MaybeUninit::<libc::utsname>::zeroed();
        // SAFETY: uname initializes the supplied utsname value on success.
        if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
            return Err(format!(
                "measure sandbox kernel: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: successful uname initialized every fixed-size C string.
        let value = unsafe { value.assume_init() };
        Ok((c_char_array(&value.machine), c_char_array(&value.release)))
    }

    fn c_char_array(value: &[libc::c_char]) -> String {
        let length = value
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value.len());
        let bytes = value[..length]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    impl PreparedBoundary {
        fn establish(network_broker: NetworkBroker) -> Result<Self, String> {
            network_broker
                .confirm_healthy()
                .map_err(|error| format!("verify sandbox network broker: {error}"))?;
            Ok(Self { network_broker })
        }

        fn confirm(&self, _runtime: &tokio::runtime::Handle) -> Result<(), String> {
            self.network_broker
                .confirm_healthy()
                .map_err(|error| format!("verify sandbox network broker: {error}"))
        }
    }

    fn install_ca_material(
        ca_cert: Option<Vec<u8>>,
        ca_bundle: Option<Vec<u8>>,
    ) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String> {
        let (ca_cert, ca_bundle) = match (ca_cert, ca_bundle) {
            (Some(ca_cert), Some(ca_bundle)) => (ca_cert, ca_bundle),
            (None, None) => return Ok(None),
            _ => {
                return Err(
                    "boundary proxy CA certificate and bundle must be supplied together"
                        .to_string(),
                );
            }
        };
        install_ca_material_at(Path::new("/run/openshell-proxy-ca"), &ca_cert, &ca_bundle)
    }

    fn install_ca_material_at(
        directory: &Path,
        ca_cert: &[u8],
        ca_bundle: &[u8],
    ) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let parent = directory
            .parent()
            .ok_or_else(|| "boundary proxy CA directory has no parent".to_string())?;
        for path in [parent, directory] {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "boundary proxy CA directory component is a symlink: {}",
                        path.display()
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(format!(
                        "boundary proxy CA directory component is not a directory: {}",
                        path.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::create_dir(path).map_err(|error| {
                        format!(
                            "create boundary proxy CA directory {}: {error}",
                            path.display()
                        )
                    })?;
                }
                Err(error) => {
                    return Err(format!(
                        "inspect boundary proxy CA directory {}: {error}",
                        path.display()
                    ));
                }
            }
            let current_mode = std::fs::metadata(path)
                .map_err(|error| {
                    format!(
                        "inspect boundary proxy CA directory permissions {}: {error}",
                        path.display()
                    )
                })?
                .permissions()
                .mode();
            if path == directory {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(
                    |error| {
                        format!(
                            "set boundary proxy CA directory permissions {}: {error}",
                            path.display()
                        )
                    },
                )?;
            } else if current_mode & 0o111 != 0o111 {
                return Err(format!(
                    "boundary proxy CA parent is not traversable by workload identities: {}",
                    path.display()
                ));
            }
        }
        let ca_path = directory.join("ca.crt");
        let bundle_path = directory.join("ca-bundle.crt");
        for (path, contents, label) in [
            (&ca_path, ca_cert, "boundary proxy CA"),
            (&bundle_path, ca_bundle, "boundary proxy CA bundle"),
        ] {
            let temporary = path.with_extension("tmp");
            if let Ok(metadata) = std::fs::symlink_metadata(&temporary) {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(format!(
                        "refusing unsafe temporary {label} path: {}",
                        temporary.display()
                    ));
                }
                std::fs::remove_file(&temporary)
                    .map_err(|error| format!("remove stale temporary {label}: {error}"))?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|error| format!("create temporary {label}: {error}"))?;
            if let Err(error) = file
                .write_all(contents)
                .and_then(|()| file.sync_all())
                .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(0o444)))
                .and_then(|()| std::fs::rename(&temporary, path))
            {
                let _ = std::fs::remove_file(&temporary);
                return Err(format!("install {label}: {error}"));
            }
        }
        Ok(Some((ca_path, bundle_path)))
    }

    type ProcessExit = Result<ExitStatusWire, String>;
    type SharedProcessExit = Arc<(Mutex<Option<ProcessExit>>, Condvar)>;

    struct ManagedProcess {
        process_id: String,
        signaler: AgentSignaler,
        exit: SharedProcessExit,
        boundary_exec: Arc<dyn BoundaryExec>,
        port_forward: Arc<dyn BoundaryPortForward>,
        main_session: Arc<MainSession>,
        attached: Arc<AtomicBool>,
        boundary_runtime: Arc<BoundaryRuntimeState>,
        provider_credentials: ProviderCredentialState,
    }

    struct ManagedProcessLaunch {
        process_id: String,
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: openshell_core::policy::SandboxPolicy,
        provider_env_revision: u64,
        provider_env: std::collections::HashMap<String, String>,
        ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    }

    fn resolve_agent_spec(mut spec: AgentSpecWire) -> Result<AgentSpecWire, String> {
        if !spec.program.is_empty() {
            return Ok(spec);
        }
        if !spec.args.is_empty() {
            return Err("default agent command cannot include arguments".to_string());
        }
        let shell = openshell_core::shell::detect_login_shell();
        if !openshell_core::shell::is_executable(&shell) {
            return Err(format!(
                "sandbox image does not provide an executable login shell at {shell}"
            ));
        }
        spec.program = shell;
        spec.args = vec!["-l".to_string()];
        Ok(spec)
    }

    impl ManagedProcess {
        fn spawn(
            runtime: &tokio::runtime::Handle,
            launch: ManagedProcessLaunch,
            _prepared: PreparedBoundary,
        ) -> Result<Self, String> {
            let ManagedProcessLaunch {
                process_id,
                sandbox_id,
                spec,
                policy,
                provider_env_revision,
                provider_env,
                ca_file_paths,
            } = launch;
            debug_assert!(!spec.program.is_empty());
            let boundary_runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();
            let entrypoint_pid = Arc::new(AtomicU32::new(0));
            let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
                provider_env_revision,
                provider_env.clone(),
            );
            let mut spawned = runtime
                .block_on(spawn_workload(
                    &spec.program,
                    &spec.args,
                    spec.workdir.as_deref(),
                    spec.timeout_secs,
                    spec.interactive,
                    Some(&sandbox_id),
                    None,
                    None,
                    false,
                    &policy,
                    entrypoint_pid,
                    None,
                    provider_credentials.clone(),
                    provider_env,
                    ca_file_paths,
                    Some(boundary_runtime.clone()),
                ))
                .map_err(|error| format!("start process supervisor leaf: {error:?}"))?;
            let signaler = spawned.signaler();
            let boundary_exec = spawned.boundary_exec();
            let port_forward = spawned.port_forward();
            let main_session = spawned.main_session();
            let exit = Arc::new((Mutex::new(None), Condvar::new()));
            let reaper_exit = exit.clone();
            runtime.spawn(async move {
                let result = spawned
                    .wait()
                    .await
                    .map(process_status)
                    .map_err(|error| format!("wait for process supervisor leaf: {error}"));
                let (state, changed) = &*reaper_exit;
                *lock(state) = Some(result);
                changed.notify_all();
            });
            Ok(Self {
                process_id,
                signaler,
                exit,
                boundary_exec,
                port_forward,
                main_session,
                attached: Arc::new(AtomicBool::new(false)),
                boundary_runtime,
                provider_credentials,
            })
        }

        fn process_id(&self) -> String {
            self.process_id.clone()
        }

        fn wait(&self) -> ProcessExit {
            let (state, changed) = &*self.exit;
            let mut exit = lock(state);
            while exit.is_none() {
                exit = changed
                    .wait(exit)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            exit.as_ref().expect("exit checked above").clone()
        }

        fn signal(&self, signal: SignalWire) -> Result<(), String> {
            if self.has_exited() {
                return Err("agent process has already exited".to_string());
            }
            let result = match signal {
                SignalWire::Term => self.signaler.term(),
                SignalWire::Kill => self.signaler.kill(),
                SignalWire::Int => self.signaler.interrupt(),
                SignalWire::Hup => self.signaler.hangup(),
            };
            result.map_err(|error| format!("signal process supervisor group: {error}"))
        }

        fn has_exited(&self) -> bool {
            let (state, _) = &*self.exit;
            lock(state).is_some()
        }

        fn exit_status(&self) -> Option<ExitStatusWire> {
            let (state, _) = &*self.exit;
            lock(state).as_ref().and_then(|result| result.clone().ok())
        }

        fn boundary_exec(&self) -> Arc<dyn BoundaryExec> {
            self.boundary_exec.clone()
        }

        fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
            self.port_forward.clone()
        }

        fn main_session(&self) -> Arc<MainSession> {
            self.main_session.clone()
        }
    }

    impl Drop for ManagedProcess {
        fn drop(&mut self) {
            self.boundary_runtime.deactivate();
        }
    }

    async fn bridge_main_stream(
        stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
        attachment: MainAttachment,
    ) -> Result<(), String> {
        let session = attachment.session.clone();
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let input = session.acquire_input_if_open().map_err(str::to_string)?;
        let owner = input.as_ref().map(|(owner, _)| *owner);
        let mut output = session.subscribe();
        let input_session = session.clone();
        let mut input_task = tokio::spawn(async move {
            let mut input = input.map(|(_, input)| input);
            while let Some((channel, payload)) = read_stream_frame(&mut reader).await? {
                match channel {
                    STREAM_STDIN => {
                        let Some(input) = input.as_ref() else {
                            return Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "main process stdin already closed",
                            ));
                        };
                        input.send(payload).await.map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "main process stdin closed")
                        })?;
                    }
                    // Keep reading after stdin closes so transport EOF still
                    // releases this control process's attachment lease.
                    STREAM_STDIN_CLOSED => {
                        input.take();
                        if let Some(owner) = owner {
                            input_session.close_input(owner).await;
                        }
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected host-to-boundary main stream channel",
                        ));
                    }
                }
            }
            Ok::<(), io::Error>(())
        });
        let result = loop {
            let output_message = tokio::select! {
                input_result = &mut input_task => {
                    break match input_result {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => Err(format!("read main process attachment: {error}")),
                        Err(error) => Err(format!("join main process input stream: {error}")),
                    };
                }
                output_message = output.recv() => output_message,
            };
            let (channel, payload) = match output_message {
                Ok(MainOutput::Stdout(payload)) => (STREAM_STDOUT, payload.to_vec()),
                Ok(MainOutput::Stderr(payload)) => (STREAM_STDERR, payload.to_vec()),
                Ok(MainOutput::Exit(code)) => {
                    let status = serde_json::to_vec(&attachment.exit_status(code))
                        .map_err(|error| format!("encode main process exit: {error}"))?;
                    break write_stream_frame(&mut *writer.lock().await, STREAM_EXIT, &status)
                        .await
                        .map_err(|error| format!("write main process exit: {error}"));
                }
                Err(error) => {
                    tracing::warn!(
                        skipped_chunks = error.skipped,
                        "main process attachment resumed after dropping retained output"
                    );
                    continue;
                }
            };
            if let Err(error) =
                write_stream_frame(&mut *writer.lock().await, channel, &payload).await
            {
                break Err(format!("write main process output: {error}"));
            }
        };
        input_task.abort();
        if let Some(owner) = owner {
            session.release_input(owner);
        }
        result
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn process_status(status: ProcessStatus) -> ExitStatusWire {
        status.signal().map_or_else(
            || ExitStatusWire::Exited(status.code()),
            ExitStatusWire::Signaled,
        )
    }

    fn guest_error(kind: &str, message: impl Into<String>) -> Response {
        Response::Error {
            kind: kind.to_string(),
            message: message.into(),
        }
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        let max_len = left.len().max(right.len());
        let mut difference = left.len() ^ right.len();
        for index in 0..max_len {
            let left_byte = left.get(index).copied().unwrap_or_default();
            let right_byte = right.get(index).copied().unwrap_or_default();
            difference |= usize::from(left_byte ^ right_byte);
        }
        difference == 0
    }

    enum ControlListener {
        Vsock {
            listener: OwnedFd,
            server_config: Arc<rustls::ServerConfig>,
        },
        Unix {
            listener: std::os::unix::net::UnixListener,
            server_config: Arc<rustls::ServerConfig>,
        },
        Tcp {
            listener: std::net::TcpListener,
            server_config: Arc<rustls::ServerConfig>,
        },
    }

    impl ControlListener {
        fn bind(config: &BoundaryListenerConfig) -> io::Result<Self> {
            match config {
                BoundaryListenerConfig::Vsock { control_port, tls } => {
                    let listener = Self::bind_vsock(*control_port)?;
                    let server_config = Arc::new(load_tls_server_config(tls)?);
                    Ok(Self::Vsock {
                        listener,
                        server_config,
                    })
                }
                BoundaryListenerConfig::Unix { socket_path, tls } => {
                    remove_owned_stale_control_socket(socket_path)?;
                    let listener = std::os::unix::net::UnixListener::bind(socket_path)?;
                    // Mutual TLS makes a same-UID pathname replacement a
                    // detectable denial of service rather than impersonation.
                    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))?;
                    listener.set_nonblocking(true)?;
                    let server_config = Arc::new(load_tls_server_config(tls)?);
                    Ok(Self::Unix {
                        listener,
                        server_config,
                    })
                }
                BoundaryListenerConfig::TlsTcp { address, tls } => {
                    let listener = std::net::TcpListener::bind(address)?;
                    listener.set_nonblocking(true)?;
                    let server_config = Arc::new(load_tls_server_config(tls)?);
                    Ok(Self::Tcp {
                        listener,
                        server_config,
                    })
                }
            }
        }

        fn bind_vsock(port: u32) -> io::Result<OwnedFd> {
            let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AF_VSOCK exceeds sa_family_t")
            })?;
            let address_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "sockaddr_vm exceeds socklen_t")
                })?;
            let raw_fd = unsafe {
                libc::socket(
                    libc::AF_VSOCK,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                )
            };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let address = libc::sockaddr_vm {
                svm_family: family,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };
            let result = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    address_length,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::listen(fd.as_raw_fd(), 16) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(fd)
        }

        #[cfg(test)]
        fn tcp_local_addr(&self) -> io::Result<std::net::SocketAddr> {
            match self {
                Self::Tcp { listener, .. } => listener.local_addr(),
                Self::Unix { .. } | Self::Vsock { .. } => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "control listener is not TCP",
                )),
            }
        }

        fn accept(&self) -> io::Result<ControlStream> {
            match self {
                Self::Vsock {
                    listener,
                    server_config,
                } => {
                    let raw_fd = unsafe {
                        libc::accept4(
                            listener.as_raw_fd(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            libc::SOCK_CLOEXEC,
                        )
                    };
                    if raw_fd < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ControlStream::PendingTls {
                            stream: PlainControlStream::Vsock(unsafe { File::from_raw_fd(raw_fd) }),
                            server_config: server_config.clone(),
                        })
                    }
                }
                Self::Unix {
                    listener,
                    server_config,
                } => {
                    let (stream, _) = listener.accept()?;
                    Ok(ControlStream::PendingTls {
                        stream: PlainControlStream::Unix(stream),
                        server_config: server_config.clone(),
                    })
                }
                Self::Tcp {
                    listener,
                    server_config,
                } => {
                    let (stream, _) = listener.accept()?;
                    if let Err(error) = stream.set_nodelay(true) {
                        tracing::debug!(%error, "Failed to set boundary TCP_NODELAY");
                    }
                    Ok(ControlStream::PendingTls {
                        stream: PlainControlStream::Tcp(stream),
                        server_config: server_config.clone(),
                    })
                }
            }
        }
    }

    fn remove_owned_stale_control_socket(socket_path: &Path) -> io::Result<()> {
        let metadata = match std::fs::symlink_metadata(socket_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to replace non-socket boundary control path {}",
                    socket_path.display()
                ),
            ));
        }
        // The private channel directory is driver-provisioned. Requiring the
        // stale inode to have been created by this exact sandbox identity
        // prevents a replacement run from unlinking another principal's path.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to replace boundary control socket {} owned by UID {}",
                    socket_path.display(),
                    metadata.uid()
                ),
            ));
        }
        std::fs::remove_file(socket_path)
    }

    fn load_tls_server_config(
        tls: &openshell_isolation_interface::boundary_protocol::BoundaryServerTls,
    ) -> io::Result<rustls::ServerConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate_bytes = std::fs::read(&tls.certificate_chain_path)?;
        let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "boundary TLS certificate chain contains no certificates",
            ));
        }
        let private_key_bytes = std::fs::read(&tls.private_key_path)?;
        let private_key = rustls_pemfile::private_key(&mut private_key_bytes.as_slice())?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "boundary TLS private-key file contains no private key",
                )
            })?;
        let client_ca_bytes = std::fs::read(&tls.client_ca_certificate_path)?;
        let client_ca_certificates = rustls_pemfile::certs(&mut client_ca_bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()?;
        if client_ca_certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "boundary TLS client CA contains no certificates",
            ));
        }
        let mut client_roots = rustls::RootCertStore::empty();
        for certificate in client_ca_certificates {
            client_roots
                .add(certificate)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        }
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        for path in [
            &tls.certificate_chain_path,
            &tls.private_key_path,
            &tls.client_ca_certificate_path,
        ] {
            std::fs::remove_file(path)?;
        }
        Ok(config)
    }

    enum PlainControlStream {
        Vsock(File),
        Unix(std::os::unix::net::UnixStream),
        Tcp(std::net::TcpStream),
    }

    impl PlainControlStream {
        fn into_tokio(
            self,
        ) -> io::Result<openshell_isolation_interface::contract::BoundaryDuplexStream> {
            match self {
                Self::Vsock(file) => {
                    let stream =
                        unsafe { std::os::unix::net::UnixStream::from_raw_fd(file.into_raw_fd()) };
                    stream.set_nonblocking(true)?;
                    Ok(Box::new(tokio::net::UnixStream::from_std(stream)?))
                }
                Self::Unix(stream) => {
                    stream.set_nonblocking(true)?;
                    Ok(Box::new(tokio::net::UnixStream::from_std(stream)?))
                }
                Self::Tcp(stream) => {
                    stream.set_nonblocking(true)?;
                    let stream = tokio::net::TcpStream::from_std(stream)?;
                    openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                    Ok(Box::new(stream))
                }
            }
        }
    }

    enum ControlStream {
        PendingTls {
            stream: PlainControlStream,
            server_config: Arc<rustls::ServerConfig>,
        },
        Tls {
            stream: Option<
                Box<
                    tokio_rustls::server::TlsStream<
                        openshell_isolation_interface::contract::BoundaryDuplexStream,
                    >,
                >,
            >,
            runtime: tokio::runtime::Handle,
        },
        #[cfg(test)]
        TestUnix(std::os::unix::net::UnixStream),
    }

    impl ControlStream {
        fn establish(self, runtime: &tokio::runtime::Handle) -> io::Result<Self> {
            let Self::PendingTls {
                stream,
                server_config,
            } = self
            else {
                return Ok(self);
            };
            let stream = {
                let _guard = runtime.enter();
                stream.into_tokio()?
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let stream = runtime.block_on(async {
                tokio::time::timeout(CONTROL_IO_TIMEOUT, acceptor.accept(stream))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "boundary TLS handshake timed out")
                    })?
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })?;
            Ok(Self::Tls {
                stream: Some(Box::new(stream)),
                runtime: runtime.clone(),
            })
        }

        fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
            let _ = timeout;
            if matches!(self, Self::Tls { .. }) {
                return Ok(());
            }
            if matches!(self, Self::PendingTls { .. }) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                ));
            }
            #[cfg(test)]
            if let Self::TestUnix(stream) = self {
                stream.set_read_timeout(Some(timeout))?;
                return stream.set_write_timeout(Some(timeout));
            }
            unreachable!("all established sandbox streams use mutual TLS")
        }

        fn into_tokio(
            self,
        ) -> Result<openshell_isolation_interface::contract::BoundaryDuplexStream, String> {
            match self {
                Self::Tls { mut stream, .. } => Ok(stream
                    .take()
                    .expect("boundary TLS stream can only be converted once")),
                Self::PendingTls { .. } => {
                    Err("boundary TLS stream has not completed its handshake".to_string())
                }
                #[cfg(test)]
                Self::TestUnix(stream) => {
                    stream
                        .set_nonblocking(true)
                        .map_err(|error| format!("set test Unix stream nonblocking: {error}"))?;
                    Ok(Box::new(tokio::net::UnixStream::from_std(stream).map_err(
                        |error| format!("register test Unix stream with Tokio: {error}"),
                    )?))
                }
            }
        }
    }

    impl Read for ControlStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::Tls { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(
                        CONTROL_IO_TIMEOUT,
                        stream
                            .as_mut()
                            .expect("boundary TLS stream must be present")
                            .read(buffer),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "boundary TLS read timed out")
                    })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.read(buffer),
            }
        }
    }

    impl Write for ControlStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            match self {
                Self::Tls { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(
                        CONTROL_IO_TIMEOUT,
                        stream
                            .as_mut()
                            .expect("boundary TLS stream must be present")
                            .write(buffer),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "boundary TLS write timed out")
                    })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.write(buffer),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            match self {
                Self::Tls { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(
                        CONTROL_IO_TIMEOUT,
                        stream
                            .as_mut()
                            .expect("boundary TLS stream must be present")
                            .flush(),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "boundary TLS flush timed out")
                    })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.flush(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use openshell_isolation_interface::boundary_protocol::{
            BoundaryClientTls, BoundaryServerTls, generate_boundary_mutual_tls_material,
        };

        #[test]
        fn replay_ledger_evicts_oldest_records_without_disabling_control() {
            let mut ledger = ReplayLedger::default();
            for index in 0..=MAX_REPLAY_LEDGER_ENTRIES {
                ledger.insert(
                    format!("request-{index}"),
                    ReplayRecord {
                        payload_digest: format!("digest-{index}"),
                        response: Response::Signaled,
                    },
                );
            }
            assert!(ledger.get("request-0").is_none());
            assert!(
                ledger
                    .get(&format!("request-{MAX_REPLAY_LEDGER_ENTRIES}"))
                    .is_some()
            );
            assert_eq!(ledger.entries.len(), MAX_REPLAY_LEDGER_ENTRIES);
        }

        #[test]
        fn scratch_agent_command_resolves_inside_the_workload_filesystem() {
            let resolved = resolve_agent_spec(AgentSpecWire {
                program: String::new(),
                args: Vec::new(),
                workdir: Some("/sandbox".to_string()),
                timeout_secs: 0,
                interactive: true,
            })
            .expect("resolve scratch command");

            assert!(openshell_core::shell::is_executable(&resolved.program));
            assert_eq!(resolved.args, vec!["-l".to_string()]);
            assert_eq!(resolved.workdir.as_deref(), Some("/sandbox"));
            assert!(resolved.interactive);
        }

        fn placeholder_server_tls() -> BoundaryServerTls {
            BoundaryServerTls {
                certificate_chain_path: Path::new("/tmp/openshell-sandbox.crt").to_path_buf(),
                private_key_path: Path::new("/tmp/openshell-sandbox.key").to_path_buf(),
                client_ca_certificate_path: Path::new("/tmp/openshell-client-ca.crt").to_path_buf(),
            }
        }

        fn stage_test_tls(
            directory: &Path,
            prefix: &str,
        ) -> (BoundaryServerTls, BoundaryClientTls) {
            let material = generate_boundary_mutual_tls_material().expect("generate test TLS");
            let certificate_chain_path = directory.join(format!("{prefix}-sandbox.crt"));
            let private_key_path = directory.join(format!("{prefix}-sandbox.key"));
            let client_ca_certificate_path = directory.join(format!("{prefix}-client-ca.crt"));
            std::fs::write(&certificate_chain_path, material.sandbox_certificate_pem)
                .expect("write sandbox certificate");
            std::fs::write(&private_key_path, material.sandbox_private_key_pem)
                .expect("write sandbox key");
            std::fs::write(&client_ca_certificate_path, &material.ca_certificate_pem)
                .expect("write client CA");
            (
                BoundaryServerTls {
                    certificate_chain_path,
                    private_key_path,
                    client_ca_certificate_path,
                },
                BoundaryClientTls {
                    server_name: material.server_name,
                    ca_certificate_pem: material.ca_certificate_pem,
                    certificate_chain_pem: material.supervisor_certificate_pem,
                    private_key_pem: material.supervisor_private_key_pem,
                },
            )
        }

        fn test_client_config(tls: &BoundaryClientTls) -> rustls::ClientConfig {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pemfile::certs(&mut tls.ca_certificate_pem.as_bytes()) {
                roots
                    .add(certificate.expect("parse test CA"))
                    .expect("add test CA");
            }
            let certificates = rustls_pemfile::certs(&mut tls.certificate_chain_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse test client certificate");
            let private_key = rustls_pemfile::private_key(&mut tls.private_key_pem.as_bytes())
                .expect("parse test client key")
                .expect("test client key");
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(certificates, private_key)
                .expect("build test client config")
        }

        #[test]
        fn boundary_config_debug_redacts_token() {
            let config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_epoch: "session-1".to_string(),
                bootstrap_token: "never-log-this-never-log-this".to_string(),
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::new(),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                driver_fence: test_driver_fence(),
                child_env: std::collections::HashMap::new(),
            };
            let debug = format!("{config:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("never-log-this"));
        }

        #[test]
        fn installed_proxy_ca_is_readable_by_a_non_root_workload_identity() {
            use std::os::unix::fs::PermissionsExt as _;

            let root = tempfile::tempdir().expect("temporary CA root");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let directory = root.path().join("openshell-proxy-ca");
            let (ca_path, bundle_path) = install_ca_material_at(
                &directory,
                b"public test certificate",
                b"public test bundle",
            )
            .expect("install proxy CA")
            .expect("CA paths");

            assert_eq!(
                std::fs::metadata(directory.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0o111,
                "non-root workload identities must be able to traverse the full path"
            );
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o755,
                "non-root workload identities must be able to traverse the CA directory"
            );
            for (path, expected) in [
                (&ca_path, b"public test certificate".as_slice()),
                (&bundle_path, b"public test bundle".as_slice()),
            ] {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o444,
                    "public CA material must be readable by the workload"
                );
                assert_eq!(std::fs::read(path).unwrap(), expected);
            }
        }

        #[test]
        fn proxy_ca_install_rejects_a_symlinked_directory() {
            let root = tempfile::tempdir().expect("temporary CA root");
            let target = root.path().join("target");
            std::fs::create_dir(&target).unwrap();
            let parent = root.path();
            std::os::unix::fs::symlink(&target, parent.join("openshell-proxy-ca")).unwrap();

            let error = install_ca_material_at(
                &parent.join("openshell-proxy-ca"),
                b"certificate",
                b"bundle",
            )
            .expect_err("symlinked CA directory must fail closed");
            assert!(error.contains("symlink"), "unexpected error: {error}");
        }

        #[test]
        fn constant_time_comparison_checks_length_and_content() {
            assert!(constant_time_eq(b"same", b"same"));
            assert!(!constant_time_eq(b"same", b"different"));
            assert!(!constant_time_eq(b"same", b"sam"));
        }

        #[test]
        fn supplementary_group_measurement_excludes_the_primary_group() {
            assert_eq!(
                normalized_supplementary_groups(vec![1002, 1001, 1000, 1001], 1000),
                vec![1001, 1002]
            );
        }

        #[test]
        fn control_connection_slots_bound_unauthenticated_threads() {
            let active = Arc::new(AtomicUsize::new(MAX_CONTROL_CONNECTIONS - 1));
            let slot = acquire_control_connection_slot(&active).expect("last available slot");
            assert!(acquire_control_connection_slot(&active).is_none());
            drop(slot);
            assert_eq!(active.load(Ordering::Acquire), MAX_CONTROL_CONNECTIONS - 1);
        }

        fn test_workload_identity() -> ResolvedWorkloadIdentity {
            let mut supplementary_gids = nix::unistd::getgroups()
                .unwrap()
                .into_iter()
                .map(nix::unistd::Gid::as_raw)
                .collect::<Vec<_>>();
            supplementary_gids.sort_unstable();
            supplementary_gids.dedup();
            ResolvedWorkloadIdentity::new(
                nix::unistd::geteuid().as_raw(),
                nix::unistd::getegid().as_raw(),
                supplementary_gids,
                "test".to_string(),
                "a".repeat(64),
            )
            .unwrap()
        }

        fn test_driver_fence() -> openshell_isolation_interface::contract::DriverFenceEvidence {
            openshell_isolation_interface::contract::DriverFenceEvidence::Vm {
                generation: "generation-1".to_string(),
                network_device_count: 0,
            }
        }

        fn test_runtime_qualification() -> crate::RuntimeQualification {
            crate::RuntimeQualification {
                seccomp: openshell_isolation_interface::contract::SeccompEvidence {
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
                landlock_abi: 6,
                landlock_allow_deny: true,
                udp_dns_round_trip: true,
                tcp_dns_round_trip: true,
                tcp_allow_round_trip: true,
                tcp_deny_round_trip: true,
            }
        }

        fn test_network_broker() -> (
            NetworkBroker,
            openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
        ) {
            let (launcher, listener) =
                openshell_isolation_interface::linux::workload_launcher::start()
                    .expect("start test listener");
            crate::process::configure_workload_launcher(launcher.clone())
                .expect("configure test workload launcher");
            (
                NetworkBroker::start_for_test(listener).expect("start test network broker"),
                launcher,
            )
        }

        #[test]
        fn unix_listener_allows_authenticated_cross_uid_control() {
            use std::os::unix::fs::PermissionsExt as _;

            let directory = tempfile::tempdir().expect("temporary directory");
            let socket_path = directory.path().join("control.sock");
            let (tls, _) = stage_test_tls(directory.path(), "initial");
            let _listener = ControlListener::bind(&BoundaryListenerConfig::Unix {
                socket_path: socket_path.clone(),
                tls,
            })
            .expect("bind Unix listener");
            let mode = socket_path
                .metadata()
                .expect("socket metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o666);
        }

        #[test]
        fn unix_listener_replaces_only_an_owned_stale_socket() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let socket_path = directory.path().join("control.sock");
            let (initial_tls, _) = stage_test_tls(directory.path(), "initial");
            drop(
                ControlListener::bind(&BoundaryListenerConfig::Unix {
                    socket_path: socket_path.clone(),
                    tls: initial_tls,
                })
                .expect("bind initial Unix listener"),
            );
            let (replacement_tls, _) = stage_test_tls(directory.path(), "replacement");
            let replacement = ControlListener::bind(&BoundaryListenerConfig::Unix {
                socket_path: socket_path.clone(),
                tls: replacement_tls,
            })
            .expect("replace owned stale Unix listener");

            drop(replacement);
            std::fs::remove_file(&socket_path).expect("remove stale socket");
            std::fs::write(&socket_path, b"not a socket").expect("write collision");
            let (collision_tls, _) = stage_test_tls(directory.path(), "collision");
            let error = ControlListener::bind(&BoundaryListenerConfig::Unix {
                socket_path,
                tls: collision_tls,
            })
            .err()
            .expect("regular-file collision must fail");
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        }

        #[test]
        fn exact_workload_identity_is_required() {
            let config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_epoch: "session-1".to_string(),
                bootstrap_token: "a".repeat(64),
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::new(),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                driver_fence: test_driver_fence(),
                child_env: std::collections::HashMap::new(),
            };

            validate_config(&config).unwrap();
            validate_running_identity(&config.workload_identity).unwrap();
        }

        #[test]
        fn runtime_resource_claim_file_must_match_admitted_claim() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let pod_uid_path = directory.path().join("pod-uid");
            std::fs::write(&pod_uid_path, "pod-uid-a\n").expect("write runtime claim");
            let mut config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_epoch: "session-1".to_string(),
                bootstrap_token: "a".repeat(64),
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::from([(
                    "kubernetes.pod_uid".to_string(),
                    "pod-uid-a".to_string(),
                )]),
                resource_claim_files: std::collections::BTreeMap::from([(
                    "kubernetes.pod_uid".to_string(),
                    pod_uid_path,
                )]),
                workload_identity: test_workload_identity(),
                driver_fence: test_driver_fence(),
                child_env: std::collections::HashMap::new(),
            };

            validate_config(&config).expect("valid runtime claim configuration");
            validate_runtime_resource_claims(&config).expect("matching runtime claim");

            config.resource_claims.insert(
                "kubernetes.pod_uid".to_string(),
                "replacement-pod-uid".to_string(),
            );
            assert!(validate_runtime_resource_claims(&config).is_err());
        }

        #[test]
        fn tls_listener_preserves_session_when_control_switches_to_async_streaming() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (server_tls, client_tls) = stage_test_tls(directory.path(), "stream");
            let listener = ControlListener::bind(&BoundaryListenerConfig::TlsTcp {
                address: "127.0.0.1:0".parse().expect("valid address"),
                tls: server_tls,
            })
            .expect("bind TLS listener");
            let address = listener.tcp_local_addr().expect("TLS listener address");
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            let server_runtime = runtime.handle().clone();
            let server = std::thread::spawn(move || {
                let mut stream = loop {
                    match listener.accept() {
                        Ok(stream) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::yield_now();
                        }
                        Err(error) => panic!("accept TLS stream: {error}"),
                    }
                }
                .establish(&server_runtime)
                .expect("establish TLS stream");
                let mut first = [0_u8; 4];
                Read::read_exact(&mut stream, &mut first).expect("read blocking TLS phase");
                assert_eq!(&first, b"sync");
                Write::write_all(&mut stream, b"ack1").expect("write blocking TLS phase");
                server_runtime.block_on(async move {
                    let mut stream = stream.into_tokio().expect("convert negotiated TLS stream");
                    let mut second = [0_u8; 5];
                    stream
                        .read_exact(&mut second)
                        .await
                        .expect("read async TLS phase");
                    assert_eq!(&second, b"async");
                    stream
                        .write_all(b"ack2")
                        .await
                        .expect("write async TLS phase");
                });
            });

            runtime.block_on(async {
                let client_config = test_client_config(&client_tls);
                let stream = tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connect TLS listener");
                let server_name = rustls::pki_types::ServerName::try_from(client_tls.server_name)
                    .expect("valid server name");
                let mut stream = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                    .connect(server_name, stream)
                    .await
                    .expect("verify TLS listener");
                stream.write_all(b"sync").await.expect("write first phase");
                let mut first_ack = [0_u8; 4];
                stream
                    .read_exact(&mut first_ack)
                    .await
                    .expect("read first acknowledgement");
                assert_eq!(&first_ack, b"ack1");
                stream
                    .write_all(b"async")
                    .await
                    .expect("write second phase");
                let mut second_ack = [0_u8; 4];
                stream
                    .read_exact(&mut second_ack)
                    .await
                    .expect("read second acknowledgement");
                assert_eq!(&second_ack, b"ack2");
            });
            server.join().expect("TLS boundary server thread");
        }

        #[test]
        fn control_restart_replays_running_lifecycle_exactly_once() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_BOUNDARY_RECONNECT_CHILD";
            if std::env::var_os(CHILD_MARKER).is_none() {
                let status = std::process::Command::new(
                    std::env::current_exe().expect("current test executable"),
                )
                .args([
                    "--exact",
                    "boundary_server::linux::tests::control_restart_replays_running_lifecycle_exactly_once",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated reconnect test");
                assert!(status.success(), "isolated reconnect test failed");
                return;
            }

            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let (network_broker, workload_launcher) = test_network_broker();
            let boundary = Arc::new(BoundaryRuntime::new(
                BoundaryConfig {
                    boundary_id: "sandbox-reconnect".to_string(),
                    generation: "generation-reconnect".to_string(),
                    session_epoch: "session-reconnect".to_string(),
                    bootstrap_token: "a".repeat(32),
                    listener: BoundaryListenerConfig::TlsTcp {
                        address: "127.0.0.1:5500".parse().expect("control address"),
                        tls: placeholder_server_tls(),
                    },
                    resource_claims: std::collections::BTreeMap::new(),
                    resource_claim_files: std::collections::BTreeMap::new(),
                    workload_identity: test_workload_identity(),
                    driver_fence: test_driver_fence(),
                    child_env: std::collections::HashMap::new(),
                },
                process_runtime.handle().clone(),
                network_broker,
                workload_launcher,
                test_runtime_qualification(),
            ));
            let policy = SandboxPolicyWire::from(openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            });
            let spec = AgentSpecWire {
                program: "/bin/sleep".to_string(),
                args: vec!["30".to_string()],
                workdir: None,
                timeout_secs: 60,
                interactive: false,
            };

            assert!(matches!(
                boundary.attach(policy.clone()),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            let start = || {
                boundary.start_agent(
                    "sandbox-reconnect".to_string(),
                    spec.clone(),
                    policy.clone(),
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                )
            };
            let Response::Started {
                process_id,
                provider_env_revision: 0,
            } = start()
            else {
                panic!("initial start did not succeed");
            };

            let update = RequestEnvelope::new(
                "sandbox-reconnect".to_string(),
                "a".repeat(32),
                Request::UpdateProviderEnvironment {
                    expected_revision: 0,
                    revision: 7,
                    provider_env: std::collections::HashMap::from([(
                        "REPLAY_TEST".to_string(),
                        "set-once".to_string(),
                    )]),
                },
            )
            .expect("build replayed update");
            assert_eq!(
                boundary.dispatch(update.clone()),
                Response::ProviderEnvironmentUpdated { revision: 7 }
            );
            assert_eq!(
                boundary.dispatch(update.clone()),
                Response::ProviderEnvironmentUpdated { revision: 7 },
                "the same request ID and payload must replay its recorded response"
            );
            let mut changed = RequestEnvelope::new(
                "sandbox-reconnect".to_string(),
                "a".repeat(32),
                Request::Terminate {
                    process_id: process_id.clone(),
                },
            )
            .expect("build changed request");
            changed.request_id = update.request_id;
            assert!(matches!(
                boundary.dispatch(changed),
                Response::Error { kind, .. } if kind == "denied"
            ));

            let (first_attachment, _) = boundary
                .attach_process(&process_id)
                .expect("initial main-process attachment");
            assert!(boundary.attach_process(&process_id).is_err());
            let (boundary_stream, control_stream) =
                std::os::unix::net::UnixStream::pair().expect("main attachment socket pair");
            let stream_boundary = boundary.clone();
            let stream_thread = std::thread::spawn(move || {
                stream_boundary
                    .stream_process(ControlStream::TestUnix(boundary_stream), first_attachment)
            });
            drop(control_stream);
            stream_thread
                .join()
                .expect("join disconnected main attachment")
                .expect("transport EOF cleanly ends main attachment");
            let (replacement_attachment, _) = boundary
                .attach_process(&process_id)
                .expect("replacement main-process attachment after disconnect");
            drop(replacement_attachment);

            assert!(matches!(
                boundary.attach(policy.clone()),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                start(),
                Response::Started {
                    process_id: process_id.clone(),
                    provider_env_revision: 7,
                }
            );

            let mut changed_policy = policy.clone();
            changed_policy.version += 1;
            assert!(matches!(
                boundary.attach(changed_policy.clone()),
                Response::Error { kind, .. } if kind == "denied"
            ));
            assert!(matches!(
                boundary.start_agent(
                    "sandbox-reconnect".to_string(),
                    spec,
                    changed_policy,
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                ),
                Response::Error { kind, .. } if kind == "denied"
            ));

            let exec_spec = ExecSpecWire {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "printf reconnected".to_string()],
                env: Vec::new(),
                workdir: None,
                pty: false,
            };
            let exec_request = RequestEnvelope::new(
                "sandbox-reconnect".to_string(),
                "a".repeat(32),
                Request::Exec {
                    spec: exec_spec.clone(),
                },
            )
            .expect("build exec request");
            let exec = boundary
                .start_exec(
                    &exec_request.request_id,
                    &exec_request.payload_digest,
                    exec_spec,
                )
                .expect("exec after reconnect");
            let exec_id = exec.process_id.clone();
            let mut output = String::new();
            let mut cursor = exec.attachment.session.subscribe();
            process_runtime.block_on(async {
                loop {
                    match cursor.recv().await.expect("retained exec output") {
                        MainOutput::Stdout(bytes) => {
                            output.push_str(std::str::from_utf8(&bytes).expect("UTF-8 output"));
                        }
                        MainOutput::Stderr(_) => {}
                        MainOutput::Exit(code) => {
                            assert_eq!(code, 0);
                            break;
                        }
                    }
                }
            });
            assert_eq!(output, "reconnected");
            drop(exec);
            let Response::Attached { snapshot } = boundary.attach(policy.clone()) else {
                panic!("reconnect attach did not return a session snapshot");
            };
            assert_eq!(snapshot.generation, "generation-reconnect");
            assert!(snapshot.processes.iter().any(|process| {
                process.process_id == process_id && process.kind == ProcessKindWire::Main
            }));
            assert!(snapshot.processes.iter().any(|process| {
                process.process_id == exec_id
                    && process.kind == ProcessKindWire::Exec
                    && process.status == Some(ExitStatusWire::Exited(0))
                    && process.retained_output.next_sequence > 0
            }));
            assert_eq!(boundary.terminate(&process_id), Response::Terminated);
        }

        #[test]
        fn canonical_exit_preserves_pending_network_accept_and_exec() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_RETAINED_BOUNDARY_CHILD";
            if std::env::var_os(CHILD_MARKER).is_none() {
                let status = std::process::Command::new(
                    std::env::current_exe().expect("current test executable"),
                )
                .args([
                    "--exact",
                    "boundary_server::linux::tests::canonical_exit_preserves_pending_network_accept_and_exec",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated retained-boundary test");
                assert!(status.success(), "isolated retained-boundary test failed");
                return;
            }

            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let policy = openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy {
                    mode: openshell_core::policy::NetworkMode::Proxy,
                    proxy: Some(openshell_core::policy::ProxyPolicy {
                        http_addr: Some("127.0.0.1:3128".parse().expect("proxy address")),
                    }),
                },
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            };
            let (network_broker, workload_launcher) = test_network_broker();
            let prepared = PreparedBoundary {
                network_broker: network_broker.clone(),
            };
            let agent_spec = AgentSpecWire {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                workdir: None,
                timeout_secs: 5,
                interactive: false,
            };
            let wire_policy = SandboxPolicyWire::from(policy.clone());
            let process = Arc::new(
                ManagedProcess::spawn(
                    process_runtime.handle(),
                    ManagedProcessLaunch {
                        process_id: "generation-retained:main:0".to_string(),
                        sandbox_id: "sandbox-retained".to_string(),
                        spec: agent_spec.clone(),
                        policy,
                        provider_env_revision: 0,
                        provider_env: std::collections::HashMap::new(),
                        ca_file_paths: None,
                    },
                    prepared,
                )
                .expect("spawn canonical process"),
            );
            let boundary = Arc::new(BoundaryRuntime::new(
                BoundaryConfig {
                    boundary_id: "sandbox-retained".to_string(),
                    generation: "generation-retained".to_string(),
                    session_epoch: "session-retained".to_string(),
                    bootstrap_token: "a".repeat(32),
                    listener: BoundaryListenerConfig::TlsTcp {
                        address: "127.0.0.1:5500".parse().expect("control address"),
                        tls: placeholder_server_tls(),
                    },
                    resource_claims: std::collections::BTreeMap::new(),
                    resource_claim_files: std::collections::BTreeMap::new(),
                    workload_identity: test_workload_identity(),
                    driver_fence: test_driver_fence(),
                    child_env: std::collections::HashMap::new(),
                },
                process_runtime.handle().clone(),
                network_broker,
                workload_launcher,
                test_runtime_qualification(),
            ));
            *lock(&boundary.state) = RuntimeState::Running(process.clone());
            *lock(&boundary.attached_policy) = Some(wire_policy.clone());
            *lock(&boundary.started_agent) = Some(StartedAgent {
                sandbox_id: "sandbox-retained".to_string(),
                spec: agent_spec.clone(),
                policy: wire_policy.clone(),
                ca_cert: None,
                ca_bundle: None,
                provider_env_revision: 0,
                provider_env: std::collections::HashMap::new(),
            });

            // A replacement control process replays the durable lifecycle and
            // receives the original process rather than spawning another one.
            assert!(matches!(
                boundary.attach(wire_policy.clone()),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                boundary.start_agent(
                    "sandbox-retained".to_string(),
                    agent_spec.clone(),
                    wire_policy.clone(),
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                ),
                Response::Started {
                    process_id: process.process_id(),
                    provider_env_revision: 0,
                }
            );

            assert_eq!(
                boundary.update_provider_environment(
                    0,
                    2,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "refreshed".to_string(),
                    )]),
                ),
                Response::ProviderEnvironmentUpdated { revision: 2 }
            );
            assert_eq!(
                boundary.update_provider_environment(
                    0,
                    1,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "stale".to_string(),
                    )]),
                ),
                Response::ProviderEnvironmentUpdated { revision: 2 }
            );
            assert_eq!(
                boundary.update_provider_environment(2, 1, std::collections::HashMap::new()),
                Response::ProviderEnvironmentUpdated { revision: 1 },
                "a numerically smaller opaque revision must revoke the environment"
            );
            assert_eq!(
                boundary.update_provider_environment(
                    2,
                    3,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "out-of-order".to_string(),
                    )]),
                ),
                Response::ProviderEnvironmentUpdated { revision: 1 },
                "a stale expected revision must not overwrite current state"
            );
            assert_eq!(
                boundary.update_provider_environment(1, 1, std::collections::HashMap::new()),
                Response::ProviderEnvironmentUpdated { revision: 1 },
                "a duplicate update must be idempotent"
            );

            assert!(matches!(
                boundary.attach(wire_policy.clone()),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                boundary.start_agent(
                    "sandbox-retained".to_string(),
                    agent_spec,
                    wire_policy,
                    None,
                    None,
                    99,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "replacement-control-snapshot".to_string(),
                    )]),
                ),
                Response::Started {
                    process_id: process.process_id(),
                    provider_env_revision: 1,
                },
                "a replacement control must resume from the boundary's current revision"
            );

            let sleep_spec = ExecSpecWire {
                program: "/bin/sleep".to_string(),
                args: vec!["30".to_string()],
                env: Vec::new(),
                workdir: None,
                pty: false,
            };
            let sleep_request = RequestEnvelope::new(
                "sandbox-retained".to_string(),
                "a".repeat(32),
                Request::Exec {
                    spec: sleep_spec.clone(),
                },
            )
            .expect("build retained exec request");
            let started = boundary
                .start_exec(
                    &sleep_request.request_id,
                    &sleep_request.payload_digest,
                    sleep_spec.clone(),
                )
                .expect("start exec whose response is disconnected");
            let retained_id = started.process_id.clone();
            drop(started);
            let replayed = boundary
                .start_exec(
                    &sleep_request.request_id,
                    &sleep_request.payload_digest,
                    sleep_spec,
                )
                .expect("reattach exec after response loss");
            assert_eq!(replayed.process_id, retained_id);
            assert_eq!(lock(&boundary.exec_handles).len(), 1);
            drop(replayed);
            assert_eq!(
                boundary.signal_exec(&retained_id, SignalWire::Kill),
                Response::Signaled
            );

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !process.has_exited() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(process.has_exited(), "canonical process did not exit");

            let mut session = process_runtime
                .block_on(
                    process.boundary_exec().exec(
                        ExecSpecWire {
                            program: "/bin/sh".to_string(),
                            args: vec![
                                "-c".to_string(),
                                "if [ -z \"${ROTATED_TOKEN+x}\" ]; then printf revoked; else printf 'unexpected:%s' \"$ROTATED_TOKEN\"; fi"
                                    .to_string(),
                            ],
                            env: Vec::new(),
                            workdir: None,
                            pty: false,
                        }
                        .into(),
                    ),
                )
                .expect("exec after canonical exit");
            let mut output = String::new();
            process_runtime
                .block_on(session.stdout.read_to_string(&mut output))
                .expect("read retained exec output");
            assert_eq!(
                output, "revoked",
                "exec after canonical exit must use the latest reconciled provider snapshot"
            );
            assert!(matches!(
                process_runtime.block_on(session.process.wait()),
                Ok(openshell_isolation_interface::contract::BoundaryExitStatus::Exited(0))
            ));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::run_boundary;

#[cfg(not(target_os = "linux"))]
pub fn run_boundary(
    _config_path: &Path,
    _qualification: crate::RuntimeQualification,
) -> Result<(), String> {
    Err("boundary mode is supported only on Linux".to_string())
}
