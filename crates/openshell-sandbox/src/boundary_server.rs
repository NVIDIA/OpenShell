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
    use crate::native_api::{
        BoundaryExec, BoundaryLoopbackConnector, BoundaryProcess, BoundaryTerminal, ExecSession,
    };

    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd as _, OwnedFd};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use crate::boundary_io::BoundaryRuntimeState;
    use crate::delegated::{AgentSignaler, spawn_workload};
    use crate::main_session::{MainOutput, MainSession};
    use crate::network_broker::NetworkBroker;
    use crate::process::ProcessStatus;
    use openshell_core::jwt::{
        SandboxId, SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SystemJwtClock,
    };
    use openshell_core::provider_credentials::ProviderCredentialState;
    use openshell_isolation_interface::contract::{
        BoundaryConfirmation, LoopbackTarget, ResolvedWorkloadIdentity,
    };
    use openshell_sandbox_backend::backend_proto::{
        DescribeIsolationBackendRequest, DescribeIsolationBackendResponse, OpenBoundaryRequest,
        OpenBoundaryResponse, ResumeBoundaryRequest, SuspendBoundaryRequest,
        SuspendBoundaryResponse,
        isolation_backend_server::{IsolationBackend, IsolationBackendServer},
        open_boundary_response::LaunchOutcome,
    };
    #[cfg(test)]
    use openshell_sandbox_backend::isolation_protocol::{chunk_data, data_chunk};
    use openshell_sandbox_backend::mediation::{
        self, DnsQueryWire, MediationFrame, MediationFrameKind,
    };
    #[cfg(test)]
    use openshell_sandbox_backend::proto::sandbox_protocol_client::SandboxProtocolClient;
    use openshell_sandbox_backend::proto::{
        ExchangeFrame, MediateFrame,
        sandbox_protocol_server::{SandboxProtocol, SandboxProtocolServer},
    };
    use openshell_sandbox_backend::sandbox_auth::{
        Promotion, SandboxAuthError, SandboxConnectionId, SandboxConnectionRegistry,
        SandboxProtocolAuthenticator, SandboxProtocolPrincipal,
    };
    use openshell_sandbox_backend::{
        ALLOW_EXTRA_SUPPLEMENTARY_GROUPS_RESOURCE_CLAIM, GPU_RESOURCE_CLAIM,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_stream::wrappers::ReceiverStream;

    use openshell_sandbox_backend::boundary_protocol::{
        AgentSpecWire, BOUNDARY_CONNECTION_WINDOW_BYTES, BOUNDARY_MAX_CONCURRENT_STREAMS,
        BOUNDARY_STREAM_WINDOW_BYTES, BinaryIdentityWire, BoundaryConfig, BoundaryErrorKind,
        BoundaryListener as BoundaryListenerConfig, DnsQueryResultWire, ExecSpecWire,
        ExitStatusWire, MediationTimingWire, NativeLinuxSandboxAuditEvidence, OutputWindowWire,
        ProcessKindWire, ProcessSnapshotWire, Request, RequestEnvelope, Response, ResponseEnvelope,
        STREAM_EXIT, STREAM_NETWORK_DECISION, STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED,
        STREAM_STDOUT, SandboxPolicyWire, SessionSnapshotWire, SignalWire, encode_frame,
        read_frame, read_stream_frame, unix_time_millis, validate_resource_claims, write_frame,
        write_stream_frame,
    };

    const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);
    const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const CONTROL_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
    const CONTROL_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
    const MEDIATION_REPLACEMENT_TIMEOUT: Duration = Duration::from_secs(20);
    const ENFORCEMENT_LOSS_TERMINATION_GRACE: Duration =
        Duration::from_secs(openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS as u64);
    const FORCE_KILL_REAP_TIMEOUT: Duration = Duration::from_secs(2);
    /// Bound the wait for a flush before acknowledging termination. A timed-out
    /// blocking task cannot be cancelled and may outlive the acknowledgement.
    const FILESYSTEM_FLUSH_TIMEOUT: Duration = Duration::from_secs(3);
    const MAX_PENDING_HANDSHAKES: usize = 32;
    const MAX_CONTROL_CONNECTIONS: usize = 128;
    /// Bounds one runtime-initiated dial, including finding the supervisor
    /// pool member that hosts the route.
    const RUNTIME_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    /// Bounds connecting to one supervisor address and negotiating the route
    /// there, so an unreachable cached owner leaves time for the configured
    /// addresses.
    const RUNTIME_ROUTE_HOP_TIMEOUT: Duration = Duration::from_secs(2);
    /// Redirects followed from each supervisor address a dial starts at.
    const MAX_RUNTIME_ROUTE_REDIRECTS: usize = 2;
    /// Spares a routed runtime keeps unused at once: one at its owner, and in
    /// a supervisor pool one at each member that discovery finds hosting its
    /// route. A lone shared supervisor is one member, so it holds one.
    const POOL_MAX_UNCLAIMED_SPARES: usize = 3;
    /// Interval of route discovery through the configured supervisor
    /// addresses, which finds a new owner while the previous one stays
    /// reachable. Only runs once a supervisor showed it is a pool member.
    const POOL_ROUTE_DISCOVERY_INTERVAL: Duration = Duration::from_secs(15);
    /// Dials in one discovery round.
    const POOL_ROUTE_DISCOVERY_PROBES: usize = 3;
    const RUNTIME_DIAL_BACKOFF_MIN: Duration = Duration::from_millis(100);
    const RUNTIME_DIAL_BACKOFF_MAX: Duration = Duration::from_secs(2);
    /// A spare that dies this quickly without being claimed counts as a failure.
    const RUNTIME_SPARE_MIN_LIFETIME: Duration = Duration::from_secs(1);
    /// How long a retired connection may take to shut down gracefully before
    /// its transport is dropped.
    const RETIRED_CONNECTION_GRACE: Duration = Duration::from_secs(2);
    /// Consecutive dial failures are expected while the supervisor starts;
    /// report a persistent failure at most this often.
    const RUNTIME_DIAL_WARNING_INTERVAL: Duration = Duration::from_secs(30);
    const MAX_REPLAY_LEDGER_ENTRIES: usize = 4096;
    const MAX_RETAINED_EXEC_PROCESSES: usize = 64;
    // Three stdio pipes require six descriptors before fork, and Rust's
    // process launcher may briefly need additional bookkeeping descriptors.
    // Reclaim closed mediated sockets before each serialized spawn so stale
    // socket sources cannot consume that bounded launch budget.
    const EXEC_SPAWN_DESCRIPTOR_HEADROOM: usize = 16;

    // NVML may traverse the persistenced socket directory during initialization;
    // WSL2 supplies GPU libraries under /usr/lib/wsl and the /dev/dxg device.
    const GPU_BASELINE_READ_ONLY: &[&str] = &["/run/nvidia-persistenced", "/usr/lib/wsl"];
    // CUDA opens device nodes read-write. Its thread-name writes through
    // /proc/<pid>/task/<tid>/comm are served by open mediation, so /proc
    // stays read-only.
    const GPU_BASELINE_READ_WRITE: &[&str] = &[
        "/dev/nvidiactl",
        "/dev/nvidia-uvm",
        "/dev/nvidia-uvm-tools",
        "/dev/nvidia-modeset",
        "/dev/dxg",
    ];

    fn duration_micros(duration: Duration) -> u64 {
        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
    }

    /// Add the filesystem paths required by GPU devices visible inside the
    /// workload. The supervisor's device namespace can differ from the
    /// workload's, so discovery must happen here, gated by the resource claim.
    fn enrich_gpu_filesystem_paths(
        policy: &mut openshell_core::policy::SandboxPolicy,
        gpu_requested: bool,
    ) -> bool {
        if !gpu_requested {
            return false;
        }
        let has_gpu = Path::new("/dev/nvidiactl").exists() || Path::new("/dev/dxg").exists();
        if !has_gpu {
            return false;
        }

        let mut read_write = GPU_BASELINE_READ_WRITE
            .iter()
            .copied()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        if let Ok(entries) = std::fs::read_dir("/dev") {
            read_write.extend(entries.flatten().filter_map(|entry| {
                let name = entry.file_name();
                let suffix = name.to_str()?.strip_prefix("nvidia")?;
                (!suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit()))
                    .then(|| entry.path())
            }));
        }

        let mut modified = false;
        for path in GPU_BASELINE_READ_ONLY.iter().copied().map(Path::new) {
            if path.exists()
                && !policy
                    .filesystem
                    .read_only
                    .iter()
                    .any(|allowed| allowed == path)
                && !policy
                    .filesystem
                    .read_write
                    .iter()
                    .any(|allowed| allowed == path)
            {
                policy.filesystem.read_only.push(path.to_path_buf());
                modified = true;
            }
        }
        for path in read_write {
            if !path.exists() || policy.filesystem.read_write.contains(&path) {
                continue;
            }
            if policy.filesystem.read_only.contains(&path) {
                continue;
            }
            policy.filesystem.read_write.push(path);
            modified = true;
        }
        modified
    }

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
    static BOUNDARY_TERMINATION_SIGNAL: AtomicI32 = AtomicI32::new(0);

    extern "C" fn request_boundary_termination(signal: libc::c_int) {
        BOUNDARY_TERMINATION_SIGNAL.store(signal, Ordering::Release);
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
        validate_running_identity(
            &config.workload_identity,
            allows_runtime_supplementary_groups(&config),
        )?;
        std::fs::remove_file(config_path).map_err(|error| {
            format!("consume boundary config {}: {error}", config_path.display())
        })?;
        crate::process::install_boundary_user_environment(config.child_env.clone())?;
        crate::sandbox::apply_supervisor_startup_hardening()
            .map_err(|error| format!("install sandbox process prelude: {error}"))?;
        // Keep orphaned workload descendants in this process tree so
        // termination can find and kill them, then reap the adopted ones.
        // PID 1 already receives orphans; elsewhere become a child subreaper.
        if nix::unistd::getpid().as_raw() != 1 {
            rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
                .map_err(|error| format!("become child subreaper: {error}"))?;
        }
        crate::managed_children::start_orphan_reaper()
            .map_err(|error| format!("start sandbox orphan reaper: {error}"))?;
        let (launcher, listener) = crate::linux::workload_launcher::start()
            .map_err(|error| format!("start sandbox workload launcher: {error}"))?;
        let protected_control_port = match &config.listener {
            BoundaryListenerConfig::TlsTcp { address, .. } => Some(address.port()),
            // Validation requires every supervisor address to share one port.
            BoundaryListenerConfig::RuntimeInitiatedTlsTcp { addresses, .. } => {
                addresses.first().map(std::net::SocketAddr::port)
            }
            BoundaryListenerConfig::Unix { .. }
            | BoundaryListenerConfig::Vsock { .. }
            | BoundaryListenerConfig::RuntimeInitiatedUnix { .. }
            | BoundaryListenerConfig::RuntimeInitiatedVsock { .. } => None,
        };
        let network_broker = NetworkBroker::start(listener, protected_control_port)
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
        )?);
        serve(&config.listener, runtime)
    }

    fn make_boundary_nondumpable() -> Result<(), String> {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|error| format!("make sandbox process nondumpable: {error}"))
    }

    fn disable_core_dumps() -> Result<(), String> {
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|error| format!("disable sandbox core dumps: {error}"))
    }

    fn install_boundary_signal_handlers() -> Result<(), String> {
        BOUNDARY_TERMINATION_REQUESTED.store(false, Ordering::Release);
        BOUNDARY_TERMINATION_SIGNAL.store(0, Ordering::Release);
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
        if config.generation.is_empty() {
            return Err("boundary generation must not be empty".to_string());
        }
        if config.gateway_id.is_empty() {
            return Err("gateway ID must not be empty".to_string());
        }
        if config.verification_keys.is_empty() {
            return Err("at least one gateway verification key is required".to_string());
        }
        validate_resource_claims(&config.resource_claims).map_err(|error| error.to_string())?;
        config
            .provisioning_evidence
            .validate(&config.generation)
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
            | BoundaryListenerConfig::RuntimeInitiatedUnix { socket_path, tls }
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
            // Workload sockets share the loopback interface with a loopback
            // listener.
            BoundaryListenerConfig::TlsTcp { address, .. }
                if address.ip().to_canonical().is_loopback() =>
            {
                return Err(
                    "boundary TLS listener must not bind a loopback address; workloads share the loopback interface"
                        .to_string(),
                );
            }
            BoundaryListenerConfig::Vsock {
                control_port: 0, ..
            } => {
                return Err("boundary control port must be nonzero".to_string());
            }
            BoundaryListenerConfig::RuntimeInitiatedVsock { host_port, tls }
                if *host_port == 0 || *host_port == u32::MAX || !tls_paths_are_absolute(tls) =>
            {
                return Err("runtime-initiated vsock requires a valid host port and absolute certificate paths".into());
            }
            BoundaryListenerConfig::RuntimeInitiatedTlsTcp {
                authority,
                addresses,
                tls,
                route,
            } => {
                validate_runtime_initiated_targets(authority, addresses, tls)?;
                if let Some(route) = route {
                    openshell_sandbox_backend::runtime_routed::validate_route_handle(route)
                        .map_err(|error| error.to_string())?;
                }
            }
            BoundaryListenerConfig::Unix { .. }
            | BoundaryListenerConfig::RuntimeInitiatedUnix { .. }
            | BoundaryListenerConfig::RuntimeInitiatedVsock { .. }
            | BoundaryListenerConfig::TlsTcp { .. }
            | BoundaryListenerConfig::Vsock { .. } => {}
        }
        if config.workload_identity.uid == 0 || config.workload_identity.gid == 0 {
            return Err("sandbox workload UID and GID must be nonzero".to_string());
        }
        Ok(())
    }

    /// VM selectors assert the protected overlay owner; they cannot choose a
    /// replacement identity. Guest init maps `sandbox` to that owner before
    /// launching this boundary, so no account lookup or privilege change belongs here.
    fn validate_vm_policy_identity(
        config: &BoundaryConfig,
        policy: &SandboxPolicyWire,
    ) -> Result<(), String> {
        if !config.resource_claims.contains_key("vm.generation") {
            return Ok(());
        }
        let identity = &config.workload_identity;
        for (field, selector, expected) in [
            ("run_as_user", policy.run_as_user.as_deref(), identity.uid),
            ("run_as_group", policy.run_as_group.as_deref(), identity.gid),
        ] {
            let Some(selector) = selector.filter(|value| !value.is_empty()) else {
                continue;
            };
            if selector != "sandbox" && selector.parse::<u32>() != Ok(expected) {
                return Err(format!(
                    "VM {field} '{selector}' conflicts with the resolved workload identity {}:{}; omit the selector or request the driver-owned identity",
                    identity.uid, identity.gid
                ));
            }
        }
        Ok(())
    }

    /// The dial target is driver-resolved bootstrap state, never workload
    /// input. Loopback is refused because workloads share the loopback
    /// interface and could otherwise receive the runtime's connection.
    fn validate_runtime_initiated_targets(
        authority: &str,
        addresses: &[std::net::SocketAddr],
        tls: &openshell_sandbox_backend::boundary_protocol::SandboxTlsServerConfig,
    ) -> Result<(), String> {
        let Some(first) = addresses.first() else {
            return Err("runtime-initiated control requires a supervisor address".to_string());
        };
        if authority.is_empty() || !tls_paths_are_absolute(tls) {
            return Err(
                "runtime-initiated control requires an authority and absolute certificate paths"
                    .to_string(),
            );
        }
        for address in addresses {
            let ip = address.ip().to_canonical();
            if address.port() == 0
                || address.port() != first.port()
                || ip.is_unspecified()
                || ip.is_loopback()
            {
                return Err(
                    "runtime-initiated supervisor addresses must be concrete, non-loopback, and share one nonzero port"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn tls_paths_are_absolute(
        tls: &openshell_sandbox_backend::boundary_protocol::SandboxTlsServerConfig,
    ) -> bool {
        tls.certificate_chain_path.is_absolute() && tls.private_key_path.is_absolute()
    }

    fn validate_runtime_resource_claims(config: &BoundaryConfig) -> Result<(), String> {
        for (claim, path) in &config.resource_claim_files {
            let expected = config
                .resource_claims
                .get(claim)
                .ok_or_else(|| format!("resource claim file has no expected value: {claim}"))?;
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

    fn allows_runtime_supplementary_groups(config: &BoundaryConfig) -> bool {
        config
            .resource_claims
            .get(GPU_RESOURCE_CLAIM)
            .is_some_and(|value| value == "true")
            || config
                .resource_claims
                .get(ALLOW_EXTRA_SUPPLEMENTARY_GROUPS_RESOURCE_CLAIM)
                .is_some_and(|value| value == "true")
    }

    fn supplementary_groups_match(actual: &[u32], expected: &[u32], allow_extra: bool) -> bool {
        if allow_extra {
            // GPU runtimes may add host device-access groups while materializing
            // an admitted GPU claim. They may extend, but never replace, the
            // image-derived identity asserted by the compute driver.
            expected.iter().all(|gid| actual.binary_search(gid).is_ok())
        } else {
            actual == expected
        }
    }

    #[allow(clippy::similar_names)]
    fn validate_running_identity(
        expected: &ResolvedWorkloadIdentity,
        allow_runtime_supplementary_groups: bool,
    ) -> Result<(), String> {
        let uid = nix::unistd::getresuid()
            .map_err(|error| format!("measure sandbox identity: {error}"))?;
        let gid = nix::unistd::getresgid()
            .map_err(|error| format!("measure sandbox identity: {error}"))?;
        if [uid.real, uid.effective, uid.saved]
            .iter()
            .any(|uid| uid.as_raw() != expected.uid)
            || [gid.real, gid.effective, gid.saved]
                .iter()
                .any(|gid| gid.as_raw() != expected.gid)
        {
            return Err(format!(
                "sandbox identity does not match resolved workload {}:{}",
                expected.uid, expected.gid
            ));
        }
        let groups = nix::unistd::getgroups()
            .map_err(|error| format!("read sandbox supplementary groups: {error}"))?
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .collect();
        let groups = normalized_supplementary_groups(groups, expected.gid);
        if !supplementary_groups_match(
            &groups,
            &expected.supplementary_gids,
            allow_runtime_supplementary_groups,
        ) {
            return Err(format!(
                "sandbox supplementary groups {groups:?} do not match resolved workload {:?}",
                expected.supplementary_gids
            ));
        }
        Ok(())
    }

    /// Shut down after SIGTERM/SIGINT; `None` while no termination is pending.
    fn take_termination(runtime: &BoundaryRuntime) -> Option<Result<(), String>> {
        if !BOUNDARY_TERMINATION_REQUESTED.load(Ordering::Acquire) {
            return None;
        }
        let signal = BOUNDARY_TERMINATION_SIGNAL.load(Ordering::Acquire);
        let before_supervisor_confirmation = !matches!(
            *lock(&runtime.supervisor_connection),
            SupervisorConnectionState::Connected(_)
        );
        runtime.shutdown();
        if before_supervisor_confirmation {
            return Some(Err(format!(
                "sandbox boundary received {} before supervisor confirmation",
                boundary_termination_signal_name(signal)
            )));
        }
        tracing::info!(
            signal = boundary_termination_signal_name(signal),
            "Sandbox boundary received termination signal"
        );
        Some(Ok(()))
    }

    fn serve(config: &BoundaryListenerConfig, runtime: Arc<BoundaryRuntime>) -> Result<(), String> {
        let dial_tls = match config {
            BoundaryListenerConfig::RuntimeInitiatedTlsTcp { tls, .. }
            | BoundaryListenerConfig::RuntimeInitiatedUnix { tls, .. }
            | BoundaryListenerConfig::RuntimeInitiatedVsock { tls, .. } => Some(tls),
            _ => None,
        };
        if let Some(tls) = dial_tls {
            return serve_runtime_initiated(config, tls, runtime);
        }
        let listener = ControlListener::bind(config)
            .map_err(|error| format!("bind boundary control listener: {error}"))?;
        let active_connections = Arc::new(AtomicUsize::new(0));
        let pending_handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
        tracing::info!(?config, "Boundary control listener ready");
        loop {
            if let Some(result) = take_termination(&runtime) {
                return result;
            }
            match listener.accept() {
                Ok(stream) => {
                    // Unauthenticated sockets use only a bounded async TLS
                    // task, never an OS thread or an authenticated session slot.
                    let Ok(pending) = pending_handshakes.clone().try_acquire_owned() else {
                        continue;
                    };
                    let active_connections = active_connections.clone();
                    let runtime = runtime.clone();
                    runtime.process_runtime.spawn({
                        let runtime = runtime.clone();
                        async move {
                            if let Err(error) = serve_control_connection(
                                stream,
                                runtime,
                                pending,
                                active_connections,
                            )
                            .await
                            {
                                tracing::debug!(%error, "Boundary control connection ended");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // A refused or already-dead peer must not stop the listener.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("accept boundary control connection: {error}")),
            }
        }
    }

    /// Runtime-initiated control: dial the supervisor instead of listening.
    /// TLS server and gRPC server roles are the same as for a listener.
    fn serve_runtime_initiated(
        config: &BoundaryListenerConfig,
        tls: &openshell_sandbox_backend::boundary_protocol::SandboxTlsServerConfig,
        runtime: Arc<BoundaryRuntime>,
    ) -> Result<(), String> {
        let server_config = Arc::new(
            load_tls_server_config(tls)
                .map_err(|error| format!("load boundary TLS identity: {error}"))?,
        );
        tracing::info!(?config, "Boundary control dialer ready");
        let dialer = runtime.process_runtime.spawn(run_runtime_initiated_control(
            config.clone(),
            server_config,
            runtime.clone(),
            Arc::new(AtomicUsize::new(0)),
        ));
        loop {
            if let Some(result) = take_termination(&runtime) {
                dialer.abort();
                return result;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Keep exactly one unclaimed spare connection open to the supervisor.
    ///
    /// The supervisor claims a spare by starting HTTP/2 on it; then the next
    /// spare is dialed so credential rotation and recovery, which open a new
    /// connection before retiring the old one, never wait on this loop. TLS
    /// failures back off like dial failures. Established spares are served
    /// like accepted connections: same identity, slot limit, and disconnect,
    /// freeze, and termination handling. A runtime of a supervisor shared by
    /// several sandboxes keeps its spares as [`run_routed_runtime_control`]
    /// describes.
    async fn run_runtime_initiated_control(
        config: BoundaryListenerConfig,
        server_config: Arc<rustls::ServerConfig>,
        runtime: Arc<BoundaryRuntime>,
        active_connections: Arc<AtomicUsize>,
    ) {
        if let BoundaryListenerConfig::RuntimeInitiatedTlsTcp {
            addresses,
            route: Some(route),
            ..
        } = &config
        {
            return run_routed_runtime_control(
                SupervisorRoute {
                    addresses: addresses.clone(),
                    route: route.clone(),
                },
                server_config,
                runtime,
                active_connections,
                POOL_ROUTE_DISCOVERY_INTERVAL,
            )
            .await;
        }
        let mut backoff = RUNTIME_DIAL_BACKOFF_MIN;
        let mut warn_at: Option<tokio::time::Instant> = None;
        loop {
            let established =
                match tokio::time::timeout(RUNTIME_DIAL_TIMEOUT, dial_supervisor(&config))
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "supervisor dial timed out",
                        ))
                    }) {
                    Ok(stream) => ControlStream::PendingTls {
                        stream,
                        server_config: server_config.clone(),
                    }
                    .establish_async(&runtime.process_runtime)
                    .await
                    .map_err(|error| format!("authenticate boundary transport: {error}")),
                    Err(error) => Err(format!("dial supervisor: {error}")),
                };
            let healthy = match established {
                Ok(stream) => {
                    warn_at = None;
                    let established_at = tokio::time::Instant::now();
                    let (claimed, claim) = tokio::sync::oneshot::channel();
                    let served = serve_authenticated_connection(
                        stream,
                        runtime.clone(),
                        active_connections.clone(),
                        Some(claimed),
                        None,
                    );
                    runtime.process_runtime.spawn(async move {
                        if let Err(error) = served.await {
                            tracing::debug!(%error, "Boundary control connection ended");
                        }
                    });
                    // A used spare, or one that stayed open, needs no backoff.
                    claim.await.is_ok() || established_at.elapsed() >= RUNTIME_SPARE_MIN_LIFETIME
                }
                Err(error) => {
                    report_runtime_dial_failure(&mut warn_at, &error);
                    false
                }
            };
            if healthy {
                backoff = RUNTIME_DIAL_BACKOFF_MIN;
            } else {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RUNTIME_DIAL_BACKOFF_MAX);
            }
        }
    }

    /// Failures are expected while the supervisor starts; report a persistent
    /// one at most once per interval.
    fn report_runtime_dial_failure(
        warn_at: &mut Option<tokio::time::Instant>,
        error: &dyn std::fmt::Display,
    ) {
        let now = tokio::time::Instant::now();
        if now >= *warn_at.get_or_insert(now + RUNTIME_DIAL_WARNING_INTERVAL) {
            *warn_at = Some(now + RUNTIME_DIAL_WARNING_INTERVAL);
            tracing::warn!(%error, "Runtime-initiated control cannot reach the supervisor; retrying");
        } else {
            tracing::debug!(%error, "Runtime-initiated control dial failed; retrying");
        }
    }

    /// Dial only driver-provided addresses of a dedicated supervisor from the
    /// bootstrap. A shared supervisor is reached through
    /// [`run_routed_runtime_control`] instead.
    async fn dial_supervisor(config: &BoundaryListenerConfig) -> io::Result<PlainControlStream> {
        match config {
            BoundaryListenerConfig::RuntimeInitiatedTlsTcp { addresses, .. } => {
                let stream = connect_supervisor(addresses).await?;
                Ok(PlainControlStream::Tcp(stream.into_std()?))
            }
            BoundaryListenerConfig::RuntimeInitiatedUnix { socket_path, .. } => {
                Ok(PlainControlStream::Unix(
                    tokio::net::UnixStream::connect(socket_path)
                        .await?
                        .into_std()?,
                ))
            }
            BoundaryListenerConfig::RuntimeInitiatedVsock { host_port, .. } => {
                let socket =
                    socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
                socket.set_nonblocking(true)?;
                match socket.connect(&socket2::SockAddr::vsock(libc::VMADDR_CID_HOST, *host_port)) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
                    Err(error) => return Err(error),
                }
                let stream =
                    tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(socket))?;
                stream.writable().await?;
                if let Some(error) = stream.take_error()? {
                    return Err(error);
                }
                Ok(PlainControlStream::Unix(stream.into_std()?))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control transport does not dial",
            )),
        }
    }

    /// Connect to the first reachable supervisor address. Keepalive detects a
    /// supervisor that vanishes while a spare sits idle.
    async fn connect_supervisor(
        addresses: &[std::net::SocketAddr],
    ) -> io::Result<tokio::net::TcpStream> {
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(addresses).await?;
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(10))
            .with_interval(Duration::from_secs(5))
            .with_retries(3);
        let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
        Ok(stream)
    }

    /// Where a runtime of a shared supervisor dials: the configured supervisor
    /// addresses (the shared supervisor's Service) and its route handle.
    struct SupervisorRoute {
        addresses: Vec<std::net::SocketAddr>,
        route: String,
    }

    /// An authenticated connection a supervisor has not used yet.
    struct RouteSpare {
        member: std::net::SocketAddr,
        claimed: tokio::sync::oneshot::Receiver<()>,
        established_at: tokio::time::Instant,
    }

    /// Unclaimed spares of a routed runtime, at most one per supervisor pool
    /// member; a lone shared supervisor is one member. A member's address
    /// grants nothing: a member whose earlier term was fenced may hold a
    /// later one, which only its signed grant proves, so every member may be
    /// offered a spare and stale credentials are refused on it.
    #[derive(Default)]
    struct RouteSpares {
        unclaimed: Vec<RouteSpare>,
        /// The member whose connection the runtime confirmed last.
        owner: Option<std::net::SocketAddr>,
        /// A supervisor named itself as a pool member or redirected this
        /// runtime: its route can move to another member, so discovery runs.
        pooled: bool,
    }

    impl RouteSpares {
        fn holds(&self, member: std::net::SocketAddr) -> bool {
            self.unclaimed.iter().any(|spare| spare.member == member)
        }

        /// Whether `member` may be given another spare.
        fn admits(&self, member: std::net::SocketAddr) -> bool {
            self.unclaimed.len() < POOL_MAX_UNCLAIMED_SPARES && !self.holds(member)
        }

        /// Whether the confirmed owner, or before one is confirmed any
        /// member, lacks a spare.
        fn wants_spare(&self) -> bool {
            self.unclaimed.len() < POOL_MAX_UNCLAIMED_SPARES
                && self
                    .owner
                    .map_or(self.unclaimed.is_empty(), |owner| !self.holds(owner))
        }

        /// The next spare its member used (`true`) or that closed unused.
        async fn next_settled(&mut self) -> (RouteSpare, bool) {
            if self.unclaimed.is_empty() {
                return std::future::pending().await;
            }
            let (index, claimed) = std::future::poll_fn(|context| {
                for (index, spare) in self.unclaimed.iter_mut().enumerate() {
                    if let Poll::Ready(result) = Future::poll(Pin::new(&mut spare.claimed), context)
                    {
                        return Poll::Ready((index, result.is_ok()));
                    }
                }
                Poll::Pending
            })
            .await;
            (self.unclaimed.swap_remove(index), claimed)
        }
    }

    /// Keep a runtime of a shared supervisor reachable by whichever
    /// supervisor owns its route.
    ///
    /// Every dial names the route in a version 2 preface. A spare waits at
    /// the member whose connection the runtime confirmed last, its
    /// authenticated owner, or wherever the configured addresses lead before
    /// one is confirmed; an unauthenticated accept never makes a member the
    /// owner. In a supervisor pool a previous owner can stay reachable, and
    /// keep its spare unused, after the gateway granted the route to another
    /// member, so once a supervisor names itself a pool member or redirects
    /// this runtime, discovery rounds also dial the configured addresses past
    /// every known member: a member found hosting the route without a spare
    /// gets one, on which it can authenticate its takeover. A lone shared
    /// supervisor is never probed. Spares are bounded per member and in
    /// total, and established connections are never closed to refresh
    /// routing.
    async fn run_routed_runtime_control(
        pool: SupervisorRoute,
        server_config: Arc<rustls::ServerConfig>,
        runtime: Arc<BoundaryRuntime>,
        active_connections: Arc<AtomicUsize>,
        discovery_interval: Duration,
    ) {
        let mut spares = RouteSpares::default();
        let mut backoff = RUNTIME_DIAL_BACKOFF_MIN;
        let mut retry_at = tokio::time::Instant::now();
        let mut warn_at: Option<tokio::time::Instant> = None;
        let mut discovery = tokio::time::interval_at(
            tokio::time::Instant::now() + discovery_interval,
            discovery_interval,
        );
        discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            spares.owner = runtime.confirmed_route_owner();
            if spares.wants_spare() && tokio::time::Instant::now() >= retry_at {
                let dialed = tokio::time::timeout(
                    RUNTIME_DIAL_TIMEOUT,
                    dial_route_owner(&pool.addresses, &pool.route, spares.owner),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "supervisor dial timed out",
                    ))
                });
                let started = match dialed {
                    Ok(dialed) => {
                        spares.pooled |= dialed.shows_pool();
                        if spares.admits(dialed.member) {
                            start_route_spare(dialed, &server_config, &runtime, &active_connections)
                                .await
                                .map(Some)
                        } else {
                            // The addresses led to a member that already
                            // holds a spare; discovery tries again.
                            Ok(None)
                        }
                    }
                    Err(error) => Err(error),
                };
                match started {
                    Ok(Some(spare)) => {
                        warn_at = None;
                        spares.unclaimed.push(spare);
                    }
                    Ok(None) => retry_at = tokio::time::Instant::now() + discovery_interval,
                    Err(error) => {
                        report_runtime_dial_failure(&mut warn_at, &error);
                        retry_at = tokio::time::Instant::now() + backoff;
                        backoff = (backoff * 2).min(RUNTIME_DIAL_BACKOFF_MAX);
                    }
                }
            }
            let waiting = spares.wants_spare() && retry_at > tokio::time::Instant::now();
            tokio::select! {
                (spare, claimed) = spares.next_settled() => {
                    if claimed {
                        // Replace a used spare at once.
                        backoff = RUNTIME_DIAL_BACKOFF_MIN;
                        retry_at = tokio::time::Instant::now();
                    } else if spare.established_at.elapsed() >= RUNTIME_SPARE_MIN_LIFETIME {
                        backoff = RUNTIME_DIAL_BACKOFF_MIN;
                    } else {
                        retry_at = tokio::time::Instant::now() + backoff;
                        backoff = (backoff * 2).min(RUNTIME_DIAL_BACKOFF_MAX);
                    }
                }
                _ = discovery.tick(), if spares.pooled => {
                    discover_route_owner(&pool, &mut spares, &server_config, &runtime, &active_connections)
                        .await;
                }
                () = tokio::time::sleep_until(retry_at), if waiting => {}
            }
        }
    }

    /// One discovery round: dial the configured addresses, past any known
    /// member, so a member that hosts the route without a spare gets one. A
    /// redirect to a member that already holds a spare means the pool's
    /// directory agrees with this runtime and ends the round.
    async fn discover_route_owner(
        pool: &SupervisorRoute,
        spares: &mut RouteSpares,
        server_config: &Arc<rustls::ServerConfig>,
        runtime: &Arc<BoundaryRuntime>,
        active_connections: &Arc<AtomicUsize>,
    ) {
        for _ in 0..POOL_ROUTE_DISCOVERY_PROBES {
            if spares.unclaimed.len() >= POOL_MAX_UNCLAIMED_SPARES {
                return;
            }
            let Ok(Ok(dialed)) = tokio::time::timeout(
                RUNTIME_DIAL_TIMEOUT,
                dial_route_owner(&pool.addresses, &pool.route, None),
            )
            .await
            else {
                return;
            };
            spares.pooled |= dialed.shows_pool();
            if spares.admits(dialed.member) {
                tracing::info!(
                    member = %dialed.member,
                    "Supervisor pool member hosts this runtime's route without a spare; opening one"
                );
                match start_route_spare(dialed, server_config, runtime, active_connections).await {
                    Ok(spare) => spares.unclaimed.push(spare),
                    Err(error) => {
                        tracing::debug!(%error, "Could not open a spare to a supervisor pool member");
                    }
                }
                return;
            }
            if dialed.redirected {
                return;
            }
        }
    }

    /// Complete the runtime's TLS handshake with a reached supervisor and
    /// serve the connection until the supervisor uses it or it closes.
    async fn start_route_spare(
        dialed: DialedMember,
        server_config: &Arc<rustls::ServerConfig>,
        runtime: &Arc<BoundaryRuntime>,
        active_connections: &Arc<AtomicUsize>,
    ) -> io::Result<RouteSpare> {
        let stream = ControlStream::PendingTls {
            stream: PlainControlStream::Tcp(dialed.stream.into_std()?),
            server_config: server_config.clone(),
        }
        .establish_async(&runtime.process_runtime)
        .await?;
        let (claimed_tx, claimed) = tokio::sync::oneshot::channel();
        let served = serve_authenticated_connection(
            stream,
            runtime.clone(),
            active_connections.clone(),
            Some(claimed_tx),
            Some(dialed.member),
        );
        runtime.process_runtime.spawn(async move {
            if let Err(error) = served.await {
                tracing::debug!(%error, "Boundary control connection ended");
            }
        });
        Ok(RouteSpare {
            member: dialed.member,
            claimed,
            established_at: tokio::time::Instant::now(),
        })
    }

    /// A supervisor that accepted this runtime's route.
    struct DialedMember {
        /// The member's runtime listener as it names itself, or the address
        /// dialed when it names none.
        member: std::net::SocketAddr,
        stream: tokio::net::TcpStream,
        /// The supervisor named itself, as only a pool member does.
        named: bool,
        /// A member's route directory led here.
        redirected: bool,
    }

    impl DialedMember {
        /// Whether reaching this supervisor showed it belongs to a pool.
        fn shows_pool(&self) -> bool {
            self.named || self.redirected
        }
    }

    /// Find a supervisor pool member that hosts `route`: `preferred` first,
    /// then each configured address, following at most
    /// [`MAX_RUNTIME_ROUTE_REDIRECTS`] redirects from each.
    ///
    /// Replies are unauthenticated hints, so they only lead where a
    /// configured address could (see [`route_redirect_allowed`]), and an
    /// accept names a member without making it the owner. The member still
    /// has to complete the generation-pinned TLS handshake, and every request
    /// still carries the instance's bearer token.
    async fn dial_route_owner(
        addresses: &[std::net::SocketAddr],
        route: &str,
        preferred: Option<std::net::SocketAddr>,
    ) -> io::Result<DialedMember> {
        use openshell_sandbox_backend::runtime_routed::RouteReply;

        let candidates = preferred.into_iter().chain(
            addresses
                .iter()
                .copied()
                .filter(|address| Some(*address) != preferred),
        );
        let mut failure = io::Error::new(
            io::ErrorKind::NotFound,
            "no supervisor address is configured",
        );
        for candidate in candidates {
            let mut target = candidate;
            let mut redirects = 0;
            failure = loop {
                let (stream, reply) = match negotiate_route_at(target, route).await {
                    Ok(negotiated) => negotiated,
                    Err(error) => break error,
                };
                match reply {
                    RouteReply::Accept(named) => {
                        let member = named
                            .filter(|named| route_redirect_allowed(*named, addresses))
                            .unwrap_or(target);
                        return Ok(DialedMember {
                            member,
                            stream,
                            named: named.is_some(),
                            redirected: redirects > 0,
                        });
                    }
                    RouteReply::Redirect(_) if redirects == MAX_RUNTIME_ROUTE_REDIRECTS => {
                        break io::Error::new(
                            io::ErrorKind::InvalidData,
                            "supervisor route redirects exceeded the hop limit",
                        );
                    }
                    RouteReply::Redirect(owner) if !route_redirect_allowed(owner, addresses) => {
                        break io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("refused supervisor route redirect to {owner}"),
                        );
                    }
                    RouteReply::Redirect(owner) => {
                        tracing::debug!(%target, %owner, "Following supervisor route redirect");
                        redirects += 1;
                        target = owner;
                    }
                    RouteReply::Unknown => {
                        break io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("supervisor {target} does not know this runtime's route"),
                        );
                    }
                }
            };
            tracing::debug!(
                error = %failure,
                %candidate,
                "Supervisor address did not accept this runtime's route"
            );
        }
        Err(failure)
    }

    /// Connect to one supervisor address and negotiate `route` there.
    ///
    /// A shared supervisor from before route negotiation closes a version 2
    /// preface without replying; it reads only the preface header, so the
    /// close usually arrives as a reset. That address is then reached again with the
    /// version 1 preface, which such a supervisor routes to its local
    /// registration of the route, and the dial reads as an accept that names
    /// no member: no pool evidence, so no discovery. The fallback changes only
    /// routing; the supervisor still has to complete the generation-pinned
    /// TLS handshake and authenticate every request, and a takeover still
    /// needs its signed grant.
    async fn negotiate_route_at(
        address: std::net::SocketAddr,
        route: &str,
    ) -> io::Result<(
        tokio::net::TcpStream,
        openshell_sandbox_backend::runtime_routed::RouteReply,
    )> {
        use openshell_sandbox_backend::runtime_routed::{
            RouteReply, encode_route_preface, negotiate_route,
        };

        tokio::time::timeout(RUNTIME_ROUTE_HOP_TIMEOUT, async {
            let mut stream = connect_supervisor(&[address]).await?;
            match negotiate_route(&mut stream, route).await {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    tracing::debug!(
                        %address,
                        "Supervisor closed the route negotiation without replying; using the version 1 preface"
                    );
                    let mut stream = connect_supervisor(&[address]).await?;
                    let preface = encode_route_preface(route).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                    })?;
                    stream.write_all(&preface).await?;
                    Ok((stream, RouteReply::Accept(None)))
                }
                negotiated => negotiated.map(|reply| (stream, reply)),
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("supervisor {address} did not answer the route negotiation"),
            ))
        })
    }

    /// A redirect may only lead where a configured address could: to the
    /// configured supervisor port, and to a loopback or unspecified address
    /// only when a configured address is one. Validation refuses those for
    /// configured addresses because workloads share the loopback interface.
    fn route_redirect_allowed(
        target: std::net::SocketAddr,
        addresses: &[std::net::SocketAddr],
    ) -> bool {
        let is_local = |address: std::net::SocketAddr| {
            let ip = address.ip().to_canonical();
            ip.is_loopback() || ip.is_unspecified()
        };
        addresses.iter().any(|address| {
            address.port() == target.port() && (!is_local(target) || is_local(*address))
        })
    }

    /// Signals once the supervisor sends its first application bytes.
    struct ClaimOnFirstRead {
        inner: openshell_isolation_interface::contract::BoundaryDuplexStream,
        claimed: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl tokio::io::AsyncRead for ClaimOnFirstRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.inner).poll_read(context, buffer);
            if matches!(result, Poll::Ready(Ok(())))
                && buffer.filled().len() > before
                && let Some(claimed) = self.claimed.take()
            {
                let _ = claimed.send(());
            }
            result
        }
    }

    impl tokio::io::AsyncWrite for ClaimOnFirstRead {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    fn boundary_termination_signal_name(signal: i32) -> &'static str {
        match signal {
            libc::SIGTERM => "SIGTERM",
            libc::SIGINT => "SIGINT",
            _ => "unknown signal",
        }
    }

    async fn serve_control_connection(
        stream: ControlStream,
        runtime: Arc<BoundaryRuntime>,
        pending: tokio::sync::OwnedSemaphorePermit,
        active_connections: Arc<AtomicUsize>,
    ) -> Result<(), String> {
        let stream = stream
            .establish_async(&runtime.process_runtime)
            .await
            .map_err(|error| format!("authenticate boundary transport: {error}"))?;
        drop(pending);
        serve_authenticated_connection(stream, runtime, active_connections, None, None).await
    }

    /// Serve one TLS-established connection, accepted or runtime-initiated.
    /// `claimed`, used by runtime-initiated spares, fires when the supervisor
    /// first sends data. `origin` names the supervisor pool member that
    /// accepted a pool runtime's connection.
    async fn serve_authenticated_connection(
        stream: ControlStream,
        runtime: Arc<BoundaryRuntime>,
        active_connections: Arc<AtomicUsize>,
        claimed: Option<tokio::sync::oneshot::Sender<()>>,
        origin: Option<std::net::SocketAddr>,
    ) -> Result<(), String> {
        let Some(_slot) = acquire_control_connection_slot(&active_connections) else {
            return Err("authenticated control connection limit reached".to_string());
        };
        let stream = stream.into_tokio()?;
        let stream = match claimed {
            Some(claimed) => Box::new(ClaimOnFirstRead {
                inner: stream,
                claimed: Some(claimed),
            }),
            None => stream,
        };
        let connection_id = SandboxConnectionId::new();
        let _origin =
            origin.map(|origin| ConnectionOrigin::record(&runtime, connection_id, origin));
        serve_grpc(stream, runtime, connection_id).await
    }

    /// The pool member a served connection came from, for as long as it is
    /// served.
    struct ConnectionOrigin {
        runtime: std::sync::Weak<BoundaryRuntime>,
        connection_id: SandboxConnectionId,
    }

    impl ConnectionOrigin {
        fn record(
            runtime: &Arc<BoundaryRuntime>,
            connection_id: SandboxConnectionId,
            origin: std::net::SocketAddr,
        ) -> Self {
            lock(&runtime.connection_origins).insert(connection_id, origin);
            Self {
                runtime: Arc::downgrade(runtime),
                connection_id,
            }
        }
    }

    impl Drop for ConnectionOrigin {
        fn drop(&mut self) {
            if let Some(runtime) = self.runtime.upgrade() {
                lock(&runtime.connection_origins).remove(&self.connection_id);
            }
        }
    }

    async fn serve_grpc(
        stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
        runtime: Arc<BoundaryRuntime>,
        connection_id: SandboxConnectionId,
    ) -> Result<(), String> {
        let (connection_shutdown, connection_closed) = tokio::sync::watch::channel(());
        runtime.register_connection(connection_id, connection_shutdown.clone());
        let connection_expiry = Arc::new(ConnectionExpiry::new(connection_shutdown.clone()));
        let incoming = tokio_stream::StreamExt::chain(
            tokio_stream::iter([Ok::<_, io::Error>(GrpcServerIo {
                stream,
                _connection_alive: connection_shutdown.clone(),
                _disconnect: TransportDisconnectGuard {
                    runtime: Arc::downgrade(&runtime),
                    connection_id,
                },
                retired: Box::pin({
                    let mut retired = connection_closed.clone();
                    async move {
                        let _ = retired.changed().await;
                        tokio::time::sleep(RETIRED_CONNECTION_GRACE).await;
                    }
                }),
                ended: false,
            })]),
            tokio_stream::pending(),
        );
        let mut shutdown = connection_closed.clone();
        let service = GrpcBoundaryService {
            runtime: runtime.clone(),
            connection_id,
            connection_expiry,
            connection_closed,
            negotiated: Arc::new(AtomicBool::new(false)),
            opened: Arc::new(AtomicBool::new(false)),
        };
        let result = tonic::transport::Server::builder()
            .http2_keepalive_interval(Some(CONTROL_KEEPALIVE_INTERVAL))
            .http2_keepalive_timeout(Some(CONTROL_KEEPALIVE_TIMEOUT))
            .max_concurrent_streams(BOUNDARY_MAX_CONCURRENT_STREAMS)
            .initial_stream_window_size(BOUNDARY_STREAM_WINDOW_BYTES)
            .initial_connection_window_size(BOUNDARY_CONNECTION_WINDOW_BYTES)
            .add_service(
                IsolationBackendServer::new(service.clone())
                    .max_decoding_message_size(64 * 1024)
                    .max_encoding_message_size(64 * 1024),
            )
            .add_service(
                SandboxProtocolServer::new(service)
                    .max_decoding_message_size(
                        openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                    )
                    .max_encoding_message_size(
                        openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                    ),
            )
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown.changed().await;
            })
            .await;
        runtime.transport_disconnected(connection_id);
        result.map_err(|error| format!("serve boundary gRPC connection: {error}"))
    }

    struct GrpcServerIo {
        stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
        // Dropping the actual HTTP/2 transport stops all detached stream
        // bridges, including on keepalive failure or task cancellation.
        _connection_alive: tokio::sync::watch::Sender<()>,
        _disconnect: TransportDisconnectGuard,
        /// Resolves a short grace after the connection is retired. A retired
        /// connection shuts down gracefully, but one whose peer never started
        /// HTTP/2, such as an unused spare, would wait for it forever; reads
        /// then end so the transport is dropped.
        retired: Pin<Box<dyn Future<Output = ()> + Send>>,
        ended: bool,
    }

    struct TransportDisconnectGuard {
        runtime: std::sync::Weak<BoundaryRuntime>,
        connection_id: SandboxConnectionId,
    }

    impl Drop for TransportDisconnectGuard {
        fn drop(&mut self) {
            if let Some(runtime) = self.runtime.upgrade() {
                runtime.transport_disconnected(self.connection_id);
            }
        }
    }

    impl tokio::io::AsyncRead for GrpcServerIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.ended || self.retired.as_mut().poll(context).is_ready() {
                self.ended = true;
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for GrpcServerIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    impl tonic::transport::server::Connected for GrpcServerIo {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    #[derive(Clone)]
    struct GrpcBoundaryService {
        runtime: Arc<BoundaryRuntime>,
        connection_id: SandboxConnectionId,
        connection_expiry: Arc<ConnectionExpiry>,
        connection_closed: tokio::sync::watch::Receiver<()>,
        negotiated: Arc<AtomicBool>,
        opened: Arc<AtomicBool>,
    }

    struct ConnectionExpiry {
        deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
        worker: tokio::task::AbortHandle,
    }

    impl ConnectionExpiry {
        fn new(connection_shutdown: tokio::sync::watch::Sender<()>) -> Self {
            let (deadline, deadline_updates) = tokio::sync::watch::channel(None);
            let worker = tokio::spawn(run_connection_expiry(deadline_updates, connection_shutdown))
                .abort_handle();
            Self { deadline, worker }
        }

        fn update(&self, expires_at: i64) {
            if expires_at == 0 {
                self.set_deadline(None);
                return;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let expires_at = u64::try_from(expires_at).unwrap_or_default();
            self.update_deadline(
                tokio::time::Instant::now() + Duration::from_secs(expires_at.saturating_sub(now)),
            );
        }

        fn update_deadline(&self, deadline: tokio::time::Instant) {
            self.set_deadline(Some(deadline));
        }

        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) {
            let _ = self.deadline.send_if_modified(|current| {
                if *current == deadline {
                    false
                } else {
                    *current = deadline;
                    true
                }
            });
        }
    }

    impl Drop for ConnectionExpiry {
        fn drop(&mut self) {
            self.worker.abort();
        }
    }

    async fn run_connection_expiry(
        mut deadline_updates: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
        connection_shutdown: tokio::sync::watch::Sender<()>,
    ) {
        loop {
            let deadline = *deadline_updates.borrow_and_update();
            let Some(deadline) = deadline else {
                if deadline_updates.changed().await.is_err() {
                    return;
                }
                continue;
            };
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    let _ = connection_shutdown.send(());
                    return;
                }
                result = deadline_updates.changed() => {
                    if result.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[tonic::async_trait]
    impl IsolationBackend for GrpcBoundaryService {
        async fn describe(
            &self,
            request: tonic::Request<DescribeIsolationBackendRequest>,
        ) -> Result<tonic::Response<DescribeIsolationBackendResponse>, tonic::Status> {
            let backend =
                openshell_sandbox_backend::isolation_protocol::metadata("openshell/sandbox");
            openshell_sandbox_backend::isolation_protocol::negotiate(
                &backend,
                request.into_inner().supervisor,
            )?;
            self.negotiated.store(true, Ordering::Release);
            Ok(tonic::Response::new(DescribeIsolationBackendResponse {
                backend: Some(backend),
            }))
        }

        async fn open_boundary(
            &self,
            request: tonic::Request<OpenBoundaryRequest>,
        ) -> Result<tonic::Response<OpenBoundaryResponse>, tonic::Status> {
            let principal = self
                .runtime
                .authenticate_request(self.connection_id, request.metadata())?;
            if !self.negotiated.load(Ordering::Acquire) {
                return Err(tonic::Status::failed_precondition(
                    "negotiate isolation capabilities before opening a boundary",
                ));
            }
            let request = request.into_inner();
            openshell_sandbox_backend::isolation_protocol::validate_open(
                &request,
                &self.runtime.config,
            )?;
            self.connection_expiry
                .update(principal.session().expires_at);
            self.opened.store(true, Ordering::Release);
            Ok(tonic::Response::new(OpenBoundaryResponse {
                boundary_id: self.runtime.routing_handle.clone(),
                outcome: LaunchOutcome::Fresh as i32,
            }))
        }

        async fn suspend_boundary(
            &self,
            request: tonic::Request<SuspendBoundaryRequest>,
        ) -> Result<tonic::Response<SuspendBoundaryResponse>, tonic::Status> {
            self.runtime
                .authenticate_request(self.connection_id, request.metadata())?;
            Err(tonic::Status::unimplemented(
                "OpenShell sandbox does not advertise suspend/resume",
            ))
        }

        async fn resume_boundary(
            &self,
            request: tonic::Request<ResumeBoundaryRequest>,
        ) -> Result<tonic::Response<OpenBoundaryResponse>, tonic::Status> {
            self.runtime
                .authenticate_request(self.connection_id, request.metadata())?;
            Err(tonic::Status::unimplemented(
                "OpenShell sandbox does not advertise suspend/resume",
            ))
        }
    }

    impl GrpcBoundaryService {
        async fn bind_stream<F: openshell_sandbox_backend::stream_adapter::ProtocolFrame>(
            &self,
            request: tonic::Request<tonic::Streaming<F>>,
        ) -> Result<(tonic::Streaming<F>, SandboxProtocolPrincipal), tonic::Status> {
            let principal = self
                .runtime
                .authenticate_request(self.connection_id, request.metadata())?;
            if !self.opened.load(Ordering::Acquire) {
                return Err(tonic::Status::failed_precondition(
                    "open a boundary before opening Sandbox Protocol streams",
                ));
            }
            self.connection_expiry
                .update(principal.session().expires_at);
            let mut inbound = request.into_inner();
            let frame = tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, inbound.message())
                .await
                .map_err(|_| {
                    tonic::Status::deadline_exceeded("boundary binding frame timed out")
                })??;
            match frame.as_ref().and_then(F::boundary_id) {
                Some(id) if id == self.runtime.routing_handle => {}
                Some(_) => {
                    return Err(tonic::Status::permission_denied(
                        "boundary handle does not match authenticated runtime",
                    ));
                }
                _ => {
                    return Err(tonic::Status::invalid_argument(
                        "first Sandbox Protocol frame must bind a boundary",
                    ));
                }
            }
            Ok((inbound, principal))
        }
    }

    type GrpcResponseStream<F = ExchangeFrame> = ReceiverStream<Result<F, tonic::Status>>;

    #[tonic::async_trait]
    impl SandboxProtocol for GrpcBoundaryService {
        type ExchangeStream = GrpcResponseStream;
        type MediateStream = GrpcResponseStream<MediateFrame>;

        async fn exchange(
            &self,
            request: tonic::Request<tonic::Streaming<ExchangeFrame>>,
        ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
            let (inbound, principal) = self.bind_stream(request).await?;
            let (stream, response) =
                bridge_grpc_server_stream(inbound, self.connection_closed.clone());
            let runtime = self.runtime.clone();
            tokio::task::spawn_blocking(move || {
                let stream = ControlStream::Grpc {
                    stream,
                    runtime: runtime.process_runtime.clone(),
                };
                if let Err(error) = serve_one(stream, &runtime, &principal) {
                    tracing::warn!(%error, "Boundary gRPC exchange failed");
                }
            });
            Ok(tonic::Response::new(response))
        }

        async fn mediate(
            &self,
            request: tonic::Request<tonic::Streaming<MediateFrame>>,
        ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
            let (inbound, principal) = self.bind_stream(request).await?;
            let (stream, response) =
                bridge_grpc_server_stream(inbound, self.connection_closed.clone());
            let runtime = self.runtime.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_persistent_mediation(stream, runtime, principal).await {
                    tracing::warn!(%error, "Persistent boundary mediation ended");
                }
            });
            Ok(tonic::Response::new(response))
        }
    }

    fn bridge_grpc_server_stream<F: openshell_sandbox_backend::stream_adapter::ProtocolFrame>(
        mut inbound: tonic::Streaming<F>,
        connection_closed: tokio::sync::watch::Receiver<()>,
    ) -> (tokio::io::DuplexStream, GrpcResponseStream<F>) {
        let (application, bridge) = tokio::io::duplex(256 * 1024);
        let (mut reader, mut writer) = tokio::io::split(bridge);
        let (outbound, outbound_rx) = tokio::sync::mpsc::channel::<Result<F, tonic::Status>>(64);
        // Do not retain the response sender while the client request direction
        // stays open: finite exchanges must still observe the server's EOF.
        let invalid_frames = outbound.downgrade();
        let mut inbound_closed = connection_closed.clone();
        tokio::spawn(async move {
            tokio::select! {
            _ = inbound_closed.changed() => {},
            () = async {
            let mut mode = openshell_sandbox_backend::stream_adapter::Mode::Request;
            loop {
                match inbound.message().await {
                    Ok(Some(chunk)) => {
                        let data = match chunk.receive(&mut mode).map_err(|error|tonic::Status::invalid_argument(error.to_string())) {
                            Ok(data) => data,
                            Err(error) => {
                                if let Some(outbound) = invalid_frames.upgrade() {
                                    let _ = outbound.send(Err(error)).await;
                                }
                                let _ = writer.shutdown().await;
                                return;
                            }
                        };
                        if writer.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = writer.shutdown().await;
                        return;
                    }
                    Err(error) => {
                        tracing::debug!(%error, "Boundary gRPC request stream ended");
                        return;
                    }
                }
            }
            } => {},
            }
        });
        let mut outbound_closed = connection_closed;
        tokio::spawn(async move {
            tokio::select! {
            _ = outbound_closed.changed() => {},
            () = async {
            let mut mode = openshell_sandbox_backend::stream_adapter::Mode::Response;
            loop {
                match F::send(&mut reader,&mut mode).await {
                    Ok(Some(chunk)) => if outbound.send(Ok(chunk)).await.is_err() { return; },
                    Ok(None) => return,
                    Err(error) => { let _=outbound.send(Err(tonic::Status::invalid_argument(error.to_string()))).await;return; }
                }
            }
            } => {},
            }
        });
        (application, ReceiverStream::new(outbound_rx))
    }

    const MEDIATION_EVENT_QUEUE: usize = 256;
    const MEDIATION_ROUTE_QUEUE: usize = 64;

    struct BoundaryOutboundFrame {
        kind: MediationFrameKind,
        stream_id: u64,
        payload: Vec<u8>,
    }

    type BoundaryMediationRoutes = Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<u64, tokio::sync::mpsc::Sender<MediationFrame>>,
        >,
    >;

    async fn serve_persistent_mediation(
        mut stream: tokio::io::DuplexStream,
        runtime: Arc<BoundaryRuntime>,
        principal: SandboxProtocolPrincipal,
    ) -> Result<(), String> {
        let request: RequestEnvelope = tokio::time::timeout(
            CONTROL_IO_TIMEOUT,
            openshell_sandbox_backend::boundary_protocol::read_frame_async(&mut stream),
        )
        .await
        .map_err(|_| "mediation attach timed out".to_string())?
        .map_err(|error| format!("read mediation attach: {error}"))?;
        let request_id = request.request_id.clone();
        let owner = runtime
            .authorize_request_async(&principal, &request.request)
            .await?;
        if !matches!(request.request, Request::OpenMediation) {
            return Err("persistent mediation stream omitted OpenMediation".to_string());
        }
        let mut response = runtime.dispatch(request);
        drop(owner);
        let lease = if matches!(response, Response::MediationReady) {
            tokio::time::timeout(
                MEDIATION_REPLACEMENT_TIMEOUT,
                runtime.mediation_active.lock(),
            )
            .await
            .map_or_else(
                |_| {
                    response = guest_error(
                        BoundaryErrorKind::Denied,
                        "a mediation session is already active",
                    );
                    None
                },
                Some,
            )
        } else {
            None
        };
        let response_frame = encode_frame(&ResponseEnvelope {
            request_id,
            response,
        })
        .map_err(|error| format!("encode mediation attach response: {error}"))?;
        stream
            .write_all(&response_frame)
            .await
            .map_err(|error| format!("write mediation attach response: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("flush mediation attach response: {error}"))?;
        let Some(_lease) = lease else {
            return Ok(());
        };
        let broker = runtime.network_accept_context()?;
        run_boundary_mediation(stream, runtime.clone(), broker, principal).await
    }

    async fn run_boundary_mediation(
        stream: tokio::io::DuplexStream,
        runtime: Arc<BoundaryRuntime>,
        broker: NetworkBroker,
        principal: SandboxProtocolPrincipal,
    ) -> Result<(), String> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<BoundaryOutboundFrame>(MEDIATION_EVENT_QUEUE);
        let routes: BoundaryMediationRoutes =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let writer_task = async {
            while let Some(frame) = outbound_rx.recv().await {
                mediation::write_frame(&mut writer, frame.kind, frame.stream_id, &frame.payload)
                    .await
                    .map_err(|error| format!("write persistent mediation frame: {error}"))?;
            }
            Ok::<(), String>(())
        };
        let reader_routes = routes.clone();
        let reader_task = async {
            while let Some(frame) = mediation::read_frame(&mut reader)
                .await
                .map_err(|error| format!("read persistent mediation frame: {error}"))?
            {
                let route = reader_routes.lock().await.get(&frame.stream_id).cloned();
                if let Some(route) = route {
                    let _ = route.send(frame).await;
                }
            }
            Ok::<(), String>(())
        };
        let accept_task = run_boundary_accepts(
            runtime,
            broker,
            outbound_tx.clone(),
            routes.clone(),
            principal,
        );
        tokio::pin!(writer_task);
        tokio::pin!(reader_task);
        tokio::pin!(accept_task);
        let result = tokio::select! {
            result = &mut writer_task => result,
            result = &mut reader_task => result,
            result = &mut accept_task => result,
        };
        routes.lock().await.clear();
        result
    }

    async fn run_boundary_accepts(
        runtime: Arc<BoundaryRuntime>,
        broker: NetworkBroker,
        outbound: tokio::sync::mpsc::Sender<BoundaryOutboundFrame>,
        routes: BoundaryMediationRoutes,
        principal: SandboxProtocolPrincipal,
    ) -> Result<(), String> {
        loop {
            let pending = broker
                .accept_dns()
                .await
                .map_err(|error| format!("accept sandbox DNS query: {error}"))?;
            let stream_id = runtime
                .next_mediation_stream_id
                .fetch_add(1, Ordering::Relaxed);
            let (route_tx, route_rx) = tokio::sync::mpsc::channel(MEDIATION_ROUTE_QUEUE);
            routes.lock().await.insert(stream_id, route_tx);
            tokio::spawn(run_boundary_dns_stream(
                stream_id,
                pending,
                route_rx,
                outbound.clone(),
                routes.clone(),
                (runtime.clone(), principal.clone()),
            ));
        }
    }

    async fn run_boundary_dns_stream(
        stream_id: u64,
        pending: crate::network_broker::PendingDnsQuery,
        mut inbound: tokio::sync::mpsc::Receiver<MediationFrame>,
        outbound: tokio::sync::mpsc::Sender<BoundaryOutboundFrame>,
        routes: BoundaryMediationRoutes,
        (runtime, principal): (Arc<BoundaryRuntime>, SandboxProtocolPrincipal),
    ) {
        let query = DnsQueryWire {
            request: pending.request.clone(),
            transport: pending.transport,
            identity: BinaryIdentityWire::from(pending.identity.clone()),
            timing: MediationTimingWire {
                notification_to_queue_us: duration_micros(pending.notification_to_queue),
                queue_wait_us: duration_micros(pending.queued_at.elapsed()),
            },
        };
        let Ok(payload) = mediation::encode_message(&query) else {
            routes.lock().await.remove(&stream_id);
            return;
        };
        if outbound
            .send(BoundaryOutboundFrame {
                kind: MediationFrameKind::DnsQuery,
                stream_id,
                payload,
            })
            .await
            .is_err()
        {
            routes.lock().await.remove(&stream_id);
            return;
        }
        let result = match inbound.recv().await {
            Some(MediationFrame {
                kind: MediationFrameKind::DnsResponse,
                payload,
                ..
            }) => mediation::decode_message::<DnsQueryResultWire>(&payload)
                .map_err(io::Error::other)
                .and_then(|response| match response {
                    DnsQueryResultWire::Response(response) => Ok(response),
                    DnsQueryResultWire::Error(error) => Err(io::Error::other(error)),
                }),
            _ => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mediation session ended before DNS response",
            )),
        };
        // Answer only for the owner in force; a replaced owner's answer fails.
        {
            let current = runtime.owner_operation_async(&principal).await;
            let result = if current.is_ok() {
                result
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the supervisor that answered is no longer the owner",
                ))
            };
            let _ = pending.complete(result);
        }
        routes.lock().await.remove(&stream_id);
    }

    fn serve_one(
        mut stream: ControlStream,
        runtime: &BoundaryRuntime,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), String> {
        stream
            .set_timeout(CONTROL_IO_TIMEOUT)
            .map_err(|error| format!("set control timeout: {error}"))?;
        let request: RequestEnvelope =
            read_frame(&mut stream).map_err(|error| format!("read control frame: {error}"))?;
        // Held until the operation takes effect; see `BoundaryRuntime::ownership`.
        let owner = runtime.authorize_request(principal, &request.request)?;
        if request.validate_payload_digest().is_err() {
            let response = ResponseEnvelope {
                request_id: request.request_id,
                response: guest_error(
                    BoundaryErrorKind::Denied,
                    "control request payload digest mismatch",
                ),
            };
            return write_frame(&mut stream, &response)
                .map_err(|error| format!("write control frame: {error}"));
        }
        match request.request.clone() {
            Request::TerminateBoundary => {
                let response = runtime
                    .process_runtime
                    .block_on(runtime.terminate_boundary());
                drop(owner);
                return write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response,
                    },
                )
                .map_err(|error| format!("write boundary termination response: {error}"));
            }
            Request::Exec { spec } => {
                let started = runtime.start_exec(
                    &request.request_id,
                    &request.payload_digest,
                    request.exec_admission_deadline_unix_ms,
                    spec,
                );
                // The exec has started or failed; its output streams outside
                // the ownership guard.
                drop(owner);
                let started = match started {
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
                let attachment = runtime.attach_process(&process_id);
                drop(owner);
                let (attachment, terminal) = match attachment {
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
            Request::LoopbackConnect { host, port } => {
                let target = LoopbackTarget::new(host, port)
                    .map_err(|error| format!("validate port-forward target: {error}"))
                    .and_then(|target| {
                        runtime
                            .connect_port(target)
                            .map_err(|error| format!("connect boundary loopback port: {error}"))
                    });
                drop(owner);
                let target = match target {
                    Ok(target) => target,
                    Err(error) => {
                        write_frame(
                            &mut stream,
                            &ResponseEnvelope {
                                request_id: request.request_id,
                                response: guest_error(BoundaryErrorKind::Process, error),
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
                        response: Response::LoopbackConnected,
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
                // Waiting for an open does not hold the ownership guard; the
                // decision is admitted again when it is applied.
                drop(owner);
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
                    // Executables keep their first offered digest across
                    // supervisor owners; a contradiction is never offered.
                    let identity = runtime.binary_pins.admit(pending.identity.clone());
                    let response = encode_frame(&ResponseEnvelope {
                        request_id,
                        response: Response::NetworkConnected {
                            identity: BinaryIdentityWire::from(identity),
                            destination: pending.destination,
                            socket: Some(pending.socket),
                            policy_generation: 0,
                            timing: MediationTimingWire {
                                notification_to_queue_us: duration_micros(
                                    pending.notification_to_queue,
                                ),
                                queue_wait_us: duration_micros(pending.queued_at.elapsed()),
                            },
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
                    let decision = openshell_sandbox_backend::protobuf::decode(&payload)
                        .map_err(|error| format!("decode network-open decision: {error}"))?;
                    // Apply the decision only while its supervisor is the
                    // owner in force; a replaced owner's decision is denied.
                    let decided = {
                        let current = runtime.owner_operation_async(principal).await;
                        let decision = if current.is_ok() {
                            decision
                        } else {
                            openshell_isolation_interface::contract::TcpOpenDecision::Denied(
                                openshell_isolation_interface::contract::TcpOpenDenial::MediationUnavailable,
                            )
                        };
                        pending.decide(decision)
                    }
                    .map_err(|error| format!("complete sandbox network open: {error}"))?;
                    let Some(target) = decided
                        .established()
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
            _ => {}
        }
        let (supervisor_instance_id, supervisor_takeover, recovery_offer) = match &request.request {
            Request::Attach {
                supervisor_instance_id,
                supervisor_takeover,
                supervisor_recovery_timeout_secs,
                ..
            } => (
                Some(*supervisor_instance_id),
                supervisor_takeover.clone(),
                *supervisor_recovery_timeout_secs,
            ),
            _ => (None, None, None),
        };
        let is_attach = supervisor_instance_id.is_some();
        let is_confirm = matches!(&request.request, Request::Confirm);
        // A recovery deadline outside the bounds is refused before the attach
        // can touch the boundary: recovery is always bounded.
        let recovery_offer = match recovery_offer {
            None => None,
            Some(seconds) => {
                let Some(offer) =
                    openshell_sandbox_backend::boundary_protocol::supervisor_recovery_timeout(
                        seconds,
                    )
                else {
                    let range =
                        openshell_sandbox_backend::boundary_protocol::SUPERVISOR_RECOVERY_TIMEOUT_RANGE;
                    return write_frame(
                        &mut stream,
                        &ResponseEnvelope {
                            request_id: request.request_id,
                            response: guest_error(
                                BoundaryErrorKind::Invalid,
                                format!(
                                    "supervisor recovery timeout must be between {} and {} seconds",
                                    range.start(),
                                    range.end()
                                ),
                            ),
                        },
                    )
                    .map_err(|error| format!("write control frame: {error}"));
                };
                Some(offer)
            }
        };
        // Attach and confirm are serialized, so what an attach's precheck
        // admits still holds when it commits.
        let _admission = (is_attach || is_confirm).then(|| lock(&runtime.admission));
        let denied = |stream: &mut ControlStream, request_id: String, message: String| {
            write_frame(
                stream,
                &ResponseEnvelope {
                    request_id,
                    response: guest_error(BoundaryErrorKind::Denied, message),
                },
            )
            .map_err(|error| format!("write control frame: {error}"))
        };
        // A takeover grant is verified before the attach can touch the
        // boundary; an invalid grant is refused like any other credential.
        let takeover = match supervisor_takeover
            .as_deref()
            .map(|grant| runtime.authenticator.verify_takeover(grant))
            .transpose()
        {
            Ok(takeover) => takeover,
            Err(error) => {
                emit_takeover_denial(&error.to_string(), None);
                return denied(&mut stream, request.request_id, error.to_string());
            }
        };
        // Refuse an attach the registry would refuse before the boundary
        // binds anything for it.
        if let Some(supervisor_instance_id) = supervisor_instance_id
            && let Err(error) = runtime.connections.check_attach(
                principal,
                supervisor_instance_id,
                takeover.as_ref(),
            )
        {
            if takeover.is_some() || attach_denial_is_takeover(&error) {
                emit_takeover_denial(&error.to_string(), takeover.as_ref());
            }
            let (kind, message) = connection_auth_error(error);
            return write_frame(
                &mut stream,
                &ResponseEnvelope {
                    request_id: request.request_id,
                    response: guest_error(kind, message),
                },
            )
            .map_err(|error| format!("write control frame: {error}"));
        }
        let mut response = ResponseEnvelope {
            request_id: request.request_id.clone(),
            response: runtime.dispatch(request),
        };
        drop(owner);
        // Report commit failures to the supervisor: a silently closed stream
        // is indistinguishable from transport loss.
        if is_attach && matches!(&response.response, Response::Attached { .. }) {
            let supervisor_instance_id = supervisor_instance_id
                .ok_or_else(|| "attach request lost supervisor instance identity".to_string())?;
            if let Err((kind, message)) = runtime.commit_attach(
                principal,
                supervisor_instance_id,
                takeover.as_ref(),
                recovery_offer,
            ) {
                if takeover.is_some() {
                    emit_takeover_denial(&message, takeover.as_ref());
                }
                response.response = guest_error(kind, message);
            }
        }
        if is_confirm
            && matches!(&response.response, Response::Confirmed { .. })
            && let Err((kind, message)) = runtime.commit_confirm(principal)
        {
            response.response = guest_error(kind, message);
        }
        write_frame(&mut stream, &response)
            .map_err(|error| format!("write control frame: {error}"))?;
        Ok(())
    }

    /// Writes the sandbox's writable filesystem to its backing store.
    type FlushFn = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

    /// Filesystem flush operation and its termination wait bound.
    struct FilesystemFlush {
        run: FlushFn,
        timeout: Duration,
    }

    impl FilesystemFlush {
        /// VM page caches disappear at shutdown. Container page caches survive
        /// in the host, where `syncfs` would flush the shared backing filesystem.
        fn for_listener(listener: &BoundaryListenerConfig) -> Option<Self> {
            match listener {
                BoundaryListenerConfig::Vsock { .. }
                | BoundaryListenerConfig::RuntimeInitiatedVsock { .. } => Some(Self {
                    run: Arc::new(flush_root_filesystem),
                    timeout: FILESYSTEM_FLUSH_TIMEOUT,
                }),
                BoundaryListenerConfig::Unix { .. }
                | BoundaryListenerConfig::TlsTcp { .. }
                | BoundaryListenerConfig::RuntimeInitiatedTlsTcp { .. }
                | BoundaryListenerConfig::RuntimeInitiatedUnix { .. } => None,
            }
        }
    }

    /// Flush the filesystem mounted at `/`, which in the VM holds the sandbox's
    /// writable layer.
    fn flush_root_filesystem() -> io::Result<()> {
        sync_filesystem_at(Path::new("/"))
    }

    /// Write back the filesystem that contains `path`. `syncfs` is used instead
    /// of a global `sync` so only that filesystem is flushed.
    fn sync_filesystem_at(path: &Path) -> io::Result<()> {
        let directory = File::open(path)?;
        nix::unistd::syncfs(directory.as_raw_fd()).map_err(io::Error::from)
    }

    /// Admission of one owner operation; see `BoundaryRuntime::ownership`.
    type OwnershipGuard<'a> = tokio::sync::RwLockReadGuard<'a, ()>;

    struct BoundaryRuntime {
        config: BoundaryConfig,
        routing_handle: String,
        authenticator: SandboxProtocolAuthenticator,
        connections: SandboxConnectionRegistry,
        connection_shutdowns:
            Mutex<std::collections::HashMap<SandboxConnectionId, tokio::sync::watch::Sender<()>>>,
        process_runtime: tokio::runtime::Handle,
        state: Mutex<RuntimeState>,
        supervisor_connection: Mutex<SupervisorConnectionState>,
        /// VM-only termination flush.
        filesystem_flush: Option<FilesystemFlush>,
        /// How long a workload stays frozen without supervision before it is
        /// terminated, unless the connection in force negotiated a deadline.
        default_recovery_timeout: Duration,
        /// Recovery deadlines supervisors offered when their connections
        /// attached; the deadline of the connection in force governs the
        /// freeze that follows its loss. Entries live as long as their
        /// connections.
        recovery_offers: Mutex<std::collections::HashMap<SandboxConnectionId, Duration>>,
        /// Recovery deadlines of the freezes this runtime started.
        #[cfg(test)]
        scheduled_recoveries: Mutex<Vec<Duration>>,
        /// Serializes attach and confirm, so a candidate's registry checks
        /// hold from its precheck, before it touches the boundary, through
        /// its commit.
        admission: Mutex<()>,
        /// Owner operations hold this for reading from their authorization
        /// through their effect; promoting a connection takes it for writing.
        /// A promoted replacement therefore waits for the replaced owner's
        /// authorized operations, and none of them takes effect after the
        /// promotion. Asynchronous tasks wait for it without blocking a
        /// runtime worker: an operation may hold it across `block_on`, which
        /// needs the workers to make progress.
        ownership: tokio::sync::RwLock<()>,
        /// Runs between a promotion and the supervisory state recording it.
        #[cfg(test)]
        promotion_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        /// Executable pins of this generation, which outlive every supervisor
        /// owner.
        binary_pins: crate::binary_pins::BinaryIdentityPins,
        /// Pool runtimes only: the supervisor pool member each served
        /// connection came from.
        connection_origins:
            Mutex<std::collections::HashMap<SandboxConnectionId, std::net::SocketAddr>>,
        /// Pool runtimes only: the member whose connection was confirmed
        /// last, where the next spare goes first.
        route_owner: Mutex<Option<std::net::SocketAddr>>,
        next_recovery_id: AtomicU64,
        /// The wire policy bound at first attach, so an idempotent attach retry
        /// carrying a different policy is denied instead of silently keeping
        /// the first policy.
        attached_policy: Mutex<Option<SandboxPolicyWire>>,
        /// The complete launch request accepted by the boundary. A replacement
        /// control process may replay it after reconnecting, but may not change
        /// any launch input or start a second workload.
        started_agent: Mutex<Option<StartedAgent>>,
        next_exec_id: AtomicU64,
        mediation_active: tokio::sync::Mutex<()>,
        next_mediation_stream_id: AtomicU64,
        exec_handles: Mutex<std::collections::HashMap<String, ExecHandle>>,
        /// Keep exec tombstones through their admission deadline. Afterwards,
        /// even a delayed first attempt is rejected without retaining its ID.
        exec_requests: Mutex<ExecRequestLedger>,
        replay_ledger: Mutex<ReplayLedger>,
        network_broker: NetworkBroker,
        workload_launcher: crate::linux::workload_launcher::WorkloadLauncher,
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

    async fn retain_exec_completion(
        process: Arc<dyn BoundaryProcess>,
        session: Arc<MainSession>,
        status: Arc<Mutex<Option<ExitStatusWire>>>,
    ) {
        let exit_status = match process.wait().await {
            Ok(exit_status) => ExitStatusWire::from(exit_status),
            Err(error) => {
                // A process wait error is terminal per the BoundaryProcess
                // contract. Retaining `None` here makes this handle look live
                // forever and can permanently exhaust exec admission.
                tracing::warn!(%error, "Exec process wait failed; recording terminal status");
                ExitStatusWire::Exited(74)
            }
        };
        *lock(&status) = Some(exit_status);
        let exit_code = match exit_status {
            ExitStatusWire::Exited(code) => code,
            ExitStatusWire::Signaled(signal) => 128 + signal,
        };
        let _ = session.finish_remote(exit_code, false).await;
    }

    #[derive(Default)]
    struct ExecRequestLedger {
        requests: std::collections::HashSet<String>,
        expirations: std::collections::BinaryHeap<std::cmp::Reverse<(u64, String)>>,
        /// A backwards wall-clock adjustment must not admit a request whose
        /// tombstone has already been removed.
        last_unix_ms: u64,
    }

    impl ExecRequestLedger {
        #[allow(clippy::result_large_err)]
        fn validate_deadline(
            &mut self,
            expires_at_unix_ms: Option<u64>,
            now_unix_ms: u64,
        ) -> Result<u64, Response> {
            self.last_unix_ms = self.last_unix_ms.max(now_unix_ms);
            while let Some(std::cmp::Reverse((expires_at, _))) = self.expirations.peek() {
                if *expires_at > self.last_unix_ms {
                    break;
                }
                if let Some(std::cmp::Reverse((_, request_id))) = self.expirations.pop() {
                    self.requests.remove(&request_id);
                }
            }
            let expires_at = expires_at_unix_ms.ok_or_else(|| {
                guest_error(
                    BoundaryErrorKind::Invalid,
                    "exec request requires an expiration deadline",
                )
            })?;
            if expires_at <= self.last_unix_ms {
                return Err(guest_error(
                    BoundaryErrorKind::Denied,
                    "exec request deadline expired; execution outcome may be unknown",
                ));
            }
            Ok(expires_at)
        }

        #[allow(clippy::result_large_err)]
        fn reserve(&mut self, request_id: &str, expires_at: u64) -> Result<(), Response> {
            if !self.requests.insert(request_id.to_owned()) {
                return Err(guest_error(
                    BoundaryErrorKind::Denied,
                    "exec request is no longer retained; it cannot be executed again",
                ));
            }
            self.expirations
                .push(std::cmp::Reverse((expires_at, request_id.to_owned())));
            Ok(())
        }
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
        ca_cert: Option<String>,
        ca_bundle: Option<String>,
        provider_env_revision: u64,
        provider_env: std::collections::HashMap<String, String>,
        provider_files: std::collections::HashMap<String, String>,
    }

    impl StartedAgent {
        /// Provider environment is mutable runtime state. A replacement
        /// control must replay every immutable launch input exactly, then
        /// reconcile the current provider snapshot through the CAS update.
        fn matches_replay(&self, other: &Self) -> bool {
            self.sandbox_id == other.sandbox_id
                && self.spec == other.spec
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
            if self.session.output_failed() {
                return ExitStatusWire::Exited(74);
            }
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
                BoundaryErrorKind::Denied,
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SupervisorConnectionState {
        AwaitingConfirmation,
        Connected(SandboxConnectionId),
        Frozen { recovery_id: u64 },
        Terminating,
        Terminal,
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
            workload_launcher: crate::linux::workload_launcher::WorkloadLauncher,
            qualification: crate::RuntimeQualification,
        ) -> Result<Self, String> {
            let sandbox_id = SandboxId::parse(config.boundary_id.clone())
                .map_err(|error| format!("validate sandbox ID: {error}"))?;
            let runtime_generation =
                openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    config.generation.clone(),
                )
                .map_err(|error| format!("validate sandbox runtime generation: {error}"))?;
            let verifier = SessionJwtVerifier::new(
                &config.gateway_id,
                SessionTokenProfile::Sandbox,
                config
                    .verification_keys
                    .iter()
                    .map(|key| SessionVerificationKey {
                        key_id: key.key_id.clone(),
                        public_key_pem: key.public_key_pem.as_bytes().to_vec(),
                    }),
                Arc::new(SystemJwtClock),
            )
            .map_err(|error| format!("configure Sandbox Protocol JWT verifier: {error}"))?;
            let filesystem_flush = FilesystemFlush::for_listener(&config.listener);
            Ok(Self {
                authenticator: SandboxProtocolAuthenticator::new(
                    verifier,
                    sandbox_id,
                    runtime_generation,
                    config.auth_epoch,
                ),
                connections: SandboxConnectionRegistry::new(
                    config.session_id,
                    config.session_rotation,
                    config.auth_epoch,
                ),
                default_recovery_timeout:
                    openshell_sandbox_backend::boundary_protocol::DEFAULT_SUPERVISOR_RECOVERY_TIMEOUT,
                recovery_offers: Mutex::new(std::collections::HashMap::new()),
                #[cfg(test)]
                scheduled_recoveries: Mutex::new(Vec::new()),
                admission: Mutex::new(()),
                ownership: tokio::sync::RwLock::new(()),
                #[cfg(test)]
                promotion_hook: Mutex::new(None),
                binary_pins: crate::binary_pins::BinaryIdentityPins::default(),
                connection_origins: Mutex::new(std::collections::HashMap::new()),
                route_owner: Mutex::new(None),
                connection_shutdowns: Mutex::new(std::collections::HashMap::new()),
                routing_handle: uuid::Uuid::new_v4().to_string(),
                config,
                process_runtime,
                state: Mutex::new(RuntimeState::AwaitingAttach),
                supervisor_connection: Mutex::new(SupervisorConnectionState::AwaitingConfirmation),
                filesystem_flush,
                next_recovery_id: AtomicU64::new(1),
                attached_policy: Mutex::new(None),
                started_agent: Mutex::new(None),
                next_exec_id: AtomicU64::new(1),
                mediation_active: tokio::sync::Mutex::new(()),
                next_mediation_stream_id: AtomicU64::new(1),
                exec_handles: Mutex::new(std::collections::HashMap::new()),
                exec_requests: Mutex::new(ExecRequestLedger::default()),
                replay_ledger: Mutex::new(ReplayLedger::default()),
                network_broker,
                workload_launcher,
                qualification,
            })
        }

        #[cfg(test)]
        fn with_filesystem_flush(mut self, filesystem_flush: FilesystemFlush) -> Self {
            self.filesystem_flush = Some(filesystem_flush);
            self
        }

        /// Authenticate a bearer and reject credentials of a replaced owner term.
        fn authenticate_request(
            &self,
            connection_id: SandboxConnectionId,
            metadata: &tonic::metadata::MetadataMap,
        ) -> Result<SandboxProtocolPrincipal, tonic::Status> {
            let principal = self
                .authenticator
                .authenticate(connection_id, metadata)
                .map_err(|error| tonic::Status::unauthenticated(error.to_string()))?;
            self.connections
                .admit(&principal)
                .map_err(|error| tonic::Status::unauthenticated(error.to_string()))?;
            Ok(principal)
        }

        fn discover_image_policy() -> Response {
            Self::discover_image_policy_from_paths(&[
                openshell_policy::CONTAINER_POLICY_PATH,
                openshell_policy::LEGACY_CONTAINER_POLICY_PATH,
            ])
        }

        fn discover_image_policy_from_paths(paths: &[&str]) -> Response {
            use std::io::Read as _;
            for path in paths {
                match File::open(path) {
                    Ok(file) => {
                        let mut yaml = String::new();
                        if file.take(1_048_577).read_to_string(&mut yaml).is_err()
                            || yaml.len() > 1_048_576
                        {
                            return Response::ImagePolicy {
                                yaml: None,
                                invalid: true,
                            };
                        }
                        return Response::ImagePolicy {
                            yaml: Some(yaml),
                            invalid: false,
                        };
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => {
                        return Response::ImagePolicy {
                            yaml: None,
                            invalid: true,
                        };
                    }
                }
            }
            Response::ImagePolicy {
                yaml: None,
                invalid: false,
            }
        }

        /// Check a request that runs without the ownership guard; `false`
        /// when it is an owner operation, which must take the guard.
        fn admits_unguarded(
            &self,
            principal: &SandboxProtocolPrincipal,
            request: &Request,
        ) -> Result<bool, String> {
            match request {
                Request::Attach { .. } | Request::DiscoverPolicy => Ok(true),
                Request::Confirm => self
                    .connections
                    .require_attached(principal)
                    .map(|()| true)
                    .map_err(|error| error.to_string()),
                // Waiting reads status and may block for the process lifetime.
                Request::Wait { .. } => self
                    .connections
                    .require_active(principal)
                    .map(|()| true)
                    .map_err(|error| error.to_string()),
                _ => Ok(false),
            }
        }

        /// Authorize a request on a blocking thread. Owner operations return
        /// the ownership guard, which the caller holds until the operation
        /// has taken effect.
        fn authorize_request(
            &self,
            principal: &SandboxProtocolPrincipal,
            request: &Request,
        ) -> Result<Option<OwnershipGuard<'_>>, String> {
            if self.admits_unguarded(principal, request)? {
                return Ok(None);
            }
            self.owner_operation(principal)
                .map(Some)
                .map_err(|error| error.to_string())
        }

        /// [`Self::authorize_request`] for an asynchronous task.
        async fn authorize_request_async(
            &self,
            principal: &SandboxProtocolPrincipal,
            request: &Request,
        ) -> Result<Option<OwnershipGuard<'_>>, String> {
            if self.admits_unguarded(principal, request)? {
                return Ok(None);
            }
            self.owner_operation_async(principal)
                .await
                .map(Some)
                .map_err(|error| error.to_string())
        }

        /// Admit one operation of the owner in force, on a blocking thread.
        /// While the returned guard lives, no confirmation can promote
        /// another connection, so the operation cannot take effect for an
        /// owner that was replaced.
        fn owner_operation(
            &self,
            principal: &SandboxProtocolPrincipal,
        ) -> Result<OwnershipGuard<'_>, SandboxAuthError> {
            let guard = self.ownership.blocking_read();
            self.connections.require_active(principal)?;
            Ok(guard)
        }

        /// [`Self::owner_operation`] for an asynchronous task, which must not
        /// block its runtime worker while a promotion is pending.
        async fn owner_operation_async(
            &self,
            principal: &SandboxProtocolPrincipal,
        ) -> Result<OwnershipGuard<'_>, SandboxAuthError> {
            let guard = self.ownership.read().await;
            self.connections.require_active(principal)?;
            Ok(guard)
        }

        /// Commit an attach the registry admits, with the recovery deadline
        /// its supervisor offered (`None` keeps the default) for the freeze
        /// that follows the loss of this connection once it is in force.
        fn commit_attach(
            &self,
            principal: &SandboxProtocolPrincipal,
            supervisor_instance_id: openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId,
            takeover: Option<&openshell_core::jwt::VerifiedSupervisorTakeover>,
            recovery_offer: Option<Duration>,
        ) -> Result<(), CommitError> {
            let replaced = self
                .connections
                .attach(principal, supervisor_instance_id, takeover)
                .map_err(connection_auth_error)?;
            {
                let mut offers = lock(&self.recovery_offers);
                // An attach that raced its connection's loss leaves an entry
                // behind; keep only served connections once the map grows.
                if offers.len() >= MAX_CONTROL_CONNECTIONS {
                    let served = lock(&self.connection_shutdowns);
                    offers.retain(|connection, _| served.contains_key(connection));
                }
                match recovery_offer {
                    Some(offer) => offers.insert(principal.connection_id(), offer),
                    None => offers.remove(&principal.connection_id()),
                };
            }
            if let Some(replaced) = replaced {
                self.close_connection(replaced);
            }
            Ok(())
        }

        fn commit_confirm(&self, principal: &SandboxProtocolPrincipal) -> Result<(), CommitError> {
            let terminating = || {
                Err((
                    BoundaryErrorKind::Terminated,
                    "sandbox session is terminating".to_string(),
                ))
            };
            // A replay on the connection in force, such as a credential
            // renewal, promotes nothing, so it neither waits for nor holds up
            // owner operations. The supervisory state lock keeps the
            // connection in force while it is checked.
            {
                let connection = lock(&self.supervisor_connection);
                if self.connections.require_active(principal).is_ok() {
                    if matches!(
                        *connection,
                        SupervisorConnectionState::Terminating
                            | SupervisorConnectionState::Terminal
                    ) {
                        self.connections.mark_terminal();
                        return terminating();
                    }
                    return Ok(());
                }
            }
            // Wait out every authorized operation of the current owner, and
            // admit none until the connection that confirms is in force.
            let _promotion = self.ownership.blocking_write();
            // The registry's promotion and the supervisory state that records
            // it change together: a connection lost in between is seen as the
            // one in force, so its loss freezes the workload under a recovery
            // deadline.
            let mut connection = lock(&self.supervisor_connection);
            if matches!(
                *connection,
                SupervisorConnectionState::Terminating | SupervisorConnectionState::Terminal
            ) {
                self.connections.mark_terminal();
                return terminating();
            }
            let Promotion { replaced, takeover } = self
                .connections
                .confirm(principal)
                .map_err(connection_auth_error)?;
            #[cfg(test)]
            {
                let hook = lock(&self.promotion_hook).take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            // The member whose connection is now in force is the
            // authenticated owner a pool runtime dials first.
            let origin = lock(&self.connection_origins)
                .get(&principal.connection_id())
                .copied();
            if let Some(origin) = origin {
                *lock(&self.route_owner) = Some(origin);
            }
            let process = {
                let state = lock(&self.state);
                match &*state {
                    RuntimeState::Running(process) => Some(process.clone()),
                    RuntimeState::AwaitingAttach
                    | RuntimeState::Bound(_)
                    | RuntimeState::Ready(_) => None,
                }
            };
            if matches!(*connection, SupervisorConnectionState::Frozen { .. })
                && let Some(process) = process
            {
                if !process.boundary_runtime.resume() {
                    return Err((
                        BoundaryErrorKind::Process,
                        "frozen workload could not be resumed".to_string(),
                    ));
                }
                self.network_broker.set_workload_frozen(false);
                tracing::info!(
                    connection_id = ?principal.connection_id(),
                    "Sandbox Protocol connection recovered; workload resumed"
                );
            }
            *connection = SupervisorConnectionState::Connected(principal.connection_id());
            drop(connection);
            if let Some(takeover) = takeover {
                // Every connection of the replaced owner term is stale now,
                // including ones that never attached.
                let retired = lock(&self.connection_shutdowns)
                    .keys()
                    .filter(|connection| **connection != principal.connection_id())
                    .copied()
                    .collect::<Vec<_>>();
                for connection in retired {
                    self.close_connection(connection);
                }
                tracing::info!(
                    auth_epoch = takeover.auth_epoch.get(),
                    owner = %takeover.owner,
                    "Supervisor takeover confirmed; previous owner fenced"
                );
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::Informational)
                        .status(openshell_ocsf::StatusId::Success)
                        .state(openshell_ocsf::StateId::Enabled, "transferred")
                        .message(format!(
                            "Supervisor ownership transferred [term:{} owner:{}]",
                            takeover.auth_epoch.get(),
                            takeover.owner
                        ))
                        .build()
                );
            } else if let Some(replaced) = replaced {
                self.close_connection(replaced);
            }
            Ok(())
        }

        /// The supervisor pool member whose connection was confirmed last.
        fn confirmed_route_owner(&self) -> Option<std::net::SocketAddr> {
            *lock(&self.route_owner)
        }

        fn register_connection(
            &self,
            connection_id: SandboxConnectionId,
            shutdown: tokio::sync::watch::Sender<()>,
        ) {
            lock(&self.connection_shutdowns).insert(connection_id, shutdown);
        }

        fn close_connection(&self, connection_id: SandboxConnectionId) {
            let shutdown = lock(&self.connection_shutdowns).remove(&connection_id);
            if let Some(shutdown) = shutdown {
                let _ = shutdown.send(());
            }
        }

        fn transport_disconnected(self: &Arc<Self>, connection_id: SandboxConnectionId) {
            let shutdown = lock(&self.connection_shutdowns).remove(&connection_id);
            if let Some(shutdown) = shutdown {
                let _ = shutdown.send(());
            }
            let recovery_offer = lock(&self.recovery_offers).remove(&connection_id);
            let recovery_id = {
                // Taken before the registry, as promotion does, so the loss
                // of a connection promoted a moment ago finds it in force.
                let mut connection = lock(&self.supervisor_connection);
                if !self.connections.disconnect(connection_id) {
                    return;
                }
                if !matches!(
                    *connection,
                    SupervisorConnectionState::Connected(active) if active == connection_id
                ) {
                    return;
                }
                let process = {
                    let state = lock(&self.state);
                    match &*state {
                        RuntimeState::Running(process) => Some(process.clone()),
                        RuntimeState::AwaitingAttach
                        | RuntimeState::Bound(_)
                        | RuntimeState::Ready(_) => None,
                    }
                };
                if let Some(process) = &process {
                    self.network_broker.set_workload_frozen(true);
                    let _ = process.boundary_runtime.freeze();
                }
                let recovery_id = self.next_recovery_id.fetch_add(1, Ordering::Relaxed);
                *connection = SupervisorConnectionState::Frozen { recovery_id };
                recovery_id
            };
            tracing::warn!(
                recovery_id,
                "Sandbox Protocol connection lost; workload frozen pending authenticated recovery"
            );
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .confidence(openshell_ocsf::ConfidenceId::High)
                    .is_alert(true)
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "sandbox-supervisor-connection-lost",
                        "Sandbox Supervisor Connection Lost",
                    ))
                    .message("Sandbox Protocol connection lost; workload frozen")
                    .build()
            );
            // The supervisor whose connection was in force chose how long its
            // replacement may take.
            let recovery_timeout = recovery_offer.unwrap_or(self.default_recovery_timeout);
            #[cfg(test)]
            lock(&self.scheduled_recoveries).push(recovery_timeout);
            let runtime = Arc::downgrade(self);
            self.process_runtime.spawn(async move {
                tokio::time::sleep(recovery_timeout).await;
                if let Some(runtime) = runtime.upgrade() {
                    runtime.expire_recovery(recovery_id).await;
                }
            });
        }

        async fn expire_recovery(&self, recovery_id: u64) {
            let process = {
                let mut connection = lock(&self.supervisor_connection);
                if *connection != (SupervisorConnectionState::Frozen { recovery_id }) {
                    return;
                }
                *connection = SupervisorConnectionState::Terminating;
                let state = lock(&self.state);
                match &*state {
                    RuntimeState::Running(process) => Some(process.clone()),
                    RuntimeState::AwaitingAttach
                    | RuntimeState::Bound(_)
                    | RuntimeState::Ready(_) => None,
                }
            };
            self.connections.mark_terminal();
            tracing::error!(
                recovery_id,
                "Sandbox Protocol recovery deadline expired; terminating workload"
            );
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::High)
                    .confidence(openshell_ocsf::ConfidenceId::High)
                    .is_alert(true)
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "sandbox-supervisor-recovery-expired",
                        "Sandbox Supervisor Recovery Expired",
                    ))
                    .message("Supervisor recovery expired; terminating sandbox workload")
                    .build()
            );
            if let Some(process) = process
                && let Err(error) = Self::terminate_process_tree(&process, true).await
            {
                tracing::error!(%error, "sandbox workload did not terminate after recovery loss");
                return;
            }
            *lock(&self.supervisor_connection) = SupervisorConnectionState::Terminal;
        }

        async fn terminate_boundary(&self) -> Response {
            {
                let mut connection = lock(&self.supervisor_connection);
                if *connection == SupervisorConnectionState::Terminal {
                    return Response::BoundaryTerminated;
                }
                *connection = SupervisorConnectionState::Terminating;
            }
            // Revocation happens before process shutdown so no concurrent or
            // replacement connection can race the terminal transition.
            self.connections.mark_terminal();
            let process = {
                let state = lock(&self.state);
                match &*state {
                    RuntimeState::Running(process) => Some(process.clone()),
                    RuntimeState::AwaitingAttach
                    | RuntimeState::Bound(_)
                    | RuntimeState::Ready(_) => None,
                }
            };
            let terminated = match process {
                Some(process) => Self::terminate_process_tree(&process, false).await,
                None => Ok(()),
            };
            // The host may end the VM on acknowledgement. Flush dirty writes
            // first, even if process termination failed.
            self.flush_filesystem().await;
            if let Err(error) = terminated {
                return guest_error(BoundaryErrorKind::Process, error);
            }
            *lock(&self.supervisor_connection) = SupervisorConnectionState::Terminal;
            Response::BoundaryTerminated
        }

        /// Log flush failures and timeouts while allowing termination to finish.
        async fn flush_filesystem(&self) {
            let Some(filesystem_flush) = &self.filesystem_flush else {
                return;
            };
            let run = Arc::clone(&filesystem_flush.run);
            let flush = tokio::task::spawn_blocking(move || run());
            match tokio::time::timeout(filesystem_flush.timeout, flush).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    tracing::warn!(%error, "Sandbox filesystem flush failed before termination");
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "Sandbox filesystem flush task failed before termination");
                }
                Err(_) => {
                    tracing::warn!(
                        timeout = ?filesystem_flush.timeout,
                        "Sandbox filesystem flush timed out before termination"
                    );
                }
            }
        }

        async fn terminate_process_tree(
            process: &ManagedProcess,
            enforcement_was_lost: bool,
        ) -> Result<(), String> {
            if enforcement_was_lost {
                let _ = process
                    .boundary_runtime
                    .begin_enforcement_loss_termination();
            } else {
                let _ = process.boundary_runtime.begin_termination();
            }
            if Self::wait_for_process_tree_exit(process, ENFORCEMENT_LOSS_TERMINATION_GRACE).await {
                return Ok(());
            }

            process.boundary_runtime.force_kill();
            if Self::wait_for_process_tree_exit(process, FORCE_KILL_REAP_TIMEOUT).await {
                Ok(())
            } else {
                Err("owned workload processes remain after forced termination".to_string())
            }
        }

        async fn wait_for_process_tree_exit(process: &ManagedProcess, timeout: Duration) -> bool {
            let deadline = tokio::time::Instant::now() + timeout;
            while process.boundary_runtime.has_owned_processes()
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            !process.boundary_runtime.has_owned_processes()
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
            if envelope.validate_payload_digest().is_err() {
                return guest_error(
                    BoundaryErrorKind::Denied,
                    "control request payload digest mismatch",
                );
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
                        BoundaryErrorKind::Denied,
                        "control request ID was reused with a different payload",
                    )
                };
            }
            let request_id = envelope.request_id;
            let payload_digest = envelope.payload_digest;
            let response = match envelope.request {
                Request::DiscoverPolicy => Self::discover_image_policy(),
                Request::Attach {
                    policy,
                    supervisor_takeover,
                    ..
                } => self.attach(*policy, supervisor_takeover.is_some()),
                Request::Confirm => self.confirm(),
                Request::StartAgent {
                    sandbox_id,
                    spec,
                    ca_cert,
                    ca_bundle,
                    provider_env_revision,
                    provider_env,
                    provider_files,
                } => self.start_agent(
                    sandbox_id,
                    spec,
                    ca_cert,
                    ca_bundle,
                    provider_env_revision,
                    provider_env,
                    provider_files,
                ),
                Request::UpdateProviderEnvironment {
                    generation,
                    revision,
                    provider_env,
                    provider_files,
                } => self.update_provider_environment(
                    generation,
                    revision,
                    provider_env,
                    provider_files,
                ),
                Request::Wait { process_id } => self.wait(&process_id),
                Request::Signal { process_id, signal } => self.signal(&process_id, signal),
                Request::Terminate { process_id } => self.terminate(&process_id),
                Request::Resize {
                    process_id,
                    cols,
                    rows,
                } => self.resize_process(&process_id, cols, rows),
                Request::OpenMediation => self.network_accept_context().map_or_else(
                    |error| guest_error(BoundaryErrorKind::Unavailable, error),
                    |_| Response::MediationReady,
                ),
                Request::Exec { .. }
                | Request::TerminateBoundary
                | Request::AttachProcess { .. }
                | Request::LoopbackConnect { .. }
                | Request::AcceptNetwork => guest_error(
                    BoundaryErrorKind::Invalid,
                    "streaming request used on control path",
                ),
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

        #[allow(
            clippy::result_large_err,
            reason = "protocol errors are returned directly as complete response frames"
        )]
        fn start_exec(
            &self,
            request_id: &str,
            payload_digest: &str,
            expires_at_unix_ms: Option<u64>,
            spec: ExecSpecWire,
        ) -> Result<StartedExec, Response> {
            let executor = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err(guest_error(
                        BoundaryErrorKind::Invalid,
                        "agent process has not been started",
                    ));
                };
                process.boundary_exec()
            };
            let mut handles = lock(&self.exec_handles);
            let mut requests = lock(&self.exec_requests);
            let now_unix_ms = unix_time_millis()
                .map_err(|error| guest_error(BoundaryErrorKind::Unavailable, error.to_string()))?;
            let expires_at = requests.validate_deadline(expires_at_unix_ms, now_unix_ms)?;
            if let Some((process_id, handle)) = handles
                .iter()
                .find(|(_, handle)| handle.request_id == request_id)
            {
                if handle.payload_digest != payload_digest {
                    return Err(guest_error(
                        BoundaryErrorKind::Denied,
                        "exec request ID was reused with a different payload",
                    ));
                }
                if handle.attached.load(Ordering::Acquire) {
                    return Err(guest_error(
                        BoundaryErrorKind::Unavailable,
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
                        BoundaryErrorKind::Unavailable,
                        "retained exec process limit reached",
                    ));
                }
            }
            requests.reserve(request_id, expires_at)?;
            drop(requests);
            self.network_broker
                .ensure_descriptor_headroom(EXEC_SPAWN_DESCRIPTOR_HEADROOM)
                .map_err(|error| {
                    guest_error(
                        BoundaryErrorKind::Unavailable,
                        format!("exec descriptor headroom unavailable: {error}"),
                    )
                })?;
            let session = self
                .process_runtime
                .block_on(executor.exec(spec.into()))
                .map_err(|error| guest_error(BoundaryErrorKind::Process, error.to_string()))?;
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
                    BoundaryErrorKind::Process,
                    "exec process stdin pipe is unavailable",
                ));
            };
            let retained = {
                let _runtime = self.process_runtime.enter();
                MainSession::from_boundary(
                    crate::native_api::ProcessAttachment {
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
                retain_exec_completion(wait_process, wait_session, wait_status).await;
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

        fn resize_process(&self, process_id: &str, cols: u16, rows: u16) -> Response {
            if let Ok(process) = self.running_process(process_id) {
                let session = process.main_session();
                if !session.terminal() {
                    return guest_error(
                        BoundaryErrorKind::Invalid,
                        "agent process has no terminal",
                    );
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
                return guest_error(BoundaryErrorKind::Invalid, "exec process has no terminal");
            };
            match self.process_runtime.block_on(terminal.resize(cols, rows)) {
                Ok(()) => Response::Resized,
                Err(error) => guest_error(BoundaryErrorKind::Process, error.to_string()),
            }
        }

        fn connect_port(
            &self,
            target: LoopbackTarget,
        ) -> Result<openshell_isolation_interface::contract::BoundaryDuplexStream, String> {
            let loopback_connector = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err("agent process has not been started".to_string());
                };
                process.loopback_connector()
            };
            self.process_runtime
                .block_on(loopback_connector.connect(target))
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
                .ok_or_else(|| guest_error(BoundaryErrorKind::Invalid, "unknown process ID"))?;
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

        /// Bind the launch controls at the first attach. A replacement
        /// supervisor attaching under a takeover grant keeps the controls
        /// already bound: they cannot change for a running generation, and
        /// the snapshot returns them for its later reattaches.
        fn attach(&self, policy: SandboxPolicyWire, takeover: bool) -> Response {
            let mut state = lock(&self.state);
            let bound = !matches!(&*state, RuntimeState::AwaitingAttach);
            // Reject a conflicting request before establishing the boundary
            // or retaining the caller's policy for later replay.
            if !(bound && takeover)
                && let Err(error) = validate_vm_policy_identity(&self.config, &policy)
            {
                return guest_error(BoundaryErrorKind::Denied, error);
            }
            let accepted = match &*state {
                RuntimeState::AwaitingAttach => {
                    let prepared = match PreparedBoundary::establish(self.network_broker.clone()) {
                        Ok(prepared) => prepared,
                        Err(error) => return guest_error(BoundaryErrorKind::Process, error),
                    };
                    *lock(&self.attached_policy) = Some(policy);
                    *state = RuntimeState::Bound(prepared);
                    true
                }
                RuntimeState::Bound(_) | RuntimeState::Ready(_) | RuntimeState::Running(_) => {
                    // Idempotent retry of the same attach; a different policy
                    // must not be silently coalesced onto the bound boundary.
                    takeover || lock(&self.attached_policy).as_ref() == Some(&policy)
                }
            };
            drop(state);
            if accepted {
                Response::Attached {
                    snapshot: self.session_snapshot(),
                }
            } else {
                guest_error(
                    BoundaryErrorKind::Denied,
                    "attach policy does not match the bound boundary",
                )
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
                bound_policy: lock(&self.attached_policy).clone().map(Box::new),
                processes,
            }
        }

        fn confirm(&self) -> Response {
            let mut state = lock(&self.state);
            match &*state {
                RuntimeState::Bound(prepared) => {
                    if let Err(error) = prepared.confirm(&self.process_runtime) {
                        return guest_error(BoundaryErrorKind::Process, error);
                    }
                    let confirmation = match self.measure_confirmation() {
                        Ok(confirmation) => confirmation,
                        Err(error) => return guest_error(BoundaryErrorKind::Process, error),
                    };
                    *state = RuntimeState::Ready(prepared.clone());
                    Response::Confirmed {
                        confirmation: Box::new(confirmation),
                    }
                }
                RuntimeState::Ready(_) | RuntimeState::Running(_) => {
                    self.measure_confirmation().map_or_else(
                        |error| guest_error(BoundaryErrorKind::Process, error),
                        |confirmation| Response::Confirmed {
                            confirmation: Box::new(confirmation),
                        },
                    )
                }
                RuntimeState::AwaitingAttach => guest_error(
                    BoundaryErrorKind::Invalid,
                    "boundary must be attached before confirm",
                ),
            }
        }

        fn measure_confirmation(&self) -> Result<BoundaryConfirmation, String> {
            validate_running_identity(
                &self.config.workload_identity,
                allows_runtime_supplementary_groups(&self.config),
            )?;
            self.network_broker
                .confirm_healthy()
                .map_err(|error| format!("verify sandbox network broker: {error}"))?;
            if !self.workload_launcher.is_alive() {
                return Err("sandbox workload launcher is not running".to_string());
            }
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|error| format!("read sandbox process status: {error}"))?;
            let capabilities = openshell_sandbox_backend::boundary_protocol::CapabilityEvidence {
                inheritable: parse_status_hex(&status, "CapInh")?,
                permitted: parse_status_hex(&status, "CapPrm")?,
                effective: parse_status_hex(&status, "CapEff")?,
                bounding: parse_status_hex(&status, "CapBnd")?,
                ambient: parse_status_hex(&status, "CapAmb")?,
            };
            let no_new_privileges = parse_status_decimal(&status, "NoNewPrivs")? == 1;
            // SAFETY: PR_GET_DUMPABLE reads one scalar process property.
            let sandbox_dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
            let (core_current, core_maximum) =
                nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
                    .map_err(|error| format!("read sandbox core limit: {error}"))?;
            let (native_architecture, kernel_release) = uname_values()?;
            let audit = NativeLinuxSandboxAuditEvidence {
                capabilities,
                no_new_privileges,
                sandbox_dumpable,
                child_dumpable: true,
                core_limit_zero: core_current == 0 && core_maximum == 0,
                native_architecture,
                kernel_release,
                seccomp: self.qualification.seccomp,
                landlock_abi: self.qualification.landlock_abi,
                landlock_allow_deny: self.qualification.landlock_allow_deny,
                udp_dns_round_trip: self.qualification.udp_dns_round_trip,
                tcp_dns_round_trip: self.qualification.tcp_dns_round_trip,
                tcp_allow_round_trip: self.qualification.tcp_allow_round_trip,
                tcp_deny_round_trip: self.qualification.tcp_deny_round_trip,
                socket_loopback_confinement: self.qualification.socket_loopback_confinement,
            };
            // The boundary reports mechanism evidence; the authenticated host
            // backend validates it before constructing a ConfirmedBoundary.
            // Keeping that decision at the verifier also lets lifecycle tests
            // exercise the protocol without claiming host-kernel enforcement.
            let backend_audit = serde_json::to_value(audit)
                .map_err(|error| format!("encode OpenShell sandbox audit evidence: {error}"))?;
            Ok(BoundaryConfirmation {
                generation: self.config.generation.clone(),
                identity: self.config.workload_identity.clone(),
                session_id: self.config.session_id,
                provisioning_evidence_digest: self.config.provisioning_evidence.evidence_digest,
                resource_claims: self.config.resource_claims.clone(),
                backend_audit,
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn start_agent(
            &self,
            sandbox_id: String,
            spec: AgentSpecWire,
            ca_cert: Option<String>,
            ca_bundle: Option<String>,
            provider_env_revision: u64,
            provider_env: std::collections::HashMap<String, String>,
            provider_files: std::collections::HashMap<String, String>,
        ) -> Response {
            let Some(policy) = lock(&self.attached_policy).clone() else {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    "boundary must be attached before start_agent",
                );
            };
            let spec = match resolve_agent_spec(spec) {
                Ok(spec) => spec,
                Err(error) => return guest_error(BoundaryErrorKind::Process, error),
            };
            let mut state = lock(&self.state);
            let requested = StartedAgent {
                sandbox_id,
                spec: spec.clone(),
                ca_cert: ca_cert.clone(),
                ca_bundle: ca_bundle.clone(),
                provider_env_revision,
                provider_env: provider_env.clone(),
                provider_files: provider_files.clone(),
            };
            if let RuntimeState::Running(process) = &*state {
                return if lock(&self.started_agent)
                    .as_ref()
                    .is_some_and(|accepted| accepted.matches_replay(&requested))
                {
                    Response::Started {
                        process_id: process.process_id(),
                        provider_env_revision: process.provider_credentials.snapshot().revision,
                        provider_env_generation: *lock(&process.provider_environment_generation),
                    }
                } else {
                    guest_error(
                        BoundaryErrorKind::Denied,
                        "start_agent inputs do not match the running boundary",
                    )
                };
            }
            let RuntimeState::Ready(prepared) = &*state else {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    "boundary must be confirmed before start_agent",
                );
            };
            if let Err(error) = self.network_broker.confirm_healthy() {
                return guest_error(BoundaryErrorKind::Unavailable, error.to_string());
            }
            if let Err(error) = crate::provider_files::ProviderFiles::validate(&provider_files) {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    format!("invalid provider files: {error}"),
                );
            }
            let ca_file_paths = match install_ca_material(ca_cert, ca_bundle) {
                Ok(paths) => paths,
                Err(error) => return guest_error(BoundaryErrorKind::Process, error),
            };
            let mut policy = policy.into();
            let gpu_requested = self
                .config
                .resource_claims
                .get(GPU_RESOURCE_CLAIM)
                .is_some_and(|value| value == "true");
            if enrich_gpu_filesystem_paths(&mut policy, gpu_requested) {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::Informational)
                        .status(openshell_ocsf::StatusId::Success)
                        .state(openshell_ocsf::StateId::Enabled, "enriched")
                        .message("Added workload-local GPU filesystem paths".to_string())
                        .build()
                );
            }
            policy.process.run_as_user = Some(self.config.workload_identity.uid.to_string());
            policy.process.run_as_group = Some(self.config.workload_identity.gid.to_string());
            let launch = ManagedProcessLaunch {
                process_id: format!("{}:main:0", self.config.generation),
                spec,
                policy,
                provider_env_revision,
                provider_env,
                ca_file_paths,
            };
            let provider_file_count = provider_files.len();
            if let Err(error) = self.network_broker.provider_files().replace(provider_files) {
                return guest_error(
                    BoundaryErrorKind::Process,
                    format!("install provider files: {error}"),
                );
            }
            let process = match ManagedProcess::spawn(
                &self.process_runtime,
                &self.workload_launcher,
                launch,
                prepared.clone(),
            ) {
                Ok(process) => Arc::new(process),
                Err(error) => return guest_error(BoundaryErrorKind::Process, error),
            };
            let process_id = process.process_id();
            *lock(&self.started_agent) = Some(requested);
            *state = RuntimeState::Running(process);
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Informational)
                    .status(openshell_ocsf::StatusId::Success)
                    .message(format!(
                        "Provider file snapshot loaded [file_count:{provider_file_count}]"
                    ))
                    .build()
            );
            Response::Started {
                process_id,
                provider_env_revision,
                provider_env_generation: 0,
            }
        }

        fn update_provider_environment(
            &self,
            generation: u64,
            revision: u64,
            provider_env: std::collections::HashMap<String, String>,
            provider_files: std::collections::HashMap<String, String>,
        ) -> Response {
            let process = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return guest_error(
                        BoundaryErrorKind::Invalid,
                        "agent process must be running before provider environment updates",
                    );
                };
                process.clone()
            };
            // The session-scoped publication order is separate from opaque
            // provider fingerprints. Holding it through installation prevents
            // a delayed request from replacing a newer same-revision repair.
            let mut installed_generation = lock(&process.provider_environment_generation);
            let current = match process.provider_credentials.child_environment_snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => return guest_error(BoundaryErrorKind::Process, error.to_string()),
            };
            if generation <= *installed_generation {
                return Response::ProviderEnvironmentUpdated {
                    revision: current.revision,
                    generation: *installed_generation,
                    applied: false,
                };
            }
            if let Err(error) = self.network_broker.confirm_healthy() {
                return guest_error(BoundaryErrorKind::Unavailable, error.to_string());
            }
            if let Err(error) = crate::provider_files::ProviderFiles::validate(&provider_files) {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    format!("invalid provider files: {error}"),
                );
            }
            let requested_revision = revision;
            let revision = match process
                .provider_credentials
                .compare_and_install_child_env_snapshot(current.revision, revision, provider_env)
            {
                Ok(revision) => revision,
                Err(error) => return guest_error(BoundaryErrorKind::Process, error.to_string()),
            };
            if revision != requested_revision {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    "provider environment changed during update",
                );
            }
            let provider_file_count = provider_files.len();
            if let Err(error) = self.network_broker.provider_files().replace(provider_files) {
                return guest_error(
                    BoundaryErrorKind::Process,
                    format!("install provider files: {error}"),
                );
            }
            *installed_generation = generation;
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Informational)
                    .status(openshell_ocsf::StatusId::Success)
                    .message(format!(
                        "Provider file snapshot updated [file_count:{provider_file_count}]"
                    ))
                    .build()
            );
            Response::ProviderEnvironmentUpdated {
                revision,
                generation,
                applied: true,
            }
        }

        fn wait(&self, process_id: &str) -> Response {
            let exec = lock(&self.exec_handles)
                .get(process_id)
                .map(|handle| handle.process.clone());
            if let Some(process) = exec {
                // Wait independently of the output attachment. Retain the
                // process, not the registry lock, while its exit is pending.
                return match self.process_runtime.block_on(process.wait()) {
                    Ok(status) => Response::Exited {
                        status: status.into(),
                    },
                    Err(error) => guest_error(BoundaryErrorKind::Process, error.to_string()),
                };
            }
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.wait() {
                Ok(status) => Response::Exited { status },
                Err(error) => guest_error(BoundaryErrorKind::Process, error),
            }
        }

        fn signal(&self, process_id: &str, signal: SignalWire) -> Response {
            let exec = lock(&self.exec_handles)
                .get(process_id)
                .map(|handle| handle.process.clone());
            if let Some(process) = exec {
                return match self.process_runtime.block_on(process.signal(signal.into())) {
                    Ok(()) => Response::Signaled,
                    Err(error) => guest_error(BoundaryErrorKind::Process, error.to_string()),
                };
            }
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.signal(signal) {
                Ok(()) => Response::Signaled,
                Err(error) => guest_error(BoundaryErrorKind::Terminated, error),
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
                Err(error) => guest_error(BoundaryErrorKind::Process, error),
            }
        }

        #[allow(
            clippy::result_large_err,
            reason = "protocol errors are returned directly as complete response frames"
        )]
        fn running_process(&self, process_id: &str) -> Result<Arc<ManagedProcess>, Response> {
            let state = lock(&self.state);
            let RuntimeState::Running(process) = &*state else {
                return Err(guest_error(
                    BoundaryErrorKind::Invalid,
                    "agent process has not been started",
                ));
            };
            if process.process_id() != process_id {
                return Err(guest_error(
                    BoundaryErrorKind::Invalid,
                    "unknown process ID",
                ));
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
        let value = nix::sys::utsname::uname()
            .map_err(|error| format!("measure sandbox kernel identity: {error}"))?;
        Ok((
            value.machine().to_string_lossy().into_owned(),
            value.release().to_string_lossy().into_owned(),
        ))
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
        ca_cert: Option<String>,
        ca_bundle: Option<String>,
    ) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String> {
        let (ca_cert, ca_bundle) = match (ca_cert, ca_bundle) {
            (Some(ca_cert), Some(ca_bundle)) => (ca_cert, ca_bundle),
            (None, None) => return Ok(None),
            _ => {
                return Err(
                    "supervisor CA certificate and bundle must be supplied together".to_string(),
                );
            }
        };
        install_ca_material_at(
            Path::new(openshell_sandbox_backend::SUPERVISOR_CA_RUNTIME_DIR),
            ca_cert.as_bytes(),
            ca_bundle.as_bytes(),
        )
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
            .ok_or_else(|| "supervisor CA directory has no parent".to_string())?;
        for path in [parent, directory] {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "supervisor CA directory component is a symlink: {}",
                        path.display()
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(format!(
                        "supervisor CA directory component is not a directory: {}",
                        path.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::create_dir(path).map_err(|error| {
                        format!("create supervisor CA directory {}: {error}", path.display())
                    })?;
                }
                Err(error) => {
                    return Err(format!(
                        "inspect supervisor CA directory {}: {error}",
                        path.display()
                    ));
                }
            }
            let current_mode = std::fs::metadata(path)
                .map_err(|error| {
                    format!(
                        "inspect supervisor CA directory permissions {}: {error}",
                        path.display()
                    )
                })?
                .permissions()
                .mode();
            if path == directory {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(
                    |error| {
                        format!(
                            "set supervisor CA directory permissions {}: {error}",
                            path.display()
                        )
                    },
                )?;
            } else if current_mode & 0o111 != 0o111 {
                return Err(format!(
                    "supervisor CA parent is not traversable by workload identities: {}",
                    path.display()
                ));
            }
        }
        let ca_path = directory.join("ca.crt");
        let bundle_path = directory.join("ca-bundle.crt");
        for (path, contents, label) in [
            (&ca_path, ca_cert, "supervisor CA"),
            (&bundle_path, ca_bundle, "supervisor CA bundle"),
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
        loopback_connector: Arc<dyn BoundaryLoopbackConnector>,
        main_session: Arc<MainSession>,
        attached: Arc<AtomicBool>,
        boundary_runtime: Arc<BoundaryRuntimeState>,
        provider_credentials: ProviderCredentialState,
        provider_environment_generation: Mutex<u64>,
    }

    struct ManagedProcessLaunch {
        process_id: String,
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
            launcher: &crate::linux::workload_launcher::WorkloadLauncher,
            launch: ManagedProcessLaunch,
            _prepared: PreparedBoundary,
        ) -> Result<Self, String> {
            let ManagedProcessLaunch {
                process_id,
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
                    launcher,
                    &spec.program,
                    &spec.args,
                    spec.workdir.as_deref(),
                    spec.timeout_secs,
                    spec.interactive,
                    &policy,
                    entrypoint_pid,
                    provider_credentials.clone(),
                    provider_env,
                    ca_file_paths,
                    Some(boundary_runtime.clone()),
                ))
                .map_err(|error| format!("start process supervisor leaf: {error:?}"))?;
            let signaler = spawned.signaler();
            let boundary_exec = spawned.boundary_exec();
            let loopback_connector = spawned.loopback_connector();
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
                loopback_connector,
                main_session,
                attached: Arc::new(AtomicBool::new(false)),
                boundary_runtime,
                provider_credentials,
                provider_environment_generation: Mutex::new(0),
            })
        }

        fn process_id(&self) -> String {
            self.process_id.clone()
        }

        fn wait(&self) -> ProcessExit {
            let (state, changed) = &*self.exit;
            let mut exit = lock(state);
            loop {
                if let Some(result) = exit.as_ref() {
                    return result.clone();
                }
                exit = changed
                    .wait(exit)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
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

        fn loopback_connector(&self) -> Arc<dyn BoundaryLoopbackConnector> {
            self.loopback_connector.clone()
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
                        // A process may close stdin before the client has
                        // finished sending it. Keep relaying stdout, stderr,
                        // and the final status after that write fails.
                        if let Some(sender) = input.as_ref()
                            && sender.send(payload).await.is_err()
                        {
                            input.take();
                        }
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
                    let status =
                        openshell_sandbox_backend::protobuf::encode(&attachment.exit_status(code))
                            .map_err(|error| format!("encode main process exit: {error}"))?;
                    break write_stream_frame(&mut *writer.lock().await, STREAM_EXIT, &status)
                        .await
                        .map_err(|error| format!("write main process exit: {error}"));
                }
                Err(error) => {
                    if matches!(&attachment.status, AttachmentStatus::Exec(_)) {
                        tracing::warn!(
                            skipped_chunks = error.skipped,
                            "exec output could not be delivered intact"
                        );
                        let message = b"openshell: exec output could not be delivered intact\n";
                        let _ =
                            write_stream_frame(&mut *writer.lock().await, STREAM_STDERR, message)
                                .await;
                        let status = openshell_sandbox_backend::protobuf::encode(
                            &ExitStatusWire::Exited(74),
                        )
                        .map_err(|error| format!("encode exec output failure: {error}"))?;
                        break write_stream_frame(&mut *writer.lock().await, STREAM_EXIT, &status)
                            .await
                            .map_err(|error| format!("write exec output failure: {error}"));
                    }
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

    type CommitError = (BoundaryErrorKind, String);

    /// Attach refusals that mean another supervisor process tried to take
    /// the generation over, or a replaced owner tried to return.
    fn attach_denial_is_takeover(error: &SandboxAuthError) -> bool {
        matches!(
            error,
            SandboxAuthError::TakeoverRequired
                | SandboxAuthError::TakeoverMismatch
                | SandboxAuthError::WrongSupervisorInstance
                | SandboxAuthError::StaleCredentialEpoch
        )
    }

    /// Report a refused supervisor takeover or replacement attach, as a
    /// configuration-state event and a detection finding. Only identifiers
    /// are recorded, never a token or grant.
    fn emit_takeover_denial(
        reason: &str,
        takeover: Option<&openshell_core::jwt::VerifiedSupervisorTakeover>,
    ) {
        let message = takeover.map_or_else(
            || format!("Supervisor takeover denied [reason:{reason}]"),
            |takeover| {
                format!(
                    "Supervisor takeover denied [reason:{reason} term:{} owner:{} grant:{}]",
                    takeover.takeover.auth_epoch.get(),
                    takeover.takeover.owner,
                    takeover.token_id
                )
            },
        );
        tracing::warn!(%message, "Supervisor takeover denied");
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Medium)
                .status(openshell_ocsf::StatusId::Failure)
                .state(openshell_ocsf::StateId::Disabled, "takeover_denied")
                .message(message.clone())
                .build()
        );
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Open)
                .severity(openshell_ocsf::SeverityId::Medium)
                .confidence(openshell_ocsf::ConfidenceId::High)
                .is_alert(true)
                .finding_info(openshell_ocsf::FindingInfo::new(
                    "sandbox-supervisor-takeover-denied",
                    "Sandbox Supervisor Takeover Denied",
                ))
                .message(message)
                .build()
        );
    }

    fn connection_auth_error(error: SandboxAuthError) -> CommitError {
        let kind = match error {
            SandboxAuthError::ConnectionStillActive => BoundaryErrorKind::Unavailable,
            SandboxAuthError::TerminalSession => BoundaryErrorKind::Terminated,
            _ => BoundaryErrorKind::Denied,
        };
        (kind, error.to_string())
    }

    fn guest_error(kind: BoundaryErrorKind, message: impl Into<String>) -> Response {
        Response::Error {
            kind,
            message: message.into(),
        }
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
            reject_local_peers: bool,
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
                BoundaryListenerConfig::RuntimeInitiatedTlsTcp { .. }
                | BoundaryListenerConfig::RuntimeInitiatedUnix { .. }
                | BoundaryListenerConfig::RuntimeInitiatedVsock { .. } => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime-initiated control dials the supervisor and binds no listener",
                )),
                BoundaryListenerConfig::TlsTcp { address, tls } => {
                    let (listener, reject_local_peers) = Self::bind_tcp(*address)?;
                    listener.set_nonblocking(true)?;
                    let server_config = Arc::new(load_tls_server_config(tls)?);
                    Ok(Self::Tcp {
                        listener,
                        server_config,
                        reject_local_peers,
                    })
                }
            }
        }

        /// Bind the TCP control listener without privileged socket filters.
        /// Production configuration rejects loopback bind addresses; only tests
        /// use them to exercise TLS without the local-peer check. All production
        /// TCP listeners reject local peers in `accept`, before TLS processing.
        fn bind_tcp(address: std::net::SocketAddr) -> io::Result<(std::net::TcpListener, bool)> {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.set_cloexec(true)?;
            socket.set_reuse_address(true)?;
            let reject_local_peers = !address.ip().is_loopback();
            socket.bind(&address.into())?;
            socket.listen(128)?;
            Ok((socket.into(), reject_local_peers))
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
                    reject_workload_unix_peer(&stream)?;
                    Ok(ControlStream::PendingTls {
                        stream: PlainControlStream::Unix(stream),
                        server_config: server_config.clone(),
                    })
                }
                Self::Tcp {
                    listener,
                    server_config,
                    reject_local_peers,
                } => {
                    let (stream, peer) = listener.accept()?;
                    if *reject_local_peers {
                        reject_workload_tcp_peer(&stream, peer)?;
                    }
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

    // Traffic the workload can reach the listener with arrives over `lo`, so one
    // end is loopback or the two ends share an address. A supervisor runs in
    // another pod and presents a different address. The peer comes from `accept`
    // because `getpeername` fails once that peer has reset.
    fn reject_workload_tcp_peer(
        stream: &std::net::TcpStream,
        peer: std::net::SocketAddr,
    ) -> io::Result<()> {
        let denied = || io::Error::from_raw_os_error(libc::EACCES);
        let local = stream.local_addr().map_err(|_| denied())?;
        if is_local_control_peer(peer.ip(), local.ip()) {
            return Err(denied());
        }
        Ok(())
    }

    fn is_local_control_peer(peer: std::net::IpAddr, local: std::net::IpAddr) -> bool {
        let peer = peer.to_canonical();
        let local = local.to_canonical();
        peer.is_loopback() || local.is_loopback() || peer == local
    }

    fn reject_workload_unix_peer(stream: &std::os::unix::net::UnixStream) -> io::Result<()> {
        let credentials =
            nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
        let peer = u32::try_from(credentials.pid())
            .map_err(|_| io::Error::from_raw_os_error(libc::EACCES))?;
        // Linux reports PID zero for a peer outside our PID namespace. Such a
        // peer still must authenticate with the per-sandbox mTLS certificate.
        if peer != 0
            && peer != std::process::id()
            && is_process_descendant(peer, std::process::id())
                .map_err(|_| io::Error::from_raw_os_error(libc::EACCES))?
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(())
    }

    fn is_process_descendant(mut process: u32, ancestor: u32) -> io::Result<bool> {
        // Drivers run the sandbox as workload PID 1, so orphaned descendants
        // reparent to it and cannot escape this check by double-forking.
        // Read kernel-owned ancestry, never workload-supplied paths or UIDs.
        // If a peer exits during inspection, fail closed for that connection.
        for _ in 0..1024 {
            if process == ancestor {
                return Ok(true);
            }
            if process == 0 {
                return Ok(false);
            }
            let stat = std::fs::read_to_string(format!("/proc/{process}/stat"))?;
            let parent = stat
                .rsplit_once(')')
                .and_then(|(_, fields)| fields.split_whitespace().nth(1))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing peer process parent")
                })?
                .parse::<u32>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if parent == process {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cyclic peer process ancestry",
                ));
            }
            process = parent;
        }
        Err(io::Error::from_raw_os_error(libc::EACCES))
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
        if metadata.uid() != nix::unistd::geteuid().as_raw() {
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
        tls: &openshell_sandbox_backend::boundary_protocol::SandboxTlsServerConfig,
    ) -> io::Result<rustls::ServerConfig> {
        openshell_crypto::tls::ensure_default_provider();
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
        let mut config = openshell_crypto::tls::server_builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ])
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        for path in [&tls.certificate_chain_path, &tls.private_key_path] {
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
            stream: Box<
                tokio_rustls::server::TlsStream<
                    openshell_isolation_interface::contract::BoundaryDuplexStream,
                >,
            >,
            runtime: tokio::runtime::Handle,
        },
        Grpc {
            stream: tokio::io::DuplexStream,
            runtime: tokio::runtime::Handle,
        },
        #[cfg(test)]
        TestUnix(std::os::unix::net::UnixStream),
    }

    impl ControlStream {
        #[cfg(test)]
        fn establish(self, runtime: &tokio::runtime::Handle) -> io::Result<Self> {
            runtime.block_on(self.establish_async(runtime))
        }

        async fn establish_async(self, runtime: &tokio::runtime::Handle) -> io::Result<Self> {
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
            let stream = {
                tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "boundary TLS handshake timed out")
                    })?
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            }?;
            Ok(Self::Tls {
                stream: Box::new(stream),
                runtime: runtime.clone(),
            })
        }

        fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
            let _ = timeout;
            match self {
                Self::Tls { .. } | Self::Grpc { .. } => Ok(()),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                #[cfg(test)]
                Self::TestUnix(stream) => {
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))
                }
            }
        }

        fn into_tokio(
            self,
        ) -> Result<openshell_isolation_interface::contract::BoundaryDuplexStream, String> {
            match self {
                Self::Tls { stream, .. } => Ok(stream),
                Self::PendingTls { .. } => {
                    Err("boundary TLS stream has not completed its handshake".to_string())
                }
                Self::Grpc { stream, .. } => Ok(Box::new(stream)),
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
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.read(buffer))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "boundary TLS read timed out")
                        })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                Self::Grpc { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.read(buffer))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "gRPC boundary read timed out")
                        })?
                }),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.read(buffer),
            }
        }
    }

    impl Write for ControlStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            match self {
                Self::Tls { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.write(buffer))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "boundary TLS write timed out")
                        })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                Self::Grpc { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.write(buffer))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "gRPC boundary write timed out")
                        })?
                }),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.write(buffer),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            match self {
                Self::Tls { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.flush())
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "boundary TLS flush timed out")
                        })?
                }),
                Self::PendingTls { .. } => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "boundary TLS stream has not completed its handshake",
                )),
                Self::Grpc { stream, runtime } => runtime.block_on(async {
                    tokio::time::timeout(CONTROL_IO_TIMEOUT, stream.flush())
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "gRPC boundary flush timed out")
                        })?
                }),
                #[cfg(test)]
                Self::TestUnix(stream) => stream.flush(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use openshell_core::jwt::{
            CredentialEpoch, DEFAULT_SESSION_TOKEN_TTL, SandboxRuntimeIdentity, SessionJwtIssuer,
        };
        use openshell_sandbox_backend::boundary_protocol::{
            GatewayVerificationKey, SandboxTlsClientConfig, SandboxTlsServerConfig,
            generate_sandbox_tls_material,
        };
        use openshell_sandbox_backend::proto::{exchange_frame::Payload, mediate_frame};
        use openshell_sandbox_backend::protobuf::WireMessage as _;
        use openshell_sandbox_backend::runtime_routed::{RuntimeRouter, new_route_handle};
        use rcgen::PKCS_ED25519;

        struct FailedWaitProcess;

        #[async_trait::async_trait]
        impl BoundaryProcess for FailedWaitProcess {
            async fn wait(
                &self,
            ) -> Result<
                openshell_isolation_interface::contract::BoundaryExitStatus,
                openshell_isolation_interface::contract::BackendError,
            > {
                Err(
                    openshell_isolation_interface::contract::BackendError::Terminated(
                        "test boundary loss".to_string(),
                    ),
                )
            }

            async fn signal(
                &self,
                _signal: openshell_isolation_interface::contract::BoundarySignal,
            ) -> Result<(), openshell_isolation_interface::contract::BackendError> {
                Ok(())
            }

            async fn terminate(
                &self,
            ) -> Result<(), openshell_isolation_interface::contract::BackendError> {
                Ok(())
            }
        }

        #[tokio::test]
        async fn exec_wait_failure_records_reclaimable_terminal_status() {
            let session = MainSession::inert();
            let mut output = session.subscribe();
            let status = Arc::new(Mutex::new(None));

            retain_exec_completion(Arc::new(FailedWaitProcess), session, status.clone()).await;

            assert_eq!(*lock(&status), Some(ExitStatusWire::Exited(74)));
            assert!(matches!(
                output.recv().await.expect("terminal exec output"),
                MainOutput::Exit(74)
            ));
        }

        #[test]
        fn exec_tombstones_expire_without_a_lifetime_limit() {
            let mut ledger = ExecRequestLedger::default();
            // More than the old 4,096 limit can be admitted in one window.
            for index in 0..10_000 {
                let deadline = ledger.validate_deadline(Some(30_000), 0).unwrap();
                ledger
                    .reserve(&format!("request-{index}"), deadline)
                    .unwrap();
            }
            assert_eq!(ledger.requests.len(), 10_000);
            assert!(ledger.reserve("request-0", 30_000).is_err());
            // Expiration clears the IDs but never lets an old envelope run again.
            assert!(ledger.validate_deadline(Some(30_000), 30_000).is_err());
            assert!(ledger.requests.is_empty());
            assert!(ledger.expirations.is_empty());
            let deadline = ledger.validate_deadline(Some(60_000), 30_000).unwrap();
            ledger.reserve("next-request", deadline).unwrap();
            assert_eq!(ledger.requests.len(), 1);
        }

        #[test]
        fn exec_deadlines_reject_missing_expired_and_delayed_first_attempts() {
            let mut ledger = ExecRequestLedger::default();
            assert!(ledger.validate_deadline(None, 10_000).is_err());
            assert!(ledger.validate_deadline(Some(10_000), 10_000).is_err());
            assert!(ledger.validate_deadline(Some(9_999), 10_000).is_err());
            // A backwards clock change cannot resurrect expired requests.
            assert!(ledger.validate_deadline(Some(10_000), 0).is_err());
        }

        #[test]
        fn exec_tombstones_expire_in_deadline_order() {
            let mut ledger = ExecRequestLedger::default();
            ledger.reserve("later", 30_000).unwrap();
            ledger.reserve("earlier", 20_000).unwrap();
            ledger.validate_deadline(Some(30_000), 20_000).unwrap();
            assert!(!ledger.requests.contains("earlier"));
            assert!(ledger.requests.contains("later"));
            assert!(ledger.reserve("later", 30_000).is_err());
        }

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

        fn test_session_id() -> openshell_core::SandboxSessionId {
            "550e8400-e29b-41d4-a716-446655440000"
                .parse()
                .expect("test session ID")
        }

        fn test_supervisor_instance_id()
        -> openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId {
            openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId::new()
        }

        fn test_verification_key() -> GatewayVerificationKey {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                .expect("generate gateway key");
            GatewayVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: key.public_key_pem(),
            }
        }

        fn test_auth_material(sandbox_id: &str) -> (GatewayVerificationKey, String) {
            let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                .expect("generate gateway key");
            let verification_key = GatewayVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: key.public_key_pem(),
            };
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().unwrap().as_bytes(),
                "test-key",
                "test-gateway",
                Some(DEFAULT_SESSION_TOKEN_TTL),
                Arc::new(SystemJwtClock),
            )
            .expect("test session issuer");
            let token = issuer
                .mint_pair(&SandboxRuntimeIdentity {
                    sandbox_id: SandboxId::parse(sandbox_id).expect("test sandbox ID"),
                    runtime_generation:
                        openshell_core::sandbox_generation::SandboxGenerationId::parse(
                            "generation-1",
                        )
                        .expect("runtime generation"),
                    auth_epoch: CredentialEpoch::new(1).expect("test auth epoch"),
                })
                .expect("test token pair")
                .sandbox
                .token
                .expose_secret()
                .to_string();
            (verification_key, token)
        }

        fn bearer_request<T>(message: T, token: &str) -> tonic::Request<T> {
            let mut request = tonic::Request::new(message);
            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {token}")
                    .parse()
                    .expect("test authorization metadata"),
            );
            request
        }

        fn test_open_request(config: &BoundaryConfig) -> OpenBoundaryRequest {
            let descriptor =
                openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor {
                    boundary_id: config.boundary_id.clone(),
                    generation: config.generation.clone(),
                    session_id: config.session_id,
                    workload_identity: config.workload_identity.clone(),
                    transport:
                        openshell_sandbox_backend::boundary_protocol::SandboxTransport::Unix {
                            socket_path: Path::new("/test/boundary.sock").to_path_buf(),
                        },
                    tls: SandboxTlsClientConfig {
                        server_name: "test-boundary".to_string(),
                        trust_anchor_pem: "unused-test-anchor".to_string(),
                    },
                    host_gateway_ip: None,
                    resource_claims: config.resource_claims.clone(),
                    provisioning_evidence: config.provisioning_evidence.clone(),
                };
            OpenBoundaryRequest {
                session_id: config.session_id.to_string(),
                backend_name: openshell_sandbox_backend::BACKEND_NAME.to_string(),
                driver_descriptor: serde_json::to_vec(&descriptor).unwrap(),
            }
        }

        async fn test_open_boundary(
            channel: tonic::transport::Channel,
            request: OpenBoundaryRequest,
            token: &str,
        ) -> String {
            let mut control = openshell_sandbox_backend::backend_proto::isolation_backend_client::IsolationBackendClient::new(channel);
            control
                .describe(DescribeIsolationBackendRequest {
                    supervisor: Some(openshell_sandbox_backend::isolation_protocol::metadata(
                        "test/supervisor",
                    )),
                })
                .await
                .unwrap();
            let first = control
                .open_boundary(bearer_request(request.clone(), token))
                .await
                .unwrap()
                .into_inner();
            let retry = control
                .open_boundary(bearer_request(request, token))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(first, retry, "opening a launch is idempotent");
            assert_eq!(first.outcome, LaunchOutcome::Fresh as i32);
            first.boundary_id
        }

        fn placeholder_server_tls() -> SandboxTlsServerConfig {
            SandboxTlsServerConfig {
                certificate_chain_path: Path::new("/tmp/openshell-sandbox.crt").to_path_buf(),
                private_key_path: Path::new("/tmp/openshell-sandbox.key").to_path_buf(),
            }
        }

        fn stage_test_tls(
            directory: &Path,
            prefix: &str,
        ) -> (SandboxTlsServerConfig, SandboxTlsClientConfig) {
            let material =
                generate_sandbox_tls_material(test_session_id()).expect("generate test TLS");
            let certificate_chain_path = directory.join(format!("{prefix}-sandbox.crt"));
            let private_key_path = directory.join(format!("{prefix}-sandbox.key"));
            std::fs::write(&certificate_chain_path, material.certificate_chain_pem)
                .expect("write sandbox certificate");
            std::fs::write(&private_key_path, material.private_key_pem).expect("write sandbox key");
            (
                SandboxTlsServerConfig {
                    certificate_chain_path,
                    private_key_path,
                },
                SandboxTlsClientConfig {
                    server_name: material.server_name,
                    trust_anchor_pem: material.trust_anchor_pem,
                },
            )
        }

        fn test_client_config(tls: &SandboxTlsClientConfig) -> rustls::ClientConfig {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pemfile::certs(&mut tls.trust_anchor_pem.as_bytes()) {
                roots
                    .add(certificate.expect("parse test CA"))
                    .expect("add test CA");
            }
            let mut config = openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            config
        }

        #[test]
        fn boundary_config_debug_redacts_verification_material() {
            let verification_key = test_verification_key();
            let config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_id: test_session_id(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .expect("session rotation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                gateway_id: "test-gateway".to_string(),
                verification_keys: vec![verification_key.clone()],
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::new(),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                provisioning_evidence: test_provisioning_evidence(),
                child_env: std::collections::HashMap::new(),
            };
            let debug = format!("{config:?}");
            assert!(debug.contains("test-key"));
            assert!(!debug.contains(&verification_key.public_key_pem));
        }

        #[test]
        fn installed_supervisor_ca_is_readable_by_a_non_root_workload_identity() {
            use std::os::unix::fs::PermissionsExt as _;

            let root = tempfile::tempdir().expect("temporary CA root");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let directory = root.path().join("openshell-supervisor-ca");
            let (ca_path, bundle_path) = install_ca_material_at(
                &directory,
                b"public test certificate",
                b"public test bundle",
            )
            .expect("install supervisor CA")
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
        fn supervisor_ca_install_rejects_a_symlinked_directory() {
            let root = tempfile::tempdir().expect("temporary CA root");
            let target = root.path().join("target");
            std::fs::create_dir(&target).unwrap();
            let parent = root.path();
            std::os::unix::fs::symlink(&target, parent.join("openshell-supervisor-ca")).unwrap();

            let error = install_ca_material_at(
                &parent.join("openshell-supervisor-ca"),
                b"certificate",
                b"bundle",
            )
            .expect_err("symlinked CA directory must fail closed");
            assert!(error.contains("symlink"), "unexpected error: {error}");
        }

        #[test]
        fn supplementary_group_measurement_excludes_the_primary_group() {
            assert_eq!(
                normalized_supplementary_groups(vec![1002, 1001, 1000, 1001], 1000),
                vec![1001, 1002]
            );
        }

        #[test]
        fn boundary_termination_signal_name_is_explicit() {
            assert_eq!(boundary_termination_signal_name(libc::SIGTERM), "SIGTERM");
            assert_eq!(boundary_termination_signal_name(libc::SIGINT), "SIGINT");
            assert_eq!(boundary_termination_signal_name(0), "unknown signal");
        }

        #[test]
        fn supplementary_group_measurement_rejects_unexpected_groups_by_default() {
            assert!(!supplementary_groups_match(&[44, 992], &[], false));
        }

        #[test]
        fn gpu_runtime_groups_may_extend_but_not_replace_expected_groups() {
            assert!(supplementary_groups_match(&[44, 992, 1001], &[1001], true));
            assert!(!supplementary_groups_match(&[44, 992], &[1001], true));
        }

        #[test]
        fn generic_identity_claim_allows_runtime_supplementary_groups() {
            let config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_id: test_session_id(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .expect("session rotation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                gateway_id: "test-gateway".to_string(),
                verification_keys: vec![],
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::from([(
                    ALLOW_EXTRA_SUPPLEMENTARY_GROUPS_RESOURCE_CLAIM.to_string(),
                    "true".to_string(),
                )]),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                provisioning_evidence: test_provisioning_evidence(),
                child_env: std::collections::HashMap::new(),
            };
            assert!(allows_runtime_supplementary_groups(&config));
        }

        #[test]
        fn control_connection_slots_bound_authenticated_sessions() {
            let active = Arc::new(AtomicUsize::new(MAX_CONTROL_CONNECTIONS - 1));
            let slot = acquire_control_connection_slot(&active).expect("last available slot");
            assert!(acquire_control_connection_slot(&active).is_none());
            drop(slot);
            assert_eq!(active.load(Ordering::Acquire), MAX_CONTROL_CONNECTIONS - 1);
        }

        #[test]
        fn unix_control_rejects_workload_descendants_before_admission() {
            const CHILD_SOCKET: &str = "OPENSHELL_TEST_CONTROL_PEER_SOCKET";
            if let Some(path) = std::env::var_os(CHILD_SOCKET) {
                let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
                return;
            }
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("control.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "boundary_server::linux::tests::unix_control_rejects_workload_descendants_before_admission", "--nocapture"])
                .env(CHILD_SOCKET, &path).spawn().unwrap();
            let (stream, _) = listener.accept().unwrap();
            assert_eq!(
                reject_workload_unix_peer(&stream)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
            drop(stream);
            assert!(child.wait().unwrap().success());
            assert!(!is_process_descendant(std::process::id(), child.id()).unwrap());
            // Trusted same-process connections and external ancestors remain
            // eligible for mTLS; we do not equate same UID with workload trust.
            let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
            let (stream, _) = listener.accept().unwrap();
            reject_workload_unix_peer(&stream).unwrap();
            drop(client);
        }

        fn availability_test_runtime() -> (Arc<BoundaryRuntime>, String) {
            availability_test_runtime_with(None)
        }

        fn availability_test_runtime_with_flush(
            flush: FilesystemFlush,
        ) -> (Arc<BoundaryRuntime>, String) {
            availability_test_runtime_with(Some(flush))
        }

        /// Build a runtime over a TCP listener. `None` keeps the flush that the
        /// listener kind selects in production.
        fn availability_test_runtime_with(
            flush: Option<FilesystemFlush>,
        ) -> (Arc<BoundaryRuntime>, String) {
            let (broker, launcher) = test_network_broker();
            let (verification_key, token) = test_auth_material("availability");
            let mut runtime = BoundaryRuntime::new(
                BoundaryConfig {
                    boundary_id: "availability".to_string(),
                    generation: "generation-1".to_string(),
                    session_id: test_session_id(),
                    session_rotation: openshell_core::jwt::SessionRotation::new(1)
                        .expect("session rotation"),
                    auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                    gateway_id: "test-gateway".to_string(),
                    verification_keys: vec![verification_key],
                    listener: BoundaryListenerConfig::TlsTcp {
                        address: "127.0.0.1:5500".parse().unwrap(),
                        tls: placeholder_server_tls(),
                    },
                    resource_claims: std::collections::BTreeMap::new(),
                    resource_claim_files: std::collections::BTreeMap::new(),
                    workload_identity: test_workload_identity(),
                    provisioning_evidence: test_provisioning_evidence(),
                    child_env: std::collections::HashMap::new(),
                },
                tokio::runtime::Handle::current(),
                broker,
                launcher,
                test_runtime_qualification(),
            )
            .expect("test boundary runtime");
            if let Some(flush) = flush {
                runtime = runtime.with_filesystem_flush(flush);
            }
            (Arc::new(runtime), token)
        }

        #[tokio::test]
        async fn connection_expiry_uses_one_updateable_deadline() {
            let (shutdown, mut closed) = tokio::sync::watch::channel(());
            let expiry = ConnectionExpiry::new(shutdown);
            expiry.update_deadline(tokio::time::Instant::now() + Duration::from_millis(20));
            expiry.update_deadline(tokio::time::Instant::now() + Duration::from_millis(200));

            assert!(
                tokio::time::timeout(Duration::from_millis(80), closed.changed())
                    .await
                    .is_err(),
                "replacing the deadline must cancel the earlier expiry"
            );
            tokio::time::timeout(Duration::from_millis(250), closed.changed())
                .await
                .expect("updated connection deadline must fire")
                .expect("expiry worker must keep the shutdown channel open");
        }

        #[tokio::test]
        async fn non_expiring_connection_has_no_deadline() {
            let (shutdown, mut closed) = tokio::sync::watch::channel(());
            let expiry = ConnectionExpiry::new(shutdown);
            expiry.update_deadline(tokio::time::Instant::now() + Duration::from_millis(20));
            expiry.update(0);

            assert!(
                tokio::time::timeout(Duration::from_millis(80), closed.changed())
                    .await
                    .is_err(),
                "non-expiring credentials must clear the connection deadline"
            );
            expiry.update_deadline(tokio::time::Instant::now() + Duration::from_millis(20));
            tokio::time::timeout(Duration::from_millis(80), closed.changed())
                .await
                .expect("replacement connection deadline must fire")
                .expect("expiry worker must keep the shutdown channel open");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn idle_uds_and_tcp_handshakes_do_not_consume_authenticated_slots() {
            let directory = tempfile::tempdir().unwrap();
            let (tls, _) = stage_test_tls(directory.path(), "pending");
            let server_config = Arc::new(load_tls_server_config(&tls).unwrap());
            let (runtime, _) = availability_test_runtime();
            let active = Arc::new(AtomicUsize::new(0));
            let pending = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
            let mut clients: Vec<Box<dyn std::any::Any>> = Vec::new();
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..MAX_PENDING_HANDSHAKES {
                let stream = if index % 2 == 0 {
                    let (server, client) = std::os::unix::net::UnixStream::pair().unwrap();
                    clients.push(Box::new(client));
                    PlainControlStream::Unix(server)
                } else {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    clients.push(Box::new(
                        std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap(),
                    ));
                    PlainControlStream::Tcp(listener.accept().unwrap().0)
                };
                let permit = pending.clone().try_acquire_owned().unwrap();
                tasks.spawn(serve_control_connection(
                    ControlStream::PendingTls {
                        stream,
                        server_config: server_config.clone(),
                    },
                    runtime.clone(),
                    permit,
                    active.clone(),
                ));
            }
            assert!(pending.clone().try_acquire_owned().is_err());
            assert_eq!(active.load(Ordering::Acquire), 0);
            tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT + Duration::from_secs(2), async {
                while let Some(result) = tasks.join_next().await {
                    assert!(result.unwrap().unwrap_err().contains("timed out"));
                }
            })
            .await
            .unwrap();
            assert_eq!(pending.available_permits(), MAX_PENDING_HANDSHAKES);
            assert_eq!(active.load(Ordering::Acquire), 0);
            drop(clients);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn disconnected_session_reconfirms_before_becoming_active() {
            let (runtime, token) = availability_test_runtime();
            let supervisor_instance_id = test_supervisor_instance_id();
            let first_id = SandboxConnectionId::new();
            let first = runtime
                .authenticate_request(first_id, bearer_request((), &token).metadata())
                .expect("first principal");
            runtime
                .commit_attach(&first, supervisor_instance_id, None, None)
                .expect("attach first");
            // Confirmation runs on a blocking thread in production.
            tokio::task::block_in_place(|| runtime.commit_confirm(&first)).expect("confirm first");
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Connected(first_id)
            );
            let early = runtime
                .authenticate_request(
                    SandboxConnectionId::new(),
                    bearer_request((), &token).metadata(),
                )
                .expect("early replacement principal");
            assert!(
                matches!(
                    runtime.commit_attach(&early, supervisor_instance_id, None, None),
                    Err((BoundaryErrorKind::Unavailable, _))
                ),
                "reattach before the old transport is retired must be retryable"
            );

            runtime.transport_disconnected(first_id);
            let connection_state = *lock(&runtime.supervisor_connection);
            let recovery_id = match connection_state {
                SupervisorConnectionState::Frozen { recovery_id } => recovery_id,
                state => panic!("expected frozen connection, got {state:?}"),
            };
            let replacement_id = SandboxConnectionId::new();
            let replacement = runtime
                .authenticate_request(replacement_id, bearer_request((), &token).metadata())
                .expect("replacement principal");
            assert!(
                runtime
                    .commit_attach(&replacement, test_supervisor_instance_id(), None, None)
                    .is_err(),
                "a replacement supervisor process must not claim the generation"
            );
            runtime
                .commit_attach(&replacement, supervisor_instance_id, None, None)
                .expect("reattach replacement");
            assert_eq!(
                runtime.connections.require_active(&replacement),
                Err(SandboxAuthError::ConnectionNotAttached)
            );
            tokio::task::block_in_place(|| runtime.commit_confirm(&replacement))
                .expect("reconfirm replacement");
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Connected(replacement_id)
            );

            runtime.expire_recovery(recovery_id).await;
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Connected(replacement_id),
                "stale recovery deadline must not terminate a reconfirmed session"
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn expired_recovery_makes_the_session_terminal() {
            let (runtime, token) = availability_test_runtime();
            let supervisor_instance_id = test_supervisor_instance_id();
            let connection_id = SandboxConnectionId::new();
            let principal = runtime
                .authenticate_request(connection_id, bearer_request((), &token).metadata())
                .expect("test principal");
            runtime
                .commit_attach(&principal, supervisor_instance_id, None, None)
                .expect("attach");
            tokio::task::block_in_place(|| runtime.commit_confirm(&principal)).expect("confirm");
            runtime.transport_disconnected(connection_id);
            let connection_state = *lock(&runtime.supervisor_connection);
            let recovery_id = match connection_state {
                SupervisorConnectionState::Frozen { recovery_id } => recovery_id,
                state => panic!("expected frozen connection, got {state:?}"),
            };

            runtime.expire_recovery(recovery_id).await;
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Terminal
            );
            let replacement_id = SandboxConnectionId::new();
            let replacement = runtime
                .authenticate_request(replacement_id, bearer_request((), &token).metadata())
                .expect("replacement principal");
            assert!(
                runtime
                    .commit_attach(&replacement, supervisor_instance_id, None, None)
                    .is_err()
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn termination_flushes_the_filesystem_before_the_terminal_acknowledgement() {
            let runtime_cell: Arc<std::sync::OnceLock<std::sync::Weak<BoundaryRuntime>>> =
                Arc::default();
            let flushes = Arc::new(AtomicUsize::new(0));
            let saw_terminating = Arc::new(AtomicBool::new(false));
            let flush = {
                let runtime_cell = Arc::clone(&runtime_cell);
                let flushes = Arc::clone(&flushes);
                let saw_terminating = Arc::clone(&saw_terminating);
                FilesystemFlush {
                    run: Arc::new(move || {
                        // Flush before the terminal transition permits VM teardown.
                        if let Some(runtime) = runtime_cell.get().and_then(std::sync::Weak::upgrade)
                        {
                            saw_terminating.store(
                                matches!(
                                    *lock(&runtime.supervisor_connection),
                                    SupervisorConnectionState::Terminating
                                ),
                                Ordering::SeqCst,
                            );
                        }
                        flushes.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }),
                    timeout: FILESYSTEM_FLUSH_TIMEOUT,
                }
            };
            let (runtime, _token) = availability_test_runtime_with_flush(flush);
            runtime_cell
                .set(Arc::downgrade(&runtime))
                .expect("runtime cell is set once");

            assert_eq!(
                runtime.terminate_boundary().await,
                Response::BoundaryTerminated
            );

            assert_eq!(flushes.load(Ordering::SeqCst), 1);
            assert!(
                saw_terminating.load(Ordering::SeqCst),
                "the flush must run before the boundary turns terminal"
            );
            // A repeated request is answered from the terminal state and does not
            // flush again.
            assert_eq!(
                runtime.terminate_boundary().await,
                Response::BoundaryTerminated
            );
            assert_eq!(flushes.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn only_the_vm_listener_flushes_the_filesystem() {
            let tls = placeholder_server_tls();
            let vsock = BoundaryListenerConfig::Vsock {
                control_port: 5500,
                tls: tls.clone(),
            };
            let flush = FilesystemFlush::for_listener(&vsock).expect("the VM backend flushes");
            assert_eq!(flush.timeout, FILESYSTEM_FLUSH_TIMEOUT);

            let unix = BoundaryListenerConfig::Unix {
                socket_path: "/run/openshell/control.sock".into(),
                tls: tls.clone(),
            };
            let tcp = BoundaryListenerConfig::TlsTcp {
                address: "127.0.0.1:5500".parse().unwrap(),
                tls,
            };
            assert!(
                FilesystemFlush::for_listener(&unix).is_none(),
                "container sandboxes on a Unix socket must not flush"
            );
            assert!(
                FilesystemFlush::for_listener(&tcp).is_none(),
                "container sandboxes on a TCP listener must not flush"
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn container_listener_termination_runs_no_flush() {
            let (runtime, _token) = availability_test_runtime_with(None);
            assert!(
                runtime.filesystem_flush.is_none(),
                "a TCP-listener boundary must not install a flush"
            );

            assert_eq!(
                runtime.terminate_boundary().await,
                Response::BoundaryTerminated
            );
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Terminal
            );
        }

        /// Exercise the real syscall and open-error path; persistence requires
        /// VM stop/start testing.
        #[test]
        fn real_filesystem_flush_syncs_an_existing_path_and_reports_a_missing_one() {
            let directory = tempfile::tempdir().expect("temporary directory");
            std::fs::write(directory.path().join("data"), b"x").expect("write test data");
            sync_filesystem_at(directory.path()).expect("sync the filesystem holding the path");
            flush_root_filesystem().expect("sync the root filesystem");

            let missing = directory.path().join("missing");
            let error = sync_filesystem_at(&missing).expect_err("a missing path cannot be synced");
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn termination_is_acknowledged_when_the_filesystem_flush_fails() {
            let (runtime, _token) = availability_test_runtime_with_flush(FilesystemFlush {
                run: Arc::new(|| Err(io::Error::other("flush failed"))),
                timeout: FILESYSTEM_FLUSH_TIMEOUT,
            });

            assert_eq!(
                runtime.terminate_boundary().await,
                Response::BoundaryTerminated
            );
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Terminal
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn termination_is_acknowledged_when_the_filesystem_flush_hangs() {
            let (release, blocked) = std::sync::mpsc::channel::<()>();
            let blocked = Mutex::new(blocked);
            let (runtime, _token) = availability_test_runtime_with_flush(FilesystemFlush {
                run: Arc::new(move || {
                    let _ = lock(&blocked).recv();
                    Ok(())
                }),
                timeout: Duration::from_millis(100),
            });

            let started = tokio::time::Instant::now();
            let response = runtime.terminate_boundary().await;
            let elapsed = started.elapsed();
            // Let the blocked flush finish so the runtime can shut down.
            release.send(()).expect("release the blocked flush");

            assert_eq!(response, Response::BoundaryTerminated);
            assert!(
                elapsed < Duration::from_secs(2),
                "a hung flush must not hold the acknowledgement: {elapsed:?}"
            );
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Terminal
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn explicit_shutdown_acknowledges_terminal_session_state() {
            let (runtime, token) = availability_test_runtime();
            let supervisor_instance_id = test_supervisor_instance_id();
            let connection_id = SandboxConnectionId::new();
            let principal = runtime
                .authenticate_request(connection_id, bearer_request((), &token).metadata())
                .expect("test principal");
            runtime
                .commit_attach(&principal, supervisor_instance_id, None, None)
                .expect("attach");
            tokio::task::block_in_place(|| runtime.commit_confirm(&principal)).expect("confirm");

            assert_eq!(
                runtime.terminate_boundary().await,
                Response::BoundaryTerminated
            );
            assert_eq!(
                *lock(&runtime.supervisor_connection),
                SupervisorConnectionState::Terminal
            );
            assert_eq!(
                runtime.connections.require_active(&principal),
                Err(SandboxAuthError::TerminalSession)
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn grpc_blackhole_expires_connection_and_releases_mediation_lease() {
            let (runtime, token) = availability_test_runtime();
            let supervisor_instance_id = test_supervisor_instance_id();
            let connection_id = SandboxConnectionId::new();
            let principal = runtime
                .authenticate_request(connection_id, bearer_request((), &token).metadata())
                .expect("test principal");
            runtime
                .connections
                .attach(&principal, supervisor_instance_id, None)
                .expect("attach test connection");
            runtime
                .connections
                .confirm(&principal)
                .expect("confirm test connection");
            *lock(&runtime.supervisor_connection) =
                SupervisorConnectionState::Connected(connection_id);
            let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_address = server_listener.local_addr().unwrap();
            let server_runtime = runtime.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = server_listener.accept().await.unwrap();
                serve_grpc(Box::new(stream), server_runtime, connection_id).await
            });
            let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = proxy_listener.local_addr().unwrap();
            let (blackhole, stop_forwarding) = tokio::sync::oneshot::channel::<()>();
            let proxy = tokio::spawn(async move {
                let (mut downstream, _) = proxy_listener.accept().await.unwrap();
                let mut upstream = tokio::net::TcpStream::connect(server_address)
                    .await
                    .unwrap();
                tokio::select! {
                    _ = stop_forwarding => {},
                    _ = tokio::io::copy_bidirectional(&mut upstream, &mut downstream) => panic!("proxy closed before blackhole"),
                }
                // Keep both sockets open without forwarding PING or ACK: this
                // models a silently dropped Kubernetes TCP path, not FIN/RST.
                std::future::pending::<()>().await;
                drop((upstream, downstream));
            });
            let channel =
                tonic::transport::Endpoint::from_shared(format!("http://{proxy_address}"))
                    .unwrap()
                    .connect()
                    .await
                    .unwrap();
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            let handle =
                test_open_boundary(channel.clone(), test_open_request(&runtime.config), &token)
                    .await;
            sender
                .send(MediateFrame {
                    payload: Some(mediate_frame::Payload::BoundaryId(handle.clone())),
                })
                .await
                .unwrap();
            let request = RequestEnvelope::new(Request::OpenMediation).unwrap();
            sender
                .send(MediateFrame {
                    payload: Some(mediate_frame::Payload::Request(request.to_proto().unwrap())),
                })
                .await
                .unwrap();
            let mut response = SandboxProtocolClient::new(channel)
                .mediate(bearer_request(ReceiverStream::new(receiver), &token))
                .await
                .unwrap()
                .into_inner();
            assert!(response.message().await.unwrap().is_some());
            tokio::time::sleep(CONTROL_KEEPALIVE_INTERVAL + Duration::from_secs(1)).await;
            assert!(
                !server.is_finished(),
                "healthy idle session must survive keepalive"
            );
            assert!(runtime.mediation_active.try_lock().is_err());
            blackhole.send(()).unwrap();
            tokio::time::timeout(
                CONTROL_KEEPALIVE_INTERVAL + CONTROL_KEEPALIVE_TIMEOUT + Duration::from_secs(3),
                server,
            )
            .await
            .expect("blackholed HTTP/2 connection must expire")
            .unwrap()
            .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while runtime.mediation_active.try_lock().is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("connection teardown must stop all bridges and release lease");
            let principal = runtime
                .authenticate_request(
                    SandboxConnectionId::new(),
                    bearer_request((), &token).metadata(),
                )
                .expect("test principal");
            runtime
                .connections
                .attach(&principal, supervisor_instance_id, None)
                .expect("attach test connection");
            runtime
                .connections
                .confirm(&principal)
                .expect("confirm test connection");
            let (mut replacement, task) = request_test_mediation(runtime, principal).await;
            let ready: ResponseEnvelope =
                openshell_sandbox_backend::boundary_protocol::read_frame_async(&mut replacement)
                    .await
                    .unwrap();
            assert!(matches!(ready.response, Response::MediationReady));
            drop(replacement);
            task.await.unwrap().unwrap();
            drop(sender);
            proxy.abort();
        }

        async fn request_test_mediation(
            runtime: Arc<BoundaryRuntime>,
            principal: SandboxProtocolPrincipal,
        ) -> (
            tokio::io::DuplexStream,
            tokio::task::JoinHandle<Result<(), String>>,
        ) {
            let (mut client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(serve_persistent_mediation(server, runtime, principal));
            let envelope = RequestEnvelope::new(Request::OpenMediation).unwrap();
            client
                .write_all(&encode_frame(&envelope).unwrap())
                .await
                .unwrap();
            (client, task)
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn mediation_replacement_waits_for_lease_and_rejects_bad_authentication() {
            let (runtime, token) = availability_test_runtime();
            let connection_id = SandboxConnectionId::new();
            let principal = runtime
                .authenticate_request(connection_id, bearer_request((), &token).metadata())
                .expect("test principal");
            runtime
                .connections
                .attach(&principal, test_supervisor_instance_id(), None)
                .expect("attach test connection");
            runtime
                .connections
                .confirm(&principal)
                .expect("confirm test connection");
            let (mut first, first_task) =
                request_test_mediation(runtime.clone(), principal.clone()).await;
            let ready: ResponseEnvelope =
                openshell_sandbox_backend::boundary_protocol::read_frame_async(&mut first)
                    .await
                    .unwrap();
            assert!(matches!(ready.response, Response::MediationReady));
            let (mut denied, denied_task) =
                request_test_mediation(runtime.clone(), principal.clone()).await;
            let response: ResponseEnvelope =
                openshell_sandbox_backend::boundary_protocol::read_frame_async(&mut denied)
                    .await
                    .unwrap();
            assert!(matches!(
                response.response,
                Response::Error {
                    kind: BoundaryErrorKind::Denied,
                    ..
                }
            ));
            denied_task.await.unwrap().unwrap();
            let (mut replacement, replacement_task) =
                request_test_mediation(runtime.clone(), principal).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), replacement.read_u8())
                    .await
                    .is_err(),
                "a live lease cannot be preempted"
            );
            drop(first);
            first_task.await.unwrap().unwrap();
            let ready: ResponseEnvelope = tokio::time::timeout(
                Duration::from_secs(1),
                openshell_sandbox_backend::boundary_protocol::read_frame_async(&mut replacement),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(ready.response, Response::MediationReady));
            assert!(runtime.mediation_active.try_lock().is_err());
            drop(replacement);
            replacement_task.await.unwrap().unwrap();
            assert!(runtime.mediation_active.try_lock().is_ok());
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

        fn test_provisioning_evidence()
        -> openshell_isolation_interface::contract::ProvisioningEvidence {
            openshell_isolation_interface::contract::ProvisioningEvidence::from_enforcement_evidence(
                "generation-1",
                b"test-vm-fence",
            )
            .unwrap()
        }

        fn test_runtime_qualification() -> crate::RuntimeQualification {
            crate::RuntimeQualification {
                seccomp: openshell_sandbox_backend::boundary_protocol::SeccompEvidence {
                    new_listener: true,
                    notification_round_trip: true,
                    id_validation: true,
                    addfd_send: true,
                    retained_socket_operation: true,
                    proc_fd_identity: true,
                    task_memory_read: true,
                },
                landlock_abi: 6,
                landlock_allow_deny: true,
                udp_dns_round_trip: true,
                tcp_dns_round_trip: true,
                tcp_allow_round_trip: true,
                tcp_deny_round_trip: true,
                socket_loopback_confinement: true,
            }
        }

        fn test_network_broker() -> (
            NetworkBroker,
            crate::linux::workload_launcher::WorkloadLauncher,
        ) {
            let (launcher, listener) =
                crate::linux::workload_launcher::start().expect("start test listener");
            (
                NetworkBroker::start_for_test(listener).expect("start test network broker"),
                launcher,
            )
        }

        #[test]
        fn image_discovery_preserves_invalid_content_and_bounds_reads() {
            let directory = tempfile::tempdir().unwrap();
            let primary = directory.path().join("policy.yaml");
            let legacy = directory.path().join("legacy.yaml");
            let paths = [primary.to_str().unwrap(), legacy.to_str().unwrap()];
            assert_eq!(
                BoundaryRuntime::discover_image_policy_from_paths(&paths),
                Response::ImagePolicy {
                    yaml: None,
                    invalid: false
                }
            );
            std::fs::write(&legacy, "legacy policy").unwrap();
            assert_eq!(
                BoundaryRuntime::discover_image_policy_from_paths(&paths),
                Response::ImagePolicy {
                    yaml: Some("legacy policy".to_string()),
                    invalid: false
                }
            );
            // Parsing belongs to admission; malformed primary content must never fall back.
            std::fs::write(&primary, "not: [valid yaml").unwrap();
            assert_eq!(
                BoundaryRuntime::discover_image_policy_from_paths(&paths),
                Response::ImagePolicy {
                    yaml: Some("not: [valid yaml".to_string()),
                    invalid: false
                }
            );
            std::fs::write(&primary, vec![b'x'; 1_048_577]).unwrap();
            assert_eq!(
                BoundaryRuntime::discover_image_policy_from_paths(&paths),
                Response::ImagePolicy {
                    yaml: None,
                    invalid: true
                }
            );
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
                session_id: test_session_id(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .expect("session rotation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                gateway_id: "test-gateway".to_string(),
                verification_keys: vec![test_verification_key()],
                listener: BoundaryListenerConfig::Vsock {
                    control_port: 5500,
                    tls: placeholder_server_tls(),
                },
                resource_claims: std::collections::BTreeMap::new(),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                provisioning_evidence: test_provisioning_evidence(),
                child_env: std::collections::HashMap::new(),
            };

            validate_config(&config).unwrap();
            validate_running_identity(&config.workload_identity, false).unwrap();
            let mut wrong_user = config.workload_identity.clone();
            wrong_user.uid = if wrong_user.uid == 10000 {
                10001
            } else {
                10000
            };
            assert!(validate_running_identity(&wrong_user, false).is_err());
            let mut wrong_group = config.workload_identity;
            wrong_group.gid = if wrong_group.gid == 10000 {
                10001
            } else {
                10000
            };
            assert!(validate_running_identity(&wrong_group, false).is_err());
        }

        fn vm_identity_test_runtime() -> (tokio::runtime::Runtime, Arc<BoundaryRuntime>) {
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("test process runtime");
            let mut boundary = {
                let _entered = process_runtime.enter();
                availability_test_runtime().0
            };
            let config = &mut Arc::get_mut(&mut boundary)
                .expect("test boundary has one owner")
                .config;
            config
                .resource_claims
                .insert("vm.generation".to_string(), config.generation.clone());
            (process_runtime, boundary)
        }

        fn vm_identity_test_policy(user: Option<&str>, group: Option<&str>) -> SandboxPolicyWire {
            SandboxPolicyWire::from(openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy {
                    run_as_user: user.map(str::to_string),
                    run_as_group: group.map(str::to_string),
                },
            })
        }

        #[test]
        fn vm_policy_identity_checks_independent_selectors() {
            let (_runtime, mut boundary) = vm_identity_test_runtime();
            let uid = boundary.config.workload_identity.uid.to_string();
            let gid = boundary.config.workload_identity.gid.to_string();
            for (user, group) in [
                (None, None),
                (Some(""), Some("")),
                (Some(uid.as_str()), None),
                (None, Some(gid.as_str())),
                (Some(uid.as_str()), Some(gid.as_str())),
                (Some("sandbox"), Some(gid.as_str())),
                (Some(uid.as_str()), Some("sandbox")),
                (Some("sandbox"), Some("sandbox")),
            ] {
                validate_vm_policy_identity(
                    &boundary.config,
                    &vm_identity_test_policy(user, group),
                )
                .expect("matching or omitted VM selectors");
            }
            let wrong_user = if uid == "10000" { "10001" } else { "10000" };
            let wrong_group = if gid == "10000" { "10001" } else { "10000" };
            for (user, group, field) in [
                (Some(wrong_user), None, "run_as_user"),
                (None, Some(wrong_group), "run_as_group"),
                (Some(uid.as_str()), Some(wrong_group), "run_as_group"),
                (Some(wrong_user), Some(gid.as_str()), "run_as_user"),
                (Some(wrong_user), Some(wrong_group), "run_as_user"),
            ] {
                let error = validate_vm_policy_identity(
                    &boundary.config,
                    &vm_identity_test_policy(user, group),
                )
                .expect_err("either mismatched selector must fail");
                assert!(error.contains(field), "{error}");
                assert!(error.contains(&format!("{uid}:{gid}")), "{error}");
            }
            for malformed in [
                "root",
                "-1",
                "4294967296",
                "1000:1000",
                " sandbox",
                "sandbox\n",
            ] {
                for (user, group) in [(Some(malformed), None), (None, Some(malformed))] {
                    assert!(
                        validate_vm_policy_identity(
                            &boundary.config,
                            &vm_identity_test_policy(user, group),
                        )
                        .is_err(),
                        "invalid selector {malformed:?} must fail"
                    );
                }
            }
            Arc::get_mut(&mut boundary)
                .expect("test boundary has one owner")
                .config
                .resource_claims
                .remove("vm.generation");
            validate_vm_policy_identity(
                &boundary.config,
                &vm_identity_test_policy(Some(wrong_user), Some("image-user")),
            )
            .expect("non-VM identity behavior is unchanged");
        }

        #[test]
        fn vm_attach_rejects_conflicting_identity_without_binding() {
            let (_runtime, boundary) = vm_identity_test_runtime();
            let identity = &boundary.config.workload_identity;
            let uid = identity.uid.to_string();
            let gid = identity.gid.to_string();
            let wrong_user = if uid == "10000" { "10001" } else { "10000" };
            let wrong_group = if gid == "10000" { "10001" } else { "10000" };
            for (user, group, field, requested) in [
                (Some(wrong_user), None, "run_as_user", wrong_user),
                (None, Some(wrong_group), "run_as_group", wrong_group),
            ] {
                let response = boundary.attach(vm_identity_test_policy(user, group), false);
                let Response::Error { kind, message } = response else {
                    panic!("conflicting identity was attached: {response:?}");
                };
                assert_eq!(kind, BoundaryErrorKind::Denied);
                assert!(
                    message.contains(&format!("{field} '{requested}'")),
                    "{message}"
                );
                assert!(message.contains(&format!("{uid}:{gid}")), "{message}");
                assert!(matches!(
                    *lock(&boundary.state),
                    RuntimeState::AwaitingAttach
                ));
                assert!(lock(&boundary.attached_policy).is_none());
            }
            assert!(matches!(
                boundary.attach(
                    vm_identity_test_policy(Some("sandbox"), Some("sandbox")),
                    false
                ),
                Response::Attached { .. }
            ));
        }

        #[test]
        fn tcp_control_listener_rejects_loopback_addresses() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (server_tls, _client_tls) = stage_test_tls(directory.path(), "validate");
            let config = |address: &str| BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_id: test_session_id(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .expect("session rotation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                gateway_id: "test-gateway".to_string(),
                verification_keys: vec![test_verification_key()],
                listener: BoundaryListenerConfig::TlsTcp {
                    address: address.parse().expect("valid address"),
                    tls: server_tls.clone(),
                },
                resource_claims: std::collections::BTreeMap::new(),
                resource_claim_files: std::collections::BTreeMap::new(),
                workload_identity: test_workload_identity(),
                provisioning_evidence: test_provisioning_evidence(),
                child_env: std::collections::HashMap::new(),
            };
            for address in [
                "127.0.0.1:5500",
                "127.0.0.2:5500",
                "[::1]:5500",
                "[::ffff:127.0.0.1]:5500",
            ] {
                assert!(
                    validate_config(&config(address)).is_err(),
                    "{address} must be rejected"
                );
            }
            for address in ["0.0.0.0:5500", "[::]:5500", "10.42.0.7:5500"] {
                validate_config(&config(address))
                    .unwrap_or_else(|error| panic!("{address} must be accepted: {error}"));
            }
        }

        /// Find the member hosting `route` as a pool runtime does, then serve
        /// the runtime's TLS identity, which only a supervisor expecting this
        /// route completes.
        async fn dial_and_serve_tls(
            addresses: &[std::net::SocketAddr],
            route: &str,
            preferred: Option<std::net::SocketAddr>,
            server_config: &Arc<rustls::ServerConfig>,
        ) -> io::Result<(std::net::SocketAddr, bool)> {
            let dialed = dial_route_owner(addresses, route, preferred).await?;
            let reached = (dialed.member, dialed.redirected);
            ControlStream::PendingTls {
                stream: PlainControlStream::Tcp(dialed.stream.into_std()?),
                server_config: server_config.clone(),
            }
            .establish_async(&tokio::runtime::Handle::current())
            .await
            .map(|_| reached)
        }

        #[tokio::test]
        async fn runtime_follows_route_redirect_to_its_owner_and_dials_a_preferred_member_first() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (server_tls, client_tls) = stage_test_tls(directory.path(), "redirect");
            let server_config =
                Arc::new(load_tls_server_config(&server_tls).expect("load runtime TLS identity"));
            let route = new_route_handle();
            // Pool members share the configured port on different addresses.
            let member = RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).expect("bind member");
            let owner = RuntimeRouter::bind(std::net::SocketAddr::new(
                "127.0.0.2".parse().unwrap(),
                member.local_addr().port(),
            ))
            .expect("bind owner");
            let registration = owner.register(&route, &client_tls).expect("register route");
            let directory_naming = |owner_address: std::net::SocketAddr| {
                std::collections::HashMap::from([(route.clone(), owner_address)])
            };
            member.set_directory(
                Some(member.local_addr()),
                directory_naming(owner.local_addr()),
            );
            owner.set_directory(
                Some(owner.local_addr()),
                directory_naming(owner.local_addr()),
            );
            let configured = [member.local_addr()];

            // The configured member redirects to the owner, which names
            // itself and completes the pinned handshake.
            assert_eq!(
                dial_and_serve_tls(&configured, &route, None, &server_config)
                    .await
                    .expect("dial through redirect"),
                (owner.local_addr(), true)
            );

            // A preferred member is dialed directly, even once the
            // configured member no longer knows the route.
            member.set_directory(Some(member.local_addr()), std::collections::HashMap::new());
            assert_eq!(
                dial_and_serve_tls(
                    &configured,
                    &route,
                    Some(owner.local_addr()),
                    &server_config
                )
                .await
                .expect("dial preferred member"),
                (owner.local_addr(), false)
            );

            // A preferred member that no longer hosts the route is passed
            // over for the configured addresses.
            drop(registration);
            let _registration = member.register(&route, &client_tls).expect("move route");
            member.set_directory(
                Some(member.local_addr()),
                directory_naming(member.local_addr()),
            );
            assert_eq!(
                dial_and_serve_tls(
                    &configured,
                    &route,
                    Some(owner.local_addr()),
                    &server_config
                )
                .await
                .expect("dial configured member"),
                (member.local_addr(), false)
            );
        }

        #[tokio::test]
        async fn a_supervisor_from_before_route_negotiation_is_reached_with_the_first_preface() {
            // A shared supervisor that only knows version 1 prefaces closes a
            // version 2 one without replying, as the #4702 router did.
            let legacy = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("legacy supervisor");
            let address = legacy.local_addr().expect("legacy address");
            let route = new_route_handle();
            let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                // Connections kept for the TLS handshake that follows; they
                // close when the task is aborted.
                #[allow(clippy::collection_is_never_read)]
                let mut kept = Vec::new();
                loop {
                    let (mut stream, _) = legacy.accept().await.expect("accept");
                    let mut header = [0_u8; 6];
                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut header)
                        .await
                        .expect("preface header");
                    if header[4] != 1 {
                        seen_tx.send((header[4], String::new())).expect("record");
                        continue;
                    }
                    let mut handle = vec![0_u8; usize::from(header[5])];
                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut handle)
                        .await
                        .expect("route handle");
                    seen_tx
                        .send((header[4], String::from_utf8(handle).expect("handle")))
                        .expect("record");
                    kept.push(stream);
                }
            });
            let (_stream, reply) = negotiate_route_at(address, &route)
                .await
                .expect("the legacy supervisor is reached");
            assert_eq!(
                reply,
                openshell_sandbox_backend::runtime_routed::RouteReply::Accept(None)
            );
            assert_eq!(seen.recv().await, Some((2, String::new())));
            assert_eq!(seen.recv().await, Some((1, route)));
            server.abort();

            // A current supervisor's refusal is a reply, not a reason to fall
            // back: the runtime stays on the negotiated path.
            let router = RuntimeRouter::bind("127.0.0.1:0".parse().expect("router address"))
                .expect("router");
            let unknown = new_route_handle();
            let (_stream, reply) = negotiate_route_at(router.local_addr(), &unknown)
                .await
                .expect("negotiated");
            assert_eq!(
                reply,
                openshell_sandbox_backend::runtime_routed::RouteReply::Unknown
            );
        }

        #[tokio::test]
        async fn runtime_refuses_route_redirects_off_the_supervisor_port_or_past_two_hops() {
            let route = new_route_handle();
            let member = RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).expect("bind member");
            let configured = [member.local_addr()];

            // A redirect to another port is refused before it is dialed.
            let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind other listener");
            member.set_directory(
                Some(member.local_addr()),
                std::collections::HashMap::from([(
                    route.clone(),
                    elsewhere.local_addr().expect("other listener address"),
                )]),
            );
            let error = dial_route_owner(&configured, &route, None)
                .await
                .err()
                .expect("an off-port redirect is refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(
                tokio::time::timeout(Duration::from_millis(200), elsewhere.accept())
                    .await
                    .is_err()
            );

            // Two members that each name the other are abandoned after two
            // redirects.
            let peer = RuntimeRouter::bind(std::net::SocketAddr::new(
                "127.0.0.2".parse().unwrap(),
                member.local_addr().port(),
            ))
            .expect("bind peer");
            member.set_directory(
                Some(member.local_addr()),
                std::collections::HashMap::from([(route.clone(), peer.local_addr())]),
            );
            peer.set_directory(
                Some(peer.local_addr()),
                std::collections::HashMap::from([(route.clone(), member.local_addr())]),
            );
            let error = dial_route_owner(&configured, &route, None)
                .await
                .err()
                .expect("a redirect loop is abandoned");
            assert!(error.to_string().contains("hop limit"), "{error}");
        }

        /// A routed runtime of a lone shared supervisor, which never names
        /// itself, keeps its one spare there and never probes the configured
        /// addresses; a runtime whose supervisor named itself a pool member
        /// runs discovery rounds through them.
        #[test]
        fn only_a_runtime_that_saw_a_pool_probes_for_its_route() {
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            for pooled in [false, true] {
                let gateway = TestGateway::new();
                let boundary = takeover_test_runtime(
                    &gateway,
                    "sandbox-probe",
                    "generation-probe",
                    &process_runtime,
                );
                let directory = tempfile::tempdir().expect("temporary directory");
                let (server_tls, client_tls) = stage_test_tls(directory.path(), "probe");
                let server_config = Arc::new(
                    load_tls_server_config(&server_tls).expect("load runtime TLS identity"),
                );
                let route = new_route_handle();
                let supervisor =
                    RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).expect("bind supervisor");
                let _registration = supervisor
                    .register(&route, &client_tls)
                    .expect("supervisor hosts route");
                if pooled {
                    supervisor.set_directory(
                        Some(supervisor.local_addr()),
                        std::collections::HashMap::from([(route.clone(), supervisor.local_addr())]),
                    );
                }
                // The configured address counts every connection the runtime
                // opens before passing it on to the supervisor.
                let service = process_runtime
                    .block_on(tokio::net::TcpListener::bind((
                        "127.0.0.3",
                        supervisor.local_addr().port(),
                    )))
                    .expect("bind service");
                let service_address = service.local_addr().expect("service address");
                let dialed = Arc::new(AtomicUsize::new(0));
                let target = supervisor.local_addr();
                let counter = dialed.clone();
                let forwarding = process_runtime.spawn(async move {
                    while let Ok((mut inbound, _)) = service.accept().await {
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                                    .await;
                            }
                        });
                    }
                });
                let control = process_runtime.spawn(run_routed_runtime_control(
                    SupervisorRoute {
                        addresses: vec![service_address],
                        route: route.clone(),
                    },
                    server_config,
                    boundary,
                    Arc::new(AtomicUsize::new(0)),
                    Duration::from_millis(100),
                ));
                std::thread::sleep(Duration::from_millis(1200));
                let connections = dialed.load(Ordering::SeqCst);
                control.abort();
                forwarding.abort();
                if pooled {
                    assert!(
                        connections > 1,
                        "a pool runtime must run discovery rounds: {connections} connections"
                    );
                } else {
                    assert_eq!(
                        connections, 1,
                        "a lone supervisor gets exactly one spare and no probes"
                    );
                }
            }
        }

        /// The gateway granted a pool runtime's route to member B while the
        /// previous owner A stays reachable: A keeps its stale route and an
        /// unused spare and never closes them. Discovery through the
        /// configured addresses still reaches B within a few rounds without
        /// touching A's connection; B authenticates its term on that
        /// connection and takes over, which closes A's spare, refuses A's
        /// credentials, and makes B the member the runtime dials first. When
        /// a restarted process at A's address is then granted a later term,
        /// it reaches the runtime and takes over from B the same way: the
        /// address that held a fenced term grants nothing and blocks nothing.
        #[test]
        #[allow(clippy::too_many_lines)]
        fn a_reachable_stale_owner_cannot_keep_a_new_owner_from_the_runtime() {
            const SANDBOX: &str = "sandbox-stale-owner";
            const GENERATION: &str = "generation-stale-owner";
            const BUDGET: Duration = Duration::from_secs(10);
            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let directory = tempfile::tempdir().expect("temporary directory");
            let (server_tls, client_tls) = stage_test_tls(directory.path(), "stale-owner");
            let server_config =
                Arc::new(load_tls_server_config(&server_tls).expect("load runtime TLS identity"));
            let route = new_route_handle();

            // Two pool members and the pool's Service, which spreads
            // connections over them in turn, all on the runtime port.
            let member_a = RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).expect("bind A");
            let port = member_a.local_addr().port();
            let member_b = RuntimeRouter::bind(std::net::SocketAddr::new(
                "127.0.0.2".parse().unwrap(),
                port,
            ))
            .expect("bind B");
            let (a, b) = (member_a.local_addr(), member_b.local_addr());
            let service = process_runtime
                .block_on(tokio::net::TcpListener::bind(("127.0.0.3", port)))
                .expect("bind service");
            let service_address = service.local_addr().expect("service address");
            process_runtime.spawn(async move {
                let backends = [a, b];
                let mut next = 0_usize;
                while let Ok((mut inbound, _)) = service.accept().await {
                    let backend = backends[next % backends.len()];
                    next += 1;
                    tokio::spawn(async move {
                        if let Ok(mut outbound) = tokio::net::TcpStream::connect(backend).await {
                            let _ =
                                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                }
            });
            let naming = |owner: std::net::SocketAddr| {
                std::collections::HashMap::from([(route.clone(), owner)])
            };
            member_a.set_directory(Some(a), naming(a));
            member_b.set_directory(Some(b), naming(a));
            let registration_a = member_a
                .register(&route, &client_tls)
                .expect("A hosts route");
            process_runtime.spawn(run_routed_runtime_control(
                SupervisorRoute {
                    addresses: vec![service_address],
                    route: route.clone(),
                },
                server_config,
                boundary.clone(),
                Arc::new(AtomicUsize::new(0)),
                Duration::from_millis(200),
            ));

            // A takes the runtime's spare and is confirmed on it with launch
            // credentials, then never uses or closes it.
            let mut stale_spare = process_runtime
                .block_on(tokio::time::timeout(
                    BUDGET,
                    registration_a.accept(&client_tls),
                ))
                .expect("A receives a spare")
                .expect("authenticated spare");
            let known_connections = || {
                lock(&boundary.connection_origins)
                    .keys()
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
            };
            // The connection a member opened after `known` was taken.
            let connection_from =
                |member: std::net::SocketAddr, known: &std::collections::HashSet<_>| {
                    let deadline = std::time::Instant::now() + BUDGET;
                    loop {
                        let found = lock(&boundary.connection_origins)
                            .iter()
                            .find(|(connection, origin)| {
                                **origin == member && !known.contains(*connection)
                            })
                            .map(|(connection, _)| *connection);
                        if let Some(connection) = found {
                            return connection;
                        }
                        assert!(
                            std::time::Instant::now() < deadline,
                            "no new connection from {member}"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                };
            let authenticate = |connection, epoch| {
                boundary
                    .authenticate_request(
                        connection,
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, epoch)).metadata(),
                    )
                    .expect("principal")
            };
            let launch_owner =
                authenticate(connection_from(a, &std::collections::HashSet::default()), 1);
            boundary
                .commit_attach(&launch_owner, test_supervisor_instance_id(), None, None)
                .expect("attach A");
            boundary.commit_confirm(&launch_owner).expect("confirm A");
            assert_eq!(boundary.confirmed_route_owner(), Some(a));

            // The gateway grants the route to B; A, cut off from the
            // gateway, still names itself.
            let registration_b = member_b
                .register(&route, &client_tls)
                .expect("B hosts route");
            member_b.set_directory(Some(b), naming(b));
            let delivered = process_runtime
                .block_on(tokio::time::timeout(
                    BUDGET,
                    registration_b.accept(&client_tls),
                ))
                .expect("B receives a runtime connection within the budget")
                .expect("authenticated connection to B");
            // Nothing of A's was closed to find B: its unused spare holds
            // only the runtime's HTTP/2 greeting.
            let mut greeting = [0_u8; 256];
            let still_open = process_runtime.block_on(tokio::time::timeout(
                Duration::from_millis(300),
                tokio::io::AsyncReadExt::read(&mut stale_spare, &mut greeting),
            ));
            assert!(
                matches!(still_open, Err(_) | Ok(Ok(1..))),
                "A's unused spare must stay open: {still_open:?}"
            );

            // B negotiates and authenticates its term on that connection.
            let mut delivered = Some(delivered);
            let channel = process_runtime
                .block_on(
                    tonic::transport::Endpoint::from_static("http://boundary.openshell.internal")
                        .connect_with_connector(tower::service_fn(
                            move |_: tonic::transport::Uri| {
                                let stream = delivered.take();
                                async move {
                                    stream.map(hyper_util::rt::TokioIo::new).ok_or_else(|| {
                                        io::Error::other("the delivered connection is in use")
                                    })
                                }
                            },
                        )),
                )
                .expect("gRPC over B's connection");
            let mut control = openshell_sandbox_backend::backend_proto::isolation_backend_client::IsolationBackendClient::new(channel);
            let described = process_runtime
                .block_on(control.describe(DescribeIsolationBackendRequest {
                    supervisor: Some(openshell_sandbox_backend::isolation_protocol::metadata(
                        "test/supervisor",
                    )),
                }))
                .expect("describe")
                .into_inner();
            assert!(
                described
                    .backend
                    .expect("backend metadata")
                    .supported_capabilities
                    .iter()
                    .any(|capability| {
                        capability
                            == openshell_sandbox_backend::isolation_protocol::SUPERVISOR_TAKEOVER_CAPABILITY
                    })
            );
            process_runtime
                .block_on(control.open_boundary(bearer_request(
                    test_open_request(&boundary.config),
                    &gateway.token(SANDBOX, GENERATION, 2),
                )))
                .expect("B opens the boundary with its term's credential");
            let replacement = test_supervisor_instance_id();
            let grant = boundary
                .authenticator
                .verify_takeover(&gateway.grant(SANDBOX, GENERATION, 2, replacement))
                .expect("grant");
            let candidate =
                authenticate(connection_from(b, &std::collections::HashSet::default()), 2);
            boundary
                .commit_attach(&candidate, replacement, Some(&grant), None)
                .expect("stage B");
            boundary.commit_confirm(&candidate).expect("confirm B");

            // A is fenced: its spare is closed and its credentials are
            // refused, and the runtime gives its next spare to B.
            assert_eq!(boundary.confirmed_route_owner(), Some(b));
            process_runtime
                .block_on(tokio::time::timeout(BUDGET, async {
                    while matches!(
                        tokio::io::AsyncReadExt::read(&mut stale_spare, &mut greeting).await,
                        Ok(1..)
                    ) {}
                }))
                .expect("A's spare closes");
            assert!(
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, 1)).metadata(),
                    )
                    .is_err(),
                "the fenced term's credentials are refused"
            );
            process_runtime
                .block_on(tokio::time::timeout(
                    BUDGET,
                    registration_b.accept(&client_tls),
                ))
                .expect("the owner receives the next spare")
                .expect("authenticated spare for B");

            // A's process restarts at the same address and the gateway grants
            // it the next term while B still holds the route.
            let returned_at = std::time::Instant::now();
            drop(registration_a);
            // Connections the previous process queued close with it.
            let drained_by = std::time::Instant::now() + BUDGET;
            while lock(&boundary.connection_origins)
                .values()
                .any(|origin| *origin == a)
            {
                assert!(
                    std::time::Instant::now() < drained_by,
                    "A's old connections linger"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let before_return = known_connections();
            let registration_a = member_a
                .register(&route, &client_tls)
                .expect("A hosts again");
            member_a.set_directory(Some(a), naming(a));
            member_b.set_directory(Some(b), naming(a));
            let _returned = process_runtime
                .block_on(tokio::time::timeout(
                    BUDGET,
                    registration_a.accept(&client_tls),
                ))
                .expect("A's new process receives a runtime connection within the budget")
                .expect("authenticated connection to A");
            let restarted = test_supervisor_instance_id();
            let grant = boundary
                .authenticator
                .verify_takeover(&gateway.grant(SANDBOX, GENERATION, 3, restarted))
                .expect("grant");
            let returning = authenticate(connection_from(a, &before_return), 3);
            boundary
                .commit_attach(&returning, restarted, Some(&grant), None)
                .expect("stage A's later term");
            boundary
                .commit_confirm(&returning)
                .expect("confirm A's later term");
            assert_eq!(boundary.confirmed_route_owner(), Some(a));
            assert!(
                returned_at.elapsed() < Duration::from_secs(5),
                "the later term at A's address must not wait out the old one: {:?}",
                returned_at.elapsed()
            );
            assert!(
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, 2)).metadata(),
                    )
                    .is_err(),
                "B's term is fenced in turn"
            );
        }

        #[test]
        fn route_redirects_never_lead_more_local_than_configured_addresses() {
            let pod: std::net::SocketAddr = "10.42.0.7:7443".parse().unwrap();
            for allowed in ["10.42.0.8:7443", "[fd00::8]:7443"] {
                assert!(route_redirect_allowed(allowed.parse().unwrap(), &[pod]));
            }
            for refused in [
                "10.42.0.8:7444",
                "127.0.0.1:7443",
                "[::1]:7443",
                "[::ffff:127.0.0.1]:7443",
                "0.0.0.0:7443",
            ] {
                assert!(
                    !route_redirect_allowed(refused.parse().unwrap(), &[pod]),
                    "{refused} must be refused"
                );
            }
            let loopback: std::net::SocketAddr = "127.0.0.1:7443".parse().unwrap();
            assert!(route_redirect_allowed(
                "127.0.0.2:7443".parse().unwrap(),
                &[loopback]
            ));
        }

        #[test]
        fn runtime_resource_claim_file_must_match_admitted_claim() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let pod_uid_path = directory.path().join("pod-uid");
            std::fs::write(&pod_uid_path, "pod-uid-a\n").expect("write runtime claim");
            let mut config = BoundaryConfig {
                boundary_id: "sandbox-1".to_string(),
                generation: "generation-1".to_string(),
                session_id: test_session_id(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1)
                    .expect("session rotation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                gateway_id: "test-gateway".to_string(),
                verification_keys: vec![test_verification_key()],
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
                provisioning_evidence: test_provisioning_evidence(),
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

        #[tokio::test(flavor = "multi_thread")]
        async fn delegated_control_and_streams_reject_unbound_or_mismatched_launches() {
            let (runtime, token) = availability_test_runtime();
            let opening = test_open_request(&runtime.config);
            let server_runtime = runtime.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let runtime = server_runtime.clone();
                    connections.spawn(async move {
                        serve_grpc(Box::new(stream), runtime, SandboxConnectionId::new())
                            .await
                            .unwrap();
                    });
                }
            });
            let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect()
                .await
                .unwrap();
            let mut control = openshell_sandbox_backend::backend_proto::isolation_backend_client::IsolationBackendClient::new(channel.clone());
            let mut streams = SandboxProtocolClient::new(channel.clone());
            let before_open = streams
                .exchange(bearer_request(
                    tokio_stream::iter([data_chunk(Vec::new())]),
                    &token,
                ))
                .await;
            assert_eq!(
                before_open.err().unwrap().code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                control
                    .open_boundary(bearer_request(opening.clone(), &token))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                control
                    .describe(DescribeIsolationBackendRequest { supervisor: None })
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            let mut incompatible =
                openshell_sandbox_backend::isolation_protocol::metadata("test/supervisor");
            incompatible.protocol_version.as_mut().unwrap().major += 1;
            assert_eq!(
                control
                    .describe(DescribeIsolationBackendRequest {
                        supervisor: Some(incompatible)
                    })
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            let mut compatible =
                openshell_sandbox_backend::isolation_protocol::metadata("test/supervisor");
            compatible.protocol_version.as_mut().unwrap().minor += 1;
            compatible
                .supported_capabilities
                .push("openshell.isolation.future".to_string());
            let mut unmet_requirement = compatible.clone();
            unmet_requirement
                .required_capabilities
                .push("openshell.isolation.future".to_string());
            assert_eq!(
                control
                    .describe(DescribeIsolationBackendRequest {
                        supervisor: Some(unmet_requirement),
                    })
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            control
                .describe(DescribeIsolationBackendRequest {
                    supervisor: Some(compatible),
                })
                .await
                .unwrap();
            assert_eq!(
                control
                    .open_boundary(opening.clone())
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
            for field in ["session", "backend", "descriptor"] {
                let mut changed = opening.clone();
                match field {
                    "session" => changed.session_id = "other-session".to_string(),
                    "backend" => changed.backend_name = "other-backend".to_string(),
                    "descriptor" => {
                        let mut descriptor: openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor = serde_json::from_slice(&changed.driver_descriptor).unwrap();
                        descriptor
                            .resource_claims
                            .insert("unprovisioned".to_string(), "resource".to_string());
                        changed.driver_descriptor = serde_json::to_vec(&descriptor).unwrap();
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    control
                        .open_boundary(bearer_request(changed, &token))
                        .await
                        .unwrap_err()
                        .code(),
                    tonic::Code::PermissionDenied
                );
            }
            let handle = test_open_boundary(channel.clone(), opening.clone(), &token).await;
            // JSON formatting does not change the provisioned resource binding.
            let mut retry = opening.clone();
            let descriptor: openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor =
                serde_json::from_slice(&retry.driver_descriptor).unwrap();
            retry.driver_descriptor = serde_json::to_vec_pretty(&descriptor).unwrap();
            assert_eq!(
                control
                    .open_boundary(bearer_request(retry, &token))
                    .await
                    .unwrap()
                    .into_inner()
                    .boundary_id,
                handle
            );
            // Knowing a previous handle does not open a new physical connection.
            let replacement = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
                .unwrap()
                .connect()
                .await
                .unwrap();
            let binding = openshell_sandbox_backend::isolation_protocol::exchange_frame(&handle);
            let mut replacement_streams = SandboxProtocolClient::new(replacement.clone());
            assert_eq!(
                replacement_streams
                    .exchange(bearer_request(
                        tokio_stream::iter([binding.clone()]),
                        &token
                    ))
                    .await
                    .err()
                    .unwrap()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                replacement_streams
                    .mediate(bearer_request(
                        tokio_stream::iter([MediateFrame {
                            payload: Some(mediate_frame::Payload::BoundaryId(handle.clone()))
                        }]),
                        &token
                    ))
                    .await
                    .err()
                    .unwrap()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                test_open_boundary(replacement, opening, &token).await,
                handle
            );
            assert_eq!(
                control
                    .suspend_boundary(bearer_request(SuspendBoundaryRequest::default(), &token))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unimplemented
            );
            assert_eq!(
                control
                    .resume_boundary(bearer_request(ResumeBoundaryRequest::default(), &token))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unimplemented
            );
            for frames in [
                vec![],
                vec![data_chunk(Vec::new())],
                vec![ExchangeFrame { payload: None }],
                vec![openshell_sandbox_backend::isolation_protocol::exchange_frame("")],
                vec![
                    openshell_sandbox_backend::isolation_protocol::exchange_frame("other-boundary"),
                ],
            ] {
                let expected = if frames
                    .first()
                    .is_some_and(|frame| matches!(frame.payload, Some(Payload::BoundaryId(_))))
                {
                    tonic::Code::PermissionDenied
                } else {
                    tonic::Code::InvalidArgument
                };
                assert_eq!(
                    streams
                        .exchange(bearer_request(tokio_stream::iter(frames.clone()), &token))
                        .await
                        .err()
                        .unwrap()
                        .code(),
                    expected
                );
                assert_eq!(
                    streams
                        .mediate(bearer_request(
                            tokio_stream::iter(frames.into_iter().map(|frame| MediateFrame {
                                payload: match frame.payload {
                                    Some(Payload::BoundaryId(id)) =>
                                        Some(mediate_frame::Payload::BoundaryId(id)),
                                    _ => None,
                                }
                            })),
                            &token
                        ))
                        .await
                        .err()
                        .unwrap()
                        .code(),
                    expected
                );
            }
            let binding = openshell_sandbox_backend::isolation_protocol::exchange_frame(&handle);
            let mut response = streams
                .exchange(bearer_request(
                    tokio_stream::iter([binding.clone(), binding]),
                    &token,
                ))
                .await
                .unwrap()
                .into_inner();
            let error = tokio::time::timeout(Duration::from_secs(2), response.message())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(matches!(
                *lock(&runtime.state),
                RuntimeState::AwaitingAttach
            ));
            assert!(lock(&runtime.started_agent).is_none());
            server.abort();
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn grpc_server_dispatches_authenticated_logical_streams() {
            let (workload_launcher, listener) =
                crate::linux::workload_launcher::start().expect("start multiplexed test listener");
            let network_broker =
                NetworkBroker::start_for_test(listener).expect("start multiplexed test broker");
            let (verification_key, token) = test_auth_material("sandbox-multiplexed");
            let boundary = Arc::new(
                BoundaryRuntime::new(
                    BoundaryConfig {
                        boundary_id: "sandbox-multiplexed".to_string(),
                        generation: "generation-1".to_string(),
                        session_id: test_session_id(),
                        session_rotation: openshell_core::jwt::SessionRotation::new(1)
                            .expect("session rotation"),
                        auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                        gateway_id: "test-gateway".to_string(),
                        verification_keys: vec![verification_key],
                        listener: BoundaryListenerConfig::TlsTcp {
                            address: "127.0.0.1:5500".parse().expect("control address"),
                            tls: placeholder_server_tls(),
                        },
                        resource_claims: std::collections::BTreeMap::new(),
                        resource_claim_files: std::collections::BTreeMap::new(),
                        workload_identity: test_workload_identity(),
                        provisioning_evidence: test_provisioning_evidence(),
                        child_env: std::collections::HashMap::new(),
                    },
                    tokio::runtime::Handle::current(),
                    network_broker,
                    workload_launcher,
                    test_runtime_qualification(),
                )
                .expect("test boundary runtime"),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind gRPC test listener");
            let address = listener.local_addr().expect("gRPC test address");
            let opening = test_open_request(&boundary.config);
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept gRPC client");
                serve_grpc(Box::new(stream), boundary, SandboxConnectionId::new()).await
            });
            let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
                .expect("valid gRPC endpoint")
                .connect()
                .await
                .expect("connect gRPC client");
            let policy = SandboxPolicyWire::from(openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            });
            let request = RequestEnvelope::new(Request::Attach {
                supervisor_instance_id: test_supervisor_instance_id(),
                policy: Box::new(policy),
                supervisor_takeover: None,
                supervisor_recovery_timeout_secs: None,
            })
            .expect("encode attach request");
            let handle = test_open_boundary(channel.clone(), opening, &token).await;
            let request_stream = tokio_stream::iter([
                openshell_sandbox_backend::isolation_protocol::exchange_frame(&handle),
                openshell_sandbox_backend::isolation_protocol::request_chunk(&request)
                    .expect("typed logical request"),
            ]);
            let mut body = SandboxProtocolClient::new(channel)
                .exchange(bearer_request(request_stream, &token))
                .await
                .expect("exchange logical request")
                .into_inner();
            let mut frame = Vec::new();
            while let Some(chunk) = body.message().await.expect("read gRPC response") {
                frame.extend_from_slice(&chunk_data(chunk).unwrap());
            }
            let response: ResponseEnvelope =
                openshell_sandbox_backend::boundary_protocol::decode_frame(&frame)
                    .expect("decode logical response");
            assert!(matches!(response.response, Response::Attached { .. }));
            server.abort();
        }

        #[test]
        fn pod_control_listener_rejects_loopback_peers_before_tls() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (server_tls, _client_tls) = stage_test_tls(directory.path(), "loopback");
            let listener = ControlListener::bind(&BoundaryListenerConfig::TlsTcp {
                address: "0.0.0.0:0".parse().expect("valid address"),
                tls: server_tls,
            })
            .expect("bind TLS listener");
            let port = listener
                .tcp_local_addr()
                .expect("TLS listener address")
                .port();
            let _client = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(300),
            )
            .expect("TCP handshake succeeds without a packet filter");
            assert_eq!(
                accept_pending(&listener)
                    .expect_err("local peer refused")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        #[test]
        fn control_peer_address_rules_cover_pod_and_loopback_addresses() {
            for (peer, local, denied) in [
                ("127.0.0.2", "10.42.0.8", true),
                ("10.42.0.8", "127.0.0.1", true),
                ("10.42.0.8", "10.42.0.8", true),
                ("10.42.0.9", "10.42.0.8", false),
                ("::1", "fd00::8", true),
                ("fd00::8", "::1", true),
                ("fd00::8", "fd00::8", true),
                ("fd00::9", "fd00::8", false),
                ("::ffff:127.0.0.2", "10.42.0.8", true),
                ("10.42.0.8", "::ffff:127.0.0.1", true),
                ("::ffff:10.42.0.8", "10.42.0.8", true),
                ("10.42.0.8", "::ffff:10.42.0.8", true),
                ("::ffff:10.42.0.9", "::ffff:10.42.0.8", false),
            ] {
                assert_eq!(
                    is_local_control_peer(peer.parse().unwrap(), local.parse().unwrap()),
                    denied,
                    "peer={peer}, local={local}"
                );
            }
        }

        /// A control listener in accept-time mode, bound to loopback so a test
        /// client can actually reach it.
        fn accept_time_control_listener(
            directory: &Path,
            name: &str,
        ) -> (ControlListener, std::net::SocketAddr) {
            let (server_tls, _client_tls) = stage_test_tls(directory, name);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let address = listener.local_addr().expect("listener address");
            let server_config =
                Arc::new(load_tls_server_config(&server_tls).expect("TLS server config"));
            (
                ControlListener::Tcp {
                    listener,
                    server_config,
                    reject_local_peers: true,
                },
                address,
            )
        }

        fn accept_pending(listener: &ControlListener) -> io::Result<()> {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    other => return other.map(|_| ()),
                }
            }
        }

        #[test]
        fn accept_refuses_a_same_host_control_peer() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (listener, address) = accept_time_control_listener(directory.path(), "local-peer");
            let _client = std::net::TcpStream::connect(address).expect("connect loopback client");
            let error = accept_pending(&listener).expect_err("loopback peer refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }

        #[test]
        fn accept_survives_a_control_peer_that_resets_before_it_is_accepted() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let (listener, address) = accept_time_control_listener(directory.path(), "reset");
            let client = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .expect("client socket");
            client.connect(&address.into()).expect("connect");
            // Zero linger makes the close an RST while the connection is still
            // queued, which is what makes `getpeername` fail with ENOTCONN.
            client
                .set_linger(Some(Duration::ZERO))
                .expect("zero linger");
            drop(client);
            let kind = accept_pending(&listener)
                .expect_err("reset peer refused")
                .kind();
            assert!(
                matches!(
                    kind,
                    io::ErrorKind::PermissionDenied | io::ErrorKind::WouldBlock
                ),
                "reset peer produced a listener-fatal error: {kind:?}"
            );
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
            let boundary = Arc::new(
                BoundaryRuntime::new(
                    BoundaryConfig {
                        boundary_id: "sandbox-reconnect".to_string(),
                        generation: "generation-reconnect".to_string(),
                        session_id: test_session_id(),
                        session_rotation: openshell_core::jwt::SessionRotation::new(1)
                            .expect("session rotation"),
                        auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                        gateway_id: "test-gateway".to_string(),
                        verification_keys: vec![test_verification_key()],
                        listener: BoundaryListenerConfig::TlsTcp {
                            address: "127.0.0.1:5500".parse().expect("control address"),
                            tls: placeholder_server_tls(),
                        },
                        resource_claims: std::collections::BTreeMap::new(),
                        resource_claim_files: std::collections::BTreeMap::new(),
                        workload_identity: test_workload_identity(),
                        provisioning_evidence: test_provisioning_evidence(),
                        child_env: std::collections::HashMap::new(),
                    },
                    process_runtime.handle().clone(),
                    network_broker,
                    workload_launcher,
                    test_runtime_qualification(),
                )
                .expect("test boundary runtime"),
            );
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
                boundary.attach(policy.clone(), false),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            let start = || {
                boundary.start_agent(
                    "sandbox-reconnect".to_string(),
                    spec.clone(),
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                )
            };
            let Response::Started {
                process_id,
                provider_env_revision: 0,
                provider_env_generation: 0,
            } = start()
            else {
                panic!("initial start did not succeed");
            };

            let update = RequestEnvelope::new(Request::UpdateProviderEnvironment {
                provider_files: std::collections::HashMap::new(),
                generation: 1,
                revision: 7,
                provider_env: std::collections::HashMap::from([(
                    "REPLAY_TEST".to_string(),
                    "set-once".to_string(),
                )]),
            })
            .expect("build replayed update");
            assert_eq!(
                boundary.dispatch(update.clone()),
                Response::ProviderEnvironmentUpdated {
                    revision: 7,
                    generation: 1,
                    applied: true,
                }
            );
            assert_eq!(
                boundary.dispatch(update.clone()),
                Response::ProviderEnvironmentUpdated {
                    revision: 7,
                    generation: 1,
                    applied: true,
                },
                "the same request ID and payload must replay its recorded response"
            );
            let mut changed = RequestEnvelope::new(Request::Terminate {
                process_id: process_id.clone(),
            })
            .expect("build changed request");
            changed.request_id = update.request_id;
            assert!(matches!(
                boundary.dispatch(changed),
                Response::Error { kind, .. } if kind == BoundaryErrorKind::Denied
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
                boundary.attach(policy.clone(), false),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                start(),
                Response::Started {
                    process_id: process_id.clone(),
                    provider_env_revision: 7,
                    provider_env_generation: 1,
                }
            );

            let mut changed_policy = policy.clone();
            changed_policy.version += 1;
            assert!(matches!(
                boundary.attach(changed_policy, false),
                Response::Error { kind, .. } if kind == BoundaryErrorKind::Denied
            ));
            assert!(matches!(
                boundary.start_agent(
                    "sandbox-reconnect".to_string(),
                    AgentSpecWire { program: "/bin/false".to_string(), ..spec },
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                ),
                Response::Error { kind, .. } if kind == BoundaryErrorKind::Denied
            ));

            // Failed refresh and recovery can retain the same provider
            // fingerprint. Distinct publications must still replace the map,
            // while a delayed older clear must never undo the repair.
            let process = boundary.running_process(&process_id).unwrap();
            let before = process
                .provider_credentials
                .child_environment_snapshot()
                .unwrap();
            assert!(matches!(
                boundary.update_provider_environment(
                    2,
                    8,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "must-not-install".to_string()
                    )]),
                    std::collections::HashMap::from([(
                        "/outside/provider".to_string(),
                        "invalid path".to_string()
                    )]),
                ),
                Response::Error {
                    kind: BoundaryErrorKind::Invalid,
                    ..
                }
            ));
            let after = process
                .provider_credentials
                .child_environment_snapshot()
                .unwrap();
            assert_eq!(before.revision, after.revision);
            assert_eq!(before.environment, after.environment);
            assert_eq!(
                boundary.update_provider_environment(
                    2,
                    7,
                    std::collections::HashMap::default(),
                    std::collections::HashMap::new()
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 7,
                    generation: 2,
                    applied: true
                }
            );
            assert_eq!(
                boundary.update_provider_environment(
                    3,
                    7,
                    std::collections::HashMap::from([(
                        "REPLAY_TEST".to_string(),
                        "reconnected".to_string()
                    ),]),
                    std::collections::HashMap::new(),
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 7,
                    generation: 3,
                    applied: true
                }
            );
            assert_eq!(
                boundary.update_provider_environment(
                    2,
                    7,
                    std::collections::HashMap::default(),
                    std::collections::HashMap::new()
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 7,
                    generation: 3,
                    applied: false
                }
            );

            let exec_spec = ExecSpecWire {
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "printf '%s' \"$REPLAY_TEST\"".to_string()],
                shell: None,
                runtime_helper: None,
                env: Vec::new(),
                workdir: None,
                pty: false,
            };
            let exec_request = RequestEnvelope::new(Request::Exec {
                spec: exec_spec.clone(),
            })
            .expect("build exec request");
            let exec = boundary
                .start_exec(
                    &exec_request.request_id,
                    &exec_request.payload_digest,
                    exec_request.exec_admission_deadline_unix_ms,
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
            for _ in 0..2 {
                assert_eq!(
                    boundary.wait(&exec_id),
                    Response::Exited {
                        status: ExitStatusWire::Exited(0),
                    },
                    "exec status must remain available after its output attachment closes"
                );
            }
            let Response::Attached { snapshot } = boundary.attach(policy, false) else {
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

        /// A gateway signing key, the runtime's verification key for it, and
        /// mints of Sandbox Protocol bearers and takeover grants.
        struct TestGateway {
            issuer: SessionJwtIssuer,
            verification_key: GatewayVerificationKey,
        }

        impl TestGateway {
            fn new() -> Self {
                let key = openshell_crypto::pki::generate_keypair_for(&PKCS_ED25519)
                    .expect("generate gateway key");
                Self {
                    verification_key: GatewayVerificationKey {
                        key_id: "test-key".to_string(),
                        public_key_pem: key.public_key_pem(),
                    },
                    issuer: SessionJwtIssuer::from_ed25519_pem(
                        key.serialize_pem().unwrap().as_bytes(),
                        "test-key",
                        "test-gateway",
                        Some(DEFAULT_SESSION_TOKEN_TTL),
                        Arc::new(SystemJwtClock),
                    )
                    .expect("test session issuer"),
                }
            }

            fn token(&self, sandbox_id: &str, generation: &str, epoch: u64) -> String {
                self.issuer
                    .mint_pair(&SandboxRuntimeIdentity {
                        sandbox_id: SandboxId::parse(sandbox_id).expect("sandbox ID"),
                        runtime_generation:
                            openshell_core::sandbox_generation::SandboxGenerationId::parse(
                                generation,
                            )
                            .expect("runtime generation"),
                        auth_epoch: CredentialEpoch::new(epoch).expect("auth epoch"),
                    })
                    .expect("token pair")
                    .sandbox
                    .token
                    .expose_secret()
                    .to_string()
            }

            fn grant(
                &self,
                sandbox_id: &str,
                generation: &str,
                epoch: u64,
                instance: openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId,
            ) -> String {
                self.issuer
                    .mint_supervisor_takeover(
                        &openshell_core::jwt::SupervisorTakeover {
                            sandbox_id: SandboxId::parse(sandbox_id).expect("sandbox ID"),
                            runtime_generation:
                                openshell_core::sandbox_generation::SandboxGenerationId::parse(
                                    generation,
                                )
                                .expect("runtime generation"),
                            auth_epoch: CredentialEpoch::new(epoch).expect("auth epoch"),
                            supervisor_instance: instance.to_string(),
                            owner: "supervisor-pool-1".to_string(),
                        },
                        Duration::from_mins(5),
                    )
                    .expect("takeover grant")
                    .token
                    .expose_secret()
                    .to_string()
            }
        }

        /// A replacement supervisor process takes over a running generation:
        /// the frozen workload resumes as the same process, the replacement
        /// adopts it from the snapshot instead of launching it again, and the
        /// previous owner's credentials and process identity stay fenced.
        #[test]
        fn granted_takeover_adopts_the_running_workload_and_fences_the_previous_owner() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_BOUNDARY_TAKEOVER_CHILD";
            const SANDBOX: &str = "sandbox-takeover";
            const GENERATION: &str = "generation-takeover";
            if std::env::var_os(CHILD_MARKER).is_none() {
                let status = std::process::Command::new(
                    std::env::current_exe().expect("current test executable"),
                )
                .args([
                    "--exact",
                    "boundary_server::linux::tests::granted_takeover_adopts_the_running_workload_and_fences_the_previous_owner",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated takeover test");
                assert!(status.success(), "isolated takeover test failed");
                return;
            }

            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let (network_broker, workload_launcher) = test_network_broker();
            let mut boundary = BoundaryRuntime::new(
                BoundaryConfig {
                    boundary_id: SANDBOX.to_string(),
                    generation: GENERATION.to_string(),
                    session_id: test_session_id(),
                    session_rotation: openshell_core::jwt::SessionRotation::new(1)
                        .expect("session rotation"),
                    auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                    gateway_id: "test-gateway".to_string(),
                    verification_keys: vec![gateway.verification_key.clone()],
                    listener: BoundaryListenerConfig::TlsTcp {
                        address: "127.0.0.1:5500".parse().expect("control address"),
                        tls: placeholder_server_tls(),
                    },
                    resource_claims: std::collections::BTreeMap::new(),
                    resource_claim_files: std::collections::BTreeMap::new(),
                    workload_identity: test_workload_identity(),
                    provisioning_evidence: test_provisioning_evidence(),
                    child_env: std::collections::HashMap::new(),
                },
                process_runtime.handle().clone(),
                network_broker,
                workload_launcher,
                test_runtime_qualification(),
            )
            .expect("test boundary runtime");
            boundary.default_recovery_timeout = Duration::from_secs(10);
            let boundary = Arc::new(boundary);
            let authenticate = |token: &str| {
                boundary.authenticate_request(
                    SandboxConnectionId::new(),
                    bearer_request((), token).metadata(),
                )
            };
            let policy = SandboxPolicyWire::from(openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            });

            // The launch owner attaches, confirms, and starts the workload.
            let launch_owner = test_supervisor_instance_id();
            let first = authenticate(&gateway.token(SANDBOX, GENERATION, 1)).expect("first");
            assert!(matches!(
                boundary.attach(policy.clone(), false),
                Response::Attached { .. }
            ));
            boundary
                .commit_attach(&first, launch_owner, None, None)
                .expect("attach launch owner");
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            boundary
                .commit_confirm(&first)
                .expect("confirm launch owner");
            let Response::Started { process_id, .. } = boundary.start_agent(
                SANDBOX.to_string(),
                AgentSpecWire {
                    program: "/bin/sleep".to_string(),
                    args: vec!["60".to_string()],
                    workdir: None,
                    timeout_secs: 120,
                    interactive: false,
                },
                None,
                None,
                0,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
            ) else {
                panic!("launch owner could not start the workload");
            };
            let workload = boundary.running_process(&process_id).expect("running");
            let workload_pid = workload.signaler.pid();
            // The launch owner's supervision pinned the workload's tool.
            let tool = |digest: char| {
                Ok(openshell_isolation_interface::contract::BinaryIdentity {
                    executable: openshell_isolation_interface::contract::ExecutableIdentity {
                        path: std::path::PathBuf::from("/usr/bin/tool"),
                        digest: Some(digest.to_string().repeat(64).parse().expect("digest")),
                    },
                    ancestors: Vec::new(),
                    cmdline_paths: Vec::new(),
                })
            };
            assert!(boundary.binary_pins.admit(tool('a')).is_ok());

            // The owner's process dies: the workload freezes, unsupervised.
            boundary.transport_disconnected(first.connection_id());
            let state = *lock(&boundary.supervisor_connection);
            let recovery_id = match state {
                SupervisorConnectionState::Frozen { recovery_id } => recovery_id,
                state => panic!("expected a frozen workload, got {state:?}"),
            };

            // Fresh credentials for a later epoch do not move ownership
            // without a grant, and a grant names one process only.
            let replacement = test_supervisor_instance_id();
            let ungranted = authenticate(&gateway.token(SANDBOX, GENERATION, 2)).expect("ahead");
            assert!(matches!(
                boundary.commit_attach(&ungranted, replacement, None, None),
                Err((BoundaryErrorKind::Denied, _))
            ));
            let grant = gateway.grant(SANDBOX, GENERATION, 2, replacement);
            let verified = boundary
                .authenticator
                .verify_takeover(&grant)
                .expect("verify grant");
            assert!(matches!(
                boundary.commit_attach(
                    &ungranted,
                    test_supervisor_instance_id(),
                    Some(&verified),
                    None
                ),
                Err((BoundaryErrorKind::Denied, _))
            ));
            // A grant for another runtime generation is refused outright.
            assert!(
                boundary
                    .authenticator
                    .verify_takeover(&gateway.grant(SANDBOX, "generation-other", 2, replacement))
                    .is_err()
            );

            // The granted replacement attaches with whatever launch controls
            // it derived; the runtime keeps and reports the bound ones, and
            // the snapshot shows the running workload to adopt.
            let mut derived = policy.clone();
            derived.version += 1;
            let candidate = authenticate(&gateway.token(SANDBOX, GENERATION, 2)).expect("cand");
            let Response::Attached { snapshot } = boundary.attach(derived, true) else {
                panic!("takeover attach was refused");
            };
            assert_eq!(snapshot.bound_policy.as_deref(), Some(&policy));
            assert!(snapshot.processes.iter().any(|process| {
                process.process_id == process_id
                    && process.kind == ProcessKindWire::Main
                    && process.status.is_none()
            }));
            boundary
                .commit_attach(&candidate, replacement, Some(&verified), None)
                .expect("stage takeover");
            // The staged replacement cannot act before it confirms, and the
            // previous owner can no longer return while it is staged.
            assert!(boundary.connections.require_active(&candidate).is_err());
            let returning = authenticate(&gateway.token(SANDBOX, GENERATION, 1)).expect("old");
            assert!(
                boundary
                    .commit_attach(&returning, launch_owner, None, None)
                    .is_err()
            );
            assert!(matches!(
                *lock(&boundary.supervisor_connection),
                SupervisorConnectionState::Frozen { .. }
            ));

            // Confirmation promotes the replacement and resumes the same
            // workload process; nothing was launched again.
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            boundary
                .commit_confirm(&candidate)
                .expect("confirm takeover");
            assert_eq!(
                *lock(&boundary.supervisor_connection),
                SupervisorConnectionState::Connected(candidate.connection_id())
            );
            let resumed = boundary
                .running_process(&process_id)
                .expect("still running");
            assert!(Arc::ptr_eq(&workload, &resumed));
            assert_eq!(resumed.signaler.pid(), workload_pid);
            assert!(!resumed.has_exited());
            boundary
                .connections
                .require_active(&candidate)
                .expect("replacement is the active owner");
            // The replacement starts without supervisor-side pins, but the
            // runtime never offers it a tool the workload replaced.
            assert!(matches!(
                boundary.binary_pins.admit(tool('b')),
                Err(openshell_isolation_interface::contract::ResolveError::Failed(_))
            ));
            assert!(boundary.binary_pins.admit(tool('a')).is_ok());

            // Every credential of the replaced term is stale from now on.
            assert!(authenticate(&gateway.token(SANDBOX, GENERATION, 1)).is_err());
            // The superseded recovery deadline cannot terminate the workload.
            process_runtime.block_on(boundary.expire_recovery(recovery_id));
            assert_eq!(
                *lock(&boundary.supervisor_connection),
                SupervisorConnectionState::Connected(candidate.connection_id())
            );
            assert!(!resumed.has_exited());
            assert_eq!(boundary.terminate(&process_id), Response::Terminated);
        }

        /// A runtime trusting `gateway`, launched at epoch 1, before any attach.
        fn takeover_test_runtime(
            gateway: &TestGateway,
            sandbox: &str,
            generation: &str,
            process_runtime: &tokio::runtime::Runtime,
        ) -> Arc<BoundaryRuntime> {
            takeover_test_runtime_with_recovery(gateway, sandbox, generation, process_runtime, None)
        }

        /// [`takeover_test_runtime`] with a recovery deadline shorter than
        /// configuration allows.
        fn takeover_test_runtime_with_recovery(
            gateway: &TestGateway,
            sandbox: &str,
            generation: &str,
            process_runtime: &tokio::runtime::Runtime,
            recovery_timeout: Option<Duration>,
        ) -> Arc<BoundaryRuntime> {
            let (network_broker, workload_launcher) = test_network_broker();
            let mut runtime = BoundaryRuntime::new(
                BoundaryConfig {
                    boundary_id: sandbox.to_string(),
                    generation: generation.to_string(),
                    session_id: test_session_id(),
                    session_rotation: openshell_core::jwt::SessionRotation::new(1)
                        .expect("session rotation"),
                    auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                    gateway_id: "test-gateway".to_string(),
                    verification_keys: vec![gateway.verification_key.clone()],
                    listener: BoundaryListenerConfig::TlsTcp {
                        address: "127.0.0.1:5500".parse().expect("control address"),
                        tls: placeholder_server_tls(),
                    },
                    resource_claims: std::collections::BTreeMap::new(),
                    resource_claim_files: std::collections::BTreeMap::new(),
                    workload_identity: test_workload_identity(),
                    provisioning_evidence: test_provisioning_evidence(),
                    child_env: std::collections::HashMap::new(),
                },
                process_runtime.handle().clone(),
                network_broker,
                workload_launcher,
                test_runtime_qualification(),
            )
            .expect("test boundary runtime");
            runtime.default_recovery_timeout = recovery_timeout.unwrap_or(Duration::from_secs(10));
            Arc::new(runtime)
        }

        fn takeover_test_policy() -> SandboxPolicyWire {
            SandboxPolicyWire::from(openshell_core::policy::SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            })
        }

        /// Send one control request through `serve_one`, as a connection of
        /// `principal`, and return the boundary's response.
        fn serve_request(
            runtime: &BoundaryRuntime,
            principal: &SandboxProtocolPrincipal,
            request: Request,
        ) -> Response {
            let (server, mut client) =
                std::os::unix::net::UnixStream::pair().expect("control socket pair");
            write_frame(
                &mut client,
                &RequestEnvelope::new(request).expect("request envelope"),
            )
            .expect("write request");
            serve_one(ControlStream::TestUnix(server), runtime, principal).expect("serve request");
            read_frame::<ResponseEnvelope>(&mut client)
                .expect("read response")
                .response
        }

        /// Candidates the registry refuses never bind launch controls or
        /// establish the boundary, every refusal is reported as an OCSF
        /// configuration event and detection finding, and no grant is logged.
        #[test]
        fn rejected_attach_candidates_never_bind_the_boundary() {
            const SANDBOX: &str = "sandbox-admission";
            const GENERATION: &str = "generation-admission";
            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let capture = openshell_ocsf::test_support::OcsfCapture::default();
            let _capture = capture.install();
            let principal = |epoch| {
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, epoch)).metadata(),
                    )
                    .expect("principal")
            };
            let mut other_policy = takeover_test_policy();
            other_policy.version += 7;
            let attach = |takeover: Option<String>, instance| Request::Attach {
                supervisor_instance_id: instance,
                policy: Box::new(other_policy.clone()),
                supervisor_takeover: takeover,
                supervisor_recovery_timeout_secs: None,
            };

            // An epoch-ahead bearer without a grant, a grant for another
            // generation, and a grant naming another process are refused.
            let candidate = test_supervisor_instance_id();
            let foreign_grant = gateway.grant(SANDBOX, "generation-other", 2, candidate);
            let mismatched_grant =
                gateway.grant(SANDBOX, GENERATION, 2, test_supervisor_instance_id());
            for request in [
                attach(None, candidate),
                attach(Some(foreign_grant.clone()), candidate),
                attach(Some(mismatched_grant.clone()), candidate),
            ] {
                assert!(matches!(
                    serve_request(&boundary, &principal(2), request),
                    Response::Error {
                        kind: BoundaryErrorKind::Denied,
                        ..
                    }
                ));
                assert!(lock(&boundary.attached_policy).is_none());
                assert!(matches!(
                    *lock(&boundary.state),
                    RuntimeState::AwaitingAttach
                ));
            }
            let events = capture.json_events();
            let denials = events
                .iter()
                .filter(|event| {
                    event["message"]
                        .as_str()
                        .is_some_and(|message| message.starts_with("Supervisor takeover denied"))
                })
                .count();
            assert_eq!(
                denials, 6,
                "a state event and a finding per refusal: {events:#?}"
            );
            assert!(events.iter().any(|event| {
                event["finding_info"]["uid"] == "sandbox-supervisor-takeover-denied"
            }));
            let exported = serde_json::to_string(&events).expect("events JSON");
            for grant in [&foreign_grant, &mismatched_grant] {
                assert!(
                    !exported.contains(grant.as_str()),
                    "a grant leaked into OCSF"
                );
            }

            // The launch owner then binds its own launch controls.
            let launch_owner = test_supervisor_instance_id();
            assert!(matches!(
                serve_request(
                    &boundary,
                    &principal(1),
                    Request::Attach {
                        supervisor_instance_id: launch_owner,
                        policy: Box::new(takeover_test_policy()),
                        supervisor_takeover: None,
                        supervisor_recovery_timeout_secs: None,
                    }
                ),
                Response::Attached { .. }
            ));
            assert_eq!(
                lock(&boundary.attached_policy).as_ref(),
                Some(&takeover_test_policy())
            );
        }

        /// The supervisor whose connection is in force when supervision is
        /// lost chose how long the workload stays frozen: the deadline its
        /// attach offered, or the default without one.
        #[test]
        fn the_lost_connections_offer_governs_the_recovery_deadline() {
            const SANDBOX: &str = "sandbox-recovery-offer";
            const GENERATION: &str = "generation-recovery-offer";
            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let owner = test_supervisor_instance_id();
            let connection = || {
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, 1)).metadata(),
                    )
                    .expect("principal")
            };
            let attach = |offer| Request::Attach {
                supervisor_instance_id: owner,
                policy: Box::new(takeover_test_policy()),
                supervisor_takeover: None,
                supervisor_recovery_timeout_secs: offer,
            };
            let mut deadlines = Vec::new();
            // The second connection reconnects the same process without an
            // offer, after the first one's loss froze the workload.
            for (offer, deadline) in [
                (Some(45), Duration::from_secs(45)),
                (None, boundary.default_recovery_timeout),
            ] {
                let principal = connection();
                assert!(matches!(
                    serve_request(&boundary, &principal, attach(offer)),
                    Response::Attached { .. }
                ));
                assert!(matches!(
                    serve_request(&boundary, &principal, Request::Confirm),
                    Response::Confirmed { .. }
                ));
                boundary.transport_disconnected(principal.connection_id());
                deadlines.push(deadline);
                assert_eq!(*lock(&boundary.scheduled_recoveries), deadlines);
                assert!(matches!(
                    *lock(&boundary.supervisor_connection),
                    SupervisorConnectionState::Frozen { .. }
                ));
            }
            assert!(lock(&boundary.recovery_offers).is_empty());
        }

        /// A recovery deadline outside the accepted bounds is refused before
        /// the attach binds launch controls or records anything.
        #[test]
        fn out_of_range_recovery_offers_are_refused_before_the_boundary_binds() {
            const SANDBOX: &str = "sandbox-recovery-bounds";
            const GENERATION: &str = "generation-recovery-bounds";
            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let owner = test_supervisor_instance_id();
            let connection = || {
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, 1)).metadata(),
                    )
                    .expect("principal")
            };
            let attach = |seconds| Request::Attach {
                supervisor_instance_id: owner,
                policy: Box::new(takeover_test_policy()),
                supervisor_takeover: None,
                supervisor_recovery_timeout_secs: Some(seconds),
            };
            for seconds in [0, 9, 301, u32::MAX] {
                assert!(matches!(
                    serve_request(&boundary, &connection(), attach(seconds)),
                    Response::Error {
                        kind: BoundaryErrorKind::Invalid,
                        ..
                    }
                ));
                assert!(lock(&boundary.attached_policy).is_none());
                assert!(matches!(
                    *lock(&boundary.state),
                    RuntimeState::AwaitingAttach
                ));
                assert!(lock(&boundary.recovery_offers).is_empty());
            }
            for seconds in [10, 300] {
                assert!(matches!(
                    serve_request(&boundary, &connection(), attach(seconds)),
                    Response::Attached { .. }
                ));
            }
        }

        /// Promoting a replacement waits for an operation the replaced owner
        /// was already authorized for, after which every later operation of
        /// that owner is refused; the replacement's snapshot taken after the
        /// promotion includes what the replaced owner started meanwhile.
        #[test]
        fn promotion_waits_for_and_then_fences_the_replaced_owner() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_BOUNDARY_PROMOTION_CHILD";
            const SANDBOX: &str = "sandbox-promotion";
            const GENERATION: &str = "generation-promotion";
            if std::env::var_os(CHILD_MARKER).is_none() {
                let status = std::process::Command::new(
                    std::env::current_exe().expect("current test executable"),
                )
                .args([
                    "--exact",
                    "boundary_server::linux::tests::promotion_waits_for_and_then_fences_the_replaced_owner",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .status()
                .expect("run isolated promotion test");
                assert!(status.success(), "isolated promotion test failed");
                return;
            }

            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let principal = |epoch| {
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, epoch)).metadata(),
                    )
                    .expect("principal")
            };
            let policy = takeover_test_policy();

            // The live owner runs the workload.
            let owner = test_supervisor_instance_id();
            let old = principal(1);
            assert!(matches!(
                boundary.attach(policy.clone(), false),
                Response::Attached { .. }
            ));
            boundary
                .commit_attach(&old, owner, None, None)
                .expect("attach");
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            boundary.commit_confirm(&old).expect("confirm");
            let Response::Started { process_id, .. } = boundary.start_agent(
                SANDBOX.to_string(),
                AgentSpecWire {
                    program: "/bin/sleep".to_string(),
                    args: vec!["60".to_string()],
                    workdir: None,
                    timeout_secs: 120,
                    interactive: false,
                },
                None,
                None,
                0,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
            ) else {
                panic!("owner could not start the workload");
            };

            // A granted replacement stages while the owner stays connected.
            let replacement = test_supervisor_instance_id();
            let candidate = principal(2);
            let grant = boundary
                .authenticator
                .verify_takeover(&gateway.grant(SANDBOX, GENERATION, 2, replacement))
                .expect("grant");
            let Response::Attached { snapshot: staged } = boundary.attach(policy.clone(), true)
            else {
                panic!("takeover attach refused");
            };
            boundary
                .commit_attach(&candidate, replacement, Some(&grant), None)
                .expect("stage takeover");
            assert!(
                staged
                    .processes
                    .iter()
                    .all(|process| process.kind == ProcessKindWire::Main)
            );

            // The owner is authorized for an operation and, still holding
            // that authorization, starts an exec the replacement's staged
            // snapshot does not show.
            let authorized = boundary.owner_operation(&old).expect("owner in force");
            let exec_request = RequestEnvelope::new(Request::Exec {
                spec: ExecSpecWire {
                    program: "/bin/sleep".to_string(),
                    args: vec!["30".to_string()],
                    shell: None,
                    runtime_helper: None,
                    env: Vec::new(),
                    workdir: None,
                    pty: false,
                },
            })
            .expect("exec request");

            // Promotion waits while the authorization is outstanding.
            let (promoted_tx, promoted) = std::sync::mpsc::channel();
            let promoting = boundary.clone();
            let promoting_candidate = candidate.clone();
            let promotion = std::thread::spawn(move || {
                assert!(matches!(promoting.confirm(), Response::Confirmed { .. }));
                promoted_tx
                    .send(promoting.commit_confirm(&promoting_candidate))
                    .expect("report promotion");
            });
            assert!(
                promoted.recv_timeout(Duration::from_millis(300)).is_err(),
                "promotion must wait for the authorized operation"
            );
            let exec = boundary
                .start_exec(
                    &exec_request.request_id,
                    &exec_request.payload_digest,
                    exec_request.exec_admission_deadline_unix_ms,
                    match exec_request.request.clone() {
                        Request::Exec { spec } => spec,
                        _ => unreachable!(),
                    },
                )
                .expect("authorized exec takes effect before the promotion");
            let exec_id = exec.process_id.clone();
            drop(exec);
            assert!(
                promoted.recv_timeout(Duration::from_millis(100)).is_err(),
                "promotion still waits"
            );
            drop(authorized);
            promoted
                .recv_timeout(Duration::from_secs(10))
                .expect("promotion completes once the operation took effect")
                .expect("promotion");
            promotion.join().expect("promotion thread");

            // Nothing of the replaced owner is admitted any more, including
            // operations it had in its pipeline.
            assert!(boundary.owner_operation(&old).is_err());
            for request in [
                Request::Terminate {
                    process_id: process_id.clone(),
                },
                Request::Signal {
                    process_id: process_id.clone(),
                    signal: SignalWire::Kill,
                },
                Request::UpdateProviderEnvironment {
                    generation: 9,
                    revision: 9,
                    provider_env: std::collections::HashMap::new(),
                    provider_files: std::collections::HashMap::new(),
                },
                Request::TerminateBoundary,
            ] {
                assert!(boundary.authorize_request(&old, &request).is_err());
            }
            let resumed = boundary.running_process(&process_id).expect("workload");
            assert!(!resumed.has_exited());

            // The replacement's post-promotion snapshot shows the exec, so
            // nothing the replaced owner started escapes adoption.
            boundary
                .connections
                .check_attach(&candidate, replacement, None)
                .expect("the promoted owner reattaches without its grant");
            let Response::Attached { snapshot } = boundary.attach(policy, false) else {
                panic!("refresh attach refused");
            };
            assert!(snapshot.processes.iter().any(|process| {
                process.process_id == exec_id
                    && process.kind == ProcessKindWire::Exec
                    && process.status.is_none()
            }));
            assert_eq!(boundary.terminate(&process_id), Response::Terminated);
        }

        /// Run one test alone in a child process, failing it if it does not
        /// finish in time instead of hanging the suite.
        fn run_isolated(test: &str, marker: &str, limit: Duration) {
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("current test executable"),
            )
            .args(["--exact", test, "--nocapture"])
            .env(marker, "1")
            .spawn()
            .expect("run isolated test");
            let deadline = std::time::Instant::now() + limit;
            loop {
                if let Some(status) = child.try_wait().expect("wait for isolated test") {
                    assert!(status.success(), "isolated test {test} failed");
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("isolated test {test} did not finish within {limit:?}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        /// Whether the process is stopped, as a frozen workload is.
        fn process_stopped(pid: u32) -> bool {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    stat.rsplit_once(") ")
                        .map(|(_, fields)| fields.starts_with('T'))
                })
                .unwrap_or(false)
        }

        /// An owner operation holds the ownership guard across `block_on`, a
        /// promotion waits for it, and a DNS answer waits behind the
        /// promotion, on a runtime with a single worker. The answer waits
        /// without blocking that worker, so timers keep running, the held
        /// operation finishes, the promotion completes, the replaced owner's
        /// answer is refused, and the new owner's answers and control
        /// requests are served. A confirmation replay on the owner in force
        /// never waits for owner operations.
        #[test]
        fn a_pending_promotion_never_stalls_a_single_worker_runtime() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_BOUNDARY_BARRIER_CHILD";
            const SANDBOX: &str = "sandbox-barrier";
            const GENERATION: &str = "generation-barrier";
            if std::env::var_os(CHILD_MARKER).is_none() {
                run_isolated(
                    "boundary_server::linux::tests::a_pending_promotion_never_stalls_a_single_worker_runtime",
                    CHILD_MARKER,
                    Duration::from_mins(1),
                );
                return;
            }

            let gateway = TestGateway::new();
            let process_runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("single-worker process runtime");
            let _entered = process_runtime.enter();
            let boundary = takeover_test_runtime(&gateway, SANDBOX, GENERATION, &process_runtime);
            let principal = |epoch| {
                boundary
                    .authenticate_request(
                        SandboxConnectionId::new(),
                        bearer_request((), &gateway.token(SANDBOX, GENERATION, epoch)).metadata(),
                    )
                    .expect("principal")
            };
            let policy = takeover_test_policy();
            let old = principal(1);
            assert!(matches!(
                boundary.attach(policy.clone(), false),
                Response::Attached { .. }
            ));
            boundary
                .commit_attach(&old, test_supervisor_instance_id(), None, None)
                .expect("attach owner");
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            boundary.commit_confirm(&old).expect("confirm owner");
            let replacement = test_supervisor_instance_id();
            let candidate = principal(2);
            let grant = boundary
                .authenticator
                .verify_takeover(&gateway.grant(SANDBOX, GENERATION, 2, replacement))
                .expect("grant");
            assert!(matches!(
                boundary.attach(policy, true),
                Response::Attached { .. }
            ));
            boundary
                .commit_attach(&candidate, replacement, Some(&grant), None)
                .expect("stage takeover");

            // An owner operation holds the guard across `block_on`, as Exec,
            // LoopbackConnect, and TerminateBoundary do; what remains of it
            // needs the runtime's timer.
            let (held_tx, held) = std::sync::mpsc::channel();
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            let (operated_tx, operated) = std::sync::mpsc::channel();
            let operating = boundary.clone();
            let operating_owner = old.clone();
            let operation = std::thread::spawn(move || {
                let guard = operating
                    .owner_operation(&operating_owner)
                    .expect("owner in force");
                held_tx.send(()).expect("report admission");
                operating.process_runtime.block_on(async {
                    let _ = released.await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                });
                drop(guard);
                operated_tx.send(()).expect("report operation");
            });
            held.recv_timeout(Duration::from_secs(10))
                .expect("operation admitted");

            // A promotion queues behind it.
            let (promoted_tx, promoted) = std::sync::mpsc::channel();
            let promoting = boundary.clone();
            let promoting_candidate = candidate.clone();
            let promotion = std::thread::spawn(move || {
                promoted_tx
                    .send(promoting.commit_confirm(&promoting_candidate))
                    .expect("report promotion");
            });
            let queued_by = std::time::Instant::now() + Duration::from_secs(10);
            while boundary.ownership.try_read().is_ok() {
                assert!(
                    std::time::Instant::now() < queued_by,
                    "promotion never queued"
                );
                std::thread::sleep(Duration::from_millis(5));
            }

            // A DNS answer arrives on the persistent mediation stream of an
            // owner; its task asks for the guard on the only worker.
            let answer = |owner: &SandboxProtocolPrincipal, response: &[u8]| {
                let (pending, answered) =
                    crate::network_broker::PendingDnsQuery::for_test(b"query".to_vec());
                let (inbound_tx, inbound) = tokio::sync::mpsc::channel(1);
                inbound_tx
                    .try_send(MediationFrame {
                        kind: MediationFrameKind::DnsResponse,
                        stream_id: 1,
                        payload: mediation::encode_message(&DnsQueryResultWire::Response(
                            response.to_vec(),
                        ))
                        .expect("encode answer"),
                    })
                    .expect("queue answer");
                let (outbound, mut queries) = tokio::sync::mpsc::channel(1);
                process_runtime.spawn(run_boundary_dns_stream(
                    1,
                    pending,
                    inbound,
                    outbound,
                    BoundaryMediationRoutes::default(),
                    (boundary.clone(), owner.clone()),
                ));
                let sent_by = std::time::Instant::now() + Duration::from_secs(10);
                while queries.try_recv().is_err() {
                    assert!(std::time::Instant::now() < sent_by, "DNS query never sent");
                    std::thread::sleep(Duration::from_millis(5));
                }
                (answered, queries, inbound_tx)
            };
            let (replaced_answer, _queries, _inbound) = answer(&old, b"stale");

            // Timers keep running while the answer waits behind the promotion.
            let (tick_tx, tick) = std::sync::mpsc::channel();
            process_runtime.spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let _ = tick_tx.send(());
            });
            tick.recv_timeout(Duration::from_secs(5))
                .expect("the runtime keeps running while a promotion is pending");

            // The held operation finishes, then the promotion completes.
            release.send(()).expect("release the operation");
            operated
                .recv_timeout(Duration::from_secs(10))
                .expect("the held operation finishes");
            promoted
                .recv_timeout(Duration::from_secs(10))
                .expect("the promotion completes")
                .expect("promotion");
            operation.join().expect("operation thread");
            promotion.join().expect("promotion thread");

            // The replaced owner's answer is refused; the new owner's
            // answers and control requests are served.
            let refused = replaced_answer
                .recv_timeout(Duration::from_secs(10))
                .expect("the replaced owner's answer completes");
            assert_eq!(
                refused
                    .expect_err("a replaced owner's answer is refused")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            let (current_answer, _queries, _inbound) = answer(&candidate, b"current");
            assert_eq!(
                current_answer
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the new owner's answer completes")
                    .expect("answer"),
                b"current"
            );
            assert!(!matches!(
                serve_request(
                    &boundary,
                    &candidate,
                    Request::Terminate {
                        process_id: "absent".to_string(),
                    },
                ),
                Response::Error {
                    kind: BoundaryErrorKind::Denied,
                    ..
                }
            ));

            // A confirmation replay, such as a credential renewal, does not
            // wait for an owner operation in progress.
            let in_progress = boundary.owner_operation(&candidate).expect("new owner");
            let (replayed_tx, replayed) = std::sync::mpsc::channel();
            let replaying = boundary.clone();
            let replaying_owner = candidate.clone();
            std::thread::spawn(move || {
                let _ = replayed_tx.send(replaying.commit_confirm(&replaying_owner));
            });
            replayed
                .recv_timeout(Duration::from_secs(5))
                .expect("a replay does not wait for owner operations")
                .expect("replay");
            drop(in_progress);
        }

        /// A replacement whose connection is lost while it is promoted is the
        /// owner in force when its loss is handled: the workload ends frozen
        /// under a fresh recovery deadline, which then terminates it, whether
        /// the previous owner was still connected or the workload was already
        /// frozen. It never runs unsupervised.
        #[test]
        fn a_replacement_lost_during_promotion_leaves_the_workload_frozen_under_a_deadline() {
            const CHILD_MARKER: &str = "OPENSHELL_TEST_BOUNDARY_PROMOTION_LOSS_CHILD";
            const SANDBOX: &str = "sandbox-promotion-loss";
            const GENERATION: &str = "generation-promotion-loss";
            if std::env::var_os(CHILD_MARKER).is_none() {
                run_isolated(
                    "boundary_server::linux::tests::a_replacement_lost_during_promotion_leaves_the_workload_frozen_under_a_deadline",
                    CHILD_MARKER,
                    Duration::from_mins(2),
                );
                return;
            }

            for previous_owner_connected in [true, false] {
                let gateway = TestGateway::new();
                let process_runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("test process runtime");
                let _entered = process_runtime.enter();
                let boundary = takeover_test_runtime_with_recovery(
                    &gateway,
                    SANDBOX,
                    GENERATION,
                    &process_runtime,
                    Some(Duration::from_millis(500)),
                );
                let principal = |epoch| {
                    boundary
                        .authenticate_request(
                            SandboxConnectionId::new(),
                            bearer_request((), &gateway.token(SANDBOX, GENERATION, epoch))
                                .metadata(),
                        )
                        .expect("principal")
                };
                let policy = takeover_test_policy();
                let old = principal(1);
                assert!(matches!(
                    boundary.attach(policy.clone(), false),
                    Response::Attached { .. }
                ));
                boundary
                    .commit_attach(&old, test_supervisor_instance_id(), None, None)
                    .expect("attach owner");
                assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
                boundary.commit_confirm(&old).expect("confirm owner");
                let Response::Started { process_id, .. } = boundary.start_agent(
                    SANDBOX.to_string(),
                    AgentSpecWire {
                        program: "/bin/sleep".to_string(),
                        args: vec!["60".to_string()],
                        workdir: None,
                        timeout_secs: 120,
                        interactive: false,
                    },
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                ) else {
                    panic!("owner could not start the workload");
                };
                let workload = boundary.running_process(&process_id).expect("running");
                let earlier_recovery = if previous_owner_connected {
                    None
                } else {
                    boundary.transport_disconnected(old.connection_id());
                    let state = *lock(&boundary.supervisor_connection);
                    match state {
                        SupervisorConnectionState::Frozen { recovery_id } => Some(recovery_id),
                        state => panic!("expected a frozen workload, got {state:?}"),
                    }
                };

                let replacement = test_supervisor_instance_id();
                let candidate = principal(2);
                let grant = boundary
                    .authenticator
                    .verify_takeover(&gateway.grant(SANDBOX, GENERATION, 2, replacement))
                    .expect("grant");
                assert!(matches!(
                    boundary.attach(policy, true),
                    Response::Attached { .. }
                ));
                boundary
                    .commit_attach(&candidate, replacement, Some(&grant), None)
                    .expect("stage takeover");

                // The replacement's connection is lost between its promotion
                // and the supervisory state recording it; the loss is given
                // every chance to be handled first.
                let (lost_tx, lost) = std::sync::mpsc::channel();
                let losing = boundary.clone();
                let lost_connection = candidate.connection_id();
                *lock(&boundary.promotion_hook) = Some(Box::new(move || {
                    let (started_tx, started) = std::sync::mpsc::channel();
                    let disconnect = std::thread::spawn(move || {
                        started_tx.send(()).expect("report start");
                        losing.transport_disconnected(lost_connection);
                    });
                    started.recv().expect("disconnect started");
                    std::thread::sleep(Duration::from_millis(200));
                    lost_tx.send(disconnect).expect("hand over disconnect");
                }));
                assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
                boundary.commit_confirm(&candidate).expect("promotion");
                lost.recv_timeout(Duration::from_secs(10))
                    .expect("promotion ran the hook")
                    .join()
                    .expect("disconnect thread");

                let state = *lock(&boundary.supervisor_connection);
                let recovery_id = match state {
                    SupervisorConnectionState::Frozen { recovery_id } => recovery_id,
                    state => panic!(
                        "lost replacement (previous owner connected: \
                         {previous_owner_connected}) left the workload {state:?}"
                    ),
                };
                assert_ne!(Some(recovery_id), earlier_recovery);
                assert!(boundary.connections.require_active(&candidate).is_err());
                let stopped_by = std::time::Instant::now() + Duration::from_secs(5);
                while !process_stopped(workload.signaler.pid()) {
                    assert!(
                        std::time::Instant::now() < stopped_by,
                        "the workload must stay frozen without a supervisor"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }

                // The fresh deadline ends the unsupervised workload.
                let terminated_by = std::time::Instant::now() + Duration::from_secs(30);
                while *lock(&boundary.supervisor_connection) != SupervisorConnectionState::Terminal
                    || !workload.has_exited()
                {
                    assert!(
                        std::time::Instant::now() < terminated_by,
                        "the recovery deadline must terminate the workload"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
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
                    &workload_launcher,
                    ManagedProcessLaunch {
                        process_id: "generation-retained:main:0".to_string(),
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
            let boundary = Arc::new(
                BoundaryRuntime::new(
                    BoundaryConfig {
                        boundary_id: "sandbox-retained".to_string(),
                        generation: "generation-retained".to_string(),
                        session_id: test_session_id(),
                        session_rotation: openshell_core::jwt::SessionRotation::new(1)
                            .expect("session rotation"),
                        auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                        gateway_id: "test-gateway".to_string(),
                        verification_keys: vec![test_verification_key()],
                        listener: BoundaryListenerConfig::TlsTcp {
                            address: "127.0.0.1:5500".parse().expect("control address"),
                            tls: placeholder_server_tls(),
                        },
                        resource_claims: std::collections::BTreeMap::new(),
                        resource_claim_files: std::collections::BTreeMap::new(),
                        workload_identity: test_workload_identity(),
                        provisioning_evidence: test_provisioning_evidence(),
                        child_env: std::collections::HashMap::new(),
                    },
                    process_runtime.handle().clone(),
                    network_broker,
                    workload_launcher,
                    test_runtime_qualification(),
                )
                .expect("test boundary runtime"),
            );
            *lock(&boundary.state) = RuntimeState::Running(process.clone());
            *lock(&boundary.attached_policy) = Some(wire_policy.clone());
            *lock(&boundary.started_agent) = Some(StartedAgent {
                provider_files: std::collections::HashMap::new(),
                sandbox_id: "sandbox-retained".to_string(),
                spec: agent_spec.clone(),
                ca_cert: None,
                ca_bundle: None,
                provider_env_revision: 0,
                provider_env: std::collections::HashMap::new(),
            });

            // A replacement control process replays the durable lifecycle and
            // receives the original process rather than spawning another one.
            assert!(matches!(
                boundary.attach(wire_policy.clone(), false),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                boundary.start_agent(
                    "sandbox-retained".to_string(),
                    agent_spec.clone(),
                    None,
                    None,
                    0,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                ),
                Response::Started {
                    process_id: process.process_id(),
                    provider_env_revision: 0,
                    provider_env_generation: 0,
                }
            );

            assert_eq!(
                boundary.update_provider_environment(
                    1,
                    2,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "refreshed".to_string(),
                    )]),
                    std::collections::HashMap::new(),
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 2,
                    generation: 1,
                    applied: true,
                }
            );
            assert_eq!(
                boundary.update_provider_environment(
                    0,
                    1,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "stale".to_string(),
                    )]),
                    std::collections::HashMap::new(),
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 2,
                    generation: 1,
                    applied: false,
                }
            );
            assert_eq!(
                boundary.update_provider_environment(
                    2,
                    1,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new()
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 1,
                    generation: 2,
                    applied: true,
                },
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
                    std::collections::HashMap::new(),
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 1,
                    generation: 2,
                    applied: false,
                },
                "a stale publication must not overwrite current state"
            );
            assert_eq!(
                boundary.update_provider_environment(
                    1,
                    1,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new()
                ),
                Response::ProviderEnvironmentUpdated {
                    revision: 1,
                    generation: 2,
                    applied: false,
                },
                "a duplicate update must be idempotent"
            );

            assert!(matches!(
                boundary.attach(wire_policy, false),
                Response::Attached { .. }
            ));
            assert!(matches!(boundary.confirm(), Response::Confirmed { .. }));
            assert_eq!(
                boundary.start_agent(
                    "sandbox-retained".to_string(),
                    agent_spec,
                    None,
                    None,
                    99,
                    std::collections::HashMap::from([(
                        "ROTATED_TOKEN".to_string(),
                        "replacement-control-snapshot".to_string(),
                    )]),
                    std::collections::HashMap::new(),
                ),
                Response::Started {
                    process_id: process.process_id(),
                    provider_env_revision: 1,
                    provider_env_generation: 2,
                },
                "a replacement control must resume from the boundary's current revision"
            );

            let sleep_spec = ExecSpecWire {
                program: "/bin/sleep".to_string(),
                args: vec!["30".to_string()],
                shell: None,
                runtime_helper: None,
                env: Vec::new(),
                workdir: None,
                pty: false,
            };
            let sleep_request = RequestEnvelope::new(Request::Exec {
                spec: sleep_spec.clone(),
            })
            .expect("build retained exec request");
            for deadline in [None, Some(0)] {
                assert!(
                    boundary
                        .start_exec(
                            &sleep_request.request_id,
                            &sleep_request.payload_digest,
                            deadline,
                            sleep_spec.clone(),
                        )
                        .is_err(),
                    "missing or expired deadlines must not start a process"
                );
                assert!(lock(&boundary.exec_handles).is_empty());
            }
            // Completed exec IDs must not impose the former lifetime limit on
            // a real process launch or recovery of its lost start response.
            {
                let mut requests = lock(&boundary.exec_requests);
                for index in 0..4096 {
                    requests
                        .reserve(
                            &format!("completed-request-{index}"),
                            sleep_request.exec_admission_deadline_unix_ms.unwrap(),
                        )
                        .unwrap();
                }
            }
            let started = boundary
                .start_exec(
                    &sleep_request.request_id,
                    &sleep_request.payload_digest,
                    sleep_request.exec_admission_deadline_unix_ms,
                    sleep_spec.clone(),
                )
                .expect("start exec whose response is disconnected");
            let retained_id = started.process_id.clone();
            drop(started);
            let replayed = boundary
                .start_exec(
                    &sleep_request.request_id,
                    &sleep_request.payload_digest,
                    sleep_request.exec_admission_deadline_unix_ms,
                    sleep_spec.clone(),
                )
                .expect("reattach exec after response loss");
            assert_eq!(replayed.process_id, retained_id);
            assert_eq!(lock(&boundary.exec_handles).len(), 1);
            drop(replayed);
            assert_eq!(
                boundary.signal(&retained_id, SignalWire::Kill),
                Response::Signaled
            );
            for _ in 0..2 {
                assert_eq!(
                    boundary.wait(&retained_id),
                    Response::Exited {
                        status: ExitStatusWire::Signaled(libc::SIGKILL),
                    },
                    "independent waits must preserve a retained exec's signal status"
                );
            }
            lock(&boundary.exec_handles).remove(&retained_id);
            assert!(
                boundary
                    .start_exec(
                        &sleep_request.request_id,
                        &sleep_request.payload_digest,
                        sleep_request.exec_admission_deadline_unix_ms,
                        sleep_spec,
                    )
                    .is_err(),
                "an evicted exec request must never start a second process"
            );

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !process.has_exited() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(process.has_exited(), "canonical process did not exit");
            assert_eq!(
                boundary.wait(&process.process_id()),
                Response::Exited {
                    status: ExitStatusWire::Exited(0),
                }
            );
            for exit_code in [0, 7] {
                let spec = ExecSpecWire {
                    program: "/bin/sh".to_string(),
                    args: vec!["-c".to_string(), format!("exit {exit_code}")],
                    shell: None,
                    runtime_helper: None,
                    env: Vec::new(),
                    workdir: None,
                    pty: false,
                };
                let request = RequestEnvelope::new(Request::Exec { spec: spec.clone() })
                    .expect("build exec status request");
                let exec = boundary
                    .start_exec(
                        &request.request_id,
                        &request.payload_digest,
                        request.exec_admission_deadline_unix_ms,
                        spec,
                    )
                    .expect("start exec after canonical exit");
                for _ in 0..2 {
                    assert_eq!(
                        boundary.wait(&exec.process_id),
                        Response::Exited {
                            status: ExitStatusWire::Exited(exit_code),
                        },
                        "wait must work independently of attachment consumption and main exit"
                    );
                }
            }
            assert!(matches!(
                boundary.wait("generation-retained:exec:unknown"),
                Response::Error {
                    kind: BoundaryErrorKind::Invalid,
                    ..
                }
            ));

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
                            shell: None,
                            runtime_helper: None,
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
pub fn run_boundary(
    config_path: &Path,
    qualification: crate::RuntimeQualification,
) -> Result<(), String> {
    linux::run_boundary(config_path, qualification)
}

#[cfg(not(target_os = "linux"))]
pub fn run_boundary(
    _config_path: &Path,
    _qualification: crate::RuntimeQualification,
) -> Result<(), String> {
    Err("boundary mode is supported only on Linux".to_string())
}
