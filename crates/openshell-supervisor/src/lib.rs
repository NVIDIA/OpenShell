// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` supervisor library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

// `defaults-without-telemetry` is an alias for the default feature set minus
// `telemetry`, not a switch that turns telemetry off. Cargo cannot subtract a
// default feature, so adding it on top of the defaults would otherwise produce
// a telemetry-on build that reads as telemetry-free. Fail the build instead.
#[cfg(all(feature = "telemetry", feature = "defaults-without-telemetry"))]
compile_error!(
    "features `telemetry` and `defaults-without-telemetry` are mutually exclusive; \
     build a telemetry-free supervisor with `--no-default-features --features defaults-without-telemetry`"
);

mod activity_aggregator;
mod backend_setup;
mod config_runtime;
mod denial_aggregator;
mod endpoint_status;
mod mechanistic_mapper;
mod provider_readiness;

use config_runtime::{
    agent_proposals_enabled_from_settings, bootstrap_result, config_apply_result_activates,
    run_policy_poll_loop,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::Duration;
use tracing::{Instrument as _, debug, info, warn};

use openshell_core::PolicyValidationFailureMode;

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfidenceId, ConfigStateChangeBuilder,
    DetectionFindingBuilder, DispositionId, EventContext, FindingInfo, OcsfEvent, SeverityId,
    StateId, StatusId, ocsf_emit,
};

// ---------------------------------------------------------------------------
// OCSF Context
// ---------------------------------------------------------------------------
//
// The following log sites intentionally remain as plain `tracing` macros
// and are NOT migrated to OCSF builders:
//
// - DEBUG/TRACE events (zombie reaping, ip commands, gRPC connects, PTY state)
// - Transient "about to do X" events where the result is logged separately
//   (e.g., "Fetching sandbox policy via gRPC", "Creating OPA engine from proto")
// - Internal SSH channel warnings (unknown channel, PTY resize failures)
// - Denial flush telemetry (the individual denials are already OCSF events)
// - Status reporting failures (sync to gateway, non-actionable)
// - Route refresh interval validation warnings
//
// These are operational plumbing that don't represent security decisions,
// policy changes, or observable sandbox behavior worth structuring.
// ---------------------------------------------------------------------------

/// Re-export the process-wide OCSF sandbox context getter.
///
/// The singleton lives in `openshell-ocsf` so both supervisor leaves can
/// reach it without depending on `openshell-sandbox`. Initialised once during
/// `run_sandbox()` startup via `openshell_ocsf::ctx::set_ctx`.
pub(crate) use openshell_ocsf::ctx::ctx as ocsf_ctx;

async fn retain_remote_access_plane(
    proxy_exited: impl Future<Output = ()>,
    shutdown_requested: impl Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(proxy_exited);
    tokio::pin!(shutdown_requested);
    tokio::select! {
        () = &mut proxy_exited => Err(miette::miette!(
            "control-mode proxy accept loop exited unexpectedly"
        )),
        () = &mut shutdown_requested => Ok(()),
    }
}

async fn completion_phase_or_shutdown<F, S>(phase: F, mut shutdown: Pin<&mut S>) -> bool
where
    F: Future<Output = ()>,
    S: Future<Output = ()> + ?Sized,
{
    tokio::pin!(phase);
    tokio::select! {
        () = &mut phase => false,
        () = &mut shutdown => true,
    }
}

/// Where the supervisor publishes readiness. The listener exists only while
/// the supervisor session is ready, so a successful connect means ready.
#[derive(Clone, Debug)]
enum ReadinessEndpoint {
    Unix(std::path::PathBuf),
    /// Wildcard TCP port reachable from the node, for kubelet `tcpSocket` probes.
    Tcp(u16),
}

enum ReadinessListener {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

impl ReadinessEndpoint {
    fn bind(&self) -> Result<ReadinessListener> {
        match self {
            Self::Unix(path) => {
                prepare_control_readiness_path(path)?;
                tokio::net::UnixListener::bind(path)
                    .map(ReadinessListener::Unix)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("bind supervisor readiness socket on {}", path.display())
                    })
            }
            Self::Tcp(port) => bind_readiness_tcp(*port)
                .and_then(tokio::net::TcpListener::from_std)
                .map(ReadinessListener::Tcp)
                .into_diagnostic()
                .wrap_err_with(|| format!("bind supervisor readiness listener on port {port}")),
        }
    }

    fn remove(&self) {
        if let Self::Unix(path) = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Falls back to IPv4 when the network namespace has IPv6 disabled.
fn bind_readiness_tcp(port: u16) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, Type};

    let bind = |domain: Domain, address: std::net::SocketAddr| {
        let socket = Socket::new(domain, Type::STREAM, None)?;
        if domain == Domain::IPV6 {
            socket.set_only_v6(false)?;
        }
        socket.set_reuse_address(true)?;
        socket.bind(&address.into())?;
        socket.listen(128)?;
        socket.set_nonblocking(true)?;
        Ok::<_, std::io::Error>(std::net::TcpListener::from(socket))
    };
    bind(Domain::IPV6, (std::net::Ipv6Addr::UNSPECIFIED, port).into())
        .or_else(|_| bind(Domain::IPV4, (std::net::Ipv4Addr::UNSPECIFIED, port).into()))
}

impl ReadinessListener {
    async fn accept(&self) -> std::io::Result<()> {
        match self {
            Self::Unix(listener) => listener.accept().await.map(drop),
            Self::Tcp(listener) => listener.accept().await.map(drop),
        }
    }
}

struct ControlReadiness {
    task: tokio::task::JoinHandle<()>,
    endpoint: ReadinessEndpoint,
}

impl ControlReadiness {
    fn start(
        endpoint: ReadinessEndpoint,
        mut session_readiness: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Result<Self> {
        if let ReadinessEndpoint::Unix(path) = &endpoint {
            prepare_control_readiness_path(path)?;
        }
        let listener = if session_readiness
            .as_ref()
            .is_some_and(|readiness| !*readiness.borrow())
        {
            None
        } else {
            Some(endpoint.bind()?)
        };
        let task_endpoint = endpoint.clone();
        let task = tokio::spawn(async move {
            let mut listener = listener;
            loop {
                let session_unready = session_readiness
                    .as_ref()
                    .is_some_and(|readiness| !*readiness.borrow());
                if listener.is_none() || session_unready {
                    if session_unready {
                        listener.take();
                        task_endpoint.remove();
                        let Some(readiness) = session_readiness.as_mut() else {
                            break;
                        };
                        if readiness.wait_for(|ready| *ready).await.is_err() {
                            break;
                        }
                    }
                    match task_endpoint.bind() {
                        Ok(rebound) => listener = Some(rebound),
                        Err(error) => {
                            tracing::warn!(%error, "control-mode readiness rebind failed; retrying");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                    continue;
                }

                let Some(active_listener) = listener.as_ref() else {
                    continue;
                };
                if let Some(readiness) = session_readiness.as_mut() {
                    tokio::select! {
                        accepted = active_listener.accept() => match accepted {
                            Ok(()) => {}
                            Err(error) => {
                                tracing::warn!(%error, "control-mode readiness accept failed; retrying");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        },
                        changed = readiness.changed() => {
                            if changed.is_err() {
                                break;
                            }
                        }
                    }
                } else {
                    match active_listener.accept().await {
                        Ok(()) => {}
                        Err(error) => {
                            tracing::warn!(%error, "control-mode readiness accept failed; retrying");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
            task_endpoint.remove();
        });
        Ok(Self { task, endpoint })
    }
}

#[cfg(unix)]
fn prepare_control_readiness_path(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    if !path.is_absolute() {
        return Err(miette::miette!(
            "supervisor readiness socket path must be absolute"
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("create readiness directory {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(miette::miette!(
                    "refusing unsafe existing readiness path {}",
                    path.display()
                ));
            }
            std::fs::remove_file(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("remove stale readiness socket {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .into_diagnostic()
                .wrap_err_with(|| format!("inspect readiness path {}", path.display()));
        }
    }
    Ok(())
}

impl Drop for ControlReadiness {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.remove();
    }
}

/// Check whether the live supervisor owns its private readiness socket.
#[cfg(unix)]
pub fn check_control_readiness(path: &std::path::Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(miette::miette!("health socket path must be absolute"));
    }
    std::os::unix::net::UnixStream::connect(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("connect supervisor readiness socket {}", path.display()))?;
    Ok(())
}

/// Health subcommands are unsupported on non-Unix hosts.
#[cfg(not(unix))]
pub fn check_control_readiness(_path: &std::path::Path) -> Result<()> {
    Err(miette::miette!(
        "supervisor readiness sockets require a Unix host"
    ))
}

#[cfg(unix)]
async fn wait_for_control_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install control SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install control SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_control_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

use openshell_core::denial::DenialEvent;
use openshell_core::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use openshell_core::proposals::AgentProposals;
use openshell_core::proto::ProviderReadinessReason;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_network::opa::{OpaEngine, PolicyGenerationGuard};
use openshell_supervisor_network::proxy::ProxyHandle;
use openshell_supervisor_process::supervisor_session::{
    ConfigApplyRequest, config_admission, config_apply_result, provider_config_revision,
    sandbox_config_revision,
};
use provider_readiness::{EnvironmentIdentity, Tracker as ProviderReadinessTracker};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;

fn shared_ssh_socket_from_env() -> bool {
    std::env::var(openshell_core::sandbox_env::SSH_SOCKET_SHARED)
        .is_ok_and(|value| shared_ssh_socket_value(&value))
}

fn shared_ssh_socket_value(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

struct PreparedNetworkProxyTlsDir {
    path: std::path::PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

fn prepare_network_proxy_tls_dir(
    requested: Option<std::path::PathBuf>,
) -> Result<PreparedNetworkProxyTlsDir> {
    let Some(requested) = requested else {
        let mut builder = tempfile::Builder::new();
        builder.prefix("openshell-supervisor-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let temporary = builder
            .tempdir()
            .into_diagnostic()
            .wrap_err("create private network-proxy TLS directory")?;
        return Ok(PreparedNetworkProxyTlsDir {
            path: temporary.path().to_path_buf(),
            _temporary: Some(temporary),
        });
    };

    match std::fs::symlink_metadata(&requested) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(miette::miette!(
                "network-proxy TLS directory must not be a symlink: {}",
                requested.display()
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(miette::miette!(
                "network-proxy TLS path is not a directory: {}",
                requested.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(&requested)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "create private network-proxy TLS directory {}",
                            requested.display()
                        )
                    })?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir(&requested)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "create private network-proxy TLS directory {}",
                        requested.display()
                    )
                })?;
        }
        Err(error) => return Err(error).into_diagnostic(),
    }

    let path = requested
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "resolve network-proxy TLS directory {}",
                requested.display()
            )
        })?;
    validate_network_proxy_tls_dir(&path)?;
    Ok(PreparedNetworkProxyTlsDir {
        path,
        _temporary: None,
    })
}

#[cfg(unix)]
fn validate_network_proxy_tls_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = nix::unistd::geteuid().as_raw();
    for (index, component) in path.ancestors().enumerate() {
        let metadata = std::fs::metadata(component)
            .into_diagnostic()
            .wrap_err_with(|| format!("inspect TLS directory component {}", component.display()))?;
        let mode = metadata.mode();
        if !metadata.is_dir() {
            return Err(miette::miette!(
                "TLS directory component is not a directory: {}",
                component.display()
            ));
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(miette::miette!(
                "TLS directory component is owned by an untrusted user: {}",
                component.display()
            ));
        }
        if index == 0 {
            if metadata.uid() != effective_uid || mode & 0o022 != 0 {
                return Err(miette::miette!(
                    "network-proxy TLS directory must be owned by the current user and not group- or world-writable: {}",
                    component.display()
                ));
            }
        } else if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(miette::miette!(
                "TLS directory has an untrusted writable ancestor: {}",
                component.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_network_proxy_tls_dir(path: &std::path::Path) -> Result<()> {
    if !path.is_dir() {
        return Err(miette::miette!(
            "network-proxy TLS path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Run the supervisor as an explicit HTTP/CONNECT network proxy.
///
/// This role deliberately bypasses the Isolation Backend: it does not attach
/// a Sandbox Runtime, launch a workload, or claim process and binary identity.
/// It reuses the same local Rego/YAML policy engine and proxy implementation as
/// sandbox supervision.
///
/// # Errors
///
/// Returns an error when policy loading or proxy startup fails, or when the
/// proxy accept loop exits unexpectedly.
pub async fn run_network_proxy(
    listen: std::net::SocketAddr,
    policy_rules: String,
    policy_data: String,
    tls_dir: Option<std::path::PathBuf>,
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
) -> Result<i32> {
    if !listen.ip().is_loopback() {
        return Err(miette::miette!(
            "network-proxy listener must use a loopback address: {listen}"
        ));
    }

    let hostname = std::fs::read_to_string("/etc/hostname").map_or_else(
        |_| "openshell-supervisor".to_string(),
        |value| value.trim().to_string(),
    );
    if !openshell_ocsf::ctx::set_ctx(EventContext {
        sandbox_id: String::new(),
        sandbox_name: "network-proxy".to_string(),
        container_image: String::new(),
        hostname,
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: listen.ip(),
        proxy_port: listen.port(),
        origin: openshell_ocsf::EventOrigin::Supervisor,
    }) {
        debug!("OCSF context already initialized, keeping existing");
    }

    let extension_credentials = openshell_extension_core::ExtensionCredentialStore::new();
    let (mut policy, opa_engine, _, _, _, initial_agent_proposals_enabled, _, _) = load_policy(
        None,
        None,
        None,
        Some(policy_rules),
        Some(policy_data),
        &extension_credentials,
        LocalPolicyIdentity::EndpointOnly,
    )
    .await?;
    policy.network = NetworkPolicy {
        mode: NetworkMode::Proxy,
        proxy: Some(ProxyPolicy {
            http_addr: Some(listen),
        }),
    };

    let provider_credentials = ProviderCredentialState::from_environment(
        0,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );
    let (_, workspace_rx) = tokio::sync::watch::channel(String::new());
    let tls_dir = prepare_network_proxy_tls_dir(tls_dir)?;
    let mut networking = openshell_supervisor_network::run::run_networking(
        &policy,
        None,
        opa_engine.as_ref(),
        None,
        Arc::new(AtomicU32::new(0)),
        false,
        &provider_credentials,
        None,
        Some("network-proxy"),
        None,
        None,
        None,
        None,
        AgentProposals::new(initial_agent_proposals_enabled),
        workspace_rx,
        &upstream_proxy_args,
        Some(&tls_dir.path),
        None,
        #[cfg(target_os = "linux")]
        None,
        None,
    )
    .await?;

    if let Some((ca_certificate, trust_bundle)) = networking.ca_file_paths.as_ref() {
        info!(
            ca_certificate = %ca_certificate.display(),
            trust_bundle = %trust_bundle.display(),
            "Network-proxy trust files ready"
        );
    }

    let proxy = networking
        .proxy
        .as_mut()
        .ok_or_else(|| miette::miette!("network-proxy role did not start a proxy listener"))?;
    let bound = proxy
        .http_addr()
        .ok_or_else(|| miette::miette!("network-proxy role did not bind an explicit listener"))?;
    let exited = proxy
        .take_exit_receiver()
        .ok_or_else(|| miette::miette!("network-proxy exit monitor is unavailable"))?;
    info!(%bound, "Network-proxy role ready");

    tokio::select! {
        _ = exited => Err(miette::miette!("network-proxy accept loop exited unexpectedly")),
        () = wait_for_control_shutdown_signal() => {
            drop(networking);
            Ok(0)
        }
    }
}

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
#[allow(
    clippy::too_many_arguments,
    clippy::implicit_hasher,
    clippy::similar_names,
    clippy::fn_params_excessive_bools
)]
pub async fn run_sandbox(
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    await_main_process_attachment: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    health_socket_path: Option<std::path::PathBuf>,
    health_port: Option<u16>,
    ocsf_enabled: Arc<AtomicBool>,
    ocsf_schema_version: Arc<std::sync::Mutex<String>>,
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
    backend_descriptor: openshell_isolation_interface::contract::BackendDescriptor,
    auth_bundle: openshell_core::jwt::SupervisorAuthBundle,
    admitted_isolation_backend: Option<String>,
    main_exit_marker: Option<std::path::PathBuf>,
) -> Result<i32> {
    // Shared startup retains policy and networking state; box it to keep callers' futures small.
    Box::pin(run_sandbox_with_backend(
        &backend_setup::OpenShellBackendSetup,
        SandboxRunConfig {
            command,
            workdir,
            timeout_secs,
            interactive,
            await_main_process_attachment,
            sandbox_id,
            sandbox,
            openshell_endpoint,
            policy_rules,
            policy_data,
            ssh_socket_path,
            health_socket_path,
            health_port,
            ocsf_enabled,
            ocsf_schema_version,
            upstream_proxy_args,
            backend_descriptor,
            auth_bundle,
            admitted_isolation_backend,
            main_exit_marker,
        },
    ))
    .await
}

struct SandboxRunConfig {
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    await_main_process_attachment: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    health_socket_path: Option<std::path::PathBuf>,
    health_port: Option<u16>,
    ocsf_enabled: Arc<AtomicBool>,
    ocsf_schema_version: Arc<std::sync::Mutex<String>>,
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
    backend_descriptor: openshell_isolation_interface::contract::BackendDescriptor,
    auth_bundle: openshell_core::jwt::SupervisorAuthBundle,
    admitted_isolation_backend: Option<String>,
    main_exit_marker: Option<std::path::PathBuf>,
}

/// Trusted composition chooses the setup before shared admission, policy, and
/// lifecycle handling. Payload contents never select a backend implementation.
#[allow(clippy::similar_names)]
async fn run_sandbox_with_backend(
    backend_setup: &dyn backend_setup::BackendSetup,
    config: SandboxRunConfig,
) -> Result<i32> {
    let SandboxRunConfig {
        command,
        workdir,
        timeout_secs,
        interactive,
        await_main_process_attachment,
        sandbox_id,
        sandbox,
        openshell_endpoint,
        policy_rules,
        policy_data,
        ssh_socket_path,
        health_socket_path,
        health_port,
        ocsf_enabled,
        ocsf_schema_version,
        upstream_proxy_args,
        backend_descriptor,
        auth_bundle,
        admitted_isolation_backend,
        main_exit_marker,
    } = config;
    // An empty command is the versioned scratch-sandbox sentinel. The
    // external supervisor cannot inspect the workload filesystem, so preserve
    // it for openshell-sandbox to resolve against the agent image.
    let (program, args) = command.split_first().map_or_else(
        || (String::new(), Vec::new()),
        |(program, args)| (program.clone(), args.to_vec()),
    );

    // Initialize the process-wide OCSF context early so that events emitted
    // during policy loading (filesystem config, validation) have a context.
    // Proxy IP/port use defaults here; the boundary mediation source carries
    // workload-side connection metadata.
    {
        let hostname = std::fs::read_to_string("/etc/hostname").map_or_else(
            |_| "openshell-sandbox".to_string(),
            |s| s.trim().to_string(),
        );

        if !openshell_ocsf::ctx::set_ctx(EventContext {
            sandbox_id: sandbox_id.clone().unwrap_or_default(),
            sandbox_name: sandbox.as_deref().unwrap_or_default().to_string(),
            container_image: std::env::var("OPENSHELL_CONTAINER_IMAGE").unwrap_or_default(),
            hostname,
            product_version: openshell_core::VERSION.to_string(),
            proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            proxy_port: 3128,
            origin: openshell_ocsf::EventOrigin::Supervisor,
        }) {
            debug!("OCSF context already initialized, keeping existing");
        }
    }

    // Extension credentials are owned by this supervisor and shared by every
    // gateway connection it opens, so the middleware registry's bearer slots
    // and the policy poll loop that rotates them stay the same objects.
    let extension_credentials = openshell_extension_core::ExtensionCredentialStore::new();

    let selected_backend = backend_setup::SelectedBackend::select(
        backend_setup,
        backend_descriptor,
        admitted_isolation_backend.as_deref(),
        sandbox_id.as_deref(),
        &auth_bundle,
    )?;
    let sandbox_bearer = openshell_core::grpc_client::install_supervisor_auth_bundle(&auth_bundle)?;
    let ssh_host_key = if ssh_socket_path.is_some() {
        Some(openshell_supervisor_process::ssh::parse_host_key(
            auth_bundle.ssh_host_private_key.as_ref(),
        )?)
    } else {
        None
    };
    // Startup joins the trace that created the sandbox when the driver passes
    // one, and ends once the access plane is up.
    let startup = tracing::info_span!(
        "supervisor.startup",
        sandbox.id = sandbox_id.as_deref().unwrap_or_default(),
        otel.status_code = tracing::field::Empty,
    );
    openshell_otel::set_parent_from_environment(&startup);
    let startup_status = startup.in_scope(openshell_otel::ErrorStatusGuard::current);
    let (image_yaml, invalid_image) = selected_backend
        .discover_policy(sandbox_bearer.clone())
        .instrument(tracing::info_span!(parent: &startup, "supervisor.boundary.discover_policy"))
        .await?;
    let image_discovery = if invalid_image {
        ImagePolicyDiscovery::Invalid
    } else if let Some(yaml) = image_yaml {
        openshell_policy::parse_sandbox_policy(&yaml)
            .map_or(ImagePolicyDiscovery::Invalid, |policy| {
                ImagePolicyDiscovery::Policy(Box::new(policy))
            })
    } else {
        ImagePolicyDiscovery::Missing
    };

    let supervisor_instance_id = uuid::Uuid::new_v4().to_string();
    let stream_image_discovery = openshell_core::proto::ImagePolicyDiscovery {
        result: Some(match &image_discovery {
            ImagePolicyDiscovery::Missing => {
                openshell_core::proto::image_policy_discovery::Result::Missing(())
            }
            ImagePolicyDiscovery::Invalid => {
                openshell_core::proto::image_policy_discovery::Result::Invalid(())
            }
            ImagePolicyDiscovery::Policy(policy) => {
                openshell_core::proto::image_policy_discovery::Result::Policy(*policy.clone())
            }
        }),
    };
    let mut prepared_supervisor_session =
        if let (Some(endpoint), Some(id)) = (&openshell_endpoint, &sandbox_id) {
            Some(
                openshell_supervisor_process::supervisor_session::prepare(
                    endpoint.clone(),
                    id.clone(),
                    supervisor_instance_id.clone(),
                    stream_image_discovery,
                    |mut policy| {
                        let enriched = enrich_proto_baseline_paths(&mut policy);
                        Ok(proto_sync_payload_for_enriched_policy(&policy, enriched))
                    },
                )
                .await
                .map_err(|error| {
                    miette::miette!("failed to establish supervisor bootstrap session: {error}")
                })?,
            )
        } else {
            None
        };
    let stream_bootstrap = prepared_supervisor_session.as_mut().and_then(
        openshell_supervisor_process::supervisor_session::PreparedSupervisorSession::take_bootstrap,
    );
    let uses_stream_configuration = prepared_supervisor_session.as_ref().is_some_and(
        openshell_supervisor_process::supervisor_session::PreparedSupervisorSession::uses_stream_configuration,
    );
    // A polling gateway has already accepted this session, but a legacy
    // gateway marks the sandbox ready as soon as it accepts one, and
    // SessionAccepted does not say which kind this is. Close the session and
    // reconnect once the workload runs, as polling supervisors always have.
    if !uses_stream_configuration {
        prepared_supervisor_session = None;
    }

    let initial_stream_snapshot: Option<openshell_core::grpc_client::SettingsPollResult> =
        match stream_bootstrap.as_ref() {
            Some(bootstrap) => Some(
                bootstrap
                    .sandbox_config
                    .clone()
                    .ok_or_else(|| {
                        miette::miette!(
                            "supervisor bootstrap omitted required sandbox configuration"
                        )
                    })?
                    .into(),
            ),
            None => None,
        };
    let vm_policy_identity = selected_backend.vm_policy_identity();

    // Load policy and initialize OPA engine
    let openshell_endpoint_for_proxy = openshell_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let (
        policy,
        opa_engine,
        retained_proto,
        middleware_registry_status,
        loaded_policy_origin,
        initial_agent_proposals_enabled,
        initial_extension_authentication_enabled,
        captured_provider_environment,
    ) = load_policy_with_gateway(
        sandbox_id.clone(),
        sandbox.clone(),
        openshell_endpoint.clone(),
        policy_rules,
        policy_data,
        &extension_credentials,
        LocalPolicyIdentity::Required,
        vm_policy_identity,
        Some(image_discovery),
        initial_stream_snapshot.clone(),
        &RemoteStartupGateway {
            endpoint: openshell_endpoint.clone().unwrap_or_default(),
        },
    )
    .instrument(tracing::info_span!(parent: &startup, "supervisor.policy.load"))
    .await?;

    // Normalize the active driver's identity contract once, while both the
    // policy and launched image filesystem are available. Kubernetes and
    // OpenShift retain their authoritative numeric pair; Docker fills only
    // omitted policy fields from OCI Config.User. A remote boundary resolves
    // identity in its own filesystem instead; control must not interpret
    // guest account data against the host's /etc/passwd and /etc/group.
    let workspace = workdir;

    let provider_readiness = ProviderReadinessTracker::new();
    let (provider_credentials, provider_bootstrap_degraded) = if let Some(snapshot) =
        stream_bootstrap
            .as_ref()
            .and_then(|bootstrap| bootstrap.provider_environment.clone())
    {
        // Polling startup fails the same way on an invalid provider response.
        let result = openshell_core::grpc_client::ProviderEnvironmentResult::try_from(snapshot)
            .wrap_err("supervisor bootstrap delivered an invalid provider environment")?;
        let degraded = result.readiness_reason != ProviderReadinessReason::Unspecified;
        let credentials = initial_provider_credentials(result, &provider_readiness);
        (credentials, degraded)
    } else if stream_bootstrap.is_some() {
        (
            ProviderCredentialState::from_child_env_snapshot(0, std::collections::HashMap::new()),
            true,
        )
    } else if let Some(environment) = captured_provider_environment {
        (environment.install(&provider_readiness), false)
    } else {
        // Fetch provider environment variables from the server.
        // This is done after loading the policy so the sandbox can still start
        // even if provider env fetch fails (graceful degradation).
        let environment = if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
            match openshell_core::grpc_client::fetch_provider_environment(endpoint, id)
                .instrument(startup.clone())
                .await
            {
                Ok(result) => {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .message(format!(
                                "Fetched provider environment [env_count:{}]",
                                result.environment.len()
                            ))
                            .build()
                    );
                    Some(result)
                }
                Err(e) => {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "fail_closed")
                            .message(format!(
                                "Failed to fetch provider environment; no provider credentials are active: {e}"
                            ))
                            .build()
                    );
                    None
                }
            }
        } else {
            None
        };

        let credentials = environment.map_or_else(
            || {
                ProviderCredentialState::from_environment(
                    0,
                    std::collections::HashMap::default(),
                    std::collections::HashMap::default(),
                    std::collections::HashMap::default(),
                )
            },
            |result| initial_provider_credentials(result, &provider_readiness),
        );
        (credentials, false)
    };

    // The bootstrap already initialized the runtime. Report what startup
    // installed before the workload starts.
    let mut prepared_bootstrap_result = stream_bootstrap.as_ref().map(|bootstrap| {
        use openshell_core::proto::{ConfigApplyOutcome, ConfigComponent};

        let provider = bootstrap.provider_environment.as_ref().map(|snapshot| {
            let revision = provider_config_revision(snapshot.provider_env_revision);
            let outcome = if provider_bootstrap_degraded {
                ConfigApplyOutcome::Degraded
            } else {
                ConfigApplyOutcome::Applied
            };
            config_apply_result(
                ConfigComponent::ProviderEnvironment,
                Some(revision.clone()),
                Some(revision),
                outcome,
                None,
            )
        });
        let sandbox = initial_stream_snapshot.as_ref().map(|snapshot| {
            let revision = sandbox_config_revision(snapshot);
            let result = if snapshot.configuration_admitted {
                // Unreachable middleware leaves the policy enforced with only
                // built-in middleware until the runtime connects it.
                let outcome =
                    if middleware_registry_status == MiddlewareRegistryStatus::Synchronized {
                        ConfigApplyOutcome::Applied
                    } else {
                        ConfigApplyOutcome::Degraded
                    };
                config_apply_result(
                    ConfigComponent::SandboxConfig,
                    Some(revision.clone()),
                    Some(revision),
                    outcome,
                    None,
                )
            } else {
                config_apply_result(
                    ConfigComponent::SandboxConfig,
                    Some(revision),
                    None,
                    ConfigApplyOutcome::FailedClosed,
                    Some((
                        "configuration_rejected",
                        &snapshot.configuration_error,
                        true,
                    )),
                )
            };
            let admission = config_admission(snapshot, config_apply_result_activates(&result));
            (result, admission)
        });
        bootstrap_result(provider, sandbox, true)
    });

    if credential_gating_unavailable(
        &loaded_policy_origin,
        provider_credentials.resolver().is_some(),
        true,
    ) {
        report_credential_gating_unavailable();
    }

    // Canonical-process overrides are deliberately applied only to the main
    // child. Keep the provider snapshot pristine for later exec/editor/SFTP
    // children launched by the sandbox.

    // Shared agent-proposals feature flag. Seed from the same initial settings
    // snapshot that produced the policy so networking and process setup agree
    // before the poll loop starts reconciling later changes.
    let agent_proposals = AgentProposals::new(initial_agent_proposals_enabled);
    // Keep the accepted launch generation fixed until the child has actually
    // spawned. Live reconciliation must not race its captured policy/env.
    let (workload_started_tx, workload_started_rx) = tokio::sync::watch::channel(false);

    // Shared PID: set after process spawn so the proxy can look up
    // the entrypoint process's /proc/net/tcp for identity binding.
    let entrypoint_pid = Arc::new(AtomicU32::new(0));

    // Construct the selected client only after shared policy and credential
    // setup has completed. Keep live credentials and later CA publication in
    // supervisor-owned handles shared with the backend.
    let admitted_backend_name = selected_backend.backend_name().to_string();
    let ca_file_paths = Arc::new(std::sync::Mutex::new(None));
    let bound = selected_backend
        .attach(
            backend_setup::BackendServices {
                ca_file_paths: ca_file_paths.clone(),
                provider_credentials: provider_credentials.clone(),
                sandbox_bearer,
            },
            policy.clone(),
            openshell_isolation_interface::AgentSpec {
                program,
                args,
                workdir: workspace,
                timeout_secs,
                interactive,
            },
        )
        .instrument(tracing::info_span!(parent: &startup, "supervisor.boundary.attach"))
        .await?;
    info!(backend = %admitted_backend_name, "Isolation boundary attached");
    let remote_boundary = (bound, admitted_backend_name, ca_file_paths);

    let transparent_tcp_capable = true;
    let transparent_tcp_substrate_ready = true;
    // The denial channel is owned by the orchestrator: the proxy (in the
    // networking leaf) and the bypass monitor (in the process leaf) both
    // produce DenialEvents that the denial aggregator (orchestrator-side)
    // consumes via the matching receiver. Both leaves are pure producers;
    // the orchestrator owns the consumer task spawned below.
    let (denial_tx, denial_rx): (Option<UnboundedSender<DenialEvent>>, _) = if sandbox_id.is_some()
    {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Anonymous activity channel: same orchestrator-owned pattern as the
    // denial channel. The proxy and the bypass monitor both emit per-event
    // activity records; the orchestrator-side aggregator drains, sanitizes,
    // and flushes anonymous summaries to the gateway.
    let (activity_tx, activity_rx) = if sandbox_id.is_some() {
        let (tx, rx) =
            tokio::sync::mpsc::channel(openshell_core::activity::ACTIVITY_EVENT_QUEUE_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Endpoint observations are bounded and never backpressure proxied traffic.
    // Reports are authorized by the currently accepted supervisor session.
    let (endpoint_observation_tx, endpoint_status_rx) = if sandbox_id.is_some() {
        let (sender, receiver) = openshell_core::endpoint_status::endpoint_status_channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let (supervisor_session_updates, supervisor_session_id) =
        tokio::sync::watch::channel::<Option<String>>(None);
    if let (
        Some(sender),
        Some(proto),
        LoadedPolicyOrigin::Gateway {
            revision: Some(revision),
            ..
        },
    ) = (
        endpoint_observation_tx.as_ref(),
        retained_proto.as_ref(),
        &loaded_policy_origin,
    ) {
        endpoint_status::reset(
            Some(sender),
            Some(proto),
            &revision.policy_hash,
            provider_credentials.snapshot().revision,
        )
        .await;
    }

    // Workspace watch: the policy poll loop learns the workspace from
    // GetSandboxConfig and broadcasts it. Flush tasks and the policy.local
    // API read the current value so proposals target the correct workspace.
    let (workspace_tx, workspace_rx) = tokio::sync::watch::channel(String::new());
    let (config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(16);
    let mut config_apply_rx = Some(config_apply_rx);
    let (config_apply_updates, config_apply_enabled) = tokio::sync::watch::channel(true);

    let remote_network_source = remote_boundary.0.network_mediation_source();
    let remote_host_gateway_ip = remote_boundary.0.host_gateway_ip();
    let (remote_ready, backend_name, ca_file_paths) = {
        let (bound, backend_name, ca_file_paths) = remote_boundary;
        let ready = bound
            .confirm()
            .instrument(tracing::info_span!(parent: &startup, "supervisor.boundary.confirm"))
            .await
            .map_err(|error| miette::miette!(error.to_string()))?;
        info!(backend = %backend_name, "Isolation boundary enforcement confirmed");
        (ready, backend_name, ca_file_paths)
    };

    let mut networking = Some(
        openshell_supervisor_network::run::run_networking(
            &policy,
            None,
            opa_engine.as_ref(),
            retained_proto.as_ref(),
            entrypoint_pid.clone(),
            // The sandbox supplies already-resolved identities across the
            // boundary. The host supervisor cannot inspect its mount or PID
            // namespace, so waiting for a host-visible entrypoint PID would
            // unnecessarily delay DNS and network readiness.
            false,
            &provider_credentials,
            sandbox_id.as_deref(),
            sandbox_name_for_agg.as_deref(),
            openshell_endpoint_for_proxy.as_deref(),
            denial_tx,
            activity_tx,
            endpoint_observation_tx.clone(),
            agent_proposals.clone(),
            workspace_rx.clone(),
            &upstream_proxy_args,
            None,
            remote_host_gateway_ip,
            #[cfg(target_os = "linux")]
            None,
            Some(remote_network_source),
        )
        .await?,
    );

    ca_file_paths
        .lock()
        .map_err(|_| miette::miette!("boundary CA path lock is poisoned"))?
        .clone_from(
            &networking
                .as_ref()
                .and_then(|runtime| runtime.ca_file_paths.clone()),
        );
    let remote_ready = (remote_ready, backend_name);

    // Spawn the denial-aggregator flush task. The aggregator drains proxy
    // denial events, batches them, and ships summaries to the gateway via
    // `SubmitPolicyAnalysis`.
    if let (Some(rx), Some(endpoint)) = (denial_rx, openshell_endpoint_for_proxy.as_deref()) {
        // SubmitPolicyAnalysis resolves by sandbox *name*, not UUID — fall
        // back to the ID when the name isn't set.
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs: u64 = std::env::var("OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let aggregator = denial_aggregator::DenialAggregator::new(rx, flush_interval_secs);
        let denial_workspace_gate = workspace_rx.clone();
        let denial_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    |summaries| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = denial_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_proposals_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summaries,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush denial summaries to gateway");
                            }
                        }
                    },
                    move || !denial_workspace_gate.borrow().is_empty(),
                )
                .await;
        });
    }

    // Spawn the activity-aggregator flush task. The aggregator drains
    // anonymous activity events from the proxy, sanitizes deny groups,
    // and ships periodic summaries to the gateway.
    if let (Some(rx), Some(endpoint)) = (activity_rx, openshell_endpoint_for_proxy.as_deref()) {
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs = activity_aggregator::activity_flush_interval_secs_from_env(
            std::env::var("OPENSHELL_ACTIVITY_FLUSH_INTERVAL_SECS")
                .ok()
                .as_deref(),
        );

        let aggregator = activity_aggregator::ActivityAggregator::new(rx, flush_interval_secs);
        let activity_workspace_gate = workspace_rx.clone();
        let activity_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    move |summary| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = activity_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_activity_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summary,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush activity summary to gateway");
                            }
                        }
                    },
                    move || !activity_workspace_gate.borrow().is_empty(),
                )
                .await;
        });
    }

    // Spawn background policy poll task (gRPC mode only).
    if let (Some(id), Some(sandbox), Some(endpoint), Some(engine)) = (
        sandbox_id.as_deref(),
        sandbox.as_deref(),
        openshell_endpoint.as_deref(),
        opa_engine.as_ref(),
    ) {
        let poll_id = id.to_string();
        let poll_sandbox = sandbox.to_string();
        let poll_endpoint = endpoint.to_string();
        let poll_engine = engine.clone();
        let poll_ocsf_enabled = ocsf_enabled.clone();
        let poll_ocsf_schema_version = ocsf_schema_version.clone();
        let poll_pid = entrypoint_pid.clone();
        let poll_provider_credentials = provider_credentials.clone();
        let poll_policy_local = networking.as_ref().map(|n| n.policy_local_ctx.clone());
        let initial_stream_configuration_admitted = initial_stream_snapshot
            .as_ref()
            .is_none_or(|snapshot| snapshot.configuration_admitted);
        let poll_endpoint_policy = (loaded_policy_origin.allows_gateway_policy_reload()
            && initial_stream_configuration_admitted)
            .then(|| retained_proto.clone())
            .flatten();
        let poll_interval_secs: u64 = std::env::var("OPENSHELL_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let poll_ctx = PolicyPollLoopContext {
            endpoint: poll_endpoint,
            sandbox_id: poll_id,
            sandbox: poll_sandbox,
            opa_engine: poll_engine,
            loaded_policy_origin,
            vm_identity: vm_policy_identity,
            entrypoint_pid: poll_pid,
            interval_secs: poll_interval_secs,
            ocsf_enabled: poll_ocsf_enabled,
            ocsf_schema_version: poll_ocsf_schema_version,
            provider_credentials: poll_provider_credentials,
            provider_readiness: provider_readiness.clone(),
            policy_local_ctx: poll_policy_local,
            agent_proposals: agent_proposals.clone(),
            middleware_registry_status,
            workspace_tx,
            extension_credentials: extension_credentials.clone(),
            extension_authentication_enabled: initial_extension_authentication_enabled,
            middleware_connector: default_middleware_connector(),
            transparent_tcp: TransparentTcpReloadState {
                capable: transparent_tcp_capable,
                substrate_ready: transparent_tcp_substrate_ready,
            },
            config_apply_rx: config_apply_rx.take(),
            initial_stream_snapshot,
            config_apply_enabled: Some(config_apply_enabled),
            endpoint_observation_tx,
            endpoint_status_rx,
            endpoint_policy: poll_endpoint_policy,
            supervisor_session_id: supervisor_session_id.clone(),
        };

        let wait_for_workload = !uses_stream_configuration;
        tokio::spawn(async move {
            let mut workload_started = workload_started_rx;
            if wait_for_workload && workload_started.wait_for(|started| *started).await.is_err() {
                return;
            }
            if let Err(e) = Box::pin(run_policy_poll_loop(poll_ctx)).await {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .message(format!("Policy poll loop exited with error: {e}"))
                        .build()
                );
            }
        });
    }

    let proxy_exited: Pin<Box<dyn Future<Output = ()> + Send>> = if let Some(rx) = networking
        .as_mut()
        .and_then(|n| n.proxy.as_mut())
        .and_then(ProxyHandle::take_exit_receiver)
    {
        Box::pin(async {
            let _ = rx.await;
        })
    } else {
        Box::pin(std::future::pending())
    };
    tokio::pin!(proxy_exited);

    // Report the stream-delivered bootstrap result while the boundary remains
    // confirmed but held. Docker and other admission-aware drivers do not
    // release the workload until the gateway accepts this result, so delaying
    // the stream until after `start_agent` would deadlock activation.
    let prestarted_supervisor_session = match prepared_supervisor_session.take() {
        Some(prepared) => Some(
            openshell_supervisor_process::delegated::start_prepared_supervisor_session(
                prepared,
                prepared_bootstrap_result.take(),
                ssh_socket_path.as_deref(),
                config_apply_tx.clone(),
                Some(supervisor_session_updates.clone()),
                config_apply_updates,
            )
            .await?,
        ),
        None => None,
    };

    let (confirmed, backend_name) = remote_ready;
    let exit_code = {
        let running = confirmed
            .into_boundary()
            .start_agent()
            .instrument(tracing::info_span!(parent: &startup, "supervisor.boundary.start_agent"))
            .await
            .map_err(|error| miette::miette!(error.to_string()))?;
        workload_started_tx.send_replace(true);
        info!(backend = %backend_name, "Isolation boundary agent started");
        let agent = running.agent();
        let boundary_access = openshell_supervisor_process::delegated::start_boundary_access(
            supervisor_instance_id,
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path.as_deref(),
            shared_ssh_socket_from_env(),
            networking
                .as_ref()
                .and_then(|runtime| runtime.ca_file_paths.clone()),
            running.exec(),
            running.loopback_connector(),
            agent.clone(),
            Some(supervisor_session_updates),
            prestarted_supervisor_session,
            config_apply_tx,
            ssh_host_key,
        )
        .instrument(tracing::info_span!(parent: &startup, "supervisor.access.start"))
        .await?;
        info!(backend = %backend_name, "Control-mode access plane started");
        startup_status.finish(Ok::<_, ()>(())).ok();
        drop(startup);
        let _provider_reporter =
            sandbox_id
                .as_ref()
                .zip(openshell_endpoint.as_ref())
                .map(|(id, endpoint)| {
                    provider_readiness.start_reporter(
                        endpoint.clone(),
                        id.clone(),
                        provider_credentials.clone(),
                        supervisor_session_id.clone(),
                        running.exec(),
                    )
                });
        let mut control_readiness = health_socket_path
            .map(ReadinessEndpoint::Unix)
            .into_iter()
            .chain(health_port.map(ReadinessEndpoint::Tcp))
            .map(|endpoint| ControlReadiness::start(endpoint, boundary_access.session_readiness()))
            .collect::<Result<Vec<_>>>()?;
        let instance_id = boundary_access.instance_id().to_string();
        let wait_agent = agent.clone();
        let shutdown_requested = wait_for_control_shutdown_signal();
        tokio::pin!(shutdown_requested);
        let wait = async move {
            wait_agent
                .wait()
                .await
                .map(|status| match status {
                    openshell_isolation_interface::contract::BoundaryExitStatus::Exited(code) => {
                        code
                    }
                    openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(
                        signal,
                    ) => 128_i32.saturating_add(signal),
                })
                .map_err(|error| miette::miette!(error.to_string()))
        };
        let (exit_code, mut retain_access) = tokio::select! {
            result = wait => (result?, true),
            () = &mut proxy_exited => {
                let _ = running.terminate().await;
                return Err(miette::miette!(
                    "control-mode proxy accept loop exited unexpectedly"
                ));
            }
            () = &mut shutdown_requested => {
                let _ = agent
                    .signal(openshell_isolation_interface::contract::BoundarySignal::Term)
                    .await;
                let status = if let Ok(result) = timeout(Duration::from_secs(5), agent.wait()).await {
                    result
                } else {
                    let _ = agent.terminate().await;
                    agent.wait().await
                }
                .map_err(|error| miette::miette!(error.to_string()))?;
                let exit_code = match status {
                    openshell_isolation_interface::contract::BoundaryExitStatus::Exited(code) => code,
                    openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(signal) => {
                        128_i32.saturating_add(signal)
                    }
                };
                running
                    .terminate()
                    .await
                    .map_err(|error| miette::miette!(
                        "sandbox did not acknowledge terminal state: {error}"
                    ))?;
                (exit_code, false)
            }
        };
        if !retain_access {
            control_readiness.clear();
        }
        boundary_access
            .publish_main_exit(exit_code, await_main_process_attachment)
            .await;
        // `shutdown_requested` has already completed when shutdown won the
        // lifecycle select above and must not be polled again.
        let mut completion_cancelled = !retain_access;
        if retain_access && let Some(marker) = main_exit_marker.as_deref() {
            persist_main_exit_marker(marker, exit_code)
                .into_diagnostic()
                .wrap_err("persist canonical-process completion marker")?;
        }
        if !completion_cancelled
            && let (Some(endpoint), Some(id)) =
                (openshell_endpoint.as_deref(), sandbox_id.as_deref())
        {
            let report = openshell_supervisor_process::delegated::report_main_process_exit(
                endpoint,
                id,
                &instance_id,
                exit_code,
            );
            completion_cancelled =
                completion_phase_or_shutdown(report, shutdown_requested.as_mut()).await;
        }
        if !completion_cancelled {
            let drain = boundary_access.drain_main_terminal_delivery();
            completion_cancelled =
                completion_phase_or_shutdown(drain, shutdown_requested.as_mut()).await;
        }
        if !completion_cancelled
            && let (Some(endpoint), Some(id)) =
                (openshell_endpoint.as_deref(), sandbox_id.as_deref())
        {
            let finalize = openshell_supervisor_process::delegated::finalize_main_process_exit(
                endpoint,
                id,
                &instance_id,
            );
            completion_cancelled =
                completion_phase_or_shutdown(finalize, shutdown_requested.as_mut()).await;
        }
        if completion_cancelled {
            retain_access = false;
            control_readiness.clear();
        }
        if retain_access {
            info!(backend = %backend_name, "Canonical process exited; retaining control-mode access plane");
            retain_remote_access_plane(&mut proxy_exited, &mut shutdown_requested).await?;
        }
        drop(control_readiness);
        drop(running);
        drop(boundary_access);
        exit_code
    };

    // Drop networking explicitly so proxy tasks tear down before we return.
    drop(networking);

    Ok(exit_code)
}

fn persist_main_exit_marker(path: &std::path::Path, exit_code: i32) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("completion marker has no parent: {}", path.display()),
            )
        })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("completion marker has no file name: {}", path.display()),
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    writeln!(file, "exit_code={exit_code}")?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(parent)?.sync_all()
}

/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    workspace: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

    let proto_summaries: Vec<DenialSummary> = summaries
        .into_iter()
        .map(|s| DenialSummary {
            sandbox_id: String::new(),
            host: s.host,
            port: u32::from(s.port),
            binary: s.binary,
            ancestors: s.ancestors,
            deny_reason: s.deny_reason,
            first_seen_time: openshell_core::time::timestamp_from_millis(s.first_seen_ms).ok(),
            last_seen_time: openshell_core::time::timestamp_from_millis(s.last_seen_ms).ok(),
            count: s.count,
            suppressed_count: 0,
            total_count: s.count,
            sample_cmdlines: s.sample_cmdlines,
            binary_sha256: String::new(),
            persistent: false,
            denial_stage: s.denial_stage,
            l7_request_samples: s
                .l7_samples
                .into_iter()
                .map(|l| L7RequestSample {
                    method: l.method,
                    path: l.path,
                    decision: "deny".to_string(),
                    count: l.count,
                })
                .collect(),
            l7_inspection_active: false,
        })
        .collect();

    // Run the mechanistic mapper sandbox-side to generate proposals.
    // The gateway is a thin persistence + validation layer — it never
    // generates proposals itself.
    let proposals = mechanistic_mapper::generate_proposals(&proto_summaries);

    info!(
        sandbox_name = %sandbox_name,
        summaries = proto_summaries.len(),
        proposals = proposals.len(),
        "Flushed denial analysis to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            proto_summaries,
            proposals,
            Vec::new(),
            "mechanistic",
        )
        .await?;

    Ok(())
}

/// Flush an anonymous activity summary to the gateway via `SubmitPolicyAnalysis`.
async fn flush_activity_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    workspace: &str,
    summary: activity_aggregator::FlushableActivitySummary,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialGroupCount, NetworkActivitySummary};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

    let proto_summary = NetworkActivitySummary {
        network_activity_count: summary.network_activity_count,
        denied_action_count: summary.denied_action_count,
        denials_by_group: summary
            .denials_by_group
            .into_iter()
            .map(|(group, count)| DenialGroupCount {
                deny_group: group,
                denied_count: count,
            })
            .collect(),
    };

    info!(
        sandbox_name = %sandbox_name,
        network_activity_count = proto_summary.network_activity_count,
        denied_action_count = proto_summary.denied_action_count,
        "Flushed activity summary to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            Vec::new(),
            Vec::new(),
            vec![proto_summary],
            "activity",
        )
        .await?;

    Ok(())
}

// ============================================================================
// Baseline filesystem path enrichment
// ============================================================================

/// Minimum read-only paths required for a proxy-mode sandbox child process to
/// function: dynamic linker, shared libraries, DNS resolution, CA certs,
/// Python venv, openshell logs, process info, and random bytes.
///
/// `/proc` and `/dev/urandom` are included here for the same reasons they
/// appear in `restrictive_default_policy()`: virtually every process needs
/// them.  Before the Landlock per-path fix (#677) these were effectively free
/// because a missing path silently disabled the entire ruleset; now they must
/// be explicit.
const PROXY_BASELINE_READ_ONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/etc",
    "/app",
    "/var/log",
    "/proc",
    "/dev/urandom",
];

/// Minimum read-write paths required for a proxy-mode sandbox child process.
/// The active workspace is granted separately through `include_workdir`.
// `/dev/null` is opened by common child-process launchers when they construct
// piped or discarded stdio. Without it, tools such as uv report EACCES while
// probing an otherwise executable interpreter under an explicit filesystem
// policy.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/tmp", "/dev/null"];

fn proxy_baseline_paths() -> (Vec<String>, Vec<String>) {
    (
        PROXY_BASELINE_READ_ONLY
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
        PROXY_BASELINE_READ_WRITE
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
    )
}

fn enrich_proto_baseline_paths_with<F>(
    proto: &mut openshell_core::proto::SandboxPolicy,
    ro: &[String],
    rw: &[String],
    path_exists: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    if ro.is_empty() && rw.is_empty() {
        return false;
    }

    let fs = proto
        .filesystem
        .get_or_insert_with(|| openshell_core::proto::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        });

    let mut modified = false;
    for path in ro {
        if !fs.read_only.iter().any(|p| p == path) && !fs.read_write.iter().any(|p| p == path) {
            if !path_exists(path) {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            fs.read_only.push(path.clone());
            modified = true;
        }
    }
    for path in rw {
        if fs.read_write.iter().any(|p| p == path) {
            continue;
        }
        if !path_exists(path) {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        if fs.read_only.iter().any(|p| p == path) {
            continue;
        }
        fs.read_write.push(path.clone());
        modified = true;
    }

    modified
}

/// Ensure a proto `SandboxPolicy` includes the baseline filesystem paths
/// required by proxy-mode sandboxes. Paths are only added if
/// missing; user-specified paths are never removed.
///
/// Returns `true` if the policy was modified (caller may want to sync back).
fn enrich_proto_baseline_paths(proto: &mut openshell_core::proto::SandboxPolicy) -> bool {
    if proto.network_policies.is_empty() {
        return false;
    }
    let (ro, rw) = proxy_baseline_paths();

    // Baseline paths are system-injected, not user-specified.  Skip paths
    // that do not exist in this container image to avoid noisy warnings from
    // Landlock and, more critically, to prevent a single missing baseline
    // path from abandoning the entire Landlock ruleset under best-effort
    // mode (see issue #664).
    let modified = enrich_proto_baseline_paths_with(proto, &ro, &rw, |path| {
        std::path::Path::new(path).exists()
    });

    if modified {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "enriched")
                .message("Enriched policy with baseline filesystem paths for proxy mode")
                .build()
        );
    }

    modified
}

fn strip_proto_provider_policy_entries(proto: &mut openshell_core::proto::SandboxPolicy) -> bool {
    openshell_policy::strip_provider_rule_names(proto)
}

fn proto_sync_payload_for_enriched_policy(
    proto: &openshell_core::proto::SandboxPolicy,
    enriched: bool,
) -> Option<openshell_core::proto::SandboxPolicy> {
    if !enriched {
        return None;
    }

    let mut sync_policy = proto.clone();
    strip_proto_provider_policy_entries(&mut sync_policy);
    Some(sync_policy)
}

/// Ensure a `SandboxPolicy` (Rust type) includes the baseline filesystem
/// paths required by proxy-mode sandboxes. Used for the
/// local-file code path where no proto is available.
fn enrich_sandbox_baseline_paths(policy: &mut SandboxPolicy) {
    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return;
    }
    let (ro, rw) = proxy_baseline_paths();

    let mut modified = false;
    for path in &ro {
        let p = std::path::PathBuf::from(path);
        if !policy.filesystem.read_only.contains(&p) && !policy.filesystem.read_write.contains(&p) {
            if !p.exists() {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            policy.filesystem.read_only.push(p);
            modified = true;
        }
    }
    for path in &rw {
        let p = std::path::PathBuf::from(path);
        if policy.filesystem.read_only.contains(&p) || policy.filesystem.read_write.contains(&p) {
            continue;
        }
        if !p.exists() {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        policy.filesystem.read_write.push(p);
        modified = true;
    }

    if modified {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "enriched")
                .message("Enriched policy with baseline filesystem paths for proxy mode")
                .build()
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod baseline_tests {
    use super::*;
    use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};
    use std::path::PathBuf;

    #[test]
    fn proxy_baseline_keeps_proc_read_only_on_every_host() {
        let (ro, rw) = proxy_baseline_paths();
        assert!(ro.contains(&"/proc".to_string()));
        assert!(!rw.contains(&"/proc".to_string()));
    }

    #[test]
    fn baseline_read_write_does_not_hardcode_sandbox() {
        let (_ro, rw) = proxy_baseline_paths();
        assert!(rw.contains(&"/tmp".to_string()));
        assert!(rw.contains(&"/dev/null".to_string()));
        assert!(!rw.contains(&"/sandbox".to_string()));
    }

    #[test]
    fn no_duplicate_paths_in_baseline() {
        let (ro, rw) = proxy_baseline_paths();
        // No path should appear in both lists.
        for path in &ro {
            assert!(
                !rw.contains(path),
                "path {path} appears in both read_only and read_write"
            );
        }
    }

    #[test]
    fn proto_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.filesystem = Some(openshell_core::proto::FilesystemPolicy {
            read_only: vec!["/tmp".to_string(), "/proc".to_string()],
            read_write: vec![],
            include_workdir: false,
        });
        policy.network_policies.insert(
            "test".into(),
            openshell_core::proto::NetworkPolicyRule {
                name: "test-rule".into(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        enrich_proto_baseline_paths(&mut policy);

        let filesystem = policy.filesystem.expect("filesystem policy");
        assert!(filesystem.read_only.contains(&"/proc".to_string()));
        assert!(!filesystem.read_write.contains(&"/proc".to_string()));
        assert!(
            filesystem.read_only.contains(&"/tmp".to_string()),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !filesystem.read_write.contains(&"/tmp".to_string()),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }

    #[test]
    fn proto_strip_provider_policy_entries_removes_only_reserved_entries() {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );
        policy.network_policies.insert(
            "sandbox_only".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "sandbox_only".to_string(),
                ..Default::default()
            },
        );

        assert!(strip_proto_provider_policy_entries(&mut policy));
        assert!(
            !policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(policy.network_policies.contains_key("sandbox_only"));
        assert!(!strip_proto_provider_policy_entries(&mut policy));
    }

    #[test]
    fn proto_sync_payload_not_created_for_provider_entries_without_enrichment() {
        let mut runtime_policy = openshell_policy::restrictive_default_policy();
        runtime_policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );

        assert!(proto_sync_payload_for_enriched_policy(&runtime_policy, false).is_none());
        assert!(
            runtime_policy
                .network_policies
                .contains_key("_provider_work_github"),
            "provider-derived rules alone must not trigger sync or mutate runtime policy"
        );
    }

    #[test]
    fn proto_sync_payload_for_enrichment_strips_provider_entries_without_mutating_runtime_policy() {
        let mut runtime_policy = openshell_policy::restrictive_default_policy();
        runtime_policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );
        runtime_policy.network_policies.insert(
            "sandbox_only".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "sandbox_only".to_string(),
                ..Default::default()
            },
        );

        let sync_policy = proto_sync_payload_for_enriched_policy(&runtime_policy, true)
            .expect("enrichment should create a sync payload");

        assert!(
            runtime_policy
                .network_policies
                .contains_key("_provider_work_github"),
            "runtime policy must retain provider-derived rules for OPA input"
        );
        assert!(
            !sync_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(sync_policy.network_policies.contains_key("sandbox_only"));
    }

    #[test]
    fn no_network_policy_is_unchanged_by_supervisor_baseline() {
        // A CPU-only workload must start with this policy even when the
        // supervisor's host has GPUs. No GPU hardware is needed by this test.
        let mut policy = openshell_policy::restrictive_default_policy();
        assert!(policy.network_policies.is_empty());
        assert!(
            policy
                .filesystem
                .as_ref()
                .unwrap()
                .read_only
                .contains(&"/proc".to_string())
        );
        let original = policy.clone();

        let enriched = enrich_proto_baseline_paths(&mut policy);

        assert!(!enriched);
        assert_eq!(policy, original);
        assert!(proto_sync_payload_for_enriched_policy(&policy, enriched).is_none());
    }

    #[test]
    fn local_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![PathBuf::from("/tmp")],
                read_write: vec![],
                include_workdir: false,
            },
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        };

        enrich_sandbox_baseline_paths(&mut policy);

        assert!(
            policy.filesystem.read_only.contains(&PathBuf::from("/tmp")),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !policy
                .filesystem
                .read_write
                .contains(&PathBuf::from("/tmp")),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }
}

/// Returns `true` if the error is transient and worth retrying.
///
/// Walks the `miette::Report` error chain looking for a `tonic::Status`. If
/// found, only the gRPC codes that represent transient failures are retryable.
/// If no `tonic::Status` is present (e.g. a raw connection error), assume the
/// failure is transient.
fn is_retryable_error(err: &miette::Report) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(err.as_ref());
    while let Some(e) = source {
        if let Some(status) = e.downcast_ref::<tonic::Status>() {
            return matches!(
                status.code(),
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::Aborted
                    | tonic::Code::Internal
                    | tonic::Code::Unknown
            );
        }
        source = e.source();
    }
    true
}

/// Bound the complete attempt, including connection setup and a pending unary
/// response. Dropping a timed-out future prevents it from stalling startup.
async fn grpc_attempt<T>(op_name: &str, operation: impl Future<Output = Result<T>>) -> Result<T> {
    timeout(Duration::from_secs(10), operation)
        .await
        .map_err(|_| {
            openshell_core::grpc_client::grpc_status_error(tonic::Status::deadline_exceeded(
                format!("{op_name} timed out after 10 seconds"),
            ))
        })?
}

/// Retry a gRPC operation with exponential backoff (capped at 4 s).
///
/// Non-transient gRPC errors (e.g. `NOT_FOUND`, `INVALID_ARGUMENT`,
/// `PERMISSION_DENIED`) are returned immediately without retrying.
async fn grpc_retry<T, F, Fut>(op_name: &str, f: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err = None;
    for attempt in 1..=5u32 {
        match grpc_attempt(op_name, f()).await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if !is_retryable_error(&e) {
                    return Err(e);
                }
                if attempt < 5 {
                    warn!(
                        attempt,
                        max_attempts = 5,
                        error = %e,
                        "{op_name} failed, retrying"
                    );
                    let backoff = Duration::from_secs((1u64 << (attempt - 1)).min(4));
                    tokio::time::sleep(backoff).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(miette::miette!(
        "{op_name} failed after 5 attempts: {}",
        last_err.expect("loop executed at least once")
    ))
}

#[tonic::async_trait]
trait StartupGateway: Send + Sync {
    async fn snapshot(
        &self,
        sandbox: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult>;
    async fn provider(
        &self,
        id: &str,
    ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult>;
    async fn sync(
        &self,
        sandbox: &str,
        policy: &openshell_core::proto::SandboxPolicy,
        workspace: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult>;
    async fn report(
        &self,
        id: &str,
        instance_id: &str,
        snapshot: Option<&openshell_core::grpc_client::SettingsPollResult>,
        state: openshell_core::proto::ConfigurationAdmissionState,
        error: &str,
    ) -> Result<()>;
}

struct RemoteStartupGateway {
    endpoint: String,
}

#[tonic::async_trait]
impl StartupGateway for RemoteStartupGateway {
    async fn snapshot(
        &self,
        sandbox: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
        openshell_core::grpc_client::fetch_settings_snapshot(&self.endpoint, sandbox).await
    }
    async fn provider(
        &self,
        id: &str,
    ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
        openshell_core::grpc_client::fetch_provider_environment(&self.endpoint, id).await
    }
    async fn sync(
        &self,
        sandbox: &str,
        policy: &openshell_core::proto::SandboxPolicy,
        workspace: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
        openshell_core::grpc_client::sync_policy_and_fetch_snapshot(
            &self.endpoint,
            sandbox,
            policy,
            workspace,
        )
        .await
    }
    async fn report(
        &self,
        id: &str,
        instance_id: &str,
        snapshot: Option<&openshell_core::grpc_client::SettingsPollResult>,
        state: openshell_core::proto::ConfigurationAdmissionState,
        error: &str,
    ) -> Result<()> {
        openshell_core::grpc_client::report_sandbox_configuration(
            &self.endpoint,
            id,
            instance_id,
            snapshot,
            state,
            error,
        )
        .await
    }
}

/// Load sandbox policy from local files or gRPC.
///
/// Priority:
/// 1. If `policy_rules` and `policy_data` are provided, load OPA engine from local files
/// 2. If `sandbox_id` and `openshell_endpoint` are provided, fetch via gRPC
/// 3. If the server returns no policy, discover from disk or use restrictive default
/// 4. Otherwise, return an error
///
/// Returns the policy, the OPA engine, and (for gRPC mode) the original proto
/// policy. The proto is retained so the OPA engine can be rebuilt with symlink
/// resolution after the container entrypoint starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalPolicyIdentity {
    Required,
    EndpointOnly,
}

/// The VM driver fixes overlay ownership before this supervisor starts. Guest
/// init maps the `sandbox` account to this pair; the host must not resolve
/// guest selectors through its own account database.
#[derive(Clone, Copy)]
struct VmPolicyIdentity {
    uid: u32,
    gid: u32,
}

impl VmPolicyIdentity {
    fn validate(self, policy: &openshell_core::proto::SandboxPolicy) -> Result<()> {
        let Some(process) = policy.process.as_ref() else {
            return Ok(());
        };
        for (field, selector, expected) in [
            ("run_as_user", process.run_as_user.as_str(), self.uid),
            ("run_as_group", process.run_as_group.as_str(), self.gid),
        ] {
            if !selector.is_empty()
                && selector != "sandbox"
                && selector.parse::<u32>() != Ok(expected)
            {
                return Err(miette::miette!(
                    "VM {field} '{selector}' conflicts with the resolved workload identity {}:{}; omit the selector or request the driver-owned identity",
                    self.uid,
                    self.gid
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CapturedProviderEnvironment {
    credentials: ProviderCredentialState,
    expires_at_ms: Option<i64>,
    identity: EnvironmentIdentity,
}

impl CapturedProviderEnvironment {
    fn install(self, readiness: &ProviderReadinessTracker) -> ProviderCredentialState {
        readiness.credentials_installed(self.identity, &self.credentials, self.expires_at_ms);
        self.credentials
    }

    /// Validate the environment's bindings without touching live credentials.
    fn prepare(provider: &openshell_core::grpc_client::ProviderEnvironmentResult) -> Result<Self> {
        prepare_provider_environment(provider).map(|credentials| Self::new(credentials, provider))
    }

    fn new(
        credentials: ProviderCredentialState,
        provider: &openshell_core::grpc_client::ProviderEnvironmentResult,
    ) -> Self {
        Self {
            credentials,
            expires_at_ms: provider
                .credential_expires_at_ms
                .values()
                .copied()
                .filter(|expiry| *expiry > 0)
                .min(),
            identity: EnvironmentIdentity::from_environment(provider),
        }
    }
}

async fn load_policy(
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
    local_policy_identity: LocalPolicyIdentity,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
    MiddlewareRegistryStatus,
    LoadedPolicyOrigin,
    bool,
    bool,
    Option<CapturedProviderEnvironment>,
)> {
    load_policy_with_gateway(
        sandbox_id,
        sandbox,
        openshell_endpoint.clone(),
        policy_rules,
        policy_data,
        extension_credentials,
        local_policy_identity,
        None,
        None,
        None,
        &RemoteStartupGateway {
            endpoint: openshell_endpoint.unwrap_or_default(),
        },
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "Startup gateway injection preserves the production policy-loading inputs"
)]
async fn load_policy_with_gateway(
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
    local_policy_identity: LocalPolicyIdentity,
    vm_identity: Option<VmPolicyIdentity>,
    image_discovery: Option<ImagePolicyDiscovery>,
    initial_snapshot: Option<openshell_core::grpc_client::SettingsPollResult>,
    gateway: &impl StartupGateway,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
    MiddlewareRegistryStatus,
    LoadedPolicyOrigin,
    bool,
    bool,
    Option<CapturedProviderEnvironment>,
)> {
    use openshell_core::proto::ConfigurationAdmissionState;
    // File mode: load OPA engine from rego rules + YAML data (dev override)
    if let (Some(policy_file), Some(data_file)) = (&policy_rules, &policy_data) {
        if sandbox_id.is_some() && openshell_endpoint.is_some() {
            return Err(miette::miette!(
                "Local policy overrides cannot be combined with gateway-managed activation; replace the sandbox policy through the gateway"
            ));
        }
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "loading")
            .unmapped("policy_rules", serde_json::json!(policy_file))
            .unmapped("policy_data", serde_json::json!(data_file))
            .message(format!(
                "Loading OPA policy engine from local files [rules:{policy_file} data:{data_file}]"
            ))
            .build());
        let validate_middleware_config = |implementation: &str, config: &prost_types::Struct| {
            openshell_supervisor_middleware_builtins::validate_config(implementation, config)
                .map_err(|error| error.to_string())
        };
        let policy_path = std::path::Path::new(policy_file);
        let data_path = std::path::Path::new(data_file);
        let engine = match local_policy_identity {
            LocalPolicyIdentity::Required => OpaEngine::from_files_with_middleware_config(
                policy_path,
                data_path,
                Some(&validate_middleware_config),
            )?,
            LocalPolicyIdentity::EndpointOnly => OpaEngine::from_files_for_endpoint_only_proxy(
                policy_path,
                data_path,
                Some(&validate_middleware_config),
            )?,
        };
        let middleware_registry =
            openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
                openshell_supervisor_middleware_builtins::services(),
                Vec::new(),
            )
            .await?;
        engine.replace_middleware_registry(middleware_registry)?;
        let config = engine.query_sandbox_config()?;
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: config.filesystem,
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: config.landlock,
            process: config.process,
        };
        enrich_sandbox_baseline_paths(&mut policy);
        // File mode has no operator-registered middleware to connect.
        return Ok((
            policy,
            Some(Arc::new(engine)),
            None,
            MiddlewareRegistryStatus::Synchronized,
            LoadedPolicyOrigin::LocalOverride,
            false,
            false,
            None,
        ));
    }

    // Stream mode: the gateway enabled authoritative streamed configuration
    // and already prepared and admitted this bootstrap for the session.
    if let (Some(id), Some(endpoint), Some(snapshot)) =
        (&sandbox_id, &openshell_endpoint, initial_snapshot)
    {
        return Box::pin(load_stream_bootstrap_policy(
            id,
            endpoint,
            snapshot,
            extension_credentials,
            vm_identity,
        ))
        .await;
    }

    // gRPC mode: fetch typed proto policy, construct OPA engine from baked rules + proto data
    if let (Some(id), Some(sandbox), Some(endpoint)) = (&sandbox_id, &sandbox, &openshell_endpoint)
    {
        info!(
            sandbox_id = %id,
            sandbox = %sandbox,
            endpoint = %endpoint,
            "Fetching sandbox policy via gRPC"
        );
        let instance_id = uuid::Uuid::new_v4().to_string();
        // Capture the previous instance once. Registration retries must never
        // rebase this fence and displace a newer supervisor instance.
        let registration_snapshot =
            grpc_retry("Startup configuration fetch", || gateway.snapshot(sandbox)).await?;
        grpc_retry("Supervisor registration", || {
            gateway.report(
                id,
                &instance_id,
                Some(&registration_snapshot),
                ConfigurationAdmissionState::Pending,
                "",
            )
        })
        .await?;
        let discovery = image_discovery.unwrap_or_else(discover_image_policy);
        let mut reconciliation_attempts = 0u32;
        let mut rejection_log = StartupRejectionLog::default();
        loop {
            if reconciliation_attempts == 5 {
                return Err(miette::miette!(
                    "Startup configuration did not stabilize after 5 attempts"
                ));
            }
            reconciliation_attempts += 1;
            let mut snapshot =
                grpc_retry("Startup configuration fetch", || gateway.snapshot(sandbox)).await?;

            if snapshot.policy.is_none() && !snapshot.configuration_error.is_empty() {
                reject_startup_configuration(
                    gateway,
                    &mut rejection_log,
                    id,
                    &instance_id,
                    &snapshot,
                    &snapshot.configuration_error,
                    None,
                )
                .await?;
                reconciliation_attempts = 0;
                continue;
            }

            let mut proto_policy = if let Some(p) = snapshot.policy.clone() {
                p
            } else {
                // No policy configured on the server. Discover from disk or
                // fall back to the restrictive default, then sync to the
                // gateway so it becomes the authoritative baseline.
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Other, "discovery")
                        .message("Server returned no policy; attempting local discovery")
                        .build()
                );
                let mut discovered = match &discovery {
                    ImagePolicyDiscovery::Policy(policy) => *policy.clone(),
                    ImagePolicyDiscovery::Missing => openshell_policy::restrictive_default_policy(),
                    ImagePolicyDiscovery::Invalid => {
                        reject_startup_configuration(gateway, &mut rejection_log, id, &instance_id, &snapshot, "Image policy is invalid; replace the sandbox policy to repair configuration", None).await?;
                        reconciliation_attempts = 0;
                        continue;
                    }
                };
                // Enrich before syncing so the gateway baseline includes
                // baseline paths from the start.
                enrich_proto_baseline_paths(&mut discovered);
                strip_proto_provider_policy_entries(&mut discovered);
                // Sync and re-fetch over a single connection to avoid extra
                // TLS handshakes.
                let ws = snapshot.workspace.clone();
                let synced = grpc_retry("Image policy synchronization", || {
                    gateway.sync(sandbox, &discovered, &ws)
                })
                .await;
                snapshot = match synced {
                    Ok(synced) => synced,
                    Err(error) => {
                        // The gateway stored nothing, so report the rejection
                        // against the snapshot this upload was built from and
                        // upload again on the next pass. Attaching the missing
                        // provider or setting a sandbox policy repairs startup.
                        let rejection =
                            startup_write_rejection("image policy", &error).ok_or(error)?;
                        reject_startup_configuration(
                            gateway,
                            &mut rejection_log,
                            id,
                            &instance_id,
                            &snapshot,
                            &rejection.diagnostic,
                            Some(&rejection.log_key),
                        )
                        .await?;
                        reconciliation_attempts = 0;
                        continue;
                    }
                };
                if let Some(policy) = snapshot.policy.clone() {
                    policy
                } else {
                    if snapshot.configuration_error.is_empty() {
                        return Err(miette::miette!(
                            "Gateway returned no effective policy after image discovery"
                        ));
                    }
                    reject_startup_configuration(
                        gateway,
                        &mut rejection_log,
                        id,
                        &instance_id,
                        &snapshot,
                        "Effective policy is unavailable after image discovery",
                        None,
                    )
                    .await?;
                    reconciliation_attempts = 0;
                    continue;
                }
            };

            // Ensure baseline filesystem paths are present for proxy-mode
            // sandboxes.  If the policy was enriched, sync the updated version
            // back to the gateway so users can see the effective policy. Only
            // a sandbox-sourced policy is written back. The gateway refuses
            // every sandbox policy write while a global policy is active, so a
            // global policy keeps the added paths in this process only.
            let enriched = enrich_proto_baseline_paths(&mut proto_policy);
            let sync_policy = proto_sync_payload_for_enriched_policy(&proto_policy, enriched)
                .filter(|_| snapshot.policy_source == openshell_core::proto::PolicySource::Sandbox);
            if let Some(sync_policy) = sync_policy {
                let synced = grpc_retry("Enriched policy synchronization", || {
                    gateway.sync(sandbox, &sync_policy, &snapshot.workspace)
                })
                .await;
                let canonical = match synced {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        // The stored policy is unchanged, so report the
                        // rejection against the snapshot it was read from and
                        // read again on the next pass, which picks up a
                        // replacement policy or a provider repair.
                        let rejection = startup_write_rejection(
                            "policy update that adds baseline filesystem paths",
                            &error,
                        )
                        .ok_or(error)?;
                        reject_startup_configuration(
                            gateway,
                            &mut rejection_log,
                            id,
                            &instance_id,
                            &snapshot,
                            &rejection.diagnostic,
                            Some(&rejection.log_key),
                        )
                        .await?;
                        reconciliation_attempts = 0;
                        continue;
                    }
                };
                proto_policy = canonical.policy.clone().ok_or_else(|| {
                    miette::miette!("Gateway returned no effective policy after enrichment")
                })?;
                snapshot = canonical;
            }

            let loaded_policy_revision = Some({
                let mut revision = LoadedPolicyRevision::from_snapshot(&snapshot);
                revision.admission_instance_id = Some(instance_id.clone());
                revision
            });

            // Build OPA engine from baked-in rules + typed proto data.
            // In cluster mode, proxy networking is always enabled so OPA is
            // always required for allow/deny decisions.
            // The initial load uses pid=0 (no symlink resolution) because the
            // container hasn't started yet. After the entrypoint spawns, the
            // engine is rebuilt with the real PID for symlink resolution.
            let has_last_valid_policy = true;
            if !snapshot.configuration_admitted {
                reject_startup_configuration(
                    gateway,
                    &mut rejection_log,
                    id,
                    &instance_id,
                    &snapshot,
                    if snapshot.configuration_error.is_empty() {
                        "Effective configuration was rejected by admission"
                    } else {
                        &snapshot.configuration_error
                    },
                    None,
                )
                .await?;
                reconciliation_attempts = 0;
                continue;
            }
            // Admission must reject incompatible image-discovered or repaired
            // selectors before reporting this policy effective.
            if let Some(identity) = vm_identity
                && let Err(error) = identity.validate(&proto_policy)
            {
                reject_startup_configuration(
                    gateway,
                    &mut rejection_log,
                    id,
                    &instance_id,
                    &snapshot,
                    &error.to_string(),
                    None,
                )
                .await?;
                reconciliation_attempts = 0;
                continue;
            }
            let provider =
                grpc_retry("Startup provider environment", || gateway.provider(id)).await?;
            if provider.provider_env_revision != snapshot.provider_env_revision {
                tokio::time::sleep(Duration::from_secs(1u64 << reconciliation_attempts.min(2)))
                    .await;
                continue;
            }
            debug!("Creating OPA engine from proto policy data");
            let (engine, policy, captured_provider_credentials) =
                match prepare_startup_configuration(&snapshot, &proto_policy, &provider) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        report_initial_policy_failure(
                            endpoint,
                            id,
                            loaded_policy_revision.as_ref(),
                            &error,
                        )
                        .await;
                        reject_startup_configuration(
                            gateway,
                            &mut rejection_log,
                            id,
                            &instance_id,
                            &snapshot,
                            "Policy or provider environment failed runtime validation",
                            None,
                        )
                        .await?;
                        reconciliation_attempts = 0;
                        continue;
                    }
                };
            let engine = Arc::new(engine);

            let middleware_registry_status = connect_startup_middleware(
                &engine,
                endpoint,
                &snapshot.supervisor_middleware_services,
                snapshot.extension_authentication_enabled,
                extension_credentials,
            )
            .await?;
            let opa_engine = Some(engine);

            // The gateway compares the entire tuple again. A concurrent repair or
            // provider rotation invalidates this candidate before any workload
            // identity, child environment or services are captured.
            if let Err(error) = grpc_attempt(
                "Startup acceptance report",
                gateway.report(
                    id,
                    &instance_id,
                    Some(&snapshot),
                    ConfigurationAdmissionState::Accepted,
                    "",
                ),
            )
            .await
            {
                if !is_retryable_error(&error) {
                    return Err(error);
                }
                tokio::time::sleep(Duration::from_secs(1u64 << reconciliation_attempts.min(2)))
                    .await;
                continue;
            }
            if rejection_log.0.is_some() {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Other, "configuration_recovered")
                        .message("Startup configuration repaired and accepted")
                        .build()
                );
            }
            return Ok((
                policy,
                opa_engine,
                Some(proto_policy),
                middleware_registry_status,
                LoadedPolicyOrigin::Gateway {
                    revision: loaded_policy_revision,
                    has_last_valid_policy,
                },
                agent_proposals_enabled_from_settings(&snapshot.settings),
                snapshot.extension_authentication_enabled,
                Some(CapturedProviderEnvironment::new(
                    captured_provider_credentials,
                    &provider,
                )),
            ));
        }
    }

    // No policy source available
    Err(miette::miette!(
        "Sandbox policy required. Provide one of:\n\
         - --policy-rules and --policy-data (or OPENSHELL_POLICY_RULES and OPENSHELL_POLICY_DATA env vars)\n\
         - --sandbox-id, --sandbox, and --openshell-endpoint (or OPENSHELL_SANDBOX_ID, OPENSHELL_SANDBOX, and OPENSHELL_ENDPOINT env vars)"
    ))
}

/// Install the gateway-prepared bootstrap delivered on the supervisor stream.
///
/// The gateway prepared the startup policy against this image and admitted the
/// generation before sending it, so this never writes policy back or retries
/// admission. A rejected generation starts fail-closed and is reported through
/// the bootstrap result.
async fn load_stream_bootstrap_policy(
    id: &str,
    endpoint: &str,
    snapshot: openshell_core::grpc_client::SettingsPollResult,
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
    vm_identity: Option<VmPolicyIdentity>,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
    MiddlewareRegistryStatus,
    LoadedPolicyOrigin,
    bool,
    bool,
    Option<CapturedProviderEnvironment>,
)> {
    info!(sandbox_id = %id, "Loading sandbox policy from supervisor bootstrap");
    let mut proto_policy = snapshot
        .policy
        .clone()
        .ok_or_else(|| miette::miette!("supervisor bootstrap omitted required sandbox policy"))?;

    // The startup candidate already carried baseline paths for a sandbox
    // policy. A global policy cannot be written back, so it keeps the added
    // paths in this process only, matching polling startup.
    let enriched = enrich_proto_baseline_paths(&mut proto_policy);
    if proto_sync_payload_for_enriched_policy(&proto_policy, enriched).is_some()
        && snapshot.policy_source == openshell_core::proto::PolicySource::Sandbox
    {
        return Err(miette::miette!(
            "supervisor bootstrap policy omitted required baseline paths"
        ));
    }

    let configuration_rejected = !snapshot.configuration_admitted;
    let loaded_policy_revision = Some(LoadedPolicyRevision::from_snapshot(&snapshot));
    if configuration_rejected {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::High)
                .status(StatusId::Failure)
                .state(StateId::Other, "configuration_error")
                .message(snapshot.configuration_error.clone())
                .build()
        );
        proto_policy = openshell_policy::restrictive_default_policy();
    } else if let Some(identity) = vm_identity {
        identity
            .validate(&proto_policy)
            .wrap_err("supervisor bootstrap policy conflicts with the VM workload identity")?;
    }

    // The initial load uses pid=0 (no symlink resolution) because the
    // container hasn't started yet. After the entrypoint spawns, the engine is
    // rebuilt with the real PID for symlink resolution.
    if !configuration_rejected {
        info!("Creating OPA engine from proto policy data");
    }
    let has_last_valid_policy = !configuration_rejected;
    let engine = Arc::new(
        OpaEngine::from_proto(&proto_policy)
            .wrap_err("failed to install required sandbox policy from supervisor bootstrap")?,
    );

    let extension_authentication_enabled =
        snapshot.extension_authentication_enabled && !configuration_rejected;
    let middleware_services: &[_] = if configuration_rejected {
        &[]
    } else {
        &snapshot.supervisor_middleware_services
    };
    let middleware_registry_status = connect_startup_middleware(
        &engine,
        endpoint,
        middleware_services,
        extension_authentication_enabled,
        extension_credentials,
    )
    .await?;

    let policy = match SandboxPolicy::try_from(proto_policy.clone()) {
        Ok(policy) => policy,
        Err(e) => {
            report_initial_policy_failure(endpoint, id, loaded_policy_revision.as_ref(), &e).await;
            return Err(e);
        }
    };
    Ok((
        policy,
        Some(engine),
        Some(proto_policy),
        middleware_registry_status,
        LoadedPolicyOrigin::Gateway {
            revision: loaded_policy_revision,
            has_last_valid_policy,
        },
        !configuration_rejected && agent_proposals_enabled_from_settings(&snapshot.settings),
        extension_authentication_enabled,
        None,
    ))
}

/// Install the startup middleware registry.
///
/// The in-process catalog is installed before any external connection can
/// fail, so a newly started sandbox can always resolve built-in bindings. A
/// failure to connect operator-registered services keeps that registry
/// active, so each request's `on_error` policy governs matched traffic, and
/// the runtime retries the install without waiting for a config change.
async fn connect_startup_middleware(
    engine: &OpaEngine,
    endpoint: &str,
    middleware_services: &[openshell_core::proto::SupervisorMiddlewareService],
    extension_authentication_enabled: bool,
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
) -> Result<MiddlewareRegistryStatus> {
    install_builtin_middleware_registry(engine).await?;
    if middleware_services.is_empty() {
        return Ok(MiddlewareRegistryStatus::Synchronized);
    }
    let connected = grpc_retry("Middleware connect", || {
        let extension_credentials = extension_credentials.clone();
        async move {
            let credentials = if extension_authentication_enabled {
                // Share the supervisor's store so the slots installed here
                // are the ones the policy poll loop later rotates in place.
                openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
                    endpoint,
                    extension_credentials,
                )
                .await?
                .refresh_extension_credentials(middleware_services)
                .await?
            } else {
                std::collections::HashMap::new()
            };
            connect_middleware_registry(
                middleware_services,
                &MiddlewareAuthentication {
                    credentials,
                    enabled: extension_authentication_enabled,
                },
            )
            .await
        }
    })
    .await
    .and_then(|registry| engine.replace_middleware_registry(registry));
    let Err(error) = connected else {
        return Ok(MiddlewareRegistryStatus::Synchronized);
    };
    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .state(StateId::Other, "degraded")
            .unmapped(
                "supervisor_middleware_service_count",
                serde_json::json!(middleware_services.len())
            )
            .message(format!(
                "Supervisor middleware connect failed at startup; continuing with built-in middleware only, per-request on_error governs matched requests [error:{error}]"
            ))
            .build()
    );
    Ok(MiddlewareRegistryStatus::NeedsReconciliation)
}

/// Capture the policy from the workload filesystem, preserving invalid input
/// as a repairable error instead of silently substituting another policy.
#[derive(Clone, Debug)]
enum ImagePolicyDiscovery {
    Missing,
    Invalid,
    Policy(Box<openshell_core::proto::SandboxPolicy>),
}

fn discover_image_policy() -> ImagePolicyDiscovery {
    for path in [
        openshell_policy::CONTAINER_POLICY_PATH,
        openshell_policy::LEGACY_CONTAINER_POLICY_PATH,
    ] {
        match discover_image_policy_from_path(std::path::Path::new(path)) {
            ImagePolicyDiscovery::Missing => {}
            discovered => return discovered,
        }
    }
    ImagePolicyDiscovery::Missing
}

fn discover_image_policy_from_path(path: &std::path::Path) -> ImagePolicyDiscovery {
    if matches!(path.try_exists(), Ok(false)) {
        return ImagePolicyDiscovery::Missing;
    }
    openshell_policy::parse_sandbox_policy_file(path)
        .map_or(ImagePolicyDiscovery::Invalid, |policy| {
            ImagePolicyDiscovery::Policy(Box::new(policy))
        })
}

/// Everything here is preparation: it cannot mutate an accepted generation.
fn prepare_startup_configuration(
    snapshot: &openshell_core::grpc_client::SettingsPollResult,
    policy: &openshell_core::proto::SandboxPolicy,
    provider: &openshell_core::grpc_client::ProviderEnvironmentResult,
) -> Result<(OpaEngine, SandboxPolicy, ProviderCredentialState)> {
    if !snapshot.configuration_admitted {
        return Err(miette::miette!(
            "Effective configuration admission rejected"
        ));
    }
    if !provider_environment_is_installable(provider.readiness_reason) {
        return Err(miette::miette!(
            "Provider credentials are not ready for installation"
        ));
    }
    if snapshot.provider_env_revision != provider.provider_env_revision {
        return Err(miette::miette!(
            "Provider environment revision changed during configuration preparation"
        ));
    }
    let engine = OpaEngine::from_proto(policy)?;
    let process_policy = SandboxPolicy::try_from(policy.clone())?;
    let credentials = prepare_provider_environment(provider)?;
    Ok((engine, process_policy, credentials))
}

/// Whether the provider response contains a complete environment snapshot that
/// can be installed. Withheld and expired credentials are intentionally absent,
/// so those responses remain valid fail-closed snapshots.
fn provider_environment_is_installable(reason: ProviderReadinessReason) -> bool {
    matches!(
        reason,
        ProviderReadinessReason::Unspecified
            | ProviderReadinessReason::CredentialsWithheld
            | ProviderReadinessReason::CredentialExpired
    )
}

fn prepare_provider_environment(
    provider: &openshell_core::grpc_client::ProviderEnvironmentResult,
) -> Result<ProviderCredentialState> {
    let prepared = ProviderCredentialState::from_bound_environment(
        provider.provider_env_revision,
        provider.environment.clone(),
        provider.credential_expires_at_ms.clone(),
        provider.dynamic_credentials.clone(),
        provider.static_credential_bindings.clone(),
        provider.non_secret_environment_keys.clone(),
    )
    .map_err(|_| miette::miette!("Provider credential bindings are invalid"))?;
    prepared.set_managed_files(provider.files.clone());
    Ok(prepared)
}

/// Returns the rejection for a startup policy write that the gateway refused
/// for a reason someone can repair while the sandbox waits, or `None` when
/// startup must keep treating the error as fatal.
///
/// `FAILED_PRECONDITION` (for example a `credential_binding` that names a
/// provider the sandbox does not have) and `INVALID_ARGUMENT` (a policy that
/// fails validation) are repaired by attaching a provider or replacing the
/// sandbox policy, so the caller reports them as a rejected configuration and
/// polls again. Every other error keeps its existing handling: `grpc_retry` has
/// already retried transient codes, and its error after the last attempt
/// carries no status. `PERMISSION_DENIED`, `NOT_FOUND` and `UNAUTHENTICATED`
/// mean the supervisor's identity or the sandbox record is wrong, which no
/// policy or provider change repairs.
///
/// The diagnostic carries the gateway's message so the sandbox log names the
/// cause. Like the gateway's own configuration diagnostics, it drops control
/// characters and keeps at most 512 characters of that message.
fn startup_write_rejection(write: &str, error: &miette::Report) -> Option<StartupWriteRejection> {
    let mut source: Option<&dyn std::error::Error> = Some(error.as_ref());
    while let Some(cause) = source {
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            if !matches!(
                status.code(),
                tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument
            ) {
                return None;
            }
            let message: String = status
                .message()
                .chars()
                .filter(|character| !character.is_control())
                .take(512)
                .collect();
            return Some(StartupWriteRejection {
                diagnostic: format!("Gateway rejected the {write}: {message}"),
                log_key: format!("Gateway rejected the {write} ({:?})", status.code()),
            });
        }
        source = cause.source();
    }
    None
}

/// A startup policy write that the gateway refused for a repairable reason.
#[derive(Debug, PartialEq, Eq)]
struct StartupWriteRejection {
    /// The write that failed and the gateway's bounded message. Startup
    /// reports it on every pass and logs it when `log_key` or the snapshot
    /// changes.
    diagnostic: String,
    /// Decides whether a repeated refusal is logged again. It names the write
    /// and the gRPC code but not the gateway's message, because the gateway
    /// walks unordered maps when it validates a policy and can name a
    /// different problem of the same policy on each attempt. A refusal of the
    /// same write against the same snapshot is therefore logged once.
    log_key: String,
}

// Retain only the most recent rejection, so A -> B -> A emits all transitions.
#[derive(Default)]
struct StartupRejectionLog(Option<(LoadedPolicyRevision, String)>);

impl StartupRejectionLog {
    fn changed(
        &mut self,
        snapshot: &openshell_core::grpc_client::SettingsPollResult,
        key: &str,
    ) -> bool {
        let rejection = (
            LoadedPolicyRevision::from_snapshot(snapshot),
            key.to_owned(),
        );
        if self.0.as_ref() == Some(&rejection) {
            return false;
        }
        self.0 = Some(rejection);
        true
    }
}

async fn reject_startup_configuration(
    gateway: &impl StartupGateway,
    rejection_log: &mut StartupRejectionLog,
    sandbox_id: &str,
    instance_id: &str,
    snapshot: &openshell_core::grpc_client::SettingsPollResult,
    error: &str,
    log_key: Option<&str>,
) -> Result<()> {
    let recorded = grpc_retry("Startup rejection report", || async {
        match gateway
            .report(
                sandbox_id,
                instance_id,
                Some(snapshot),
                openshell_core::proto::ConfigurationAdmissionState::Rejected,
                error,
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<tonic::Status>()
                        .is_some_and(|status| status.code() == tonic::Code::Aborted)
                }) =>
            {
                // The desired generation changed while this report was in
                // flight. Replaying the old snapshot cannot succeed; let the
                // caller fetch the repair immediately without logging a stale
                // rejection or delaying it as an unchanged configuration.
                Ok(false)
            }
            Err(error) => Err(error),
        }
    })
    .await?;
    if !recorded {
        return Ok(());
    }
    // Keep reporting readiness on every retry, but log only changed rejections.
    // The log key is the diagnostic itself unless the caller passes a stable
    // `log_key` because its diagnostic text can vary between identical
    // rejections. Diagnostics are fixed strings or bounded gateway messages;
    // callers never pass the candidate policy or credential values.
    if rejection_log.changed(snapshot, log_key.unwrap_or(error)) {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::High)
                .status(StatusId::Failure)
                .state(StateId::Disabled, "configuration_error")
                .message(error)
                .build()
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MiddlewareRegistryStatus {
    Synchronized,
    NeedsReconciliation,
}

#[derive(Debug)]
enum GatewayRuntimeReloadError {
    PolicyValidation(miette::Report),
    TransparentTcpPrerequisite(miette::Report),
    MiddlewareRegistry(miette::Report),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayRuntimeFailureClass {
    PolicyValidation,
    TransparentTcpPrerequisite,
    MiddlewareRegistry,
}

impl std::fmt::Display for GatewayRuntimeReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyValidation(error)
            | Self::TransparentTcpPrerequisite(error)
            | Self::MiddlewareRegistry(error) => error.fmt(f),
        }
    }
}

impl GatewayRuntimeReloadError {
    fn class(&self) -> GatewayRuntimeFailureClass {
        match self {
            Self::PolicyValidation(_) => GatewayRuntimeFailureClass::PolicyValidation,
            Self::TransparentTcpPrerequisite(_) => {
                GatewayRuntimeFailureClass::TransparentTcpPrerequisite
            }
            Self::MiddlewareRegistry(_) => GatewayRuntimeFailureClass::MiddlewareRegistry,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FailedRuntimeRevision {
    config_revision: u64,
    policy_hash: String,
    failure_class: GatewayRuntimeFailureClass,
}

impl FailedRuntimeRevision {
    fn new(config_revision: u64, policy_hash: &str, failure: &GatewayRuntimeReloadError) -> Self {
        Self {
            config_revision,
            policy_hash: policy_hash.to_string(),
            failure_class: failure.class(),
        }
    }
}

struct MiddlewareReloadContext<'a> {
    desired_services: &'a [openshell_core::proto::SupervisorMiddlewareService],
    authentication: &'a MiddlewareAuthentication,
    registry_changed: bool,
    connector: &'a MiddlewareConnector,
}

#[cfg(test)]
async fn reload_gateway_policy_runtime(
    engine: &OpaEngine,
    policy: Option<&openshell_core::proto::SandboxPolicy>,
    entrypoint_pid: u32,
    middleware: MiddlewareReloadContext<'_>,
    transparent_tcp: TransparentTcpReloadState,
) -> std::result::Result<PolicyGenerationGuard, GatewayRuntimeReloadError> {
    reload_gateway_configuration_runtime(
        engine,
        policy,
        entrypoint_pid,
        middleware,
        transparent_tcp,
        None,
        || {},
    )
    .await
}

async fn reload_gateway_configuration_runtime(
    engine: &OpaEngine,
    policy: Option<&openshell_core::proto::SandboxPolicy>,
    entrypoint_pid: u32,
    middleware: MiddlewareReloadContext<'_>,
    transparent_tcp: TransparentTcpReloadState,
    vm_identity: Option<VmPolicyIdentity>,
    commit_credentials: impl FnOnce(),
) -> std::result::Result<PolicyGenerationGuard, GatewayRuntimeReloadError> {
    if let (Some(identity), Some(policy)) = (vm_identity, policy) {
        // Global policy changes also reach this path. Validate before any
        // policy generation, middleware or provider credentials are committed.
        identity
            .validate(policy)
            .map_err(GatewayRuntimeReloadError::PolicyValidation)?;
    }
    if let Some(policy) = policy
        && policy_contains_explicit_tcp(policy)
    {
        if !transparent_tcp.capable {
            return Err(GatewayRuntimeReloadError::TransparentTcpPrerequisite(
                miette::miette!(
                    "candidate policy introduces protocol: tcp, but the runtime does not advertise transparent TCP support; previous policy remains active"
                ),
            ));
        }
        if !transparent_tcp.substrate_ready {
            return Err(GatewayRuntimeReloadError::TransparentTcpPrerequisite(
                miette::miette!(
                    "candidate policy introduces protocol: tcp, but this sandbox started without the transparent TCP substrate; recreate the sandbox to enable TCP; previous policy remains active"
                ),
            ));
        }
    }
    match policy {
        Some(policy) if middleware.registry_changed => {
            let registry = (middleware.connector)(
                middleware.desired_services.to_vec(),
                middleware.authentication.clone(),
            )
            .await
            .map_err(GatewayRuntimeReloadError::MiddlewareRegistry)?;
            engine
                .reload_configuration_from_proto_with_pid(
                    policy,
                    entrypoint_pid,
                    Some(registry),
                    commit_credentials,
                )
                .map_err(GatewayRuntimeReloadError::PolicyValidation)
        }
        // Policy-only change: the installed registry already matches the
        // delivered service set, so swap the engine alone. This must not
        // require middleware reachability.
        Some(policy) => engine
            .reload_configuration_from_proto_with_pid(
                policy,
                entrypoint_pid,
                None,
                commit_credentials,
            )
            .map_err(GatewayRuntimeReloadError::PolicyValidation),
        None => Err(GatewayRuntimeReloadError::PolicyValidation(
            miette::miette!("runtime reload requires a policy payload but none was returned"),
        )),
    }
}

fn policy_contains_explicit_tcp(policy: &openshell_core::proto::SandboxPolicy) -> bool {
    policy.network_policies.values().any(|rule| {
        rule.endpoints
            .iter()
            .any(|endpoint| endpoint.protocol.eq_ignore_ascii_case("tcp"))
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TransparentTcpReloadState {
    capable: bool,
    substrate_ready: bool,
}

/// True when the installed middleware registry no longer matches the desired
/// service set and must be rebuilt (reconnecting every delivered service).
///
/// A policy-only change never requires a rebuild: middleware configs were
/// validated at gateway admission and the installed registry's manifests
/// already cover the unchanged service set, so requiring the services to be
/// reachable would only let a middleware outage block the policy update.
fn middleware_registry_needs_rebuild(
    registry_status: MiddlewareRegistryStatus,
    current_services: &[openshell_core::proto::SupervisorMiddlewareService],
    desired_services: &[openshell_core::proto::SupervisorMiddlewareService],
) -> bool {
    registry_status == MiddlewareRegistryStatus::NeedsReconciliation
        || current_services != desired_services
}

fn gateway_policy_runtime_needs_reconciliation(
    reloads_gateway_policy: bool,
    current_policy_hash: &str,
    desired_policy_hash: &str,
    current_services: &[openshell_core::proto::SupervisorMiddlewareService],
    desired_services: &[openshell_core::proto::SupervisorMiddlewareService],
    registry_status: MiddlewareRegistryStatus,
) -> bool {
    reloads_gateway_policy
        && (current_policy_hash != desired_policy_hash
            || middleware_registry_needs_rebuild(
                registry_status,
                current_services,
                desired_services,
            ))
}

/// Identity returned with the exact policy snapshot used to construct OPA.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LoadedPolicyRevision {
    version: u32,
    policy_hash: String,
    config_revision: u64,
    policy_source: openshell_core::proto::PolicySource,
    admission_instance_id: Option<String>,
    provider_env_revision: u64,
}

/// Identifies where the policy currently loaded into OPA came from.
///
/// A missing gateway revision means the policy was loaded from the gateway but
/// could not be bound to an authoritative snapshot (for example, enrichment
/// sync failed). That state must reconcile on the first successful poll. A
/// local-file override is different: gateway policy revisions are observed for
/// settings/provider refreshes but must never replace the explicit local OPA
/// policy.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LoadedPolicyOrigin {
    LocalOverride,
    Gateway {
        revision: Option<LoadedPolicyRevision>,
        has_last_valid_policy: bool,
    },
}

impl LoadedPolicyOrigin {
    fn allows_gateway_policy_reload(&self) -> bool {
        matches!(self, Self::Gateway { .. })
    }

    fn has_last_valid_policy(&self) -> bool {
        match self {
            Self::LocalOverride => true,
            Self::Gateway {
                has_last_valid_policy,
                ..
            } => *has_last_valid_policy,
        }
    }
}

impl LoadedPolicyRevision {
    fn from_snapshot(snapshot: &openshell_core::grpc_client::SettingsPollResult) -> Self {
        Self {
            version: snapshot.version,
            policy_hash: snapshot.policy_hash.clone(),
            config_revision: snapshot.config_revision,
            policy_source: snapshot.policy_source,
            admission_instance_id: None,
            provider_env_revision: snapshot.provider_env_revision,
        }
    }
}

/// A sandbox-scoped policy revision that was constructed successfully at
/// startup and must be acknowledged to the gateway exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InitialPolicyAck {
    version: u32,
    policy_hash: String,
    config_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyStatusUpdate {
    version: u32,
    loaded: bool,
    error: String,
    success_event: Option<PolicyStatusSuccessEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PolicyStatusSuccessEvent {
    InitialAcknowledgement { policy_hash: String },
    UnchangedAcknowledgement { policy_hash: String },
}

impl PolicyStatusUpdate {
    fn initial_loaded(ack: &InitialPolicyAck) -> Self {
        Self {
            version: ack.version,
            loaded: true,
            error: String::new(),
            success_event: Some(PolicyStatusSuccessEvent::InitialAcknowledgement {
                policy_hash: ack.policy_hash.clone(),
            }),
        }
    }

    fn loaded(version: u32) -> Self {
        Self {
            version,
            loaded: true,
            error: String::new(),
            success_event: None,
        }
    }

    fn unchanged_loaded(version: u32, policy_hash: String) -> Self {
        Self {
            version,
            loaded: true,
            error: String::new(),
            success_event: Some(PolicyStatusSuccessEvent::UnchangedAcknowledgement { policy_hash }),
        }
    }

    fn failed(version: u32, error: String) -> Self {
        Self {
            version,
            loaded: false,
            error,
            success_event: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InitialPollDisposition {
    Acknowledge(InitialPolicyAck),
    Reconcile,
    TrackOnly,
}

/// Determine whether the initially loaded policy corresponds to an
/// authoritative sandbox-scoped revision that must be acknowledged.
///
/// Returns `Some` only for sandbox-sourced revisions (version > 0) whose
/// captured gateway identity matches the current version and hash. Global
/// policies, local-file development policies, version zero, and changed
/// identities yield `None`, so those paths never emit a sandbox-revision
/// acknowledgement.
fn initial_policy_ack_candidate(
    loaded: Option<&LoadedPolicyRevision>,
    canonical: &openshell_core::grpc_client::SettingsPollResult,
) -> Option<InitialPolicyAck> {
    let loaded = loaded?;
    if !canonical.configuration_admitted
        || canonical.provider_env_revision != loaded.provider_env_revision
    {
        return None;
    }
    if loaded.policy_source != openshell_core::proto::PolicySource::Sandbox
        || canonical.policy_source != openshell_core::proto::PolicySource::Sandbox
    {
        return None;
    }
    if loaded.version == 0 || canonical.version == 0 {
        return None;
    }
    if loaded.version != canonical.version
        || loaded.policy_hash != canonical.policy_hash
        || canonical.config_revision != loaded.config_revision
    {
        return None;
    }
    Some(InitialPolicyAck {
        version: loaded.version,
        policy_hash: loaded.policy_hash.clone(),
        config_revision: canonical.config_revision,
    })
}

fn initial_poll_disposition(
    origin: &LoadedPolicyOrigin,
    canonical: &openshell_core::grpc_client::SettingsPollResult,
) -> InitialPollDisposition {
    match origin {
        LoadedPolicyOrigin::LocalOverride => InitialPollDisposition::TrackOnly,
        LoadedPolicyOrigin::Gateway { revision, .. } => {
            initial_policy_ack_candidate(revision.as_ref(), canonical).map_or(
                InitialPollDisposition::Reconcile,
                InitialPollDisposition::Acknowledge,
            )
        }
    }
}

fn unchanged_policy_revision_candidate(
    reloads_gateway_policy: bool,
    recovering_rejected_policy: bool,
    current_policy_version: u32,
    current_policy_hash: &str,
    result: &openshell_core::grpc_client::SettingsPollResult,
) -> Option<u32> {
    (reloads_gateway_policy
        && !recovering_rejected_policy
        && !current_policy_hash.is_empty()
        && result.policy_source == openshell_core::proto::PolicySource::Sandbox
        && result.version > current_policy_version
        && result.policy_hash == current_policy_hash)
        .then_some(result.version)
}

fn unchanged_policy_revision_ready_to_ack(
    candidate: Option<u32>,
    policy_runtime_changed: bool,
    policy_runtime_reconciled: bool,
) -> Option<u32> {
    candidate.filter(|_| !policy_runtime_changed || policy_runtime_reconciled)
}

/// Whether the credential-provenance gates cannot apply to the loaded policy.
///
/// The gateway derives `provider_credentialed` and deliberately keeps it out of
/// the policy YAML schema, so a local-file policy never carries it and never
/// will: gateway revisions are observed for settings and providers but must not
/// replace the local OPA policy. Provider credentials still arrive from the
/// gateway on that path, so the raw-tunnel and WebSocket binary-frame refusals
/// have nothing to match on. The request-body backstop is unaffected because it
/// keys off the secret resolver rather than endpoint provenance.
fn credential_gating_unavailable(
    origin: &LoadedPolicyOrigin,
    has_resolver: bool,
    network_enabled: bool,
) -> bool {
    network_enabled && has_resolver && matches!(origin, LoadedPolicyOrigin::LocalOverride)
}

/// Report that credential provenance is unavailable for the loaded policy.
///
/// Carries no credential name, host, or value: the finding states which
/// controls are inactive, nothing about what they would have protected.
fn report_credential_gating_unavailable() {
    ocsf_emit!(
        DetectionFindingBuilder::new(ocsf_ctx())
            .activity(ActivityId::Open)
            .severity(SeverityId::High)
            .confidence(ConfidenceId::High)
            .is_alert(true)
            .finding_info(
                FindingInfo::new(
                    "credential-gating-unavailable",
                    "Credential Provenance Unavailable",
                )
                .with_desc(
                    "Provider credentials are injected, but the loaded policy comes from local \
                     files and carries no gateway-derived credential provenance. Uninspected \
                     credentialed tunnels and WebSocket binary frames are not refused. Load \
                     policy from the gateway to enable these controls."
                ),
            )
            .evidence_pairs(&[
                ("policy_source", "local-override"),
                ("uninspected_connect_gate", "inactive"),
                ("websocket_binary_gate", "inactive"),
                ("request_body_backstop", "active"),
            ])
            .remediation(
                "Remove the local policy override so the gateway-delivered effective policy \
                 applies, or detach provider credentials from this sandbox."
            )
            .message(
                "Credential provenance unavailable for local-file policy; uninspected credential gates inactive"
            )
            .build()
    );
}

/// Install the first gateway snapshot before passing placeholders to the workload.
/// Invalid static bindings leave only independently authorized dynamic grants active.
fn initial_provider_credentials(
    result: openshell_core::grpc_client::ProviderEnvironmentResult,
    readiness: &ProviderReadinessTracker,
) -> ProviderCredentialState {
    let identity = EnvironmentIdentity::from_environment(&result);
    let expires_at_ms = result
        .credential_expires_at_ms
        .values()
        .copied()
        .filter(|expiry| *expiry > 0)
        .min();
    if result.readiness_reason != ProviderReadinessReason::Unspecified {
        readiness.credentials_failed(identity, result.readiness_reason);
        return ProviderCredentialState::from_environment(
            result.provider_env_revision,
            std::collections::HashMap::default(),
            std::collections::HashMap::default(),
            result.dynamic_credentials,
        );
    }
    let dynamic_credentials_fallback = result.dynamic_credentials.clone();
    match ProviderCredentialState::from_bound_environment(
        result.provider_env_revision,
        result.environment,
        result.credential_expires_at_ms,
        result.dynamic_credentials,
        result.static_credential_bindings,
        result.non_secret_environment_keys,
    ) {
        Ok(credentials) => {
            credentials.set_managed_files(result.files);
            readiness.credentials_installed(identity, &credentials, expires_at_ms);
            credentials
        }
        Err(error) => {
            readiness
                .credentials_failed(identity, ProviderReadinessReason::CredentialInstallFailed);
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::High)
                    .status(StatusId::Failure)
                    .state(StateId::Disabled, "fail_closed")
                    .message(format!(
                        "Rejected provider environment bindings; static provider credentials were revoked; fetched dynamic token grants remain active: {error}"
                    ))
                    .build()
            );
            ProviderCredentialState::from_environment(
                result.provider_env_revision,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                dynamic_credentials_fallback,
            )
        }
    }
}

/// Deliver policy status updates independently from policy reconciliation.
///
/// The channel is FIFO, so a delayed older status can never arrive after a
/// newer status and move the gateway's active version backward. Delivery uses
/// the existing bounded retry, but failures never delay policy enforcement.
#[tonic::async_trait]
trait PolicyGatewayClient: Clone + Send + Sync + 'static {
    async fn poll_settings(
        &self,
        sandbox: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult>;

    async fn report_policy_status(
        &self,
        sandbox_id: &str,
        version: u32,
        loaded: bool,
        error: &str,
    ) -> Result<()>;

    async fn report_endpoint_status(
        &self,
        _sandbox_id: &str,
        _snapshot: &openshell_core::endpoint_status::EndpointStatusSnapshot,
    ) -> Result<()> {
        Ok(())
    }

    /// Fetch the complete provider snapshot through the ordinary static-binding API.
    async fn fetch_provider_environment(
        &self,
        endpoint: &str,
        sandbox_id: &str,
    ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
        openshell_core::grpc_client::fetch_provider_environment(endpoint, sandbox_id).await
    }

    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        Ok(())
    }

    async fn extension_credentials_for(
        &self,
        _services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        Ok(std::collections::HashMap::new())
    }

    fn workspace(&self) -> String;
}

#[tonic::async_trait]
impl PolicyGatewayClient for openshell_core::grpc_client::CachedOpenShellClient {
    async fn poll_settings(
        &self,
        sandbox: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
        self.poll_settings(sandbox).await
    }

    async fn report_policy_status(
        &self,
        sandbox_id: &str,
        version: u32,
        loaded: bool,
        error: &str,
    ) -> Result<()> {
        self.report_policy_status(sandbox_id, version, loaded, error)
            .await
    }

    async fn report_endpoint_status(
        &self,
        sandbox_id: &str,
        snapshot: &openshell_core::endpoint_status::EndpointStatusSnapshot,
    ) -> Result<()> {
        self.report_endpoint_status(sandbox_id, snapshot).await
    }

    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        self.refresh_installed_extension_credentials().await
    }

    async fn extension_credentials_for(
        &self,
        services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        self.extension_credentials_for(services).await
    }

    fn workspace(&self) -> String {
        self.workspace()
    }
}

async fn run_policy_status_reporter<C: PolicyGatewayClient>(
    client: C,
    sandbox_id: String,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<PolicyStatusUpdate>,
) {
    'updates: while let Some(update) = updates.recv().await {
        let operation = if matches!(
            update.success_event,
            Some(PolicyStatusSuccessEvent::InitialAcknowledgement { .. })
        ) {
            "Initial policy acknowledgement"
        } else {
            "Policy status report"
        };
        let mut attempt = 1_u32;
        loop {
            let sandbox_id = sandbox_id.clone();
            let error = update.error.clone();
            let client = client.clone();
            match client
                .report_policy_status(&sandbox_id, update.version, update.loaded, &error)
                .await
            {
                Ok(()) => break,
                Err(error) if is_retryable_error(&error) => {
                    let backoff = Duration::from_secs(1_u64 << attempt.saturating_sub(1).min(5));
                    warn!(
                        %error,
                        attempt,
                        version = update.version,
                        loaded = update.loaded,
                        retry_in_secs = backoff.as_secs(),
                        "{operation} failed transiently; retaining ordered update"
                    );
                    tokio::time::sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    warn!(
                        %error,
                        version = update.version,
                        loaded = update.loaded,
                        "Discarding terminal policy status update"
                    );
                    continue 'updates;
                }
            }
        }

        if let Some(event) = update.success_event {
            let (policy_hash, message) = match event {
                PolicyStatusSuccessEvent::InitialAcknowledgement { policy_hash } => (
                    policy_hash,
                    format!(
                        "Acknowledged initial policy revision as loaded [version:{}]",
                        update.version
                    ),
                ),
                PolicyStatusSuccessEvent::UnchangedAcknowledgement { policy_hash } => (
                    policy_hash,
                    format!(
                        "Acknowledged unchanged policy revision as loaded [version:{}]",
                        update.version
                    ),
                ),
            };
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped("version", serde_json::json!(update.version))
                    .unmapped("policy_hash", serde_json::json!(policy_hash))
                    .message(message)
                    .build()
            );
        }
    }
}

fn enqueue_policy_status(sender: &UnboundedSender<PolicyStatusUpdate>, update: PolicyStatusUpdate) {
    let version = update.version;
    if let Err(error) = sender.send(update) {
        warn!(
            %error,
            version,
            "Policy status reporter unavailable during shutdown"
        );
    }
}

/// Best-effort `FAILED` acknowledgement when initial policy construction or
/// conversion fails.
///
/// Uses the revision identity captured with the policy that failed to build,
/// and preserves the original construction error as the reported message. A
/// delivery failure here is swallowed so it can never mask that error.
async fn report_initial_policy_failure(
    endpoint: &str,
    sandbox_id: &str,
    revision: Option<&LoadedPolicyRevision>,
    error: &miette::Report,
) {
    let Some(revision) = revision.filter(|revision| {
        revision.version > 0
            && revision.policy_source == openshell_core::proto::PolicySource::Sandbox
    }) else {
        return;
    };
    let client = match openshell_core::grpc_client::CachedOpenShellClient::connect(endpoint).await {
        Ok(client) => client,
        Err(e) => {
            warn!(error = %e, "Failed to connect to report initial policy failure");
            return;
        }
    };
    let message = error.to_string();
    if let Err(e) = grpc_retry("Initial policy failure report", || {
        let client = client.clone();
        let message = message.clone();
        async move {
            client
                .report_policy_status(sandbox_id, revision.version, false, &message)
                .await
        }
    })
    .await
    {
        warn!(error = %e, version = revision.version, "Failed to report initial policy failure");
    }
}

/// Background loop that polls the server for policy updates.
///
/// When a new version is detected, attempts to reload the OPA engine via
/// `reload_from_proto_with_pid()`. Reports load success/failure back to the
/// server. On failure, the previous engine is untouched (LKG behavior).
///
/// When the entrypoint PID is available, policy reloads include symlink
/// resolution for binary paths via the container filesystem.
struct PolicyPollLoopContext {
    endpoint: String,
    sandbox_id: String,
    /// Canonical sandbox reference used by name-scoped configuration APIs.
    sandbox: String,
    opa_engine: Arc<OpaEngine>,
    /// Source of the policy currently loaded into OPA. This distinguishes an
    /// explicit local-file override from an unbound gateway revision so the
    /// former is never replaced by policy polling.
    loaded_policy_origin: LoadedPolicyOrigin,
    /// Immutable VM overlay identity, also enforced for global policy updates.
    vm_identity: Option<VmPolicyIdentity>,
    entrypoint_pid: Arc<AtomicU32>,
    interval_secs: u64,
    ocsf_enabled: Arc<AtomicBool>,
    ocsf_schema_version: Arc<std::sync::Mutex<String>>,
    provider_credentials: ProviderCredentialState,
    provider_readiness: ProviderReadinessTracker,
    policy_local_ctx: Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
    agent_proposals: AgentProposals,
    middleware_registry_status: MiddlewareRegistryStatus,
    workspace_tx: tokio::sync::watch::Sender<String>,
    extension_credentials: openshell_extension_core::ExtensionCredentialStore,
    extension_authentication_enabled: bool,
    middleware_connector: MiddlewareConnector,
    /// Immutable driver capability and startup substrate state.
    transparent_tcp: TransparentTcpReloadState,
    /// Payloads delivered over the supervisor session.
    config_apply_rx: Option<tokio::sync::mpsc::Receiver<ConfigApplyRequest>>,
    /// Present when the session delivered a bootstrap. It already initialized
    /// the runtime, so it seeds the applied trackers and the runtime applies
    /// delivered updates instead of polling.
    initial_stream_snapshot: Option<openshell_core::grpc_client::SettingsPollResult>,
    /// Whether the current supervisor session delivers configuration
    /// authoritatively. A stream-started runtime polls while it is false.
    config_apply_enabled: Option<tokio::sync::watch::Receiver<bool>>,
    /// Producer shared with network enforcement and policy installation.
    endpoint_observation_tx: Option<openshell_core::endpoint_status::EndpointObservationSender>,
    /// Single FIFO consumed by the endpoint status reporter.
    endpoint_status_rx: Option<openshell_core::endpoint_status::EndpointStatusReceiver>,
    /// Gateway policy currently installed in OPA, absent for local overrides.
    endpoint_policy: Option<openshell_core::proto::SandboxPolicy>,
    /// Session accepted by `ConnectSupervisor`; `None` suspends endpoint reports.
    supervisor_session_id: tokio::sync::watch::Receiver<Option<String>>,
}

type MiddlewareConnector = Arc<
    dyn Fn(
            Vec<openshell_core::proto::SupervisorMiddlewareService>,
            MiddlewareAuthentication,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<openshell_supervisor_middleware::MiddlewareRegistry>,
                    > + Send,
            >,
        > + Send
        + Sync,
>;

#[derive(Clone, Default)]
struct MiddlewareAuthentication {
    credentials: std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>,
    enabled: bool,
}

fn default_middleware_connector() -> MiddlewareConnector {
    Arc::new(|services, authentication| {
        Box::pin(async move { connect_middleware_registry(&services, &authentication).await })
    })
}

async fn connect_middleware_registry(
    services: &[openshell_core::proto::SupervisorMiddlewareService],
    authentication: &MiddlewareAuthentication,
) -> Result<openshell_supervisor_middleware::MiddlewareRegistry> {
    if authentication.enabled {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services_authenticated(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
            &authentication.credentials,
        )
        .await
    } else {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
        )
        .await
    }
}

async fn install_builtin_middleware_registry(opa_engine: &OpaEngine) -> Result<()> {
    let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        openshell_supervisor_middleware_builtins::services(),
        Vec::new(),
    )
    .await?;
    opa_engine.replace_middleware_registry(registry)
}

/// Wait the configured poll interval, but never past the point at which an
/// installed extension credential must be rotated.
fn next_poll_delay(
    store: &openshell_extension_core::ExtensionCredentialStore,
    interval: Duration,
) -> Duration {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    store.next_refresh_delay(interval, now_ms)
}

/// Drop credentials for services no longer in the installed registry.
///
/// Call only after a registry swap succeeds, so a failed candidate cannot
/// invalidate the last-known-good clients.
fn retain_extension_credentials(
    store: &openshell_extension_core::ExtensionCredentialStore,
    installed: &[openshell_core::proto::SupervisorMiddlewareService],
    extension_authentication_enabled: bool,
) {
    let retained = if extension_authentication_enabled {
        installed
            .iter()
            .map(|service| service.name.as_str())
            .collect()
    } else {
        std::collections::HashSet::default()
    };
    store.retain(&retained);
}

struct MiddlewareRegistryReconciliation<'a> {
    desired_services: &'a [openshell_core::proto::SupervisorMiddlewareService],
    authentication: MiddlewareAuthentication,
    registry_changed: bool,
    extension_credentials: &'a openshell_extension_core::ExtensionCredentialStore,
    current_services: &'a mut Vec<openshell_core::proto::SupervisorMiddlewareService>,
    status: &'a mut MiddlewareRegistryStatus,
}

async fn reconcile_middleware_registry(
    opa_engine: &OpaEngine,
    middleware_connector: &MiddlewareConnector,
    reconciliation: MiddlewareRegistryReconciliation<'_>,
) {
    if !reconciliation.registry_changed {
        return;
    }

    match middleware_connector(
        reconciliation.desired_services.to_vec(),
        reconciliation.authentication.clone(),
    )
    .await
    .and_then(|registry| opa_engine.replace_middleware_registry(registry))
    {
        Ok(()) => {
            retain_extension_credentials(
                reconciliation.extension_credentials,
                reconciliation.desired_services,
                reconciliation.authentication.enabled,
            );
            reconciliation.current_services.clear();
            reconciliation
                .current_services
                .extend_from_slice(reconciliation.desired_services);
            *reconciliation.status = MiddlewareRegistryStatus::Synchronized;
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped(
                        "supervisor_middleware_service_count",
                        serde_json::json!(reconciliation.current_services.len())
                    )
                    .message(format!(
                        "Supervisor middleware registry reloaded [service_count:{}]",
                        reconciliation.current_services.len()
                    ))
                    .build()
            );
        }
        Err(error) => {
            // Emit only on the transition into the failed state to avoid
            // repeating the same finding on every poll during an outage.
            if *reconciliation.status == MiddlewareRegistryStatus::Synchronized {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "failed")
                        .message(format!(
                            "Supervisor middleware registry reload failed, keeping last-known-good registry [error:{error}]"
                        ))
                        .build()
                );
            }
            *reconciliation.status = MiddlewareRegistryStatus::NeedsReconciliation;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PolicyValidationFailureDisposition {
    configured_mode: PolicyValidationFailureMode,
    mode: PolicyValidationFailureMode,
    previous_policy_active: bool,
    active_generation: u64,
}

struct RejectedPolicyGeneration {
    version: u32,
    policy_hash: String,
    validation_error: String,
    configured_mode: PolicyValidationFailureMode,
}

enum GatewayRuntimeFailureDisposition {
    PolicyRejected {
        error: String,
        disposition: PolicyValidationFailureDisposition,
    },
    MiddlewareUnavailable {
        error: String,
    },
    TransparentTcpExpansionRejected {
        error: String,
        active_generation: u64,
    },
}

fn apply_gateway_runtime_reload_failure(
    engine: &OpaEngine,
    failure: GatewayRuntimeReloadError,
    configured_mode: PolicyValidationFailureMode,
    has_last_valid_policy: bool,
    version: u32,
) -> Result<GatewayRuntimeFailureDisposition> {
    match failure {
        GatewayRuntimeReloadError::PolicyValidation(error) => {
            let error = error.to_string();
            let disposition = apply_policy_validation_failure(
                engine,
                configured_mode,
                has_last_valid_policy,
                version,
                &error,
            )?;
            Ok(GatewayRuntimeFailureDisposition::PolicyRejected { error, disposition })
        }
        GatewayRuntimeReloadError::TransparentTcpPrerequisite(error) => Ok(
            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                error: error.to_string(),
                active_generation: engine.current_generation(),
            },
        ),
        GatewayRuntimeReloadError::MiddlewareRegistry(error) => {
            Ok(GatewayRuntimeFailureDisposition::MiddlewareUnavailable {
                error: error.to_string(),
            })
        }
    }
}

fn emit_transparent_tcp_expansion_rejection(
    version: u32,
    policy_hash: &str,
    active_generation: u64,
    error: &str,
) {
    let message = format!(
        "Transparent TCP policy expansion rejected; previous policy IS active [version:{version} active_generation:{active_generation} error:{error}]"
    );
    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .state(StateId::Enabled, "retained_previous_policy")
            .unmapped("candidate_version", serde_json::json!(version))
            .unmapped("candidate_policy_hash", serde_json::json!(policy_hash))
            .unmapped("previous_policy_active", serde_json::json!(true))
            .unmapped("active_generation", serde_json::json!(active_generation))
            .unmapped("validation_error", serde_json::json!(error))
            .message(message)
            .build()
    );
}

fn apply_policy_validation_failure(
    engine: &OpaEngine,
    configured_mode: PolicyValidationFailureMode,
    has_last_valid_policy: bool,
    version: u32,
    error: &str,
) -> Result<PolicyValidationFailureDisposition> {
    let mode = if has_last_valid_policy {
        configured_mode
    } else {
        PolicyValidationFailureMode::FailClosed
    };
    match mode {
        PolicyValidationFailureMode::FailClosed => {
            let reason = format!(
                "policy validation failed; fail-closed quarantine is active; candidate version {version} rejected: {error}"
            );
            let active_generation = engine.enter_fail_closed(reason)?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: false,
                active_generation,
            })
        }
        PolicyValidationFailureMode::RetainLastValid => {
            let active_generation = engine.exit_fail_closed()?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: true,
                active_generation,
            })
        }
    }
}

fn policy_validation_failure_events(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) -> [OcsfEvent; 2] {
    let previous_policy_state = if disposition.previous_policy_active {
        "IS active"
    } else {
        "IS NOT active"
    };
    let state = if disposition.previous_policy_active {
        (StateId::Enabled, "retained_last_valid")
    } else {
        (StateId::Disabled, "fail_closed")
    };
    let message = format!(
        "Policy validation failed; configured_mode={} effective_mode={}; previous policy {previous_policy_state} [version:{version} active_generation:{} error:{error}]",
        disposition.configured_mode.as_str(),
        disposition.mode.as_str(),
        disposition.active_generation,
    );
    let finding_uid = format!("policy-validation-failed-{version}");
    let version_string = version.to_string();
    let config = ConfigStateChangeBuilder::new(ocsf_ctx())
        .severity(SeverityId::High)
        .status(StatusId::Failure)
        .state(state.0, state.1)
        .unmapped("candidate_version", serde_json::json!(version))
        .unmapped("candidate_policy_hash", serde_json::json!(policy_hash))
        .unmapped(
            "validation_failure_mode",
            serde_json::json!(disposition.mode.as_str()),
        )
        .unmapped(
            "configured_validation_failure_mode",
            serde_json::json!(disposition.configured_mode.as_str()),
        )
        .unmapped(
            "previous_policy_active",
            serde_json::json!(disposition.previous_policy_active),
        )
        .unmapped(
            "active_generation",
            serde_json::json!(disposition.active_generation),
        )
        .unmapped("validation_error", serde_json::json!(error))
        .message(message.clone())
        .build();
    let finding = DetectionFindingBuilder::new(ocsf_ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .is_alert(true)
        .finding_info(
            FindingInfo::new(&finding_uid, "Invalid policy generation rejected").with_desc(error),
        )
        .evidence_pairs(&[
            ("candidate_version", &version_string),
            ("candidate_policy_hash", policy_hash),
            ("validation_failure_mode", disposition.mode.as_str()),
            (
                "configured_validation_failure_mode",
                disposition.configured_mode.as_str(),
            ),
            (
                "previous_policy_active",
                if disposition.previous_policy_active {
                    "true"
                } else {
                    "false"
                },
            ),
        ])
        .remediation("Submit a valid, unambiguous policy generation")
        .message(message)
        .build();
    [config, finding]
}

fn emit_policy_validation_failure(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) {
    for event in policy_validation_failure_events(disposition, version, policy_hash, error) {
        ocsf_emit!(event);
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Admission must reject this input before any backend decodes its payload
    /// or contacts a workload. Keep this fixture independent of setup helpers
    /// so it can also reproduce the ordering defect on earlier revisions.
    #[tokio::test]
    async fn startup_rejects_missing_admission_before_decoding_payload() {
        let auth_bundle = openshell_core::jwt::SupervisorAuthBundle {
            session_id: openshell_core::SandboxSessionId::new(),
            runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                "generation-1",
            )
            .expect("generation"),
            session_rotation: openshell_core::jwt::SessionRotation::new(1).expect("rotation"),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).expect("epoch"),
            gateway_token: openshell_core::jwt::SecretJwt::parse("test-gateway-token")
                .expect("token"),
            gateway_expires_at: 0,
            sandbox_token: openshell_core::jwt::SecretJwt::parse("test-sandbox-token")
                .expect("token"),
            sandbox_expires_at: 0,
            ssh_host_private_key: None,
        };
        let error = run_sandbox(
            vec!["true".to_string()],
            None,
            0,
            false,
            false,
            Some("sandbox-1".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(String::new())),
            openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
            openshell_isolation_interface::contract::BackendDescriptor {
                backend_name: "in-process-test".to_string(),
                payload: b"in-process-only-launch-data".to_vec(),
            },
            auth_bundle,
            None,
            None,
        )
        .await
        .expect_err("missing admission cannot authorize startup");

        assert_eq!(
            error.to_string(),
            "runtime descriptor supplied without an admitted isolation backend"
        );
    }

    #[test]
    fn shared_ssh_socket_setting_is_explicit() {
        assert!(shared_ssh_socket_value("1"));
        assert!(shared_ssh_socket_value("true"));
        assert!(shared_ssh_socket_value("TRUE"));
        assert!(!shared_ssh_socket_value("0"));
        assert!(!shared_ssh_socket_value("yes"));
    }

    #[cfg(unix)]
    #[test]
    fn network_proxy_tls_directory_is_private_and_not_symlinked() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let automatic = prepare_network_proxy_tls_dir(None).expect("private default directory");
        let mode = std::fs::metadata(&automatic.path)
            .expect("default directory metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);

        let root = tempfile::tempdir().expect("temporary root");
        let target = root.path().join("target");
        std::fs::create_dir(&target).expect("target directory");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("private target permissions");
        let link = root.path().join("link");
        symlink(&target, &link).expect("TLS directory symlink");
        assert!(prepare_network_proxy_tls_dir(Some(link)).is_err());

        let writable = root.path().join("writable");
        std::fs::create_dir(&writable).expect("writable directory");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
            .expect("writable permissions");
        assert!(prepare_network_proxy_tls_dir(Some(writable)).is_err());
    }

    #[tokio::test]
    async fn control_readiness_exists_only_while_guard_is_live() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("health.sock");
        let readiness = ControlReadiness::start(ReadinessEndpoint::Unix(path.clone()), None)
            .expect("start readiness listener");
        check_control_readiness(&path).expect("running supervisor accepts readiness probes");

        drop(readiness);
        tokio::task::yield_now().await;
        assert!(check_control_readiness(&path).is_err());
    }

    #[tokio::test]
    async fn control_readiness_tracks_supervisor_session() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("health.sock");
        let (session_tx, session_rx) = tokio::sync::watch::channel(false);
        let _readiness =
            ControlReadiness::start(ReadinessEndpoint::Unix(path.clone()), Some(session_rx))
                .expect("start readiness listener");
        assert!(check_control_readiness(&path).is_err());

        session_tx.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first accepted session creates readiness socket");

        session_tx.send_replace(false);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lost session removes readiness socket");

        session_tx.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement session restores readiness socket");
    }

    #[test]
    fn tcp_readiness_listener_accepts_ipv4_regardless_of_bindv6only() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|reserved| reserved.local_addr())
            .expect("reserve loopback port")
            .port();
        let listener = bind_readiness_tcp(port).expect("bind readiness listener");
        if listener.local_addr().expect("local address").is_ipv6() {
            assert!(
                !socket2::SockRef::from(&listener)
                    .only_v6()
                    .expect("read IPV6_V6ONLY"),
                "net.ipv6.bindv6only=1 must not make the wildcard listener IPv6-only"
            );
        }
        std::net::TcpStream::connect(("127.0.0.1", port))
            .expect("IPv4 kubelet probe reaches the readiness listener");
    }

    #[tokio::test]
    async fn tcp_control_readiness_tracks_supervisor_session() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|reserved| reserved.local_addr())
            .expect("reserve loopback port")
            .port();
        let (session_tx, session_rx) = tokio::sync::watch::channel(true);
        let readiness = ControlReadiness::start(ReadinessEndpoint::Tcp(port), Some(session_rx))
            .expect("start TCP readiness listener");
        let connects = || std::net::TcpStream::connect(("127.0.0.1", port)).is_ok();
        assert!(connects(), "accepted session is ready");

        session_tx.send_replace(false);
        timeout(Duration::from_secs(1), async {
            while connects() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lost session closes readiness listener");

        session_tx.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while !connects() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement session reopens readiness listener");

        drop(readiness);
        timeout(Duration::from_secs(1), async {
            while connects() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped guard closes readiness listener");
    }

    #[test]
    fn control_readiness_rejects_relative_path() {
        let error = prepare_control_readiness_path(std::path::Path::new("health.sock"))
            .expect_err("relative readiness path must be rejected");
        assert!(error.to_string().contains("must be absolute"));
    }

    #[test]
    fn main_exit_marker_atomically_replaces_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("main-exited");
        std::fs::write(&marker, b"stale\n").unwrap();

        persist_main_exit_marker(&marker, 23).unwrap();

        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "exit_code=23\n");
        assert!(
            !directory
                .path()
                .join(format!(".main-exited.tmp-{}", std::process::id()))
                .exists()
        );
    }

    #[tokio::test]
    async fn remote_access_plane_outlives_main_completion_until_teardown() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let retained = retain_remote_access_plane(std::future::pending(), async {
            let _ = shutdown_rx.await;
        });
        tokio::pin!(retained);

        assert!(
            timeout(Duration::from_millis(10), &mut retained)
                .await
                .is_err(),
            "access plane must remain live after canonical process completion"
        );
        shutdown_tx.send(()).expect("request teardown");
        timeout(Duration::from_secs(1), &mut retained)
            .await
            .expect("teardown should release retained access plane")
            .expect("clean teardown");
    }

    #[tokio::test]
    async fn completion_retry_phase_is_cancelled_by_shutdown() {
        let mut shutdown = Box::pin(std::future::ready(()));
        assert!(
            completion_phase_or_shutdown(std::future::pending(), shutdown.as_mut()).await,
            "shutdown must cancel an indefinitely retrying completion phase"
        );
    }

    #[test]
    fn discover_policy_from_nonexistent_path_is_missing() {
        let path = std::path::Path::new("/nonexistent/policy.yaml");
        assert!(matches!(
            discover_image_policy_from_path(path),
            ImagePolicyDiscovery::Missing
        ));
    }

    #[test]
    fn discover_policy_from_valid_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only:
    - /usr
  read_write:
    - /tmp
network_policies:
  test:
    name: test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        )
        .unwrap();

        let ImagePolicyDiscovery::Policy(policy) = discover_image_policy_from_path(&path) else {
            panic!("expected parsed policy")
        };
        assert_eq!(policy.network_policies.len(), 1);
        assert!(policy.network_policies.contains_key("test"));
        let fs = policy.filesystem.unwrap();
        assert!(!fs.include_workdir);
    }

    #[test]
    fn discover_policy_from_invalid_yaml_remains_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "this is not valid yaml: [[[").unwrap();

        assert!(matches!(
            discover_image_policy_from_path(&path),
            ImagePolicyDiscovery::Invalid
        ));
    }

    #[test]
    fn discover_policy_from_oversized_file_remains_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        let oversized = format!("version: 1\n{}", " ".repeat(4 * 1024 * 1024));
        std::fs::write(&path, oversized).unwrap();
        assert!(matches!(
            discover_image_policy_from_path(&path),
            ImagePolicyDiscovery::Invalid
        ));
    }

    #[test]
    fn discover_policy_from_unsafe_yaml_preserves_candidate_for_admission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
version: 1
process:
  run_as_user: root
  run_as_group: root
filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
  read_write:
    - /tmp
"#,
        )
        .unwrap();

        let ImagePolicyDiscovery::Policy(policy) = discover_image_policy_from_path(&path) else {
            panic!("expected parsed policy")
        };
        assert!(openshell_policy::validate_sandbox_policy(&policy).is_err());
    }

    #[test]
    fn discover_policy_restrictive_default_blocks_network() {
        // In cluster mode we keep proxy mode enabled so all egress passes
        // through proxy/OPA controls.
        let proto = openshell_policy::restrictive_default_policy();
        let local_policy = SandboxPolicy::try_from(proto).expect("conversion should succeed");
        assert!(matches!(local_policy.network.mode, NetworkMode::Proxy));
    }

    // ---- Initial policy acknowledgement tests ----

    pub fn proto_policy_fixture() -> openshell_core::proto::SandboxPolicy {
        openshell_policy::restrictive_default_policy()
    }

    pub fn proto_tcp_policy_fixture() -> openshell_core::proto::SandboxPolicy {
        openshell_policy::parse_sandbox_policy(
            r#"
version: 1
network_policies:
  redis:
    name: redis
    endpoints:
      - host: redis.example.com
        port: 6379
        protocol: tcp
    binaries:
      - path: /usr/bin/redis-cli
"#,
        )
        .expect("parse TCP policy")
    }

    pub fn settings_poll_result(
        policy: Option<openshell_core::proto::SandboxPolicy>,
        version: u32,
        source: openshell_core::proto::PolicySource,
    ) -> openshell_core::grpc_client::SettingsPollResult {
        openshell_core::grpc_client::SettingsPollResult {
            policy,
            version,
            policy_hash: format!("hash-v{version}"),
            config_revision: u64::from(version) * 100,
            policy_source: source,
            settings: std::collections::HashMap::new(),
            global_policy_version: 0,
            provider_env_revision: 0,
            provider_attachment_epoch: String::new(),
            supervisor_middleware_services: Vec::new(),
            workspace: String::new(),
            policy_validation_failure_mode: PolicyValidationFailureMode::default(),
            extension_authentication_enabled: false,
            configuration_admitted: true,
            configuration_error: String::new(),
            configuration_instance_id: String::new(),
            settings_revision: 0,
        }
    }

    #[derive(Clone)]
    struct TestStartupGateway {
        desired: Arc<std::sync::Mutex<openshell_core::grpc_client::SettingsPollResult>>,
        reports: UnboundedSender<openshell_core::proto::ConfigurationAdmissionState>,
        reject_next_accept: Arc<AtomicBool>,
        snapshot_error: Option<tonic::Code>,
        report_error: Option<tonic::Code>,
        pending_snapshot: bool,
        pending_acceptance: bool,
    }

    #[tonic::async_trait]
    impl StartupGateway for TestStartupGateway {
        async fn snapshot(
            &self,
            _id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            if self.pending_snapshot {
                return std::future::pending().await;
            }
            if let Some(code) = self.snapshot_error {
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::new(code, "snapshot unavailable"),
                ));
            }
            Ok(self.desired.lock().unwrap().clone())
        }
        async fn provider(
            &self,
            _id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            Ok(startup_provider(
                self.desired.lock().unwrap().provider_env_revision,
            ))
        }
        async fn sync(
            &self,
            _sandbox: &str,
            _policy: &openshell_core::proto::SandboxPolicy,
            _workspace: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.snapshot("").await
        }
        async fn report(
            &self,
            _id: &str,
            _instance_id: &str,
            snapshot: Option<&openshell_core::grpc_client::SettingsPollResult>,
            state: openshell_core::proto::ConfigurationAdmissionState,
            _error: &str,
        ) -> Result<()> {
            use openshell_core::proto::ConfigurationAdmissionState;
            if let Some(code) = self.report_error {
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::new(code, "registration fence changed"),
                ));
            }
            self.reports.send(state).unwrap();
            if state == ConfigurationAdmissionState::Accepted {
                if self.pending_acceptance {
                    return std::future::pending().await;
                }
                if self.reject_next_accept.swap(false, Ordering::SeqCst) {
                    return Err(miette::miette!(
                        "desired generation changed before activation"
                    ));
                }
                assert_eq!(
                    snapshot.unwrap().config_revision,
                    self.desired.lock().unwrap().config_revision
                );
            }
            Ok(())
        }
    }

    #[test]
    fn startup_rejection_logs_only_changed_configuration_or_error() {
        let mut snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let mut log = StartupRejectionLog::default();
        assert!(log.changed(&snapshot, "invalid policy"));
        for _ in 0..10 {
            assert!(!log.changed(&snapshot, "invalid policy"));
        }
        snapshot.config_revision += 1;
        assert!(log.changed(&snapshot, "invalid policy"));
        snapshot.provider_env_revision += 1;
        assert!(log.changed(&snapshot, "invalid policy"));
        snapshot.policy_hash.push_str("changed");
        assert!(log.changed(&snapshot, "invalid policy"));
        snapshot.version += 1;
        assert!(log.changed(&snapshot, "invalid policy"));
        assert!(log.changed(&snapshot, "invalid provider"));
        assert!(!log.changed(&snapshot, "invalid provider"));
        assert!(log.changed(&snapshot, "invalid policy"));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_rejects_vm_identity_until_matching_policy_is_available() {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        let mut policy = proto_policy_fixture();
        enrich_proto_baseline_paths(&mut policy);
        policy.process = Some(openshell_core::proto::ProcessPolicy {
            run_as_user: "10000".into(),
            run_as_group: "1001".into(),
        });
        let (reports, mut reported) = tokio::sync::mpsc::unbounded_channel();
        let gateway = TestStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(settings_poll_result(
                Some(policy),
                1,
                PolicySource::Sandbox,
            ))),
            reports,
            reject_next_accept: Arc::new(AtomicBool::new(false)),
            snapshot_error: None,
            report_error: None,
            pending_snapshot: false,
            pending_acceptance: false,
        };
        let active_gateway = gateway.clone();
        let handle = tokio::spawn(async move {
            load_policy_with_gateway(
                Some("sandbox-id".into()),
                Some("sandbox".into()),
                Some("http://unused.invalid".into()),
                None,
                None,
                &openshell_extension_core::ExtensionCredentialStore::new(),
                LocalPolicyIdentity::Required,
                Some(VmPolicyIdentity {
                    uid: 1000,
                    gid: 1001,
                }),
                Some(ImagePolicyDiscovery::Missing),
                None,
                &active_gateway,
            )
            .await
        });
        assert_eq!(
            reported.recv().await,
            Some(ConfigurationAdmissionState::Pending)
        );
        assert_eq!(
            reported.recv().await,
            Some(ConfigurationAdmissionState::Rejected)
        );
        assert!(
            !handle.is_finished(),
            "mismatched policy must never be returned as effective"
        );
        {
            let mut desired = gateway.desired.lock().unwrap();
            desired
                .policy
                .as_mut()
                .unwrap()
                .process
                .as_mut()
                .unwrap()
                .run_as_user = "sandbox".into();
            desired.config_revision += 1;
        }
        assert_eq!(
            reported.recv().await,
            Some(ConfigurationAdmissionState::Accepted)
        );
        handle
            .await
            .unwrap()
            .expect("matching repair should permit startup");
    }

    #[test]
    fn vm_startup_identity_validates_selectors_independently() {
        let identity = VmPolicyIdentity {
            uid: 1000,
            gid: 1001,
        };
        for (user, group, accepted) in [
            ("", "", true),
            ("1000", "", true),
            ("", "1001", true),
            ("sandbox", "sandbox", true),
            ("10000", "", false),
            ("", "10001", false),
        ] {
            let policy = openshell_core::proto::SandboxPolicy {
                process: Some(openshell_core::proto::ProcessPolicy {
                    run_as_user: user.into(),
                    run_as_group: group.into(),
                }),
                ..Default::default()
            };
            assert_eq!(
                identity.validate(&policy).is_ok(),
                accepted,
                "{user}:{group}"
            );
        }
    }

    #[tokio::test]
    async fn vm_identity_conflict_prevents_runtime_policy_and_credential_commit() {
        let mut policy = proto_policy_fixture();
        let engine = OpaEngine::from_proto(&policy).unwrap();
        let before = engine.current_generation();
        policy.process = Some(openshell_core::proto::ProcessPolicy {
            run_as_user: "sandbox".into(),
            run_as_group: "10000".into(),
        });
        let committed = AtomicBool::new(false);
        let result = reload_gateway_configuration_runtime(
            &engine,
            Some(&policy),
            0,
            MiddlewareReloadContext {
                desired_services: &[],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: false,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState::default(),
            Some(VmPolicyIdentity {
                uid: 1000,
                gid: 1001,
            }),
            || {
                committed.store(true, Ordering::SeqCst);
            },
        )
        .await;
        let Err(GatewayRuntimeReloadError::PolicyValidation(error)) = result else {
            panic!("conflicting VM group should fail policy validation");
        };
        assert!(error.to_string().contains("run_as_group '10000'"));
        assert!(error.to_string().contains("1000:1001"));
        assert_eq!(engine.current_generation(), before);
        assert!(!committed.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_pending_gateway_calls_exhaust_their_budgets() {
        for pending_snapshot in [true, false] {
            let mut policy = proto_policy_fixture();
            enrich_proto_baseline_paths(&mut policy);
            let (reports, _reported) = tokio::sync::mpsc::unbounded_channel();
            let gateway = TestStartupGateway {
                desired: Arc::new(std::sync::Mutex::new(settings_poll_result(
                    Some(policy),
                    1,
                    openshell_core::proto::PolicySource::Sandbox,
                ))),
                reports,
                reject_next_accept: Arc::new(AtomicBool::new(false)),
                snapshot_error: None,
                report_error: None,
                pending_snapshot,
                pending_acceptance: !pending_snapshot,
            };
            let result = timeout(
                Duration::from_mins(2),
                load_policy_with_gateway(
                    Some("sandbox-id".to_string()),
                    Some("sandbox".to_string()),
                    Some("http://unused.invalid".to_string()),
                    None,
                    None,
                    &openshell_extension_core::ExtensionCredentialStore::new(),
                    LocalPolicyIdentity::Required,
                    None,
                    Some(ImagePolicyDiscovery::Missing),
                    None,
                    &gateway,
                ),
            )
            .await
            .expect("pending RPC must not hang startup");
            let Err(error) = result else {
                panic!("pending gateway unexpectedly admitted startup")
            };
            assert!(
                error.to_string().contains(if pending_snapshot {
                    "failed after 5 attempts"
                } else {
                    "did not stabilize after 5 attempts"
                }),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn startup_transient_gateway_errors_exhaust_retry_budget() {
        let calls = AtomicUsize::new(0);
        let result: Result<()> = timeout(
            Duration::from_secs(15),
            grpc_retry("Startup configuration fetch", || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(openshell_core::grpc_client::grpc_status_error(
                        tonic::Status::unavailable("gateway down"),
                    ))
                }
            }),
        )
        .await
        .expect("transient failure must have a bounded retry budget");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed after 5 attempts")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn startup_returns_permanent_gateway_errors_without_waiting_for_policy_repair() {
        for (snapshot_error, report_error) in [
            (Some(tonic::Code::PermissionDenied), None),
            (Some(tonic::Code::NotFound), None),
            (None, Some(tonic::Code::FailedPrecondition)),
        ] {
            let (reports, _reported) = tokio::sync::mpsc::unbounded_channel();
            let gateway = TestStartupGateway {
                desired: Arc::new(std::sync::Mutex::new(settings_poll_result(
                    None,
                    1,
                    openshell_core::proto::PolicySource::Sandbox,
                ))),
                reports,
                reject_next_accept: Arc::new(AtomicBool::new(false)),
                snapshot_error,
                report_error,
                pending_snapshot: false,
                pending_acceptance: false,
            };
            let result = timeout(
                Duration::from_secs(1),
                load_policy_with_gateway(
                    Some("sandbox-id".to_string()),
                    Some("sandbox".to_string()),
                    Some("http://unused.invalid".to_string()),
                    None,
                    None,
                    &openshell_extension_core::ExtensionCredentialStore::new(),
                    LocalPolicyIdentity::Required,
                    None,
                    Some(ImagePolicyDiscovery::Missing),
                    None,
                    &gateway,
                ),
            )
            .await
            .expect("permanent errors must terminate startup");
            let Err(error) = result else {
                panic!("startup unexpectedly succeeded")
            };
            assert!(!is_retryable_error(&error));
            assert!(error.to_string().contains(if report_error.is_some() {
                "registration fence changed"
            } else {
                "snapshot unavailable"
            }));
        }
    }

    #[tokio::test]
    async fn startup_waits_for_repair_and_retries_stale_activation_before_returning() {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        let mut policy = proto_policy_fixture();
        enrich_proto_baseline_paths(&mut policy);
        let mut rejected = settings_poll_result(Some(policy), 1, PolicySource::Sandbox);
        rejected.configuration_admitted = false;
        let (reports, mut reported) = tokio::sync::mpsc::unbounded_channel();
        let gateway = TestStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(rejected)),
            reports,
            reject_next_accept: Arc::new(AtomicBool::new(true)),
            snapshot_error: None,
            report_error: None,
            pending_snapshot: false,
            pending_acceptance: false,
        };
        let active_gateway = gateway.clone();
        let handle = tokio::spawn(async move {
            load_policy_with_gateway(
                Some("sandbox-id".to_string()),
                Some("sandbox".to_string()),
                Some("http://unused.invalid".to_string()),
                None,
                None,
                &openshell_extension_core::ExtensionCredentialStore::new(),
                LocalPolicyIdentity::Required,
                None,
                Some(ImagePolicyDiscovery::Missing),
                None,
                &active_gateway,
            )
            .await
        });
        assert_eq!(
            reported.recv().await,
            Some(ConfigurationAdmissionState::Pending)
        );
        assert_eq!(
            reported.recv().await,
            Some(ConfigurationAdmissionState::Rejected)
        );
        assert!(
            !handle.is_finished(),
            "rejected configuration must not return a launch bundle"
        );
        assert_eq!(
            timeout(Duration::from_secs(5), reported.recv())
                .await
                .unwrap(),
            Some(ConfigurationAdmissionState::Rejected),
            "unchanged rejection must still report readiness on subsequent polls"
        );
        {
            let mut desired = gateway.desired.lock().unwrap();
            desired.configuration_admitted = true;
            desired.config_revision += 1;
        }
        assert_eq!(
            timeout(Duration::from_secs(5), reported.recv())
                .await
                .unwrap(),
            Some(ConfigurationAdmissionState::Accepted)
        );
        assert!(
            !handle.is_finished(),
            "a stale activation acknowledgement must not return a launch bundle"
        );
        assert_eq!(
            timeout(Duration::from_secs(5), reported.recv())
                .await
                .unwrap(),
            Some(ConfigurationAdmissionState::Accepted)
        );
        let bundle = timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap()
            .expect("repair returns one launch bundle");
        assert!(
            bundle.7.is_some(),
            "launch bundle retains matching provider state"
        );
    }

    // ---- Startup policy write refusal tests ----

    /// `UpdateConfig` diagnostic for a credential binding whose provider is not
    /// attached to the sandbox. The gateway returns it as `FAILED_PRECONDITION`.
    const UNATTACHED_PROVIDER_DIAGNOSTIC: &str = "credential_binding references provider 'github', but that provider is not attached to the sandbox";

    /// The same refusal naming a second unattached provider of one policy. The
    /// gateway reports whichever unattached provider it meets first, so one
    /// policy can be refused with either message.
    const UNATTACHED_SECOND_PROVIDER_DIAGNOSTIC: &str = "credential_binding references provider 'gitlab', but that provider is not attached to the sandbox";

    /// `UpdateConfig` diagnostic for middleware configuration the gateway
    /// cannot validate. The gateway returns it as `INVALID_ARGUMENT`.
    const INVALID_MIDDLEWARE_DIAGNOSTIC: &str =
        "policy middleware validation failed: binding 'redact' has an invalid config";

    /// `UpdateConfig` diagnostic for any sandbox policy write while a global
    /// policy is active. The gateway returns it as `FAILED_PRECONDITION`.
    const GLOBAL_POLICY_DIAGNOSTIC: &str =
        "policy is managed globally; delete global policy before sandbox policy update";

    /// One gateway call made by startup, recorded in call order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum StartupCall {
        Snapshot,
        Sync,
        Report(StartupReport),
    }

    /// One admission report startup sent to the gateway.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StartupReport {
        state: openshell_core::proto::ConfigurationAdmissionState,
        error: String,
        /// Generation of the snapshot sent with the report. The gateway
        /// answers `ABORTED` to a `Rejected` or `Accepted` report whose
        /// generation is no longer current.
        generation: Option<ReportGeneration>,
    }

    /// `(version, policy_hash, config_revision, provider_env_revision)` of a
    /// snapshot, the fields the gateway compares when it admits a report.
    type ReportGeneration = (u32, String, u64, u64);

    fn report_generation(
        snapshot: &openshell_core::grpc_client::SettingsPollResult,
    ) -> ReportGeneration {
        (
            snapshot.version,
            snapshot.policy_hash.clone(),
            snapshot.config_revision,
            snapshot.provider_env_revision,
        )
    }

    /// Snapshot of a sandbox with no stored policy, as the gateway returns it:
    /// version 0 and an empty policy hash. The configuration and provider
    /// revisions are nonzero, so a report built from any other snapshot names
    /// a different generation.
    fn unset_policy_snapshot() -> openshell_core::grpc_client::SettingsPollResult {
        let mut snapshot =
            settings_poll_result(None, 0, openshell_core::proto::PolicySource::Sandbox);
        snapshot.policy_hash = String::new();
        snapshot.config_revision = 7;
        snapshot.provider_env_revision = 3;
        snapshot
    }

    /// A scripted refusal of one startup `UpdateConfig` write.
    #[derive(Clone)]
    struct SyncRefusal {
        code: tonic::Code,
        message: &'static str,
    }

    impl SyncRefusal {
        fn new(code: tonic::Code, message: &'static str) -> Self {
            Self { code, message }
        }
    }

    /// Startup gateway double for the two startup policy writes: the image
    /// policy upload and the baseline-path write-back.
    ///
    /// `sync` consumes the next scripted refusal and fails with its status,
    /// wrapped the way the remote client wraps it. While the desired policy is
    /// global, it refuses every write the way the gateway does. Otherwise,
    /// without a refusal, it stores the payload as the next policy revision and
    /// returns the new snapshot, as the gateway does for an accepted write.
    /// Every call is recorded, including the generation each report names.
    /// Reports for obsolete generations fail with `ABORTED`, as the gateway
    /// requires. Tests can install a repair before a refused write returns or
    /// script rejection-report errors to exercise retries and fatal failures.
    #[derive(Clone)]
    struct WriteRefusingStartupGateway {
        desired: Arc<std::sync::Mutex<openshell_core::grpc_client::SettingsPollResult>>,
        refusals: Arc<std::sync::Mutex<std::collections::VecDeque<SyncRefusal>>>,
        repair_after_refusal: Option<openshell_core::grpc_client::SettingsPollResult>,
        rejection_report_errors: Arc<std::sync::Mutex<std::collections::VecDeque<tonic::Code>>>,
        calls: UnboundedSender<StartupCall>,
    }

    #[tonic::async_trait]
    impl StartupGateway for WriteRefusingStartupGateway {
        async fn snapshot(
            &self,
            _sandbox: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.calls.send(StartupCall::Snapshot).unwrap();
            Ok(self.desired.lock().unwrap().clone())
        }
        async fn provider(
            &self,
            _id: &str,
        ) -> Result<openshell_core::grpc_client::ProviderEnvironmentResult> {
            Ok(startup_provider(
                self.desired.lock().unwrap().provider_env_revision,
            ))
        }
        async fn sync(
            &self,
            _sandbox: &str,
            policy: &openshell_core::proto::SandboxPolicy,
            _workspace: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.calls.send(StartupCall::Sync).unwrap();
            let mut desired = self.desired.lock().unwrap();
            // The gateway checks for a global policy before it validates the
            // payload, so this refusal does not consume a scripted one.
            let refusal = if desired.policy_source == openshell_core::proto::PolicySource::Global {
                Some(SyncRefusal::new(
                    tonic::Code::FailedPrecondition,
                    GLOBAL_POLICY_DIAGNOSTIC,
                ))
            } else {
                self.refusals.lock().unwrap().pop_front()
            };
            if let Some(refusal) = refusal {
                if let Some(repaired) = &self.repair_after_refusal {
                    *desired = repaired.clone();
                }
                return Err(
                    openshell_core::grpc_client::grpc_status_error(tonic::Status::new(
                        refusal.code,
                        refusal.message,
                    ))
                    .wrap_err("failed to sync policy to server"),
                );
            }
            let version = desired.version + 1;
            *desired = settings_poll_result(
                Some(policy.clone()),
                version,
                openshell_core::proto::PolicySource::Sandbox,
            );
            Ok(desired.clone())
        }
        async fn report(
            &self,
            _id: &str,
            _instance_id: &str,
            snapshot: Option<&openshell_core::grpc_client::SettingsPollResult>,
            state: openshell_core::proto::ConfigurationAdmissionState,
            error: &str,
        ) -> Result<()> {
            self.calls
                .send(StartupCall::Report(StartupReport {
                    state,
                    error: error.to_owned(),
                    generation: snapshot.map(report_generation),
                }))
                .unwrap();
            if state == openshell_core::proto::ConfigurationAdmissionState::Rejected
                && let Some(code) = self.rejection_report_errors.lock().unwrap().pop_front()
            {
                return Err(
                    openshell_core::grpc_client::grpc_status_error(tonic::Status::new(
                        code,
                        "rejection report failed",
                    ))
                    .wrap_err("failed to report sandbox configuration"),
                );
            }
            if matches!(
                state,
                openshell_core::proto::ConfigurationAdmissionState::Rejected
                    | openshell_core::proto::ConfigurationAdmissionState::Accepted
            ) && snapshot.map(report_generation)
                != Some(report_generation(&self.desired.lock().unwrap()))
            {
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::aborted("configuration generation has changed"),
                )
                .wrap_err("failed to report sandbox configuration"));
            }
            Ok(())
        }
    }

    /// Waits for startup's next admission report and returns it together with
    /// the snapshot and write calls startup made since the previous report. If
    /// startup returns first, the test fails with startup's result.
    async fn next_startup_report<T>(
        calls: &mut tokio::sync::mpsc::UnboundedReceiver<StartupCall>,
        startup: &mut tokio::task::JoinHandle<Result<T>>,
    ) -> (Vec<StartupCall>, StartupReport) {
        let mut preceding = Vec::new();
        loop {
            tokio::select! {
                // Drain recorded calls before startup's result so a report sent
                // just before startup returned is still observed.
                biased;
                call = calls.recv() => match call {
                    Some(StartupCall::Report(report)) => return (preceding, report),
                    Some(call) => preceding.push(call),
                    None => panic!("the test gateway call channel closed"),
                },
                result = &mut *startup => match result.expect("startup task panicked") {
                    Ok(_) => panic!("startup accepted a configuration before the expected report"),
                    Err(error) => panic!(
                        "startup exited instead of reporting: {}",
                        startup_error_chain(&error)
                    ),
                },
            }
        }
    }

    /// Formats startup's error chain on one line. The gRPC status wrapper
    /// displays the same text as the status it wraps, so repeats are dropped.
    fn startup_error_chain(error: &miette::Report) -> String {
        let mut causes: Vec<String> = error.chain().map(ToString::to_string).collect();
        causes.dedup();
        causes.join(": ")
    }

    /// Starts a sandbox against a gateway that refuses the startup policy write
    /// described by `write` once for each entry of `refusals`, then checks the
    /// repair flow the policy documentation promises. On every refused pass,
    /// startup reads a fresh snapshot, sends the write again, and reports
    /// `Rejected` with the gateway's diagnostic against `initial`, the snapshot
    /// the refused write was built from, while it keeps waiting. Once an
    /// operator stores `repaired`, the next snapshot is accepted and startup
    /// installs that policy.
    async fn assert_refused_startup_write_waits_for_repair(
        initial: openshell_core::grpc_client::SettingsPollResult,
        discovery: ImagePolicyDiscovery,
        write: &str,
        refusals: Vec<SyncRefusal>,
        repaired: openshell_core::proto::SandboxPolicy,
    ) {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        let refused_generation = report_generation(&initial);
        let diagnostics: Vec<String> = refusals
            .iter()
            .map(|refusal| format!("Gateway rejected the {write}: {}", refusal.message))
            .collect();
        let (calls, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let gateway = WriteRefusingStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(initial)),
            refusals: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(
                refusals,
            ))),
            repair_after_refusal: None,
            rejection_report_errors: Arc::default(),
            calls,
        };
        let startup_gateway = gateway.clone();
        let mut startup = tokio::spawn(async move {
            load_policy_with_gateway(
                Some("sandbox-id".to_string()),
                Some("sandbox".to_string()),
                Some("http://unused.invalid".to_string()),
                None,
                None,
                &openshell_extension_core::ExtensionCredentialStore::new(),
                LocalPolicyIdentity::Required,
                None,
                Some(discovery),
                None,
                &startup_gateway,
            )
            .await
        });
        // A regression that keeps looping without the expected report fails at
        // this deadline instead of hanging; the paused clock makes it free.
        timeout(Duration::from_mins(1), async {
            let (_, registration) = next_startup_report(&mut observed, &mut startup).await;
            assert_eq!(registration.state, ConfigurationAdmissionState::Pending);
            for (pass, diagnostic) in diagnostics.into_iter().enumerate() {
                let (preceding, report) = next_startup_report(&mut observed, &mut startup).await;
                assert_eq!(
                    preceding,
                    [StartupCall::Snapshot, StartupCall::Sync],
                    "refused pass {pass}: startup must read a fresh snapshot and send the write again"
                );
                assert_eq!(
                    report,
                    StartupReport {
                        state: ConfigurationAdmissionState::Rejected,
                        error: diagnostic,
                        generation: Some(refused_generation.clone()),
                    },
                    "refused pass {pass}: the rejection must carry the gateway diagnostic and name the snapshot the refused write was built from"
                );
                assert!(
                    !startup.is_finished(),
                    "refused pass {pass}: a refused startup write must leave the sandbox waiting for repair"
                );
            }
            {
                let mut desired = gateway.desired.lock().unwrap();
                let version = desired.version + 1;
                *desired =
                    settings_poll_result(Some(repaired.clone()), version, PolicySource::Sandbox);
            }
            let (_, accepted) = next_startup_report(&mut observed, &mut startup).await;
            assert_eq!(accepted.state, ConfigurationAdmissionState::Accepted);
            let bundle = (&mut startup)
                .await
                .unwrap()
                .expect("the repaired configuration returns one launch bundle");
            assert_eq!(
                bundle.2,
                Some(repaired),
                "startup must install the repaired policy"
            );
        })
        .await
        .expect("startup must report every refusal and then accept the repair");
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_failed_precondition_waits_for_repair() {
        // The gateway has no policy, so startup uploads the image policy.
        assert_refused_startup_write_waits_for_repair(
            unset_policy_snapshot(),
            ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            "image policy",
            vec![SyncRefusal::new(
                tonic::Code::FailedPrecondition,
                UNATTACHED_PROVIDER_DIAGNOSTIC,
            )],
            proto_policy_fixture(),
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_invalid_argument_waits_for_repair() {
        assert_refused_startup_write_waits_for_repair(
            unset_policy_snapshot(),
            ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            "image policy",
            vec![SyncRefusal::new(
                tonic::Code::InvalidArgument,
                INVALID_MIDDLEWARE_DIAGNOSTIC,
            )],
            proto_policy_fixture(),
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_baseline_write_back_waits_for_repair() {
        // The gateway policy has network rules but lacks the proxy baseline
        // paths, so startup writes an enriched copy back. The repaired policy
        // already carries those paths and needs no write-back.
        let mut repaired = proto_tcp_policy_fixture();
        assert!(enrich_proto_baseline_paths(&mut repaired));
        assert_refused_startup_write_waits_for_repair(
            settings_poll_result(
                Some(proto_tcp_policy_fixture()),
                1,
                openshell_core::proto::PolicySource::Sandbox,
            ),
            ImagePolicyDiscovery::Missing,
            "policy update that adds baseline filesystem paths",
            vec![SyncRefusal::new(
                tonic::Code::FailedPrecondition,
                UNATTACHED_PROVIDER_DIAGNOSTIC,
            )],
            repaired,
        )
        .await;
    }

    /// Install an operator's repair after the refused write but before its
    /// rejection report. The obsolete report must lead straight to a new
    /// snapshot, without resending the write or delaying the repaired launch.
    async fn assert_startup_repair_before_rejection_refetches(
        initial: openshell_core::grpc_client::SettingsPollResult,
        discovery: ImagePolicyDiscovery,
        repaired: openshell_core::proto::SandboxPolicy,
        refusal: SyncRefusal,
        write: &str,
    ) {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        let initial_generation = report_generation(&initial);
        let repaired_snapshot = settings_poll_result(
            Some(repaired.clone()),
            initial.version + 1,
            PolicySource::Sandbox,
        );
        let repaired_generation = report_generation(&repaired_snapshot);
        let diagnostic = format!("Gateway rejected the {write}: {}", refusal.message);
        let (calls, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let gateway = WriteRefusingStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(initial)),
            refusals: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from([
                refusal,
            ]))),
            repair_after_refusal: Some(repaired_snapshot),
            rejection_report_errors: Arc::default(),
            calls,
        };
        let started = tokio::time::Instant::now();
        let bundle = timeout(
            Duration::from_secs(30),
            load_policy_with_gateway(
                Some("sandbox-id".to_string()),
                Some("sandbox".to_string()),
                Some("http://unused.invalid".to_string()),
                None,
                None,
                &openshell_extension_core::ExtensionCredentialStore::new(),
                LocalPolicyIdentity::Required,
                None,
                Some(discovery),
                None,
                &gateway,
            ),
        )
        .await
        .expect("a superseded rejection must not stall startup")
        .unwrap_or_else(|error| {
            panic!(
                "a repair that precedes its rejection report must resume startup: {}",
                startup_error_chain(&error)
            )
        });
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "a superseded rejection must fetch the repaired generation immediately"
        );
        let mut trace = Vec::new();
        while let Ok(call) = observed.try_recv() {
            trace.push(call);
        }
        assert_eq!(
            trace,
            [
                StartupCall::Snapshot,
                StartupCall::Report(StartupReport {
                    state: ConfigurationAdmissionState::Pending,
                    error: String::new(),
                    generation: Some(initial_generation.clone()),
                }),
                StartupCall::Snapshot,
                StartupCall::Sync,
                StartupCall::Report(StartupReport {
                    state: ConfigurationAdmissionState::Rejected,
                    error: diagnostic,
                    generation: Some(initial_generation),
                }),
                StartupCall::Snapshot,
                StartupCall::Report(StartupReport {
                    state: ConfigurationAdmissionState::Accepted,
                    error: String::new(),
                    generation: Some(repaired_generation),
                }),
            ],
            "startup must discard the obsolete rejection and validate the repair"
        );
        assert_eq!(bundle.2, Some(repaired));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_image_repair_before_report_refetches() {
        Box::pin(assert_startup_repair_before_rejection_refetches(
            unset_policy_snapshot(),
            ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            proto_policy_fixture(),
            SyncRefusal::new(
                tonic::Code::FailedPrecondition,
                UNATTACHED_PROVIDER_DIAGNOSTIC,
            ),
            "image policy",
        ))
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_baseline_repair_before_report_refetches() {
        let mut repaired = proto_tcp_policy_fixture();
        assert!(enrich_proto_baseline_paths(&mut repaired));
        Box::pin(assert_startup_repair_before_rejection_refetches(
            settings_poll_result(
                Some(proto_tcp_policy_fixture()),
                1,
                openshell_core::proto::PolicySource::Sandbox,
            ),
            ImagePolicyDiscovery::Missing,
            repaired,
            SyncRefusal::new(tonic::Code::InvalidArgument, INVALID_MIDDLEWARE_DIAGNOSTIC),
            "policy update that adds baseline filesystem paths",
        ))
        .await;
    }

    /// Exercise rejection reporting directly so transport and identity errors
    /// cannot be mistaken for policy-write failures or registration failures.
    async fn startup_rejection_report_with_errors(
        errors: Vec<tonic::Code>,
    ) -> (Result<()>, Vec<StartupCall>, Duration, StartupRejectionLog) {
        let snapshot = unset_policy_snapshot();
        let (calls, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let gateway = WriteRefusingStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(snapshot.clone())),
            refusals: Arc::default(),
            repair_after_refusal: None,
            rejection_report_errors: Arc::new(std::sync::Mutex::new(errors.into())),
            calls,
        };
        let mut log = StartupRejectionLog::default();
        let started = tokio::time::Instant::now();
        let result = reject_startup_configuration(
            &gateway,
            &mut log,
            "sandbox-id",
            "instance-id",
            &snapshot,
            "policy write refused",
            None,
        )
        .await;
        let mut trace = Vec::new();
        while let Ok(call) = observed.try_recv() {
            trace.push(call);
        }
        assert!(trace.iter().all(|call| matches!(
            call,
            StartupCall::Report(report)
                if report.state == openshell_core::proto::ConfigurationAdmissionState::Rejected
                    && report.generation == Some(report_generation(&snapshot))
                    && report.error == "policy write refused"
        )));
        (result, trace, started.elapsed(), log)
    }

    #[tokio::test(start_paused = true)]
    async fn startup_rejection_report_aborted_after_transient_failure_refetches() {
        let (result, trace, elapsed, log) = startup_rejection_report_with_errors(vec![
            tonic::Code::Unavailable,
            tonic::Code::Aborted,
        ])
        .await;
        result.expect("a superseded report must return to reconciliation");
        assert_eq!(trace.len(), 2, "an obsolete report must not be resent");
        assert_eq!(elapsed, Duration::from_secs(1));
        assert!(log.0.is_none(), "an obsolete rejection must not be logged");
    }

    #[tokio::test(start_paused = true)]
    async fn startup_rejection_report_transient_failure_retries_and_logs() {
        let (result, trace, elapsed, log) =
            startup_rejection_report_with_errors(vec![tonic::Code::Unavailable]).await;
        result.expect("a transient report failure must retry");
        assert_eq!(trace.len(), 2);
        assert_eq!(elapsed, Duration::from_secs(3));
        assert_eq!(
            log.0,
            Some((
                LoadedPolicyRevision::from_snapshot(&unset_policy_snapshot()),
                "policy write refused".to_string(),
            )),
            "a recorded rejection must retain its diagnostic for log suppression"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn startup_rejection_report_transient_exhaustion_stays_fatal() {
        let (result, trace, elapsed, log) =
            startup_rejection_report_with_errors(vec![tonic::Code::Unavailable; 5]).await;
        let error = result.expect_err("exhausted report retries must terminate startup");
        assert!(error.to_string().contains("failed after 5 attempts"));
        assert_eq!(trace.len(), 5);
        assert_eq!(elapsed, Duration::from_secs(11));
        assert!(log.0.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn startup_rejection_report_permanent_failure_stays_fatal() {
        for code in [
            tonic::Code::FailedPrecondition,
            tonic::Code::InvalidArgument,
            tonic::Code::PermissionDenied,
            tonic::Code::NotFound,
            tonic::Code::Unauthenticated,
        ] {
            let (result, trace, elapsed, log) =
                startup_rejection_report_with_errors(vec![code]).await;
            let error = result.expect_err("a permanent report failure must terminate startup");
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<tonic::Status>()
                    .is_some_and(|status| status.code() == code)
            }));
            assert_eq!(trace.len(), 1, "{code:?} must not be retried");
            assert_eq!(elapsed, Duration::ZERO);
            assert!(log.0.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_image_upload_outlasts_the_attempt_limit() {
        // Startup gives up after five passes that neither accept nor reject a
        // configuration. A refused upload is a rejection, so the same refusal
        // repeated seven times must keep the sandbox waiting for repair.
        assert_refused_startup_write_waits_for_repair(
            unset_policy_snapshot(),
            ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            "image policy",
            vec![
                SyncRefusal::new(
                    tonic::Code::FailedPrecondition,
                    UNATTACHED_PROVIDER_DIAGNOSTIC
                );
                7
            ],
            proto_policy_fixture(),
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_write_back_outlasts_the_attempt_limit() {
        // The same limit applies to a refused baseline-path write-back.
        let mut repaired = proto_tcp_policy_fixture();
        assert!(enrich_proto_baseline_paths(&mut repaired));
        assert_refused_startup_write_waits_for_repair(
            settings_poll_result(
                Some(proto_tcp_policy_fixture()),
                1,
                openshell_core::proto::PolicySource::Sandbox,
            ),
            ImagePolicyDiscovery::Missing,
            "policy update that adds baseline filesystem paths",
            vec![
                SyncRefusal::new(
                    tonic::Code::FailedPrecondition,
                    UNATTACHED_PROVIDER_DIAGNOSTIC
                );
                7
            ],
            repaired,
        )
        .await;
    }

    /// Collects the sandbox log lines that a test's OCSF events render to.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_logs_a_varying_gateway_message_once() {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        // One policy with two unattached providers is refused with either
        // provider's name on each attempt. The snapshot does not change, so the
        // sandbox log must record the refusal once, with the first message,
        // while every report still carries the message of its own attempt.
        let log = CapturedLog::default();
        // Keep two dispatchers alive so tracing consults registered subscribers
        // when caching callsite interest. With only one, a parallel test thread
        // without a default subscriber can cache `Interest::never` for our events.
        let _other_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let _subscriber = tracing_subscriber::registry()
            .with(openshell_ocsf::OcsfShorthandLayer::new(log.clone()).with_non_ocsf(false))
            .set_default();
        let first = SyncRefusal::new(
            tonic::Code::FailedPrecondition,
            UNATTACHED_PROVIDER_DIAGNOSTIC,
        );
        let second = SyncRefusal::new(
            tonic::Code::FailedPrecondition,
            UNATTACHED_SECOND_PROVIDER_DIAGNOSTIC,
        );
        assert_refused_startup_write_waits_for_repair(
            unset_policy_snapshot(),
            ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            "image policy",
            vec![first.clone(), second.clone(), first, second],
            proto_policy_fixture(),
        )
        .await;
        let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        let logged: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("Gateway rejected the image policy"))
            .collect();
        assert_eq!(
            logged.len(),
            1,
            "an unchanged refusal must be logged once; log:\n{log}"
        );
        assert!(
            logged[0].contains(UNATTACHED_PROVIDER_DIAGNOSTIC),
            "the log must keep the gateway's first message; log:\n{log}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_global_policy_skips_baseline_write_back() {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        // The gateway serves a global policy that has network rules but lacks
        // the proxy baseline paths. It refuses every sandbox policy write while
        // that policy is active, so startup must add the paths locally and
        // install the policy without writing it back.
        let mut global =
            settings_poll_result(Some(proto_tcp_policy_fixture()), 1, PolicySource::Global);
        global.global_policy_version = 1;
        let global_generation = report_generation(&global);
        let mut enriched = proto_tcp_policy_fixture();
        assert!(enrich_proto_baseline_paths(&mut enriched));
        let (calls, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let gateway = WriteRefusingStartupGateway {
            desired: Arc::new(std::sync::Mutex::new(global)),
            refusals: Arc::default(),
            repair_after_refusal: None,
            rejection_report_errors: Arc::default(),
            calls,
        };
        let bundle = timeout(
            Duration::from_mins(1),
            load_policy_with_gateway(
                Some("sandbox-id".to_string()),
                Some("sandbox".to_string()),
                Some("http://unused.invalid".to_string()),
                None,
                None,
                &openshell_extension_core::ExtensionCredentialStore::new(),
                LocalPolicyIdentity::Required,
                None,
                Some(ImagePolicyDiscovery::Missing),
                None,
                &gateway,
            ),
        )
        .await
        .expect("startup must not wait for repair under a global policy")
        .unwrap_or_else(|error| {
            panic!(
                "startup exited under a global policy: {}",
                startup_error_chain(&error)
            )
        });
        let mut trace = Vec::new();
        while let Ok(call) = observed.try_recv() {
            trace.push(call);
        }
        let report = |state| {
            StartupCall::Report(StartupReport {
                state,
                error: String::new(),
                generation: Some(global_generation.clone()),
            })
        };
        assert_eq!(
            trace,
            [
                StartupCall::Snapshot,
                report(ConfigurationAdmissionState::Pending),
                StartupCall::Snapshot,
                report(ConfigurationAdmissionState::Accepted),
            ],
            "startup must not write a global policy back as a sandbox policy"
        );
        assert_eq!(
            bundle.2,
            Some(enriched),
            "startup installs the global policy with the baseline paths added"
        );
        let LoadedPolicyOrigin::Gateway {
            revision: Some(revision),
            ..
        } = bundle.4
        else {
            panic!("startup must bind the global policy to its gateway revision");
        };
        assert_eq!(revision.policy_source, PolicySource::Global);
    }

    #[tokio::test(start_paused = true)]
    async fn startup_policy_write_refusal_permanent_codes_still_exit() {
        use openshell_core::proto::{ConfigurationAdmissionState, PolicySource};
        // No policy or provider change repairs these refusals, so startup
        // keeps exiting instead of holding the sandbox in its repair window.
        // Both writes are checked: the image policy upload to a gateway with
        // no policy, and the write-back of a stored policy that lacks the
        // proxy baseline paths.
        let writes = [
            (
                "image policy upload",
                unset_policy_snapshot(),
                ImagePolicyDiscovery::Policy(Box::new(proto_tcp_policy_fixture())),
            ),
            (
                "baseline write-back",
                settings_poll_result(Some(proto_tcp_policy_fixture()), 1, PolicySource::Sandbox),
                ImagePolicyDiscovery::Missing,
            ),
        ];
        for (write, initial, discovery) in writes {
            for code in [
                tonic::Code::PermissionDenied,
                tonic::Code::NotFound,
                tonic::Code::Unauthenticated,
            ] {
                let (calls, mut observed) = tokio::sync::mpsc::unbounded_channel();
                let gateway = WriteRefusingStartupGateway {
                    desired: Arc::new(std::sync::Mutex::new(initial.clone())),
                    refusals: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from([
                        SyncRefusal::new(code, "sandbox caller cannot write this policy"),
                    ]))),
                    repair_after_refusal: None,
                    rejection_report_errors: Arc::default(),
                    calls,
                };
                let result = timeout(
                    Duration::from_mins(1),
                    load_policy_with_gateway(
                        Some("sandbox-id".to_string()),
                        Some("sandbox".to_string()),
                        Some("http://unused.invalid".to_string()),
                        None,
                        None,
                        &openshell_extension_core::ExtensionCredentialStore::new(),
                        LocalPolicyIdentity::Required,
                        None,
                        Some(discovery.clone()),
                        None,
                        &gateway,
                    ),
                )
                .await
                .expect("a permanent write error must end startup");
                let Err(error) = result else {
                    panic!("{write}: startup accepted a configuration after {code:?}");
                };
                assert!(
                    startup_error_chain(&error).contains("sandbox caller cannot write this policy"),
                    "{write}, {code:?}: {}",
                    startup_error_chain(&error)
                );
                let mut trace = Vec::new();
                while let Ok(call) = observed.try_recv() {
                    trace.push(call);
                }
                assert!(
                    !trace.iter().any(|call| matches!(
                        call,
                        StartupCall::Report(report)
                            if report.state == ConfigurationAdmissionState::Rejected
                    )),
                    "{write}, {code:?} is not a configuration rejection; calls: {trace:?}"
                );
            }
        }
    }

    #[test]
    fn startup_policy_write_refusal_bounds_the_gateway_message() {
        let refused = openshell_core::grpc_client::grpc_status_error(
            tonic::Status::invalid_argument(format!("bad\nrule {}", "x".repeat(600))),
        )
        .wrap_err("failed to sync policy to server");
        // The log key leaves out the gateway's message, so a refusal whose
        // wording changes between attempts is logged once per snapshot.
        assert_eq!(
            startup_write_rejection("image policy", &refused),
            Some(StartupWriteRejection {
                diagnostic: format!(
                    "Gateway rejected the image policy: badrule {}",
                    "x".repeat(504)
                ),
                log_key: "Gateway rejected the image policy (InvalidArgument)".to_owned(),
            })
        );
        // Exhausted transient retries and connection failures carry no status
        // and stay fatal.
        assert_eq!(
            startup_write_rejection(
                "image policy",
                &miette::miette!("Image policy synchronization failed after 5 attempts")
            ),
            None
        );
    }

    pub fn startup_provider(
        revision: u64,
    ) -> openshell_core::grpc_client::ProviderEnvironmentResult {
        openshell_core::grpc_client::ProviderEnvironmentResult {
            files: std::collections::HashMap::new(),
            provider_env_revision: revision,
            provider_attachment_epoch: String::new(),
            policy_hash: String::new(),
            readiness_reason: ProviderReadinessReason::Unspecified,
            environment: std::collections::HashMap::new(),
            credential_expires_at_ms: std::collections::HashMap::new(),
            dynamic_credentials: std::collections::HashMap::new(),
            static_credential_bindings: std::collections::HashMap::new(),
            non_secret_environment_keys: Vec::new(),
        }
    }

    #[test]
    fn startup_configuration_rejects_mixed_provider_revision() {
        let policy = proto_policy_fixture();
        let mut snapshot = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        snapshot.provider_env_revision = 10;
        assert!(prepare_startup_configuration(&snapshot, &policy, &startup_provider(11)).is_err());
        let (_, _, credentials) =
            prepare_startup_configuration(&snapshot, &policy, &startup_provider(10))
                .expect("matching generation is admitted");
        assert_eq!(credentials.revision(), 10);
    }

    #[test]
    fn startup_environment_seeds_provider_readiness() {
        let mut provider = startup_provider(10);
        provider.provider_attachment_epoch = "epoch".to_string();
        provider.policy_hash = "policy".to_string();
        let identity = EnvironmentIdentity::from_environment(&provider);
        let credentials = prepare_provider_environment(&provider).unwrap();
        let readiness = ProviderReadinessTracker::new();

        let credentials =
            CapturedProviderEnvironment::new(credentials, &provider).install(&readiness);

        assert_eq!(credentials.revision(), 10);
        assert!(!readiness.needs_environment(&identity));
    }

    #[test]
    fn startup_configuration_accepts_fail_closed_provider_environment() {
        let policy = proto_policy_fixture();
        let mut snapshot = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        snapshot.provider_env_revision = 10;

        for reason in [
            ProviderReadinessReason::CredentialsWithheld,
            ProviderReadinessReason::CredentialExpired,
        ] {
            let mut provider = startup_provider(10);
            provider.readiness_reason = reason;
            provider
                .environment
                .insert("PROJECT_ID".to_string(), "example-project".to_string());
            provider
                .non_secret_environment_keys
                .push("PROJECT_ID".to_string());
            let (_, _, credentials) = prepare_startup_configuration(&snapshot, &policy, &provider)
                .expect("withheld credentials preserve fail-closed startup");
            assert_eq!(credentials.revision(), 10);
            assert!(credentials.snapshot().child_env.contains_key("PROJECT_ID"));
        }
    }

    #[test]
    fn startup_configuration_rejects_provider_installation_failure() {
        let policy = proto_policy_fixture();
        let snapshot = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let mut provider = startup_provider(0);
        provider.readiness_reason = ProviderReadinessReason::CredentialInstallFailed;

        assert!(prepare_startup_configuration(&snapshot, &policy, &provider).is_err());
    }

    #[test]
    fn startup_configuration_revalidates_on_restart_and_accepts_repair() {
        let policy = proto_policy_fixture();
        let mut snapshot = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        for _restart in 0..2 {
            snapshot.configuration_admitted = false;
            assert!(
                prepare_startup_configuration(&snapshot, &policy, &startup_provider(0)).is_err()
            );
            snapshot.configuration_admitted = true;
            assert!(
                prepare_startup_configuration(&snapshot, &policy, &startup_provider(0)).is_ok()
            );
        }
    }

    #[test]
    fn startup_configuration_does_not_substitute_invalid_opa_policy() {
        let mut policy = proto_tcp_policy_fixture();
        policy
            .network_policies
            .values_mut()
            .next()
            .expect("fixture has policy")
            .endpoints[0]
            .protocol = "invalid-protocol".to_string();
        let snapshot = settings_poll_result(
            Some(policy.clone()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        assert!(prepare_startup_configuration(&snapshot, &policy, &startup_provider(0)).is_err());
    }

    fn proto_provenance_policy_fixture() -> openshell_core::proto::SandboxPolicy {
        let mut policy = proto_tcp_policy_fixture();
        policy.landlock = proto_policy_fixture().landlock;
        let endpoint = &mut policy.network_policies.get_mut("redis").unwrap().endpoints[0];
        endpoint.host = "allowed.example.com".into();
        endpoint.port = 443;
        endpoint.ports = vec![443];
        endpoint.protocol.clear();
        // Typed validation must retain gateway provenance so OPA can apply
        // credential guards and distinguish advisor-proposed endpoints.
        endpoint.provider_credentialed = true;
        endpoint.advisor_proposed = true;
        policy
    }

    fn assert_gateway_policy_authorization(
        engine: &OpaEngine,
        allowed_host: &str,
        generation: u64,
    ) {
        use openshell_supervisor_network::opa::{NetworkAction, NetworkInput};

        assert_eq!(engine.current_generation(), generation);
        for host in ["allowed.example.com", "repaired.example.com"] {
            let input = NetworkInput {
                host: host.into(),
                port: 443,
                binary_path: "/usr/bin/redis-cli".into(),
                binary_sha256: String::new(),
                ancestors: vec![],
                cmdline_paths: vec![],
            };
            let authorization = engine.authorize_egress(&input).expect("authorize endpoint");
            assert_eq!(authorization.generation, generation);
            assert_eq!(
                matches!(authorization.action, NetworkAction::Allow { .. }),
                host == allowed_host,
                "unexpected authorization for {host}"
            );
            if host == allowed_host {
                assert!(!authorization.exact_declared_endpoint_host);
                let guards = engine
                    .query_endpoint_credential_guards(&input)
                    .expect("query credential provenance");
                assert_eq!(guards.len(), 1);
                assert!(
                    openshell_supervisor_network::l7::parse_endpoint_credential_guard(&guards[0])
                        .provider_credentialed
                );
            }
        }
    }

    async fn assert_gateway_reload_rejects_and_repairs(registry_changed: bool) {
        let policy = proto_provenance_policy_fixture();
        let engine = OpaEngine::from_proto(&policy).expect("build initial gateway policy");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install initial registry");
        let generation = engine.current_generation();
        assert_gateway_policy_authorization(&engine, "allowed.example.com", generation);

        let connections = Arc::new(AtomicUsize::new(0));
        let connections_for_connector = connections.clone();
        let connector: MiddlewareConnector = Arc::new(move |services, authentication| {
            connections_for_connector.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { connect_middleware_registry(&services, &authentication).await })
        });
        let authentication = MiddlewareAuthentication::default();
        let middleware = || MiddlewareReloadContext {
            desired_services: &[],
            authentication: &authentication,
            registry_changed,
            connector: &connector,
        };
        let mut candidate = policy;
        candidate.landlock.as_mut().unwrap().compatibility = "unsupported".into();
        candidate
            .network_policies
            .get_mut("redis")
            .unwrap()
            .endpoints[0]
            .host = "repaired.example.com".into();
        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&candidate),
            0,
            middleware(),
            TransparentTcpReloadState::default(),
        )
        .await
        .expect_err("invalid protobuf scalar must reject the complete candidate");
        assert!(matches!(
            failure,
            GatewayRuntimeReloadError::PolicyValidation(_)
        ));
        let disposition = apply_gateway_runtime_reload_failure(
            &engine,
            failure,
            PolicyValidationFailureMode::RetainLastValid,
            true,
            2,
        )
        .expect("retain accepted runtime");
        assert!(matches!(
            disposition,
            GatewayRuntimeFailureDisposition::PolicyRejected { disposition, .. }
                if disposition.previous_policy_active && disposition.active_generation == generation
        ));
        assert!(engine.fail_closed_reason().is_none());
        assert_gateway_policy_authorization(&engine, "allowed.example.com", generation);

        // Repair only the rejected scalar: the endpoint change must now install
        // with both runtime provenance flags and one new generation.
        candidate.landlock.as_mut().unwrap().compatibility = "best_effort".into();
        reload_gateway_policy_runtime(
            &engine,
            Some(&candidate),
            0,
            middleware(),
            TransparentTcpReloadState::default(),
        )
        .await
        .expect("install repaired gateway policy");
        assert_gateway_policy_authorization(&engine, "repaired.example.com", generation + 1);
        assert_eq!(
            connections.load(Ordering::Relaxed),
            if registry_changed { 2 } else { 0 }
        );
    }

    #[tokio::test]
    async fn gateway_policy_only_reload_rejects_candidate_retains_policy_and_accepts_repair() {
        assert_gateway_reload_rejects_and_repairs(false).await;
    }

    #[tokio::test]
    async fn gateway_policy_and_registry_reload_rejects_candidate_retains_policy_and_accepts_repair()
     {
        assert_gateway_reload_rejects_and_repairs(true).await;
    }

    #[tokio::test]
    async fn local_file_startup_normalizes_matchers_and_rejects_malformed_policy() {
        use openshell_supervisor_network::opa::NetworkInput;

        let files = tempfile::tempdir().expect("policy directory");
        let rules_path = files.path().join("policy.rego");
        let data_path = files.path().join("policy.yaml");
        std::fs::write(
            &rules_path,
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
        )
        .expect("write policy rules");
        std::fs::write(
            &data_path,
            r#"
network_policies:
  startup:
    endpoints:
      - host: startup.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**", query: { scope: "public-*" } }
    binaries:
      - { path: /usr/bin/curl }
"#,
        )
        .expect("write raw policy");
        let credentials = openshell_extension_core::ExtensionCredentialStore::new();
        let startup = || {
            load_policy(
                None,
                None,
                None,
                Some(rules_path.to_string_lossy().into_owned()),
                Some(data_path.to_string_lossy().into_owned()),
                &credentials,
                LocalPolicyIdentity::Required,
            )
        };
        let (
            _,
            engine,
            proto,
            registry,
            origin,
            proposals,
            extension_authentication_enabled,
            provider_credentials,
        ) = startup().await.expect("load valid local policy");
        assert!(provider_credentials.is_none());
        assert!(proto.is_none());
        assert!(matches!(origin, LoadedPolicyOrigin::LocalOverride));
        assert!(matches!(registry, MiddlewareRegistryStatus::Synchronized));
        assert!(!proposals && !extension_authentication_enabled);
        let engine = engine.expect("local startup installs OPA");
        assert!(engine.binary_identity_required());
        // Installing the built-in registry creates the first active generation.
        assert_eq!(engine.current_generation(), 1);

        let mut input = NetworkInput {
            host: "startup.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        assert!(
            engine
                .evaluate_network(&input)
                .expect("allowed binary")
                .allowed
        );
        let endpoint = engine
            .query_endpoint_config(&input)
            .expect("query startup endpoint")
            .expect("startup endpoint must exist");
        let endpoint: serde_json::Value =
            serde_json::from_str(&endpoint.to_json_str().expect("serialize endpoint"))
                .expect("endpoint JSON");
        assert_eq!(
            endpoint["rules"][0]["allow"]["query"]["scope"],
            serde_json::json!({ "glob": "public-*" }),
        );
        input.binary_path = "/usr/bin/unlisted".into();
        assert!(
            !engine
                .evaluate_network(&input)
                .expect("unlisted binary")
                .allowed
        );

        // A malformed new startup must fail before returning an active evaluator.
        std::fs::write(&data_path, "network_policies: []\n").expect("write malformed policy");
        let Err(error) = startup().await else {
            panic!("malformed startup must reject");
        };
        assert!(
            error
                .to_string()
                .contains("network_policies must be an object")
        );
    }

    #[tokio::test]
    async fn failed_external_startup_registry_build_preserves_installed_builtins() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let builtins_generation = engine.current_generation();
        assert_eq!(builtins_generation, 1);

        let invalid_external = openshell_core::proto::SupervisorMiddlewareService {
            name: "unavailable-guard".into(),
            grpc_endpoint: "http://127.0.0.1:1".into(),
            max_payload_bytes: 1024,
            ..Default::default()
        };
        connect_middleware_registry(&[invalid_external], &MiddlewareAuthentication::default())
            .await
            .expect_err("unavailable external service must not replace built-ins");

        assert_eq!(engine.current_generation(), builtins_generation);
    }

    #[tokio::test]
    async fn unavailable_middleware_reload_keeps_last_known_good_runtime_active() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let active_generation = engine.current_generation();
        let unavailable_service = openshell_core::proto::SupervisorMiddlewareService {
            name: "unavailable-guard".into(),
            grpc_endpoint: "http://127.0.0.1:1".into(),
            max_payload_bytes: 1024,
            ..Default::default()
        };

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[unavailable_service],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: true,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState::default(),
        )
        .await
        .expect_err("unavailable middleware must fail candidate preparation");
        let disposition = apply_gateway_runtime_reload_failure(
            &engine,
            failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            2,
        )
        .expect("middleware failure handling must succeed");

        assert!(matches!(
            disposition,
            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { .. }
        ));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[tokio::test]
    async fn tcp_policy_reload_without_startup_substrate_is_rejected_and_keeps_previous_policy() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        let active_generation = engine.current_generation();

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_tcp_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: false,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState {
                capable: true,
                substrate_ready: false,
            },
        )
        .await
        .expect_err("TCP expansion must require startup substrate");
        let disposition = apply_gateway_runtime_reload_failure(
            &engine,
            failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            2,
        )
        .expect("runtime prerequisite failure handling must succeed");

        assert!(matches!(
            disposition,
            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                active_generation: generation,
                ..
            } if generation == active_generation
        ));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[tokio::test]
    async fn tcp_policy_reload_on_unsupported_runtime_is_rejected() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_tcp_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: false,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState::default(),
        )
        .await
        .expect_err("unsupported runtime must reject TCP expansion");

        assert!(matches!(
            failure,
            GatewayRuntimeReloadError::TransparentTcpPrerequisite(_)
        ));
        assert_eq!(engine.current_generation(), 0);
    }

    #[test]
    fn policy_rejection_after_middleware_outage_is_not_deduplicated() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let middleware_failure = GatewayRuntimeReloadError::MiddlewareRegistry(miette::miette!(
            "middleware service unavailable"
        ));
        let first_failure = FailedRuntimeRevision::new(42, "sha256:candidate", &middleware_failure);
        let middleware_disposition = apply_gateway_runtime_reload_failure(
            &engine,
            middleware_failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
        )
        .unwrap();

        assert!(matches!(
            middleware_disposition,
            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { .. }
        ));
        assert!(engine.fail_closed_reason().is_none());

        let policy_failure = GatewayRuntimeReloadError::PolicyValidation(miette::miette!(
            "conflicting endpoint metadata"
        ));
        let second_failure = FailedRuntimeRevision::new(42, "sha256:candidate", &policy_failure);
        assert_ne!(
            first_failure, second_failure,
            "a changed failure class for the same candidate must be handled"
        );

        let policy_disposition = apply_gateway_runtime_reload_failure(
            &engine,
            policy_failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
        )
        .unwrap();
        assert!(matches!(
            policy_disposition,
            GatewayRuntimeFailureDisposition::PolicyRejected { .. }
        ));
        assert!(engine.fail_closed_reason().is_some());
    }

    #[test]
    fn failed_gateway_runtime_snapshot_is_retried_without_revision_change() {
        let services = Vec::new();

        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &services,
            &services,
            MiddlewareRegistryStatus::NeedsReconciliation,
        ));
        assert!(!gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &services,
            &services,
            MiddlewareRegistryStatus::Synchronized,
        ));
    }

    #[test]
    fn gateway_runtime_reconciliation_tracks_policy_and_service_changes() {
        let no_services = Vec::new();
        let desired_services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v2",
            &no_services,
            &no_services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &no_services,
            &desired_services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(!gateway_policy_runtime_needs_reconciliation(
            false,
            "local-policy",
            "hash-v2",
            &no_services,
            &desired_services,
            MiddlewareRegistryStatus::NeedsReconciliation,
        ));
    }

    #[test]
    fn policy_only_change_does_not_rebuild_middleware_registry() {
        let services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        // The runtime must reconcile, but the registry (and therefore
        // middleware reachability) is not part of that reconciliation.
        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v2",
            &services,
            &services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(!middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &services,
            &services,
        ));
    }

    #[test]
    fn registry_rebuild_requires_service_set_change_or_degraded_registry() {
        let no_services = Vec::new();
        let desired_services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        assert!(middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &no_services,
            &desired_services,
        ));
        assert!(middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::NeedsReconciliation,
            &desired_services,
            &desired_services,
        ));
        assert!(!middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &desired_services,
            &desired_services,
        ));
    }

    #[test]
    fn provider_readiness_initial_policy_requires_exact_config_identity() {
        let mut canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);
        for revision in [1, u64::MAX] {
            canonical.config_revision = revision;
            assert!(
                initial_policy_ack_candidate(Some(&loaded), &canonical).is_none(),
                "matching policy bytes cannot acknowledge a different installed configuration"
            );
        }
    }

    #[test]
    fn initial_ack_candidate_matches_sandbox_revision() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        let ack = initial_policy_ack_candidate(Some(&loaded), &canonical)
            .expect("sandbox-sourced matching revision should be acknowledged");

        assert_eq!(ack.version, 2);
        assert_eq!(ack.policy_hash, "hash-v2");
        assert_eq!(ack.config_revision, 200);
    }

    #[test]
    fn initial_ack_candidate_ignores_global_policy() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Global,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_ignores_version_zero() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            0,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_ignores_local_file_mode() {
        // Local-file mode retains no proto policy, so there is nothing to
        // acknowledge to the gateway.
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert!(initial_policy_ack_candidate(None, &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_rejects_mismatched_identity() {
        let loaded_snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&loaded_snapshot);
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_poll_reconciles_provider_composition_that_was_not_loaded() {
        let loaded_snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&loaded_snapshot);
        let mut newer = proto_policy_fixture();
        newer.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule::default(),
        );
        let canonical =
            settings_poll_result(Some(newer), 1, openshell_core::proto::PolicySource::Sandbox);
        let canonical = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "hash-provider-change".to_string(),
            config_revision: loaded.config_revision + 1,
            ..canonical
        };

        assert_eq!(
            initial_poll_disposition(
                &LoadedPolicyOrigin::Gateway {
                    revision: Some(loaded),
                    has_last_valid_policy: true,
                },
                &canonical,
            ),
            InitialPollDisposition::Reconcile
        );
    }

    #[test]
    fn initial_poll_tracks_local_override_without_reconciliation() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert_eq!(
            initial_poll_disposition(&LoadedPolicyOrigin::LocalOverride, &canonical),
            InitialPollDisposition::TrackOnly
        );
        assert!(!LoadedPolicyOrigin::LocalOverride.allows_gateway_policy_reload());
    }

    #[test]
    fn initial_poll_reconciles_unbound_gateway_policy() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let origin = LoadedPolicyOrigin::Gateway {
            revision: None,
            has_last_valid_policy: true,
        };

        assert_eq!(
            initial_poll_disposition(&origin, &canonical),
            InitialPollDisposition::Reconcile
        );
        assert!(origin.allows_gateway_policy_reload());
    }

    #[test]
    fn unchanged_sandbox_policy_revision_candidate_is_strictly_scoped() {
        let sandbox_result = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "same-policy".to_string(),
            ..settings_poll_result(
                Some(proto_policy_fixture()),
                2,
                openshell_core::proto::PolicySource::Sandbox,
            )
        };

        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "same-policy", &sandbox_result),
            Some(2)
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 2, "same-policy", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(
                true,
                false,
                1,
                "different-policy",
                &sandbox_result,
            ),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(false, false, 1, "same-policy", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, true, 1, "same-policy", &sandbox_result),
            None
        );

        let global_result = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "same-policy".to_string(),
            ..settings_poll_result(
                Some(proto_policy_fixture()),
                2,
                openshell_core::proto::PolicySource::Global,
            )
        };
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "same-policy", &global_result),
            None
        );
    }

    #[test]
    fn unchanged_policy_revision_waits_for_required_runtime_reconciliation() {
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), false, false),
            Some(2),
            "a same-hash revision needs no OPA reload"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), true, false),
            None,
            "failed runtime reconciliation must keep the revision pending"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), true, true),
            Some(2),
            "successful runtime reconciliation permits acknowledgement"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(None, false, true),
            None,
            "runtime success cannot manufacture a revision candidate"
        );
    }

    #[test]
    fn credential_gating_unavailable_for_local_override_with_credentials() {
        assert!(credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            true,
            true
        ));
    }

    #[test]
    fn credential_gating_available_without_local_override_or_credentials() {
        // A gateway policy is stamped with provenance, so the gates apply.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: true,
            },
            true,
            true
        ));
        // No provider credentials means there is nothing to leak.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            false,
            true
        ));
        // Without networking the proxy never evaluates endpoint provenance.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            true,
            false
        ));
    }

    #[test]
    fn policy_status_outbox_preserves_all_revision_order() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        for version in 1..=128 {
            enqueue_policy_status(&sender, PolicyStatusUpdate::loaded(version));
        }

        for version in 1..=128 {
            assert_eq!(
                receiver.try_recv().unwrap(),
                PolicyStatusUpdate::loaded(version)
            );
        }
    }

    #[test]
    fn settings_snapshot_carries_workspace_for_policy_sync() {
        let mut snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        snapshot.workspace = "beta".to_string();

        let revision = LoadedPolicyRevision::from_snapshot(&snapshot);
        assert_eq!(revision.version, 1);
        assert_eq!(
            snapshot.workspace, "beta",
            "workspace must survive the snapshot so sync_policy_and_fetch_snapshot receives it"
        );
    }
    #[test]
    fn fail_closed_validation_failure_deactivates_previous_generation() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(!disposition.previous_policy_active);
        assert!(disposition.active_generation > previous_generation);
        assert!(
            engine
                .fail_closed_reason()
                .expect("quarantine reason")
                .contains("candidate version 7 rejected")
        );
    }

    #[test]
    fn retain_validation_failure_keeps_previous_generation_active() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let quarantined = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            6,
            "conflicting tls metadata",
        )
        .unwrap();
        assert!(!quarantined.previous_policy_active);

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(disposition.previous_policy_active);
        assert!(disposition.active_generation > quarantined.active_generation);
        assert!(disposition.active_generation > previous_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[test]
    fn retain_validation_failure_without_last_valid_policy_stays_fail_closed() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            false,
            1,
            "conflicting tls metadata",
        )
        .unwrap();

        assert_eq!(
            disposition.configured_mode,
            PolicyValidationFailureMode::RetainLastValid
        );
        assert_eq!(disposition.mode, PolicyValidationFailureMode::FailClosed);
        assert!(!disposition.previous_policy_active);
        assert!(engine.fail_closed_reason().is_some());

        let [config, _] = policy_validation_failure_events(
            &disposition,
            1,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "retain_last_valid"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
    }

    #[test]
    fn validation_failure_ocsf_states_whether_previous_policy_is_active() {
        let fail_closed = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::FailClosed,
            mode: PolicyValidationFailureMode::FailClosed,
            previous_policy_active: false,
            active_generation: 9,
        };
        let [config, finding] = policy_validation_failure_events(
            &fail_closed,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["class_uid"], 5019);
        assert_eq!(config["status"], "Failure");
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "fail_closed"
        );
        assert_eq!(config["unmapped"]["previous_policy_active"], false);
        assert_eq!(
            config["unmapped"]["validation_error"],
            "conflicting tls metadata"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("error:conflicting tls metadata")
        );

        let finding = finding.to_json().unwrap();
        assert_eq!(finding["class_uid"], 2004);
        assert_eq!(finding["action"], "Denied");
        assert_eq!(finding["disposition"], "Blocked");

        let retained = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::RetainLastValid,
            mode: PolicyValidationFailureMode::RetainLastValid,
            previous_policy_active: true,
            active_generation: 4,
        };
        let [config, _] = policy_validation_failure_events(
            &retained,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["previous_policy_active"], true);
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS active")
        );
    }
}
