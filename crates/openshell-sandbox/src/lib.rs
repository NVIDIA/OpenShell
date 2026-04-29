// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

pub mod bypass_monitor;
mod child_env;
pub mod denial_aggregator;
mod grpc_client;
mod identity;
pub mod l7;
pub mod log_push;
pub mod mechanistic_mapper;
pub mod opa;
mod policy;
mod process;
pub mod procfs;
pub mod proxy;
mod sandbox;
mod secrets;
mod ssh;
mod supervisor_session;

use miette::{IntoDiagnostic, Result};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, FindingInfo, LaunchTypeId, Process as OcsfProcess, ProcessActivityBuilder,
    SandboxContext, SeverityId, StateId, StatusId, ocsf_emit,
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

/// Process-wide OCSF sandbox context. Initialized once during `run_sandbox()`
/// startup and accessible from any module in the crate via [`ocsf_ctx()`].
static OCSF_CTX: OnceLock<SandboxContext> = OnceLock::new();

/// Fallback context used when `OCSF_CTX` has not been initialized (e.g. in
/// unit tests that exercise individual functions without calling `run_sandbox`).
static OCSF_CTX_FALLBACK: std::sync::LazyLock<SandboxContext> =
    std::sync::LazyLock::new(|| SandboxContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: String::new(),
        hostname: "test".to_string(),
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
        proxy_port: 3128,
    });

/// Return a reference to the process-wide [`SandboxContext`].
///
/// Falls back to a default context if `run_sandbox()` has not yet been called
/// (e.g. during unit tests).
pub(crate) fn ocsf_ctx() -> &'static SandboxContext {
    OCSF_CTX.get().unwrap_or(&OCSF_CTX_FALLBACK)
}

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, read_system_ca_bundle,
    write_ca_files,
};
use crate::opa::OpaEngine;
use crate::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use crate::proxy::ProxyHandle;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::netns::NetworkNamespace;
use crate::secrets::SecretResolver;
pub use process::{ProcessHandle, ProcessStatus};
pub use sandbox::apply_supervisor_startup_hardening;

/// Default interval (seconds) for re-fetching the inference route bundle from
/// the gateway in cluster mode. Override at runtime with the
/// `OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS` environment variable.
/// File-based routes (`--inference-routes`) are loaded once at startup and never
/// refreshed.
const DEFAULT_ROUTE_REFRESH_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InferenceRouteSource {
    File,
    Cluster,
    None,
}

fn infer_route_source(
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> InferenceRouteSource {
    if inference_routes.is_some() {
        InferenceRouteSource::File
    } else if sandbox_id.is_some() && openshell_endpoint.is_some() {
        InferenceRouteSource::Cluster
    } else {
        InferenceRouteSource::None
    }
}

fn disable_inference_on_empty_routes(source: InferenceRouteSource) -> bool {
    !matches!(source, InferenceRouteSource::Cluster)
}

fn route_refresh_interval_secs() -> u64 {
    match std::env::var("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS") {
        Ok(value) => match value.parse::<u64>() {
            Ok(interval) if interval > 0 => interval,
            Ok(_) => {
                warn!(
                    default_interval_secs = DEFAULT_ROUTE_REFRESH_INTERVAL_SECS,
                    "Ignoring zero route refresh interval"
                );
                DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
            }
            Err(error) => {
                warn!(
                    interval = %value,
                    error = %error,
                    default_interval_secs = DEFAULT_ROUTE_REFRESH_INTERVAL_SECS,
                    "Ignoring invalid route refresh interval"
                );
                DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
            }
        },
        Err(_) => DEFAULT_ROUTE_REFRESH_INTERVAL_SECS,
    }
}

#[cfg(target_os = "linux")]
static MANAGED_CHILDREN: LazyLock<Mutex<HashSet<i32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(target_os = "linux")]
pub(crate) fn register_managed_child(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    if pid <= 0 {
        return;
    }
    if let Ok(mut children) = MANAGED_CHILDREN.lock() {
        children.insert(pid);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn unregister_managed_child(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    if pid <= 0 {
        return;
    }
    if let Ok(mut children) = MANAGED_CHILDREN.lock() {
        children.remove(&pid);
    }
}

#[cfg(target_os = "linux")]
fn is_managed_child(pid: i32) -> bool {
    MANAGED_CHILDREN
        .lock()
        .is_ok_and(|children| children.contains(&pid))
}

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub async fn run_sandbox(
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    ssh_handshake_secret: Option<String>,
    ssh_handshake_skew_secs: u64,
    _health_check: bool,
    _health_port: u16,
    inference_routes: Option<String>,
    ocsf_enabled: Arc<std::sync::atomic::AtomicBool>,
) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| miette::miette!("No command specified"))?;

    // Initialize the process-wide OCSF context early so that events emitted
    // during policy loading (filesystem config, validation) have a context.
    // Proxy IP/port use defaults here; they are only significant for network
    // events which happen after the netns is created.
    {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "openshell-sandbox".to_string());

        if OCSF_CTX
            .set(SandboxContext {
                sandbox_id: sandbox_id.clone().unwrap_or_default(),
                sandbox_name: sandbox.as_deref().unwrap_or_default().to_string(),
                container_image: std::env::var("OPENSHELL_CONTAINER_IMAGE").unwrap_or_default(),
                hostname,
                product_version: openshell_core::VERSION.to_string(),
                proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
                proxy_port: 3128,
            })
            .is_err()
        {
            debug!("OCSF context already initialized, keeping existing");
        }
    }

    // Load policy and initialize OPA engine
    let openshell_endpoint_for_proxy = openshell_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let (policy, opa_engine, retained_proto) = load_policy(
        sandbox_id.clone(),
        sandbox,
        openshell_endpoint.clone(),
        policy_rules,
        policy_data,
    )
    .await?;

    // Validate that the required "sandbox" user exists in this image.
    // All sandbox images must include this user for privilege dropping.
    #[cfg(unix)]
    validate_sandbox_user(&policy)?;

    // Fetch provider environment variables from the server.
    // This is done after loading the policy so the sandbox can still start
    // even if provider env fetch fails (graceful degradation).
    let provider_env = if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        match grpc_client::fetch_provider_environment(endpoint, id).await {
            Ok(env) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "loaded")
                        .message(format!(
                            "Fetched provider environment [env_count:{}]",
                            env.len()
                        ))
                        .build()
                );
                env
            }
            Err(e) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "degraded")
                        .message(format!(
                            "Failed to fetch provider environment, continuing without: {e}"
                        ))
                        .build()
                );
                std::collections::HashMap::new()
            }
        }
    } else {
        std::collections::HashMap::new()
    };

    let (provider_env, secret_resolver) = SecretResolver::from_provider_env(provider_env);
    let secret_resolver = secret_resolver.map(Arc::new);

    // Create identity cache for SHA256 TOFU when OPA is active
    let identity_cache = opa_engine
        .as_ref()
        .map(|_| Arc::new(BinaryIdentityCache::new()));

    // Prepare filesystem: create and chown read_write directories
    prepare_filesystem(&policy)?;

    // Generate ephemeral CA and TLS state for HTTPS L7 inspection.
    // The CA cert is written to disk so sandbox processes can trust it.
    let (tls_state, ca_file_paths) = if matches!(policy.network.mode, NetworkMode::Proxy) {
        match SandboxCa::generate() {
            Ok(ca) => {
                let tls_dir = std::path::Path::new("/etc/openshell-tls");
                let system_ca_bundle = read_system_ca_bundle();
                match write_ca_files(&ca, tls_dir, &system_ca_bundle) {
                    Ok(paths) => {
                        // /etc/openshell-tls is subsumed by the /etc baseline
                        // path injected by enrich_*_baseline_paths(), so no
                        // explicit Landlock entry is needed here.

                        let upstream_config = build_upstream_client_config(&system_ca_bundle);
                        let cert_cache = CertCache::new(ca);
                        let state = Arc::new(ProxyTlsState::new(cert_cache, upstream_config));
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "enabled")
                                .message("TLS termination enabled: ephemeral CA generated")
                                .build()
                        );
                        (Some(state), Some(paths))
                    }
                    Err(e) => {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Medium)
                                .status(StatusId::Failure)
                                .state(StateId::Disabled, "disabled")
                                .message(format!(
                                    "Failed to write CA files, TLS termination disabled: {e}"
                                ))
                                .build()
                        );
                        (None, None)
                    }
                }
            }
            Err(e) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Disabled, "disabled")
                        .message(format!(
                            "Failed to generate ephemeral CA, TLS termination disabled: {e}"
                        ))
                        .build()
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // Create network namespace for proxy mode (Linux only)
    // This must be created before the proxy AND SSH server so that SSH
    // sessions can enter the namespace for network isolation.
    #[cfg(target_os = "linux")]
    let netns = if matches!(policy.network.mode, NetworkMode::Proxy) {
        match NetworkNamespace::create() {
            Ok(ns) => {
                // Install bypass detection rules (iptables LOG + REJECT).
                // This provides fast-fail UX and diagnostic logging for direct
                // connection attempts that bypass the HTTP CONNECT proxy.
                let proxy_port = policy
                    .network
                    .proxy
                    .as_ref()
                    .and_then(|p| p.http_addr)
                    .map_or(3128, |addr| addr.port());
                if let Err(e) = ns.install_bypass_rules(proxy_port) {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Medium)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "degraded")
                            .message(format!(
                                "Failed to install bypass detection rules (non-fatal): {e}"
                            ))
                            .build()
                    );
                }
                Some(ns)
            }
            Err(e) => {
                return Err(miette::miette!(
                    "Network namespace creation failed and proxy mode requires isolation. \
                     Ensure CAP_NET_ADMIN and CAP_SYS_ADMIN are available and iproute2 is installed. \
                     Error: {e}"
                ));
            }
        }
    } else {
        None
    };

    // On non-Linux, network namespace isolation is not supported
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::no_effect_underscore_binding)]
    let _netns: Option<()> = None;

    // Install the supervisor seccomp prelude after privileged startup helpers
    // (network namespace setup, iptables probes) complete, but before the SSH
    // listener and workload process are exposed.
    apply_supervisor_startup_hardening()?;

    // Shared PID: set after process spawn so the proxy can look up
    // the entrypoint process's /proc/net/tcp for identity binding.
    let entrypoint_pid = Arc::new(AtomicU32::new(0));

    let (_proxy, denial_rx, bypass_denial_tx) = if matches!(policy.network.mode, NetworkMode::Proxy)
    {
        let proxy_policy = policy.network.proxy.as_ref().ok_or_else(|| {
            miette::miette!("Network mode is set to proxy but no proxy configuration was provided")
        })?;

        let engine = opa_engine.clone().ok_or_else(|| {
            miette::miette!("Proxy mode requires an OPA engine (--rego-policy and --rego-data)")
        })?;

        let cache = identity_cache.clone().ok_or_else(|| {
            miette::miette!("Proxy mode requires an identity cache (OPA engine must be configured)")
        })?;

        // If we have a network namespace, bind to the veth host IP so sandboxed
        // processes can reach the proxy via TCP.
        #[cfg(target_os = "linux")]
        let bind_addr = netns.as_ref().map(|ns| {
            let port = proxy_policy.http_addr.map_or(3128, |addr| addr.port());
            SocketAddr::new(ns.host_ip(), port)
        });

        #[cfg(not(target_os = "linux"))]
        let bind_addr: Option<SocketAddr> = None;

        // Build inference context for local routing of intercepted inference calls.
        let inference_ctx = build_inference_context(
            sandbox_id.as_deref(),
            openshell_endpoint_for_proxy.as_deref(),
            inference_routes.as_deref(),
        )
        .await?;

        // Create denial aggregator channel if in gRPC mode (sandbox_id present).
        // Clone the sender for the bypass monitor before passing to the proxy.
        let (denial_tx, denial_rx, bypass_denial_tx) = if sandbox_id.is_some() {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let bypass_tx = tx.clone();
            (Some(tx), Some(rx), Some(bypass_tx))
        } else {
            (None, None, None)
        };

        let proxy_handle = ProxyHandle::start_with_bind_addr(
            proxy_policy,
            bind_addr,
            engine,
            cache,
            entrypoint_pid.clone(),
            tls_state,
            inference_ctx,
            secret_resolver.clone(),
            denial_tx,
        )
        .await?;
        (Some(proxy_handle), denial_rx, bypass_denial_tx)
    } else {
        (None, None, None)
    };

    // Spawn bypass detection monitor (Linux only, proxy mode only).
    // Reads /dev/kmsg for iptables LOG entries and emits structured
    // tracing events for direct connection attempts that bypass the proxy.
    #[cfg(target_os = "linux")]
    let _bypass_monitor = if netns.is_some() {
        bypass_monitor::spawn(
            netns.as_ref().expect("netns is Some").name().to_string(),
            entrypoint_pid.clone(),
            bypass_denial_tx,
        )
    } else {
        None
    };

    // On non-Linux, bypass_denial_tx is unused (no /dev/kmsg).
    #[cfg(not(target_os = "linux"))]
    drop(bypass_denial_tx);

    // Compute the proxy URL and netns fd for SSH sessions.
    // SSH shell processes need both to enforce network policy:
    // - netns_fd: enter the network namespace via setns() so all traffic
    //   goes through the veth pair (hard enforcement, non-bypassable)
    // - proxy_url: set proxy env vars so cooperative tools route through the
    //   CONNECT proxy; this also opts Node.js into honoring those vars
    #[cfg(target_os = "linux")]
    let ssh_netns_fd = netns.as_ref().and_then(NetworkNamespace::ns_fd);

    #[cfg(not(target_os = "linux"))]
    let ssh_netns_fd: Option<i32> = None;

    let ssh_proxy_url = if matches!(policy.network.mode, NetworkMode::Proxy) {
        #[cfg(target_os = "linux")]
        {
            netns.as_ref().map(|ns| {
                let port = policy
                    .network
                    .proxy
                    .as_ref()
                    .and_then(|p| p.http_addr)
                    .map_or(3128, |addr| addr.port());
                format!("http://{}:{port}", ns.host_ip())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            policy
                .network
                .proxy
                .as_ref()
                .and_then(|p| p.http_addr)
                .map(|addr| format!("http://{addr}"))
        }
    } else {
        None
    };

    // Zombie reaper — openshell-sandbox may run as PID 1 in containers and
    // must reap orphaned grandchildren (e.g. background daemons started by
    // coding agents) to prevent zombie accumulation.
    //
    // Use waitid(..., WNOWAIT) so we can inspect exited children before
    // actually reaping them. This avoids racing explicit `child.wait()` calls
    // for managed children (entrypoint and SSH session processes).
    #[cfg(target_os = "linux")]
    tokio::spawn(async {
        use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
        use tokio::signal::unix::{SignalKind, signal};
        use tokio::time::MissedTickBehavior;

        let mut sigchld = match signal(SignalKind::child()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to register SIGCHLD handler for zombie reaping");
                return;
            }
        };
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        retry.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = sigchld.recv() => {}
                _ = retry.tick() => {}
            }

            loop {
                let status = match waitid(
                    Id::All,
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                ) {
                    Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
                    Ok(status) => status,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        tracing::debug!(error = %e, "waitid error during zombie reaping");
                        break;
                    }
                };

                let Some(pid) = status.pid() else {
                    break;
                };

                if is_managed_child(pid.as_raw()) {
                    // Let the explicit waiter own this child status.
                    break;
                }

                match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => {}
                    Ok(reaped) => {
                        tracing::debug!(?reaped, "Reaped orphaned child process");
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, "waitpid error during orphan reap");
                        break;
                    }
                }
            }
        }
    });

    let ssh_socket_path: Option<std::path::PathBuf> = ssh_socket_path.map(std::path::PathBuf::from);
    if let Some(listen_path) = ssh_socket_path.clone() {
        let policy_clone = policy.clone();
        let workdir_clone = workdir.clone();
        let _ = ssh_handshake_secret; // retained in the signature for compat; unused
        let _ = ssh_handshake_skew_secs;
        let proxy_url = ssh_proxy_url;
        let netns_fd = ssh_netns_fd;
        let ca_paths = ca_file_paths.clone();
        let provider_env_clone = provider_env.clone();

        let (ssh_ready_tx, ssh_ready_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            if let Err(err) = ssh::run_ssh_server(
                listen_path,
                ssh_ready_tx,
                policy_clone,
                workdir_clone,
                netns_fd,
                proxy_url,
                ca_paths,
                provider_env_clone,
            )
            .await
            {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Critical)
                        .status(StatusId::Failure)
                        .message(format!("SSH server failed: {err}"))
                        .build()
                );
            }
        });

        // Wait for the SSH server to bind its socket before spawning the
        // entrypoint process. This prevents exec requests from racing against
        // SSH server startup when Kubernetes marks the pod Ready.
        match timeout(Duration::from_secs(10), ssh_ready_rx).await {
            Ok(Ok(Ok(()))) => {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Open)
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .message("SSH server is ready to accept connections")
                        .build()
                );
            }
            Ok(Ok(Err(err))) => {
                return Err(err.context("SSH server failed during startup"));
            }
            Ok(Err(_)) => {
                return Err(miette::miette!(
                    "SSH server task panicked before signaling ready"
                ));
            }
            Err(_) => {
                return Err(miette::miette!(
                    "SSH server did not start within 10 seconds"
                ));
            }
        }
    }

    // Spawn the persistent supervisor session if we have a gateway endpoint
    // and sandbox identity. The session provides relay channels for SSH
    // connect and ExecSandbox through the gateway.
    if let (Some(endpoint), Some(id), Some(socket)) = (
        openshell_endpoint.as_ref(),
        sandbox_id.as_ref(),
        ssh_socket_path.as_ref(),
    ) {
        supervisor_session::spawn(endpoint.clone(), id.clone(), socket.clone());
        info!("supervisor session task spawned");
    }

    #[cfg(target_os = "linux")]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        workdir.as_deref(),
        interactive,
        &policy,
        netns.as_ref(),
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    #[cfg(not(target_os = "linux"))]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        workdir.as_deref(),
        interactive,
        &policy,
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    // Store the entrypoint PID so the proxy can resolve TCP peer identity
    entrypoint_pid.store(handle.pid(), Ordering::Release);
    ocsf_emit!(
        ProcessActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .launch_type(LaunchTypeId::Spawn)
            .process(OcsfProcess::new(program, i64::from(handle.pid())))
            .message(format!("Process started: pid={}", handle.pid()))
            .build()
    );

    // Spawn a task to resolve policy binary symlinks after the container
    // filesystem becomes accessible via /proc/<pid>/root/. This expands
    // symlinks like /usr/bin/python3 → /usr/bin/python3.11 in the OPA
    // policy data so that either path matches at evaluation time.
    //
    // We cannot do this synchronously here because the child process has
    // just been spawned and its mount namespace / procfs entries may not
    // be fully populated yet. Instead, we probe with retries until
    // /proc/<pid>/root/ is accessible or we exhaust attempts.
    if let (Some(engine), Some(proto)) = (&opa_engine, &retained_proto) {
        let resolve_engine = engine.clone();
        let resolve_proto = proto.clone();
        let resolve_pid = entrypoint_pid.clone();
        tokio::spawn(async move {
            let pid = resolve_pid.load(Ordering::Acquire);
            let probe_path = format!("/proc/{pid}/root/");
            // Retry up to 10 times with 500ms intervals (5s total).
            // The child's mount namespace is typically ready within a
            // few hundred ms of spawn.
            for attempt in 1..=10 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if std::fs::metadata(&probe_path).is_ok() {
                    info!(
                        pid = pid,
                        attempt = attempt,
                        "Container filesystem accessible, resolving policy binary symlinks"
                    );
                    match resolve_engine.reload_from_proto_with_pid(&resolve_proto, pid) {
                        Ok(()) => {
                            info!(
                                pid = pid,
                                "Policy binary symlink resolution complete \
                                 (check logs above for per-binary results)"
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to rebuild OPA engine with symlink resolution \
                                 (non-fatal, falling back to literal path matching): {e}"
                            );
                        }
                    }
                    return;
                }
                debug!(
                    pid = pid,
                    attempt = attempt,
                    probe_path = %probe_path,
                    "Container filesystem not yet accessible, retrying symlink resolution"
                );
            }
            warn!(
                "Container filesystem /proc/{pid}/root/ not accessible after 10 attempts (5s); \
                 binary symlink resolution skipped. Policy binary paths will be matched literally. \
                 If binaries are symlinks, use canonical paths in your policy \
                 (run 'readlink -f <path>' inside the sandbox)"
            );
        });
    }

    // Spawn background policy poll task (gRPC mode only).
    if let (Some(id), Some(endpoint), Some(engine)) =
        (&sandbox_id, &openshell_endpoint, &opa_engine)
    {
        let poll_id = id.clone();
        let poll_endpoint = endpoint.clone();
        let poll_engine = engine.clone();
        let poll_ocsf_enabled = ocsf_enabled.clone();
        let poll_pid = entrypoint_pid.clone();
        let poll_interval_secs: u64 = std::env::var("OPENSHELL_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        tokio::spawn(async move {
            if let Err(e) = run_policy_poll_loop(
                &poll_endpoint,
                &poll_id,
                &poll_engine,
                &poll_pid,
                poll_interval_secs,
                &poll_ocsf_enabled,
            )
            .await
            {
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

        // Spawn denial aggregator (gRPC mode only, when proxy is active).
        if let Some(rx) = denial_rx {
            // SubmitPolicyAnalysis resolves by sandbox *name*, not UUID.
            let agg_name = sandbox_name_for_agg.clone().unwrap_or_else(|| id.clone());
            let agg_endpoint = endpoint.clone();
            let flush_interval_secs: u64 = std::env::var("OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);

            let aggregator = denial_aggregator::DenialAggregator::new(rx, flush_interval_secs);

            tokio::spawn(async move {
                aggregator
                    .run(|summaries| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        async move {
                            if let Err(e) =
                                flush_proposals_to_gateway(&endpoint, &sandbox_name, summaries)
                                    .await
                            {
                                warn!(error = %e, "Failed to flush denial summaries to gateway");
                            }
                        }
                    })
                    .await;
            });
        }
    }

    // Wait for process with optional timeout
    let result = if timeout_secs > 0 {
        if let Ok(result) = timeout(Duration::from_secs(timeout_secs), handle.wait()).await {
            result
        } else {
            ocsf_emit!(
                ProcessActivityBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Close)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Critical)
                    .status(StatusId::Failure)
                    .message("Process timed out, killing")
                    .build()
            );
            handle.kill()?;
            return Ok(124); // Standard timeout exit code
        }
    } else {
        handle.wait().await
    };

    let status = result.into_diagnostic()?;

    ocsf_emit!(
        ProcessActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Close)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .exit_code(status.code())
            .message(format!("Process exited with code {}", status.code()))
            .build()
    );

    Ok(status.code())
}

/// Build an inference context for local routing, if route sources are available.
///
/// Route sources (in priority order):
/// 1. Inference routes file (standalone mode) — always takes precedence
/// 2. Cluster bundle (fetched from gateway via gRPC)
///
/// If both a routes file and cluster credentials are provided, the routes file
/// wins and the cluster bundle is not fetched.
///
/// Returns `None` if neither source is configured (inference routing disabled).
async fn build_inference_context(
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> Result<Option<Arc<proxy::InferenceContext>>> {
    use openshell_router::Router;
    use openshell_router::config::RouterConfig;

    let source = infer_route_source(sandbox_id, openshell_endpoint, inference_routes);

    // Captured during the initial cluster bundle fetch so the background refresh
    // loop can skip no-op updates from the very first tick.
    let mut initial_revision: Option<String> = None;

    let routes = match source {
        InferenceRouteSource::File => {
            let Some(path) = inference_routes else {
                return Ok(None);
            };

            // Standalone mode: load routes from file (fail-fast on errors)
            if sandbox_id.is_some() {
                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped("inference_routes", serde_json::json!(path))
                    .message(format!(
                        "Inference routes file takes precedence over cluster bundle [path:{path}]"
                    ))
                    .build());
            }
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Other, "loading")
                    .unmapped("inference_routes", serde_json::json!(path))
                    .message(format!("Loading inference routes from file [path:{path}]"))
                    .build()
            );
            let config = RouterConfig::load_from_file(std::path::Path::new(path))
                .map_err(|e| miette::miette!("failed to load inference routes {path}: {e}"))?;
            config
                .resolve_routes()
                .map_err(|e| miette::miette!("failed to resolve routes from {path}: {e}"))?
        }
        InferenceRouteSource::Cluster => {
            let (Some(_id), Some(endpoint)) = (sandbox_id, openshell_endpoint) else {
                return Ok(None);
            };

            // Cluster mode: fetch bundle from gateway
            info!(endpoint = %endpoint, "Fetching inference route bundle from gateway");
            match grpc_client::fetch_inference_bundle(endpoint).await {
                Ok(bundle) => {
                    initial_revision = Some(bundle.revision.clone());
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("route_count", serde_json::json!(bundle.routes.len()))
                            .unmapped("revision", serde_json::json!(&bundle.revision))
                            .message(format!(
                                "Loaded inference route bundle [route_count:{} revision:{}]",
                                bundle.routes.len(),
                                bundle.revision
                            ))
                            .build()
                    );
                    bundle_to_resolved_routes(&bundle)
                }
                Err(e) => {
                    // Distinguish expected "not configured" states from server errors.
                    // gRPC PermissionDenied/NotFound means inference bundle is unavailable
                    // for this sandbox — skip gracefully. Other errors are unexpected.
                    let msg = e.to_string();
                    if msg.contains("permission denied") || msg.contains("not found") {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Disabled, "disabled")
                                .unmapped("error", serde_json::json!(e.to_string()))
                                .message(format!(
                                    "Inference bundle unavailable, routing disabled [error:{e}]"
                                ))
                                .build()
                        );
                        return Ok(None);
                    }
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Disabled, "disabled")
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Failed to fetch inference bundle, inference routing disabled [error:{e}]"
                        ))
                        .build());
                    return Ok(None);
                }
            }
        }
        InferenceRouteSource::None => {
            // No route source — inference routing is not configured
            return Ok(None);
        }
    };

    if routes.is_empty() && disable_inference_on_empty_routes(source) {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Disabled, "disabled")
                .message("No usable inference routes, inference routing disabled")
                .build()
        );
        return Ok(None);
    }

    if routes.is_empty() {
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "waiting")
            .message("Inference route bundle is empty; keeping routing enabled and waiting for refresh")
            .build());
    }

    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "enabled")
            .unmapped("route_count", serde_json::json!(routes.len()))
            .message(format!(
                "Inference routing enabled with local execution [route_count:{}]",
                routes.len()
            ))
            .build()
    );

    // Partition routes by name into user-facing and system caches.
    let (user_routes, system_routes) = partition_routes(routes);

    let router =
        Router::new().map_err(|e| miette::miette!("failed to initialize inference router: {e}"))?;
    let patterns = l7::inference::default_patterns();

    let ctx = Arc::new(proxy::InferenceContext::new(
        patterns,
        router,
        user_routes,
        system_routes,
    ));

    // Spawn background route cache refresh for cluster mode at startup so
    // request handling never depends on control-plane latency.
    if matches!(source, InferenceRouteSource::Cluster)
        && let (Some(_id), Some(endpoint)) = (sandbox_id, openshell_endpoint)
    {
        spawn_route_refresh(
            ctx.route_cache(),
            ctx.system_route_cache(),
            endpoint.to_string(),
            route_refresh_interval_secs(),
            initial_revision,
        );
    }

    Ok(Some(ctx))
}

/// Route name for the sandbox system inference route.
const SANDBOX_SYSTEM_ROUTE_NAME: &str = "sandbox-system";

/// Split resolved routes into user-facing and system caches by route name.
///
/// Routes named `"sandbox-system"` go to the system cache; everything else
/// (including `"inference.local"` and empty names) goes to the user cache.
fn partition_routes(
    routes: Vec<openshell_router::config::ResolvedRoute>,
) -> (
    Vec<openshell_router::config::ResolvedRoute>,
    Vec<openshell_router::config::ResolvedRoute>,
) {
    let mut user = Vec::new();
    let mut system = Vec::new();
    for r in routes {
        if r.name == SANDBOX_SYSTEM_ROUTE_NAME {
            system.push(r);
        } else {
            user.push(r);
        }
    }
    (user, system)
}

/// Convert a proto bundle response into resolved routes for the router.
pub(crate) fn bundle_to_resolved_routes(
    bundle: &openshell_core::proto::GetInferenceBundleResponse,
) -> Vec<openshell_router::config::ResolvedRoute> {
    bundle
        .routes
        .iter()
        .map(|r| {
            let (auth, default_headers, passthrough_headers) =
                openshell_core::inference::route_headers_for_provider_type(&r.provider_type);
            let timeout = if r.timeout_secs == 0 {
                openshell_router::config::DEFAULT_ROUTE_TIMEOUT
            } else {
                Duration::from_secs(r.timeout_secs)
            };
            openshell_router::config::ResolvedRoute {
                name: r.name.clone(),
                endpoint: r.base_url.clone(),
                model: r.model_id.clone(),
                api_key: r.api_key.clone(),
                protocols: r.protocols.clone(),
                auth,
                default_headers,
                passthrough_headers,
                timeout,
            }
        })
        .collect()
}

/// Spawn a background task that periodically refreshes both route caches from the gateway.
///
/// The loop uses the bundle `revision` hash to avoid unnecessary cache writes
/// when routes haven't changed. `initial_revision` is the revision captured
/// during the startup fetch in [`build_inference_context`] so the first refresh
/// cycle can already skip a no-op update.
pub(crate) fn spawn_route_refresh(
    user_cache: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
    system_cache: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
    endpoint: String,
    interval_secs: u64,
    initial_revision: Option<String>,
) {
    tokio::spawn(async move {
        use tokio::time::{MissedTickBehavior, interval};

        let mut current_revision = initial_revision;

        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tick.tick().await;

            match grpc_client::fetch_inference_bundle(&endpoint).await {
                Ok(bundle) => {
                    if current_revision.as_deref() == Some(&bundle.revision) {
                        trace!(revision = %bundle.revision, "Inference bundle unchanged");
                        continue;
                    }

                    let routes = bundle_to_resolved_routes(&bundle);
                    let (user_routes, system_routes) = partition_routes(routes);
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "updated")
                        .unmapped("user_route_count", serde_json::json!(user_routes.len()))
                        .unmapped("system_route_count", serde_json::json!(system_routes.len()))
                        .unmapped("revision", serde_json::json!(&bundle.revision))
                        .message(format!(
                            "Inference routes updated [user_route_count:{} system_route_count:{} revision:{}]",
                            user_routes.len(),
                            system_routes.len(),
                            bundle.revision
                        ))
                        .build());
                    current_revision = Some(bundle.revision);
                    *user_cache.write().await = user_routes;
                    *system_cache.write().await = system_routes;
                }
                Err(e) => {
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "stale")
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Failed to refresh inference route cache, keeping stale routes [error:{e}]"
                        ))
                        .build());
                }
            }
        }
    });
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

/// Minimum read-write paths required for a proxy-mode sandbox child process:
/// user working directory and temporary files.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/sandbox", "/tmp"];

/// GPU read-only paths.
///
/// `/run/nvidia-persistenced`: NVML tries to connect to the persistenced
/// socket at init time.  If the directory exists but Landlock denies traversal
/// (EACCES vs ECONNREFUSED), NVML returns `NVML_ERROR_INSUFFICIENT_PERMISSIONS`
/// even though the daemon is optional.  Only read/traversal access is needed.
const GPU_BASELINE_READ_ONLY: &[&str] = &["/run/nvidia-persistenced"];

/// GPU read-write paths (static).
///
/// `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`,
/// `/dev/nvidia-modeset`: control and UVM devices injected by CDI.
/// Landlock restricts `open(2)` on device files even when DAC allows it;
/// these need read-write because NVML/CUDA opens them with `O_RDWR`.
///
/// `/proc`: CUDA writes to `/proc/<pid>/task/<tid>/comm` during `cuInit()`
/// to set thread names.  Without write access, `cuInit()` returns error 304.
/// Must use `/proc` (not `/proc/self/task`) because Landlock rules bind to
/// inodes and child processes have different procfs inodes than the parent.
///
/// Per-GPU device files (`/dev/nvidia0`, …) are enumerated at runtime by
/// `enumerate_gpu_device_nodes()` since the count varies.
const GPU_BASELINE_READ_WRITE: &[&str] = &[
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
    "/proc",
];

/// Returns true if GPU devices are present in the container.
fn has_gpu_devices() -> bool {
    std::path::Path::new("/dev/nvidiactl").exists()
}

/// Enumerate per-GPU device nodes (`/dev/nvidia0`, `/dev/nvidia1`, …).
fn enumerate_gpu_device_nodes() -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(suffix) = name.strip_prefix("nvidia") {
                if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                paths.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    paths
}

/// Collect all baseline paths for enrichment: proxy defaults + GPU (if present).
/// Returns `(read_only, read_write)` as owned `String` vecs.
fn baseline_enrichment_paths() -> (Vec<String>, Vec<String>) {
    let mut ro: Vec<String> = PROXY_BASELINE_READ_ONLY
        .iter()
        .map(|&s| s.to_string())
        .collect();
    let mut rw: Vec<String> = PROXY_BASELINE_READ_WRITE
        .iter()
        .map(|&s| s.to_string())
        .collect();

    if has_gpu_devices() {
        ro.extend(GPU_BASELINE_READ_ONLY.iter().map(|&s| s.to_string()));
        rw.extend(GPU_BASELINE_READ_WRITE.iter().map(|&s| s.to_string()));
        rw.extend(enumerate_gpu_device_nodes());
    }

    // A path promoted to read_write (e.g. /proc for GPU) should not also
    // appear in read_only — Landlock handles the overlap correctly but the
    // duplicate is confusing when inspecting the effective policy.
    ro.retain(|p| !rw.contains(p));

    (ro, rw)
}

/// Ensure a proto `SandboxPolicy` includes the baseline filesystem paths
/// required for proxy-mode sandboxes.  Paths are only added if missing;
/// user-specified paths are never removed.
///
/// Returns `true` if the policy was modified (caller may want to sync back).
fn enrich_proto_baseline_paths(proto: &mut openshell_core::proto::SandboxPolicy) -> bool {
    // Only enrich if network_policies are present (proxy mode indicator).
    if proto.network_policies.is_empty() {
        return false;
    }

    let fs = proto
        .filesystem
        .get_or_insert_with(|| openshell_core::proto::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        });

    let (ro, rw) = baseline_enrichment_paths();

    // Baseline paths are system-injected, not user-specified.  Skip paths
    // that do not exist in this container image to avoid noisy warnings from
    // Landlock and, more critically, to prevent a single missing baseline
    // path from abandoning the entire Landlock ruleset under best-effort
    // mode (see issue #664).
    let mut modified = false;
    for path in &ro {
        if !fs.read_only.iter().any(|p| p == path) && !fs.read_write.iter().any(|p| p == path) {
            if !std::path::Path::new(path).exists() {
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
    for path in &rw {
        if fs.read_only.iter().any(|p| p == path) || fs.read_write.iter().any(|p| p == path) {
            continue;
        }
        if !std::path::Path::new(path).exists() {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        fs.read_write.push(path.clone());
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

    modified
}

/// Ensure a `SandboxPolicy` (Rust type) includes the baseline filesystem
/// paths required for proxy-mode sandboxes.  Used for the local-file code
/// path where no proto is available.
fn enrich_sandbox_baseline_paths(policy: &mut SandboxPolicy) {
    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return;
    }

    let (ro, rw) = baseline_enrichment_paths();

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
mod baseline_tests {
    use super::*;
    use crate::policy::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};

    #[test]
    fn proc_not_in_both_read_only_and_read_write_when_gpu_present() {
        // When GPU devices are present, /proc is promoted to read_write
        // (CUDA needs to write /proc/<pid>/task/<tid>/comm). It should
        // NOT also appear in read_only.
        if !has_gpu_devices() {
            // Can't test GPU dedup without GPU devices; skip silently.
            return;
        }
        let (ro, rw) = baseline_enrichment_paths();
        assert!(
            rw.contains(&"/proc".to_string()),
            "/proc should be in read_write when GPU is present"
        );
        assert!(
            !ro.contains(&"/proc".to_string()),
            "/proc should NOT be in read_only when it is already in read_write"
        );
    }

    #[test]
    fn proc_in_read_only_without_gpu() {
        if has_gpu_devices() {
            // On a GPU host we can't test the non-GPU path; skip silently.
            return;
        }
        let (ro, _rw) = baseline_enrichment_paths();
        assert!(
            ro.contains(&"/proc".to_string()),
            "/proc should be in read_only when GPU is not present"
        );
    }

    #[test]
    fn baseline_read_write_always_includes_sandbox_and_tmp() {
        let (_ro, rw) = baseline_enrichment_paths();
        assert!(rw.contains(&"/sandbox".to_string()));
        assert!(rw.contains(&"/tmp".to_string()));
    }

    #[test]
    fn enumerate_gpu_device_nodes_skips_bare_nvidia() {
        // "nvidia" (without a trailing digit) is a valid /dev entry on some
        // systems but is not a per-GPU device node.  The enumerator must
        // not match it.
        let nodes = enumerate_gpu_device_nodes();
        assert!(
            !nodes.contains(&"/dev/nvidia".to_string()),
            "bare /dev/nvidia should not be enumerated: {nodes:?}"
        );
    }

    #[test]
    fn no_duplicate_paths_in_baseline() {
        let (ro, rw) = baseline_enrichment_paths();
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
            read_only: vec!["/tmp".to_string()],
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
    fn local_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![std::path::PathBuf::from("/tmp")],
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
            policy
                .filesystem
                .read_only
                .contains(&std::path::PathBuf::from("/tmp")),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !policy
                .filesystem
                .read_write
                .contains(&std::path::PathBuf::from("/tmp")),
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

/// Retry a gRPC operation with exponential backoff (capped at 4 s).
///
/// Non-transient gRPC errors (e.g. `NOT_FOUND`, `INVALID_ARGUMENT`,
/// `PERMISSION_DENIED`) are returned immediately without retrying.
async fn grpc_retry<T, F, Fut>(op_name: &str, f: F) -> miette::Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = miette::Result<T>>,
{
    let mut last_err = None;
    for attempt in 1..=5u32 {
        match f().await {
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
async fn load_policy(
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
)> {
    // File mode: load OPA engine from rego rules + YAML data (dev override)
    if let (Some(policy_file), Some(data_file)) = (&policy_rules, &policy_data) {
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
        let engine = OpaEngine::from_files(
            std::path::Path::new(policy_file),
            std::path::Path::new(data_file),
        )?;
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
        return Ok((policy, Some(Arc::new(engine)), None));
    }

    // gRPC mode: fetch typed proto policy, construct OPA engine from baked rules + proto data
    if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        info!(
            sandbox_id = %id,
            endpoint = %endpoint,
            "Fetching sandbox policy via gRPC"
        );
        let proto_policy =
            grpc_retry("Policy fetch", || grpc_client::fetch_policy(endpoint, id)).await?;

        let mut proto_policy = match proto_policy {
            Some(p) => p,
            None => {
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
                let mut discovered = discover_policy_from_disk_or_default();
                // Enrich before syncing so the gateway baseline includes
                // baseline paths from the start.
                enrich_proto_baseline_paths(&mut discovered);
                let sandbox = sandbox.as_deref().ok_or_else(|| {
                    miette::miette!(
                        "Cannot sync discovered policy: sandbox not available.\n\
                         Set OPENSHELL_SANDBOX or --sandbox to enable policy sync."
                    )
                })?;

                // Sync and re-fetch over a single connection to avoid extra
                // TLS handshakes.
                grpc_retry("Policy discovery sync", || {
                    grpc_client::discover_and_sync_policy(endpoint, id, sandbox, &discovered)
                })
                .await?
            }
        };

        // Ensure baseline filesystem paths are present for proxy-mode
        // sandboxes.  If the policy was enriched, sync the updated version
        // back to the gateway so users can see the effective policy.
        let enriched = enrich_proto_baseline_paths(&mut proto_policy);
        if enriched {
            if let Some(sandbox_name) = sandbox.as_deref() {
                if let Err(e) =
                    grpc_client::sync_policy(endpoint, sandbox_name, &proto_policy).await
                {
                    warn!(
                        error = %e,
                        "Failed to sync enriched policy back to gateway (non-fatal)"
                    );
                }
            }
        }

        // Build OPA engine from baked-in rules + typed proto data.
        // In cluster mode, proxy networking is always enabled so OPA is
        // always required for allow/deny decisions.
        // The initial load uses pid=0 (no symlink resolution) because the
        // container hasn't started yet. After the entrypoint spawns, the
        // engine is rebuilt with the real PID for symlink resolution.
        info!("Creating OPA engine from proto policy data");
        let opa_engine = Some(Arc::new(OpaEngine::from_proto(&proto_policy)?));

        let policy = SandboxPolicy::try_from(proto_policy.clone())?;
        return Ok((policy, opa_engine, Some(proto_policy)));
    }

    // No policy source available
    Err(miette::miette!(
        "Sandbox policy required. Provide one of:\n\
         - --policy-rules and --policy-data (or OPENSHELL_POLICY_RULES and OPENSHELL_POLICY_DATA env vars)\n\
         - --sandbox-id and --openshell-endpoint (or OPENSHELL_SANDBOX_ID and OPENSHELL_ENDPOINT env vars)"
    ))
}

/// Try to discover a sandbox policy from the well-known disk path, falling
/// back to the legacy path, then to the hardcoded restrictive default.
fn discover_policy_from_disk_or_default() -> openshell_core::proto::SandboxPolicy {
    let primary = std::path::Path::new(openshell_policy::CONTAINER_POLICY_PATH);
    if primary.exists() {
        return discover_policy_from_path(primary);
    }
    let legacy = std::path::Path::new(openshell_policy::LEGACY_CONTAINER_POLICY_PATH);
    if legacy.exists() {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "loaded")
                .unmapped(
                    "legacy_path",
                    serde_json::json!(legacy.display().to_string())
                )
                .unmapped("new_path", serde_json::json!(primary.display().to_string()))
                .message(format!(
                    "Policy found at legacy path; consider moving [legacy_path:{} new_path:{}]",
                    legacy.display(),
                    primary.display()
                ))
                .build()
        );
        return discover_policy_from_path(legacy);
    }
    discover_policy_from_path(primary)
}

/// Try to read a sandbox policy YAML from `path`, falling back to the
/// hardcoded restrictive default if the file is missing or invalid.
fn discover_policy_from_path(path: &std::path::Path) -> openshell_core::proto::SandboxPolicy {
    use openshell_policy::{
        parse_sandbox_policy, restrictive_default_policy, validate_sandbox_policy,
    };

    match std::fs::read_to_string(path) {
        Ok(yaml) => {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .message(format!(
                        "Loaded sandbox policy from container disk [path:{}]",
                        path.display()
                    ))
                    .build()
            );
            match parse_sandbox_policy(&yaml) {
                Ok(policy) => {
                    // Validate the disk-loaded policy for safety.
                    if let Err(violations) = validate_sandbox_policy(&policy) {
                        let messages: Vec<String> =
                            violations.iter().map(ToString::to_string).collect();
                        ocsf_emit!(DetectionFindingBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Open)
                            .severity(SeverityId::Medium)
                            .action(ActionId::Denied)
                            .disposition(DispositionId::Blocked)
                            .finding_info(
                                FindingInfo::new(
                                    "unsafe-disk-policy",
                                    "Unsafe Disk Policy Content",
                                )
                                .with_desc(&format!(
                                    "Disk policy at {} contains unsafe content: {}",
                                    path.display(),
                                    messages.join("; "),
                                )),
                            )
                            .message(format!(
                                "Disk policy contains unsafe content, using restrictive default [path:{}]",
                                path.display()
                            ))
                            .build());
                        return restrictive_default_policy();
                    }
                    policy
                }
                Err(e) => {
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "fallback")
                        .message(format!(
                            "Failed to parse disk policy, using restrictive default [path:{} error:{e}]",
                            path.display()
                        ))
                        .build());
                    restrictive_default_policy()
                }
            }
        }
        Err(_) => {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "default")
                    .message(format!(
                        "No policy file on disk, using restrictive default [path:{}]",
                        path.display()
                    ))
                    .build()
            );
            restrictive_default_policy()
        }
    }
}

/// Validate that the `sandbox` user exists in this image.
///
/// All sandbox images must include a `sandbox` user for privilege dropping.
/// This check runs at supervisor startup (inside the container) where we can
/// inspect `/etc/passwd`. If the user is missing, the sandbox fails fast
/// with a clear error instead of silently running child processes as root.
#[cfg(unix)]
fn validate_sandbox_user(policy: &SandboxPolicy) -> Result<()> {
    use nix::unistd::User;

    let user_name = policy.process.run_as_user.as_deref().unwrap_or("sandbox");

    if user_name.is_empty() || user_name == "sandbox" {
        match User::from_name("sandbox") {
            Ok(Some(_)) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "validated")
                        .message("Validated 'sandbox' user exists in image")
                        .build()
                );
            }
            Ok(None) => {
                return Err(miette::miette!(
                    "sandbox user 'sandbox' not found in image; \
                     all sandbox images must include a 'sandbox' user and group"
                ));
            }
            Err(e) => {
                return Err(miette::miette!("failed to look up 'sandbox' user: {e}"));
            }
        }
    }

    Ok(())
}

/// Prepare a `read_write` path for the sandboxed process.
///
/// Returns `true` when the path was created by the supervisor and therefore
/// still needs to be chowned to the sandbox user/group. Existing paths keep
/// their image-defined ownership.
#[cfg(unix)]
fn prepare_read_write_path(path: &std::path::Path) -> Result<bool> {
    // SECURITY: use symlink_metadata (lstat) to inspect each path *before*
    // calling chown. chown follows symlinks, so a malicious container image
    // could place a symlink (e.g. /sandbox -> /etc/shadow) to trick the
    // root supervisor into transferring ownership of arbitrary files.
    // The TOCTOU window between lstat and chown is not exploitable because
    // no untrusted process is running yet (the child has not been forked).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(miette::miette!(
                "read_write path '{}' is a symlink — refusing to chown (potential privilege escalation)",
                path.display()
            ));
        }

        debug!(
            path = %path.display(),
            "Preserving ownership for existing read_write path"
        );
        Ok(false)
    } else {
        debug!(path = %path.display(), "Creating read_write directory");
        std::fs::create_dir_all(path).into_diagnostic()?;
        Ok(true)
    }
}

/// Prepare filesystem for the sandboxed process.
///
/// Creates `read_write` directories if they don't exist and sets ownership
/// on newly-created paths to the configured sandbox user/group. This runs as
/// the supervisor (root) before forking the child process.
#[cfg(unix)]
fn prepare_filesystem(policy: &SandboxPolicy) -> Result<()> {
    use nix::unistd::{Group, User, chown};

    let user_name = match policy.process.run_as_user.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };
    let group_name = match policy.process.run_as_group.as_deref() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    };

    // If no user/group configured, nothing to do
    if user_name.is_none() && group_name.is_none() {
        return Ok(());
    }

    // Resolve user and group
    let uid = if let Some(name) = user_name {
        Some(
            User::from_name(name)
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("Sandbox user not found: {name}"))?
                .uid,
        )
    } else {
        None
    };

    let gid = if let Some(name) = group_name {
        Some(
            Group::from_name(name)
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("Sandbox group not found: {name}"))?
                .gid,
        )
    } else {
        None
    };

    // Create missing read_write paths and only chown the ones we created.
    for path in &policy.filesystem.read_write {
        if prepare_read_write_path(path)? {
            debug!(
                path = %path.display(),
                ?uid,
                ?gid,
                "Setting ownership on newly created read_write path"
            );
            chown(path, uid, gid).into_diagnostic()?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn prepare_filesystem(_policy: &SandboxPolicy) -> Result<()> {
    Ok(())
}

/// Background loop that polls the server for policy updates.
///
/// When a new version is detected, attempts to reload the OPA engine via
/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use crate::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;

    // Convert FlushableDenialSummary to proto DenialSummary.
    let proto_summaries: Vec<DenialSummary> = summaries
        .into_iter()
        .map(|s| DenialSummary {
            sandbox_id: String::new(),
            host: s.host,
            port: s.port as u32,
            binary: s.binary,
            ancestors: s.ancestors,
            deny_reason: s.deny_reason,
            first_seen_ms: s.first_seen_ms,
            last_seen_ms: s.last_seen_ms,
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
    let proposals = mechanistic_mapper::generate_proposals(&proto_summaries).await;

    info!(
        sandbox_name = %sandbox_name,
        summaries = proto_summaries.len(),
        proposals = proposals.len(),
        "Flushed denial analysis to gateway"
    );

    client
        .submit_policy_analysis(sandbox_name, proto_summaries, proposals, "mechanistic")
        .await?;

    Ok(())
}

/// `reload_from_proto_with_pid()`. Reports load success/failure back to the
/// server. On failure, the previous engine is untouched (LKG behavior).
///
/// When the entrypoint PID is available, policy reloads include symlink
/// resolution for binary paths via the container filesystem.
async fn run_policy_poll_loop(
    endpoint: &str,
    sandbox_id: &str,
    opa_engine: &Arc<OpaEngine>,
    entrypoint_pid: &Arc<AtomicU32>,
    interval_secs: u64,
    ocsf_enabled: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    use crate::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::PolicySource;
    use std::sync::atomic::Ordering;

    let client = CachedOpenShellClient::connect(endpoint).await?;
    let mut current_config_revision: u64 = 0;
    let mut current_policy_hash = String::new();
    let mut current_settings: std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    > = std::collections::HashMap::new();

    // Initialize revision from the first poll.
    match client.poll_settings(sandbox_id).await {
        Ok(result) => {
            current_config_revision = result.config_revision;
            current_policy_hash = result.policy_hash.clone();
            current_settings = result.settings;
            debug!(
                config_revision = current_config_revision,
                "Settings poll: initial config revision"
            );
        }
        Err(e) => {
            warn!(error = %e, "Settings poll: failed to fetch initial version, will retry");
        }
    }

    let interval = Duration::from_secs(interval_secs);
    loop {
        tokio::time::sleep(interval).await;

        let result = match client.poll_settings(sandbox_id).await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "Settings poll: server unreachable, will retry");
                continue;
            }
        };

        if result.config_revision == current_config_revision {
            continue;
        }

        let policy_changed = result.policy_hash != current_policy_hash;

        // Log which settings changed.
        log_setting_changes(&current_settings, &result.settings);

        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "detected")
            .unmapped("old_config_revision", serde_json::json!(current_config_revision))
            .unmapped("new_config_revision", serde_json::json!(result.config_revision))
            .unmapped("policy_changed", serde_json::json!(policy_changed))
            .message(format!(
                "Settings poll: config change detected [old_revision:{current_config_revision} new_revision:{} policy_changed:{policy_changed}]",
                result.config_revision
            ))
            .build());

        // Only reload OPA when the policy payload actually changed.
        if policy_changed {
            let Some(policy) = result.policy.as_ref() else {
                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Other, "skipped")
                    .message("Settings poll: policy hash changed but no policy payload present; skipping reload")
                    .build());
                current_config_revision = result.config_revision;
                current_policy_hash = result.policy_hash;
                current_settings = result.settings;
                continue;
            };

            let pid = entrypoint_pid.load(Ordering::Acquire);
            match opa_engine.reload_from_proto_with_pid(policy, pid) {
                Ok(()) => {
                    if result.global_policy_version > 0 {
                        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                            .unmapped("global_version", serde_json::json!(result.global_policy_version))
                            .message(format!(
                                "Policy reloaded successfully (global) [policy_hash:{} global_version:{}]",
                                result.policy_hash,
                                result.global_policy_version
                            ))
                            .build());
                    } else {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                .message(format!(
                                    "Policy reloaded successfully [policy_hash:{}]",
                                    result.policy_hash
                                ))
                                .build()
                        );
                    }
                    if result.version > 0 && result.policy_source == PolicySource::Sandbox {
                        if let Err(e) = client
                            .report_policy_status(sandbox_id, result.version, true, "")
                            .await
                        {
                            warn!(error = %e, "Failed to report policy load success");
                        }
                    }
                }
                Err(e) => {
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "failed")
                        .unmapped("version", serde_json::json!(result.version))
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Policy reload failed, keeping last-known-good policy [version:{} error:{e}]",
                            result.version
                        ))
                        .build());
                    if result.version > 0 && result.policy_source == PolicySource::Sandbox {
                        if let Err(report_err) = client
                            .report_policy_status(sandbox_id, result.version, false, &e.to_string())
                            .await
                        {
                            warn!(error = %report_err, "Failed to report policy load failure");
                        }
                    }
                }
            }
        }

        // Apply OCSF JSON toggle from the `ocsf_json_enabled` setting.
        let new_ocsf = extract_bool_setting(&result.settings, "ocsf_json_enabled").unwrap_or(false);
        let prev_ocsf = ocsf_enabled.swap(new_ocsf, Ordering::Relaxed);
        if new_ocsf != prev_ocsf {
            info!(ocsf_json_enabled = new_ocsf, "OCSF JSONL logging toggled");
        }

        current_config_revision = result.config_revision;
        current_policy_hash = result.policy_hash;
        current_settings = result.settings;
    }
}

/// Extract a bool value from an effective setting, if present.
fn extract_bool_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<bool> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::BoolValue(b) => Some(*b),
            _ => None,
        })
}

/// Log individual setting changes between two snapshots.
fn log_setting_changes(
    old: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    new: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    for (key, new_es) in new {
        let new_val = format_setting_value(new_es);
        match old.get(key) {
            Some(old_es) => {
                let old_val = format_setting_value(old_es);
                if old_val != new_val {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "updated")
                            .unmapped("key", serde_json::json!(key))
                            .unmapped("old", serde_json::json!(old_val.to_string()))
                            .unmapped("new", serde_json::json!(new_val.to_string()))
                            .message(format!(
                                "Setting changed [key:{key} old:{old_val} new:{new_val}]"
                            ))
                            .build()
                    );
                }
            }
            None => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "enabled")
                        .unmapped("key", serde_json::json!(key))
                        .unmapped("value", serde_json::json!(new_val.to_string()))
                        .message(format!("Setting added [key:{key} value:{new_val}]"))
                        .build()
                );
            }
        }
    }
    for key in old.keys() {
        if !new.contains_key(key) {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "disabled")
                    .unmapped("key", serde_json::json!(key))
                    .message(format!("Setting removed [key:{key}]"))
                    .build()
            );
        }
    }
}

/// Format an `EffectiveSetting` value for log display.
fn format_setting_value(es: &openshell_core::proto::EffectiveSetting) -> String {
    use openshell_core::proto::setting_value;
    match es.value.as_ref().and_then(|sv| sv.value.as_ref()) {
        None => "<unset>".to_string(),
        Some(setting_value::Value::StringValue(v)) => v.clone(),
        Some(setting_value::Value::BoolValue(v)) => v.to_string(),
        Some(setting_value::Value::IntValue(v)) => v.to_string(),
        Some(setting_value::Value::BytesValue(_)) => "<bytes>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};
    #[cfg(unix)]
    use nix::unistd::{Group, User};
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, symlink};
    use temp_env::with_vars;

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[test]
    fn bundle_to_resolved_routes_converts_all_fields() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![
                openshell_core::proto::ResolvedRoute {
                    name: "frontier".to_string(),
                    base_url: "https://api.example.com/v1".to_string(),
                    api_key: "sk-test-key".to_string(),
                    model_id: "gpt-4".to_string(),
                    protocols: vec![
                        "openai_chat_completions".to_string(),
                        "openai_responses".to_string(),
                    ],
                    provider_type: "openai".to_string(),
                    timeout_secs: 0,
                },
                openshell_core::proto::ResolvedRoute {
                    name: "local".to_string(),
                    base_url: "http://vllm:8000/v1".to_string(),
                    api_key: "local-key".to_string(),
                    model_id: "llama-3".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                    provider_type: String::new(),
                    timeout_secs: 120,
                },
            ],
            revision: "abc123".to_string(),
            generated_at_ms: 1000,
        };

        let routes = bundle_to_resolved_routes(&bundle);

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].endpoint, "https://api.example.com/v1");
        assert_eq!(routes[0].model, "gpt-4");
        assert_eq!(routes[0].api_key, "sk-test-key");
        assert_eq!(
            routes[0].auth,
            openshell_core::inference::AuthHeader::Bearer
        );
        assert_eq!(
            routes[0].protocols,
            vec!["openai_chat_completions", "openai_responses"]
        );
        assert_eq!(
            routes[0].timeout,
            openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            "timeout_secs=0 should map to default"
        );
        assert_eq!(routes[1].endpoint, "http://vllm:8000/v1");
        assert_eq!(
            routes[1].auth,
            openshell_core::inference::AuthHeader::Bearer
        );
        assert_eq!(
            routes[1].timeout,
            Duration::from_secs(120),
            "timeout_secs=120 should map to 120s"
        );
    }

    #[test]
    fn bundle_to_resolved_routes_handles_empty_bundle() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![],
            revision: "empty".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert!(routes.is_empty());
    }

    #[test]
    fn bundle_to_resolved_routes_preserves_name_field() {
        let bundle = openshell_core::proto::GetInferenceBundleResponse {
            routes: vec![openshell_core::proto::ResolvedRoute {
                name: "sandbox-system".to_string(),
                base_url: "https://api.example.com/v1".to_string(),
                api_key: "key".to_string(),
                model_id: "model".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                provider_type: "openai".to_string(),
                timeout_secs: 0,
            }],
            revision: "rev".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert_eq!(routes[0].name, "sandbox-system");
    }

    #[test]
    fn routes_segregated_by_name() {
        let routes = vec![
            openshell_router::config::ResolvedRoute {
                name: "inference.local".to_string(),
                endpoint: "https://api.openai.com/v1".to_string(),
                model: "gpt-4o".to_string(),
                api_key: "key1".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                auth: openshell_core::inference::AuthHeader::Bearer,
                default_headers: vec![],
                passthrough_headers: vec![],
                timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            },
            openshell_router::config::ResolvedRoute {
                name: "sandbox-system".to_string(),
                endpoint: "https://api.anthropic.com/v1".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                api_key: "key2".to_string(),
                protocols: vec!["anthropic_messages".to_string()],
                auth: openshell_core::inference::AuthHeader::Custom("x-api-key"),
                default_headers: vec![],
                passthrough_headers: vec![],
                timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
            },
        ];

        let (user, system) = partition_routes(routes);
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].name, "inference.local");
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].name, "sandbox-system");
    }

    // -- build_inference_context tests --

    #[tokio::test]
    async fn build_inference_context_route_file_loads_routes() {
        use std::io::Write;

        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:8000/v1
    model: llama-3
    protocols: [openai_chat_completions]
    api_key: test-key
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        let ctx = build_inference_context(None, None, Some(path))
            .await
            .expect("should load routes from file");

        let ctx = ctx.expect("context should be Some");
        let cache = ctx.route_cache();
        let routes = cache.read().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].endpoint, "http://localhost:8000/v1");
    }

    #[tokio::test]
    async fn build_inference_context_empty_route_file_returns_none() {
        use std::io::Write;

        // Route file with empty routes list → inference routing disabled (not an error)
        let yaml = "routes: []\n";
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        let ctx = build_inference_context(None, None, Some(path))
            .await
            .expect("empty routes file should not error");
        assert!(
            ctx.is_none(),
            "empty routes should disable inference routing"
        );
    }

    #[tokio::test]
    async fn build_inference_context_no_sources_returns_none() {
        let ctx = build_inference_context(None, None, None)
            .await
            .expect("should succeed with None");

        assert!(ctx.is_none(), "no sources should return None");
    }

    #[tokio::test]
    async fn build_inference_context_route_file_overrides_cluster() {
        use std::io::Write;

        let yaml = r#"
routes:
  - name: inference.local
    endpoint: http://localhost:9999/v1
    model: file-model
    protocols: [openai_chat_completions]
    api_key: file-key
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap();

        // Even with sandbox_id and endpoint, route_file takes precedence
        let ctx = build_inference_context(Some("sb-1"), Some("http://localhost:50051"), Some(path))
            .await
            .expect("should load from file");

        let ctx = ctx.expect("context should be Some");
        let cache = ctx.route_cache();
        let routes = cache.read().await;
        assert_eq!(routes[0].endpoint, "http://localhost:9999/v1");
    }

    #[test]
    fn infer_route_source_prefers_file_mode() {
        assert_eq!(
            infer_route_source(
                Some("sb-1"),
                Some("http://localhost:50051"),
                Some("routes.yaml")
            ),
            InferenceRouteSource::File
        );
    }

    #[test]
    fn infer_route_source_cluster_requires_id_and_endpoint() {
        assert_eq!(
            infer_route_source(Some("sb-1"), Some("http://localhost:50051"), None),
            InferenceRouteSource::Cluster
        );
        assert_eq!(
            infer_route_source(Some("sb-1"), None, None),
            InferenceRouteSource::None
        );
        assert_eq!(
            infer_route_source(None, Some("http://localhost:50051"), None),
            InferenceRouteSource::None
        );
    }

    #[test]
    fn disable_inference_on_empty_routes_depends_on_source() {
        assert!(disable_inference_on_empty_routes(
            InferenceRouteSource::File
        ));
        assert!(!disable_inference_on_empty_routes(
            InferenceRouteSource::Cluster
        ));
        assert!(disable_inference_on_empty_routes(
            InferenceRouteSource::None
        ));
    }

    // ---- Policy disk discovery tests ----

    #[test]
    fn discover_policy_from_nonexistent_path_returns_restrictive_default() {
        let path = std::path::Path::new("/nonexistent/policy.yaml");
        let policy = discover_policy_from_path(path);
        // Restrictive default has no network policies.
        assert!(policy.network_policies.is_empty());
        // But does have filesystem and process policies.
        assert!(policy.filesystem.is_some());
        assert!(policy.process.is_some());
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

        let policy = discover_policy_from_path(&path);
        assert_eq!(policy.network_policies.len(), 1);
        assert!(policy.network_policies.contains_key("test"));
        let fs = policy.filesystem.unwrap();
        assert!(!fs.include_workdir);
    }

    #[test]
    fn discover_policy_from_invalid_yaml_returns_restrictive_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "this is not valid yaml: [[[").unwrap();

        let policy = discover_policy_from_path(&path);
        // Falls back to restrictive default.
        assert!(policy.network_policies.is_empty());
        assert!(policy.filesystem.is_some());
    }

    #[test]
    fn discover_policy_from_unsafe_yaml_falls_back_to_default() {
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

        let policy = discover_policy_from_path(&path);
        // Falls back to restrictive default because of root user.
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn discover_policy_restrictive_default_blocks_network() {
        // In cluster mode we keep proxy mode enabled so `inference.local`
        // can always be routed through proxy/OPA controls.
        let proto = openshell_policy::restrictive_default_policy();
        let local_policy = SandboxPolicy::try_from(proto).expect("conversion should succeed");
        assert!(matches!(local_policy.network.mode, NetworkMode::Proxy));
    }

    // ---- Route refresh interval + revision tests ----

    #[test]
    fn default_route_refresh_interval_is_five_seconds() {
        assert_eq!(DEFAULT_ROUTE_REFRESH_INTERVAL_SECS, 5);
    }

    #[test]
    fn route_refresh_interval_uses_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("9"))],
            || {
                assert_eq!(route_refresh_interval_secs(), 9);
            },
        );
    }

    #[test]
    fn route_refresh_interval_rejects_zero() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("0"))],
            || {
                assert_eq!(
                    route_refresh_interval_secs(),
                    DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
                );
            },
        );
    }

    #[test]
    fn route_refresh_interval_rejects_invalid_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_vars(
            [("OPENSHELL_ROUTE_REFRESH_INTERVAL_SECS", Some("abc"))],
            || {
                assert_eq!(
                    route_refresh_interval_secs(),
                    DEFAULT_ROUTE_REFRESH_INTERVAL_SECS
                );
            },
        );
    }

    #[tokio::test]
    async fn route_cache_preserves_content_when_not_written() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let routes = vec![openshell_router::config::ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "http://original:8000/v1".to_string(),
            model: "original-model".to_string(),
            api_key: "key".to_string(),
            auth: openshell_core::inference::AuthHeader::Bearer,
            protocols: vec!["openai_chat_completions".to_string()],
            default_headers: vec![],
            passthrough_headers: vec![],
            timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
        }];

        let cache = Arc::new(RwLock::new(routes));

        // Verify the cache preserves its content — the revision-based skip
        // logic in spawn_route_refresh ensures the cache is only written
        // when the revision actually changes.
        let read = cache.read().await;
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].model, "original-model");
    }

    #[cfg(unix)]
    fn sandbox_policy_with_read_write(
        path: std::path::PathBuf,
        run_as_user: Option<String>,
        run_as_group: Option<String>,
    ) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![],
                read_write: vec![path],
                include_workdir: false,
            },
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user,
                run_as_group,
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_creates_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing").join("nested");

        assert!(prepare_read_write_path(&missing).unwrap());
        assert!(missing.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_preserves_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();

        assert!(!prepare_read_write_path(&existing).unwrap());
        assert!(existing.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_read_write_path_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = prepare_read_write_path(&link).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is a symlink — refusing to chown"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_filesystem_skips_chown_for_existing_read_write_paths() {
        if nix::unistd::geteuid().is_root() {
            return;
        }

        let current_user = User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .expect("current user entry");
        let restricted_group = Group::from_gid(nix::unistd::Gid::from_raw(0))
            .unwrap()
            .expect("gid 0 group entry");
        if restricted_group.gid == nix::unistd::getegid() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let before = std::fs::metadata(&existing).unwrap();

        let policy = sandbox_policy_with_read_write(
            existing.clone(),
            Some(current_user.name),
            Some(restricted_group.name),
        );

        prepare_filesystem(&policy).expect("existing path should not be re-owned");

        let after = std::fs::metadata(&existing).unwrap();
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }
}
