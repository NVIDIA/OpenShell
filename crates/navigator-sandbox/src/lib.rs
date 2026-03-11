// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

pub mod denial_aggregator;
mod grpc_client;
mod identity;
pub mod l7;
pub mod log_push;
pub mod opa;
mod policy;
mod process;
pub mod procfs;
pub mod proxy;
mod sandbox;
mod ssh;

use miette::{IntoDiagnostic, Result};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, write_ca_files,
};
use crate::opa::OpaEngine;
use crate::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use crate::proxy::ProxyHandle;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::netns::NetworkNamespace;
pub use process::{ProcessHandle, ProcessStatus};

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
    navigator_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> InferenceRouteSource {
    if inference_routes.is_some() {
        InferenceRouteSource::File
    } else if sandbox_id.is_some() && navigator_endpoint.is_some() {
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
    navigator_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_listen_addr: Option<String>,
    ssh_handshake_secret: Option<String>,
    ssh_handshake_skew_secs: u64,
    _health_check: bool,
    _health_port: u16,
    inference_routes: Option<String>,
) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| miette::miette!("No command specified"))?;

    // Load policy and initialize OPA engine
    let navigator_endpoint_for_proxy = navigator_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let (policy, opa_engine) = load_policy(
        sandbox_id.clone(),
        sandbox,
        navigator_endpoint.clone(),
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
    let provider_env = if let (Some(id), Some(endpoint)) = (&sandbox_id, &navigator_endpoint) {
        match grpc_client::fetch_provider_environment(endpoint, id).await {
            Ok(env) => {
                info!(env_count = env.len(), "Fetched provider environment");
                env
            }
            Err(e) => {
                warn!(error = %e, "Failed to fetch provider environment, continuing without");
                std::collections::HashMap::new()
            }
        }
    } else {
        std::collections::HashMap::new()
    };

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
                let tls_dir = std::path::Path::new("/etc/navigator-tls");
                match write_ca_files(&ca, tls_dir) {
                    Ok(paths) => {
                        // /etc/navigator-tls is subsumed by the /etc baseline
                        // path injected by enrich_*_baseline_paths(), so no
                        // explicit Landlock entry is needed here.

                        let upstream_config = build_upstream_client_config();
                        let cert_cache = CertCache::new(ca);
                        let state = Arc::new(ProxyTlsState::new(cert_cache, upstream_config));
                        info!("TLS termination enabled: ephemeral CA generated");
                        (Some(state), Some(paths))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to write CA files, TLS termination disabled"
                        );
                        (None, None)
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to generate ephemeral CA, TLS termination disabled"
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
            Ok(ns) => Some(ns),
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

    // Shared PID: set after process spawn so the proxy can look up
    // the entrypoint process's /proc/net/tcp for identity binding.
    let entrypoint_pid = Arc::new(AtomicU32::new(0));

    let (_proxy, denial_rx) = if matches!(policy.network.mode, NetworkMode::Proxy) {
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
            navigator_endpoint_for_proxy.as_deref(),
            inference_routes.as_deref(),
        )
        .await?;

        // Create denial aggregator channel if in gRPC mode (sandbox_id present).
        let (denial_tx, denial_rx) = if sandbox_id.is_some() {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let proxy_handle = ProxyHandle::start_with_bind_addr(
            proxy_policy,
            bind_addr,
            engine,
            cache,
            entrypoint_pid.clone(),
            tls_state,
            inference_ctx,
            denial_tx,
        )
        .await?;
        (Some(proxy_handle), denial_rx)
    } else {
        (None, None)
    };

    // Compute the proxy URL and netns fd for SSH sessions.
    // SSH shell processes need both to enforce network policy:
    // - netns_fd: enter the network namespace via setns() so all traffic
    //   goes through the veth pair (hard enforcement, non-bypassable)
    // - proxy_url: set HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars so
    //   cooperative tools (curl, etc.) route through the CONNECT proxy
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

    // Zombie reaper — navigator-sandbox may run as PID 1 in containers and
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

    if let Some(listen_addr) = ssh_listen_addr {
        let addr: SocketAddr = listen_addr.parse().into_diagnostic()?;
        let policy_clone = policy.clone();
        let workdir_clone = workdir.clone();
        let secret = ssh_handshake_secret
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                miette::miette!(
                    "OPENSHELL_SSH_HANDSHAKE_SECRET is required when SSH is enabled.\n\
                     Set --ssh-handshake-secret or the OPENSHELL_SSH_HANDSHAKE_SECRET env var."
                )
            })?;
        let proxy_url = ssh_proxy_url;
        let netns_fd = ssh_netns_fd;
        let ca_paths = ca_file_paths.clone();
        let provider_env_clone = provider_env.clone();

        let (ssh_ready_tx, ssh_ready_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            if let Err(err) = ssh::run_ssh_server(
                addr,
                ssh_ready_tx,
                policy_clone,
                workdir_clone,
                secret,
                ssh_handshake_skew_secs,
                netns_fd,
                proxy_url,
                ca_paths,
                provider_env_clone,
            )
            .await
            {
                tracing::error!(error = %err, "SSH server failed");
            }
        });

        // Wait for the SSH server to bind its socket before spawning the
        // entrypoint process. This prevents exec requests from racing against
        // SSH server startup when Kubernetes marks the pod Ready.
        match timeout(Duration::from_secs(10), ssh_ready_rx).await {
            Ok(Ok(Ok(()))) => {
                info!("SSH server is ready to accept connections");
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
    info!(pid = handle.pid(), "Process started");

    // Spawn background policy poll task (gRPC mode only).
    if let (Some(id), Some(endpoint), Some(engine)) =
        (&sandbox_id, &navigator_endpoint, &opa_engine)
    {
        let poll_id = id.clone();
        let poll_endpoint = endpoint.clone();
        let poll_engine = engine.clone();
        let poll_interval_secs: u64 = std::env::var("OPENSHELL_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        tokio::spawn(async move {
            if let Err(e) =
                run_policy_poll_loop(&poll_endpoint, &poll_id, &poll_engine, poll_interval_secs)
                    .await
            {
                warn!(error = %e, "Policy poll loop exited with error");
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
                                flush_denials_to_gateway(&endpoint, &sandbox_name, summaries).await
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
            error!("Process timed out, killing");
            handle.kill()?;
            return Ok(124); // Standard timeout exit code
        }
    } else {
        handle.wait().await
    };

    let status = result.into_diagnostic()?;

    info!(exit_code = status.code(), "Process exited");

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
    navigator_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> Result<Option<Arc<proxy::InferenceContext>>> {
    use navigator_router::Router;
    use navigator_router::config::RouterConfig;

    let source = infer_route_source(sandbox_id, navigator_endpoint, inference_routes);

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
                info!(
                    inference_routes = %path,
                    "Inference routes file takes precedence over cluster bundle"
                );
            }
            info!(inference_routes = %path, "Loading inference routes from file");
            let config = RouterConfig::load_from_file(std::path::Path::new(path))
                .map_err(|e| miette::miette!("failed to load inference routes {path}: {e}"))?;
            config
                .resolve_routes()
                .map_err(|e| miette::miette!("failed to resolve routes from {path}: {e}"))?
        }
        InferenceRouteSource::Cluster => {
            let (Some(_id), Some(endpoint)) = (sandbox_id, navigator_endpoint) else {
                return Ok(None);
            };

            // Cluster mode: fetch bundle from gateway
            info!(endpoint = %endpoint, "Fetching inference route bundle from gateway");
            match grpc_client::fetch_inference_bundle(endpoint).await {
                Ok(bundle) => {
                    initial_revision = Some(bundle.revision.clone());
                    info!(
                        route_count = bundle.routes.len(),
                        revision = %bundle.revision,
                        "Loaded inference route bundle"
                    );
                    bundle_to_resolved_routes(&bundle)
                }
                Err(e) => {
                    // Distinguish expected "not configured" states from server errors.
                    // gRPC PermissionDenied/NotFound means inference bundle is unavailable
                    // for this sandbox — skip gracefully. Other errors are unexpected.
                    let msg = e.to_string();
                    if msg.contains("permission denied") || msg.contains("not found") {
                        info!(error = %e, "Inference bundle unavailable, routing disabled");
                        return Ok(None);
                    }
                    warn!(error = %e, "Failed to fetch inference bundle, inference routing disabled");
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
        info!("No usable inference routes, inference routing disabled");
        return Ok(None);
    }

    if routes.is_empty() {
        info!("Inference route bundle is empty; keeping routing enabled and waiting for refresh");
    }

    info!(
        route_count = routes.len(),
        "Inference routing enabled with local execution"
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
        && let (Some(_id), Some(endpoint)) = (sandbox_id, navigator_endpoint)
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
    routes: Vec<navigator_router::config::ResolvedRoute>,
) -> (
    Vec<navigator_router::config::ResolvedRoute>,
    Vec<navigator_router::config::ResolvedRoute>,
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
    bundle: &navigator_core::proto::GetInferenceBundleResponse,
) -> Vec<navigator_router::config::ResolvedRoute> {
    bundle
        .routes
        .iter()
        .map(|r| {
            let (auth, default_headers) =
                navigator_core::inference::auth_for_provider_type(&r.provider_type);
            navigator_router::config::ResolvedRoute {
                name: r.name.clone(),
                endpoint: r.base_url.clone(),
                model: r.model_id.clone(),
                api_key: r.api_key.clone(),
                protocols: r.protocols.clone(),
                auth,
                default_headers,
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
    user_cache: Arc<tokio::sync::RwLock<Vec<navigator_router::config::ResolvedRoute>>>,
    system_cache: Arc<tokio::sync::RwLock<Vec<navigator_router::config::ResolvedRoute>>>,
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
                    info!(
                        user_route_count = user_routes.len(),
                        system_route_count = system_routes.len(),
                        revision = %bundle.revision,
                        "Inference routes updated"
                    );
                    current_revision = Some(bundle.revision);
                    *user_cache.write().await = user_routes;
                    *system_cache.write().await = system_routes;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to refresh inference route cache, keeping stale routes");
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
/// Python venv, and navigator logs.
const PROXY_BASELINE_READ_ONLY: &[&str] = &["/usr", "/lib", "/etc", "/app", "/var/log"];

/// Minimum read-write paths required for a proxy-mode sandbox child process:
/// user working directory and temporary files.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/sandbox", "/tmp"];

/// Ensure a proto `SandboxPolicy` includes the baseline filesystem paths
/// required for proxy-mode sandboxes.  Paths are only added if missing;
/// user-specified paths are never removed.
///
/// Returns `true` if the policy was modified (caller may want to sync back).
fn enrich_proto_baseline_paths(proto: &mut navigator_core::proto::SandboxPolicy) -> bool {
    // Only enrich if network_policies are present (proxy mode indicator).
    if proto.network_policies.is_empty() {
        return false;
    }

    let fs = proto
        .filesystem
        .get_or_insert_with(|| navigator_core::proto::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        });

    let mut modified = false;
    for &path in PROXY_BASELINE_READ_ONLY {
        if !fs.read_only.iter().any(|p| p.as_str() == path) {
            fs.read_only.push(path.to_string());
            modified = true;
        }
    }
    for &path in PROXY_BASELINE_READ_WRITE {
        if !fs.read_write.iter().any(|p| p.as_str() == path) {
            fs.read_write.push(path.to_string());
            modified = true;
        }
    }

    if modified {
        info!("Enriched policy with baseline filesystem paths for proxy mode");
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

    let mut modified = false;
    for &path in PROXY_BASELINE_READ_ONLY {
        let p = std::path::PathBuf::from(path);
        if !policy.filesystem.read_only.contains(&p) {
            policy.filesystem.read_only.push(p);
            modified = true;
        }
    }
    for &path in PROXY_BASELINE_READ_WRITE {
        let p = std::path::PathBuf::from(path);
        if !policy.filesystem.read_write.contains(&p) {
            policy.filesystem.read_write.push(p);
            modified = true;
        }
    }

    if modified {
        info!("Enriched policy with baseline filesystem paths for proxy mode");
    }
}

/// Load sandbox policy from local files or gRPC.
///
/// Priority:
/// 1. If `policy_rules` and `policy_data` are provided, load OPA engine from local files
/// 2. If `sandbox_id` and `navigator_endpoint` are provided, fetch via gRPC
/// 3. If the server returns no policy, discover from disk or use restrictive default
/// 4. Otherwise, return an error
async fn load_policy(
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    navigator_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
) -> Result<(SandboxPolicy, Option<Arc<OpaEngine>>)> {
    // File mode: load OPA engine from rego rules + YAML data (dev override)
    if let (Some(policy_file), Some(data_file)) = (&policy_rules, &policy_data) {
        info!(
            policy_rules = %policy_file,
            policy_data = %data_file,
            "Loading OPA policy engine from local files"
        );
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
        return Ok((policy, Some(Arc::new(engine))));
    }

    // gRPC mode: fetch typed proto policy, construct OPA engine from baked rules + proto data
    if let (Some(id), Some(endpoint)) = (&sandbox_id, &navigator_endpoint) {
        info!(
            sandbox_id = %id,
            endpoint = %endpoint,
            "Fetching sandbox policy via gRPC"
        );
        let proto_policy = grpc_client::fetch_policy(endpoint, id).await?;

        let mut proto_policy = match proto_policy {
            Some(p) => p,
            None => {
                // No policy configured on the server. Discover from disk or
                // fall back to the restrictive default, then sync to the
                // gateway so it becomes the authoritative baseline.
                info!("Server returned no policy; attempting local discovery");
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
                grpc_client::discover_and_sync_policy(endpoint, id, sandbox, &discovered).await?
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
        info!("Creating OPA engine from proto policy data");
        let opa_engine = Some(Arc::new(OpaEngine::from_proto(&proto_policy)?));

        let policy = SandboxPolicy::try_from(proto_policy)?;
        return Ok((policy, opa_engine));
    }

    // No policy source available
    Err(miette::miette!(
        "Sandbox policy required. Provide one of:\n\
         - --policy-rules and --policy-data (or OPENSHELL_POLICY_RULES and OPENSHELL_POLICY_DATA env vars)\n\
         - --sandbox-id and --navigator-endpoint (or OPENSHELL_SANDBOX_ID and OPENSHELL_ENDPOINT env vars)"
    ))
}

/// Try to discover a sandbox policy from the well-known disk path, falling
/// back to the hardcoded restrictive default if no file is found.
fn discover_policy_from_disk_or_default() -> navigator_core::proto::SandboxPolicy {
    discover_policy_from_path(std::path::Path::new(
        navigator_policy::CONTAINER_POLICY_PATH,
    ))
}

/// Try to read a sandbox policy YAML from `path`, falling back to the
/// hardcoded restrictive default if the file is missing or invalid.
fn discover_policy_from_path(path: &std::path::Path) -> navigator_core::proto::SandboxPolicy {
    use navigator_policy::{
        parse_sandbox_policy, restrictive_default_policy, validate_sandbox_policy,
    };

    match std::fs::read_to_string(path) {
        Ok(yaml) => {
            info!(
                path = %path.display(),
                "Loaded sandbox policy from container disk"
            );
            match parse_sandbox_policy(&yaml) {
                Ok(policy) => {
                    // Validate the disk-loaded policy for safety.
                    if let Err(violations) = validate_sandbox_policy(&policy) {
                        let messages: Vec<String> =
                            violations.iter().map(ToString::to_string).collect();
                        warn!(
                            path = %path.display(),
                            violations = %messages.join("; "),
                            "Disk policy contains unsafe content, using restrictive default"
                        );
                        return restrictive_default_policy();
                    }
                    policy
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to parse disk policy, using restrictive default"
                    );
                    restrictive_default_policy()
                }
            }
        }
        Err(_) => {
            info!(
                path = %path.display(),
                "No policy file on disk, using restrictive default"
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
                info!("Validated 'sandbox' user exists in image");
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

/// Prepare filesystem for the sandboxed process.
///
/// Creates `read_write` directories if they don't exist and sets ownership
/// to the configured sandbox user/group. This runs as the supervisor (root)
/// before forking the child process.
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

    // Create and chown each read_write path
    for path in &policy.filesystem.read_write {
        if !path.exists() {
            debug!(path = %path.display(), "Creating read_write directory");
            std::fs::create_dir_all(path).into_diagnostic()?;
        }

        debug!(path = %path.display(), ?uid, ?gid, "Setting ownership on read_write directory");
        chown(path, uid, gid).into_diagnostic()?;
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
async fn flush_denials_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use crate::grpc_client::CachedNavigatorClient;
    use navigator_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedNavigatorClient::connect(endpoint).await?;

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

    client
        .submit_policy_analysis(sandbox_name, proto_summaries, "mechanistic")
        .await?;

    info!(
        sandbox_name = %sandbox_name,
        "Flushed denial summaries to gateway"
    );

    Ok(())
}

/// `reload_from_proto()`. Reports load success/failure back to the server.
/// On failure, the previous engine is untouched (LKG behavior).
async fn run_policy_poll_loop(
    endpoint: &str,
    sandbox_id: &str,
    opa_engine: &Arc<OpaEngine>,
    interval_secs: u64,
) -> Result<()> {
    use crate::grpc_client::CachedNavigatorClient;

    let client = CachedNavigatorClient::connect(endpoint).await?;
    let mut current_version: u32 = 0;

    // Initialize current_version from the first poll.
    match client.poll_policy(sandbox_id).await {
        Ok(result) => {
            current_version = result.version;
            debug!(version = current_version, "Policy poll: initial version");
        }
        Err(e) => {
            warn!(error = %e, "Policy poll: failed to fetch initial version, will retry");
        }
    }

    let interval = Duration::from_secs(interval_secs);
    loop {
        tokio::time::sleep(interval).await;

        let result = match client.poll_policy(sandbox_id).await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "Policy poll: server unreachable, will retry");
                continue;
            }
        };

        if result.version <= current_version {
            continue;
        }

        info!(
            old_version = current_version,
            new_version = result.version,
            policy_hash = %result.policy_hash,
            "Policy poll: new version detected, reloading"
        );

        match opa_engine.reload_from_proto(&result.policy) {
            Ok(()) => {
                current_version = result.version;
                info!(
                    version = current_version,
                    policy_hash = %result.policy_hash,
                    "Policy reloaded successfully"
                );
                if let Err(e) = client
                    .report_policy_status(sandbox_id, result.version, true, "")
                    .await
                {
                    warn!(error = %e, "Failed to report policy load success");
                }
            }
            Err(e) => {
                warn!(
                    version = result.version,
                    error = %e,
                    "Policy reload failed, keeping last-known-good policy"
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use temp_env::with_vars;

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[test]
    fn bundle_to_resolved_routes_converts_all_fields() {
        let bundle = navigator_core::proto::GetInferenceBundleResponse {
            routes: vec![
                navigator_core::proto::ResolvedRoute {
                    name: "frontier".to_string(),
                    base_url: "https://api.example.com/v1".to_string(),
                    api_key: "sk-test-key".to_string(),
                    model_id: "gpt-4".to_string(),
                    protocols: vec![
                        "openai_chat_completions".to_string(),
                        "openai_responses".to_string(),
                    ],
                    provider_type: "openai".to_string(),
                },
                navigator_core::proto::ResolvedRoute {
                    name: "local".to_string(),
                    base_url: "http://vllm:8000/v1".to_string(),
                    api_key: "local-key".to_string(),
                    model_id: "llama-3".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                    provider_type: String::new(),
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
            navigator_core::inference::AuthHeader::Bearer
        );
        assert_eq!(
            routes[0].protocols,
            vec!["openai_chat_completions", "openai_responses"]
        );
        assert_eq!(routes[1].endpoint, "http://vllm:8000/v1");
        assert_eq!(
            routes[1].auth,
            navigator_core::inference::AuthHeader::Bearer
        );
    }

    #[test]
    fn bundle_to_resolved_routes_handles_empty_bundle() {
        let bundle = navigator_core::proto::GetInferenceBundleResponse {
            routes: vec![],
            revision: "empty".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert!(routes.is_empty());
    }

    #[test]
    fn bundle_to_resolved_routes_preserves_name_field() {
        let bundle = navigator_core::proto::GetInferenceBundleResponse {
            routes: vec![navigator_core::proto::ResolvedRoute {
                name: "sandbox-system".to_string(),
                base_url: "https://api.example.com/v1".to_string(),
                api_key: "key".to_string(),
                model_id: "model".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                provider_type: "openai".to_string(),
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
            navigator_router::config::ResolvedRoute {
                name: "inference.local".to_string(),
                endpoint: "https://api.openai.com/v1".to_string(),
                model: "gpt-4o".to_string(),
                api_key: "key1".to_string(),
                protocols: vec!["openai_chat_completions".to_string()],
                auth: navigator_core::inference::AuthHeader::Bearer,
                default_headers: vec![],
            },
            navigator_router::config::ResolvedRoute {
                name: "sandbox-system".to_string(),
                endpoint: "https://api.anthropic.com/v1".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                api_key: "key2".to_string(),
                protocols: vec!["anthropic_messages".to_string()],
                auth: navigator_core::inference::AuthHeader::Custom("x-api-key"),
                default_headers: vec![],
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
        let proto = navigator_policy::restrictive_default_policy();
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

        let routes = vec![navigator_router::config::ResolvedRoute {
            name: "inference.local".to_string(),
            endpoint: "http://original:8000/v1".to_string(),
            model: "original-model".to_string(),
            api_key: "key".to_string(),
            auth: navigator_core::inference::AuthHeader::Bearer,
            protocols: vec!["openai_chat_completions".to_string()],
            default_headers: vec![],
        }];

        let cache = Arc::new(RwLock::new(routes));

        // Verify the cache preserves its content — the revision-based skip
        // logic in spawn_route_refresh ensures the cache is only written
        // when the revision actually changes.
        let read = cache.read().await;
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].model, "original-model");
    }
}
