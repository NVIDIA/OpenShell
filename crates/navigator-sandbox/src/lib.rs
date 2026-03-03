// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Navigator Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

mod grpc_client;
mod identity;
pub mod l7;
pub mod log_push;
pub mod opa;
mod policy;
mod process;
pub mod procfs;
mod proxy;
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
use tracing::{debug, error, info, warn};

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

/// How often the sandbox re-fetches the inference route bundle from the gateway
/// in cluster mode. Keeps local route cache reasonably fresh without excessive
/// gRPC traffic. File-based routes (`--inference-routes`) are loaded once at
/// startup and never refreshed.
const ROUTE_REFRESH_INTERVAL_SECS: u64 = 30;

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
    let (mut policy, opa_engine) = load_policy(
        sandbox_id.clone(),
        navigator_endpoint.clone(),
        policy_rules,
        policy_data,
    )
    .await?;

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
                        // Make the TLS directory readable under Landlock
                        policy.filesystem.read_only.push(tls_dir.to_path_buf());

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

    let _proxy = if matches!(policy.network.mode, NetworkMode::Proxy) {
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

        // Build the control plane allowlist: the navigator endpoint is always
        // allowed so sandbox processes can reach the server for inference.
        let control_plane_endpoints = navigator_endpoint_for_proxy
            .as_deref()
            .and_then(proxy::parse_endpoint_url)
            .into_iter()
            .collect::<Vec<_>>();

        // Build inference context for local routing of intercepted inference calls.
        let inference_ctx = build_inference_context(
            sandbox_id.as_deref(),
            navigator_endpoint_for_proxy.as_deref(),
            inference_routes.as_deref(),
        )
        .await?;

        Some(
            ProxyHandle::start_with_bind_addr(
                proxy_policy,
                bind_addr,
                engine,
                cache,
                entrypoint_pid.clone(),
                control_plane_endpoints,
                tls_state,
                inference_ctx,
            )
            .await?,
        )
    } else {
        None
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
        let secret = ssh_handshake_secret.unwrap_or_default();
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
        let poll_interval_secs: u64 = std::env::var("NAVIGATOR_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        tokio::spawn(async move {
            if let Err(e) =
                run_policy_poll_loop(&poll_endpoint, &poll_id, &poll_engine, poll_interval_secs)
                    .await
            {
                warn!(error = %e, "Policy poll loop exited with error");
            }
        });
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
            let (Some(id), Some(endpoint)) = (sandbox_id, navigator_endpoint) else {
                return Ok(None);
            };

            // Cluster mode: fetch bundle from gateway
            info!(sandbox_id = %id, endpoint = %endpoint, "Fetching inference route bundle from gateway");
            match grpc_client::fetch_inference_bundle(endpoint, id).await {
                Ok(bundle) => {
                    info!(
                        route_count = bundle.routes.len(),
                        revision = %bundle.revision,
                        "Loaded inference route bundle"
                    );
                    bundle_to_resolved_routes(&bundle)
                }
                Err(e) => {
                    // Distinguish "no inference policy" (expected) from server errors.
                    // gRPC PermissionDenied/NotFound means inference is not configured
                    // for this sandbox — skip gracefully. Other errors are unexpected.
                    let msg = e.to_string();
                    if msg.contains("permission denied") || msg.contains("not found") {
                        info!(error = %e, "Sandbox has no inference policy, inference routing disabled");
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

    let router =
        Router::new().map_err(|e| miette::miette!("failed to initialize inference router: {e}"))?;
    let patterns = l7::inference::default_patterns();
    let ctx = Arc::new(proxy::InferenceContext::new(patterns, router, routes));

    // Spawn background route cache refresh for cluster mode
    if matches!(source, InferenceRouteSource::Cluster)
        && let (Some(id), Some(endpoint)) = (sandbox_id, navigator_endpoint)
    {
        spawn_route_refresh(ctx.route_cache(), id.to_string(), endpoint.to_string());
    }

    Ok(Some(ctx))
}

/// Convert a proto bundle response into resolved routes for the router.
fn bundle_to_resolved_routes(
    bundle: &navigator_core::proto::GetSandboxInferenceBundleResponse,
) -> Vec<navigator_router::config::ResolvedRoute> {
    bundle
        .routes
        .iter()
        .map(|r| navigator_router::config::ResolvedRoute {
            routing_hint: r.routing_hint.clone(),
            endpoint: r.base_url.clone(),
            model: r.model_id.clone(),
            api_key: r.api_key.clone(),
            protocols: r.protocols.clone(),
        })
        .collect()
}

/// Spawn a background task that periodically refreshes the route cache from the gateway.
fn spawn_route_refresh(
    cache: Arc<tokio::sync::RwLock<Vec<navigator_router::config::ResolvedRoute>>>,
    sandbox_id: String,
    endpoint: String,
) {
    tokio::spawn(async move {
        use tokio::time::{MissedTickBehavior, interval};

        let mut tick = interval(Duration::from_secs(ROUTE_REFRESH_INTERVAL_SECS));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tick.tick().await;

            match grpc_client::fetch_inference_bundle(&endpoint, &sandbox_id).await {
                Ok(bundle) => {
                    let routes = bundle_to_resolved_routes(&bundle);
                    debug!(
                        route_count = routes.len(),
                        revision = %bundle.revision,
                        "Refreshed inference route cache"
                    );
                    *cache.write().await = routes;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to refresh inference route cache, keeping stale routes");
                }
            }
        }
    });
}

/// Load sandbox policy from local files or gRPC.
///
/// Priority:
/// 1. If `policy_rules` and `policy_data` are provided, load OPA engine from local files
/// 2. If `sandbox_id` and `navigator_endpoint` are provided, fetch via gRPC
/// 3. Otherwise, return an error
async fn load_policy(
    sandbox_id: Option<String>,
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
        let policy = SandboxPolicy {
            version: 1,
            filesystem: config.filesystem,
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: config.landlock,
            process: config.process,
        };
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

        // Build OPA engine from baked-in rules + typed proto data.
        // The engine is needed when network policies exist OR inference routing
        // is configured (inference routing uses OPA to decide inspect_for_inference).
        let has_network_policies = !proto_policy.network_policies.is_empty();
        let has_inference = proto_policy
            .inference
            .as_ref()
            .is_some_and(|inf| !inf.allowed_routes.is_empty());
        let opa_engine = if has_network_policies || has_inference {
            info!("Creating OPA engine from proto policy data");
            Some(Arc::new(OpaEngine::from_proto(&proto_policy)?))
        } else {
            info!("No network policies or inference config in proto, skipping OPA engine");
            None
        };

        let policy = SandboxPolicy::try_from(proto_policy)?;
        return Ok((policy, opa_engine));
    }

    // No policy source available
    Err(miette::miette!(
        "Sandbox policy required. Provide one of:\n\
         - --policy-rules and --policy-data (or NAVIGATOR_POLICY_RULES and NAVIGATOR_POLICY_DATA env vars)\n\
         - --sandbox-id and --navigator-endpoint (or NAVIGATOR_SANDBOX_ID and NAVIGATOR_ENDPOINT env vars)"
    ))
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

    #[test]
    fn bundle_to_resolved_routes_converts_all_fields() {
        let bundle = navigator_core::proto::GetSandboxInferenceBundleResponse {
            routes: vec![
                navigator_core::proto::SandboxResolvedRoute {
                    routing_hint: "frontier".to_string(),
                    base_url: "https://api.example.com/v1".to_string(),
                    api_key: "sk-test-key".to_string(),
                    model_id: "gpt-4".to_string(),
                    protocols: vec![
                        "openai_chat_completions".to_string(),
                        "openai_responses".to_string(),
                    ],
                },
                navigator_core::proto::SandboxResolvedRoute {
                    routing_hint: "local".to_string(),
                    base_url: "http://vllm:8000/v1".to_string(),
                    api_key: "local-key".to_string(),
                    model_id: "llama-3".to_string(),
                    protocols: vec!["openai_chat_completions".to_string()],
                },
            ],
            revision: "abc123".to_string(),
            generated_at_ms: 1000,
        };

        let routes = bundle_to_resolved_routes(&bundle);

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].routing_hint, "frontier");
        assert_eq!(routes[0].endpoint, "https://api.example.com/v1");
        assert_eq!(routes[0].model, "gpt-4");
        assert_eq!(routes[0].api_key, "sk-test-key");
        assert_eq!(
            routes[0].protocols,
            vec!["openai_chat_completions", "openai_responses"]
        );
        assert_eq!(routes[1].routing_hint, "local");
        assert_eq!(routes[1].endpoint, "http://vllm:8000/v1");
    }

    #[test]
    fn bundle_to_resolved_routes_handles_empty_bundle() {
        let bundle = navigator_core::proto::GetSandboxInferenceBundleResponse {
            routes: vec![],
            revision: "empty".to_string(),
            generated_at_ms: 0,
        };

        let routes = bundle_to_resolved_routes(&bundle);
        assert!(routes.is_empty());
    }

    // -- build_inference_context tests --

    #[tokio::test]
    async fn build_inference_context_route_file_loads_routes() {
        use std::io::Write;

        let yaml = r#"
routes:
  - routing_hint: local
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
        assert_eq!(routes[0].routing_hint, "local");
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
  - routing_hint: file-route
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
        assert_eq!(routes[0].routing_hint, "file-route");
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
}
