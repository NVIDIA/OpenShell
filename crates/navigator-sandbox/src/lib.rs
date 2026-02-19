//! Navigator Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

mod grpc_client;
mod identity;
pub mod l7;
pub mod opa;
mod policy;
mod process;
pub mod procfs;
mod proxy;
mod sandbox;
mod ssh;

use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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
                // Log warning but continue without netns - allows running without CAP_NET_ADMIN
                tracing::warn!(
                    error = %e,
                    "Failed to create network namespace, continuing without isolation"
                );
                None
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

        Some(
            ProxyHandle::start_with_bind_addr(
                proxy_policy,
                bind_addr,
                engine,
                cache,
                entrypoint_pid.clone(),
                control_plane_endpoints,
                tls_state,
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
    let ssh_netns_fd = netns.as_ref().and_then(|ns| ns.ns_fd());

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

    if let Some(listen_addr) = ssh_listen_addr {
        let addr: SocketAddr = listen_addr.parse().into_diagnostic()?;
        let policy_clone = policy.clone();
        let workdir_clone = workdir.clone();
        let secret = ssh_handshake_secret.unwrap_or_default();
        let proxy_url = ssh_proxy_url;
        let netns_fd = ssh_netns_fd;
        let ca_paths = ca_file_paths.clone();
        let provider_env_clone = provider_env.clone();
        tokio::spawn(async move {
            if let Err(err) = ssh::run_ssh_server(
                addr,
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

        // Build OPA engine from baked-in rules + typed proto data
        let opa_engine = if proto_policy.network_policies.is_empty() {
            info!("No network policies in proto, skipping OPA engine");
            None
        } else {
            info!("Creating OPA engine from proto policy data");
            Some(Arc::new(OpaEngine::from_proto(&proto_policy)?))
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
