//! Navigator Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

mod grpc_client;
mod identity;
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
use tracing::{debug, error, info};

use crate::identity::BinaryIdentityCache;
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
    rego_policy: Option<String>,
    rego_data: Option<String>,
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
    let (policy, opa_engine) =
        load_policy(sandbox_id, navigator_endpoint, rego_policy, rego_data).await?;

    // Create identity cache for SHA256 TOFU when OPA is active
    let identity_cache = opa_engine
        .as_ref()
        .map(|_| Arc::new(BinaryIdentityCache::new()));

    // Prepare filesystem: create and chown read_write directories
    prepare_filesystem(&policy)?;

    if let Some(listen_addr) = ssh_listen_addr {
        let addr: SocketAddr = listen_addr.parse().into_diagnostic()?;
        let policy_clone = policy.clone();
        let workdir_clone = workdir.clone();
        let secret = ssh_handshake_secret.unwrap_or_default();
        tokio::spawn(async move {
            if let Err(err) = ssh::run_ssh_server(
                addr,
                policy_clone,
                workdir_clone,
                secret,
                ssh_handshake_skew_secs,
            )
            .await
            {
                tracing::error!(error = %err, "SSH server failed");
            }
        });
    }

    // Create network namespace for proxy mode (Linux only)
    // This must be created before the proxy so the proxy can bind to the veth IP
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

        Some(
            ProxyHandle::start_with_bind_addr(
                proxy_policy,
                bind_addr,
                engine,
                cache,
                entrypoint_pid.clone(),
            )
            .await?,
        )
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        workdir.as_deref(),
        interactive,
        &policy,
        netns.as_ref(),
    )?;

    #[cfg(not(target_os = "linux"))]
    let mut handle = ProcessHandle::spawn(program, args, workdir.as_deref(), interactive, &policy)?;

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

/// Load sandbox policy from Rego files or gRPC.
///
/// Priority:
/// 1. If `rego_policy` and `rego_data` are provided, load OPA engine from Rego files
/// 2. If `sandbox_id` and `navigator_endpoint` are provided, fetch via gRPC
/// 3. Otherwise, return an error
async fn load_policy(
    sandbox_id: Option<String>,
    navigator_endpoint: Option<String>,
    rego_policy: Option<String>,
    rego_data: Option<String>,
) -> Result<(SandboxPolicy, Option<Arc<OpaEngine>>)> {
    // Rego mode: load OPA engine and extract sandbox config from Rego files (dev override)
    if let (Some(policy_file), Some(data_file)) = (&rego_policy, &rego_data) {
        info!(
            rego_policy = %policy_file,
            rego_data = %data_file,
            "Loading OPA policy engine from rego files"
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
         - --rego-policy and --rego-data (or NAVIGATOR_REGO_POLICY and NAVIGATOR_REGO_DATA env vars)\n\
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
