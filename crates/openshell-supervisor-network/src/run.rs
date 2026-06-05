// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Networking stack startup for the sandbox.
//!
//! Builds the network namespace (Linux), the CONNECT proxy with TLS L7
//! interception, the inference context, and wires the proxy to the
//! caller-supplied denial-event channel. Returns a [`Networking`] handle
//! whose RAII fields keep the proxy task alive for the lifetime of the
//! sandbox supervisor.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use miette::Result;
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use openshell_core::netns::NetworkNamespace;
use openshell_core::policy::{NetworkMode, SandboxPolicy};
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_ocsf::{
    ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};

use openshell_core::denial::DenialEvent;
use tokio::sync::mpsc::UnboundedSender;

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, read_system_ca_bundle,
    write_ca_files,
};
use crate::opa::OpaEngine;
use crate::policy_local::PolicyLocalContext;
use crate::proxy::ProxyHandle;

/// Create the workload's network namespace and install bypass detection
/// rules. Returns `None` when the policy is not in proxy mode. Linux-only.
///
/// The namespace is shared infrastructure: the proxy binds to its host-side
/// veth IP and reads /dev/kmsg from inside it for bypass detection, while
/// the workload child and SSH sessions enter it via `setns()`.
///
/// # Errors
///
/// Returns an error if proxy mode is requested but the namespace cannot be
/// created (e.g., missing `CAP_NET_ADMIN` / `CAP_SYS_ADMIN` or `iproute2`).
/// Failure to install nftables bypass-detection rules is non-fatal and is
/// reported via OCSF instead.
#[cfg(target_os = "linux")]
pub fn create_netns_for_proxy(policy: &SandboxPolicy) -> Result<Option<NetworkNamespace>> {
    if !matches!(policy.network.mode, NetworkMode::Proxy) {
        return Ok(None);
    }
    match NetworkNamespace::create() {
        Ok(ns) => {
            // Install bypass detection rules (nftables log + reject).
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
            Ok(Some(ns))
        }
        Err(e) => Err(miette::miette!(
            "Network namespace creation failed and proxy mode requires isolation. \
             Ensure CAP_NET_ADMIN and CAP_SYS_ADMIN are available and iproute2 is installed. \
             Error: {e}"
        )),
    }
}

/// Handles and values produced by [`run_networking`] that the rest of
/// `run_sandbox` consumes.
///
/// The `proxy` field is an RAII handle whose drop tears down the proxy
/// task. It must remain alive for the duration of the sandbox wait loop,
/// which is achieved by holding the returned `Networking` value in
/// `run_sandbox`'s frame.
pub struct Networking {
    pub proxy: Option<ProxyHandle>,

    pub ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// Policy-local route context: shared with the orchestrator's policy poll
    /// loop so it can publish updated `SandboxPolicy` snapshots that the
    /// `policy.local` route handler returns to the workload.
    pub policy_local_ctx: Arc<PolicyLocalContext>,
}

/// Set up the networking stack: ephemeral CA + TLS state, proxy server,
/// and the SSH-side proxy URL / netns FD.
///
/// The network namespace is created by `run_sandbox` and borrowed in here —
/// it is shared infrastructure used by both the proxy (bind address) and
/// the workload child (entered via `setns()` in `pre_exec`).
///
/// `denial_tx` and `denial_rx` are owned by the caller. The proxy uses the
/// sender; the aggregator owns the receiver. The caller is also responsible
/// for cloning `denial_tx` for the bypass monitor (which lives in
/// `openshell-supervisor-process`).
///
/// # Errors
///
/// Returns an error if proxy mode is requested but the proxy configuration,
/// OPA engine, or identity cache is missing, if inference route resolution
/// fails, or if the proxy server fails to start.
#[allow(clippy::too_many_arguments)]
pub async fn run_networking(
    policy: &SandboxPolicy,
    #[cfg(target_os = "linux")] netns: Option<&NetworkNamespace>,
    opa_engine: Option<&Arc<OpaEngine>>,
    retained_proto: Option<&ProtoSandboxPolicy>,
    entrypoint_pid: Arc<AtomicU32>,
    provider_credentials: &ProviderCredentialState,
    sandbox_id: Option<&str>,
    sandbox_name: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
    denial_tx: Option<UnboundedSender<DenialEvent>>,
) -> Result<Networking> {
    // Build the policy-local route context. The orchestrator's policy poll
    // loop also holds an `Arc` clone (via `Networking::policy_local_ctx`) so
    // it can publish updated policy snapshots after a successful reload.
    let policy_local_ctx = Arc::new(PolicyLocalContext::new(
        retained_proto.cloned(),
        openshell_endpoint.map(str::to_string),
        sandbox_name
            .map(str::to_string)
            .or_else(|| sandbox_id.map(str::to_string)),
    ));

    // Spawn a task to resolve policy binary symlinks once the workload's mount
    // namespace becomes accessible via /proc/<pid>/root/. Reads entrypoint_pid
    // lazily, so spawning before run_process sets the PID is safe — the probe
    // loop just waits.
    if let (Some(engine), Some(proto)) = (opa_engine, retained_proto) {
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

    // Identity cache for SHA256 TOFU when OPA is active. Only consumed by
    // the proxy, so it's owned here.
    let identity_cache = opa_engine.map(|_| Arc::new(BinaryIdentityCache::new()));

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

    let proxy_handle = if matches!(policy.network.mode, NetworkMode::Proxy) {
        let proxy_policy = policy.network.proxy.as_ref().ok_or_else(|| {
            miette::miette!("Network mode is set to proxy but no proxy configuration was provided")
        })?;

        let engine = opa_engine.cloned().ok_or_else(|| {
            miette::miette!("Proxy mode requires an OPA engine (--rego-policy and --rego-data)")
        })?;

        let cache = identity_cache.clone().ok_or_else(|| {
            miette::miette!("Proxy mode requires an identity cache (OPA engine must be configured)")
        })?;

        // If we have a network namespace, bind to the veth host IP so sandboxed
        // processes can reach the proxy via TCP.
        #[cfg(target_os = "linux")]
        let bind_addr = netns.map(|ns| {
            let port = proxy_policy.http_addr.map_or(3128, |addr| addr.port());
            SocketAddr::new(ns.host_ip(), port)
        });

        #[cfg(not(target_os = "linux"))]
        let bind_addr: Option<SocketAddr> = None;

        // Build inference context for local routing of intercepted inference calls.
        let inference_ctx = crate::inference_routes::build_inference_context(
            sandbox_id,
            openshell_endpoint,
            inference_routes,
        )
        .await?;

        let proxy_handle = ProxyHandle::start_with_bind_addr(
            proxy_policy,
            bind_addr,
            engine,
            cache,
            entrypoint_pid.clone(),
            tls_state,
            inference_ctx,
            Some(provider_credentials.clone()),
            Some(policy_local_ctx.clone()),
            denial_tx,
        )
        .await?;
        Some(proxy_handle)
    } else {
        None
    };

    Ok(Networking {
        proxy: proxy_handle,
        ca_file_paths,
        policy_local_ctx,
    })
}
