// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Networking stack startup for the sandbox.
//!
//! Builds the network namespace (Linux), the CONNECT proxy with TLS L7
//! interception, the bypass monitor, the inference context, and the
//! denial-event channel. Returns a [`Networking`] handle whose RAII fields
//! keep the proxy and bypass-monitor tasks alive for the lifetime of the
//! sandbox supervisor.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use miette::Result;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use openshell_core::netns::NetworkNamespace;
use openshell_core::policy::{NetworkMode, SandboxPolicy};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_ocsf::{
    ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};

use crate::denial_aggregator::{DenialAggregator, FlushableDenialSummary};
use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, read_system_ca_bundle,
    write_ca_files,
};
use crate::mechanistic_mapper;
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
/// The `proxy` / `bypass_monitor` fields are RAII handles whose drop
/// tears down the proxy and bypass-monitor tasks. They must remain alive for
/// the duration of the sandbox wait loop, which is achieved by holding the
/// returned `Networking` value in `run_sandbox`'s frame.
pub struct Networking {
    pub proxy: Option<ProxyHandle>,
    #[cfg(target_os = "linux")]
    pub bypass_monitor: Option<tokio::task::JoinHandle<()>>,

    pub ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    pub ssh_proxy_url: Option<String>,
    pub ssh_netns_fd: Option<i32>,
}

/// Set up the networking stack: ephemeral CA + TLS state, proxy server,
/// bypass monitor, and the SSH-side proxy URL / netns FD.
///
/// The network namespace is created by `run_sandbox` and borrowed in here —
/// it is shared infrastructure used by both the proxy (bind address, bypass
/// monitor) and the workload child (entered via `setns()` in `pre_exec`).
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
    entrypoint_pid: Arc<AtomicU32>,
    provider_credentials: &ProviderCredentialState,
    policy_local_ctx: &Arc<PolicyLocalContext>,
    sandbox_id: Option<&str>,
    sandbox_name: Option<&str>,
    openshell_endpoint: Option<&str>,
    inference_routes: Option<&str>,
) -> Result<Networking> {
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

    let (proxy_handle, denial_rx, bypass_denial_tx) =
        if matches!(policy.network.mode, NetworkMode::Proxy) {
            let proxy_policy = policy.network.proxy.as_ref().ok_or_else(|| {
                miette::miette!(
                    "Network mode is set to proxy but no proxy configuration was provided"
                )
            })?;

            let engine = opa_engine.cloned().ok_or_else(|| {
                miette::miette!("Proxy mode requires an OPA engine (--rego-policy and --rego-data)")
            })?;

            let cache = identity_cache.clone().ok_or_else(|| {
                miette::miette!(
                    "Proxy mode requires an identity cache (OPA engine must be configured)"
                )
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
                Some(provider_credentials.clone()),
                Some(policy_local_ctx.clone()),
                denial_tx,
            )
            .await?;
            (Some(proxy_handle), denial_rx, bypass_denial_tx)
        } else {
            (None, None, None)
        };

    // Spawn the denial-aggregator flush task. The aggregator drains denial
    // events from the proxy + bypass monitor, batches them, and ships
    // summaries to the gateway via SubmitPolicyAnalysis.
    if let (Some(rx), Some(endpoint)) = (denial_rx, openshell_endpoint) {
        // SubmitPolicyAnalysis resolves by sandbox *name*, not UUID — fall back
        // to the ID when the name isn't set.
        let agg_name = sandbox_name
            .map(str::to_string)
            .or_else(|| sandbox_id.map(str::to_string))
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs: u64 = std::env::var("OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let aggregator = DenialAggregator::new(rx, flush_interval_secs);

        tokio::spawn(async move {
            aggregator
                .run(|summaries| {
                    let endpoint = agg_endpoint.clone();
                    let sandbox_name = agg_name.clone();
                    async move {
                        if let Err(e) =
                            flush_proposals_to_gateway(&endpoint, &sandbox_name, summaries).await
                        {
                            warn!(error = %e, "Failed to flush denial summaries to gateway");
                        }
                    }
                })
                .await;
        });
    }

    // Spawn bypass detection monitor (Linux only, proxy mode only).
    // Reads /dev/kmsg for nftables log entries and emits structured
    // tracing events for direct connection attempts that bypass the proxy.
    #[cfg(target_os = "linux")]
    let bypass_monitor_handle = netns.and_then(|ns| {
        crate::bypass_monitor::spawn(
            ns.name().to_string(),
            entrypoint_pid.clone(),
            bypass_denial_tx,
        )
    });

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
    let ssh_netns_fd = netns.and_then(NetworkNamespace::ns_fd);

    #[cfg(not(target_os = "linux"))]
    let ssh_netns_fd: Option<i32> = None;

    let ssh_proxy_url = if matches!(policy.network.mode, NetworkMode::Proxy) {
        #[cfg(target_os = "linux")]
        {
            netns.map(|ns| {
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

    Ok(Networking {
        proxy: proxy_handle,
        #[cfg(target_os = "linux")]
        bypass_monitor: bypass_monitor_handle,
        ca_file_paths,
        ssh_proxy_url,
        ssh_netns_fd,
    })
}

/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    summaries: Vec<FlushableDenialSummary>,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;

    let proto_summaries: Vec<DenialSummary> = summaries
        .into_iter()
        .map(|s| DenialSummary {
            sandbox_id: String::new(),
            host: s.host,
            port: u32::from(s.port),
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
    let proposals = mechanistic_mapper::generate_proposals(&proto_summaries);

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
