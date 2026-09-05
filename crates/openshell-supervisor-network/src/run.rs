// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Networking stack startup for the sandbox.
//!
//! Builds the network namespace (Linux), the CONNECT proxy with TLS L7
//! interception, the inference context, and wires the proxy to the
//! caller-supplied denial-event channel. Returns a [`Networking`] handle
//! whose RAII fields keep the proxy task alive for the lifetime of the
//! sandbox supervisor.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use miette::Result;
use tracing::{debug, info, warn};

use openshell_core::policy::{NetworkMode, SandboxPolicy};
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_ocsf::{
    ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};

use openshell_core::activity::ActivitySender;
use openshell_core::denial::DenialEvent;
use openshell_core::proposals::AgentProposals;
use tokio::sync::mpsc::UnboundedSender;

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, read_system_ca_bundle,
    write_ca_files,
};
use crate::opa::OpaEngine;
use crate::policy_local::PolicyLocalContext;
use crate::proxy::ProxyHandle;

#[cfg(target_os = "linux")]
pub struct TransparentRuntimeSetup {
    pub listeners: Vec<tokio::net::TcpListener>,
    pub dns_udp: tokio::net::UdpSocket,
    pub dns_tcp: tokio::net::TcpListener,
    config: crate::policy_dns::PolicyDnsRuntimeConfig,
}

#[cfg(target_os = "linux")]
impl TransparentRuntimeSetup {
    /// Build one boot-scoped synthetic allocation epoch. The epoch advances
    /// before workload execution, so addresses cached across a supervisor
    /// restart fall outside the newly installed capture ranges.
    ///
    /// # Errors
    ///
    /// Returns an error when the epoch cannot be read or atomically persisted,
    /// or when the derived synthetic pools are invalid.
    pub fn new(
        listeners: Vec<tokio::net::TcpListener>,
        dns_udp: tokio::net::UdpSocket,
        dns_tcp: tokio::net::TcpListener,
        sandbox_id: Option<&str>,
    ) -> Result<Self> {
        let epoch = advance_allocation_epoch(
            std::path::Path::new("/run/openshell/policy-dns-epoch"),
            sandbox_id,
        )?;
        Ok(Self {
            listeners,
            dns_udp,
            dns_tcp,
            config: crate::policy_dns::PolicyDnsRuntimeConfig::for_epoch(epoch)?,
        })
    }

    #[must_use]
    pub fn synthetic_cidrs(&self) -> (String, String) {
        (
            self.config.ipv4_cidr.to_string(),
            self.config.ipv6_cidr.to_string(),
        )
    }
}

#[cfg(target_os = "linux")]
fn advance_allocation_epoch(path: &std::path::Path, sandbox_id: Option<&str>) -> Result<u64> {
    use miette::{IntoDiagnostic, WrapErr};
    use std::io::Write as _;

    let seed = sandbox_id.map_or(0, |value| {
        value
            .as_bytes()
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            })
    });
    let previous = match std::fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .into_diagnostic()
            .wrap_err("policy DNS allocation epoch is invalid")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => seed,
        Err(error) => {
            return Err(error)
                .into_diagnostic()
                .wrap_err("failed to read policy DNS allocation epoch");
        }
    };
    let epoch = previous.wrapping_add(1);
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("policy DNS allocation epoch has no parent directory"))?;
    std::fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err("failed to create policy DNS runtime directory")?;
    let temporary = parent.join(format!(
        ".policy-dns-epoch-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{epoch}")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
        .into_diagnostic()
        .wrap_err("failed to atomically persist policy DNS allocation epoch")?;
    Ok(epoch)
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
    #[cfg(target_os = "linux")]
    _policy_dns: Option<crate::policy_dns::PolicyDnsRuntime>,
    #[cfg(target_os = "linux")]
    _transparent_tcp: Option<crate::proxy::TransparentTcpHandle>,
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
    proxy_bind_ip: Option<IpAddr>,
    opa_engine: Option<&Arc<OpaEngine>>,
    retained_proto: Option<&ProtoSandboxPolicy>,
    entrypoint_pid: Arc<AtomicU32>,
    process_enabled: bool,
    provider_credentials: &ProviderCredentialState,
    sandbox_id: Option<&str>,
    sandbox_name: Option<&str>,
    openshell_endpoint: Option<&str>,
    #[allow(unused_variables)] inference_routes: Option<&str>,
    denial_tx: Option<UnboundedSender<DenialEvent>>,
    activity_tx: Option<ActivitySender>,
    agent_proposals: AgentProposals,
    workspace_rx: tokio::sync::watch::Receiver<String>,
    upstream_proxy_args: &crate::upstream_proxy::UpstreamProxyArgs,
    #[cfg(target_os = "linux")] transparent_runtime: Option<TransparentRuntimeSetup>,
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
        agent_proposals.clone(),
        workspace_rx,
    ));

    // Readiness signal for the proxy accept loop: the proxy binds the TCP
    // listener immediately (so the OS backlog queues early SYN packets) but
    // defers `accept()` until symlink resolution completes. This eliminates
    // the race where an in-flight request observes a generation transition
    // during the OPA engine reload.
    let (engine_ready_tx, engine_ready_rx) = tokio::sync::watch::channel(false);
    #[cfg(target_os = "linux")]
    let transparent_engine_ready_rx = engine_ready_rx.clone();
    #[cfg(target_os = "linux")]
    let policy_dns_engine_ready_rx = engine_ready_rx.clone();

    // Spawn a task to resolve policy binary symlinks once the workload's mount
    // namespace becomes accessible via /proc/<pid>/root/. The task starts
    // before run_process spawns the child, so first wait for the orchestrator
    // to publish a non-zero PID, then poll for proc-root readiness.
    if let (Some(engine), Some(proto)) = (opa_engine, retained_proto) {
        if process_enabled {
            let resolve_engine = engine.clone();
            let resolve_proto = proto.clone();
            let resolve_pid = entrypoint_pid.clone();
            tokio::spawn(async move {
                // Phase 1: wait for run_process to publish the entrypoint PID.
                // 20 attempts * 250ms = 5s window.
                let mut pid = 0;
                for attempt in 1..=20 {
                    pid = resolve_pid.load(Ordering::Acquire);
                    if pid != 0 {
                        break;
                    }
                    debug!(
                        attempt,
                        "Entrypoint PID not yet published, waiting before symlink resolution"
                    );
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                if pid == 0 {
                    warn!(
                        "Entrypoint PID never published; binary symlink resolution skipped. \
                     Policy binary paths will be matched literally."
                    );
                    let _ = engine_ready_tx.send(true);
                    return;
                }

                // Phase 2: wait for /proc/<pid>/root/ to become traversable. The
                // child's mount namespace is typically ready within a few hundred
                // ms of spawn. 10 attempts * 500ms = 5s window.
                let probe_path = format!("/proc/{pid}/root/");
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
                        let _ = engine_ready_tx.send(true);
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
                let _ = engine_ready_tx.send(true);
            });
        } else {
            // No process supervisor — PID will never arrive, skip symlink resolution.
            let _ = engine_ready_tx.send(true);
        }
    } else {
        // No symlink resolution needed — unblock the proxy immediately.
        let _ = engine_ready_tx.send(true);
    }

    // Identity cache for SHA256 TOFU when OPA is active. Only consumed by
    // the proxy, so it's owned here.
    let identity_cache = opa_engine.map(|_| Arc::new(BinaryIdentityCache::new()));

    // Generate ephemeral CA and TLS state for HTTPS L7 inspection.
    // The CA cert is written to disk so sandbox processes can trust it.
    let (tls_state, ca_file_paths) = if matches!(policy.network.mode, NetworkMode::Proxy) {
        match SandboxCa::generate() {
            Ok(ca) => {
                let tls_dir = std::env::var(openshell_core::sandbox_env::PROXY_TLS_DIR)
                    .unwrap_or_else(|_| openshell_core::container_paths::TLS_ROOT.to_string());
                let tls_dir = std::path::Path::new(&tls_dir);
                let mut system_ca_bundle = read_system_ca_bundle();
                // A TLS-intercepting corporate proxy (issue #1792) re-signs
                // tunneled server certificates with the corporate CA, so the
                // operator-provided bundle must be trusted for upstream
                // re-encryption (build_upstream_client_config below) and by
                // sandbox processes (the combined bundle written by
                // write_ca_files) — not only for the TLS handshake with an
                // https:// proxy listener. Fail closed on an unreadable or
                // certificate-free bundle, matching the rest of the
                // operator-owned proxy configuration.
                if let Some(path) = upstream_proxy_args.proxy_ca_bundle.as_deref() {
                    let pem = crate::upstream_proxy::read_proxy_ca_bundle(
                        path,
                        crate::upstream_proxy::ARG_PROXY_CA_BUNDLE,
                    )
                    .map_err(|err| miette::miette!("{err}"))?;
                    if !system_ca_bundle.is_empty() && !system_ca_bundle.ends_with('\n') {
                        system_ca_bundle.push('\n');
                    }
                    system_ca_bundle.push_str(&pem);
                }
                match write_ca_files(&ca, tls_dir, &system_ca_bundle) {
                    Ok(paths) => {
                        // /etc/openshell-tls is subsumed by the /etc baseline
                        // path injected by enrich_*_baseline_paths(), so no
                        // explicit Landlock entry is needed here.

                        let upstream_config = build_upstream_client_config(&system_ca_bundle)?;
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
                        // High severity: with TLS termination disabled the proxy
                        // cannot rewrite credentials, so it fails closed on
                        // TLS-bearing connections (see proxy.rs) rather than
                        // leaking placeholders through a raw tunnel.
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::High)
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
                // High severity: with TLS termination disabled the proxy cannot
                // rewrite credentials, so it fails closed on TLS-bearing
                // connections (see proxy.rs) rather than leaking placeholders
                // through a raw tunnel.
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::High)
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

        // If the orchestrator gave us a proxy bind IP (the host-side veth IP
        // from the workload's netns on Linux), use it so only traffic
        // originating inside the namespace can reach the proxy. Otherwise the
        // proxy falls back to the policy-declared http_addr (loopback in
        // tests, etc.).
        let bind_addr = proxy_bind_ip.map(|ip| {
            let port = proxy_policy.http_addr.map_or(3128, |addr| addr.port());
            SocketAddr::new(ip, port)
        });

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
            denial_tx.clone(),
            activity_tx.clone(),
            engine_ready_rx,
            upstream_proxy_args,
        )
        .await?;
        Some(proxy_handle)
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let (policy_dns, transparent_tcp) = if let Some(runtime) = transparent_runtime {
        let engine = opa_engine
            .cloned()
            .ok_or_else(|| miette::miette!("transparent TCP requires an OPA policy engine"))?;
        let cache = identity_cache
            .clone()
            .ok_or_else(|| miette::miette!("transparent TCP requires a process identity cache"))?;
        let trusted_gateway = crate::proxy::detect_trusted_host_gateway();
        let dns = crate::policy_dns::PolicyDnsRuntime::start(
            engine.clone(),
            runtime.dns_udp,
            runtime.dns_tcp,
            trusted_gateway,
            runtime.config,
            policy_dns_engine_ready_rx,
        )?;
        let transparent = crate::proxy::TransparentTcpHandle::start(
            runtime.listeners,
            dns.store.clone(),
            engine,
            cache,
            entrypoint_pid,
            agent_proposals,
            denial_tx,
            activity_tx,
            upstream_proxy_args,
            transparent_engine_ready_rx,
        )?;
        (Some(dns), Some(transparent))
    } else {
        (None, None)
    };

    Ok(Networking {
        proxy: proxy_handle,
        ca_file_paths,
        policy_local_ctx,
        #[cfg(target_os = "linux")]
        _policy_dns: policy_dns,
        #[cfg(target_os = "linux")]
        _transparent_tcp: transparent_tcp,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod transparent_runtime_tests {
    use super::*;

    #[test]
    fn allocation_epoch_advances_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("epoch");
        let first = advance_allocation_epoch(&path, Some("sandbox-a")).unwrap();
        let second = advance_allocation_epoch(&path, Some("sandbox-a")).unwrap();
        assert_eq!(second, first + 1);
    }

    #[test]
    fn invalid_allocation_epoch_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("epoch");
        std::fs::write(&path, "corrupt\n").unwrap();
        let error = advance_allocation_epoch(&path, Some("sandbox-a")).unwrap_err();
        assert!(error.to_string().contains("allocation epoch is invalid"));
    }
}
