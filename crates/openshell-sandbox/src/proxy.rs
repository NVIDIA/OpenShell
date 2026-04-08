// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP CONNECT proxy with OPA policy evaluation and process-identity binding.

use crate::denial_aggregator::DenialEvent;
use crate::identity::BinaryIdentityCache;
use crate::l7::tls::ProxyTlsState;
use crate::opa::{NetworkAction, OpaEngine};
use crate::policy::ProxyPolicy;
use crate::secrets::{SecretResolver, rewrite_header_line};
use miette::{IntoDiagnostic, Result};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, Process, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const MAX_HEADER_BYTES: usize = 8192;
const INFERENCE_LOCAL_HOST: &str = "inference.local";

/// Maximum total bytes for a streaming inference response body (32 MiB).
const MAX_STREAMING_BODY: usize = 32 * 1024 * 1024;

/// Idle timeout per chunk when relaying streaming inference responses.
const CHUNK_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Result of a proxy CONNECT policy decision.
struct ConnectDecision {
    action: NetworkAction,
    /// Resolved binary path.
    binary: Option<PathBuf>,
    /// PID owning the socket.
    binary_pid: Option<u32>,
    /// Ancestor binary paths from process tree walk.
    ancestors: Vec<PathBuf>,
    /// Cmdline-derived absolute paths (for script detection).
    cmdline_paths: Vec<PathBuf>,
}

/// Outcome of an inference interception attempt.
///
/// Returned by [`handle_inference_interception`] so the call site can emit
/// a structured CONNECT deny log when the connection is not successfully routed.
enum InferenceOutcome {
    /// At least one request was successfully routed to a local inference backend.
    Routed,
    /// The connection was denied (TLS failure, non-inference request, etc.).
    Denied { reason: String },
}

/// Inference routing context for sandbox-local execution.
///
/// Holds a `Router` (HTTP client) and cached sets of resolved routes.
/// User routes serve `inference.local` traffic; system routes are consumed
/// in-process by the supervisor for platform functions (e.g. agent harness).
pub struct InferenceContext {
    pub patterns: Vec<crate::l7::inference::InferenceApiPattern>,
    router: openshell_router::Router,
    /// Routes for the user-facing `inference.local` endpoint.
    routes: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
    /// Routes for supervisor-only system inference (`sandbox-system`).
    system_routes: Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>>,
}

impl InferenceContext {
    pub fn new(
        patterns: Vec<crate::l7::inference::InferenceApiPattern>,
        router: openshell_router::Router,
        routes: Vec<openshell_router::config::ResolvedRoute>,
        system_routes: Vec<openshell_router::config::ResolvedRoute>,
    ) -> Self {
        Self {
            patterns,
            router,
            routes: Arc::new(tokio::sync::RwLock::new(routes)),
            system_routes: Arc::new(tokio::sync::RwLock::new(system_routes)),
        }
    }

    /// Get a handle to the user route cache for background refresh.
    pub fn route_cache(
        &self,
    ) -> Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>> {
        self.routes.clone()
    }

    /// Get a handle to the system route cache for background refresh.
    pub fn system_route_cache(
        &self,
    ) -> Arc<tokio::sync::RwLock<Vec<openshell_router::config::ResolvedRoute>>> {
        self.system_routes.clone()
    }

    /// Make an inference call using system routes (supervisor-only).
    ///
    /// This is the in-process API for platform functions. It bypasses the
    /// CONNECT proxy entirely — the supervisor calls the router directly
    /// from the host network namespace.
    pub async fn system_inference(
        &self,
        protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
    ) -> Result<openshell_router::ProxyResponse, openshell_router::RouterError> {
        let routes = self.system_routes.read().await;
        self.router
            .proxy_with_candidates(protocol, method, path, headers, body, &routes)
            .await
    }
}

#[derive(Debug)]
pub struct ProxyHandle {
    #[allow(dead_code)]
    http_addr: Option<SocketAddr>,
    join: JoinHandle<()>,
}

impl ProxyHandle {
    /// Start the proxy with OPA engine for policy evaluation.
    ///
    /// The proxy uses OPA for network decisions with process-identity binding
    /// via `/proc/net/tcp`. All connections are evaluated through OPA policy.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
        tls_state: Option<Arc<ProxyTlsState>>,
        inference_ctx: Option<Arc<InferenceContext>>,
        secret_resolver: Option<Arc<SecretResolver>>,
        denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
    ) -> Result<Self> {
        // Use override bind_addr, fall back to policy http_addr, then default
        // to loopback:3128.  The default allows the proxy to function when no
        // network namespace is available (e.g. missing CAP_NET_ADMIN) and the
        // policy doesn't specify an explicit address.
        let default_addr: SocketAddr = ([127, 0, 0, 1], 3128).into();
        let http_addr = bind_addr.or(policy.http_addr).unwrap_or(default_addr);

        // Only enforce loopback restriction when not using network namespace override
        if bind_addr.is_none() && !http_addr.ip().is_loopback() {
            return Err(miette::miette!(
                "Proxy http_addr must be loopback-only: {http_addr}"
            ));
        }

        let listener = TcpListener::bind(http_addr).await.into_diagnostic()?;
        let local_addr = listener.local_addr().into_diagnostic()?;
        {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Listen)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .dst_endpoint(Endpoint::from_ip(local_addr.ip(), local_addr.port()))
                .message(format!("Proxy listening on {local_addr}"))
                .build();
            ocsf_emit!(event);
        }

        let join = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let opa = opa_engine.clone();
                        let cache = identity_cache.clone();
                        let spid = entrypoint_pid.clone();
                        let tls = tls_state.clone();
                        let inf = inference_ctx.clone();
                        let resolver = secret_resolver.clone();
                        let dtx = denial_tx.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_tcp_connection(
                                stream, opa, cache, spid, tls, inf, resolver, dtx,
                            )
                            .await
                            {
                                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                                    .activity(ActivityId::Fail)
                                    .severity(SeverityId::Low)
                                    .status(StatusId::Failure)
                                    .message(format!("Proxy connection error: {err}"))
                                    .build();
                                ocsf_emit!(event);
                            }
                        });
                    }
                    Err(err) => {
                        let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::Low)
                            .status(StatusId::Failure)
                            .message(format!("Proxy accept error: {err}"))
                            .build();
                        ocsf_emit!(event);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            http_addr: Some(local_addr),
            join,
        })
    }

    #[allow(dead_code)]
    pub const fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Emit a denial event to the aggregator channel (if configured).
/// Used by `handle_tcp_connection` which owns `Option<Sender>`.
fn emit_denial(
    tx: &Option<mpsc::UnboundedSender<DenialEvent>>,
    host: &str,
    port: u16,
    binary: &str,
    decision: &ConnectDecision,
    reason: &str,
    stage: &str,
) {
    if let Some(tx) = tx {
        let _ = tx.send(DenialEvent {
            host: host.to_string(),
            port,
            binary: binary.to_string(),
            ancestors: decision
                .ancestors
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            deny_reason: reason.to_string(),
            denial_stage: stage.to_string(),
            l7_method: None,
            l7_path: None,
        });
    }
}

/// Emit a denial event from a borrowed sender reference.
/// Used by `handle_forward_proxy` which borrows `Option<&Sender>`.
fn emit_denial_simple(
    tx: Option<&mpsc::UnboundedSender<DenialEvent>>,
    host: &str,
    port: u16,
    binary: &str,
    decision: &ConnectDecision,
    reason: &str,
    stage: &str,
) {
    if let Some(tx) = tx {
        let _ = tx.send(DenialEvent {
            host: host.to_string(),
            port,
            binary: binary.to_string(),
            ancestors: decision
                .ancestors
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            deny_reason: reason.to_string(),
            denial_stage: stage.to_string(),
            l7_method: None,
            l7_path: None,
        });
    }
}

async fn handle_tcp_connection(
    mut client: TcpStream,
    opa_engine: Arc<OpaEngine>,
    identity_cache: Arc<BinaryIdentityCache>,
    entrypoint_pid: Arc<AtomicU32>,
    tls_state: Option<Arc<ProxyTlsState>>,
    inference_ctx: Option<Arc<InferenceContext>>,
    secret_resolver: Option<Arc<SecretResolver>>,
    denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_HEADER_BYTES];
    let mut used = 0usize;

    loop {
        if used == buf.len() {
            respond(
                &mut client,
                b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n",
            )
            .await?;
            return Ok(());
        }

        let n = client.read(&mut buf[used..]).await.into_diagnostic()?;
        if n == 0 {
            return Ok(());
        }
        used += n;

        if buf[..used].windows(4).any(|win| win == b"\r\n\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf[..used]);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "CONNECT" {
        return handle_forward_proxy(
            method,
            target,
            &buf[..],
            used,
            &mut client,
            opa_engine,
            identity_cache,
            entrypoint_pid,
            secret_resolver,
            denial_tx.as_ref(),
        )
        .await;
    }

    let (host, port) = parse_target(target)?;
    let host_lc = host.to_ascii_lowercase();

    if host_lc == INFERENCE_LOCAL_HOST {
        respond(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let outcome = handle_inference_interception(
            client,
            INFERENCE_LOCAL_HOST,
            port,
            tls_state.as_ref(),
            inference_ctx.as_ref(),
        )
        .await?;
        if let InferenceOutcome::Denied { reason } = outcome {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, port))
                .message(format!("Inference interception denied: {reason}"))
                .status_detail(&reason)
                .build();
            ocsf_emit!(event);
        }
        return Ok(());
    }

    let peer_addr = client.peer_addr().into_diagnostic()?;
    let _local_addr = client.local_addr().into_diagnostic()?;

    // Evaluate OPA policy with process-identity binding.
    // Wrapped in spawn_blocking because identity resolution does heavy sync I/O:
    // /proc scanning + SHA256 hashing of binaries (e.g. node at 124MB).
    let opa_clone = opa_engine.clone();
    let cache_clone = identity_cache.clone();
    let pid_clone = entrypoint_pid.clone();
    let host_clone = host_lc.clone();
    let decision = tokio::task::spawn_blocking(move || {
        evaluate_opa_tcp(
            peer_addr,
            &opa_clone,
            &cache_clone,
            &pid_clone,
            &host_clone,
            port,
        )
    })
    .await
    .map_err(|e| miette::miette!("identity resolution task panicked: {e}"))?;

    // Extract action string and matched policy for logging
    let (matched_policy, deny_reason) = match &decision.action {
        NetworkAction::Allow { matched_policy } => (matched_policy.clone(), String::new()),
        NetworkAction::Deny { reason } => (None, reason.clone()),
    };

    // Build log context fields (shared by deny log below and deferred allow log after L7 check)
    let binary_str = decision
        .binary
        .as_ref()
        .map_or_else(|| "-".to_string(), |p| p.display().to_string());
    let pid_str = decision
        .binary_pid
        .map_or_else(|| "-".to_string(), |p| p.to_string());
    let ancestors_str = if decision.ancestors.is_empty() {
        "-".to_string()
    } else {
        decision
            .ancestors
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    };
    let cmdline_str = if decision.cmdline_paths.is_empty() {
        "-".to_string()
    } else {
        decision
            .cmdline_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let policy_str = matched_policy.as_deref().unwrap_or("-");

    // Log denied connections immediately — they never reach L7.
    // Allowed connections are logged after the L7 config check (below)
    // so we can distinguish CONNECT (L4-only) from CONNECT_L7 (L7 follows).
    if matches!(decision.action, NetworkAction::Deny { .. }) {
        let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
            .src_endpoint_addr(peer_addr.ip(), peer_addr.port())
            .actor_process(
                Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                    .with_cmd_line(&cmdline_str),
            )
            .firewall_rule("-", "opa")
            .message(format!("CONNECT denied {host_lc}:{port}"))
            .status_detail(&deny_reason)
            .build();
        ocsf_emit!(event);
        emit_denial(
            &denial_tx,
            &host_lc,
            port,
            &binary_str,
            &decision,
            &deny_reason,
            "connect",
        );
        respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    // Query allowed_ips from the matched endpoint config (if any).
    // When present, the SSRF check validates resolved IPs against this
    // allowlist instead of blanket-blocking all private IPs.
    // When the policy host is already a literal IP address, treat it as
    // implicitly allowed — the user explicitly declared the destination.
    let mut raw_allowed_ips = query_allowed_ips(&opa_engine, &decision, &host_lc, port);
    if raw_allowed_ips.is_empty() {
        raw_allowed_ips = implicit_allowed_ips_for_ip_host(&host);
    }

    // Defense-in-depth: resolve DNS and reject connections to internal IPs.
    let dns_connect_start = std::time::Instant::now();
    let mut upstream = if !raw_allowed_ips.is_empty() {
        // allowed_ips mode: validate resolved IPs against CIDR allowlist.
        // Loopback and link-local are still always blocked.
        match parse_allowed_ips(&raw_allowed_ips) {
            Ok(nets) => match resolve_and_check_allowed_ips(&host, port, &nets).await {
                Ok(addrs) => TcpStream::connect(addrs.as_slice())
                    .await
                    .into_diagnostic()?,
                Err(reason) => {
                    {
                        let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                            .activity(ActivityId::Open)
                            .action(ActionId::Denied)
                            .disposition(DispositionId::Blocked)
                            .severity(SeverityId::Medium)
                            .status(StatusId::Failure)
                            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                            .src_endpoint_addr(peer_addr.ip(), peer_addr.port())
                            .actor_process(
                                Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                    .with_cmd_line(&cmdline_str),
                            )
                            .firewall_rule("-", "ssrf")
                            .message(format!(
                                "CONNECT blocked: allowed_ips check failed for {host_lc}:{port}"
                            ))
                            .status_detail(&reason)
                            .build();
                        ocsf_emit!(event);
                    }
                    emit_denial(
                        &denial_tx,
                        &host_lc,
                        port,
                        &binary_str,
                        &decision,
                        &reason,
                        "ssrf",
                    );
                    respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                    return Ok(());
                }
            },
            Err(reason) => {
                {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Open)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .src_endpoint_addr(peer_addr.ip(), peer_addr.port())
                        .actor_process(
                            Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                .with_cmd_line(&cmdline_str),
                        )
                        .firewall_rule("-", "ssrf")
                        .message(format!(
                            "CONNECT blocked: invalid allowed_ips in policy for {host_lc}:{port}"
                        ))
                        .status_detail(&reason)
                        .build();
                    ocsf_emit!(event);
                }
                emit_denial(
                    &denial_tx,
                    &host_lc,
                    port,
                    &binary_str,
                    &decision,
                    &reason,
                    "ssrf",
                );
                respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    } else {
        // Default: reject all internal IPs (loopback, RFC 1918, link-local).
        match resolve_and_reject_internal(&host, port).await {
            Ok(addrs) => TcpStream::connect(addrs.as_slice())
                .await
                .into_diagnostic()?,
            Err(reason) => {
                {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Open)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .src_endpoint_addr(peer_addr.ip(), peer_addr.port())
                        .actor_process(
                            Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                .with_cmd_line(&cmdline_str),
                        )
                        .firewall_rule("-", "ssrf")
                        .message(format!(
                            "CONNECT blocked: internal address {host_lc}:{port}"
                        ))
                        .status_detail(&reason)
                        .build();
                    ocsf_emit!(event);
                }
                emit_denial(
                    &denial_tx,
                    &host_lc,
                    port,
                    &binary_str,
                    &decision,
                    &reason,
                    "ssrf",
                );
                respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    };

    debug!(
        "handle_tcp_connection dns_resolve_and_tcp_connect: {}ms host={host_lc}",
        dns_connect_start.elapsed().as_millis()
    );

    respond(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Check if endpoint has L7 config for protocol-aware inspection
    let l7_config = query_l7_config(&opa_engine, &decision, &host_lc, port);

    // Log the allowed CONNECT — use CONNECT_L7 when L7 inspection follows,
    // so log consumers can distinguish L4-only decisions from tunnel lifecycle events.
    let connect_msg = if l7_config.is_some() {
        "CONNECT_L7"
    } else {
        "CONNECT"
    };
    {
        let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
            .src_endpoint_addr(peer_addr.ip(), peer_addr.port())
            .actor_process(
                Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                    .with_cmd_line(&cmdline_str),
            )
            .firewall_rule(policy_str, "opa")
            .message(format!("{connect_msg} allowed {host_lc}:{port}"))
            .build();
        ocsf_emit!(event);
    }

    // Determine effective TLS mode. Check the raw endpoint config for
    // `tls: skip` independently of L7 config (which requires `protocol`).
    let effective_tls_skip =
        query_tls_mode(&opa_engine, &decision, &host_lc, port) == crate::l7::TlsMode::Skip;

    // Build L7 eval context (shared by TLS-terminated and plaintext paths).
    let ctx = crate::l7::relay::L7EvalContext {
        host: host_lc.clone(),
        port,
        policy_name: matched_policy.clone().unwrap_or_default(),
        binary_path: decision
            .binary
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ancestors: decision
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        cmdline_paths: decision
            .cmdline_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        secret_resolver: secret_resolver.clone(),
    };

    if effective_tls_skip {
        // tls: skip — raw tunnel, no termination, no credential injection.
        debug!(
            host = %host_lc,
            port = port,
            "tls: skip — bypassing TLS auto-detection, raw tunnel"
        );
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .into_diagnostic()?;
        return Ok(());
    }

    // Auto-detect TLS by peeking the first bytes.
    let mut peek_buf = [0u8; 8];
    let n = client.peek(&mut peek_buf).await.into_diagnostic()?;
    if n == 0 {
        return Ok(());
    }

    let is_tls = crate::l7::tls::looks_like_tls(&peek_buf[..n]);
    let is_http = crate::l7::rest::looks_like_http(&peek_buf[..n]);

    if is_tls {
        // TLS detected — terminate unconditionally.
        if let Some(ref tls) = tls_state {
            let tls_result = async {
                let mut tls_client =
                    crate::l7::tls::tls_terminate_client(client, tls, &host_lc).await?;
                let mut tls_upstream =
                    crate::l7::tls::tls_connect_upstream(upstream, &host_lc, tls.upstream_config())
                        .await?;

                if let Some(ref l7_config) = l7_config {
                    // L7 inspection on terminated TLS traffic.
                    let tunnel_engine = opa_engine.clone_engine_for_tunnel().unwrap_or_else(|e| {
                        let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::Low)
                            .status(StatusId::Failure)
                            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                            .message(format!(
                                "Failed to clone OPA engine for L7, falling back to relay-only: {e}"
                            ))
                            .build();
                        ocsf_emit!(event);
                        regorus::Engine::new()
                    });
                    crate::l7::relay::relay_with_inspection(
                        l7_config,
                        std::sync::Mutex::new(tunnel_engine),
                        &mut tls_client,
                        &mut tls_upstream,
                        &ctx,
                    )
                    .await
                } else {
                    // No L7 config — relay with credential injection only.
                    crate::l7::relay::relay_passthrough_with_credentials(
                        &mut tls_client,
                        &mut tls_upstream,
                        &ctx,
                    )
                    .await
                }
            };
            if let Err(e) = tls_result.await {
                if is_benign_relay_error(&e) {
                    debug!(
                        host = %host_lc,
                        port = port,
                        error = %e,
                        "TLS connection closed"
                    );
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .message(format!("TLS relay error: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
            }
        } else {
            {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .severity(SeverityId::Low)
                    .status(StatusId::Failure)
                    .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                    .message(format!(
                        "TLS detected but TLS state not configured for {host_lc}:{port}, falling back to raw tunnel"
                    ))
                    .build();
                ocsf_emit!(event);
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .into_diagnostic()?;
        }
    } else if is_http {
        // Plaintext HTTP detected.
        if let Some(ref l7_config) = l7_config {
            let tunnel_engine = opa_engine.clone_engine_for_tunnel().unwrap_or_else(|e| {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .severity(SeverityId::Low)
                    .status(StatusId::Failure)
                    .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                    .message(format!(
                        "Failed to clone OPA engine for L7, falling back to relay-only: {e}"
                    ))
                    .build();
                ocsf_emit!(event);
                regorus::Engine::new()
            });
            if let Err(e) = crate::l7::relay::relay_with_inspection(
                l7_config,
                std::sync::Mutex::new(tunnel_engine),
                &mut client,
                &mut upstream,
                &ctx,
            )
            .await
            {
                if is_benign_relay_error(&e) {
                    debug!(host = %host_lc, port = port, error = %e, "L7 connection closed");
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .message(format!("L7 relay error: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
            }
        } else {
            // Plaintext HTTP, no L7 config — relay with credential injection.
            if let Err(e) = crate::l7::relay::relay_passthrough_with_credentials(
                &mut client,
                &mut upstream,
                &ctx,
            )
            .await
            {
                if is_benign_relay_error(&e) {
                    debug!(host = %host_lc, port = port, error = %e, "HTTP relay closed");
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .message(format!("HTTP relay error: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
            }
        }
    } else {
        // Neither TLS nor HTTP — raw binary relay.
        debug!(
            host = %host_lc,
            port = port,
            "Non-TLS non-HTTP traffic detected, raw tunnel"
        );
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .into_diagnostic()?;
    }

    Ok(())
}

/// Evaluate OPA policy for a TCP connection with identity binding via /proc/net/tcp.
#[cfg(target_os = "linux")]
fn evaluate_opa_tcp(
    peer_addr: SocketAddr,
    engine: &OpaEngine,
    identity_cache: &BinaryIdentityCache,
    entrypoint_pid: &AtomicU32,
    host: &str,
    port: u16,
) -> ConnectDecision {
    use crate::opa::NetworkInput;
    use std::sync::atomic::Ordering;

    let deny = |reason: String,
                binary: Option<PathBuf>,
                binary_pid: Option<u32>,
                ancestors: Vec<PathBuf>,
                cmdline_paths: Vec<PathBuf>|
     -> ConnectDecision {
        ConnectDecision {
            action: NetworkAction::Deny { reason },
            binary,
            binary_pid,
            ancestors,
            cmdline_paths,
        }
    };

    let pid = entrypoint_pid.load(Ordering::Acquire);
    if pid == 0 {
        return deny(
            "entrypoint process not yet spawned".into(),
            None,
            None,
            vec![],
            vec![],
        );
    }

    let total_start = std::time::Instant::now();
    let peer_port = peer_addr.port();

    let (bin_path, binary_pid) = match crate::procfs::resolve_tcp_peer_identity(pid, peer_port) {
        Ok(r) => r,
        Err(e) => {
            return deny(
                format!("failed to resolve peer binary: {e}"),
                None,
                None,
                vec![],
                vec![],
            );
        }
    };

    // TOFU verify the immediate binary
    let bin_hash = match identity_cache.verify_or_cache(&bin_path) {
        Ok(h) => h,
        Err(e) => {
            return deny(
                format!("binary integrity check failed: {e}"),
                Some(bin_path),
                Some(binary_pid),
                vec![],
                vec![],
            );
        }
    };

    // Walk the process tree upward to collect ancestor binaries
    let ancestors = crate::procfs::collect_ancestor_binaries(binary_pid, pid);

    for ancestor in &ancestors {
        if let Err(e) = identity_cache.verify_or_cache(ancestor) {
            return deny(
                format!(
                    "ancestor integrity check failed for {}: {e}",
                    ancestor.display()
                ),
                Some(bin_path),
                Some(binary_pid),
                ancestors.clone(),
                vec![],
            );
        }
    }

    // Collect cmdline paths for script-based binary detection.
    let mut exclude = ancestors.clone();
    exclude.push(bin_path.clone());
    let cmdline_paths = crate::procfs::collect_cmdline_paths(binary_pid, pid, &exclude);

    let input = NetworkInput {
        host: host.to_string(),
        port,
        binary_path: bin_path.clone(),
        binary_sha256: bin_hash,
        ancestors: ancestors.clone(),
        cmdline_paths: cmdline_paths.clone(),
    };

    let result = match engine.evaluate_network_action(&input) {
        Ok(action) => ConnectDecision {
            action,
            binary: Some(bin_path),
            binary_pid: Some(binary_pid),
            ancestors,
            cmdline_paths,
        },
        Err(e) => deny(
            format!("policy evaluation error: {e}"),
            Some(bin_path),
            Some(binary_pid),
            ancestors,
            cmdline_paths,
        ),
    };
    debug!(
        "evaluate_opa_tcp TOTAL: {}ms host={host} port={port}",
        total_start.elapsed().as_millis()
    );
    result
}

/// Non-Linux stub: OPA identity binding requires /proc.
#[cfg(not(target_os = "linux"))]
fn evaluate_opa_tcp(
    _peer_addr: SocketAddr,
    _engine: &OpaEngine,
    _identity_cache: &BinaryIdentityCache,
    _entrypoint_pid: &AtomicU32,
    _host: &str,
    _port: u16,
) -> ConnectDecision {
    ConnectDecision {
        action: NetworkAction::Deny {
            reason: "identity binding unavailable on this platform".into(),
        },
        binary: None,
        binary_pid: None,
        ancestors: vec![],
        cmdline_paths: vec![],
    }
}

/// Maximum buffer size for inference request parsing (10 MiB).
const MAX_INFERENCE_BUF: usize = 10 * 1024 * 1024;

/// Initial buffer size for inference request parsing (64 KiB).
const INITIAL_INFERENCE_BUF: usize = 65536;

/// Handle an intercepted connection for inference routing.
///
/// TLS-terminates the client connection, parses HTTP requests, and executes
/// inference API calls locally via `openshell-router`.
/// Non-inference requests are denied with 403.
///
/// Returns [`InferenceOutcome::Routed`] if at least one request was successfully
/// routed, or [`InferenceOutcome::Denied`] with a reason for all denial cases.
async fn handle_inference_interception(
    client: TcpStream,
    host: &str,
    port: u16,
    tls_state: Option<&Arc<ProxyTlsState>>,
    inference_ctx: Option<&Arc<InferenceContext>>,
) -> Result<InferenceOutcome> {
    use crate::l7::inference::{ParseResult, format_http_response, try_parse_http_request};

    let Some(ctx) = inference_ctx else {
        return Ok(InferenceOutcome::Denied {
            reason: "cluster inference context not configured".to_string(),
        });
    };

    let Some(tls) = tls_state else {
        return Ok(InferenceOutcome::Denied {
            reason: "missing TLS state".to_string(),
        });
    };

    // TLS-terminate the client side (present a cert for the target host)
    let mut tls_client = match crate::l7::tls::tls_terminate_client(client, tls, host).await {
        Ok(c) => c,
        Err(e) => {
            return Ok(InferenceOutcome::Denied {
                reason: format!("TLS handshake failed: {e}"),
            });
        }
    };

    // Read and process HTTP requests from the tunnel.
    // Track whether any request was successfully routed so that a late denial
    // on a keep-alive connection still counts as "routed".
    let mut buf = vec![0u8; INITIAL_INFERENCE_BUF];
    let mut used = 0usize;
    let mut routed_any = false;

    loop {
        let n = match tls_client.read(&mut buf[used..]).await {
            Ok(n) => n,
            Err(e) => {
                if routed_any {
                    break;
                }
                return Ok(InferenceOutcome::Denied {
                    reason: format!("I/O error: {e}"),
                });
            }
        };
        if n == 0 {
            if routed_any {
                break;
            }
            return Ok(InferenceOutcome::Denied {
                reason: "client closed connection".to_string(),
            });
        }
        used += n;

        // Try to parse a complete HTTP request
        match try_parse_http_request(&buf[..used]) {
            ParseResult::Complete(request, consumed) => {
                let was_routed = route_inference_request(&request, ctx, &mut tls_client).await?;
                if was_routed {
                    routed_any = true;
                } else if !routed_any {
                    return Ok(InferenceOutcome::Denied {
                        reason: "connection not allowed by policy".to_string(),
                    });
                }

                // Shift buffer for next request
                buf.copy_within(consumed..used, 0);
                used -= consumed;
            }
            ParseResult::Incomplete => {
                // Need more data — grow buffer if full
                if used == buf.len() {
                    if buf.len() >= MAX_INFERENCE_BUF {
                        let response = format_http_response(413, &[], b"Payload Too Large");
                        write_all(&mut tls_client, &response).await?;
                        if routed_any {
                            break;
                        }
                        return Ok(InferenceOutcome::Denied {
                            reason: "payload too large".to_string(),
                        });
                    }
                    buf.resize((buf.len() * 2).min(MAX_INFERENCE_BUF), 0);
                }
            }
            ParseResult::Invalid(reason) => {
                {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Refuse)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Rejected)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, port))
                        .message(format!("Rejecting malformed inference request: {reason}"))
                        .status_detail(&reason)
                        .build();
                    ocsf_emit!(event);
                }
                let response = format_http_response(400, &[], b"Bad Request");
                write_all(&mut tls_client, &response).await?;
                return Ok(InferenceOutcome::Denied { reason });
            }
        }
    }

    Ok(InferenceOutcome::Routed)
}

/// Route a parsed inference request locally via the sandbox router, or deny it.
///
/// Returns `Ok(true)` if the request was routed to an inference backend,
/// `Ok(false)` if it was denied as a non-inference request.
async fn route_inference_request(
    request: &crate::l7::inference::ParsedHttpRequest,
    ctx: &InferenceContext,
    tls_client: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<bool> {
    use crate::l7::inference::{detect_inference_pattern, format_http_response};

    let normalized_path = normalize_inference_path(&request.path);

    if let Some(pattern) =
        detect_inference_pattern(&request.method, &normalized_path, &ctx.patterns)
    {
        {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Detected)
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, 443))
                .message(format!(
                    "Intercepted inference request, routing locally: {} {} (protocol={}, kind={})",
                    request.method, normalized_path, pattern.protocol, pattern.kind
                ))
                .build();
            ocsf_emit!(event);
        }

        // Strip credential + framing/hop-by-hop headers.
        let filtered_headers = sanitize_inference_request_headers(&request.headers);

        let routes = ctx.routes.read().await;

        if routes.is_empty() {
            let body = serde_json::json!({
                "error": "cluster inference is not configured",
                "hint": "run: openshell cluster inference set --help"
            });
            let body_bytes = body.to_string();
            let response = format_http_response(
                503,
                &[("content-type".to_string(), "application/json".to_string())],
                body_bytes.as_bytes(),
            );
            write_all(tls_client, &response).await?;
            return Ok(true);
        }

        match ctx
            .router
            .proxy_with_candidates_streaming(
                &pattern.protocol,
                &request.method,
                &normalized_path,
                filtered_headers,
                bytes::Bytes::from(request.body.clone()),
                &routes,
            )
            .await
        {
            Ok(mut resp) => {
                use crate::l7::inference::{
                    format_chunk, format_chunk_terminator, format_http_response_header,
                };

                let resp_headers = sanitize_inference_response_headers(
                    std::mem::take(&mut resp.headers).into_iter().collect(),
                );

                // Write response headers immediately (chunked TE).
                let header_bytes = format_http_response_header(resp.status, &resp_headers);
                write_all(tls_client, &header_bytes).await?;

                // Stream body chunks with byte cap and idle timeout.
                let mut total_bytes: usize = 0;
                loop {
                    match tokio::time::timeout(CHUNK_IDLE_TIMEOUT, resp.next_chunk()).await {
                        Ok(Ok(Some(chunk))) => {
                            total_bytes += chunk.len();
                            if total_bytes > MAX_STREAMING_BODY {
                                warn!(
                                    total_bytes = total_bytes,
                                    limit = MAX_STREAMING_BODY,
                                    "streaming response exceeded byte limit, truncating"
                                );
                                break;
                            }
                            let encoded = format_chunk(&chunk);
                            write_all(tls_client, &encoded).await?;
                        }
                        Ok(Ok(None)) => break,
                        Ok(Err(e)) => {
                            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                                .activity(ActivityId::Fail)
                                .severity(SeverityId::Low)
                                .status(StatusId::Failure)
                                .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, 443))
                                .message(format!("error reading upstream response chunk: {e}"))
                                .build();
                            ocsf_emit!(event);
                            break;
                        }
                        Err(_) => {
                            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                                .activity(ActivityId::Fail)
                                .severity(SeverityId::Low)
                                .status(StatusId::Failure)
                                .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, 443))
                                .message("streaming response chunk idle timeout, closing")
                                .build();
                            ocsf_emit!(event);
                            break;
                        }
                    }
                }

                // Terminate the chunked stream.
                write_all(tls_client, format_chunk_terminator()).await?;
            }
            Err(e) => {
                {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, 443))
                        .message(format!(
                            "inference endpoint detected but upstream service failed: {e}"
                        ))
                        .build();
                    ocsf_emit!(event);
                }
                let (status, msg) = router_error_to_http(&e);
                let body = serde_json::json!({"error": msg});
                let body_bytes = body.to_string();
                let response = format_http_response(
                    status,
                    &[("content-type".to_string(), "application/json".to_string())],
                    body_bytes.as_bytes(),
                );
                write_all(tls_client, &response).await?;
            }
        }
        Ok(true)
    } else {
        // Not an inference request — deny
        {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Open)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(INFERENCE_LOCAL_HOST, 443))
                .message(format!(
                    "connection not allowed by policy: {} {}",
                    request.method, normalized_path
                ))
                .build();
            ocsf_emit!(event);
        }
        let body = serde_json::json!({"error": "connection not allowed by policy"});
        let body_bytes = body.to_string();
        let response = format_http_response(
            403,
            &[("content-type".to_string(), "application/json".to_string())],
            body_bytes.as_bytes(),
        );
        write_all(tls_client, &response).await?;
        Ok(false)
    }
}

/// Map router errors to HTTP status codes and sanitized messages.
///
/// Returns generic error messages instead of verbatim internal details.
/// Full error context (upstream URLs, hostnames, TLS details) is logged
/// server-side by the caller at `warn` level for debugging.
fn router_error_to_http(err: &openshell_router::RouterError) -> (u16, String) {
    use openshell_router::RouterError;
    match err {
        RouterError::RouteNotFound(_) => (400, "no inference route configured".to_string()),
        RouterError::NoCompatibleRoute(_) => {
            (400, "no compatible inference route available".to_string())
        }
        RouterError::Unauthorized(_) => (401, "unauthorized".to_string()),
        RouterError::UpstreamUnavailable(_) => (503, "inference service unavailable".to_string()),
        RouterError::UpstreamProtocol(_) | RouterError::Internal(_) => {
            (502, "inference service error".to_string())
        }
    }
}

fn sanitize_inference_request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !should_strip_request_header(name))
        .cloned()
        .collect()
}

fn sanitize_inference_response_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(name, _)| !should_strip_response_header(name))
        .collect()
}

fn should_strip_request_header(name: &str) -> bool {
    let name_lc = name.to_ascii_lowercase();
    matches!(
        name_lc.as_str(),
        "authorization" | "x-api-key" | "host" | "content-length"
    ) || is_hop_by_hop_header(&name_lc)
}

fn should_strip_response_header(name: &str) -> bool {
    let name_lc = name.to_ascii_lowercase();
    matches!(name_lc.as_str(), "content-length") || is_hop_by_hop_header(&name_lc)
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Write all bytes to an async writer.
async fn write_all(writer: &mut (impl tokio::io::AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    writer.write_all(data).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

/// Query L7 endpoint config from the OPA engine for a matched CONNECT decision.
///
/// Returns `Some(L7EndpointConfig)` if the matched endpoint has L7 config (protocol field),
/// `None` for L4-only endpoints.
fn query_l7_config(
    engine: &OpaEngine,
    decision: &ConnectDecision,
    host: &str,
    port: u16,
) -> Option<crate::l7::L7EndpointConfig> {
    // Only query if action is Allow (not Deny)
    let has_policy = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.is_some(),
        _ => false,
    };
    if !has_policy {
        return None;
    }

    let input = crate::opa::NetworkInput {
        host: host.to_string(),
        port,
        binary_path: decision.binary.clone().unwrap_or_default(),
        binary_sha256: String::new(),
        ancestors: decision.ancestors.clone(),
        cmdline_paths: decision.cmdline_paths.clone(),
    };

    match engine.query_endpoint_config(&input) {
        Ok(Some(val)) => crate::l7::parse_l7_config(&val),
        Ok(None) => None,
        Err(e) => {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Fail)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .message(format!("Failed to query L7 endpoint config: {e}"))
                .build();
            ocsf_emit!(event);
            None
        }
    }
}

/// Query the TLS mode for an endpoint, independent of L7 config.
///
/// This extracts `tls: skip` from the endpoint even when no `protocol` is set.
fn query_tls_mode(
    engine: &OpaEngine,
    decision: &ConnectDecision,
    host: &str,
    port: u16,
) -> crate::l7::TlsMode {
    let has_policy = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.is_some(),
        _ => false,
    };
    if !has_policy {
        return crate::l7::TlsMode::Auto;
    }

    let input = crate::opa::NetworkInput {
        host: host.to_string(),
        port,
        binary_path: decision.binary.clone().unwrap_or_default(),
        binary_sha256: String::new(),
        ancestors: decision.ancestors.clone(),
        cmdline_paths: decision.cmdline_paths.clone(),
    };

    match engine.query_endpoint_config(&input) {
        Ok(Some(val)) => crate::l7::parse_tls_mode(&val),
        _ => crate::l7::TlsMode::Auto,
    }
}

/// Check if an IP address is internal (loopback, private RFC1918, link-local, or unspecified).
///
/// This is a defense-in-depth check to prevent SSRF via the CONNECT proxy.
/// It covers:
/// - IPv4 loopback (127.0.0.0/8), private (10/8, 172.16/12, 192.168/16), link-local (169.254/16), unspecified (`0.0.0.0`)
/// - IPv6 loopback (`::1`), link-local (`fe80::/10`), ULA (`fc00::/7`), unspecified (`::`)
/// - IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unwrapped and checked as IPv4
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // fe80::/10 — IPv6 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 — IPv6 unique local addresses (ULA)
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified();
            }
            false
        }
    }
}

/// When the policy endpoint host is a literal IP address, the user has
/// explicitly declared intent to allow that destination.  Synthesize an
/// `allowed_ips` entry so the existing allowlist-validation path is used
/// instead of the blanket internal-IP rejection.  Loopback and link-local
/// addresses are still blocked by `resolve_and_check_allowed_ips`.
fn implicit_allowed_ips_for_ip_host(host: &str) -> Vec<String> {
    if host.parse::<IpAddr>().is_ok() {
        vec![host.to_string()]
    } else {
        vec![]
    }
}

/// Resolve DNS for a host:port and reject if any resolved address is internal.
///
/// Returns the resolved `SocketAddr` list on success. Returns an error string
/// if any resolved IP is in an internal range or if DNS resolution fails.
async fn resolve_and_reject_internal(
    host: &str,
    port: u16,
) -> std::result::Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}:{port}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!(
            "DNS resolution returned no addresses for {host}:{port}"
        ));
    }

    for addr in &addrs {
        if is_internal_ip(addr.ip()) {
            return Err(format!(
                "{host} resolves to internal address {}, connection rejected",
                addr.ip()
            ));
        }
    }

    Ok(addrs)
}

/// Check if an IP address is always blocked regardless of policy.
///
/// Loopback, link-local, and unspecified addresses are never allowed even when an endpoint
/// has `allowed_ips` configured. This prevents proxy bypass (loopback) and
/// cloud metadata SSRF (link-local 169.254.x.x).
fn is_always_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // fe80::/10 — IPv6 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_link_local() || v4.is_unspecified();
            }
            false
        }
    }
}

/// Resolve DNS and validate resolved addresses against a CIDR/IP allowlist.
///
/// Rejects loopback and link-local unconditionally. For all other resolved
/// addresses, checks that each one matches at least one entry in `allowed_ips`.
/// Entries can be CIDR notation ("10.0.5.0/24") or exact IPs ("10.0.5.20").
///
/// Returns the resolved `SocketAddr` list on success.
async fn resolve_and_check_allowed_ips(
    host: &str,
    port: u16,
    allowed_ips: &[ipnet::IpNet],
) -> std::result::Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}:{port}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!(
            "DNS resolution returned no addresses for {host}:{port}"
        ));
    }

    // Block control-plane ports regardless of IP match.
    if BLOCKED_CONTROL_PLANE_PORTS.contains(&port) {
        return Err(format!(
            "port {port} is a blocked control-plane port, connection rejected"
        ));
    }

    for addr in &addrs {
        // Always block loopback and link-local
        if is_always_blocked_ip(addr.ip()) {
            return Err(format!(
                "{host} resolves to always-blocked address {}, connection rejected",
                addr.ip()
            ));
        }

        // Check resolved IP against the allowlist
        let ip_allowed = allowed_ips.iter().any(|net| net.contains(&addr.ip()));
        if !ip_allowed {
            return Err(format!(
                "{host} resolves to {} which is not in allowed_ips, connection rejected",
                addr.ip()
            ));
        }
    }

    Ok(addrs)
}

/// Minimum CIDR prefix length before logging a breadth warning.
/// CIDRs broader than /16 (65,536+ addresses) may unintentionally expose
/// control-plane services on the same network.
const MIN_SAFE_PREFIX_LEN: u8 = 16;

/// Ports that are always blocked in `resolve_and_check_allowed_ips`, even
/// when the resolved IP matches an `allowed_ips` entry.  These ports belong
/// to control-plane services that should never be reachable from a sandbox.
const BLOCKED_CONTROL_PLANE_PORTS: &[u16] = &[
    2379,  // etcd client
    2380,  // etcd peer
    6443,  // Kubernetes API server
    10250, // kubelet API
    10255, // kubelet read-only
];

/// Parse CIDR/IP strings into `IpNet` values, rejecting invalid entries and
/// entries that cover loopback or link-local ranges.
///
/// Returns parsed networks on success, or an error describing which entries
/// are invalid. Logs a warning for overly broad CIDRs.
fn parse_allowed_ips(raw: &[String]) -> std::result::Result<Vec<ipnet::IpNet>, String> {
    let mut nets = Vec::with_capacity(raw.len());
    let mut errors = Vec::new();

    for entry in raw {
        // Try as CIDR first, then as bare IP (convert to /32 or /128)
        let parsed = entry.parse::<ipnet::IpNet>().or_else(|_| {
            entry
                .parse::<IpAddr>()
                .map(|ip| match ip {
                    IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::from(v4)),
                    IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::from(v6)),
                })
                .map_err(|_| ())
        });

        match parsed {
            Ok(n) => {
                if n.prefix_len() < MIN_SAFE_PREFIX_LEN {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Other)
                        .severity(SeverityId::Medium)
                        .message(format!(
                            "allowed_ips entry has a very broad CIDR {n} (/{}) < /{MIN_SAFE_PREFIX_LEN}; \
                             this may expose control-plane services on the same network",
                            n.prefix_len()
                        ))
                        .build();
                    ocsf_emit!(event);
                }
                nets.push(n);
            }
            Err(_) => errors.push(format!("invalid CIDR/IP in allowed_ips: {entry}")),
        }
    }

    if errors.is_empty() {
        Ok(nets)
    } else {
        Err(errors.join("; "))
    }
}

/// Query allowed_ips from the matched endpoint config for a CONNECT decision.
fn query_allowed_ips(
    engine: &OpaEngine,
    decision: &ConnectDecision,
    host: &str,
    port: u16,
) -> Vec<String> {
    // Only query if action is Allow with a matched policy
    let has_policy = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.is_some(),
        _ => false,
    };
    if !has_policy {
        return vec![];
    }

    let input = crate::opa::NetworkInput {
        host: host.to_string(),
        port,
        binary_path: decision.binary.clone().unwrap_or_default(),
        binary_sha256: String::new(),
        ancestors: decision.ancestors.clone(),
        cmdline_paths: decision.cmdline_paths.clone(),
    };

    match engine.query_allowed_ips(&input) {
        Ok(ips) => ips,
        Err(e) => {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Fail)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .message(format!(
                    "Failed to query allowed_ips from endpoint config: {e}"
                ))
                .build();
            ocsf_emit!(event);
            vec![]
        }
    }
}

fn normalize_inference_path(path: &str) -> String {
    if let Some(scheme_idx) = path.find("://") {
        let after_scheme = &path[scheme_idx + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            return after_scheme[path_start..].to_string();
        }
        return "/".to_string();
    }
    path.to_string()
}

/// Extract the hostname from an absolute-form URI used in plain HTTP proxy requests.
///
/// For example, `"http://example.com/path"` yields `"example.com"` and
/// `"http://example.com:8080/path"` yields `"example.com"`. Returns `"unknown"`
/// if the URI cannot be parsed.
#[cfg(test)]
fn extract_host_from_uri(uri: &str) -> String {
    // Absolute-form URIs look like "http://host[:port]/path"
    // Strip the scheme prefix, then extract the authority (host[:port]) before the first '/'.
    let after_scheme = uri.find("://").map(|i| &uri[i + 3..]).unwrap_or(uri);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    // Strip port if present (handle IPv6 bracket notation)
    let host = if authority.starts_with('[') {
        // IPv6: [::1]:port
        authority
            .find(']')
            .map(|i| &authority[..=i])
            .unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        "unknown".to_string()
    } else {
        host.to_string()
    }
}

/// Parse an absolute-form proxy request URI into its components.
///
/// For example, `"http://10.86.8.223:8000/screenshot/"` yields
/// `("http", "10.86.8.223", 8000, "/screenshot/")`.
///
/// Handles:
/// - Default port 80 for `http`, 443 for `https`
/// - IPv6 bracket notation (`[::1]`)
/// - Missing path (defaults to `/`)
/// - Query strings (preserved in path)
fn parse_proxy_uri(uri: &str) -> Result<(String, String, u16, String)> {
    // Extract scheme
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| miette::miette!("Missing scheme in proxy URI: {uri}"))?;
    let scheme = scheme.to_ascii_lowercase();

    // Split authority from path
    let (authority, path) = if rest.starts_with('[') {
        // IPv6: [::1]:port/path
        let bracket_end = rest
            .find(']')
            .ok_or_else(|| miette::miette!("Unclosed IPv6 bracket in URI: {uri}"))?;
        let after_bracket = &rest[bracket_end + 1..];
        if let Some(slash_pos) = after_bracket.find('/') {
            (
                &rest[..bracket_end + 1 + slash_pos],
                &after_bracket[slash_pos..],
            )
        } else {
            (&rest[..], "/")
        }
    } else if let Some(slash_pos) = rest.find('/') {
        (&rest[..slash_pos], &rest[slash_pos..])
    } else {
        (rest, "/")
    };

    // Parse host and port from authority
    let (host, port) = if authority.starts_with('[') {
        // IPv6: [::1]:port or [::1]
        let bracket_end = authority
            .find(']')
            .ok_or_else(|| miette::miette!("Unclosed IPv6 bracket: {uri}"))?;
        let host = &authority[1..bracket_end]; // strip brackets
        let port_str = &authority[bracket_end + 1..];
        let port = if let Some(port_str) = port_str.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| miette::miette!("Invalid port in URI: {uri}"))?
        } else {
            match scheme.as_str() {
                "https" => 443,
                _ => 80,
            }
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| miette::miette!("Invalid port in URI: {uri}"))?;
        (h.to_string(), port)
    } else {
        let port = match scheme.as_str() {
            "https" => 443,
            _ => 80,
        };
        (authority.to_string(), port)
    };

    if host.is_empty() {
        return Err(miette::miette!("Empty host in URI: {uri}"));
    }

    let path = if path.is_empty() { "/" } else { path };

    Ok((scheme, host, port, path.to_string()))
}

/// Rewrite an absolute-form HTTP proxy request to origin-form for upstream.
///
/// Transforms `GET http://host:port/path HTTP/1.1` into `GET /path HTTP/1.1`,
/// strips proxy hop-by-hop headers, injects `Connection: close` and `Via`.
///
/// Returns the rewritten request bytes (headers + any overflow body bytes).
fn rewrite_forward_request(
    raw: &[u8],
    used: usize,
    path: &str,
    secret_resolver: Option<&SecretResolver>,
) -> Result<Vec<u8>, crate::secrets::UnresolvedPlaceholderError> {
    let header_end = raw[..used]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(used, |p| p + 4);

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let lines = header_str.split("\r\n").collect::<Vec<_>>();

    // Rebuild headers, stripping hop-by-hop and adding proxy headers
    let mut output = Vec::with_capacity(header_end + 128);
    let mut has_connection = false;
    let mut has_via = false;

    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            // Rewrite request line: METHOD absolute-uri HTTP/1.1 → METHOD path HTTP/1.1
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() == 3 {
                output.extend_from_slice(parts[0].as_bytes());
                output.push(b' ');
                output.extend_from_slice(path.as_bytes());
                output.push(b' ');
                output.extend_from_slice(parts[2].as_bytes());
            } else {
                output.extend_from_slice(line.as_bytes());
            }
            output.extend_from_slice(b"\r\n");
            continue;
        }
        if line.is_empty() {
            // End of headers
            break;
        }

        let lower = line.to_ascii_lowercase();

        // Strip proxy hop-by-hop headers
        if lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authorization:")
            || lower.starts_with("proxy-authenticate:")
        {
            continue;
        }

        // Replace Connection header
        if lower.starts_with("connection:") {
            has_connection = true;
            output.extend_from_slice(b"Connection: close\r\n");
            continue;
        }

        let rewritten_line = match secret_resolver {
            Some(resolver) => rewrite_header_line(line, resolver),
            None => line.to_string(),
        };

        output.extend_from_slice(rewritten_line.as_bytes());
        output.extend_from_slice(b"\r\n");

        if lower.starts_with("via:") {
            has_via = true;
        }
    }

    // Inject missing headers
    if !has_connection {
        output.extend_from_slice(b"Connection: close\r\n");
    }
    if !has_via {
        output.extend_from_slice(b"Via: 1.1 openshell-sandbox\r\n");
    }

    // End of headers
    output.extend_from_slice(b"\r\n");

    // Append any overflow body bytes from the original buffer
    if header_end < used {
        output.extend_from_slice(&raw[header_end..used]);
    }

    // Fail-closed: scan for any remaining unresolved placeholders
    if secret_resolver.is_some() {
        let output_str = String::from_utf8_lossy(&output);
        if output_str.contains(crate::secrets::PLACEHOLDER_PREFIX_PUBLIC) {
            return Err(crate::secrets::UnresolvedPlaceholderError { location: "header" });
        }
    }

    Ok(output)
}

/// Handle a plain HTTP forward proxy request (non-CONNECT).
///
/// Public IPs are allowed through when the endpoint passes OPA evaluation.
/// Private IPs require explicit `allowed_ips` on the endpoint config (SSRF
/// override). Rewrites the absolute-form request to origin-form, connects
/// upstream, and relays the response using `copy_bidirectional` for streaming.
async fn handle_forward_proxy(
    method: &str,
    target_uri: &str,
    buf: &[u8],
    used: usize,
    client: &mut TcpStream,
    opa_engine: Arc<OpaEngine>,
    identity_cache: Arc<BinaryIdentityCache>,
    entrypoint_pid: Arc<AtomicU32>,
    secret_resolver: Option<Arc<SecretResolver>>,
    denial_tx: Option<&mpsc::UnboundedSender<DenialEvent>>,
) -> Result<()> {
    // 1. Parse the absolute-form URI
    let (scheme, host, port, path) = match parse_proxy_uri(target_uri) {
        Ok(parsed) => parsed,
        Err(e) => {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Fail)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .message(format!("FORWARD parse error for {target_uri}: {e}"))
                .build();
            ocsf_emit!(event);
            respond(client, b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            return Ok(());
        }
    };
    let host_lc = host.to_ascii_lowercase();

    // 2. Reject HTTPS — must use CONNECT for TLS
    if scheme == "https" {
        {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Refuse)
                .action(ActionId::Denied)
                .disposition(DispositionId::Rejected)
                .severity(SeverityId::Informational)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                .message(format!(
                    "FORWARD rejected: HTTPS requires CONNECT for {host_lc}:{port}"
                ))
                .build();
            ocsf_emit!(event);
        }
        respond(
            client,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\nUse CONNECT for HTTPS URLs",
        )
        .await?;
        return Ok(());
    }

    // 3. Evaluate OPA policy (same identity binding as CONNECT)
    let peer_addr = client.peer_addr().into_diagnostic()?;
    let _local_addr = client.local_addr().into_diagnostic()?;

    let opa_clone = opa_engine.clone();
    let cache_clone = identity_cache.clone();
    let pid_clone = entrypoint_pid.clone();
    let host_clone = host_lc.clone();
    let decision = tokio::task::spawn_blocking(move || {
        evaluate_opa_tcp(
            peer_addr,
            &opa_clone,
            &cache_clone,
            &pid_clone,
            &host_clone,
            port,
        )
    })
    .await
    .map_err(|e| miette::miette!("identity resolution task panicked: {e}"))?;

    // Build log context
    let binary_str = decision
        .binary
        .as_ref()
        .map_or_else(|| "-".to_string(), |p| p.display().to_string());
    let pid_str = decision
        .binary_pid
        .map_or_else(|| "-".to_string(), |p| p.to_string());
    let ancestors_str = if decision.ancestors.is_empty() {
        "-".to_string()
    } else {
        decision
            .ancestors
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    };
    let cmdline_str = if decision.cmdline_paths.is_empty() {
        "-".to_string()
    } else {
        decision
            .cmdline_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    // 4. Only proceed on explicit Allow — reject Deny
    let matched_policy = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone(),
        NetworkAction::Deny { reason } => {
            {
                let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Other)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .http_request(HttpRequest::new(
                        method,
                        OcsfUrl::new("http", &host_lc, &path, port),
                    ))
                    .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                    .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                    .actor_process(
                        Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                            .with_cmd_line(&cmdline_str),
                    )
                    .firewall_rule("-", "opa")
                    .message(format!("FORWARD denied {method} {host_lc}:{port}{path}"))
                    .build();
                ocsf_emit!(event);
            }
            emit_denial_simple(
                denial_tx,
                &host_lc,
                port,
                &binary_str,
                &decision,
                reason,
                "forward",
            );
            respond(client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }
    };
    let policy_str = matched_policy.as_deref().unwrap_or("-");

    // 4b. If the endpoint has L7 config, evaluate the request against
    //     L7 policy.  The forward proxy handles exactly one request per
    //     connection (Connection: close), so a single evaluation suffices.
    if let Some(l7_config) = query_l7_config(&opa_engine, &decision, &host_lc, port) {
        let tunnel_engine = opa_engine.clone_engine_for_tunnel().unwrap_or_else(|e| {
            let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Fail)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                .message(format!("Failed to clone OPA engine for forward L7: {e}"))
                .build();
            ocsf_emit!(event);
            regorus::Engine::new()
        });
        let engine_mutex = std::sync::Mutex::new(tunnel_engine);

        let l7_ctx = crate::l7::relay::L7EvalContext {
            host: host_lc.clone(),
            port,
            policy_name: matched_policy.clone().unwrap_or_default(),
            binary_path: decision
                .binary
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            ancestors: decision
                .ancestors
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            cmdline_paths: decision
                .cmdline_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            secret_resolver: secret_resolver.clone(),
        };

        let (target_path, query_params) = crate::l7::rest::parse_target_query(&path)
            .unwrap_or_else(|_| (path.clone(), std::collections::HashMap::new()));
        let request_info = crate::l7::L7RequestInfo {
            action: method.to_string(),
            target: target_path,
            query_params,
        };

        let (allowed, reason) =
            crate::l7::relay::evaluate_l7_request(&engine_mutex, &l7_ctx, &request_info)
                .unwrap_or_else(|e| {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .status(StatusId::Failure)
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .message(format!("L7 eval failed, denying request: {e}"))
                        .build();
                    ocsf_emit!(event);
                    (false, format!("L7 evaluation error: {e}"))
                });

        let decision_str = match (allowed, l7_config.enforcement) {
            (true, _) => "allow",
            (false, crate::l7::EnforcementMode::Audit) => "audit",
            (false, crate::l7::EnforcementMode::Enforce) => "deny",
        };

        {
            let (action_id, disposition_id, severity) = match decision_str {
                "allow" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    method,
                    OcsfUrl::new("http", &host_lc, &path, port),
                ))
                .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                .actor_process(
                    Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                        .with_cmd_line(&cmdline_str),
                )
                .firewall_rule(policy_str, "l7")
                .message(format!(
                    "FORWARD_L7 {decision_str} {method} {host_lc}:{port}{path} reason={reason}"
                ))
                .build();
            ocsf_emit!(event);
        }

        let effectively_denied =
            !allowed && l7_config.enforcement == crate::l7::EnforcementMode::Enforce;

        if effectively_denied {
            emit_denial_simple(
                denial_tx,
                &host_lc,
                port,
                &binary_str,
                &decision,
                &reason,
                "forward-l7-deny",
            );
            respond(client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }
    }

    // 5. DNS resolution + SSRF defence (mirrors the CONNECT path logic).
    //    - If allowed_ips is set: validate resolved IPs against the allowlist
    //      (this is the SSRF override for private IP destinations).
    //    - If allowed_ips is empty: reject internal IPs, allow public IPs through.
    //    When the policy host is already a literal IP address, treat it as
    //    implicitly allowed — the user explicitly declared the destination.
    let mut raw_allowed_ips = query_allowed_ips(&opa_engine, &decision, &host_lc, port);
    if raw_allowed_ips.is_empty() {
        raw_allowed_ips = implicit_allowed_ips_for_ip_host(&host);
    }

    let addrs = if !raw_allowed_ips.is_empty() {
        // allowed_ips mode: validate resolved IPs against CIDR allowlist.
        match parse_allowed_ips(&raw_allowed_ips) {
            Ok(nets) => match resolve_and_check_allowed_ips(&host, port, &nets).await {
                Ok(addrs) => addrs,
                Err(reason) => {
                    {
                        let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                            .activity(ActivityId::Other)
                            .action(ActionId::Denied)
                            .disposition(DispositionId::Blocked)
                            .severity(SeverityId::Medium)
                            .status(StatusId::Failure)
                            .http_request(HttpRequest::new(
                                method,
                                OcsfUrl::new("http", &host_lc, &path, port),
                            ))
                            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                            .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                            .actor_process(
                                Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                    .with_cmd_line(&cmdline_str),
                            )
                            .firewall_rule(policy_str, "ssrf")
                            .message(format!(
                                "FORWARD blocked: allowed_ips check failed for {host_lc}:{port}: {reason}"
                            ))
                            .build();
                        ocsf_emit!(event);
                    }
                    emit_denial_simple(
                        denial_tx,
                        &host_lc,
                        port,
                        &binary_str,
                        &decision,
                        &reason,
                        "ssrf",
                    );
                    respond(client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                    return Ok(());
                }
            },
            Err(reason) => {
                {
                    let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Other)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .http_request(HttpRequest::new(
                            method,
                            OcsfUrl::new("http", &host_lc, &path, port),
                        ))
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                        .actor_process(
                            Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                .with_cmd_line(&cmdline_str),
                        )
                        .firewall_rule(policy_str, "ssrf")
                        .message(format!(
                            "FORWARD blocked: invalid allowed_ips in policy for {host_lc}:{port}: {reason}"
                        ))
                        .build();
                    ocsf_emit!(event);
                }
                emit_denial_simple(
                    denial_tx,
                    &host_lc,
                    port,
                    &binary_str,
                    &decision,
                    &reason,
                    "ssrf",
                );
                respond(client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    } else {
        // No allowed_ips: reject internal IPs, allow public IPs through.
        match resolve_and_reject_internal(&host, port).await {
            Ok(addrs) => addrs,
            Err(reason) => {
                {
                    let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Other)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .http_request(HttpRequest::new(
                            method,
                            OcsfUrl::new("http", &host_lc, &path, port),
                        ))
                        .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                        .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                        .actor_process(
                            Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                                .with_cmd_line(&cmdline_str),
                        )
                        .firewall_rule(policy_str, "ssrf")
                        .message(format!(
                            "FORWARD blocked: internal IP without allowed_ips for {host_lc}:{port}: {reason}"
                        ))
                        .build();
                    ocsf_emit!(event);
                }
                emit_denial_simple(
                    denial_tx,
                    &host_lc,
                    port,
                    &binary_str,
                    &decision,
                    &reason,
                    "ssrf",
                );
                respond(client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    };

    // 6. Connect upstream
    let mut upstream = match TcpStream::connect(addrs.as_slice()).await {
        Ok(s) => s,
        Err(e) => {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Fail)
                .severity(SeverityId::Low)
                .status(StatusId::Failure)
                .http_request(HttpRequest::new(
                    method,
                    OcsfUrl::new("http", &host_lc, &path, port),
                ))
                .dst_endpoint(Endpoint::from_domain(&host_lc, port))
                .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
                .actor_process(
                    Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                        .with_cmd_line(&cmdline_str),
                )
                .message(format!(
                    "FORWARD upstream connect failed for {host_lc}:{port}: {e}"
                ))
                .build();
            ocsf_emit!(event);
            respond(client, b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Ok(());
        }
    };

    // Log success
    {
        let event = HttpActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Other)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .http_request(HttpRequest::new(
                method,
                OcsfUrl::new("http", &host_lc, &path, port),
            ))
            .dst_endpoint(Endpoint::from_domain(&host_lc, port))
            .src_endpoint(Endpoint::from_ip(peer_addr.ip(), peer_addr.port()))
            .actor_process(
                Process::from_bypass(&binary_str, &pid_str, &ancestors_str)
                    .with_cmd_line(&cmdline_str),
            )
            .firewall_rule(policy_str, "opa")
            .message(format!("FORWARD allowed {method} {host_lc}:{port}{path}"))
            .build();
        ocsf_emit!(event);
    }

    // 9. Rewrite request and forward to upstream
    let rewritten = match rewrite_forward_request(buf, used, &path, secret_resolver.as_deref()) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(
                dst_host = %host_lc,
                dst_port = port,
                error = %e,
                "credential injection failed in forward proxy"
            );
            respond(client, b"HTTP/1.1 500 Internal Server Error\r\n\r\n").await?;
            return Ok(());
        }
    };
    upstream.write_all(&rewritten).await.into_diagnostic()?;

    // 8. Relay remaining traffic bidirectionally (supports streaming)
    let _ = tokio::io::copy_bidirectional(client, &mut upstream)
        .await
        .into_diagnostic()?;

    Ok(())
}

fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port_str) = target
        .split_once(':')
        .ok_or_else(|| miette::miette!("CONNECT target missing port: {target}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| miette::miette!("Invalid port in CONNECT target: {target}"))?;
    Ok((host.to_string(), port))
}

async fn respond(client: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    client.write_all(bytes).await.into_diagnostic()?;
    Ok(())
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_relay_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // -- is_internal_ip: IPv4 --

    #[test]
    fn test_rejects_ipv4_loopback() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
    }

    #[test]
    fn test_rejects_ipv4_private_10() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    }

    #[test]
    fn test_rejects_ipv4_private_172_16() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
    }

    #[test]
    fn test_rejects_ipv4_private_192_168() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 255, 255
        ))));
    }

    #[test]
    fn test_rejects_ipv4_link_local_metadata() {
        // Cloud metadata endpoint
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
    }

    #[test]
    fn test_rejects_ipv4_unspecified() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_allows_ipv4_public() {
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn test_allows_ipv4_non_private_172() {
        // 172.32.0.0 is outside the 172.16/12 private range
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    // -- is_internal_ip: IPv6 --

    #[test]
    fn test_rejects_ipv6_loopback() {
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_rejects_ipv6_unspecified() {
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_rejects_ipv6_link_local() {
        // fe80::1
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_rejects_ipv6_unique_local_address() {
        // fdc4:f303:9324::254
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfdc4, 0xf303, 0x9324, 0, 0, 0, 0, 0x0254
        ))));
    }

    #[test]
    fn test_rejects_ipv4_mapped_ipv6_private() {
        // ::ffff:10.0.0.1
        let v6 = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped();
        assert!(is_internal_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_rejects_ipv4_mapped_ipv6_loopback() {
        // ::ffff:127.0.0.1
        let v6 = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(is_internal_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_rejects_ipv4_mapped_ipv6_link_local() {
        // ::ffff:169.254.169.254
        let v6 = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert!(is_internal_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_allows_ipv6_public() {
        // 2001:4860:4860::8888 (Google DNS)
        assert!(!is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_allows_ipv4_mapped_ipv6_public() {
        // ::ffff:8.8.8.8
        let v6 = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped();
        assert!(!is_internal_ip(IpAddr::V6(v6)));
    }

    // -- resolve_and_reject_internal --

    #[tokio::test]
    async fn test_rejects_localhost_resolution() {
        let result = resolve_and_reject_internal("localhost", 80).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("internal address"),
            "expected 'internal address' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rejects_loopback_ip_literal() {
        let result = resolve_and_reject_internal("127.0.0.1", 443).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("internal address"),
            "expected 'internal address' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_rejects_metadata_ip() {
        let result = resolve_and_reject_internal("169.254.169.254", 80).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("internal address"),
            "expected 'internal address' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_failure_returns_error() {
        let result = resolve_and_reject_internal("this-host-does-not-exist.invalid", 80).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("DNS resolution failed"),
            "expected 'DNS resolution failed' in error: {err}"
        );
    }

    #[test]
    fn sanitize_request_headers_strips_auth_and_framing() {
        let headers = vec![
            ("authorization".to_string(), "Bearer test".to_string()),
            ("x-api-key".to_string(), "secret".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            ("content-length".to_string(), "42".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept".to_string(), "text/event-stream".to_string()),
        ];

        let kept = sanitize_inference_request_headers(&headers);

        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("authorization")),
            "authorization should be stripped"
        );
        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("x-api-key")),
            "x-api-key should be stripped"
        );
        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding")),
            "transfer-encoding should be stripped"
        );
        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("content-length")),
            "content-length should be stripped"
        );
        assert!(
            kept.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
            "content-type should be preserved"
        );
        assert!(
            kept.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")),
            "accept should be preserved"
        );
    }

    // -- router_error_to_http --

    #[test]
    fn router_error_route_not_found_maps_to_400() {
        let err = openshell_router::RouterError::RouteNotFound("local".into());
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 400);
        assert_eq!(msg, "no inference route configured");
        // SEC-008: must NOT leak the route hint to sandboxed code
        assert!(!msg.contains("local"));
    }

    #[test]
    fn router_error_no_compatible_route_maps_to_400() {
        let err = openshell_router::RouterError::NoCompatibleRoute("anthropic_messages".into());
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 400);
        assert_eq!(msg, "no compatible inference route available");
        // SEC-008: must NOT leak the protocol name to sandboxed code
        assert!(!msg.contains("anthropic_messages"));
    }

    #[test]
    fn router_error_unauthorized_maps_to_401() {
        let err =
            openshell_router::RouterError::Unauthorized("bad token from 10.0.0.5:8080".into());
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 401);
        assert_eq!(msg, "unauthorized");
        // SEC-008: must NOT leak upstream details to sandboxed code
        assert!(!msg.contains("10.0.0.5"));
    }

    #[test]
    fn router_error_upstream_unavailable_maps_to_503() {
        let err = openshell_router::RouterError::UpstreamUnavailable(
            "connection refused to 10.0.0.5:8080".into(),
        );
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 503);
        assert_eq!(msg, "inference service unavailable");
        // SEC-008: must NOT leak upstream address to sandboxed code
        assert!(!msg.contains("10.0.0.5"));
    }

    #[test]
    fn router_error_upstream_protocol_maps_to_502() {
        let err = openshell_router::RouterError::UpstreamProtocol(
            "TLS handshake failed for nim.internal.svc:443".into(),
        );
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 502);
        assert_eq!(msg, "inference service error");
        // SEC-008: must NOT leak internal hostnames to sandboxed code
        assert!(!msg.contains("nim.internal"));
    }

    #[test]
    fn router_error_internal_maps_to_502() {
        let err = openshell_router::RouterError::Internal(
            "failed to read /etc/openshell/routes.json".into(),
        );
        let (status, msg) = router_error_to_http(&err);
        assert_eq!(status, 502);
        assert_eq!(msg, "inference service error");
        // SEC-008: must NOT leak file paths to sandboxed code
        assert!(!msg.contains("/etc/openshell"));
    }

    #[test]
    fn sanitize_response_headers_strips_hop_by_hop() {
        let headers = vec![
            ("transfer-encoding".to_string(), "chunked".to_string()),
            ("content-length".to_string(), "128".to_string()),
            ("connection".to_string(), "keep-alive".to_string()),
            ("content-type".to_string(), "text/event-stream".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
        ];

        let kept = sanitize_inference_response_headers(headers);

        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding")),
            "transfer-encoding should be stripped"
        );
        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("content-length")),
            "content-length should be stripped"
        );
        assert!(
            kept.iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("connection")),
            "connection should be stripped"
        );
        assert!(
            kept.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
            "content-type should be preserved"
        );
        assert!(
            kept.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("cache-control")),
            "cache-control should be preserved"
        );
    }

    // -- is_always_blocked_ip --

    #[test]
    fn test_always_blocked_loopback_v4() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 2
        ))));
    }

    #[test]
    fn test_always_blocked_link_local_v4() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_loopback_v6() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_always_blocked_link_local_v6() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_ipv4_unspecified() {
        assert!(is_always_blocked_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_always_blocked_ipv6_unspecified() {
        assert!(is_always_blocked_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_always_blocked_ipv4_mapped_v6_loopback() {
        let v6 = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(is_always_blocked_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_always_blocked_ipv4_mapped_v6_link_local() {
        let v6 = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert!(is_always_blocked_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn test_always_blocked_allows_rfc1918() {
        // RFC 1918 addresses should NOT be always-blocked (they're allowed
        // when allowed_ips is configured)
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 0, 1
        ))));
    }

    #[test]
    fn test_always_blocked_allows_public() {
        assert!(!is_always_blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_always_blocked_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    // -- parse_allowed_ips --

    #[test]
    fn test_parse_cidr_notation() {
        let raw = vec!["10.0.5.0/24".to_string()];
        let nets = parse_allowed_ips(&raw).unwrap();
        assert_eq!(nets.len(), 1);
        assert!(nets[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1))));
        assert!(!nets[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 6, 1))));
    }

    #[test]
    fn test_parse_exact_ip() {
        let raw = vec!["10.0.5.20".to_string()];
        let nets = parse_allowed_ips(&raw).unwrap();
        assert_eq!(nets.len(), 1);
        assert!(nets[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 5, 20))));
        assert!(!nets[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 5, 21))));
    }

    #[test]
    fn test_parse_multiple_entries() {
        let raw = vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.1.1".to_string(),
        ];
        let nets = parse_allowed_ips(&raw).unwrap();
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn test_parse_invalid_entry_errors() {
        let raw = vec!["not-an-ip".to_string()];
        let result = parse_allowed_ips(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid CIDR/IP"));
    }

    #[test]
    fn test_parse_mixed_valid_invalid_errors() {
        let raw = vec!["10.0.5.0/24".to_string(), "garbage".to_string()];
        let result = parse_allowed_ips(&raw);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_blocks_loopback() {
        let nets = parse_allowed_ips(&["127.0.0.0/8".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("127.0.0.1", 80, &nets).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("always-blocked"),
            "expected 'always-blocked' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_blocks_metadata() {
        let nets = parse_allowed_ips(&["169.254.0.0/16".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("169.254.169.254", 80, &nets).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("always-blocked"),
            "expected 'always-blocked' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_blocks_unspecified() {
        let nets = parse_allowed_ips(&["0.0.0.0/0".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("0.0.0.0", 80, &nets).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("always-blocked"),
            "expected 'always-blocked' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_rejects_outside_allowlist() {
        // 8.8.8.8 resolves to a public IP which is NOT in 10.0.0.0/8
        let nets = parse_allowed_ips(&["10.0.0.0/8".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("dns.google", 443, &nets).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not in allowed_ips"),
            "expected 'not in allowed_ips' in error: {err}"
        );
    }

    // --- SEC-005: CIDR breadth warning and control-plane port blocklist ---

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_blocks_control_plane_ports() {
        let nets = parse_allowed_ips(&["0.0.0.0/0".to_string()]).unwrap();
        // K8s API server port
        let result = resolve_and_check_allowed_ips("8.8.8.8", 6443, &nets).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked control-plane port"));

        // etcd client port
        let result = resolve_and_check_allowed_ips("8.8.8.8", 2379, &nets).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked control-plane port"));

        // kubelet API port
        let result = resolve_and_check_allowed_ips("8.8.8.8", 10250, &nets).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked control-plane port"));
    }

    #[tokio::test]
    async fn test_resolve_check_allowed_ips_allows_non_control_plane_ports() {
        // Port 443 should not be blocked by the control-plane port list
        let nets = parse_allowed_ips(&["8.8.8.0/24".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("8.8.8.8", 443, &nets).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_allowed_ips_broad_cidr_is_accepted() {
        // Broad CIDRs are accepted (just warned about) -- design trade-off
        let result = parse_allowed_ips(&["10.0.0.0/8".to_string()]);
        assert!(result.is_ok());
    }

    // --- extract_host_from_uri tests ---

    #[test]
    fn test_extract_host_from_http_uri() {
        assert_eq!(
            extract_host_from_uri("http://example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_host_from_https_uri() {
        assert_eq!(
            extract_host_from_uri("https://api.openai.com/v1/chat/completions"),
            "api.openai.com"
        );
    }

    #[test]
    fn test_extract_host_from_uri_with_port() {
        assert_eq!(
            extract_host_from_uri("http://example.com:8080/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_host_from_uri_ipv6() {
        assert_eq!(extract_host_from_uri("http://[::1]:8080/path"), "[::1]");
    }

    #[test]
    fn test_extract_host_from_uri_no_path() {
        assert_eq!(extract_host_from_uri("http://example.com"), "example.com");
    }

    #[test]
    fn test_extract_host_from_uri_empty() {
        assert_eq!(extract_host_from_uri(""), "unknown");
    }

    #[test]
    fn test_extract_host_from_uri_malformed() {
        // Gracefully handles garbage input
        let result = extract_host_from_uri("not-a-uri");
        assert!(!result.is_empty());
    }

    // --- parse_proxy_uri tests ---

    #[test]
    fn test_parse_proxy_uri_standard() {
        let (scheme, host, port, path) =
            parse_proxy_uri("http://10.86.8.223:8000/screenshot/").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "10.86.8.223");
        assert_eq!(port, 8000);
        assert_eq!(path, "/screenshot/");
    }

    #[test]
    fn test_parse_proxy_uri_default_port() {
        let (scheme, host, port, path) = parse_proxy_uri("http://example.com/path").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_proxy_uri_https_default_port() {
        let (scheme, host, port, path) =
            parse_proxy_uri("https://api.example.com/v1/chat").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/v1/chat");
    }

    #[test]
    fn test_parse_proxy_uri_missing_path() {
        let (_, host, port, path) = parse_proxy_uri("http://10.0.0.1:9090").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9090);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_proxy_uri_with_query() {
        let (_, _, _, path) = parse_proxy_uri("http://host:80/api?key=val&foo=bar").unwrap();
        assert_eq!(path, "/api?key=val&foo=bar");
    }

    #[test]
    fn test_parse_proxy_uri_ipv6() {
        let (_, host, port, path) = parse_proxy_uri("http://[::1]:8080/test").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
        assert_eq!(path, "/test");
    }

    #[test]
    fn test_parse_proxy_uri_ipv6_default_port() {
        let (_, host, port, path) = parse_proxy_uri("http://[fe80::1]/path").unwrap();
        assert_eq!(host, "fe80::1");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_proxy_uri_missing_scheme() {
        let result = parse_proxy_uri("example.com/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_proxy_uri_empty_host() {
        let result = parse_proxy_uri("http:///path");
        assert!(result.is_err());
    }

    // --- rewrite_forward_request tests ---

    #[test]
    fn test_rewrite_get_request() {
        let raw =
            b"GET http://10.0.0.1:8000/api HTTP/1.1\r\nHost: 10.0.0.1:8000\r\nAccept: */*\r\n\r\n";
        let result = rewrite_forward_request(raw, raw.len(), "/api", None).expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.starts_with("GET /api HTTP/1.1\r\n"));
        assert!(result_str.contains("Host: 10.0.0.1:8000"));
        assert!(result_str.contains("Connection: close"));
        assert!(result_str.contains("Via: 1.1 openshell-sandbox"));
    }

    #[test]
    fn test_rewrite_strips_proxy_headers() {
        let raw = b"GET http://host/p HTTP/1.1\r\nHost: host\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n";
        let result = rewrite_forward_request(raw, raw.len(), "/p", None).expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            !result_str
                .to_ascii_lowercase()
                .contains("proxy-authorization")
        );
        assert!(!result_str.to_ascii_lowercase().contains("proxy-connection"));
        assert!(result_str.contains("Accept: */*"));
    }

    #[test]
    fn test_rewrite_replaces_connection_header() {
        let raw = b"GET http://host/p HTTP/1.1\r\nHost: host\r\nConnection: keep-alive\r\n\r\n";
        let result = rewrite_forward_request(raw, raw.len(), "/p", None).expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Connection: close"));
        assert!(!result_str.contains("keep-alive"));
    }

    #[test]
    fn test_rewrite_preserves_body_overflow() {
        let raw = b"POST http://host/api HTTP/1.1\r\nHost: host\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        let result = rewrite_forward_request(raw, raw.len(), "/api", None).expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("{\"key\":\"val\"}"));
        assert!(result_str.contains("POST /api HTTP/1.1"));
    }

    #[test]
    fn test_rewrite_preserves_existing_via() {
        let raw = b"GET http://host/p HTTP/1.1\r\nHost: host\r\nVia: 1.0 upstream\r\n\r\n";
        let result = rewrite_forward_request(raw, raw.len(), "/p", None).expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Via: 1.0 upstream"));
        // Should not add a second Via header
        assert!(!result_str.contains("Via: 1.1 openshell-sandbox"));
    }

    #[test]
    fn test_rewrite_resolves_placeholder_auth_headers() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let raw = b"GET http://host/p HTTP/1.1\r\nHost: host\r\nAuthorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY\r\n\r\n";
        let result = rewrite_forward_request(raw, raw.len(), "/p", resolver.as_ref())
            .expect("should succeed");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Authorization: Bearer sk-test"));
        assert!(!result_str.contains("openshell:resolve:env:ANTHROPIC_API_KEY"));
    }

    // --- Forward proxy SSRF defence tests ---
    //
    // The forward proxy handler uses the same SSRF logic as the CONNECT path:
    //   - No allowed_ips: resolve_and_reject_internal blocks private IPs, allows public.
    //   - With allowed_ips: resolve_and_check_allowed_ips validates against allowlist.
    //
    // These tests document that contract for the forward proxy path specifically.

    #[tokio::test]
    async fn test_forward_public_ip_allowed_without_allowed_ips() {
        // Public IPs (e.g. dns.google -> 8.8.8.8) should pass through
        // resolve_and_reject_internal without needing allowed_ips.
        let result = resolve_and_reject_internal("dns.google", 80).await;
        assert!(
            result.is_ok(),
            "Public IP should be allowed without allowed_ips: {result:?}"
        );
        let addrs = result.unwrap();
        assert!(!addrs.is_empty(), "Should resolve to at least one address");
        // All resolved addresses should be public.
        for addr in &addrs {
            assert!(
                !is_internal_ip(addr.ip()),
                "dns.google should resolve to public IPs, got {}",
                addr.ip()
            );
        }
    }

    #[tokio::test]
    async fn test_forward_private_ip_rejected_without_allowed_ips() {
        // Private IP literals should be rejected by resolve_and_reject_internal.
        let result = resolve_and_reject_internal("10.0.0.1", 80).await;
        assert!(
            result.is_err(),
            "Private IP should be rejected without allowed_ips"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("internal address"),
            "expected 'internal address' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_forward_private_ip_accepted_with_allowed_ips() {
        // Private IP with matching allowed_ips should pass through.
        let nets = parse_allowed_ips(&["10.0.0.0/8".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("10.0.0.1", 80, &nets).await;
        assert!(
            result.is_ok(),
            "Private IP with matching allowed_ips should be accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_forward_private_ip_rejected_with_wrong_allowed_ips() {
        // Private IP not in allowed_ips should be rejected.
        let nets = parse_allowed_ips(&["192.168.0.0/16".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("10.0.0.1", 80, &nets).await;
        assert!(
            result.is_err(),
            "Private IP not in allowed_ips should be rejected"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("not in allowed_ips"),
            "expected 'not in allowed_ips' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_forward_loopback_always_blocked_even_with_allowed_ips() {
        // Loopback addresses are always blocked, even if in allowed_ips.
        let nets = parse_allowed_ips(&["127.0.0.0/8".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("127.0.0.1", 80, &nets).await;
        assert!(result.is_err(), "Loopback should be always blocked");
        let err = result.unwrap_err();
        assert!(
            err.contains("always-blocked"),
            "expected 'always-blocked' in error: {err}"
        );
    }

    #[tokio::test]
    async fn test_forward_link_local_always_blocked_even_with_allowed_ips() {
        // Link-local / cloud metadata addresses are always blocked.
        let nets = parse_allowed_ips(&["169.254.0.0/16".to_string()]).unwrap();
        let result = resolve_and_check_allowed_ips("169.254.169.254", 80, &nets).await;
        assert!(result.is_err(), "Link-local should be always blocked");
        let err = result.unwrap_err();
        assert!(
            err.contains("always-blocked"),
            "expected 'always-blocked' in error: {err}"
        );
    }

    // -- implicit_allowed_ips_for_ip_host --

    #[test]
    fn test_implicit_allowed_ips_returns_ip_for_ipv4_literal() {
        let result = implicit_allowed_ips_for_ip_host("192.168.1.100");
        assert_eq!(result, vec!["192.168.1.100"]);
    }

    #[test]
    fn test_implicit_allowed_ips_returns_ip_for_ipv6_literal() {
        let result = implicit_allowed_ips_for_ip_host("::1");
        assert_eq!(result, vec!["::1"]);
    }

    #[test]
    fn test_implicit_allowed_ips_returns_empty_for_hostname() {
        let result = implicit_allowed_ips_for_ip_host("api.github.com");
        assert!(result.is_empty());
    }

    #[test]
    fn test_implicit_allowed_ips_returns_empty_for_wildcard() {
        let result = implicit_allowed_ips_for_ip_host("*.example.com");
        assert!(result.is_empty());
    }
}
