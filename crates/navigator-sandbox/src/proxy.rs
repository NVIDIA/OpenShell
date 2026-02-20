//! HTTP CONNECT proxy with OPA policy evaluation and process-identity binding.

use crate::identity::BinaryIdentityCache;
use crate::l7::tls::ProxyTlsState;
use crate::opa::OpaEngine;
use crate::policy::ProxyPolicy;
use miette::{IntoDiagnostic, Result};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const MAX_HEADER_BYTES: usize = 8192;

/// Result of a proxy CONNECT policy decision.
struct ConnectDecision {
    allowed: bool,
    /// Resolved binary path.
    binary: Option<PathBuf>,
    /// PID owning the socket.
    binary_pid: Option<u32>,
    /// Ancestor binary paths from process tree walk.
    ancestors: Vec<PathBuf>,
    /// Cmdline-derived absolute paths (for script detection).
    cmdline_paths: Vec<PathBuf>,
    /// Name of the matched policy rule (allow only).
    matched_policy: Option<String>,
    /// Which engine made the decision ("opa" or "`control_plane`").
    engine: &'static str,
    /// Deny reason or error context.
    reason: String,
}

/// An endpoint that the proxy always allows without OPA evaluation.
/// Used for infrastructure endpoints like the navigator control plane.
#[derive(Debug, Clone)]
pub struct AllowedEndpoint {
    pub host: String,
    pub port: u16,
}

/// Parse a URL like `http://host:port` into an `AllowedEndpoint`.
///
/// Strips the scheme and extracts host + port. Returns `None` if the
/// URL can't be parsed.
pub fn parse_endpoint_url(url: &str) -> Option<AllowedEndpoint> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let (host, port_str) = without_scheme.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some(AllowedEndpoint {
        host: host.to_ascii_lowercase(),
        port,
    })
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
    /// via `/proc/net/tcp`. Connections to `control_plane_endpoints` are always
    /// allowed without OPA evaluation — these are infrastructure endpoints
    /// (like the navigator server) that the sandbox needs to function.
    pub async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
        control_plane_endpoints: Vec<AllowedEndpoint>,
        tls_state: Option<Arc<ProxyTlsState>>,
    ) -> Result<Self> {
        // Use override bind_addr or fall back to policy http_addr
        let http_addr = bind_addr.or(policy.http_addr);

        let http_addr = http_addr.ok_or_else(|| {
            miette::miette!("Proxy policy must set http_addr or provide a bind address")
        })?;

        // Only enforce loopback restriction when not using network namespace override
        if bind_addr.is_none() && !http_addr.ip().is_loopback() {
            return Err(miette::miette!(
                "Proxy http_addr must be loopback-only: {http_addr}"
            ));
        }

        let listener = TcpListener::bind(http_addr).await.into_diagnostic()?;
        let local_addr = listener.local_addr().into_diagnostic()?;
        info!(addr = %local_addr, "Proxy listening (tcp)");

        let cp_endpoints = Arc::new(control_plane_endpoints);
        let join = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let opa = opa_engine.clone();
                        let cache = identity_cache.clone();
                        let spid = entrypoint_pid.clone();
                        let cp = cp_endpoints.clone();
                        let tls = tls_state.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                handle_tcp_connection(stream, opa, cache, spid, cp, tls).await
                            {
                                warn!(error = %err, "Proxy connection error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "Proxy accept error");
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

async fn handle_tcp_connection(
    mut client: TcpStream,
    opa_engine: Arc<OpaEngine>,
    identity_cache: Arc<BinaryIdentityCache>,
    entrypoint_pid: Arc<AtomicU32>,
    control_plane_endpoints: Arc<Vec<AllowedEndpoint>>,
    tls_state: Option<Arc<ProxyTlsState>>,
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
        respond(&mut client, b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }

    let (host, port) = parse_target(target)?;
    let host_lc = host.to_ascii_lowercase();

    let peer_addr = client.peer_addr().into_diagnostic()?;
    let local_addr = client.local_addr().into_diagnostic()?;

    // Allow control plane endpoints (e.g. navigator server) without OPA evaluation.
    // These are infrastructure endpoints the sandbox needs to function.
    let is_control_plane = control_plane_endpoints
        .iter()
        .any(|ep| ep.host == host_lc && ep.port == port);

    let decision = if is_control_plane {
        ConnectDecision {
            allowed: true,
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
            matched_policy: Some("control_plane".into()),
            engine: "control_plane",
            reason: String::new(),
        }
    } else {
        // Evaluate OPA policy with process-identity binding
        evaluate_opa_tcp(
            peer_addr,
            &opa_engine,
            &identity_cache,
            &entrypoint_pid,
            &host_lc,
            port,
        )
    };

    // Unified log line: one info! per CONNECT with full context
    let action = if decision.allowed { "allow" } else { "deny" };
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
    let policy_str = decision.matched_policy.as_deref().unwrap_or("-");

    info!(
        src_addr = %peer_addr.ip(),
        src_port = peer_addr.port(),
        proxy_addr = %local_addr,
        dst_host = %host_lc,
        dst_port = port,
        binary = %binary_str,
        binary_pid = %pid_str,
        ancestors = %ancestors_str,
        cmdline = %cmdline_str,
        action = %action,
        engine = %decision.engine,
        policy = %policy_str,
        reason = %decision.reason,
        "CONNECT",
    );

    if !decision.allowed {
        respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    // Defense-in-depth: resolve DNS and reject connections to internal IPs.
    // Control plane endpoints are exempt — they legitimately resolve to private
    // IPs in cluster deployments and are already checked before OPA evaluation.
    let mut upstream = if is_control_plane {
        TcpStream::connect((host.as_str(), port))
            .await
            .into_diagnostic()?
    } else {
        match resolve_and_reject_internal(&host, port).await {
            Ok(addrs) => TcpStream::connect(addrs.as_slice())
                .await
                .into_diagnostic()?,
            Err(reason) => {
                warn!(
                    dst_host = %host_lc,
                    dst_port = port,
                    reason = %reason,
                    "CONNECT blocked: internal address"
                );
                respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    };

    respond(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Check if endpoint has L7 config for protocol-aware inspection
    if !is_control_plane
        && let Some(l7_config) = query_l7_config(&opa_engine, &decision, &host_lc, port)
    {
        // Clone engine for per-tunnel L7 evaluation (cheap: shares compiled policy via Arc)
        let tunnel_engine = opa_engine.clone_engine_for_tunnel().unwrap_or_else(|e| {
            warn!(error = %e, "Failed to clone OPA engine for L7, falling back to L4-only");
            // This shouldn't happen, but if it does fall through to copy_bidirectional
            regorus::Engine::new()
        });

        let ctx = crate::l7::relay::L7EvalContext {
            host: host_lc.clone(),
            port,
            policy_name: decision.matched_policy.clone().unwrap_or_default(),
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
        };

        if l7_config.tls == crate::l7::TlsMode::Terminate {
            // TLS termination: MITM decrypt, inspect, re-encrypt
            if let Some(ref tls) = tls_state {
                let l7_result = async {
                    let mut tls_client =
                        crate::l7::tls::tls_terminate_client(client, tls, &host_lc).await?;
                    let mut tls_upstream = crate::l7::tls::tls_connect_upstream(
                        upstream,
                        &host_lc,
                        tls.upstream_config(),
                    )
                    .await?;
                    // No protocol detection needed — ALPN proves HTTP
                    crate::l7::relay::relay_with_inspection(
                        &l7_config,
                        std::sync::Mutex::new(tunnel_engine),
                        &mut tls_client,
                        &mut tls_upstream,
                        &ctx,
                    )
                    .await
                };
                if let Err(e) = l7_result.await {
                    if is_benign_relay_error(&e) {
                        debug!(
                            host = %host_lc,
                            port = port,
                            error = %e,
                            "TLS L7 connection closed"
                        );
                    } else {
                        warn!(
                            host = %host_lc,
                            port = port,
                            error = %e,
                            "TLS L7 relay error"
                        );
                    }
                }
            } else {
                warn!(
                    host = %host_lc,
                    port = port,
                    "TLS termination requested but TLS state not configured, falling back to L4"
                );
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .into_diagnostic()?;
            }
        } else {
            // Plaintext: protocol detection via peek on raw TcpStream
            if l7_config.protocol == crate::l7::L7Protocol::Rest {
                let mut peek_buf = [0u8; 8];
                let n = client.peek(&mut peek_buf).await.into_diagnostic()?;
                if n == 0 {
                    return Ok(());
                }
                if !crate::l7::rest::looks_like_http(&peek_buf[..n]) {
                    warn!(
                        host = %host_lc,
                        port = port,
                        policy = %ctx.policy_name,
                        "Expected REST protocol but received non-matching bytes. Connection rejected."
                    );
                    return Err(miette::miette!(
                        "Protocol mismatch: expected HTTP but received non-HTTP bytes"
                    ));
                }
            }
            if let Err(e) = crate::l7::relay::relay_with_inspection(
                &l7_config,
                std::sync::Mutex::new(tunnel_engine),
                &mut client,
                &mut upstream,
                &ctx,
            )
            .await
            {
                if is_benign_relay_error(&e) {
                    debug!(
                        host = %host_lc,
                        port = port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    warn!(
                        host = %host_lc,
                        port = port,
                        error = %e,
                        "L7 relay error"
                    );
                }
            }
        }
        return Ok(());
    }

    // L4-only: raw bidirectional copy (existing behavior)
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .into_diagnostic()?;

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

    let pid = entrypoint_pid.load(Ordering::Acquire);
    if pid == 0 {
        return ConnectDecision {
            allowed: false,
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
            matched_policy: None,
            engine: "opa",
            reason: "entrypoint process not yet spawned".into(),
        };
    }

    let peer_port = peer_addr.port();
    let (bin_path, binary_pid) = match crate::procfs::resolve_tcp_peer_identity(pid, peer_port) {
        Ok(r) => r,
        Err(e) => {
            return ConnectDecision {
                allowed: false,
                binary: None,
                binary_pid: None,
                ancestors: vec![],
                cmdline_paths: vec![],
                matched_policy: None,
                engine: "opa",
                reason: format!("failed to resolve peer binary: {e}"),
            };
        }
    };

    // TOFU verify the immediate binary
    let bin_hash = match identity_cache.verify_or_cache(&bin_path) {
        Ok(h) => h,
        Err(e) => {
            return ConnectDecision {
                allowed: false,
                binary: Some(bin_path),
                binary_pid: Some(binary_pid),
                ancestors: vec![],
                cmdline_paths: vec![],
                matched_policy: None,
                engine: "opa",
                reason: format!("binary integrity check failed: {e}"),
            };
        }
    };

    // Walk the process tree upward to collect ancestor binaries
    let ancestors = crate::procfs::collect_ancestor_binaries(binary_pid, pid);

    // TOFU verify each ancestor binary
    for ancestor in &ancestors {
        if let Err(e) = identity_cache.verify_or_cache(ancestor) {
            return ConnectDecision {
                allowed: false,
                binary: Some(bin_path),
                binary_pid: Some(binary_pid),
                ancestors: ancestors.clone(),
                cmdline_paths: vec![],
                matched_policy: None,
                engine: "opa",
                reason: format!(
                    "ancestor integrity check failed for {}: {e}",
                    ancestor.display()
                ),
            };
        }
    }

    // Collect cmdline paths for script-based binary detection.
    // Excludes exe paths already captured in bin_path/ancestors to avoid duplicates.
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

    match engine.evaluate_network(&input) {
        Ok(decision) => ConnectDecision {
            allowed: decision.allowed,
            binary: Some(bin_path),
            binary_pid: Some(binary_pid),
            ancestors,
            cmdline_paths,
            matched_policy: decision.matched_policy,
            engine: "opa",
            reason: decision.reason,
        },
        Err(e) => ConnectDecision {
            allowed: false,
            binary: Some(bin_path),
            binary_pid: Some(binary_pid),
            ancestors,
            cmdline_paths,
            matched_policy: None,
            engine: "opa",
            reason: format!("policy evaluation error: {e}"),
        },
    }
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
        allowed: false,
        binary: None,
        binary_pid: None,
        ancestors: vec![],
        cmdline_paths: vec![],
        matched_policy: None,
        engine: "opa",
        reason: "identity binding unavailable on this platform".into(),
    }
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
    // Only query if L4 allowed and we have a matched policy
    if !decision.allowed || decision.matched_policy.is_none() {
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
            warn!(error = %e, "Failed to query L7 endpoint config");
            None
        }
    }
}

/// Check if an IP address is internal (loopback, private RFC1918, or link-local).
///
/// This is a defense-in-depth check to prevent SSRF via the CONNECT proxy.
/// It covers:
/// - IPv4 loopback (127.0.0.0/8), private (10/8, 172.16/12, 192.168/16), link-local (169.254/16)
/// - IPv6 loopback (`::1`), link-local (`fe80::/10`)
/// - IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unwrapped and checked as IPv4
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            // fe80::/10 — IPv6 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            false
        }
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
    fn test_rejects_ipv6_link_local() {
        // fe80::1
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
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
}
