//! HTTP CONNECT proxy with OPA policy evaluation and process-identity binding.

use crate::identity::BinaryIdentityCache;
use crate::opa::OpaEngine;
use crate::policy::ProxyPolicy;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{info, warn};

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
    /// Deny reason or error context.
    reason: String,
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
    /// via `/proc/net/tcp`.
    pub async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
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

        let join = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let opa = opa_engine.clone();
                        let cache = identity_cache.clone();
                        let spid = entrypoint_pid.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_tcp_connection(stream, opa, cache, spid).await
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

    // Evaluate OPA policy
    let decision = evaluate_opa_tcp(
        peer_addr,
        &opa_engine,
        &identity_cache,
        &entrypoint_pid,
        &host_lc,
        port,
    );

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
        engine = "opa",
        policy = %policy_str,
        reason = %decision.reason,
        "CONNECT",
    );

    if !decision.allowed {
        respond(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    let mut upstream = TcpStream::connect((host.as_str(), port))
        .await
        .into_diagnostic()?;

    respond(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

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
            reason: decision.reason,
        },
        Err(e) => ConnectDecision {
            allowed: false,
            binary: Some(bin_path),
            binary_pid: Some(binary_pid),
            ancestors,
            cmdline_paths,
            matched_policy: None,
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
        reason: "identity binding unavailable on this platform".into(),
    }
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
