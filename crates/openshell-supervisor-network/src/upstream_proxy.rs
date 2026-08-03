// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Upstream corporate proxy chaining for the sandbox egress proxy.
//!
//! In proxy-required enterprise networks (issue #1792) the supervisor cannot
//! dial policy-approved destinations directly: all outbound traffic must go
//! through a corporate forward proxy. The operator-owned proxy configuration
//! reaches the supervisor as command-line arguments ([`UpstreamProxyArgs`])
//! that the compute driver sets when it launches the supervisor — never
//! through the environment, which sandbox images could bake `ENV` values
//! into — and this module chains approved TLS tunnels through the corporate
//! proxy with HTTP CONNECT.
//!
//! Only TLS (CONNECT) egress is chained: plain-HTTP requests always dial the
//! destination directly. Forwarding plain HTTP through a corporate proxy
//! requires absolute-form request forwarding rather than CONNECT tunneling
//! and is out of scope for this feature.
//!
//! The conventional `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`
//! variables are intentionally ignored: those are controlled by the sandbox
//! creator and are rewritten separately to point the workload child at the
//! local policy proxy, so honoring them would let a sandbox pick an arbitrary
//! upstream proxy or disable proxying with `NO_PROXY=*`.
//!
//! Scope and invariants:
//! - Only `http://` proxy URLs are supported. Configuration is fail-closed:
//!   any present-but-invalid driver-supplied setting — an empty argument
//!   value, an unsupported (`https://`, SOCKS) or malformed proxy URL, an
//!   unreadable auth file, a malformed credential, or an auth file without the explicit
//!   cleartext-credential acknowledgement — is a fatal startup error rather
//!   than being silently ignored, so a typo can never quietly downgrade the
//!   operator's egress boundary to direct dialing or unauthenticated proxy
//!   access. Validation semantics are shared with the compute driver via
//!   [`openshell_core::driver_utils::parse_upstream_proxy_url`] and
//!   [`openshell_core::driver_utils::parse_upstream_proxy_credential`].
//! - Policy evaluation, DNS resolution, and SSRF checks run exactly as in the
//!   direct-dial path; the corporate proxy only replaces the final TCP dial.
//! - CONNECT requests target a validated resolved address by default, so the
//!   proxy performs no DNS resolution and the tunnel stays bound to the
//!   answer that passed SSRF/`allowed_ips` validation. The
//!   `--upstream-proxy-connect-by-hostname` opt-in sends the hostname
//!   instead, for proxies whose ACLs filter on hostnames.
//! - The operator `NO_PROXY` list decides which destinations bypass the
//!   corporate proxy and keep dialing directly (cluster-internal services,
//!   host gateway, etc.). Loopback destinations always bypass the proxy.

use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

/// Upper bound on the corporate proxy's CONNECT response header block.
const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;

/// End-to-end budget for dialing the corporate proxy and completing the
/// CONNECT handshake.
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed corporate proxy endpoint.
#[derive(Clone)]
pub struct ProxyEndpoint {
    host: String,
    port: u16,
    /// Pre-computed `Basic <base64>` header value from the proxy auth file.
    /// Never logged.
    proxy_authorization: Option<String>,
}

impl ProxyEndpoint {
    /// `host:port` label for logs. Excludes credentials.
    #[must_use]
    pub fn display_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("proxy_authorization", &self.proxy_authorization.is_some())
            .finish()
    }
}

/// The pattern half of one parsed `NO_PROXY` entry.
#[derive(Debug, Clone)]
enum NoProxyPattern {
    /// `*` — bypass the proxy for every destination.
    Wildcard,
    /// Domain suffix match: `corp.com` matches `corp.com` and `x.corp.com`.
    Domain(String),
    /// Exact IP match, against an IP-literal host or its resolved addresses.
    Ip(IpAddr),
    /// CIDR match, against an IP-literal host or its resolved addresses.
    Cidr(ipnet::IpNet),
}

/// One parsed `NO_PROXY` entry.
#[derive(Debug, Clone)]
struct NoProxyEntry {
    pattern: NoProxyPattern,
    /// When set (`internal.corp:8443`), the entry only applies to this
    /// destination port instead of every port.
    port: Option<u16>,
}

/// Parsed `NO_PROXY` list.
#[derive(Debug, Clone, Default)]
struct NoProxy {
    entries: Vec<NoProxyEntry>,
}

impl NoProxy {
    fn parse(raw: &str) -> Self {
        let mut entries = Vec::new();
        for item in raw.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if item == "*" {
                entries.push(NoProxyEntry {
                    pattern: NoProxyPattern::Wildcard,
                    port: None,
                });
                continue;
            }
            // Whole-item IP/CIDR forms first: a bare IPv6 literal contains
            // colons that must never be misread as a port qualifier.
            if let Ok(net) = item.parse::<ipnet::IpNet>() {
                entries.push(NoProxyEntry {
                    pattern: NoProxyPattern::Cidr(net),
                    port: None,
                });
                continue;
            }
            if let Ok(ip) = item.trim_matches(['[', ']']).parse::<IpAddr>() {
                entries.push(NoProxyEntry {
                    pattern: NoProxyPattern::Ip(ip),
                    port: None,
                });
                continue;
            }
            // Optional `:port` qualifier: only a valid trailing u16 counts;
            // anything else stays part of the pattern.
            let (head, port) = item
                .rsplit_once(':')
                .map_or((item, None), |(head, port_str)| {
                    port_str
                        .parse::<u16>()
                        .map_or((item, None), |port| (head, Some(port)))
                });
            let pattern = if let Ok(net) = head.parse::<ipnet::IpNet>() {
                NoProxyPattern::Cidr(net)
            } else if let Ok(ip) = head.trim_matches(['[', ']']).parse::<IpAddr>() {
                NoProxyPattern::Ip(ip)
            } else {
                // Domain entry. Strip any leading `*.` or `.` so
                // `.corp.com`, `*.corp.com`, and `corp.com` all behave
                // identically.
                let name = head
                    .strip_prefix("*.")
                    .or_else(|| head.strip_prefix('.'))
                    .unwrap_or(head)
                    .to_ascii_lowercase();
                if name.is_empty() {
                    continue;
                }
                NoProxyPattern::Domain(name)
            };
            entries.push(NoProxyEntry { pattern, port });
        }
        Self { entries }
    }

    /// The validated addresses that may be dialed directly for
    /// `(host, port)`, or `None` when no entry matches and the corporate
    /// proxy must be used.
    ///
    /// Hostname-level matches — `*`, a domain entry, or an IP/CIDR entry
    /// matching an IP-literal host — authorize every validated address.
    /// IP/CIDR entries match hostnames through their *resolved* addresses and
    /// authorize only the addresses they contain, so a bypass scoped to an
    /// internal range can never widen into a direct dial of an address
    /// outside that range.
    ///
    /// The automatic loopback bypass is derived from resolved addresses, never
    /// from the host string: `resolved` may come from the sandbox's own
    /// `/etc/hosts` (see `resolve_socket_addrs`), which the workload controls,
    /// so treating the name `localhost` as proof of loopback would let a
    /// spoofed mapping dial a policy-allowed public address while escaping the
    /// operator proxy. A spoofed `localhost` falls through to the entries below
    /// and is proxied unless an explicit `NO_PROXY` entry matches.
    fn direct_addrs(
        &self,
        host: &str,
        port: u16,
        resolved: &[SocketAddr],
    ) -> Option<Vec<SocketAddr>> {
        let host_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
        if let Some(ip) = host_ip {
            // An IP literal is its own destination, so the host string is
            // authoritative here.
            if ip.is_loopback() {
                return Some(resolved.to_vec());
            }
        } else if host == "localhost"
            && !resolved.is_empty()
            && resolved.iter().all(|addr| addr.ip().is_loopback())
        {
            return Some(resolved.to_vec());
        }
        let mut subset: Vec<SocketAddr> = Vec::new();
        for entry in &self.entries {
            if entry.port.is_some_and(|entry_port| entry_port != port) {
                continue;
            }
            match &entry.pattern {
                NoProxyPattern::Wildcard => return Some(resolved.to_vec()),
                NoProxyPattern::Domain(suffix) => {
                    if host == suffix
                        || host
                            .strip_suffix(suffix)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                    {
                        return Some(resolved.to_vec());
                    }
                }
                NoProxyPattern::Ip(ip) => {
                    if host_ip == Some(*ip) {
                        return Some(resolved.to_vec());
                    }
                    for addr in resolved {
                        if addr.ip() == *ip && !subset.contains(addr) {
                            subset.push(*addr);
                        }
                    }
                }
                NoProxyPattern::Cidr(net) => {
                    if host_ip.is_some_and(|ip| net.contains(&ip)) {
                        return Some(resolved.to_vec());
                    }
                    for addr in resolved {
                        if net.contains(&addr.ip()) && !subset.contains(addr) {
                            subset.push(*addr);
                        }
                    }
                }
            }
        }
        if subset.is_empty() {
            None
        } else {
            Some(subset)
        }
    }
}

/// How a validated destination must be dialed, per the operator `NO_PROXY`
/// contract. Produced by [`UpstreamProxyConfig::decision`].
#[derive(Debug)]
pub enum ProxyDecision<'a> {
    /// Chain through the corporate proxy with HTTP CONNECT.
    Proxy(&'a ProxyEndpoint),
    /// Dial directly, restricted to this subset of the validated addresses:
    /// all of them for hostname-level matches (loopback, `*`, domain
    /// entries, IP-literal hosts), only the addresses contained in the
    /// matching IP/CIDR entries otherwise.
    Direct(Vec<SocketAddr>),
}

/// What the supervisor puts in the CONNECT request line sent to the
/// corporate proxy.
#[derive(Debug, Clone, Copy)]
pub enum ConnectTarget {
    /// CONNECT to this validated address; the proxy performs no DNS
    /// resolution, so the tunnel is bound to the answer that already passed
    /// SSRF and `allowed_ips` validation. The destination hostname still
    /// travels inside the tunnel (TLS SNI, application `Host`).
    Ip(IpAddr),
    /// CONNECT by hostname; the proxy resolves the name itself. Operator
    /// opt-in for hostname-filtering proxy ACLs
    /// (`--upstream-proxy-connect-by-hostname`).
    Hostname,
}

/// Corporate proxy configuration built from the driver-supplied
/// command-line arguments ([`UpstreamProxyArgs`]).
#[derive(Debug, Clone)]
pub struct UpstreamProxyConfig {
    https: ProxyEndpoint,
    no_proxy: NoProxy,
    connect_by_hostname: bool,
}

/// Operator-owned corporate proxy settings passed to the supervisor as
/// command-line arguments by the compute driver.
///
/// Argv is set by the driver when it creates the container/VM and cannot be
/// influenced by sandbox environment or image `ENV`, so a field left `None`
/// / `false` genuinely means "not configured by the operator".
#[derive(Debug, Clone, Default)]
pub struct UpstreamProxyArgs {
    /// `http://host:port` corporate proxy URL, or `None` for direct egress.
    pub https_proxy: Option<String>,
    /// Comma-separated `NO_PROXY` list.
    pub no_proxy: Option<String>,
    /// Path to the root-only credential mount (`user:pass`).
    pub proxy_auth_file: Option<String>,
    /// Operator acknowledgement that credentials travel as cleartext Basic
    /// auth over the plain-TCP proxy connection.
    pub proxy_auth_allow_insecure: bool,
    /// Send the destination hostname in CONNECT instead of a validated IP.
    pub proxy_connect_by_hostname: bool,
}

// Supervisor CLI flag names for the corporate-proxy settings, used as the
// dispatch keys in `from_lookup` and in operator-facing error messages.
const ARG_HTTPS_PROXY: &str = "--upstream-proxy";
const ARG_NO_PROXY: &str = "--upstream-no-proxy";
const ARG_PROXY_AUTH_FILE: &str = "--upstream-proxy-auth-file";
const ARG_PROXY_AUTH_ALLOW_INSECURE: &str = "--upstream-proxy-auth-allow-insecure";
const ARG_PROXY_CONNECT_BY_HOSTNAME: &str = "--upstream-proxy-connect-by-hostname";

impl UpstreamProxyConfig {
    /// Build the corporate proxy configuration from the driver-supplied
    /// command-line [`UpstreamProxyArgs`]. Returns `Ok(None)` when no proxy
    /// is configured.
    ///
    /// The conventional `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` /
    /// `NO_PROXY` environment variables are intentionally never consulted:
    /// they are controlled by the sandbox creator (and rewritten to point
    /// workload children at the local policy proxy), so honoring them would
    /// let a sandbox choose an arbitrary upstream proxy or disable proxying
    /// entirely.
    ///
    /// # Errors
    ///
    /// This is an operator-owned security boundary, so a present-but-invalid
    /// value is fatal instead of being treated as unset: an empty (or
    /// whitespace-only) argument, an invalid or unsupported proxy URL, an
    /// auth file that is set but unreadable or holds a malformed credential,
    /// an auth file without the cleartext-credential acknowledgement, or an
    /// auth file / `NO_PROXY` list / acknowledgement / connect-by-hostname
    /// flag with no proxy configured. Failing closed prevents a
    /// misconfiguration from silently degrading to direct dialing or
    /// unauthenticated proxy access.
    pub fn from_args(args: &UpstreamProxyArgs) -> Result<Option<Self>, String> {
        // Present the typed argv fields under their canonical identifiers so
        // the shared validation runs once. Booleans map to Some("true") /
        // None, so every pairing rule (auth file needs the acknowledgement,
        // no auxiliary setting without a proxy) applies unchanged.
        Self::from_lookup(|name| {
            if name == ARG_HTTPS_PROXY {
                args.https_proxy.clone()
            } else if name == ARG_NO_PROXY {
                args.no_proxy.clone()
            } else if name == ARG_PROXY_AUTH_FILE {
                args.proxy_auth_file.clone()
            } else if name == ARG_PROXY_AUTH_ALLOW_INSECURE {
                args.proxy_auth_allow_insecure.then(|| "true".to_string())
            } else if name == ARG_PROXY_CONNECT_BY_HOSTNAME {
                args.proxy_connect_by_hostname.then(|| "true".to_string())
            } else {
                None
            }
        })
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        // A missing setting means "not configured". A present-but-empty value
        // is a misconfiguration (the driver never emits one), so it is fatal
        // rather than silently downgrading the boundary to direct dialing or
        // unauthenticated proxy access.
        let var = |name: &str| -> Result<Option<String>, String> {
            match lookup(name) {
                None => Ok(None),
                Some(value) if value.trim().is_empty() => {
                    Err(format!("{name} must not be empty when set"))
                }
                Some(value) => Ok(Some(value)),
            }
        };
        let https = var(ARG_HTTPS_PROXY)?
            .map(|url| parse_proxy_url(&url, ARG_HTTPS_PROXY))
            .transpose()?;
        let auth_file = var(ARG_PROXY_AUTH_FILE)?;
        let auth_allow_insecure = var(ARG_PROXY_AUTH_ALLOW_INSECURE)?;
        let connect_by_hostname_raw = var(ARG_PROXY_CONNECT_BY_HOSTNAME)?;
        let no_proxy_list = var(ARG_NO_PROXY)?;
        let Some(mut https) = https else {
            // Auxiliary proxy settings without a proxy mean the operator
            // believed a proxy boundary was in effect; refuse rather than
            // silently running with direct egress.
            for (name, value) in [
                (ARG_PROXY_AUTH_FILE, &auth_file),
                (ARG_PROXY_AUTH_ALLOW_INSECURE, &auth_allow_insecure),
                (ARG_PROXY_CONNECT_BY_HOSTNAME, &connect_by_hostname_raw),
                (ARG_NO_PROXY, &no_proxy_list),
            ] {
                if value.is_some() {
                    return Err(format!("{name} is set but no upstream proxy is configured"));
                }
            }
            return Ok(None);
        };

        // CONNECT-target mode. The default binds the tunnel to a validated
        // address; hostname CONNECT re-opens proxy-side DNS resolution and
        // is only honored as the exact opt-in value the driver writes.
        let connect_by_hostname = match connect_by_hostname_raw.as_deref().map(str::trim) {
            None => false,
            Some("true") => true,
            Some(_) => {
                return Err(format!(
                    "{ARG_PROXY_CONNECT_BY_HOSTNAME} must be 'true' when set"
                ));
            }
        };

        // Cleartext-credential acknowledgement. `Proxy-Authorization: Basic`
        // travels over plain TCP to the http:// proxy, so credentials are
        // only sent when the operator explicitly opted in. The compute driver
        // enforces the same pairing at sandbox-create time; enforcing it here
        // as well keeps the supervisor fail-closed against a bypassed or
        // foreign driver.
        let allow_insecure = match auth_allow_insecure.as_deref().map(str::trim) {
            None => false,
            Some("true") => true,
            Some(_) => {
                return Err(format!(
                    "{ARG_PROXY_AUTH_ALLOW_INSECURE} must be 'true' when set"
                ));
            }
        };
        if auth_file.is_none() && auth_allow_insecure.is_some() {
            return Err(format!(
                "{ARG_PROXY_AUTH_ALLOW_INSECURE} is set but no {ARG_PROXY_AUTH_FILE} is configured"
            ));
        }
        if auth_file.is_some() && !allow_insecure {
            return Err(format!(
                "{ARG_PROXY_AUTH_FILE} sends the credential as cleartext Basic auth \
                 over the plain-TCP proxy connection; refusing without \
                 {ARG_PROXY_AUTH_ALLOW_INSECURE}"
            ));
        }

        // Load proxy credentials from the configured auth file, if any.
        // The file is delivered through a root-only secret mount so the
        // credentials never appear in the environment or container metadata.
        if let Some(path) = auth_file {
            let credential =
                openshell_core::driver_utils::read_upstream_proxy_credential_file(&path)?;
            let header = basic_auth_header(&credential).map_err(|err| {
                format!("invalid credential in upstream proxy auth file '{path}': {err}")
            })?;
            https.proxy_authorization = Some(header);
        }

        Ok(Some(Self {
            https,
            no_proxy: NoProxy::parse(&no_proxy_list.unwrap_or_default()),
            connect_by_hostname,
        }))
    }

    /// Whether CONNECT requests carry the destination hostname instead of a
    /// validated IP (operator opt-in for hostname-filtering proxy ACLs).
    #[must_use]
    pub fn connect_by_hostname(&self) -> bool {
        self.connect_by_hostname
    }

    /// How to dial the validated destination `(host, port, resolved)`,
    /// honoring the operator `NO_PROXY` list.
    ///
    /// Entries may carry a `:port` qualifier that limits them to that
    /// destination port. IP/CIDR entries also match a hostname through its
    /// already-validated resolved addresses; such a match authorizes a
    /// direct dial of only the addresses inside the entry (see
    /// [`ProxyDecision::Direct`]).
    #[must_use]
    pub fn decision<'a>(
        &'a self,
        host: &str,
        port: u16,
        resolved: &[SocketAddr],
    ) -> ProxyDecision<'a> {
        self.no_proxy
            .direct_addrs(host, port, resolved)
            .map_or(ProxyDecision::Proxy(&self.https), ProxyDecision::Direct)
    }

    /// Credential-free summary for startup logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "https_proxy={} no_proxy_entries={} connect_target={}",
            self.https.display_addr(),
            self.no_proxy.entries.len(),
            if self.connect_by_hostname {
                "hostname"
            } else {
                "validated-ip"
            }
        )
    }
}

/// Parse an `http://host:port` proxy URL with the same validation rules the
/// compute driver applies at sandbox-create time
/// ([`parse_upstream_proxy_url`](openshell_core::driver_utils::parse_upstream_proxy_url)).
///
/// Credentials are never taken from the URL: they are delivered out of band
/// through the root-only auth-file mount (`--upstream-proxy-auth-file`) so
/// they never appear in config or container metadata.
///
/// # Errors
///
/// Rejects unsupported schemes (TLS or SOCKS proxies), inline `user:pass@`
/// credentials, and malformed addresses. The error names `var_name` so the
/// operator can locate the offending setting.
fn parse_proxy_url(raw: &str, var_name: &str) -> Result<ProxyEndpoint, String> {
    let addr = openshell_core::driver_utils::parse_upstream_proxy_url(raw)
        .map_err(|err| format!("{var_name} is invalid: {err}"))?;
    Ok(ProxyEndpoint {
        host: addr.host,
        port: addr.port,
        proxy_authorization: None,
    })
}

/// Build a `Proxy-Authorization: Basic <base64>` header value from a raw
/// `user:pass` credential.
///
/// The credential is used verbatim after trimming: it is delivered through a
/// trusted operator file, not a URL, so there is no percent-encoding to
/// decode. Validation is shared with the compute driver through
/// [`parse_upstream_proxy_credential`](openshell_core::driver_utils::parse_upstream_proxy_credential),
/// so a credential the driver staged at sandbox-create time is never rejected
/// here.
///
/// # Errors
///
/// Rejects an empty credential, one containing control characters that could
/// inject additional HTTP headers, and one not in `user:pass` form. Error
/// messages never include the credential content.
fn basic_auth_header(credential: &str) -> Result<String, String> {
    let credential = openshell_core::driver_utils::parse_upstream_proxy_credential(credential)
        .map_err(|err| err.to_string())?;
    Ok(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credential)
    ))
}

/// A `TcpStream` that first replays bytes already read from the socket.
///
/// The CONNECT handshake reads from the proxy socket in chunks, so the read
/// that completes the response header block may also contain the first
/// tunneled payload bytes (a server-speaks-first destination, or a proxy
/// that coalesces writes). Those bytes belong to the destination byte
/// stream and must reach the caller rather than being discarded; this
/// wrapper yields them before reading from the socket again. Writes pass
/// straight through.
#[derive(Debug)]
pub struct PrefixedStream {
    inner: TcpStream,
    /// Bytes read past the CONNECT header terminator, replayed first.
    prefix: Vec<u8>,
    /// Read offset into `prefix`.
    pos: usize,
}

impl PrefixedStream {
    /// Wrap `inner`, replaying `prefix` before socket reads.
    #[must_use]
    pub fn new(inner: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }

    /// Wrap a directly dialed stream with nothing to replay.
    #[must_use]
    pub fn without_prefix(inner: TcpStream) -> Self {
        Self::new(inner, Vec::new())
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.pos);
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                // Drained: release the buffer instead of holding it for the
                // tunnel's lifetime.
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Open a tunnel to the destination through the corporate proxy with HTTP
/// CONNECT.
///
/// Returns the connected stream once the proxy answers 200; after that the
/// stream is a transparent byte pipe to the destination. Any tunneled bytes
/// received in the same read as the CONNECT response are preserved and
/// replayed by the returned [`PrefixedStream`].
///
/// `target` selects the CONNECT request target. The default mode sends a
/// validated IP ([`ConnectTarget::Ip`]) so the proxy performs no DNS
/// resolution and the tunnel is bound to an address that already passed
/// SSRF and `allowed_ips` validation; `host` then only labels logs and is
/// used by the caller for TLS SNI inside the tunnel. With the operator
/// opt-in ([`ConnectTarget::Hostname`]) the hostname is sent instead so
/// hostname-filtering proxy ACLs keep working, at the cost of proxy-side
/// resolution. Local DNS resolution and SSRF validation must already have
/// happened at the call site in both modes.
///
/// # Errors
///
/// Returns an error when the proxy is unreachable, the handshake times out,
/// or the proxy answers with a non-200 status.
pub async fn connect_via(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
    target: ConnectTarget,
) -> std::io::Result<PrefixedStream> {
    tokio::time::timeout(
        CONNECT_HANDSHAKE_TIMEOUT,
        connect_via_inner(endpoint, host, port, target),
    )
    .await
    .map_err(|_| {
        IoError::new(
            ErrorKind::TimedOut,
            format!(
                "upstream proxy {} CONNECT handshake timed out",
                endpoint.display_addr()
            ),
        )
    })?
}

/// Open a validated-IP CONNECT tunnel, trying each validated address in
/// order until one succeeds.
///
/// The direct-dial path hands `TcpStream::connect` the whole validated list
/// and it falls back across addresses; this is the proxied equivalent, so a
/// dual-stack destination whose first validated address is unreachable
/// through the corporate proxy still connects via a later one. All attempts
/// share one aggregate handshake budget ([`CONNECT_HANDSHAKE_TIMEOUT`]),
/// matching the single-attempt paths; within it, each attempt is capped at
/// its fair share of the remaining time (`remaining / attempts_left`) so a
/// proxy that accepts a CONNECT but never answers cannot starve the
/// remaining validated addresses. Time an attempt fails without using
/// rolls over to later attempts.
///
/// # Errors
///
/// Returns an error when `addrs` is empty, or when every attempt fails or
/// times out (the last attempt's error, annotated with the attempt count
/// when there were several).
pub async fn connect_via_validated(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
) -> std::io::Result<PrefixedStream> {
    connect_via_validated_with_budget(endpoint, host, port, addrs, CONNECT_HANDSHAKE_TIMEOUT).await
}

/// [`connect_via_validated`] with an explicit aggregate budget, split out so
/// tests can exercise the hang-fallback behavior without real 30s waits.
async fn connect_via_validated_with_budget(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    budget: Duration,
) -> std::io::Result<PrefixedStream> {
    if addrs.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("no validated addresses to CONNECT to for {host}"),
        ));
    }
    let deadline = tokio::time::Instant::now() + budget;
    let mut last_err = None;
    let mut attempted = 0usize;
    for (index, addr) in addrs.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempts_left = u32::try_from(addrs.len() - index).unwrap_or(u32::MAX);
        let attempt_budget = remaining / attempts_left;
        attempted += 1;
        match tokio::time::timeout(
            attempt_budget,
            connect_via_inner(endpoint, host, port, ConnectTarget::Ip(addr.ip())),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => {
                last_err = Some(IoError::new(
                    ErrorKind::TimedOut,
                    format!(
                        "upstream proxy {} CONNECT to {} timed out",
                        endpoint.display_addr(),
                        addr.ip(),
                    ),
                ));
            }
        }
    }
    // The first iteration always runs (`remaining` starts at the full
    // budget), so at least one attempt recorded an error.
    let last = last_err.expect("at least one CONNECT attempt");
    if addrs.len() == 1 {
        return Err(last);
    }
    let scope = if attempted == addrs.len() {
        format!("all {} validated addresses", addrs.len())
    } else {
        format!(
            "{attempted} of {} validated addresses (handshake budget exhausted)",
            addrs.len()
        )
    };
    Err(IoError::new(
        last.kind(),
        format!("CONNECT failed for {scope} of {host}; last: {last}"),
    ))
}

async fn connect_via_inner(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
    target: ConnectTarget,
) -> std::io::Result<PrefixedStream> {
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;

    let target = match target {
        ConnectTarget::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        ConnectTarget::Ip(ip) => format!("{ip}:{port}"),
        ConnectTarget::Hostname if host.contains(':') => format!("[{host}]:{port}"),
        ConnectTarget::Hostname => format!("{host}:{port}"),
    };
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = &endpoint.proxy_authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read the proxy's response header block. A read may run past the
    // `\r\n\r\n` terminator into tunneled payload; those bytes are preserved
    // below, never discarded.
    let mut buf = vec![0u8; MAX_CONNECT_RESPONSE_BYTES];
    let mut used = 0;
    let header_end = loop {
        if used == buf.len() {
            return Err(IoError::other(format!(
                "upstream proxy {} CONNECT response headers exceed {MAX_CONNECT_RESPONSE_BYTES} bytes",
                endpoint.display_addr()
            )));
        }
        let n = stream.read(&mut buf[used..]).await?;
        if n == 0 {
            return Err(IoError::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "upstream proxy {} closed the connection during CONNECT",
                    endpoint.display_addr()
                ),
            ));
        }
        used += n;
        if let Some(pos) = buf[..used].windows(4).position(|win| win == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let response = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = response.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    match status_code {
        Some(200) => {
            debug!(
                proxy = %endpoint.display_addr(),
                target = %target,
                "upstream proxy CONNECT tunnel established"
            );
            buf.truncate(used);
            let overflow = buf.split_off(header_end);
            Ok(PrefixedStream::new(stream, overflow))
        }
        Some(code) => Err(IoError::other(format!(
            "upstream proxy {} refused CONNECT to {target}: HTTP {code}",
            endpoint.display_addr()
        ))),
        None => Err(IoError::new(
            ErrorKind::InvalidData,
            format!(
                "upstream proxy {} sent a malformed CONNECT response",
                endpoint.display_addr()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        ARG_HTTPS_PROXY as HTTPS_PROXY, ARG_NO_PROXY as NO_PROXY,
        ARG_PROXY_AUTH_ALLOW_INSECURE as PROXY_AUTH_ALLOW_INSECURE,
        ARG_PROXY_AUTH_FILE as PROXY_AUTH_FILE,
        ARG_PROXY_CONNECT_BY_HOSTNAME as PROXY_CONNECT_BY_HOSTNAME,
    };

    fn config_from(pairs: &[(&str, &str)]) -> Result<Option<UpstreamProxyConfig>, String> {
        UpstreamProxyConfig::from_lookup(|name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        })
    }

    /// Shorthand for tests exercising a configuration that must load.
    fn config_ok(pairs: &[(&str, &str)]) -> UpstreamProxyConfig {
        config_from(pairs).unwrap().unwrap()
    }

    #[test]
    fn no_env_yields_none() {
        assert!(config_from(&[]).unwrap().is_none());
    }

    #[test]
    fn from_args_maps_cli_arguments_to_config() {
        // The driver-supplied argv is the authoritative source; the shared
        // validation applies to it exactly as in the flag-keyed lookup.
        let args = UpstreamProxyArgs {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            no_proxy: Some("*.svc.cluster.local".to_string()),
            proxy_connect_by_hostname: true,
            ..UpstreamProxyArgs::default()
        };
        let cfg = UpstreamProxyConfig::from_args(&args).unwrap().unwrap();
        assert!(cfg.connect_by_hostname());
        assert!(bypasses(&cfg, "kubernetes.default.svc.cluster.local"));

        // No proxy URL means no configuration.
        assert!(
            UpstreamProxyConfig::from_args(&UpstreamProxyArgs::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn from_args_enforces_the_auth_file_acknowledgement_pairing() {
        // An auth file without the acknowledgement is fatal, exactly as in
        // the flag-keyed lookup the driver validation mirrors.
        let args = UpstreamProxyArgs {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            proxy_auth_file: Some("/etc/openshell/auth/upstream-proxy".to_string()),
            ..UpstreamProxyArgs::default()
        };
        let err = UpstreamProxyConfig::from_args(&args).unwrap_err();
        assert!(err.contains(PROXY_AUTH_ALLOW_INSECURE), "{err}");

        // Auxiliary settings without a proxy are fatal.
        let args = UpstreamProxyArgs {
            proxy_connect_by_hostname: true,
            ..UpstreamProxyArgs::default()
        };
        let err = UpstreamProxyConfig::from_args(&args).unwrap_err();
        assert!(err.contains("no upstream proxy"), "{err}");
    }

    #[test]
    fn conventional_proxy_vars_are_ignored() {
        // The sandbox creator controls these names; they must not steer the
        // supervisor's operator-owned egress boundary.
        assert!(
            config_from(&[
                ("HTTPS_PROXY", "http://attacker:9999"),
                ("HTTP_PROXY", "http://attacker:9999"),
                ("ALL_PROXY", "http://attacker:9999"),
                ("https_proxy", "http://attacker:9999"),
            ])
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn present_but_empty_values_are_fatal() {
        // A setting the operator did not configure is absent, never empty:
        // the driver only passes configured values. A present-but-blank
        // value is therefore a misconfiguration and must not silently mean
        // "no proxy".
        for (name, value) in [
            (HTTPS_PROXY, ""),
            (HTTPS_PROXY, "  "),
            (NO_PROXY, " "),
            (PROXY_AUTH_FILE, ""),
            (PROXY_AUTH_ALLOW_INSECURE, ""),
        ] {
            let err = config_from(&[(name, value)]).unwrap_err();
            assert!(err.contains(name), "{err}");
            assert!(err.contains("empty"), "{err}");
        }
    }

    /// Shorthand: the proxy endpoint chosen for `host:443` with no resolved
    /// addresses in play, or `None` when the destination dials directly.
    fn proxy_endpoint<'a>(cfg: &'a UpstreamProxyConfig, host: &str) -> Option<&'a ProxyEndpoint> {
        match cfg.decision(host, 443, &[]) {
            ProxyDecision::Proxy(ep) => Some(ep),
            ProxyDecision::Direct(_) => None,
        }
    }

    #[test]
    fn https_proxy_parsed_with_port() {
        let cfg = config_ok(&[(HTTPS_PROXY, "http://proxy.corp.com:8080")]);
        let ep = proxy_endpoint(&cfg, "api.stripe.com").unwrap();
        assert_eq!(ep.display_addr(), "proxy.corp.com:8080");
        assert!(ep.proxy_authorization.is_none());
    }

    #[test]
    fn scheme_less_or_port_less_proxy_url_is_fatal() {
        // The accepted grammar is exactly `http://host:port`; lenient
        // defaulting would let a typo silently target the wrong proxy.
        for url in [
            "proxy.corp.com",
            "proxy.corp.com:3128",
            "http://proxy.corp.com",
        ] {
            let err = config_from(&[(HTTPS_PROXY, url)]).unwrap_err();
            assert!(err.contains(HTTPS_PROXY), "{url}: {err}");
            assert!(err.contains("explicit"), "{url}: {err}");
        }
    }

    // -- Fail-closed configuration validation --
    //
    // Present-but-invalid settings must be fatal, never silently treated
    // as unset: a typo must not downgrade the operator's egress boundary
    // to direct dialing or unauthenticated proxy access.

    #[test]
    fn tls_and_socks_proxies_are_fatal() {
        for url in ["https://proxy:443", "socks5://proxy:1080"] {
            let err = config_from(&[(HTTPS_PROXY, url)]).unwrap_err();
            assert!(err.contains(HTTPS_PROXY), "{err}");
            assert!(err.contains("scheme"), "{err}");
        }
    }

    #[test]
    fn url_userinfo_is_fatal_not_used_as_credentials() {
        // Inline credentials in the URL must never become the proxy auth;
        // credentials come only from the auth file. Matching the compute
        // driver, a URL that embeds them is rejected outright.
        let err = config_from(&[(HTTPS_PROXY, "http://user:secret@proxy:8080")]).unwrap_err();
        assert!(err.contains(HTTPS_PROXY), "{err}");
        assert!(
            !err.contains("secret"),
            "error must not leak the credential: {err}"
        );
    }

    #[test]
    fn malformed_proxy_address_is_fatal() {
        let err = config_from(&[(HTTPS_PROXY, "http://proxy:notaport")]).unwrap_err();
        assert!(err.contains(HTTPS_PROXY), "{err}");
        // A path/query/fragment addresses an endpoint, not a proxy; it is
        // rejected rather than silently discarded.
        for url in [
            "http://proxy:8080/path",
            "http://proxy:8080?x=1",
            "http://proxy:8080#frag",
        ] {
            let err = config_from(&[(HTTPS_PROXY, url)]).unwrap_err();
            assert!(err.contains(HTTPS_PROXY), "{url}: {err}");
        }
    }

    #[test]
    fn unreadable_auth_file_is_fatal() {
        let err = config_from(&[
            (HTTPS_PROXY, "http://proxy.corp.com:8080"),
            (PROXY_AUTH_FILE, "/nonexistent/upstream-proxy-auth"),
            (PROXY_AUTH_ALLOW_INSECURE, "true"),
        ])
        .unwrap_err();
        assert!(err.contains("auth file"), "{err}");
    }

    #[test]
    fn oversized_auth_file_is_fatal() {
        // The supervisor uses the same bounded reader as the driver, so an
        // oversized credential file is rejected rather than read unbounded.
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![b'a'; 8192]).unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let err = config_from(&[
            (HTTPS_PROXY, "http://proxy.corp.com:8080"),
            (PROXY_AUTH_FILE, &path),
            (PROXY_AUTH_ALLOW_INSECURE, "true"),
        ])
        .unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }

    #[test]
    fn auth_file_without_insecure_acknowledgement_is_fatal() {
        // Basic auth over the plain-TCP proxy connection is readable on the
        // network path; sending it requires the explicit opt-in.
        let err = config_from(&[
            (HTTPS_PROXY, "http://proxy.corp.com:8080"),
            (PROXY_AUTH_FILE, "/etc/openshell/auth/upstream-proxy"),
        ])
        .unwrap_err();
        assert!(err.contains(PROXY_AUTH_ALLOW_INSECURE), "{err}");
        assert!(err.contains("cleartext"), "{err}");
    }

    #[test]
    fn invalid_insecure_acknowledgement_value_is_fatal() {
        for value in ["false", "yes", "1", "TRUE"] {
            let err = config_from(&[
                (HTTPS_PROXY, "http://proxy.corp.com:8080"),
                (PROXY_AUTH_FILE, "/etc/openshell/auth/upstream-proxy"),
                (PROXY_AUTH_ALLOW_INSECURE, value),
            ])
            .unwrap_err();
            assert!(err.contains(PROXY_AUTH_ALLOW_INSECURE), "{value}: {err}");
        }
    }

    #[test]
    fn insecure_acknowledgement_without_auth_file_is_fatal() {
        let err = config_from(&[
            (HTTPS_PROXY, "http://proxy.corp.com:8080"),
            (PROXY_AUTH_ALLOW_INSECURE, "true"),
        ])
        .unwrap_err();
        assert!(err.contains(PROXY_AUTH_ALLOW_INSECURE), "{err}");
        assert!(err.contains(PROXY_AUTH_FILE), "{err}");
    }

    #[test]
    fn malformed_auth_file_credential_is_fatal() {
        // Empty, header-injecting, and non-`user:pass` credentials are all
        // rejected by the parser shared with the compute driver.
        for credential in ["  ", "user:pa\r\nss", "userpass", ":pass"] {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), credential).unwrap();
            let path = file.path().to_str().unwrap().to_string();
            let err = config_from(&[
                (HTTPS_PROXY, "http://proxy.corp.com:8080"),
                (PROXY_AUTH_FILE, &path),
                (PROXY_AUTH_ALLOW_INSECURE, "true"),
            ])
            .unwrap_err();
            assert!(err.contains("auth file"), "{err}");
            assert!(
                !err.contains("pa\r\nss"),
                "error must not leak the credential: {err}"
            );
        }
    }

    #[test]
    fn auxiliary_settings_without_proxy_are_fatal() {
        // An auth file or NO_PROXY list only makes sense relative to a proxy
        // boundary the operator believed was in effect.
        for (name, value) in [
            (PROXY_AUTH_FILE, "/etc/openshell/auth/upstream-proxy"),
            (PROXY_AUTH_ALLOW_INSECURE, "true"),
            (NO_PROXY, "*.svc.cluster.local"),
        ] {
            let err = config_from(&[(name, value)]).unwrap_err();
            assert!(err.contains(name), "{err}");
            assert!(err.contains("no upstream proxy"), "{err}");
        }
    }

    #[test]
    fn auth_file_credentials_are_applied_to_the_endpoint() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "user:secret\n").unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let cfg = config_ok(&[
            (HTTPS_PROXY, "http://proxy:8080"),
            (PROXY_AUTH_FILE, &path),
            (PROXY_AUTH_ALLOW_INSECURE, "true"),
        ]);
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:secret")
        );
        let ep = proxy_endpoint(&cfg, "example.com").unwrap();
        assert_eq!(ep.proxy_authorization.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn basic_auth_header_encodes_and_rejects_malformed_credentials() {
        assert_eq!(
            basic_auth_header("user:p@ss").as_deref(),
            Ok(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("user:p@ss")
            )
            .as_str())
        );
        assert!(basic_auth_header("  ").is_err());
        assert!(basic_auth_header("user:pa\r\nss").is_err());
        assert!(basic_auth_header("user:pa\nInjected: header").is_err());
        assert!(basic_auth_header("no-separator").is_err());
    }

    #[test]
    fn debug_output_hides_credentials() {
        let mut cfg = config_ok(&[(HTTPS_PROXY, "http://proxy:8080")]);
        cfg.https.proxy_authorization = Some(basic_auth_header("user:secret").unwrap());
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("secret"));
        assert!(!cfg.summary().contains("secret"));
    }

    #[test]
    fn ipv6_proxy_address_parses() {
        let cfg = config_ok(&[(HTTPS_PROXY, "http://[fd00::1]:8080")]);
        let ep = proxy_endpoint(&cfg, "example.com").unwrap();
        assert_eq!(ep.display_addr(), "fd00::1:8080");
    }

    // -- NO_PROXY matching --

    fn no_proxy_cfg(no_proxy: &str) -> UpstreamProxyConfig {
        config_ok(&[(HTTPS_PROXY, "http://proxy:8080"), (NO_PROXY, no_proxy)])
    }

    /// Hostname-level bypass check at an arbitrary port with no resolved
    /// addresses in play.
    fn bypasses(cfg: &UpstreamProxyConfig, host: &str) -> bool {
        bypasses_port(cfg, host, 443)
    }

    fn bypasses_port(cfg: &UpstreamProxyConfig, host: &str, port: u16) -> bool {
        matches!(cfg.decision(host, port, &[]), ProxyDecision::Direct(_))
    }

    fn bypasses_with(cfg: &UpstreamProxyConfig, host: &str, resolved: &[SocketAddr]) -> bool {
        matches!(cfg.decision(host, 443, resolved), ProxyDecision::Direct(_))
    }

    fn sock(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn no_proxy_domain_suffix_matches_host_and_subdomains() {
        let cfg = no_proxy_cfg("corp.com,other.example");
        assert!(bypasses(&cfg, "corp.com"));
        assert!(bypasses(&cfg, "api.corp.com"));
        assert!(!bypasses(&cfg, "notcorp.com"));
        assert!(!bypasses(&cfg, "corp.com.evil.io"));
    }

    #[test]
    fn no_proxy_leading_dot_and_wildcard_prefix_are_equivalent() {
        for entry in [".svc.cluster.local", "*.svc.cluster.local"] {
            let cfg = no_proxy_cfg(entry);
            assert!(
                bypasses(&cfg, "kubernetes.default.svc.cluster.local"),
                "{entry}"
            );
            assert!(!bypasses(&cfg, "example.com"), "{entry}");
        }
    }

    #[test]
    fn no_proxy_cidr_matches_ip_literals() {
        let cfg = no_proxy_cfg("10.96.0.0/12");
        assert!(bypasses(&cfg, "10.96.0.1"));
        assert!(bypasses(&cfg, "10.100.20.30"));
        assert!(!bypasses(&cfg, "10.200.0.9"));
        assert!(!bypasses(&cfg, "93.184.216.34"));
    }

    #[test]
    fn no_proxy_exact_ip_matches() {
        let cfg = no_proxy_cfg("192.168.1.5");
        assert!(bypasses(&cfg, "192.168.1.5"));
        assert!(!bypasses(&cfg, "192.168.1.6"));
    }

    #[test]
    fn no_proxy_wildcard_bypasses_everything() {
        let cfg = no_proxy_cfg("*");
        assert!(bypasses(&cfg, "example.com"));
    }

    #[test]
    fn no_proxy_port_qualifier_limits_bypass_to_that_port() {
        // `internal.corp:8443` documents a bypass for one port; broadening
        // it to every port would bypass the proxy for traffic the operator
        // never excluded.
        let cfg = no_proxy_cfg("internal.corp:8443");
        assert!(bypasses_port(&cfg, "internal.corp", 8443));
        assert!(bypasses_port(&cfg, "svc.internal.corp", 8443));
        assert!(!bypasses_port(&cfg, "internal.corp", 443));
        assert!(!bypasses_port(&cfg, "svc.internal.corp", 80));
    }

    #[test]
    fn no_proxy_port_qualifier_applies_to_ip_and_cidr_entries() {
        let cfg = no_proxy_cfg("192.168.1.5:8443,10.96.0.0/12:6443");
        assert!(bypasses_port(&cfg, "192.168.1.5", 8443));
        assert!(!bypasses_port(&cfg, "192.168.1.5", 443));
        assert!(bypasses_port(&cfg, "10.96.0.1", 6443));
        assert!(!bypasses_port(&cfg, "10.96.0.1", 443));
    }

    #[test]
    fn no_proxy_invalid_port_qualifier_is_not_stripped() {
        // A trailing qualifier that is not a valid port stays part of the
        // pattern instead of silently widening the entry to every port.
        let cfg = no_proxy_cfg("internal.corp:99999");
        assert!(!bypasses(&cfg, "internal.corp"));
    }

    #[test]
    fn no_proxy_cidr_matches_resolved_addresses_of_hostnames() {
        // The operator's `10.96.0.0/12` bypass covers cluster-internal
        // destinations however they are named; a hostname whose validated
        // resolution lands in the range must dial directly.
        let cfg = no_proxy_cfg("10.96.0.0/12");
        let inside = sock("10.96.0.7", 443);
        match cfg.decision("svc.internal", 443, &[inside]) {
            ProxyDecision::Direct(addrs) => assert_eq!(addrs, vec![inside]),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
        // Resolution outside the range keeps the proxy.
        assert!(matches!(
            cfg.decision("example.com", 443, &[sock("93.184.216.34", 443)]),
            ProxyDecision::Proxy(_)
        ));
    }

    #[test]
    fn no_proxy_resolved_address_match_limits_direct_dial_to_matching_addrs() {
        // Split resolution: only the addresses inside the bypassed range may
        // be dialed directly; the others are not covered by the operator's
        // exclusion and must not ride along.
        let cfg = no_proxy_cfg("10.96.0.0/12");
        let inside = sock("10.96.0.7", 443);
        let outside = sock("93.184.216.34", 443);
        match cfg.decision("svc.internal", 443, &[outside, inside]) {
            ProxyDecision::Direct(addrs) => assert_eq!(addrs, vec![inside]),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
    }

    #[test]
    fn no_proxy_ip_entry_matches_resolved_addresses() {
        let cfg = no_proxy_cfg("10.0.0.5");
        let matching = sock("10.0.0.5", 443);
        match cfg.decision("db.internal", 443, &[matching, sock("10.0.0.6", 443)]) {
            ProxyDecision::Direct(addrs) => assert_eq!(addrs, vec![matching]),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
    }

    #[test]
    fn no_proxy_bracketed_ipv6_entry_honors_port_qualifier() {
        // The colons of an IPv6 literal must not be misread as a port
        // qualifier; only the bracketed form can carry one.
        let cfg = no_proxy_cfg("[fd00::1]:8443");
        assert!(bypasses_port(&cfg, "fd00::1", 8443));
        assert!(bypasses_port(&cfg, "[fd00::1]", 8443));
        assert!(!bypasses_port(&cfg, "fd00::1", 443));
        assert!(!bypasses_port(&cfg, "fd00::2", 8443));

        // A bare IPv6 entry keeps every-port semantics.
        let cfg = no_proxy_cfg("fd00::1");
        assert!(bypasses_port(&cfg, "fd00::1", 8443));
        assert!(bypasses_port(&cfg, "fd00::1", 443));
    }

    #[test]
    fn no_proxy_ipv6_cidr_matches_resolved_addresses_of_hostnames() {
        let cfg = no_proxy_cfg("fd00::/8");
        // An IPv6-literal host inside the range bypasses at hostname level.
        assert!(bypasses(&cfg, "fd00::7"));
        assert!(!bypasses(&cfg, "2001:db8::1"));

        // A hostname resolving into the range dials directly, restricted to
        // the resolved addresses the entry contains.
        let inside = sock("fd00::42", 443);
        let outside = sock("2001:db8::1", 443);
        match cfg.decision("svc.internal", 443, &[outside, inside]) {
            ProxyDecision::Direct(addrs) => assert_eq!(addrs, vec![inside]),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
    }

    #[test]
    fn no_proxy_ipv6_cidr_honors_port_qualifier() {
        let cfg = no_proxy_cfg("fd00::/8:6443");
        assert!(bypasses_port(&cfg, "fd00::7", 6443));
        assert!(!bypasses_port(&cfg, "fd00::7", 443));
        match cfg.decision("svc.internal", 6443, &[sock("fd00::42", 6443)]) {
            ProxyDecision::Direct(addrs) => assert_eq!(addrs, vec![sock("fd00::42", 6443)]),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
        assert!(matches!(
            cfg.decision("svc.internal", 443, &[sock("fd00::42", 443)]),
            ProxyDecision::Proxy(_)
        ));
    }

    #[test]
    fn no_proxy_hostname_match_authorizes_all_resolved_addresses() {
        let cfg = no_proxy_cfg("internal.corp");
        let addrs = [sock("10.0.0.5", 443), sock("93.184.216.34", 443)];
        match cfg.decision("internal.corp", 443, &addrs) {
            ProxyDecision::Direct(direct) => assert_eq!(direct, addrs.to_vec()),
            ProxyDecision::Proxy(ep) => panic!("expected direct dial, got proxy {ep:?}"),
        }
    }

    #[test]
    fn loopback_bypasses_without_no_proxy() {
        // No NO_PROXY at all: loopback still bypasses unconditionally.
        let cfg = config_ok(&[(HTTPS_PROXY, "http://proxy:8080")]);
        assert!(bypasses_with(&cfg, "localhost", &[sock("127.0.0.1", 443)]));
        assert!(bypasses(&cfg, "127.0.0.1"));
        assert!(bypasses(&cfg, "::1"));
        assert!(!bypasses(&cfg, "example.com"));
    }

    /// A sandbox controls its own `/etc/hosts`, and `resolve_socket_addrs`
    /// consults it before DNS, so `localhost` can resolve to any address the
    /// network policy happens to allow. The name must not authorize a direct
    /// dial that escapes the operator proxy — only genuinely loopback
    /// resolved addresses may.
    #[test]
    fn spoofed_localhost_resolution_does_not_bypass_proxy() {
        let cfg = config_ok(&[(HTTPS_PROXY, "http://proxy:8080")]);
        assert!(!bypasses_with(
            &cfg,
            "localhost",
            &[sock("203.0.113.10", 443)]
        ));
        // A mixed answer is not partially honored: one non-loopback address
        // disqualifies the automatic bypass entirely.
        assert!(!bypasses_with(
            &cfg,
            "localhost",
            &[sock("127.0.0.1", 443), sock("203.0.113.10", 443)],
        ));
        // An empty resolution proves nothing about the destination.
        assert!(!bypasses_with(&cfg, "localhost", &[]));
        // Genuine loopback resolution still bypasses, including IPv6 and
        // dual-stack answers.
        assert!(bypasses_with(&cfg, "localhost", &[sock("127.0.0.1", 443)]));
        assert!(bypasses_with(&cfg, "localhost", &[sock("::1", 443)]));
        assert!(bypasses_with(
            &cfg,
            "localhost",
            &[sock("127.0.0.1", 443), sock("::1", 443)],
        ));
    }

    /// Losing the automatic bypass does not disable an operator's explicit
    /// `NO_PROXY` entry: the operator, not the sandbox, declares that one.
    #[test]
    fn spoofed_localhost_still_honors_explicit_no_proxy_entry() {
        let cfg = no_proxy_cfg("localhost");
        assert!(bypasses_with(
            &cfg,
            "localhost",
            &[sock("203.0.113.10", 443)]
        ));
    }

    // -- CONNECT handshake --

    async fn fake_proxy(response: &'static str) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (addr, handle)
    }

    fn endpoint_for(addr: SocketAddr, auth: Option<&str>) -> ProxyEndpoint {
        ProxyEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
            proxy_authorization: auth.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn connect_via_targets_validated_ip_by_default() {
        // The default CONNECT target is a validated address, so the proxy
        // performs no DNS resolution; the hostname only travels inside the
        // tunnel (TLS SNI, application Host).
        let (addr, handle) = fake_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
        let endpoint = endpoint_for(addr, Some("Basic dXNlcjpwYXNz"));
        let stream = connect_via(
            &endpoint,
            "api.example.com",
            443,
            ConnectTarget::Ip("93.184.216.34".parse().unwrap()),
        )
        .await
        .unwrap();
        drop(stream);
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: 93.184.216.34:443\r\n"));
        assert!(
            !request.contains("api.example.com"),
            "hostname must not leak into the CONNECT request in IP mode: {request}"
        );
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    /// Read one request's header block from a fake-proxy socket.
    async fn read_request(socket: &mut TcpStream) -> String {
        let mut buf = vec![0u8; 4096];
        let mut used = 0;
        loop {
            let n = socket.read(&mut buf[used..]).await.unwrap();
            used += n;
            if n == 0 || buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf[..used]).into_owned()
    }

    #[tokio::test]
    async fn connect_via_validated_falls_back_across_validated_addresses() {
        // The direct path tries every validated address; the proxied path
        // must too, or a dual-stack destination whose first address is
        // unreachable through the proxy fails needlessly.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            // First attempt: refuse the tunnel.
            let (mut refused, _) = listener.accept().await.unwrap();
            let first = read_request(&mut refused).await;
            refused
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .unwrap();
            drop(refused);
            // Second attempt: establish it.
            let (mut accepted, _) = listener.accept().await.unwrap();
            let second = read_request(&mut accepted).await;
            accepted
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            (first, second, accepted)
        });

        let endpoint = endpoint_for(addr, None);
        let addrs = [sock("192.0.2.1", 443), sock("192.0.2.2", 443)];
        let stream = connect_via_validated(&endpoint, "api.example.com", 443, &addrs)
            .await
            .unwrap();
        let (first, second, _accepted) = handle.await.unwrap();
        drop(stream);
        assert!(
            first.starts_with("CONNECT 192.0.2.1:443 HTTP/1.1\r\n"),
            "{first}"
        );
        assert!(
            second.starts_with("CONNECT 192.0.2.2:443 HTTP/1.1\r\n"),
            "{second}"
        );
    }

    #[tokio::test]
    async fn connect_via_validated_survives_a_hanging_first_attempt() {
        // A proxy that accepts the CONNECT but never answers must not
        // consume the whole aggregate budget: the per-address cap moves on
        // to the next validated address.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            // First attempt: read the CONNECT, then hang with the socket
            // held open until the client times the attempt out.
            let (mut hung, _) = listener.accept().await.unwrap();
            let first = read_request(&mut hung).await;
            // Second attempt: establish the tunnel.
            let (mut accepted, _) = listener.accept().await.unwrap();
            let second = read_request(&mut accepted).await;
            accepted
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            drop(hung);
            (first, second, accepted)
        });

        let endpoint = endpoint_for(addr, None);
        let addrs = [sock("192.0.2.1", 443), sock("192.0.2.2", 443)];
        // Small real-time budget: the first attempt hangs for its fair
        // share (half), then the second succeeds within the remainder.
        let stream = connect_via_validated_with_budget(
            &endpoint,
            "api.example.com",
            443,
            &addrs,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let (first, second, _accepted) = handle.await.unwrap();
        drop(stream);
        assert!(
            first.starts_with("CONNECT 192.0.2.1:443 HTTP/1.1\r\n"),
            "{first}"
        );
        assert!(
            second.starts_with("CONNECT 192.0.2.2:443 HTTP/1.1\r\n"),
            "{second}"
        );
    }

    #[tokio::test]
    async fn connect_via_validated_reports_failure_across_all_addresses() {
        let (addr, _handle) = fake_proxy("HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        // Only the first attempt gets a response; the second finds the
        // listener gone, and the aggregate error must say both were tried.
        let addrs = [sock("192.0.2.1", 443), sock("192.0.2.2", 443)];
        let err = connect_via_validated(&endpoint, "api.example.com", 443, &addrs)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("all 2 validated addresses"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn connect_via_validated_rejects_empty_address_list() {
        let endpoint = endpoint_for(sock("127.0.0.1", 3128), None);
        let err = connect_via_validated(&endpoint, "api.example.com", 443, &[])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn validated_ip_connect_tunnels_to_upstream_tls_verified_by_hostname() {
        // End-to-end composition of the SSRF-to-TLS boundary: a validated
        // address is CONNECTed to the corporate proxy (never the hostname),
        // the proxy tunnels to the destination, and upstream TLS is verified
        // against the original hostname carried in SNI. Covers both a
        // matching-hostname success and a mismatched-certificate rejection.
        use crate::l7::tls;
        use std::sync::{Arc, Mutex};
        use tokio::io::copy_bidirectional;

        const SERVER_HOSTNAME: &str = "upstream.example.test";

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Trusted CA; the client config trusts it, and the fake upstream
        // server presents a leaf for SERVER_HOSTNAME signed by it.
        let ca = tls::SandboxCa::generate().unwrap();
        let client_config = tls::build_upstream_client_config(ca.cert_pem());
        let tls_state = Arc::new(tls::ProxyTlsState::new(
            tls::CertCache::new(ca),
            tls::build_upstream_client_config(""),
        ));

        // Fake upstream TLS server: accepts tunneled connections and completes
        // a TLS handshake presenting the SERVER_HOSTNAME cert.
        let tls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((conn, _)) = tls_listener.accept().await {
                let state = tls_state.clone();
                tokio::spawn(async move {
                    let _ = tls::tls_terminate_client(conn, &state, SERVER_HOSTNAME).await;
                });
            }
        });

        // Fake corporate proxy: records each CONNECT request line and splices
        // the tunnel to the upstream TLS server.
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connect_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let connect_lines = connect_lines.clone();
            tokio::spawn(async move {
                while let Ok((mut client, _)) = proxy_listener.accept().await {
                    let connect_lines = connect_lines.clone();
                    tokio::spawn(async move {
                        let request = read_request(&mut client).await;
                        connect_lines
                            .lock()
                            .unwrap()
                            .push(request.lines().next().unwrap_or_default().to_string());
                        client
                            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            .await
                            .unwrap();
                        if let Ok(mut upstream) = TcpStream::connect(tls_addr).await {
                            let _ = copy_bidirectional(&mut client, &mut upstream).await;
                        }
                    });
                }
            });
        }

        let endpoint = endpoint_for(proxy_addr, None);

        // Success: CONNECT to the validated IP, TLS verified against the
        // requested hostname.
        let stream =
            connect_via_validated(&endpoint, SERVER_HOSTNAME, tls_addr.port(), &[tls_addr])
                .await
                .unwrap();
        tls::tls_connect_upstream(stream, SERVER_HOSTNAME, &client_config)
            .await
            .expect("TLS must verify for the requested hostname");

        // The proxy saw the validated IP in the CONNECT authority, never the
        // hostname — the tunnel is bound to the SSRF-validated address.
        {
            let lines = connect_lines.lock().unwrap();
            let line = lines.last().expect("proxy received a CONNECT");
            assert!(
                line.starts_with(&format!("CONNECT {}:", tls_addr.ip())),
                "CONNECT must target the validated IP: {line}"
            );
            assert!(
                !line.contains(SERVER_HOSTNAME),
                "hostname must not appear in the CONNECT authority: {line}"
            );
        }

        // Mismatch: the same validated tunnel, but verifying a different
        // hostname must fail — the server cert is only valid for
        // SERVER_HOSTNAME, so a rebinding/split-horizon substitution cannot
        // pass certificate verification.
        let stream = connect_via_validated(
            &endpoint,
            "wrong.example.test",
            tls_addr.port(),
            &[tls_addr],
        )
        .await
        .unwrap();
        assert!(
            tls::tls_connect_upstream(stream, "wrong.example.test", &client_config)
                .await
                .is_err(),
            "TLS must reject a certificate that does not match the requested hostname"
        );
    }

    #[tokio::test]
    async fn connect_via_sends_hostname_on_operator_opt_in() {
        let (addr, handle) = fake_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let stream = connect_via(&endpoint, "api.example.com", 443, ConnectTarget::Hostname)
            .await
            .unwrap();
        drop(stream);
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT api.example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: api.example.com:443\r\n"));
    }

    #[tokio::test]
    async fn connect_via_preserves_payload_after_connect_response() {
        // The proxy's 200 response and the first tunneled bytes can arrive
        // in a single read; the suffix belongs to the destination stream and
        // must be replayed, not discarded.
        let (addr, _handle) =
            fake_proxy("HTTP/1.1 200 Connection established\r\n\r\nserver-first-payload").await;
        let endpoint = endpoint_for(addr, None);
        let mut stream = connect_via(&endpoint, "api.example.com", 443, ConnectTarget::Hostname)
            .await
            .unwrap();
        let mut payload = vec![0u8; "server-first-payload".len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, b"server-first-payload");
    }

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_before_socket_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (mut accepted, _) = listener.accept().await.unwrap();
        let dialed = connect.await.unwrap();

        accepted.write_all(b" from-socket").await.unwrap();
        let mut stream = PrefixedStream::new(dialed, b"from-prefix".to_vec());
        let mut out = vec![0u8; "from-prefix from-socket".len()];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(out, b"from-prefix from-socket");

        // Writes pass through to the socket untouched by the prefix.
        stream.write_all(b"reply").await.unwrap();
        let mut reply = vec![0u8; 5];
        accepted.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
    }

    #[tokio::test]
    async fn connect_via_rejects_non_200() {
        let (addr, _handle) =
            fake_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let err = connect_via(&endpoint, "api.example.com", 443, ConnectTarget::Hostname)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("407"), "{err}");
    }

    #[tokio::test]
    async fn connect_via_rejects_malformed_response() {
        let (addr, _handle) = fake_proxy("garbage without status\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let err = connect_via(&endpoint, "api.example.com", 443, ConnectTarget::Hostname)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn connect_via_ipv6_target_is_bracketed() {
        // Both modes must bracket IPv6 authorities in the request line.
        let (addr, handle) = fake_proxy("HTTP/1.1 200 OK\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let _ = connect_via(
            &endpoint,
            "v6.example.com",
            443,
            ConnectTarget::Ip("2001:db8::1".parse().unwrap()),
        )
        .await
        .unwrap();
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));

        let (addr, handle) = fake_proxy("HTTP/1.1 200 OK\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let _ = connect_via(&endpoint, "2001:db8::1", 443, ConnectTarget::Hostname)
            .await
            .unwrap();
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn connect_by_hostname_requires_exact_true() {
        // Default is the validated-IP binding.
        let cfg = config_ok(&[(HTTPS_PROXY, "http://proxy:8080")]);
        assert!(!cfg.connect_by_hostname());

        let cfg = config_ok(&[
            (HTTPS_PROXY, "http://proxy:8080"),
            (PROXY_CONNECT_BY_HOSTNAME, "true"),
        ]);
        assert!(cfg.connect_by_hostname());

        // Anything other than the exact opt-in value the driver writes is a
        // misconfiguration, not a silent fallback to either mode.
        for value in ["false", "yes", "1", "TRUE"] {
            let err = config_from(&[
                (HTTPS_PROXY, "http://proxy:8080"),
                (PROXY_CONNECT_BY_HOSTNAME, value),
            ])
            .unwrap_err();
            assert!(err.contains(PROXY_CONNECT_BY_HOSTNAME), "{value}: {err}");
        }
    }

    #[test]
    fn connect_by_hostname_without_proxy_is_fatal() {
        let err = config_from(&[(PROXY_CONNECT_BY_HOSTNAME, "true")]).unwrap_err();
        assert!(err.contains(PROXY_CONNECT_BY_HOSTNAME), "{err}");
        assert!(err.contains("no upstream proxy"), "{err}");
    }
}
