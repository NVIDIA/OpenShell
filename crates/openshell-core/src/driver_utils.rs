// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility helpers shared across compute-driver crates.

use std::path::{Path, PathBuf};

use crate::proto::compute::v1::DriverSandbox;

// ---------------------------------------------------------------------------
// Sandbox container/pod label keys (openshell.ai/ namespace)
// ---------------------------------------------------------------------------

/// Container/pod label that identifies this resource as managed by `OpenShell`.
/// Value should be `"openshell"`.
pub const LABEL_MANAGED_BY: &str = "openshell.ai/managed-by";

/// Expected value for [`LABEL_MANAGED_BY`].
pub const LABEL_MANAGED_BY_VALUE: &str = "openshell";

/// Container/pod label carrying the sandbox ID.
pub const LABEL_SANDBOX_ID: &str = "openshell.ai/sandbox-id";

/// Container/pod label carrying the sandbox name.
pub const LABEL_SANDBOX_NAME: &str = "openshell.ai/sandbox-name";

/// Container/pod label carrying the sandbox namespace.
pub const LABEL_SANDBOX_NAMESPACE: &str = "openshell.ai/sandbox-namespace";

/// Container/pod label carrying the sandbox workspace.
pub const LABEL_SANDBOX_WORKSPACE: &str = "openshell.ai/sandbox-workspace";

/// Label carrying the gateway identity on managed namespaces.
pub const LABEL_GATEWAY_ID: &str = "openshell.ai/gateway-id";

/// Label selector that matches all OpenShell-managed resources which carry a
/// sandbox ID label.  Used by list and watch operations to exclude foreign
/// resources from the same namespace.
pub fn openshell_sandbox_label_selector() -> String {
    format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_SANDBOX_ID}")
}

// ---------------------------------------------------------------------------
// Sandbox condition reason strings set by compute drivers.
// ---------------------------------------------------------------------------

/// Ready-condition reason when a container exits on its own.
///
/// Covers an ordinary application exit or crash (exit 0, a non-zero error code,
/// or an uncaught fault). This is a terminal reason: gateway startup does NOT
/// auto-restart it, so a genuine failure keeps its error signal instead of
/// being relaunched.
pub const CONDITION_EXITED: &str = "ContainerExited";

/// Ready-condition reason when a container was terminated by an external signal.
///
/// SIGKILL/SIGTERM (exit 137/143) is what a Podman/Docker machine or daemon
/// restart does to running containers. Distinct from `CONDITION_EXITED` so
/// gateway startup can recover machine-restart victims while leaving ordinary
/// application exits terminal.
pub const CONDITION_RUNTIME_RESTART: &str = "ContainerRuntimeRestart";

/// Ready-condition reason when a container is explicitly stopped via the
/// runtime API (e.g. `podman stop`, gateway-initiated shutdown).
pub const CONDITION_STOPPED: &str = "ContainerStopped";

// ---------------------------------------------------------------------------

/// Path to the sandbox supervisor binary inside the container image.
///
/// All compute drivers must launch this binary as the container entrypoint to
/// start the sandboxed environment.  The value must be kept in sync with the
/// path used when building the `openshell-sandbox` image layer.
pub const SUPERVISOR_IMAGE_BINARY_PATH: &str = "/openshell-sandbox";

/// Directory inside sandbox containers where the supervisor binary is mounted.
///
/// Compute drivers that side-load the supervisor into a shared volume mount
/// the binary here so the sandbox container can execute it from a fixed path.
pub const SUPERVISOR_CONTAINER_DIR: &str = "/opt/openshell/bin";

/// Full path to the supervisor binary inside sandbox containers.
///
/// Equals `SUPERVISOR_CONTAINER_DIR + "/openshell-sandbox"`. Use this when
/// the full executable path is needed (Docker entrypoint, Podman entrypoint,
/// VM rootfs injection). Use `SUPERVISOR_CONTAINER_DIR` when only the
/// directory mount-point is needed (Kubernetes emptyDir volume mount).
pub const SUPERVISOR_CONTAINER_BINARY: &str = "/opt/openshell/bin/openshell-sandbox";

// ---------------------------------------------------------------------------
// In-container mount paths for guest TLS materials and the sandbox token.
//
// All container-based drivers (Docker, Podman, Kubernetes) mount the gateway's
// mTLS client credentials at these fixed paths inside every sandbox container.
// The supervisor reads these paths on startup to establish its gRPC-over-mTLS
// connection back to the gateway. The paths must remain stable across driver
// versions since the supervisor binary is built and packaged separately.
// ---------------------------------------------------------------------------

/// Container-side mount path for the guest mTLS CA certificate.
pub const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";

/// Container-side mount path for the guest mTLS client certificate.
pub const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";

/// Container-side mount path for the guest mTLS client private key.
pub const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";

/// Container-side mount path for the per-sandbox JWT token.
pub const SANDBOX_TOKEN_MOUNT_PATH: &str = "/etc/openshell/auth/sandbox.jwt";

/// Container-side mount path for the corporate upstream-proxy credentials.
///
/// The file holds the `user:pass` userinfo used to build the
/// `Proxy-Authorization` header. It is delivered through a root-only secret
/// mount so the credential never appears in container environment/metadata.
pub const UPSTREAM_PROXY_AUTH_MOUNT_PATH: &str = "/etc/openshell/auth/upstream-proxy";

/// Container-side mount path for the corporate proxy CA bundle.
///
/// Drivers with a `proxy_ca_bundle` operator setting bind-mount the host PEM
/// file here (read-only) and pass the path on the supervisor's argv via
/// `--upstream-proxy-ca-bundle`. The supervisor trusts it for the TLS
/// handshake with an `https://` corporate egress proxy and for server
/// certificates re-signed by a TLS-intercepting proxy. Unlike the proxy
/// credential, a CA certificate is not secret, so a plain read-only bind
/// mount is used rather than a driver secret.
pub const PROXY_CA_MOUNT_PATH: &str = "/etc/openshell/tls/proxy/ca-bundle.pem";

/// A validated corporate upstream-proxy address.
///
/// Produced by [`parse_upstream_proxy_url`], which is the single source of
/// truth for what counts as a valid upstream proxy URL. Compute drivers use
/// it to reject bad operator config at sandbox-create time, and the
/// in-container supervisor applies the same rules to its driver-supplied
/// arguments so a value one side accepts is never rejected (or silently
/// ignored) by the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxyAddr {
    /// Proxy hostname, IPv4, or IPv6 address (IPv6 without brackets).
    pub host: String,
    /// Proxy TCP port (always explicit in the accepted URL grammar).
    pub port: u16,
    /// `true` when the proxy URL used the `https://` scheme, so the supervisor
    /// wraps the connection to the proxy in TLS before the CONNECT handshake.
    pub secure: bool,
}

/// Why an upstream proxy URL was rejected by [`parse_upstream_proxy_url`].
///
/// Kept as a typed error so each consumer (driver config validation,
/// supervisor startup) can phrase the message for its own surface while
/// enforcing identical semantics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamProxyUrlError {
    /// The value is empty or whitespace-only.
    #[error("proxy URL is empty")]
    Empty,
    /// The value does not parse as a URL.
    #[error("not a valid proxy URL: {0}")]
    Invalid(url::ParseError),
    /// The value has no `scheme://` prefix. Bare `host[:port]` forms are
    /// rejected so the accepted grammar matches the documented
    /// `http://host:port` contract exactly.
    #[error("proxy URL must include an explicit scheme, e.g. http://proxy.corp.com:3128")]
    MissingScheme,
    /// The URL uses a scheme other than `http` or `https` (SOCKS proxies are
    /// not supported by the sandbox supervisor).
    #[error(
        "unsupported proxy scheme '{0}': only http:// and https:// forward \
         proxies are supported by the sandbox supervisor"
    )]
    UnsupportedScheme(String),
    /// The URL has no explicit port. Corporate proxies rarely listen on the
    /// scheme default (80), so a forgotten port is rejected instead of
    /// silently dialing port 80.
    #[error("proxy URL must include an explicit proxy port, e.g. http://proxy.corp.com:3128")]
    MissingPort,
    /// The URL specifies port `0`, which is not a connectable TCP port. It
    /// would pass startup validation but fail every proxied dial, so it is
    /// rejected up front.
    #[error("proxy URL port must not be 0")]
    ZeroPort,
    /// The URL embeds `user:pass@` credentials, which would leak into config
    /// and container metadata. Credentials must come from the proxy auth file.
    #[error("proxy URL must not embed credentials; supply them via the proxy auth file")]
    InlineCredentials,
    /// The URL has no host component.
    #[error("proxy URL is missing a proxy host")]
    MissingHost,
    /// The URL carries a path, query, or fragment. A forward proxy is
    /// addressed by `host:port` only, so extra components indicate a
    /// misconfiguration (e.g. a pasted endpoint URL) and are rejected instead
    /// of being silently discarded.
    #[error("proxy URL must not contain a {0}; use scheme://host:port only")]
    UnexpectedComponent(&'static str),
}

/// Parse and validate a corporate upstream-proxy URL.
///
/// The accepted grammar is exactly `http://host:port` or `https://host:port`:
/// the scheme and the port must both be explicit, only `http://` and
/// `https://` proxies are accepted, and inline userinfo is rejected. The URL
/// must address the proxy only: a path (other than a bare trailing `/`),
/// query, or fragment is rejected rather than silently discarded. The
/// returned [`UpstreamProxyAddr::secure`] records whether the `https://`
/// scheme was used so the supervisor knows to TLS-wrap the proxy connection.
///
/// # Errors
///
/// Returns an [`UpstreamProxyUrlError`] describing the first rule the value
/// violates.
pub fn parse_upstream_proxy_url(raw: &str) -> Result<UpstreamProxyAddr, UpstreamProxyUrlError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UpstreamProxyUrlError::Empty);
    }
    if !trimmed.contains("://") {
        return Err(UpstreamProxyUrlError::MissingScheme);
    }
    let parsed = url::Url::parse(trimmed).map_err(UpstreamProxyUrlError::Invalid)?;

    let secure = if parsed.scheme().eq_ignore_ascii_case("https") {
        true
    } else if parsed.scheme().eq_ignore_ascii_case("http") {
        false
    } else {
        return Err(UpstreamProxyUrlError::UnsupportedScheme(
            parsed.scheme().to_string(),
        ));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(UpstreamProxyUrlError::InlineCredentials);
    }
    let host = match parsed.host() {
        // `Host::Ipv6` renders without brackets, which is what socket
        // connect APIs expect.
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        Some(host) => host.to_string(),
        None => return Err(UpstreamProxyUrlError::MissingHost),
    };
    if host.is_empty() {
        return Err(UpstreamProxyUrlError::MissingHost);
    }
    // The `url` crate normalizes an absent path to "/" for http URLs, so a
    // bare trailing slash is indistinguishable from no path and is accepted.
    if !matches!(parsed.path(), "" | "/") {
        return Err(UpstreamProxyUrlError::UnexpectedComponent("path"));
    }
    if parsed.query().is_some() {
        return Err(UpstreamProxyUrlError::UnexpectedComponent("query"));
    }
    if parsed.fragment().is_some() {
        return Err(UpstreamProxyUrlError::UnexpectedComponent("fragment"));
    }
    if !authority_has_explicit_port(trimmed) {
        return Err(UpstreamProxyUrlError::MissingPort);
    }
    // Explicit-port presence was verified above; `port()` is `None` only when
    // the URL spells out the scheme default (`:80` for http, `:443` for
    // https), which the url crate normalizes away.
    let port = parsed.port().unwrap_or(if secure { 443 } else { 80 });
    if port == 0 {
        return Err(UpstreamProxyUrlError::ZeroPort);
    }
    Ok(UpstreamProxyAddr { host, port, secure })
}

/// Return `true` when the raw URL's authority carries an explicit `:port`.
///
/// The `url` crate normalizes a scheme-default port (`:80` for http) to
/// `None`, making it indistinguishable from an absent port in the parsed
/// form, so the raw authority must be inspected instead.
fn authority_has_explicit_port(raw: &str) -> bool {
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Userinfo is rejected by the caller, but strip it anyway so this check
    // never misreads a `user:pass@` colon as a port.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    host_port.rfind(']').map_or_else(
        || {
            host_port
                .rsplit_once(':')
                .is_some_and(|(_, port)| !port.is_empty())
        },
        // Bracketed IPv6 literal: a port can only follow the bracket, and a
        // bare trailing `]:` is no more explicit than no port at all.
        |end| {
            host_port[end + 1..]
                .strip_prefix(':')
                .is_some_and(|port| !port.is_empty())
        },
    )
}

/// Why an upstream proxy credential was rejected by
/// [`parse_upstream_proxy_credential`].
///
/// Variants carry no payload so an error can never leak credential content
/// into logs or user-facing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamProxyCredentialError {
    /// The credential is empty or whitespace-only.
    #[error("credential is empty")]
    Empty,
    /// The credential contains control characters (CR, LF, NUL, tab, ...)
    /// that could inject additional HTTP headers.
    #[error("credential contains control characters")]
    ControlCharacters,
    /// The credential has no `:` separating user from password.
    #[error("credential must use the user:pass form (missing ':')")]
    MissingSeparator,
    /// The credential has an empty user before the `:` separator.
    #[error("credential must use the user:pass form (empty user)")]
    EmptyUser,
}

/// Validate a corporate upstream-proxy credential read from the proxy auth
/// file, returning the trimmed `user:pass` value.
///
/// Single source of truth for what counts as a valid proxy credential: the
/// compute driver applies it at sandbox-create time (before staging the
/// secret) and the in-container supervisor applies it again before building
/// the `Proxy-Authorization: Basic` header, so a credential one side accepts
/// is never rejected by the other.
///
/// Surrounding whitespace (including the conventional trailing newline) is
/// trimmed. The user part must be non-empty; the password may be empty and
/// may itself contain `:` (per RFC 7617 the first `:` is the separator).
///
/// # Errors
///
/// Returns an [`UpstreamProxyCredentialError`] describing the first rule the
/// value violates. Errors never contain the credential itself.
pub fn parse_upstream_proxy_credential(raw: &str) -> Result<&str, UpstreamProxyCredentialError> {
    let credential = raw.trim();
    if credential.is_empty() {
        return Err(UpstreamProxyCredentialError::Empty);
    }
    if credential.contains(|c: char| c.is_control()) {
        return Err(UpstreamProxyCredentialError::ControlCharacters);
    }
    match credential.split_once(':') {
        None => Err(UpstreamProxyCredentialError::MissingSeparator),
        Some(("", _)) => Err(UpstreamProxyCredentialError::EmptyUser),
        Some(_) => Ok(credential),
    }
}

/// Hard upper bound on the size of a proxy-auth credential file.
///
/// A `user:pass` credential is tiny; this cap only exists to stop a hostile
/// or misconfigured path (a huge file, or a special file such as
/// `/dev/zero`) from exhausting memory during a bounded read.
pub const MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES: u64 = 4096;

/// Read a proxy-auth credential file with a hard size bound.
///
/// Rejects non-regular files (e.g. `/dev/zero`, directories, FIFOs) and
/// files larger than [`MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES`], and reads at
/// most that many bytes, so a hostile or misconfigured path cannot exhaust
/// gateway or supervisor memory. Returns the raw contents; callers pass the
/// result to [`parse_upstream_proxy_credential`].
///
/// Shared by the compute driver (at sandbox-create time) and the in-container
/// supervisor so both enforce the same bound. This is a blocking read; async
/// callers should wrap it (e.g. `tokio::task::spawn_blocking`).
///
/// # Errors
///
/// Returns a descriptive error (never containing file contents) when the path
/// cannot be opened or stat'd, is not a regular file, or exceeds the size
/// bound.
pub fn read_upstream_proxy_credential_file(path: &str) -> Result<String, String> {
    read_regular_file_bounded(path, MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES).map_err(|err| match err {
        BoundedReadError::Open(e) => format!("failed to open proxy auth file '{path}': {e}"),
        BoundedReadError::Stat(e) => format!("failed to stat proxy auth file '{path}': {e}"),
        BoundedReadError::NotRegular => format!("proxy auth file '{path}' is not a regular file"),
        BoundedReadError::TooLarge => format!(
            "proxy auth file '{path}' exceeds the {MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES}-byte limit"
        ),
        BoundedReadError::Read(e) => format!("failed to read proxy auth file '{path}': {e}"),
    })
}

/// Hard upper bound on the size of a corporate proxy CA bundle file.
///
/// A CA bundle holding every corporate trust anchor is a few tens of
/// kilobytes; this cap only exists so a hostile or misconfigured path (a huge
/// file, or a special file such as `/dev/zero`) cannot exhaust gateway,
/// driver, or supervisor memory during a bounded read.
pub const MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES: u64 = 1024 * 1024;

/// Read and validate an operator corporate proxy CA bundle PEM file.
///
/// Rejects non-regular files (e.g. `/dev/zero`, directories, FIFOs) and files
/// larger than [`MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES`], then requires the
/// bundle to contribute at least one trust anchor rustls actually accepts —
/// see [`validate_upstream_proxy_ca_bundle_pem`]. Returns the PEM contents.
///
/// Shared by the compute driver (at sandbox-create time, so the operator gets
/// an error naming the setting) and the in-container supervisor (at startup),
/// so a bundle accepted on the host is never rejected inside the sandbox and
/// vice versa. This is a blocking read; async callers should wrap it (e.g.
/// `tokio::task::spawn_blocking`).
///
/// `label` names the operator-facing setting (`proxy_ca_bundle`, or the
/// supervisor's argument name) and prefixes every error.
///
/// # Errors
///
/// Returns a descriptive error (never containing file contents) when the path
/// cannot be read, is not a regular file, exceeds the size bound, or holds no
/// usable certificate.
pub fn read_upstream_proxy_ca_bundle_file(path: &str, label: &str) -> Result<String, String> {
    let pem = read_regular_file_bounded(path, MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES).map_err(
        |err| match err {
            BoundedReadError::Open(e) | BoundedReadError::Stat(e) | BoundedReadError::Read(e) => {
                format!("{label} '{path}' could not be read: {e}")
            }
            BoundedReadError::NotRegular => {
                format!("{label} '{path}' is not a regular file")
            }
            BoundedReadError::TooLarge => format!(
                "{label} '{path}' exceeds the {MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES}-byte limit"
            ),
        },
    )?;
    validate_upstream_proxy_ca_bundle_pem(&pem, path, label)?;
    Ok(pem)
}

/// Require a CA bundle PEM to contribute at least one usable trust anchor.
///
/// Fail-closed to match the rest of the operator-owned proxy configuration:
/// the operator explicitly pointed at this file, so a bundle with no usable
/// certificate is an error rather than a silent fall-back to the built-in
/// roots that would quietly weaken the trust boundary.
///
/// Validating that rustls accepts an anchor — rather than only that PEM
/// framing base64-decodes — is what makes the host-side check equivalent to
/// the guest-side one: a PEM block holding invalid DER passes
/// `rustls_pemfile::certs` but is silently dropped by
/// `RootCertStore::add_parsable_certificates`, so counting PEM blocks alone
/// would accept on the host a bundle that contributes zero anchors at runtime.
///
/// # Errors
///
/// Returns a descriptive error, prefixed with `label` and naming `path`, when
/// the PEM holds no certificate block or no block contains valid X.509 DER.
pub fn validate_upstream_proxy_ca_bundle_pem(
    pem: &str,
    path: &str,
    label: &str,
) -> Result<(), String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes())
        .flatten()
        .collect();
    if certs.is_empty() {
        return Err(format!(
            "{label} '{path}' contains no PEM certificate blocks"
        ));
    }
    let mut store = rustls::RootCertStore::empty();
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!(
            "{label} '{path}' contains no usable trust anchors \
             (PEM blocks were found but none contain valid X.509 DER)"
        ));
    }
    Ok(())
}

/// Failure modes of [`read_regular_file_bounded`], so each caller can phrase
/// them in terms of the operator setting it is reading.
enum BoundedReadError {
    Open(std::io::Error),
    Stat(std::io::Error),
    NotRegular,
    TooLarge,
    Read(std::io::Error),
}

/// Read a regular file into a `String`, rejecting anything larger than
/// `max_bytes` and anything that is not a regular file.
///
/// Backs the operator-supplied proxy file readers, which must never let a
/// hostile or misconfigured path (`/dev/zero`, a FIFO, a directory, a huge
/// file) exhaust memory or block the caller.
fn read_regular_file_bounded(path: &str, max_bytes: u64) -> Result<String, BoundedReadError> {
    use std::io::Read as _;

    // Windows rejects opening a directory before a file handle is available,
    // while Unix permits the open and rejects it via handle metadata below.
    // Preflight the path so every platform reports the intended non-regular
    // file error. The post-open check remains necessary to close the TOCTOU
    // window if the path is replaced between these operations.
    #[cfg(target_os = "windows")]
    {
        let path_metadata = std::fs::metadata(path).map_err(BoundedReadError::Open)?;
        if !path_metadata.is_file() {
            return Err(BoundedReadError::NotRegular);
        }
    }

    // On Unix, open non-blocking so a FIFO with no writer does not hang the
    // open() call indefinitely; the regular-file check below then rejects it.
    // O_NONBLOCK has no effect on the subsequent read of a regular file.
    #[cfg(unix)]
    let open_result = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let open_result = std::fs::File::open(path);

    let file = open_result.map_err(BoundedReadError::Open)?;
    let metadata = file.metadata().map_err(BoundedReadError::Stat)?;
    if !metadata.is_file() {
        return Err(BoundedReadError::NotRegular);
    }
    if metadata.len() > max_bytes {
        return Err(BoundedReadError::TooLarge);
    }
    // Bound the read even if the file grows between stat and read.
    let mut buf = String::new();
    file.take(max_bytes + 1)
        .read_to_string(&mut buf)
        .map_err(BoundedReadError::Read)?;
    if buf.len() as u64 > max_bytes {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(buf)
}

/// Operator-supplied corporate upstream-proxy settings, as a borrowed view.
///
/// Compute drivers store these keys under their own
/// `[openshell.drivers.<name>]` table; this type exists so the pairing rules
/// between them live in one place instead of being restated per driver.
/// Field names map 1:1 onto the documented TOML keys `https_proxy`,
/// `no_proxy`, `proxy_auth_file`, `proxy_auth_allow_insecure`,
/// `proxy_connect_by_hostname`, and `proxy_ca_bundle`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UpstreamProxySettings<'a> {
    /// `https_proxy`: the corporate forward proxy URL.
    pub url: Option<&'a str>,
    /// `no_proxy`: comma-separated bypass list.
    pub no_proxy: Option<&'a str>,
    /// `proxy_auth_file`: host path to a `user:pass` credential file.
    pub auth_file: Option<&'a str>,
    /// `proxy_auth_allow_insecure`: acknowledgement that Basic auth to an
    /// `http://` proxy travels in cleartext.
    pub auth_allow_insecure: Option<bool>,
    /// `proxy_connect_by_hostname`: send hostnames rather than validated IPs
    /// in CONNECT requests.
    pub connect_by_hostname: Option<bool>,
    /// `proxy_ca_bundle`: host path to a PEM CA bundle trusted for the proxy.
    pub ca_bundle: Option<&'a str>,
}

/// Validate operator-supplied corporate upstream-proxy settings, fail-closed.
///
/// Shares URL semantics with the in-container supervisor through
/// [`parse_upstream_proxy_url`], so a value accepted here can never be
/// rejected by the supervisor at sandbox startup (or vice versa). Every
/// auxiliary setting is only meaningful relative to a proxy boundary the
/// operator believed was in effect, so a stray one is rejected rather than
/// silently accepted while all egress dials directly.
///
/// A present-but-empty string is rejected everywhere: the supervisor treats
/// an empty driver-supplied argument as a fatal misconfiguration, so a driver
/// must never accept (and later pass) one.
///
/// # Errors
///
/// Returns a message naming the offending key.
pub fn validate_upstream_proxy_settings(
    settings: &UpstreamProxySettings<'_>,
) -> Result<(), String> {
    let proxy_secure = if let Some(url) = settings.url {
        let addr = parse_upstream_proxy_url(url).map_err(|err| match err {
            UpstreamProxyUrlError::Empty => "https_proxy must not be empty when set".to_string(),
            UpstreamProxyUrlError::InlineCredentials => {
                "https_proxy must not embed credentials in the URL; supply them via \
                 proxy_auth_file so they are not stored in config or sandbox metadata"
                    .to_string()
            }
            err => format!("https_proxy {err}"),
        })?;
        addr.secure
    } else {
        false
    };

    if let Some(list) = settings.no_proxy {
        if list.trim().is_empty() {
            return Err("no_proxy must not be empty when set; omit it instead".to_string());
        }
        if settings.url.is_none() {
            return Err("no_proxy is set but no https_proxy is configured".to_string());
        }
    }

    if let Some(path) = settings.auth_file {
        if path.trim().is_empty() {
            return Err("proxy_auth_file must not be empty when set".to_string());
        }
        if settings.url.is_none() {
            return Err("proxy_auth_file is set but no https_proxy is configured".to_string());
        }
        // Basic auth over the plain-TCP proxy connection is readable by
        // anyone on the network path; sending it requires an explicit
        // operator acknowledgement rather than being an implicit side effect
        // of configuring credentials. For an https:// proxy the credential is
        // inside the verified TLS session, so the acknowledgement is
        // unnecessary (but tolerated).
        if settings.auth_allow_insecure != Some(true) && !proxy_secure {
            return Err(
                "proxy_auth_file sends the credential as cleartext Basic auth over the \
                 plain-TCP connection to the http:// proxy; set proxy_auth_allow_insecure \
                 = true to accept that exposure, or remove proxy_auth_file"
                    .to_string(),
            );
        }
    } else if settings.auth_allow_insecure.is_some() {
        // The acknowledgement without credentials means the operator believed
        // an auth file was configured; surface the mismatch.
        return Err(
            "proxy_auth_allow_insecure is set but no proxy_auth_file is configured".to_string(),
        );
    }

    if settings.connect_by_hostname.is_some() && settings.url.is_none() {
        return Err(
            "proxy_connect_by_hostname is set but no https_proxy is configured".to_string(),
        );
    }

    // A CA bundle only makes sense relative to a proxy boundary (an https://
    // proxy handshake, or a TLS-intercepting proxy's re-sign CA). The file's
    // readability and certificate content are checked at sandbox-create time
    // by the driver and fail closed again in the supervisor.
    if let Some(path) = settings.ca_bundle {
        if path.trim().is_empty() {
            return Err("proxy_ca_bundle must not be empty when set".to_string());
        }
        if settings.url.is_none() {
            return Err("proxy_ca_bundle is set but no https_proxy is configured".to_string());
        }
    }

    Ok(())
}

/// Container-side directory where the provider SPIFFE Workload API socket is mounted.
pub const PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR: &str = "/spiffe-workload-api";

/// Return the XDG state path for a driver's sandbox JWT token file.
///
/// The resulting path is `$XDG_STATE_HOME/openshell/<driver_subdir>[/<namespace>]/<sandbox_id>/sandbox.jwt`.
///
/// `driver_subdir` is driver-specific. When `namespace` is `Some`, it is
/// appended as an additional path component (with `/` and `\` replaced by
/// `-`).
///
/// # Errors
/// Returns an error if the XDG state directory cannot be resolved.
pub fn sandbox_token_path(
    driver_subdir: &str,
    namespace: Option<&str>,
    sandbox_id: &str,
) -> miette::Result<PathBuf> {
    let mut path = crate::paths::xdg_state_dir()?
        .join("openshell")
        .join(driver_subdir);
    if let Some(ns) = namespace {
        path = path.join(ns.replace(['/', '\\'], "-"));
    }
    Ok(path.join(sandbox_id).join("sandbox.jwt"))
}

/// Return the effective log level for a sandbox.
///
/// Uses the level from the sandbox spec when non-empty, falling back to
/// `default_level` otherwise.
pub fn sandbox_log_level(sandbox: &DriverSandbox, default_level: &str) -> String {
    sandbox
        .spec
        .as_ref()
        .map(|spec| spec.log_level.as_str())
        .filter(|level| !level.is_empty())
        .unwrap_or(default_level)
        .to_string()
}

// ---------------------------------------------------------------------------
// Supervisor image helpers shared by container-backed drivers
// ---------------------------------------------------------------------------

/// Return the tag portion of a supervisor image reference, or `None` if the
/// reference uses a digest (`@sha256:...`).
///
/// Examples:
/// - `"ghcr.io/org/image:1.2.3"` → `Some("1.2.3")`
/// - `"ghcr.io/org/image:latest"` → `Some("latest")`
/// - `"ghcr.io/org/image"` → `Some("latest")`  (implied tag)
/// - `"ghcr.io/org/image@sha256:abc"` → `None`  (pinned by digest)
/// - `"ghcr.io/org/image:"` → `None`  (empty tag)
pub fn supervisor_image_tag(image: &str) -> Option<&str> {
    if image.contains('@') {
        return None;
    }

    let image_name = image.rsplit('/').next().unwrap_or(image);
    image_name
        .rsplit_once(':')
        .map_or(Some("latest"), |(_, tag)| {
            if tag.is_empty() { None } else { Some(tag) }
        })
}

/// Return `true` if the supervisor image should be refreshed before each use.
///
/// Mutable tags (`dev`, `latest`) are always re-pulled so that the running
/// container tracks the latest pushed version.  Digest-pinned references and
/// all other versioned tags are treated as immutable and pulled at most once.
pub fn supervisor_image_should_refresh(image: &str) -> bool {
    matches!(supervisor_image_tag(image), Some("dev" | "latest"))
}

// ---------------------------------------------------------------------------
// Supervisor binary extraction helpers shared by container-backed drivers
// ---------------------------------------------------------------------------

#[cfg(feature = "driver-extraction")]
/// Extract the payload of the first regular-file entry in a tar archive.
///
/// Container archive endpoints return a single-file tar when `path` points to
/// a file, so only the first entry is consumed. Returns an error when the
/// archive is empty, the first entry is not a regular file, or the payload is
/// empty.
pub fn extract_first_tar_entry(tar_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut entries = archive
        .entries()
        .map_err(|err| format!("open tar archive: {err}"))?;
    let mut entry = entries
        .next()
        .ok_or_else(|| "tar archive was empty".to_string())?
        .map_err(|err| format!("read tar entry: {err}"))?;
    let kind = entry.header().entry_type();
    if !kind.is_file() {
        return Err(format!(
            "expected a regular file in tar archive, got type {kind:?}"
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes)
        .map_err(|err| format!("read tar entry payload: {err}"))?;
    if bytes.is_empty() {
        return Err("tar entry payload was empty".to_string());
    }
    Ok(bytes)
}

#[cfg(feature = "driver-extraction")]
/// Atomically write `bytes` to `final_path` via a sibling temp file.
///
/// Creates parent directories as needed. The temp file is synced, `chmod 755`
/// (on Unix), and renamed into place so concurrent readers never observe a
/// partial write. Returns a human-readable error string on failure.
pub fn write_cache_binary_atomic(final_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = final_path
        .parent()
        .ok_or_else(|| format!("cache path '{}' has no parent", final_path.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create cache dir '{}': {err}", dir.display()))?;

    let mut temp = tempfile::Builder::new()
        .prefix(".openshell-sandbox-")
        .tempfile_in(dir)
        .map_err(|err| format!("failed to create temp file in '{}': {err}", dir.display()))?;
    std::io::Write::write_all(&mut temp, bytes)
        .map_err(|err| format!("failed to write supervisor binary: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync supervisor binary: {err}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("failed to chmod supervisor binary: {err}"))?;
    }

    temp.persist(final_path).map_err(|err| {
        format!(
            "failed to persist supervisor binary to '{}': {}",
            final_path.display(),
            err.error,
        )
    })?;
    Ok(())
}

/// Return the host-side cache path for an extracted supervisor binary.
///
/// The path is `$XDG_DATA_HOME/openshell/<driver_subdir>/<sanitized-digest>/openshell-sandbox`.
/// `driver_subdir` distinguishes caches across drivers.
pub fn supervisor_cache_path(driver_subdir: &str, digest: &str) -> Result<PathBuf, String> {
    let base = crate::paths::xdg_data_dir()
        .map_err(|err| format!("failed to resolve XDG data dir: {err}"))?;
    Ok(supervisor_cache_path_with_base(
        &base,
        driver_subdir,
        digest,
    ))
}

/// [`supervisor_cache_path`] with an explicit base directory (for testing).
pub fn supervisor_cache_path_with_base(base: &Path, driver_subdir: &str, digest: &str) -> PathBuf {
    let sanitized = digest.replace(':', "-");
    base.join("openshell")
        .join(driver_subdir)
        .join(sanitized)
        .join("openshell-sandbox")
}

/// Generate a unique container name for supervisor binary extraction.
///
/// Uses the process ID and an atomic counter to avoid collisions across
/// concurrent gateway starts.
pub fn temp_extract_container_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("openshell-supervisor-extract-{pid}-{seq}")
}

/// Validate that the file at `path` starts with the ELF magic bytes (`\x7fELF`).
///
/// Returns a human-readable error when the file cannot be read or is not a
/// Linux ELF binary.
pub fn validate_linux_elf_binary(path: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|err| {
        format!(
            "failed to open supervisor binary '{}': {err}",
            path.display()
        )
    })?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|err| {
        format!(
            "failed to read supervisor binary '{}': {err}",
            path.display()
        )
    })?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(format!(
            "supervisor binary '{}' is not a Linux ELF executable",
            path.display(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_proxy_url_accepts_http_with_port() {
        let addr = parse_upstream_proxy_url("http://proxy.corp.com:8080").unwrap();
        assert_eq!(addr.host, "proxy.corp.com");
        assert_eq!(addr.port, 8080);
        assert!(!addr.secure, "http:// is not TLS-wrapped");
    }

    #[test]
    fn upstream_proxy_url_accepts_https_with_port() {
        let addr = parse_upstream_proxy_url("https://proxy.corp.com:3130").unwrap();
        assert_eq!(addr.host, "proxy.corp.com");
        assert_eq!(addr.port, 3130);
        assert!(addr.secure, "https:// is TLS-wrapped");
        // An explicit scheme-default port (:443) is accepted even though the
        // url crate normalizes it away in the parsed form.
        let addr = parse_upstream_proxy_url("https://proxy.corp.com:443").unwrap();
        assert_eq!(addr.port, 443);
        assert!(addr.secure);
    }

    #[test]
    fn upstream_proxy_url_rejects_missing_scheme() {
        for url in [
            "proxy.corp.com",
            "proxy.corp.com:3128",
            "user:pass@proxy.corp.com:8080",
        ] {
            assert_eq!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::MissingScheme),
                "{url}"
            );
        }
    }

    #[test]
    fn upstream_proxy_url_rejects_missing_port() {
        for url in [
            "http://proxy.corp.com",
            "http://proxy.corp.com/",
            "http://proxy.corp.com:",
            "http://[fd00::1]",
            "http://[fd00::1]:",
        ] {
            assert_eq!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::MissingPort),
                "{url}"
            );
        }
        // An explicit scheme-default port is accepted even though the url
        // crate normalizes it away in the parsed form.
        let addr = parse_upstream_proxy_url("http://proxy.corp.com:80").unwrap();
        assert_eq!(addr.port, 80);
    }

    #[test]
    fn upstream_proxy_url_rejects_zero_port() {
        // Port 0 parses as an explicit port but is not connectable; reject it
        // up front instead of failing every proxied dial later.
        for url in ["http://proxy.corp.com:0", "http://[fd00::1]:0"] {
            assert_eq!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::ZeroPort),
                "{url}"
            );
        }
    }

    #[test]
    fn upstream_proxy_url_ipv6_host_is_bracket_free() {
        let addr = parse_upstream_proxy_url("http://[fd00::1]:8080").unwrap();
        assert_eq!(addr.host, "fd00::1");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn upstream_proxy_url_rejects_socks_schemes() {
        // http:// and https:// are supported; only other schemes (SOCKS, etc.)
        // are rejected.
        for url in [
            "socks5://proxy:1080",
            "socks4://proxy:1080",
            "ftp://proxy:21",
        ] {
            assert!(
                matches!(
                    parse_upstream_proxy_url(url),
                    Err(UpstreamProxyUrlError::UnsupportedScheme(_))
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn upstream_proxy_url_rejects_inline_credentials() {
        for url in ["http://user:pass@proxy:8080", "http://user@proxy:8080"] {
            assert_eq!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::InlineCredentials)
            );
        }
    }

    #[test]
    fn upstream_proxy_url_rejects_empty_and_invalid() {
        assert_eq!(
            parse_upstream_proxy_url("  "),
            Err(UpstreamProxyUrlError::Empty)
        );
        assert!(matches!(
            parse_upstream_proxy_url("http://proxy:notaport"),
            Err(UpstreamProxyUrlError::Invalid(_))
        ));
        assert!(parse_upstream_proxy_url("http://").is_err());
    }

    #[test]
    fn upstream_proxy_url_rejects_path_query_and_fragment() {
        for (url, component) in [
            ("http://proxy.corp.com:8080/some/path", "path"),
            ("http://proxy.corp.com:8080?x=1", "query"),
            ("http://proxy.corp.com:8080/?x=1", "query"),
            ("http://proxy.corp.com:8080#frag", "fragment"),
        ] {
            assert_eq!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::UnexpectedComponent(component)),
                "{url}"
            );
        }
        // A bare trailing slash is URL normalization, not a real path.
        let addr = parse_upstream_proxy_url("http://proxy.corp.com:8080/").unwrap();
        assert_eq!(addr.host, "proxy.corp.com");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn upstream_proxy_credential_accepts_user_pass_and_trims() {
        assert_eq!(
            parse_upstream_proxy_credential("user:pass\n"),
            Ok("user:pass")
        );
        // The password may be empty and may contain further colons.
        assert_eq!(parse_upstream_proxy_credential("user:"), Ok("user:"));
        assert_eq!(
            parse_upstream_proxy_credential("user:p@:ss"),
            Ok("user:p@:ss")
        );
    }

    #[test]
    fn upstream_proxy_credential_rejects_empty() {
        for raw in ["", "  ", "\n"] {
            assert_eq!(
                parse_upstream_proxy_credential(raw),
                Err(UpstreamProxyCredentialError::Empty)
            );
        }
    }

    #[test]
    fn upstream_proxy_credential_rejects_control_characters() {
        for raw in ["user:pa\r\nss", "user:pa\0ss", "user:pa\tss"] {
            assert_eq!(
                parse_upstream_proxy_credential(raw),
                Err(UpstreamProxyCredentialError::ControlCharacters)
            );
        }
    }

    #[test]
    fn upstream_proxy_credential_rejects_malformed_user_pass_form() {
        assert_eq!(
            parse_upstream_proxy_credential("userpass"),
            Err(UpstreamProxyCredentialError::MissingSeparator)
        );
        assert_eq!(
            parse_upstream_proxy_credential(":pass"),
            Err(UpstreamProxyCredentialError::EmptyUser)
        );
    }

    #[test]
    fn credential_file_reads_within_the_size_bound() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "user:pass\n").unwrap();
        let raw = read_upstream_proxy_credential_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(parse_upstream_proxy_credential(&raw), Ok("user:pass"));
    }

    #[test]
    fn credential_file_rejects_oversized_files() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let huge = vec![b'a'; usize::try_from(MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES + 1).unwrap()];
        std::fs::write(file.path(), &huge).unwrap();
        let err = read_upstream_proxy_credential_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }

    #[test]
    fn credential_file_rejects_non_regular_files() {
        // A directory is a non-regular path; /dev/zero would be rejected the
        // same way (not a regular file) without risking an unbounded read.
        let dir = tempfile::tempdir().unwrap();
        let err = read_upstream_proxy_credential_file(dir.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("regular file"), "{err}");

        if Path::new("/dev/zero").exists() {
            let err = read_upstream_proxy_credential_file("/dev/zero").unwrap_err();
            assert!(err.contains("regular file"), "{err}");
        }
    }

    #[test]
    fn credential_file_missing_path_is_an_error() {
        let err = read_upstream_proxy_credential_file("/nonexistent/proxy-auth").unwrap_err();
        assert!(err.contains("open proxy auth file"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_rejects_fifo_without_hanging() {
        // A FIFO with no writer would block a blocking open() forever. The
        // reader opens non-blocking and rejects the non-regular file, so it
        // must return promptly even though nothing ever opens the write end.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("proxy-auth-fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();

        let start = std::time::Instant::now();
        let err = read_upstream_proxy_credential_file(fifo.to_str().unwrap()).unwrap_err();
        assert!(err.contains("regular file"), "{err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "reading a FIFO must not block"
        );
    }

    /// Build settings with only the fields a case cares about.
    #[test]
    fn ca_bundle_file_accepts_a_real_certificate() {
        // The positive case that pins host acceptance to guest acceptance:
        // what the driver stages is exactly what rustls will trust.
        let cert = rcgen::generate_simple_self_signed(vec!["proxy.corp.example".to_string()])
            .expect("test CA");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-ca.pem");
        std::fs::write(&path, cert.cert.pem()).unwrap();

        let pem =
            read_upstream_proxy_ca_bundle_file(path.to_str().unwrap(), "proxy_ca_bundle").unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn ca_bundle_file_rejects_non_regular_and_oversized_paths() {
        // /dev/zero is the case that matters: an unbounded read of it would
        // exhaust gateway or driver memory on any authorized sandbox create.
        let dir = tempfile::tempdir().unwrap();
        let err =
            read_upstream_proxy_ca_bundle_file(dir.path().to_str().unwrap(), "proxy_ca_bundle")
                .unwrap_err();
        assert!(err.contains("regular file"), "{err}");
        assert!(err.contains("proxy_ca_bundle"), "{err}");

        if Path::new("/dev/zero").exists() {
            let err =
                read_upstream_proxy_ca_bundle_file("/dev/zero", "proxy_ca_bundle").unwrap_err();
            assert!(err.contains("regular file"), "{err}");
        }

        let oversized = dir.path().join("oversized.pem");
        std::fs::write(
            &oversized,
            vec![b'x'; usize::try_from(MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err =
            read_upstream_proxy_ca_bundle_file(oversized.to_str().unwrap(), "proxy_ca_bundle")
                .unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn ca_bundle_file_missing_path_is_an_error() {
        let err =
            read_upstream_proxy_ca_bundle_file("/nonexistent/proxy-ca.pem", "proxy_ca_bundle")
                .unwrap_err();
        assert!(err.contains("could not be read"), "{err}");
    }

    #[test]
    fn ca_bundle_rejects_a_file_without_certificate_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-ca.pem");
        std::fs::write(&path, "this is not a certificate\n").unwrap();
        let err = read_upstream_proxy_ca_bundle_file(path.to_str().unwrap(), "proxy_ca_bundle")
            .unwrap_err();
        assert!(err.contains("no PEM certificate blocks"), "{err}");

        std::fs::write(&path, "").unwrap();
        let err = read_upstream_proxy_ca_bundle_file(path.to_str().unwrap(), "proxy_ca_bundle")
            .unwrap_err();
        assert!(err.contains("no PEM certificate blocks"), "{err}");
    }

    #[test]
    fn ca_bundle_rejects_pem_blocks_holding_invalid_der() {
        // Passes `rustls_pemfile::certs` but contributes no trust anchor, so
        // accepting it on the host would break every guest after boot.
        let err = validate_upstream_proxy_ca_bundle_pem(
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            "/etc/openshell/tls/proxy-ca.pem",
            "proxy_ca_bundle",
        )
        .unwrap_err();
        assert!(err.contains("no usable trust anchors"), "{err}");
    }

    fn proxy_settings(url: Option<&str>) -> UpstreamProxySettings<'_> {
        UpstreamProxySettings {
            url,
            ..UpstreamProxySettings::default()
        }
    }

    #[test]
    fn upstream_proxy_settings_accept_a_bare_proxy_url() {
        validate_upstream_proxy_settings(&proxy_settings(Some("http://proxy.corp.com:3128")))
            .expect("a lone proxy URL is a complete configuration");
    }

    #[test]
    fn upstream_proxy_settings_accept_an_empty_configuration() {
        validate_upstream_proxy_settings(&UpstreamProxySettings::default())
            .expect("no proxy configured at all is valid");
    }

    #[test]
    fn upstream_proxy_settings_reject_an_unsupported_scheme() {
        let err = validate_upstream_proxy_settings(&proxy_settings(Some("socks5://proxy:1080")))
            .expect_err("only http:// and https:// proxies are supported");
        assert!(err.starts_with("https_proxy "), "{err}");
        assert!(err.contains("unsupported proxy scheme"), "{err}");
    }

    #[test]
    fn upstream_proxy_settings_reject_inline_credentials_by_naming_the_auth_file() {
        let err = validate_upstream_proxy_settings(&proxy_settings(Some("http://u:p@proxy:3128")))
            .expect_err("inline credentials would be stored in gateway config");
        assert!(err.contains("proxy_auth_file"), "{err}");
    }

    #[test]
    fn upstream_proxy_settings_reject_an_empty_proxy_url() {
        let err = validate_upstream_proxy_settings(&proxy_settings(Some("   ")))
            .expect_err("present-but-empty is a misconfiguration, not 'unset'");
        assert_eq!(err, "https_proxy must not be empty when set");
    }

    #[test]
    fn upstream_proxy_settings_reject_auxiliary_keys_without_a_proxy_url() {
        // Each auxiliary key implies a proxy boundary the operator believed
        // was in effect; accepting one while every dial goes direct would
        // hide a fail-open state.
        for (settings, key) in [
            (
                UpstreamProxySettings {
                    no_proxy: Some("10.0.0.0/8"),
                    ..UpstreamProxySettings::default()
                },
                "no_proxy",
            ),
            (
                UpstreamProxySettings {
                    auth_file: Some("/etc/openshell/secrets/proxy-auth"),
                    ..UpstreamProxySettings::default()
                },
                "proxy_auth_file",
            ),
            (
                UpstreamProxySettings {
                    connect_by_hostname: Some(true),
                    ..UpstreamProxySettings::default()
                },
                "proxy_connect_by_hostname",
            ),
            (
                UpstreamProxySettings {
                    ca_bundle: Some("/etc/openshell/tls/proxy-ca.pem"),
                    ..UpstreamProxySettings::default()
                },
                "proxy_ca_bundle",
            ),
        ] {
            let err = validate_upstream_proxy_settings(&settings)
                .expect_err("an auxiliary key without a proxy URL must fail closed");
            assert_eq!(
                err,
                format!("{key} is set but no https_proxy is configured")
            );
        }
    }

    #[test]
    fn upstream_proxy_settings_reject_empty_auxiliary_values() {
        for (settings, expected) in [
            (
                UpstreamProxySettings {
                    url: Some("http://proxy:3128"),
                    no_proxy: Some(" "),
                    ..UpstreamProxySettings::default()
                },
                "no_proxy must not be empty when set; omit it instead",
            ),
            (
                UpstreamProxySettings {
                    url: Some("http://proxy:3128"),
                    auth_file: Some(""),
                    ..UpstreamProxySettings::default()
                },
                "proxy_auth_file must not be empty when set",
            ),
            (
                UpstreamProxySettings {
                    url: Some("http://proxy:3128"),
                    ca_bundle: Some(""),
                    ..UpstreamProxySettings::default()
                },
                "proxy_ca_bundle must not be empty when set",
            ),
        ] {
            let err = validate_upstream_proxy_settings(&settings)
                .expect_err("present-but-empty must never be treated as unset");
            assert_eq!(err, expected);
        }
    }

    #[test]
    fn upstream_proxy_credentials_require_the_cleartext_acknowledgement() {
        let err = validate_upstream_proxy_settings(&UpstreamProxySettings {
            url: Some("http://proxy:3128"),
            auth_file: Some("/etc/openshell/secrets/proxy-auth"),
            ..UpstreamProxySettings::default()
        })
        .expect_err("Basic auth to an http:// proxy is cleartext on the wire");
        assert!(err.contains("proxy_auth_allow_insecure"), "{err}");

        validate_upstream_proxy_settings(&UpstreamProxySettings {
            url: Some("http://proxy:3128"),
            auth_file: Some("/etc/openshell/secrets/proxy-auth"),
            auth_allow_insecure: Some(true),
            ..UpstreamProxySettings::default()
        })
        .expect("the explicit acknowledgement makes the exposure an operator decision");
    }

    #[test]
    fn upstream_proxy_credentials_need_no_acknowledgement_for_an_https_proxy() {
        // The credential travels inside the verified TLS session to the proxy.
        validate_upstream_proxy_settings(&UpstreamProxySettings {
            url: Some("https://proxy:3130"),
            auth_file: Some("/etc/openshell/secrets/proxy-auth"),
            ..UpstreamProxySettings::default()
        })
        .expect("an https:// proxy does not expose the credential on the wire");

        // ... but setting it anyway is tolerated rather than an error.
        validate_upstream_proxy_settings(&UpstreamProxySettings {
            url: Some("https://proxy:3130"),
            auth_file: Some("/etc/openshell/secrets/proxy-auth"),
            auth_allow_insecure: Some(true),
            ..UpstreamProxySettings::default()
        })
        .expect("a redundant acknowledgement is tolerated");
    }

    #[test]
    fn upstream_proxy_acknowledgement_without_credentials_is_rejected() {
        // Including `= false`: the operator believed an auth file was
        // configured, so the mismatch is surfaced rather than ignored.
        for ack in [Some(true), Some(false)] {
            let err = validate_upstream_proxy_settings(&UpstreamProxySettings {
                url: Some("http://proxy:3128"),
                auth_allow_insecure: ack,
                ..UpstreamProxySettings::default()
            })
            .expect_err("the acknowledgement is meaningless without a credential");
            assert_eq!(
                err,
                "proxy_auth_allow_insecure is set but no proxy_auth_file is configured"
            );
        }
    }

    #[test]
    fn upstream_proxy_ca_bundle_is_valid_with_a_plain_http_proxy() {
        // A TLS-intercepting proxy can be reached over plain HTTP while still
        // re-signing tunneled server certificates with its own CA.
        validate_upstream_proxy_settings(&UpstreamProxySettings {
            url: Some("http://proxy:3128"),
            ca_bundle: Some("/etc/openshell/tls/proxy-ca.pem"),
            ..UpstreamProxySettings::default()
        })
        .expect("an intercepting proxy's CA is meaningful without an https:// proxy URL");
    }
}
