// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility helpers shared across compute-driver crates.

use std::path::PathBuf;

use crate::proto::compute::v1::{DriverSandbox, GetCapabilitiesResponse};

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

/// Label selector that matches all OpenShell-managed resources which carry a
/// sandbox ID label.  Used by list and watch operations to exclude foreign
/// resources from the same namespace.
pub fn openshell_sandbox_label_selector() -> String {
    format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_SANDBOX_ID}")
}

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
    /// The URL uses a scheme other than `http` (TLS and SOCKS proxies are
    /// not supported by the sandbox supervisor).
    #[error(
        "unsupported proxy scheme '{0}': only http:// forward proxies are \
         supported by the sandbox supervisor"
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
/// The accepted grammar is exactly `http://host:port`: the scheme and the
/// port must both be explicit, only `http://` proxies are accepted, and
/// inline userinfo is rejected. The URL must address the proxy only: a path
/// (other than a bare trailing `/`), query, or fragment is rejected rather
/// than silently discarded.
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

    if !parsed.scheme().eq_ignore_ascii_case("http") {
        return Err(UpstreamProxyUrlError::UnsupportedScheme(
            parsed.scheme().to_string(),
        ));
    }
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
    // Explicit-port presence was verified above; `port()` is `None` only
    // when the URL spells out the scheme default (`:80`), which the url crate
    // normalizes away.
    let port = parsed.port().unwrap_or(80);
    if port == 0 {
        return Err(UpstreamProxyUrlError::ZeroPort);
    }
    Ok(UpstreamProxyAddr { host, port })
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
    use std::io::Read as _;

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

    let file = open_result.map_err(|e| format!("failed to open proxy auth file '{path}': {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to stat proxy auth file '{path}': {e}"))?;
    if !metadata.is_file() {
        return Err(format!("proxy auth file '{path}' is not a regular file"));
    }
    if metadata.len() > MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES {
        return Err(format!(
            "proxy auth file '{path}' exceeds the {MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES}-byte limit"
        ));
    }
    // Bound the read even if the file grows between stat and read.
    let mut buf = String::new();
    file.take(MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|e| format!("failed to read proxy auth file '{path}': {e}"))?;
    if buf.len() as u64 > MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES {
        return Err(format!(
            "proxy auth file '{path}' exceeds the {MAX_UPSTREAM_PROXY_CREDENTIAL_BYTES}-byte limit"
        ));
    }
    Ok(buf)
}

/// Return the XDG state path for a driver's sandbox JWT token file.
///
/// The resulting path is `$XDG_STATE_HOME/openshell/<driver_subdir>[/<namespace>]/<sandbox_id>/sandbox.jwt`.
///
/// `driver_subdir` is driver-specific, e.g. `"docker-sandbox-tokens"` or
/// `"podman-sandbox-tokens"`.  When `namespace` is `Some`, it is appended as
/// an additional path component (with `/` and `\` replaced by `-`).
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

/// Build a [`GetCapabilitiesResponse`] from the common driver capability fields.
///
/// Every compute driver constructs this response with the same fields. Shared
/// here to avoid repeating the struct literal in each driver crate.
pub fn build_capabilities_response(
    driver_name: &str,
    driver_version: impl Into<String>,
    default_image: impl Into<String>,
) -> GetCapabilitiesResponse {
    GetCapabilitiesResponse {
        driver_name: driver_name.to_string(),
        driver_version: driver_version.into(),
        default_image: default_image.into(),
    }
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
// Supervisor image helpers (shared by Docker and Podman drivers)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_proxy_url_accepts_http_with_port() {
        let addr = parse_upstream_proxy_url("http://proxy.corp.com:8080").unwrap();
        assert_eq!(addr.host, "proxy.corp.com");
        assert_eq!(addr.port, 8080);
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
    fn upstream_proxy_url_rejects_tls_and_socks_schemes() {
        for url in ["https://proxy:443", "socks5://proxy:1080"] {
            assert!(matches!(
                parse_upstream_proxy_url(url),
                Err(UpstreamProxyUrlError::UnsupportedScheme(_))
            ));
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

        if std::path::Path::new("/dev/zero").exists() {
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
}
