// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport policy for gateway-to-gateway (peer) RPCs.
//!
//! Peer RPCs carry the gateway `ServiceAccount` bearer token and whole relayed
//! sandbox sessions, so the dialer decides what it may dial: `https://` with an
//! explicit CA, or plaintext `http://` only when an operator explicitly opts
//! out on a plaintext gateway. Nothing else.
//!
//! Unit-test builds of this crate (`cfg(test)`) also dial numeric-loopback
//! `http://` peers, so in-process tests can stand up fake peers. Production
//! builds and `tests/` integration targets never do.

use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use openshell_core::settings::parse_bool_like;
use openshell_core::{Config, Error, Result, TlsConfig};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{CertificateError, InconsistentKeys, RootCertStore};
use tonic::Status;
use tracing::{debug, warn};

use crate::supervisor_session::PeerTlsClientConfig;

/// Explicit, loud opt-out that lets a plaintext gateway use `http://` peers.
pub const PEER_ALLOW_INSECURE_TRANSPORT_ENV: &str = "OPENSHELL_PEER_ALLOW_INSECURE_TRANSPORT";

/// Appended to every peer-transport startup error.
pub const PEER_TRANSPORT_DOCS_URL: &str = "https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration#peer-transport-contract";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDialScheme {
    Https,
    Http,
}

/// How the plaintext opt-out resolved for this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecureOptOut {
    Off,
    IgnoredOnTlsGateway,
    Active,
}

/// Default fails closed: no plaintext, and https refuses to dial because no CA
/// is configured.
#[derive(Debug, Default)]
pub struct PeerTransportPolicy {
    allow_plaintext: bool,
    tls: PeerTlsClientConfig,
}

impl PeerTransportPolicy {
    pub fn new(allow_plaintext: bool, tls: PeerTlsClientConfig) -> Self {
        Self {
            allow_plaintext,
            tls,
        }
    }

    /// Resolves the plaintext opt-out. Pure: no logging and no env access.
    ///
    /// The opt-out is honored only on a plaintext gateway. An unrecognized
    /// value fails startup instead of silently meaning false.
    pub fn resolve(
        opt_out: Option<&str>,
        gateway_serves_tls: bool,
        tls: PeerTlsClientConfig,
    ) -> Result<(Self, InsecureOptOut)> {
        let requested = match opt_out {
            Some(raw) if !raw.trim().is_empty() => parse_bool_like(raw).ok_or_else(|| {
                startup_error(format!(
                    "{PEER_ALLOW_INSECURE_TRANSPORT_ENV} must be true or false, got {raw:?}"
                ))
            })?,
            _ => false,
        };
        let outcome = match (requested, gateway_serves_tls) {
            (false, _) => InsecureOptOut::Off,
            (true, true) => InsecureOptOut::IgnoredOnTlsGateway,
            (true, false) => InsecureOptOut::Active,
        };
        Ok((Self::new(outcome == InsecureOptOut::Active, tls), outcome))
    }

    /// Reads the peer transport env once and logs how the opt-out resolved.
    ///
    /// `dials_peers` is true on a `PostgreSQL` store: such a gateway dials owner
    /// replicas even when it advertises no peer endpoint of its own.
    pub fn from_env(config: &Config, dials_peers: bool) -> Result<Self> {
        let opt_out = std::env::var(PEER_ALLOW_INSECURE_TRANSPORT_ENV).ok();
        let (policy, outcome) = Self::resolve(
            opt_out.as_deref(),
            config.tls.is_some(),
            PeerTlsClientConfig::from_env(),
        )?;
        match outcome {
            InsecureOptOut::Active if dials_peers => warn!(
                env = PEER_ALLOW_INSECURE_TRANSPORT_ENV,
                "gateway peer plaintext transport is enabled: peer RPCs may use http://, exposing \
                 the gateway ServiceAccount token and relayed sandbox traffic to the pod network; \
                 use only on a trusted network"
            ),
            InsecureOptOut::Active => debug!(
                env = PEER_ALLOW_INSECURE_TRANSPORT_ENV,
                "gateway peer plaintext transport opt-out is set but inactive because this \
                 gateway does not route to peers"
            ),
            InsecureOptOut::IgnoredOnTlsGateway => warn!(
                env = PEER_ALLOW_INSECURE_TRANSPORT_ENV,
                "gateway peer insecure transport opt-out is ignored because this gateway serves \
                 TLS; peers must use https"
            ),
            InsecureOptOut::Off => {}
        }
        Ok(policy)
    }

    pub fn allows_plaintext(&self) -> bool {
        self.allow_plaintext
    }

    pub fn tls(&self) -> &PeerTlsClientConfig {
        &self.tls
    }

    /// Dial-time rule. No I/O; refusals never name the endpoint because
    /// callers surface them to users.
    pub fn check_dial(&self, endpoint: &str) -> std::result::Result<PeerDialScheme, Status> {
        // Unit tests dial in-process fake peers on 127.0.0.1 through the
        // default policy; production builds never admit loopback plaintext.
        self.check_dial_with(endpoint, cfg!(test))
    }

    /// `check_dial` plus the https settings every dial needs: a peer CA and,
    /// if configured, a complete client identity. A refusal here means no
    /// dial to `endpoint` can succeed under this policy. No I/O.
    pub fn preflight(&self, endpoint: &str) -> std::result::Result<PeerDialScheme, Status> {
        let scheme = self.check_dial(endpoint)?;
        if scheme == PeerDialScheme::Https {
            self.tls.identity_files()?;
            self.tls.require_ca_file()?;
        }
        Ok(scheme)
    }

    fn check_dial_with(
        &self,
        endpoint: &str,
        allow_test_loopback: bool,
    ) -> std::result::Result<PeerDialScheme, Status> {
        let (scheme, host) = classify_endpoint(endpoint)
            .map_err(|rejection| Status::failed_precondition(rejection.dial_message()))?;
        match scheme {
            PeerDialScheme::Https => Ok(scheme),
            PeerDialScheme::Http
                if self.allow_plaintext || (allow_test_loopback && is_numeric_loopback(&host)) =>
            {
                Ok(scheme)
            }
            PeerDialScheme::Http => Err(Status::failed_precondition(format!(
                "gateway peer transport refused a plaintext http:// peer endpoint; peer RPCs \
                 carry the gateway ServiceAccount token and relayed sandbox traffic, so they \
                 require https. Serve TLS on every gateway replica, or set \
                 {PEER_ALLOW_INSECURE_TRANSPORT_ENV}=true on plaintext gateways to accept the risk"
            ))),
        }
    }

    /// Startup rule for the endpoint this replica advertises to its peers.
    ///
    /// Called only when peer routing is active. It also checks that this
    /// gateway's own server certificate would pass peer verification: every
    /// replica serves the same TLS configuration, so a local check of the
    /// certificate a peer's SNI selects covers all peers. Likewise, a listener
    /// that requires client certificates needs a peer client identity.
    pub fn validate_own_endpoint(
        &self,
        endpoint: &str,
        server_tls: Option<&TlsConfig>,
    ) -> Result<()> {
        let (scheme, host) = classify_endpoint(endpoint).map_err(|rejection| {
            startup_error(format!(
                "gateway peer endpoint {endpoint} is not dialable by peers ({}); set an https:// \
                 OPENSHELL_PEER_ENDPOINT",
                rejection.reason()
            ))
        })?;
        match scheme {
            PeerDialScheme::Http => {
                if !self.allows_plaintext() {
                    return Err(startup_error(format!(
                        "gateway peer endpoint {endpoint} is plaintext, but peer routing \
                         (PostgreSQL store with a peer endpoint) requires https; serve TLS on \
                         every gateway replica, or set {PEER_ALLOW_INSECURE_TRANSPORT_ENV}=true \
                         on a plaintext gateway to accept cleartext peer traffic"
                    )));
                }
                // Plaintext peers never load TLS materials, but any that are
                // configured must still be usable (a no-op when none are set).
                validate_tls_materials(&self.tls, false)
            }
            PeerDialScheme::Https => {
                validate_tls_materials(&self.tls, true)?;
                if self.tls.server_name.is_none() && host.parse::<IpAddr>().is_ok() {
                    warn!(
                        peer_endpoint = endpoint,
                        "gateway peer endpoint host is an IP address and \
                         OPENSHELL_PEER_TLS_SERVER_NAME is unset; peers will verify certificates \
                         against the IP"
                    );
                }
                if let Some(server_tls) = server_tls {
                    require_client_identity(server_tls, &self.tls)?;
                    verify_own_server_certificate(server_tls, &self.tls, &host)?;
                }
                Ok(())
            }
        }
    }
}

/// Renders `err` and each of its sources, joined by `": "`.
///
/// tonic's transport error prints only "transport error"; the TLS cause lives
/// in its source chain. A segment equal to the previous one is skipped, since
/// wrappers such as tonic's connect error repeat their inner error's text.
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = err.to_string();
    let mut previous = chain.clone();
    let mut source = err.source();
    while let Some(cause) = source {
        let segment = cause.to_string();
        if segment != previous {
            chain.push_str(": ");
            chain.push_str(&segment);
        }
        previous = segment;
        source = cause.source();
    }
    chain
}

enum EndpointRejection {
    Empty,
    UnixSocket,
    Malformed,
    MissingHost,
    Scheme(String),
}

impl EndpointRejection {
    fn dial_message(&self) -> String {
        match self {
            Self::Empty => "gateway peer transport refused an empty peer endpoint".to_string(),
            Self::UnixSocket => {
                "gateway peer transport refused a unix socket peer endpoint".to_string()
            }
            Self::Malformed | Self::MissingHost => {
                "gateway peer transport refused a malformed peer endpoint".to_string()
            }
            Self::Scheme(scheme) => format!(
                "gateway peer transport refused peer endpoint scheme '{scheme}'; only https:// \
                 (or http:// with {PEER_ALLOW_INSECURE_TRANSPORT_ENV}=true on a plaintext \
                 gateway) is dialed"
            ),
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Empty => "empty".to_string(),
            Self::UnixSocket => "unix socket".to_string(),
            Self::Malformed => "malformed".to_string(),
            Self::MissingHost => "missing host".to_string(),
            Self::Scheme(scheme) => format!("scheme '{scheme}'"),
        }
    }
}

/// Classifies a peer endpoint the way tonic would dial it.
///
/// tonic dials any `unix:` string as a Unix socket and any scheme other than
/// `https` as plaintext TCP, so only `https` and `http` pass. Returns the host
/// with IPv6 brackets stripped.
fn classify_endpoint(
    endpoint: &str,
) -> std::result::Result<(PeerDialScheme, String), EndpointRejection> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(EndpointRejection::Empty);
    }
    if endpoint
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("unix:"))
    {
        return Err(EndpointRejection::UnixSocket);
    }
    let uri = http::Uri::try_from(endpoint).map_err(|_| EndpointRejection::Malformed)?;
    let scheme = match uri.scheme_str() {
        Some("https") => PeerDialScheme::Https,
        Some("http") => PeerDialScheme::Http,
        other => {
            return Err(EndpointRejection::Scheme(
                other.unwrap_or_default().to_string(),
            ));
        }
    };
    let host = uri
        .host()
        .map(|host| {
            host.strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host)
        })
        .filter(|host| !host.is_empty())
        .ok_or(EndpointRejection::MissingHost)?;
    Ok((scheme, host.to_string()))
}

/// Brackets a bare IPv6 host in `<scheme>://<host>:<port>[/path]`.
///
/// Kubernetes substitutes the chart's `$(OPENSHELL_POD_IP)` into the
/// Deployment peer endpoint without brackets, and an unbracketed IPv6
/// authority is not a valid URI. The last `:`-separated segment is read as
/// the port, since the unbracketed form cannot carry both. Any other endpoint
/// is returned unchanged.
pub fn bracket_ipv6_endpoint_host(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return endpoint.to_string();
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    match authority.rsplit_once(':') {
        Some((host, port)) if host.parse::<Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok() => {
            format!("{scheme}://[{host}]:{port}{path}")
        }
        _ => endpoint.to_string(),
    }
}

/// Numeric loopback only: `localhost` resolves through DNS or the hosts file.
fn is_numeric_loopback(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        Ok(IpAddr::V6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Err(_) => false,
    }
}

fn startup_error(message: impl std::fmt::Display) -> Error {
    Error::config(format!("{message}; see {PEER_TRANSPORT_DOCS_URL}"))
}

/// Parses the peer CA file into a root store holding at least one anchor.
fn load_peer_ca_roots(ca_path: &Path) -> Result<RootCertStore> {
    let certs = crate::tls::load_certs(ca_path).map_err(|err| {
        startup_error(format!(
            "gateway peer TLS CA {} is unusable: {err}",
            ca_path.display()
        ))
    })?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(startup_error(format!(
            "gateway peer TLS CA {} contains no usable CA certificates",
            ca_path.display()
        )));
    }
    Ok(roots)
}

/// Parses the configured peer TLS files so a bad file fails startup instead of
/// every later handshake.
fn validate_tls_materials(tls: &PeerTlsClientConfig, require_ca: bool) -> Result<()> {
    let identity = tls
        .identity_files()
        .map_err(|status| startup_error(status.message()))?;
    let ca_path = if require_ca {
        Some(
            tls.require_ca_file()
                .map_err(|status| startup_error(status.message()))?,
        )
    } else {
        tls.ca_file.as_deref()
    };
    if let Some(ca_path) = ca_path {
        load_peer_ca_roots(ca_path)?;
    }
    if let Some((cert_path, key_path)) = identity {
        let certified = crate::tls::load_certified_key(cert_path, key_path).map_err(|err| {
            startup_error(format!(
                "gateway peer TLS client identity {} / {} is unusable: {err}",
                cert_path.display(),
                key_path.display()
            ))
        })?;
        match certified.keys_match() {
            // `Unknown`: the key type cannot report its public key, so there is
            // nothing to compare.
            Ok(()) | Err(rustls::Error::InconsistentKeys(InconsistentKeys::Unknown)) => {}
            Err(rustls::Error::InconsistentKeys(InconsistentKeys::KeyMismatch)) => {
                return Err(startup_error(format!(
                    "gateway peer TLS certificate {} and key {} do not match",
                    cert_path.display(),
                    key_path.display()
                )));
            }
            Err(err) => {
                return Err(startup_error(format!(
                    "gateway peer TLS client identity {} / {} is unusable: {err}",
                    cert_path.display(),
                    key_path.display()
                )));
            }
        }
    }
    tls.validate_server_name()
        .map_err(|status| startup_error(status.message()))
}

/// Every replica shares this listener, so one that requires client
/// certificates refuses a peer that has no client identity to present.
fn require_client_identity(server_tls: &TlsConfig, tls: &PeerTlsClientConfig) -> Result<()> {
    let requires_client_cert =
        server_tls.require_client_auth && server_tls.client_ca_path.is_some();
    let identity = tls
        .identity_files()
        .map_err(|status| startup_error(status.message()))?;
    if requires_client_cert && identity.is_none() {
        return Err(startup_error(
            "the gateway listener requires client certificates, but \
             OPENSHELL_PEER_TLS_CERT_FILE and OPENSHELL_PEER_TLS_KEY_FILE are unset, so peers \
             would refuse this gateway's handshake; set both to a client certificate signed by \
             the gateway client CA",
        ));
    }
    Ok(())
}

/// The certificate a peer dialing `peer_name` receives. SNI selects the
/// external certificate for its configured names; rustls sends no SNI for an
/// IP address, strips one trailing dot from a DNS name (RFC 6066), and the
/// server compares the lowercased name. Verification still uses `peer_name`.
fn peer_facing_cert_path<'a>(server_tls: &'a TlsConfig, peer_name: &str) -> &'a Path {
    let sni = peer_name
        .strip_suffix('.')
        .unwrap_or(peer_name)
        .to_ascii_lowercase();
    match server_tls.external_cert_path.as_deref() {
        Some(external)
            if peer_name.parse::<IpAddr>().is_err()
                && server_tls
                    .external_server_names
                    .iter()
                    .any(|name| crate::tls::sni_matches(name, &sni)) =>
        {
            external
        }
        _ => &server_tls.cert_path,
    }
}

/// Verifies this gateway's server certificate the way a peer would: against
/// the peer CA alone, for the peer server name (or the endpoint host).
fn verify_own_server_certificate(
    server_tls: &TlsConfig,
    tls: &PeerTlsClientConfig,
    endpoint_host: &str,
) -> Result<()> {
    let ca_path = tls
        .require_ca_file()
        .map_err(|status| startup_error(status.message()))?;
    let peer_name = tls.server_name.as_deref().unwrap_or(endpoint_host);
    let cert_path = peer_facing_cert_path(server_tls, peer_name);
    let selected_by = if cert_path == server_tls.cert_path {
        ""
    } else {
        " (served to peers because the peer name matches external_server_names)"
    };
    let refused = |err: &dyn std::fmt::Display| {
        startup_error(format!(
            "gateway server certificate {}{selected_by} would fail peer verification against \
             OPENSHELL_PEER_TLS_CA_FILE {} for peer name {peer_name:?}: {err}; the server \
             certificate must chain to that CA and carry that name",
            cert_path.display(),
            ca_path.display()
        ))
    };

    let roots = load_peer_ca_roots(ca_path)?;
    let chain = crate::tls::load_certs(cert_path).map_err(|err| refused(&err))?;
    let Some((end_entity, intermediates)) = chain.split_first() else {
        return Err(refused(&"no certificates found in file"));
    };
    let server_name = ServerName::try_from(peer_name.to_string()).map_err(|err| refused(&err))?;
    // Explicit provider: `builder()` depends on a process-wide default.
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .map_err(|err| refused(&err))?;

    let verify_at =
        |time| verifier.verify_server_cert(end_entity, intermediates, &server_name, &[], time);
    match verify_at(UnixTime::now()) {
        Ok(_) => Ok(()),
        // Peers reject it at handshake anyway; renewal is the PKI job's or
        // cert-manager's concern, so an expiring certificate adds no crash.
        Err(err) if is_validity_window_error(&err) => {
            // webpki checks the validity window before the issuer and the
            // name, so check those at a time inside the window first.
            if let Some(inside) = validity_window_bound(&err)
                && let Err(inner) = verify_at(inside)
                && !is_validity_window_error(&inner)
            {
                return Err(refused(&inner));
            }
            warn!(
                "gateway server certificate {} is outside its validity period; peers will reject \
                 it until it is renewed: {err}",
                cert_path.display()
            );
            Ok(())
        }
        Err(err) => Err(refused(&err)),
    }
}

fn is_validity_window_error(err: &rustls::Error) -> bool {
    matches!(
        err,
        rustls::Error::InvalidCertificate(
            CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. }
        )
    )
}

/// The validity-window bound `err` reports. webpki's bounds are inclusive, so
/// that time is inside the window.
fn validity_window_bound(err: &rustls::Error) -> Option<UnixTime> {
    match err {
        rustls::Error::InvalidCertificate(CertificateError::ExpiredContext {
            not_after, ..
        }) => Some(*not_after),
        rustls::Error::InvalidCertificate(CertificateError::NotValidYetContext {
            not_before,
            ..
        }) => Some(*not_before),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
