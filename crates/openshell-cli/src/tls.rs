// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::inference_client::InferenceClient;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_sdk::EdgeAuthInterceptor;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

// `build_insecure_rustls_config` lives in the SDK (used by the SDK's
// transport stack and by CLI's HTTP health check). The other former
// `tls.rs` helpers (`build_rustls_config`, `build_tonic_tls_config`,
// `load_private_key`, `TlsMaterials`) were tied to mTLS and now live
// below as CLI-private legacy code — they will go away when mTLS is
// retired as an auth method.
pub use openshell_sdk::transport::build_insecure_rustls_config;

/// Concrete gRPC client type used by all commands.
pub type GrpcClient = OpenShellClient<InterceptedService<Channel, EdgeAuthInterceptor>>;
/// Concrete inference client type.
pub type GrpcInferenceClient = InferenceClient<InterceptedService<Channel, EdgeAuthInterceptor>>;

#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    /// Gateway name for resolving default cert directory.
    gateway_name: Option<String>,
    /// Edge auth bearer token — when set, disables mTLS client certs and
    /// injects authentication headers on every gRPC request instead.
    pub edge_token: Option<String>,
    /// OIDC bearer token — when set, injects `authorization: Bearer <token>`
    /// on every gRPC request. Takes precedence over `edge_token`.
    pub oidc_token: Option<String>,
    /// Skip TLS certificate verification for gateway connections.
    pub gateway_insecure: bool,
}

impl TlsOptions {
    pub fn new(ca: Option<PathBuf>, cert: Option<PathBuf>, key: Option<PathBuf>) -> Self {
        Self {
            ca,
            cert,
            key,
            gateway_name: None,
            edge_token: None,
            oidc_token: None,
            gateway_insecure: false,
        }
    }

    pub fn has_any(&self) -> bool {
        self.ca.is_some() || self.cert.is_some() || self.key.is_some()
    }

    /// Return the gateway name, if set.
    pub fn gateway_name(&self) -> Option<&str> {
        self.gateway_name.as_deref()
    }

    /// Set the gateway name for cert directory resolution.
    #[must_use]
    pub fn with_gateway_name(&self, name: &str) -> Self {
        Self {
            gateway_name: Some(name.to_string()),
            ..self.clone()
        }
    }

    #[must_use]
    pub fn with_default_paths(&self, server: &str) -> Self {
        let base = self
            .gateway_name
            .as_deref()
            .and_then(tls_dir_for_gateway)
            .or_else(|| default_tls_dir(server));
        Self {
            ca: self
                .ca
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("ca.crt"))),
            cert: self
                .cert
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("tls.crt"))),
            key: self
                .key
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("tls.key"))),
            gateway_name: self.gateway_name.clone(),
            ..self.clone()
        }
    }

    /// Returns `true` when using bearer token auth.
    pub fn is_bearer_auth(&self) -> bool {
        self.edge_token.is_some() || self.oidc_token.is_some()
    }

    /// Returns `true` when this `TlsOptions` carries a full mTLS client
    /// identity (cert + key on disk). Used by [`build_channel`] to route
    /// mTLS-authenticated gateways through the legacy inline path.
    pub fn has_mtls_identity(&self, server: &str) -> bool {
        let resolved = self.with_default_paths(server);
        resolved.cert.as_ref().is_some_and(|p| p.exists())
            && resolved.key.as_ref().is_some_and(|p| p.exists())
    }

    /// Convert this CLI-side `TlsOptions` into an SDK [`openshell_sdk::ClientConfig`]
    /// for non-mTLS gateways.
    ///
    /// Reads the CA cert from disk if a path resolves; a missing file is
    /// non-fatal and falls back to system roots (matches today's OIDC
    /// fallback behavior). Maps tokens to [`openshell_sdk::AuthConfig`]
    /// with OIDC taking precedence over `EdgeJwt` when both are set.
    ///
    /// mTLS materials are intentionally not carried through; gateways
    /// requiring client certificates are dispatched to the legacy inline
    /// path in [`build_channel`] before this conversion is reached.
    pub fn to_client_config(&self, server: &str) -> openshell_sdk::ClientConfig {
        let resolved = self.with_default_paths(server);
        let ca_cert = resolved
            .ca
            .as_ref()
            .and_then(|ca_path| std::fs::read(ca_path).ok());
        let auth = match (&resolved.oidc_token, &resolved.edge_token) {
            (Some(token), _) => Some(openshell_sdk::AuthConfig::Oidc(token.clone())),
            (None, Some(token)) => Some(openshell_sdk::AuthConfig::EdgeJwt(token.clone())),
            (None, None) => None,
        };
        let mut config = openshell_sdk::ClientConfig::new(server);
        config.ca_cert = ca_cert;
        config.auth = auth;
        config.insecure_skip_verify = resolved.gateway_insecure;
        config
    }
}

/// Resolve the TLS cert directory for a known gateway name.
fn tls_dir_for_gateway(name: &str) -> Option<PathBuf> {
    let safe_name = sanitize_name(name);
    let base = xdg_config_dir().ok()?.join("openshell").join("gateways");
    Some(base.join(safe_name).join("mtls"))
}

/// Fallback TLS directory resolution from a server URL.
///
/// Used when no gateway name is set (e.g., `SshProxy` which receives a raw URL).
fn default_tls_dir(server: &str) -> Option<PathBuf> {
    let mut name = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if name.is_none()
        && let Ok(uri) = server.parse::<hyper::Uri>()
        && let Some(host) = uri.host()
    {
        name = Some(
            if host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") {
                "openshell".to_string()
            } else {
                host.to_string()
            },
        );
    }

    let name = name.unwrap_or_else(|| "openshell".to_string());
    let safe_name = sanitize_name(&name);
    let base = xdg_config_dir().ok()?.join("openshell").join("gateways");
    Some(base.join(safe_name).join("mtls"))
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn xdg_config_dir() -> Result<PathBuf> {
    openshell_core::paths::xdg_config_dir()
}

// ── Legacy mTLS path ─────────────────────────────────────────────────
// Everything in this section supports gateways that authenticate clients
// with an mTLS certificate. mTLS is being retired as an auth method, and
// the SDK does not speak it. Until product removes mTLS support, these
// helpers stay in CLI for the `else { full mTLS }` branch of
// `build_channel` and the matching branch of `http_health_check`.

/// In-memory mTLS materials read from disk by [`require_tls_materials`].
pub struct TlsMaterials {
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

pub fn require_tls_materials(server: &str, tls: &TlsOptions) -> Result<TlsMaterials> {
    let resolved = tls.with_default_paths(server);
    let default_hint = default_tls_dir(server).map_or_else(String::new, |dir| {
        format!(" or place certs in {}", dir.display())
    });
    let ca_path = resolved
        .ca
        .as_ref()
        .ok_or_else(|| miette::miette!("TLS CA is required for https endpoints{default_hint}"))?;
    let cert_path = resolved.cert.as_ref().ok_or_else(|| {
        miette::miette!("TLS client cert is required for https endpoints{default_hint}")
    })?;
    let key_path = resolved.key.as_ref().ok_or_else(|| {
        miette::miette!("TLS client key is required for https endpoints{default_hint}")
    })?;

    let ca = std::fs::read(ca_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS CA from {}", ca_path.display()))?;
    let cert = std::fs::read(cert_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS cert from {}", cert_path.display()))?;
    let key = std::fs::read(key_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS key from {}", key_path.display()))?;

    Ok(TlsMaterials { ca, cert, key })
}

/// Parse a PEM-encoded private key for the legacy mTLS rustls path.
fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    let key = rustls_pemfile::private_key(&mut cursor)
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("no private key found in TLS key PEM"))?;
    Ok(key)
}

/// Build a `rustls` mTLS client config (used by `http_health_check`).
pub fn build_rustls_config(materials: &TlsMaterials) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut ca_cursor = Cursor::new(&materials.ca);
    let ca_certs = rustls_pemfile::certs(&mut ca_cursor)
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    for cert in ca_certs {
        roots.add(cert).into_diagnostic()?;
    }

    let mut cert_cursor = Cursor::new(&materials.cert);
    let cert_chain = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    let key = load_private_key(&materials.key)?;

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .into_diagnostic()
}

/// Build a `tonic` mTLS client config (used by the legacy `build_channel`
/// mTLS branch and by `completers.rs`).
pub fn build_tonic_tls_config(materials: &TlsMaterials) -> ClientTlsConfig {
    let ca_cert = Certificate::from_pem(materials.ca.clone());
    let identity = Identity::from_pem(materials.cert.clone(), materials.key.clone());
    ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
}

// ── Channel construction (legacy mTLS dispatcher) ────────────────────
// `build_channel` is a thin dispatcher: gateways that authenticate
// clients with mTLS take the inline `build_legacy_mtls_channel` path
// below; everything else converts to a `ClientConfig` and delegates to
// `openshell_sdk::transport::build_channel`. When mTLS retires as an
// auth method, `needs_legacy_mtls` and `build_legacy_mtls_channel` go
// with it.

pub async fn build_channel(server: &str, tls: &TlsOptions) -> Result<Channel> {
    if needs_legacy_mtls(tls, server) {
        return build_legacy_mtls_channel(server, tls).await;
    }
    let config = tls.to_client_config(server);
    Ok(openshell_sdk::transport::build_channel(&config).await?)
}

/// Returns `true` when this connection should run through the CLI's
/// inline mTLS path: HTTPS, no insecure-skip, no edge tunnel, and either
/// no OIDC token or OIDC paired with mTLS materials on disk. The combined
/// mTLS+OIDC case preserves the documented "mTLS as transport trust
/// boundary, Bearer for full scope" deployment model.
fn needs_legacy_mtls(tls: &TlsOptions, server: &str) -> bool {
    server.starts_with("https://")
        && !tls.gateway_insecure
        && tls.edge_token.is_none()
        && (tls.oidc_token.is_none() || tls.has_mtls_identity(server))
}

/// Inline mTLS channel construction for gateways that require client
/// certificates as the transport-level trust boundary. Goes away when
/// mTLS is retired as an auth method.
async fn build_legacy_mtls_channel(server: &str, tls: &TlsOptions) -> Result<Channel> {
    let materials = require_tls_materials(server, tls)?;
    let tls_config = build_tonic_tls_config(&materials);
    let endpoint = Endpoint::from_shared(server.to_string())
        .into_diagnostic()?
        .connect_timeout(Duration::from_secs(10))
        .http2_adaptive_window(true)
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .tls_config(tls_config)
        .into_diagnostic()?;
    endpoint.connect().await.into_diagnostic()
}

/// Build a gRPC [`OpenShellClient`].
///
/// When `tls.edge_token` is set, the returned client is wrapped with an
/// interceptor that injects authentication headers on every request.
/// Otherwise, standard mTLS is used (interceptor is a no-op).
pub async fn grpc_client(server: &str, tls: &TlsOptions) -> Result<GrpcClient> {
    let channel = build_channel(server, tls).await?;
    let interceptor = interceptor_from_tls(tls)?;
    Ok(OpenShellClient::with_interceptor(channel, interceptor))
}

fn interceptor_from_tls(tls: &TlsOptions) -> Result<EdgeAuthInterceptor> {
    Ok(EdgeAuthInterceptor::new(
        tls.oidc_token.as_deref(),
        tls.edge_token.as_deref(),
    )?)
}

pub async fn grpc_inference_client(server: &str, tls: &TlsOptions) -> Result<GrpcInferenceClient> {
    let channel = build_channel(server, tls).await?;
    let interceptor = interceptor_from_tls(tls)?;
    Ok(InferenceClient::with_interceptor(channel, interceptor))
}
