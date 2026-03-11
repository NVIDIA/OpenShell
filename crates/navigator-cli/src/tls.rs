// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::inference_client::InferenceClient;
use navigator_core::proto::navigator_client::NavigatorClient;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::debug;

/// Concrete gRPC client type used by all commands.
pub type GrpcClient = NavigatorClient<InterceptedService<Channel, EdgeAuthInterceptor>>;
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
}

impl TlsOptions {
    pub fn new(ca: Option<PathBuf>, cert: Option<PathBuf>, key: Option<PathBuf>) -> Self {
        Self {
            ca,
            cert,
            key,
            gateway_name: None,
            edge_token: None,
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

    /// Returns `true` when using edge token auth (no mTLS client certs).
    pub fn is_bearer_auth(&self) -> bool {
        self.edge_token.is_some()
    }
}

pub struct TlsMaterials {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
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
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
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

fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    let key = rustls_pemfile::private_key(&mut cursor)
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("no private key found in TLS key PEM"))?;
    Ok(key)
}

pub fn build_rustls_config(materials: &TlsMaterials) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut ca_cursor = Cursor::new(&materials.ca);
    let ca_certs = rustls_pemfile::certs(&mut ca_cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    for cert in ca_certs {
        roots.add(cert).into_diagnostic()?;
    }

    let mut cert_cursor = Cursor::new(&materials.cert);
    let cert_chain = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    let key = load_private_key(&materials.key)?;

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .into_diagnostic()
}

pub fn build_tonic_tls_config(materials: &TlsMaterials) -> ClientTlsConfig {
    let ca_cert = Certificate::from_pem(materials.ca.clone());
    let identity = Identity::from_pem(materials.cert.clone(), materials.key.clone());
    ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
}

/// Tunnel proxy addresses keyed by upstream endpoint + token.
///
/// Each distinct edge-authenticated gateway gets its own local proxy instead of
/// reusing the first gateway touched in the current process.
static EDGE_TUNNEL_ADDRS: OnceLock<Mutex<HashMap<(String, String), SocketAddr>>> = OnceLock::new();

async fn edge_tunnel_addr(server: &str, token: &str) -> Result<SocketAddr> {
    let key = (server.to_string(), token.to_string());
    let registry = EDGE_TUNNEL_ADDRS.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let addrs = registry.lock().await;
        if let Some(addr) = addrs.get(&key).copied() {
            return Ok(addr);
        }
    }

    let proxy = crate::edge_tunnel::start_tunnel_proxy(server, token).await?;
    debug!(
        local_addr = %proxy.local_addr,
        server,
        "edge tunnel proxy started, routing gRPC through local proxy"
    );

    let mut addrs = registry.lock().await;
    Ok(*addrs.entry(key).or_insert(proxy.local_addr))
}

pub async fn build_channel(server: &str, tls: &TlsOptions) -> Result<Channel> {
    // When edge bearer auth is active and the server is HTTPS,
    // route traffic through a local WebSocket tunnel proxy instead.
    if tls.is_bearer_auth() && server.starts_with("https://") {
        let token = tls
            .edge_token
            .as_deref()
            .ok_or_else(|| miette::miette!("edge token required for tunnel"))?;
        let local_addr = edge_tunnel_addr(server, token).await?;

        // Connect to the local tunnel proxy over plaintext HTTP/2.
        let local_url = format!("http://{local_addr}");
        let endpoint = Endpoint::from_shared(local_url)
            .into_diagnostic()?
            .connect_timeout(Duration::from_secs(10))
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_while_idle(true);
        return endpoint.connect().await.into_diagnostic();
    }

    let mut endpoint = Endpoint::from_shared(server.to_string())
        .into_diagnostic()?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true);

    let tls_config = if tls.is_bearer_auth() {
        // Bearer mode without HTTPS (e.g. http:// direct) — no tunnel needed,
        // but also no TLS config to set. This branch shouldn't normally happen
        // (edge endpoints are always HTTPS) but handle gracefully.
        return endpoint.connect().await.into_diagnostic();
    } else {
        // Standard mTLS: private CA + client cert.
        let materials = require_tls_materials(server, tls)?;
        build_tonic_tls_config(&materials)
    };
    endpoint = endpoint.tls_config(tls_config).into_diagnostic()?;
    endpoint.connect().await.into_diagnostic()
}

/// Build a gRPC [`NavigatorClient`].
///
/// When `tls.edge_token` is set, the returned client is wrapped with an
/// interceptor that injects authentication headers on every request.
/// Otherwise, standard mTLS is used (interceptor is a no-op).
pub async fn grpc_client(server: &str, tls: &TlsOptions) -> Result<GrpcClient> {
    let channel = build_channel(server, tls).await?;
    let interceptor = EdgeAuthInterceptor::maybe_from(tls)?;
    Ok(NavigatorClient::with_interceptor(channel, interceptor))
}

/// Interceptor that injects edge authentication headers into every outgoing
/// gRPC request. When no token is set, acts as a no-op.
///
/// Currently sends Cloudflare Access headers for compatibility:
/// - `Cf-Access-Jwt-Assertion` header
/// - `CF_Authorization` cookie
#[derive(Clone)]
pub struct EdgeAuthInterceptor {
    header_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    cookie_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
}

impl EdgeAuthInterceptor {
    /// Create an interceptor from [`TlsOptions`].  Returns a no-op interceptor
    /// when no edge token is configured.
    pub fn maybe_from(tls: &TlsOptions) -> Result<Self> {
        let (header_value, cookie_value) = match tls.edge_token.as_deref() {
            Some(t) => {
                let hv: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = t
                    .parse()
                    .map_err(|_| miette::miette!("invalid edge token value"))?;
                let cv: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
                    format!("CF_Authorization={t}")
                        .parse()
                        .map_err(|_| miette::miette!("invalid edge token value for cookie"))?;
                (Some(hv), Some(cv))
            }
            None => (None, None),
        };
        Ok(Self {
            header_value,
            cookie_value,
        })
    }
}

impl tonic::service::Interceptor for EdgeAuthInterceptor {
    fn call(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        if let Some(ref val) = self.header_value {
            req.metadata_mut()
                .insert("cf-access-jwt-assertion", val.clone());
        }
        if let Some(ref val) = self.cookie_value {
            req.metadata_mut().insert("cookie", val.clone());
        }
        Ok(req)
    }
}

pub async fn grpc_inference_client(server: &str, tls: &TlsOptions) -> Result<GrpcInferenceClient> {
    let channel = build_channel(server, tls).await?;
    let interceptor = EdgeAuthInterceptor::maybe_from(tls)?;
    Ok(InferenceClient::with_interceptor(channel, interceptor))
}
