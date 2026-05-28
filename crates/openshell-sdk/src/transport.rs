// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC transport stack: channel construction and the insecure-TLS connector.
//!
//! mTLS is intentionally out of scope here. Gateways that require client
//! certificates are handled by `openshell-cli`'s legacy path until the auth
//! method is retired.

use crate::config::{AuthConfig, ClientConfig};
use crate::edge_tunnel;
use crate::error::{Result, SdkError};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::debug;

/// Standard endpoint settings used by every dialed connection.
///
/// Centralizes timeouts and HTTP/2 keepalive so behavior is consistent across
/// transport branches. Returns an `Endpoint` ready for `connect()` /
/// `connect_with_connector()`.
fn standard_endpoint(uri: String) -> Result<Endpoint> {
    Endpoint::from_shared(uri)
        .map(|ep| {
            ep.connect_timeout(Duration::from_secs(10))
                .http2_adaptive_window(true)
                .http2_keep_alive_interval(Duration::from_secs(10))
                .keep_alive_while_idle(true)
        })
        .map_err(|e| SdkError::invalid_config(format!("invalid gateway URL: {e}")))
}

// ── Edge tunnel registry ─────────────────────────────────────────────
// Each distinct edge-authenticated gateway gets its own local proxy
// instead of reusing the first gateway touched in the current process.
static EDGE_TUNNEL_ADDRS: OnceLock<Mutex<HashMap<(String, String), SocketAddr>>> = OnceLock::new();

/// Look up (or start) the local tunnel proxy for an edge-authenticated
/// gateway. Subsequent calls with the same `(server, token)` reuse the
/// existing proxy.
async fn edge_tunnel_addr(server: &str, token: &str) -> Result<SocketAddr> {
    let key = (server.to_string(), token.to_string());
    let registry = EDGE_TUNNEL_ADDRS.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let addrs = registry.lock().await;
        if let Some(addr) = addrs.get(&key).copied() {
            return Ok(addr);
        }
    }

    let proxy = edge_tunnel::start_tunnel_proxy(server, token).await?;
    debug!(
        local_addr = %proxy.local_addr,
        server,
        "edge tunnel proxy started, routing gRPC through local proxy"
    );

    let mut addrs = registry.lock().await;
    Ok(*addrs.entry(key).or_insert(proxy.local_addr))
}

// ── Channel construction ─────────────────────────────────────────────

/// Open a gRPC channel to the gateway described by `config`.
///
/// Routing is determined by `gateway` scheme + `auth` variant +
/// `insecure_skip_verify`. Reference today's CLI implementation in
/// `openshell-cli/src/tls.rs::build_channel` (lines 219–308) for behavior
/// the SDK needs to preserve.
///
/// **Branch table:**
///
/// | `gateway` scheme | `auth` | `insecure_skip_verify` | TLS handling |
/// |------------------|--------|------------------------|-------------|
/// | `http://` | (any)  | (any) | plaintext, ignore tls |
/// | `https://` | `Some(EdgeJwt)` | (any) | tunnel proxy + plaintext to local proxy |
/// | `https://` | (any) | `true` | `InsecureTlsConnector`, no verification |
/// | `https://` | `Some(Oidc)` or `None` | `false` | tonic TLS, pin `ca_cert` if set, system roots otherwise |
pub async fn build_channel(config: &ClientConfig) -> Result<Channel> {
    let gateway = &config.gateway;

    // Branch 1 — plaintext.
    // Reference: cli/tls.rs:220-228 (http:// branch).
    if gateway.starts_with("http://") {
        return standard_endpoint(gateway.clone())?
            .connect()
            .await
            .map_err(|e| SdkError::connect(format!("{e}")));
    }

    if !gateway.starts_with("https://") {
        return Err(SdkError::invalid_config(format!(
            "gateway URL must start with http:// or https://: {gateway}"
        )));
    }

    // Branch 2 — Cloudflare Access edge JWT: tunnel proxy + plaintext-to-local.
    // Reference: cli/tls.rs:233-249 (https:// + edge_token branch). Use
    // `edge_tunnel_addr(gateway, token).await?` to get the local proxy
    // address, then `standard_endpoint(format!("http://{local_addr}"))?.connect()`.
    if let Some(AuthConfig::EdgeJwt(token)) = &config.auth {
        let local_addr = edge_tunnel_addr(gateway, token).await?;
        return standard_endpoint(format!("http://{local_addr}"))?
            .connect()
            .await
            .map_err(|e| SdkError::connect(format!("{e}")));
    }

    // Branch 3 — insecure TLS (skip cert verification).
    // Reference: cli/tls.rs:251-268 (gateway_insecure branch). Build the
    // insecure rustls config, wrap it in `InsecureTlsConnector`, swap the
    // gateway scheme to http:// (so tonic doesn't double-layer TLS), and
    // call `endpoint.connect_with_connector(connector)`.
    if config.insecure_skip_verify {
        tracing::warn!("TLS certificate verification is disabled — do not use in production");
        let rustls_config = build_insecure_rustls_config()?;
        let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(rustls_config));
        let connector = InsecureTlsConnector { tls_connector };
        let http_uri = gateway.replacen("https://", "http://", 1);
        return standard_endpoint(http_uri)?
            .connect_with_connector(connector)
            .await
            .map_err(|e| SdkError::connect(format!("{e}")));
    }

    // Branch 4 — anonymous TLS or OIDC bearer over HTTPS.
    // Reference: cli/tls.rs:270-307 (the `oidc_token` and final mTLS
    // branches collapsed). Build a `ClientTlsConfig`:
    //   - if `config.ca_cert` is `Some(pem)`, pin it via `.ca_certificate(...)`
    //   - else fall back to `.with_enabled_roots()` (system roots)
    // Then `endpoint.tls_config(tls_config)?.connect()`.
    //
    // The OIDC bearer header is added by the gRPC interceptor at request
    // time, not here — `build_channel` only owns the TLS layer.

    let tls_config = config.ca_cert.as_ref().map_or_else(
        || ClientTlsConfig::new().with_enabled_roots(),
        |ca_cert| ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_cert)),
    );
    standard_endpoint(gateway.clone())?
        .tls_config(tls_config)
        .map_err(|e| SdkError::tls(format!("{e}")))?
        .connect()
        .await
        .map_err(|e| SdkError::connect(format!("{e}")))
}

/// rustls verifier that accepts any server certificate.
///
/// Used only when the caller explicitly opts into
/// [`ClientConfig::insecure_skip_verify`]. Do not use in production.
///
/// [`ClientConfig::insecure_skip_verify`]: crate::config::ClientConfig::insecure_skip_verify
#[derive(Debug)]
pub struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// rustls client config that disables server certificate verification.
///
/// Pairs with [`InsecureTlsConnector`] for transports that need to skip
/// verification (development, debug). Returns `Result` for symmetry with
/// future verifying variants; the current implementation cannot fail.
pub fn build_insecure_rustls_config() -> Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(InsecureServerCertVerifier))
        .with_no_client_auth())
}

/// `tower::Service` connector that performs TLS using the supplied rustls
/// connector, bypassing tonic's built-in TLS layering.
///
/// Used to plumb [`InsecureServerCertVerifier`]-backed configs into a tonic
/// `Endpoint` via `connect_with_connector`.
#[derive(Clone)]
pub struct InsecureTlsConnector {
    /// Inner rustls connector configured by the caller.
    pub tls_connector: tokio_rustls::TlsConnector,
}

impl tower::Service<hyper::Uri> for InsecureTlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let tls_connector = self.tls_connector.clone();
        Box::pin(async move {
            let host = uri.host().unwrap_or("localhost").to_string();
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{host}:{port}");
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let server_name = ServerName::try_from(host)?;
            let tls_stream = tls_connector.connect(server_name, tcp).await?;
            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
}
