// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for edge tunnel auth compatibility.
//!
//! These tests verify that the gateway can operate in "dual-auth" mode where
//! the TLS layer accepts connections both with and without client certificates.
//! This is the foundation for edge-authenticated tunnel support: the edge proxy
//! terminates TLS and re-originates a new connection to the gateway without a
//! client cert.  The gateway must accept these connections and defer auth to the
//! application layer (e.g. a bearer JWT header).
//!
//! Test matrix:
//!
//! | `client_ca` | client cert  | bearer header | expected                  |
//! |-------------|-------------|---------------|---------------------------|
//! | Some        | valid       | —             | OK (cert validated)       |
//! | Some        | none        | —             | OK (cert optional)        |
//! | Some        | none        | present       | OK (bearer auth)          |
//! | Some        | rogue CA    | —             | rejected (bad cert)       |
//! | None        | none        | —             | OK (HTTPS-only)           |
//!
//! Client certificates are always optional when a CA is configured.  They are
//! validated when present (rogue-CA certs are rejected) but never required.
//! Authentication is handled at the application layer (OIDC bearer tokens).

mod common;

use bytes::Bytes;
use common::{
    PkiBundle, build_tls_root, generate_pki, generate_rogue_pki, grpc_client_mtls,
    install_rustls_provider, start_test_server,
};
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use openshell_core::proto::{HealthRequest, ServiceStatus, open_shell_client::OpenShellClient};
use openshell_server::TlsAcceptor;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use tonic::Status;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

/// Build a gRPC client *without* a client cert (simulates Cloudflare tunnel).
async fn grpc_client_no_cert(
    addr: std::net::SocketAddr,
    ca_pem: Vec<u8>,
) -> OpenShellClient<Channel> {
    let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");
    let channel = endpoint.connect().await.expect("failed to connect");
    OpenShellClient::new(channel)
}

/// Build a gRPC client without a client cert, adding a `cf-authorization`
/// metadata header to every request (simulates the steady-state tunnel flow).
async fn grpc_client_with_cf_header(
    addr: std::net::SocketAddr,
    ca_pem: Vec<u8>,
    token: &str,
) -> OpenShellClient<tonic::service::interceptor::InterceptedService<Channel, CfInterceptor>> {
    let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");
    let channel = endpoint.connect().await.expect("failed to connect");
    OpenShellClient::with_interceptor(
        channel,
        CfInterceptor {
            token: token.to_string(),
        },
    )
}

#[derive(Clone)]
struct CfInterceptor {
    token: String,
}

impl tonic::service::Interceptor for CfInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        req.metadata_mut().insert(
            "cf-authorization",
            self.token.parse().expect("invalid metadata value"),
        );
        Ok(req)
    }
}

/// Build an HTTPS client with mTLS.
fn https_client_mtls(
    pki: &PkiBundle,
) -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
> {
    let roots = build_tls_root(&pki.ca_cert_pem);
    let client_certs = {
        let mut cursor = std::io::Cursor::new(&pki.client_cert_pem);
        certs(&mut cursor)
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .expect("failed to parse client cert pem")
    };
    let client_key = {
        let mut cursor = std::io::Cursor::new(&pki.client_key_pem);
        rustls_pemfile::private_key(&mut cursor)
            .expect("failed to parse client key pem")
            .expect("no private key found")
    };
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .expect("failed to build client TLS config with client cert");
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Build an HTTPS client *without* a client cert (simulates Cloudflare tunnel).
fn https_client_no_cert(
    ca_pem: &[u8],
) -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
> {
    let roots = build_tls_root(ca_pem);
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

// ===========================================================================
// Tests
// ===========================================================================

/// Valid client cert is accepted when a CA is configured.
#[tokio::test]
async fn mtls_valid_client_cert_accepted() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // gRPC
    let mut grpc = grpc_client_mtls(
        addr,
        pki.ca_cert_pem.clone(),
        pki.client_cert_pem.clone(),
        pki.client_key_pem.clone(),
    )
    .await;
    let resp = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(resp.get_ref().status, ServiceStatus::Healthy as i32);

    // HTTP
    let client = https_client_mtls(&pki);
    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/healthz", addr.port()))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.abort();
}

/// No client cert is accepted when a CA is configured — client certs are
/// always optional.  Auth is deferred to the application layer.
#[tokio::test]
async fn no_client_cert_accepted_with_ca_configured() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // gRPC without client cert — should pass TLS handshake
    let mut grpc = grpc_client_no_cert(addr, pki.ca_cert_pem.clone()).await;
    let resp = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(
        resp.get_ref().status,
        ServiceStatus::Healthy as i32,
        "gRPC health check should succeed without client cert"
    );

    // HTTP without client cert
    let client = https_client_no_cert(&pki.ca_cert_pem);
    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/healthz", addr.port()))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "HTTP health check should succeed without client cert"
    );

    server.abort();
}

/// Bearer auth header passes through to the gRPC handler when no client
/// cert is presented.
#[tokio::test]
async fn bearer_header_reaches_server_without_client_cert() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // gRPC without client cert but with cf-authorization header
    let mut grpc =
        grpc_client_with_cf_header(addr, pki.ca_cert_pem.clone(), "eyJhbGciOiJSUzI1NiJ9.test")
            .await;
    let resp = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(
        resp.get_ref().status,
        ServiceStatus::Healthy as i32,
        "gRPC with bearer header should succeed without client cert"
    );

    server.abort();
}

/// A client cert from a rogue CA is rejected at the TLS layer even though
/// client certs are optional — presented certs are still validated.
#[tokio::test]
async fn rogue_cert_rejected() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // Generate a rogue CA + client cert
    let rogue = generate_rogue_pki();

    let ca_cert = tonic::transport::Certificate::from_pem(pki.ca_cert_pem.clone());
    let identity =
        tonic::transport::Identity::from_pem(rogue.client_cert_pem, rogue.client_key_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");

    let result = endpoint.connect().await;
    if let Ok(channel) = result {
        let mut client = OpenShellClient::new(channel);
        let rpc_result = client.health(HealthRequest {}).await;
        assert!(
            rpc_result.is_err(),
            "expected RPC to fail with rogue client cert"
        );
    }
    // If connect() itself failed, that's also correct.

    server.abort();
}

/// HTTPS-only mode: no client CA configured, so the server never requests
/// client certificates.  Clients connect with server-only TLS.
#[tokio::test]
async fn https_only_no_client_cert_required() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        None,
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // gRPC without client cert — should succeed (no client certs requested)
    let mut grpc = grpc_client_no_cert(addr, pki.ca_cert_pem.clone()).await;
    let resp = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(
        resp.get_ref().status,
        ServiceStatus::Healthy as i32,
        "gRPC health check should succeed in HTTPS-only mode"
    );

    // HTTP without client cert
    let client = https_client_no_cert(&pki.ca_cert_pem);
    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/healthz", addr.port()))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "HTTP health check should succeed in HTTPS-only mode"
    );

    server.abort();
}
