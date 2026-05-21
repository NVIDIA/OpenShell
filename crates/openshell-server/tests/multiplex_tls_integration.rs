// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod common;

use bytes::Bytes;
use common::{
    PkiBundle, generate_pki, generate_rogue_pki, install_rustls_provider, start_test_server,
};
use http_body_util::Empty;
use hyper::Request;
use hyper::StatusCode;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use openshell_core::proto::{HealthRequest, ServiceStatus, open_shell_client::OpenShellClient};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

fn build_tls_root(cert_pem: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(cert_pem);
    let parsed = certs(&mut cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .expect("failed to parse cert pem");
    for cert in parsed {
        roots.add(cert).expect("failed to add cert");
    }
    roots
}

/// Build a gRPC client with mTLS (CA + client cert).
async fn grpc_client_mtls(
    addr: std::net::SocketAddr,
    ca_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
) -> OpenShellClient<Channel> {
    let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
    let identity = tonic::transport::Identity::from_pem(client_cert_pem, client_key_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");
    let channel = endpoint.connect().await.expect("failed to connect");
    OpenShellClient::new(channel)
}

/// Build an HTTPS client with mTLS (CA trust + client cert/key).
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

#[tokio::test]
async fn serves_grpc_and_http_over_tls_on_same_port() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = openshell_server::TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // gRPC with mTLS
    let mut grpc = grpc_client_mtls(
        addr,
        pki.ca_cert_pem.clone(),
        pki.client_cert_pem.clone(),
        pki.client_key_pem.clone(),
    )
    .await;
    let response = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    // HTTP with mTLS
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

#[tokio::test]
async fn mtls_valid_client_cert_accepted() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = openshell_server::TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    let mut grpc = grpc_client_mtls(
        addr,
        pki.ca_cert_pem.clone(),
        pki.client_cert_pem.clone(),
        pki.client_key_pem.clone(),
    )
    .await;
    let response = grpc.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    server.abort();
}

#[tokio::test]
async fn no_client_cert_accepted_with_ca() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = openshell_server::TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // Connect with CA trust but no client cert — should succeed (certs are optional).
    let ca_cert = tonic::transport::Certificate::from_pem(pki.ca_cert_pem.clone());
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");

    let channel = endpoint
        .connect()
        .await
        .expect("should connect without client cert");
    let mut client = OpenShellClient::new(channel);
    let response = client.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    server.abort();
}

#[tokio::test]
async fn no_client_cert_rejected_when_required() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = openshell_server::TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        true,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    let ca_cert = tonic::transport::Certificate::from_pem(pki.ca_cert_pem.clone());
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
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
            "expected RPC to fail without client cert when mTLS is required"
        );
    }

    server.abort();
}

#[tokio::test]
async fn mtls_wrong_ca_client_cert_rejected() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = openshell_server::TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        Some(temp.path().join("ca.pem").as_path()),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // Generate a rogue CA + client cert not signed by the server's CA.
    let rogue = generate_rogue_pki();

    // Connect with rogue client cert -- server should reject it.
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

    server.abort();
}
