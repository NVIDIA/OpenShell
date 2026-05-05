// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxesRequest, ListSandboxesResponse,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, SupervisorMessage, UpdateProviderRequest,
    WatchSandboxRequest,
    open_shell_client::OpenShellClient,
    open_shell_server::{OpenShell, OpenShellServer},
};
use openshell_server::{MultiplexedService, TlsAcceptor, health_router};
use rcgen::{CertificateParams, IsCa, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use std::io::Write;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Response, Status};

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone, Default)]
struct TestOpenShell;

#[tonic::async_trait]
impl OpenShell for TestOpenShell {
    async fn health(
        &self,
        _request: tonic::Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse::default()))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<GetSandboxConfigRequest>,
    ) -> Result<Response<GetSandboxConfigResponse>, Status> {
        Ok(Response::new(GetSandboxConfigResponse::default()))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<GetGatewayConfigRequest>,
    ) -> Result<Response<GetGatewayConfigResponse>, Status> {
        Ok(Response::new(GetGatewayConfigResponse::default()))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn create_ssh_session(
        &self,
        _request: tonic::Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        Ok(Response::new(CreateSshSessionResponse::default()))
    }

    async fn revoke_ssh_session(
        &self,
        _request: tonic::Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        Ok(Response::new(RevokeSshSessionResponse::default()))
    }

    async fn create_provider(
        &self,
        _request: tonic::Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        Err(Status::unimplemented(
            "create_provider not implemented in test",
        ))
    }

    async fn get_provider(
        &self,
        _request: tonic::Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        Err(Status::unimplemented(
            "get_provider not implemented in test",
        ))
    }

    async fn list_providers(
        &self,
        _request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        Err(Status::unimplemented(
            "list_providers not implemented in test",
        ))
    }

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_provider_profile(
        &self,
        _request: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn import_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_provider_profile(
        &self,
        _request: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_provider(
        &self,
        _request: tonic::Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        Err(Status::unimplemented(
            "update_provider not implemented in test",
        ))
    }

    async fn delete_provider(
        &self,
        _request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        Err(Status::unimplemented(
            "delete_provider not implemented in test",
        ))
    }

    type WatchSandboxStream = ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream = ReceiverStream<Result<GatewayMessage, Status>>;

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn update_config(
        &self,
        _request: tonic::Request<openshell_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<openshell_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<openshell_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<openshell_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream = ReceiverStream<Result<openshell_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

/// PKI bundle: CA cert, server cert+key, client cert+key.
#[allow(dead_code, clippy::struct_field_names)]
struct PkiBundle {
    ca_cert_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

/// Generate a full PKI: CA -> server cert (for localhost) + client cert.
fn generate_pki() -> (tempfile::TempDir, PkiBundle) {
    // Generate CA
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-ca");
    let ca_key = KeyPair::generate().expect("failed to generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("failed to sign CA cert");

    // Generate server cert signed by CA
    let server_params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create server params");
    let server_key = KeyPair::generate().expect("failed to generate server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("failed to sign server cert");

    // Generate client cert signed by CA
    let mut client_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-client");
    let client_key = KeyPair::generate().expect("failed to generate client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("failed to sign client cert");

    let dir = tempdir().expect("failed to create tempdir");
    let write = |name: &str, data: &[u8]| {
        let path = dir.path().join(name);
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(data))
            .expect("failed to write file");
    };

    write("ca.pem", ca_cert.pem().as_bytes());
    write("server-cert.pem", server_cert.pem().as_bytes());
    write("server-key.pem", server_key.serialize_pem().as_bytes());
    write("client-cert.pem", client_cert.pem().as_bytes());
    write("client-key.pem", client_key.serialize_pem().as_bytes());

    let bundle = PkiBundle {
        ca_cert_pem: ca_cert.pem().into_bytes(),
        server_cert_pem: server_cert.pem().into_bytes(),
        server_key_pem: server_key.serialize_pem().into_bytes(),
        client_cert_pem: client_cert.pem().into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
    };

    (dir, bundle)
}

/// Start a test server with the given TLS acceptor, returning its address and
/// a handle that aborts the server on drop.
async fn start_test_server(
    tls_acceptor: TlsAcceptor,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_service, http_service);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            let tls = tls_acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = tls.inner().accept(stream).await else {
                    return;
                };
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), svc)
                    .await;
            });
        }
    });

    (addr, handle)
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

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        &temp.path().join("ca.pem"),
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

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        &temp.path().join("ca.pem"),
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
async fn mtls_no_client_cert_rejected() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        &temp.path().join("ca.pem"),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // Connect with CA trust but no client cert -- should be rejected.
    let ca_cert = tonic::transport::Certificate::from_pem(pki.ca_cert_pem.clone());
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("localhost");
    let endpoint = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("invalid endpoint")
        .tls_config(tls)
        .expect("failed to set tls");

    let result = endpoint.connect().await;
    // Connection should fail at the TLS handshake level or shortly after.
    // The exact error depends on timing -- it may fail on connect or on first RPC.
    if let Ok(channel) = result {
        let mut client = OpenShellClient::new(channel);
        let rpc_result = client.health(HealthRequest {}).await;
        assert!(
            rpc_result.is_err(),
            "expected RPC to fail without client cert"
        );
    }

    server.abort();
}

#[tokio::test]
async fn mtls_wrong_ca_client_cert_rejected() {
    install_rustls_provider();
    let (temp, pki) = generate_pki();

    let tls_acceptor = TlsAcceptor::from_files(
        &temp.path().join("server-cert.pem"),
        &temp.path().join("server-key.pem"),
        &temp.path().join("ca.pem"),
        false,
    )
    .unwrap();

    let (addr, server) = start_test_server(tls_acceptor).await;

    // Generate a rogue CA + client cert not signed by the server's CA.
    let mut rogue_ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create rogue CA params");
    rogue_ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    rogue_ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rogue-ca");
    let rogue_ca_key = KeyPair::generate().expect("failed to generate rogue CA key");
    let rogue_ca_cert = rogue_ca_params
        .self_signed(&rogue_ca_key)
        .expect("failed to sign rogue CA cert");

    let mut rogue_client_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create rogue client params");
    rogue_client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rogue-client");
    let rogue_client_key = KeyPair::generate().expect("failed to generate rogue client key");
    let rogue_client_cert = rogue_client_params
        .signed_by(&rogue_client_key, &rogue_ca_cert, &rogue_ca_key)
        .expect("failed to sign rogue client cert");

    // Connect with rogue client cert -- server should reject it.
    let ca_cert = tonic::transport::Certificate::from_pem(pki.ca_cert_pem.clone());
    let identity = tonic::transport::Identity::from_pem(
        rogue_client_cert.pem(),
        rogue_client_key.serialize_pem(),
    );
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
