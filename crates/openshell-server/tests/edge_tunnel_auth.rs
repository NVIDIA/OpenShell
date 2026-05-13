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
    ProviderResponse, RelayFrame, RevokeSshSessionRequest, RevokeSshSessionResponse,
    SandboxResponse, SandboxStreamEvent, ServiceStatus, SupervisorMessage, TcpForwardFrame,
    UpdateProviderRequest, WatchSandboxRequest,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Minimal `OpenShell` implementation for testing.
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

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxProvidersResponse::default(),
        ))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<openshell_core::proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<openshell_core::proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DetachSandboxProviderResponse::default(),
        ))
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

    async fn expose_service(
        &self,
        _request: tonic::Request<openshell_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ServiceEndpointResponse::default(),
        ))
    }

    async fn get_service(
        &self,
        _: tonic::Request<openshell_core::proto::GetServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<openshell_core::proto::ListServicesRequest>,
    ) -> Result<Response<openshell_core::proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteServiceRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
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
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_provider(
        &self,
        _request: tonic::Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_providers(
        &self,
        _request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
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
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_provider(
        &self,
        _request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
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

    type RelayStreamStream = ReceiverStream<Result<RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<TcpForwardFrame, Status>> + Send>>;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

// ---------------------------------------------------------------------------
// PKI generation
// ---------------------------------------------------------------------------

#[allow(dead_code, clippy::struct_field_names)]
struct PkiBundle {
    ca_cert_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn generate_pki() -> (tempfile::TempDir, PkiBundle) {
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

    let server_params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create server params");
    let server_key = KeyPair::generate().expect("failed to generate server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("failed to sign server cert");

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
    let write_file = |name: &str, data: &[u8]| {
        let path = dir.path().join(name);
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(data))
            .expect("failed to write file");
    };

    write_file("ca.pem", ca_cert.pem().as_bytes());
    write_file("server-cert.pem", server_cert.pem().as_bytes());
    write_file("server-key.pem", server_key.serialize_pem().as_bytes());
    write_file("client-cert.pem", client_cert.pem().as_bytes());
    write_file("client-key.pem", client_key.serialize_pem().as_bytes());

    let bundle = PkiBundle {
        ca_cert_pem: ca_cert.pem().into_bytes(),
        server_cert_pem: server_cert.pem().into_bytes(),
        server_key_pem: server_key.serialize_pem().into_bytes(),
        client_cert_pem: client_cert.pem().into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
    };

    (dir, bundle)
}

// ---------------------------------------------------------------------------
// Server + client helpers
// ---------------------------------------------------------------------------

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
