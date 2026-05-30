// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for openshell-server integration tests.
//!
//! Include with `mod common;` at the top of each integration test file.
//! Items may not be used by every test file; the blanket `#[allow]` prevents
//! spurious dead-code warnings.

#![allow(dead_code)]

use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxInput, ExecSandboxRequest, GatewayMessage,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    IssueSandboxTokenRequest, IssueSandboxTokenResponse, ListProvidersRequest,
    ListProvidersResponse, ListSandboxesRequest, ListSandboxesResponse, ProviderResponse,
    RefreshSandboxTokenRequest, RefreshSandboxTokenResponse, RelayFrame, RevokeSshSessionRequest,
    RevokeSshSessionResponse, SandboxResponse, SandboxStreamEvent, ServiceStatus,
    SupervisorMessage, TcpForwardFrame, UpdateProviderRequest, WatchSandboxRequest,
    open_shell_server::{OpenShell, OpenShellServer},
};
use openshell_server::{MultiplexedService, Store, TlsAcceptor, health_router};
use rcgen::{CertificateParams, IsCa, KeyPair};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};

// ---------------------------------------------------------------------------
// Minimal OpenShell stub: all methods return defaults or Unimplemented.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct TestOpenShell;

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

    async fn get_provider_refresh_status(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _: tonic::Request<openshell_core::proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<openshell_core::proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _: tonic::Request<openshell_core::proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<openshell_core::proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
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

    type ExecSandboxInteractiveStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;

    async fn exec_sandbox_interactive(
        &self,
        _request: tonic::Request<tonic::Streaming<ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
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

    async fn issue_sandbox_token(
        &self,
        _request: tonic::Request<IssueSandboxTokenRequest>,
    ) -> Result<Response<IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<RefreshSandboxTokenRequest>,
    ) -> Result<Response<RefreshSandboxTokenResponse>, Status> {
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
// TLS / PKI helpers (used by TLS integration tests)
// ---------------------------------------------------------------------------

/// Initialise the rustls crypto provider (idempotent).
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// PKI bundle: CA cert, server cert+key, client cert+key (all PEM).
#[allow(clippy::struct_field_names)]
pub struct PkiBundle {
    pub ca_cert_pem: Vec<u8>,
    pub server_cert_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
}

/// Generate a full PKI: CA → server cert (for `localhost`) + client cert.
/// Returns a `TempDir` that must be kept alive while the paths are in use.
pub fn generate_pki() -> (tempfile::TempDir, PkiBundle) {
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

/// Start a TLS-wrapped test server using the given `TlsAcceptor`.
/// Returns the bound address and a task handle (abort to stop).
pub async fn start_test_server(
    tls_acceptor: TlsAcceptor,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router(test_health_store().await);
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
/// Rogue PKI bundle: client cert + key not signed by the server's CA.
pub struct RoguePkiBundle {
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Generate a rogue CA and a client certificate signed by that CA.
///
/// Used to verify that the server rejects mTLS connections from clients whose
/// certificate chain does not trace back to the trusted CA.
pub fn generate_rogue_pki() -> RoguePkiBundle {
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

    RoguePkiBundle {
        client_cert_pem: rogue_client_cert.pem(),
        client_key_pem: rogue_client_key.serialize_pem(),
    }
}

/// Build an in-memory store sufficient for wiring `health_router` in tests
/// where the persistence layer itself is not under test.
pub async fn test_health_store() -> Arc<Store> {
    Arc::new(
        Store::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite store for tests"),
    )
}
