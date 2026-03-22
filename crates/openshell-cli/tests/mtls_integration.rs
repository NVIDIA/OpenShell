// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_cli::tls::{TlsOptions, grpc_client};
use openshell_core::proto::{
    CreateProviderRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, ExecSandboxEvent, ExecSandboxRequest,
    GetProviderRequest, HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, ServiceStatus,
    UpdateProviderRequest,
    open_shell_server::{OpenShell, OpenShellServer},
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Response, Status,
    transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig},
};

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
    }
}

#[allow(unsafe_code)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe {
                std::env::set_var(self.key, value);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

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
        _request: tonic::Request<openshell_core::proto::CreateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxesResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxesResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::DeleteSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteSandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DeleteSandboxResponse { deleted: true },
        ))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetSandboxConfigResponse::default(),
        ))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<openshell_core::proto::GetGatewayConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetGatewayConfigResponse::default(),
        ))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxProviderEnvironmentResponse>, Status>
    {
        Ok(Response::new(
            openshell_core::proto::GetSandboxProviderEnvironmentResponse::default(),
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

    type WatchSandboxStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::SandboxStreamEvent, Status>,
    >;
    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
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
}

fn build_ca() -> (Certificate, KeyPair) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

fn build_server_cert(ca: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

fn build_client_cert(ca: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

async fn run_server(
    server_cert: String,
    server_key: String,
    ca_cert: String,
) -> std::net::SocketAddr {
    let identity = Identity::from_pem(server_cert, server_key);
    let client_ca = TlsCertificate::from_pem(ca_cert);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(OpenShellServer::new(TestOpenShell))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    addr
}

#[tokio::test]
async fn cli_connects_with_client_cert() {
    install_rustls_provider();

    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let dir = tempdir().unwrap();
    let ca_path = dir.path().join("ca.crt");
    let cert_path = dir.path().join("tls.crt");
    let key_path = dir.path().join("tls.key");
    std::fs::write(&ca_path, ca_cert).unwrap();
    std::fs::write(&cert_path, client_cert).unwrap();
    std::fs::write(&key_path, client_key).unwrap();

    let tls = TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path));
    let endpoint = format!("https://localhost:{}", addr.port());
    let mut client = grpc_client(&endpoint, &tls).await.unwrap();
    let response = client.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);
}

#[tokio::test]
async fn cli_requires_client_cert_for_https() {
    install_rustls_provider();

    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let dir = tempdir().unwrap();
    // Point XDG_CONFIG_HOME at the isolated temp dir so that default_tls_dir
    // cannot discover real client certs from the developer's machine.
    let _xdg_env = EnvVarGuard::set("XDG_CONFIG_HOME", &dir.path().to_string_lossy());
    let ca_path = dir.path().join("ca.crt");
    std::fs::write(&ca_path, ca_cert).unwrap();

    let tls = TlsOptions::new(Some(ca_path), None, None);
    let endpoint = format!("https://localhost:{}", addr.port());
    let result = grpc_client(&endpoint, &tls).await;
    assert!(result.is_err());
}
