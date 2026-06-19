// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal mock gRPC gateway for TUI tests.
//!
//! The TUI's gateway-switch flow needs a reachable gRPC endpoint to prove it
//! connected to the right server — but it doesn't need any real business logic.
//! [`MockGateway`] implements the full [`OpenShell`] trait with stubs so that
//! tonic is satisfied, while only [`list_providers`](OpenShell::list_providers)
//! does meaningful work (counting calls so tests can assert connectivity).
//!
//! Use [`start_gateway`] to bind a random loopback port and get a
//! [`RunningGateway`] handle whose `provider_calls` counter you can check.

use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use openshell_core::proto::{
    self,
    open_shell_server::{OpenShell, OpenShellServer},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Certificate as TonicCert, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

#[derive(Clone)]
pub struct MockGateway {
    provider_name: String,
    provider_calls: Arc<AtomicUsize>,
    required_edge_token: Option<String>,
    required_bearer_token: Option<String>,
}

impl MockGateway {
    fn provider(&self) -> proto::Provider {
        proto::Provider {
            metadata: Some(proto::datamodel::v1::ObjectMeta {
                id: format!("id-{}", self.provider_name),
                name: self.provider_name.clone(),
                ..Default::default()
            }),
            r#type: "mock".to_string(),
            ..Default::default()
        }
    }

    fn check_auth<T>(&self, request: &tonic::Request<T>) -> Result<(), Status> {
        if let Some(ref expected) = self.required_edge_token {
            match request.metadata().get("cf-access-jwt-assertion") {
                Some(v) if v.to_str().unwrap_or("") == expected => {}
                _ => return Err(Status::unauthenticated("missing or invalid edge token")),
            }
        }
        if let Some(ref expected) = self.required_bearer_token {
            let expected_value = format!("Bearer {expected}");
            match request.metadata().get("authorization") {
                Some(v) if v.to_str().unwrap_or("") == expected_value => {}
                _ => return Err(Status::unauthenticated("missing or invalid bearer token")),
            }
        }
        Ok(())
    }
}

fn empty_stream<T>() -> ReceiverStream<Result<T, Status>> {
    let (_tx, rx) = mpsc::channel(1);
    ReceiverStream::new(rx)
}

fn empty_box_stream<T>() -> Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>
where
    T: Send + 'static,
{
    Box::pin(tokio_stream::empty())
}

#[tonic::async_trait]
impl OpenShell for MockGateway {
    type WatchSandboxStream = ReceiverStream<Result<proto::SandboxStreamEvent, Status>>;
    type ExecSandboxStream = ReceiverStream<Result<proto::ExecSandboxEvent, Status>>;
    type ExecSandboxInteractiveStream = ReceiverStream<Result<proto::ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream = ReceiverStream<Result<proto::GatewayMessage, Status>>;
    type RelayStreamStream = ReceiverStream<Result<proto::RelayFrame, Status>>;
    type ForwardTcpStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<proto::TcpForwardFrame, Status>> + Send>>;

    async fn health(
        &self,
        request: tonic::Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        self.check_auth(&request)?;
        Ok(Response::new(proto::HealthResponse {
            status: proto::ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<proto::CreateSandboxRequest>,
    ) -> Result<Response<proto::SandboxResponse>, Status> {
        Ok(Response::new(proto::SandboxResponse::default()))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<proto::GetSandboxRequest>,
    ) -> Result<Response<proto::SandboxResponse>, Status> {
        Ok(Response::new(proto::SandboxResponse::default()))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<proto::ListSandboxesRequest>,
    ) -> Result<Response<proto::ListSandboxesResponse>, Status> {
        Ok(Response::new(proto::ListSandboxesResponse::default()))
    }

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(proto::ListSandboxProvidersResponse::default()))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            proto::DetachSandboxProviderResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<proto::DeleteSandboxRequest>,
    ) -> Result<Response<proto::DeleteSandboxResponse>, Status> {
        Ok(Response::new(proto::DeleteSandboxResponse {
            deleted: true,
        }))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<proto::GetSandboxConfigRequest>,
    ) -> Result<Response<proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(proto::GetSandboxConfigResponse::default()))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<proto::GetGatewayConfigRequest>,
    ) -> Result<Response<proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(proto::GetGatewayConfigResponse {
            settings: std::collections::HashMap::default(),
            settings_revision: 1,
        }))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<proto::GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            proto::GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn create_ssh_session(
        &self,
        _request: tonic::Request<proto::CreateSshSessionRequest>,
    ) -> Result<Response<proto::CreateSshSessionResponse>, Status> {
        Ok(Response::new(proto::CreateSshSessionResponse::default()))
    }

    async fn expose_service(
        &self,
        _request: tonic::Request<proto::ExposeServiceRequest>,
    ) -> Result<Response<proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(proto::ServiceEndpointResponse::default()))
    }

    async fn get_service(
        &self,
        _request: tonic::Request<proto::GetServiceRequest>,
    ) -> Result<Response<proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _request: tonic::Request<proto::ListServicesRequest>,
    ) -> Result<Response<proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _request: tonic::Request<proto::DeleteServiceRequest>,
    ) -> Result<Response<proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn revoke_ssh_session(
        &self,
        _request: tonic::Request<proto::RevokeSshSessionRequest>,
    ) -> Result<Response<proto::RevokeSshSessionResponse>, Status> {
        Ok(Response::new(proto::RevokeSshSessionResponse::default()))
    }

    async fn create_provider(
        &self,
        _request: tonic::Request<proto::CreateProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_provider(
        &self,
        _request: tonic::Request<proto::GetProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_providers(
        &self,
        request: tonic::Request<proto::ListProvidersRequest>,
    ) -> Result<Response<proto::ListProvidersResponse>, Status> {
        self.check_auth(&request)?;
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(proto::ListProvidersResponse {
            providers: vec![self.provider()],
        }))
    }

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<proto::ListProviderProfilesRequest>,
    ) -> Result<Response<proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_provider_profile(
        &self,
        _request: tonic::Request<proto::GetProviderProfileRequest>,
    ) -> Result<Response<proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn import_provider_profiles(
        &self,
        _request: tonic::Request<proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<proto::LintProviderProfilesRequest>,
    ) -> Result<Response<proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_profile(
        &self,
        _request: tonic::Request<proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn update_provider(
        &self,
        _request: tonic::Request<proto::UpdateProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_provider_refresh_status(
        &self,
        _request: tonic::Request<proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _request: tonic::Request<proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _request: tonic::Request<proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _request: tonic::Request<proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<proto::DeleteProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider(
        &self,
        _request: tonic::Request<proto::DeleteProviderRequest>,
    ) -> Result<Response<proto::DeleteProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<proto::WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        Ok(Response::new(empty_stream()))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<proto::ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        Ok(Response::new(empty_stream()))
    }

    async fn exec_sandbox_interactive(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
        Ok(Response::new(empty_stream()))
    }

    async fn update_config(
        &self,
        _request: tonic::Request<proto::UpdateConfigRequest>,
    ) -> Result<Response<proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<proto::ListSandboxPoliciesResponse>, Status> {
        Ok(Response::new(proto::ListSandboxPoliciesResponse::default()))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<proto::GetSandboxLogsRequest>,
    ) -> Result<Response<proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<proto::GetDraftPolicyRequest>,
    ) -> Result<Response<proto::GetDraftPolicyResponse>, Status> {
        Ok(Response::new(proto::GetDraftPolicyResponse::default()))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<proto::RejectDraftChunkRequest>,
    ) -> Result<Response<proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<proto::EditDraftChunkRequest>,
    ) -> Result<Response<proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<proto::UndoDraftChunkRequest>,
    ) -> Result<Response<proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<proto::ClearDraftChunksRequest>,
    ) -> Result<Response<proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<proto::GetDraftHistoryRequest>,
    ) -> Result<Response<proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn issue_sandbox_token(
        &self,
        _request: tonic::Request<proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Ok(Response::new(empty_box_stream()))
    }
}

pub struct RunningGateway {
    pub endpoint: String,
    pub provider_calls: Arc<AtomicUsize>,
    pub task: JoinHandle<()>,
}

pub async fn start_gateway(provider_name: &str) -> RunningGateway {
    spawn_gateway(provider_name, None, None, None).await
}

pub async fn start_gateway_with_edge_token(
    provider_name: &str,
    required_token: &str,
) -> RunningGateway {
    spawn_gateway(
        provider_name,
        Some(required_token.to_string()),
        None,
        None,
    )
    .await
}

/// Start a TLS-only mock gateway (no client cert required) that validates
/// a Bearer token in every request. Used for OIDC gateway tests.
pub async fn start_gateway_with_tls_and_bearer(
    provider_name: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
    required_bearer_token: &str,
) -> RunningGateway {
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(server_cert_pem, server_key_pem));
    spawn_gateway(
        provider_name,
        None,
        Some(required_bearer_token.to_string()),
        Some(tls),
    )
    .await
}

/// Start a mutual-TLS mock gateway that requires a client certificate signed
/// by the given CA. Used for mTLS gateway tests.
pub async fn start_gateway_with_mtls(
    provider_name: &str,
    ca_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> RunningGateway {
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert_pem, server_key_pem))
        .client_ca_root(TonicCert::from_pem(ca_pem));
    spawn_gateway(provider_name, None, None, Some(tls)).await
}

async fn spawn_gateway(
    provider_name: &str,
    required_edge_token: Option<String>,
    required_bearer_token: Option<String>,
    tls: Option<ServerTlsConfig>,
) -> RunningGateway {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test gateway");
    let addr = listener.local_addr().expect("read test gateway addr");
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let service = MockGateway {
        provider_name: provider_name.to_string(),
        provider_calls: Arc::clone(&provider_calls),
        required_edge_token,
        required_bearer_token,
    };
    let use_tls = tls.is_some();
    let task = tokio::spawn(async move {
        let mut builder = Server::builder();
        if let Some(tls_config) = tls {
            builder = builder.tls_config(tls_config).unwrap();
        }
        builder
            .add_service(OpenShellServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve test gateway");
    });
    RunningGateway {
        endpoint: format!("{}://{addr}", if use_tls { "https" } else { "http" }),
        provider_calls,
        task,
    }
}
