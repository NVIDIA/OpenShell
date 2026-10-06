// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::{EnvVarGuard, build_ca, build_client_cert, build_server_cert};
use ryno_bootstrap::{get_gateway_metadata, load_active_gateway};
use ryno_cli::{
    run,
    tls::{TlsOptions, grpc_client},
};
use ryno_core::proto::{
    CreateProviderRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, ExchangeProviderSubjectTokenRequest,
    ExchangeProviderSubjectTokenResponse, ExecSandboxEvent, ExecSandboxInput, ExecSandboxRequest,
    GetProviderRequest, HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, ServiceStatus,
    UpdateProviderRequest,
    ryno_server::{Ryno, RynoServer},
};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Response, Status,
    transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig},
};

#[derive(Clone, Default)]
struct TestRyno;

#[tonic::async_trait]
impl Ryno for TestRyno {
    async fn peer_report_provider_readiness(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportProviderReadinessRequest>,
    ) -> Result<Response<ryno_core::proto::ReportProviderReadinessResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn peer_report_endpoint_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportEndpointStatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn peer_get_sandbox_provider_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxProviderStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxProviderStatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn report_endpoint_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportEndpointStatusResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ReportEndpointStatusResponse {},
        ))
    }

    async fn begin_rootfs_tar_staging(
        &self,
        _request: tonic::Request<ryno_core::proto::BeginRootfsTarStagingRequest>,
    ) -> Result<Response<ryno_core::proto::BeginRootfsTarStagingResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn report_main_process_exit(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportMainProcessExitRequest>,
    ) -> Result<Response<ryno_core::proto::ReportMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn finalize_main_process_exit(
        &self,
        _request: tonic::Request<ryno_core::proto::FinalizeMainProcessExitRequest>,
    ) -> Result<Response<ryno_core::proto::FinalizeMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn get_current_user(
        &self,
        _request: tonic::Request<ryno_core::proto::GetCurrentUserRequest>,
    ) -> Result<Response<ryno_core::proto::GetCurrentUserResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn health(
        &self,
        _request: tonic::Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn get_gateway_info(
        &self,
        _request: tonic::Request<ryno_core::proto::GetGatewayInfoRequest>,
    ) -> Result<Response<ryno_core::proto::GetGatewayInfoResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::CreateSandboxRequest>,
    ) -> Result<Response<ryno_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(ryno_core::proto::SandboxResponse::default()))
    }

    async fn stop_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::StopSandboxRequest>,
    ) -> Result<Response<ryno_core::proto::SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn start_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::StartSandboxRequest>,
    ) -> Result<Response<ryno_core::proto::SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxRequest>,
    ) -> Result<Response<ryno_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(ryno_core::proto::SandboxResponse::default()))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ryno_core::proto::ListSandboxesRequest>,
    ) -> Result<Response<ryno_core::proto::ListSandboxesResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ListSandboxesResponse::default(),
        ))
    }

    unimplemented_sandbox_template_rpcs!();

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<ryno_core::proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<ryno_core::proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ListSandboxProvidersResponse::default(),
        ))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<ryno_core::proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<ryno_core::proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<ryno_core::proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<ryno_core::proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::DetachSandboxProviderResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::DeleteSandboxRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteSandboxResponse>, Status> {
        Ok(Response::new(ryno_core::proto::DeleteSandboxResponse {
            sandbox_id: String::new(),
            outcome: ryno_core::proto::DeletionOutcome::Completed.into(),
        }))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxConfigRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::GetSandboxConfigResponse::default(),
        ))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<ryno_core::proto::GetGatewayConfigRequest>,
    ) -> Result<Response<ryno_core::proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::GetGatewayConfigResponse::default(),
        ))
    }

    async fn get_sandbox_provider_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxProviderStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxProviderStatusResponse>, Status> {
        Err(Status::unimplemented(
            "provider readiness is not exercised by this mock",
        ))
    }

    async fn report_provider_readiness(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportProviderReadinessRequest>,
    ) -> Result<Response<ryno_core::proto::ReportProviderReadinessResponse>, Status> {
        Err(Status::unimplemented(
            "provider installation reports are not exercised by this mock",
        ))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::GetSandboxProviderEnvironmentResponse::default(),
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
        _request: tonic::Request<ryno_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<ryno_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ServiceEndpointResponse::default(),
        ))
    }

    async fn get_service(
        &self,
        _: tonic::Request<ryno_core::proto::GetServiceRequest>,
    ) -> Result<Response<ryno_core::proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<ryno_core::proto::ListServicesRequest>,
    ) -> Result<Response<ryno_core::proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<ryno_core::proto::DeleteServiceRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn revoke_ssh_session(
        &self,
        _request: tonic::Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        Ok(Response::new(RevokeSshSessionResponse::default()))
    }

    async fn exchange_provider_subject_token(
        &self,
        _request: tonic::Request<ExchangeProviderSubjectTokenRequest>,
    ) -> Result<Response<ExchangeProviderSubjectTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
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
        _request: tonic::Request<ryno_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_provider_profile(
        &self,
        _request: tonic::Request<ryno_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<ryno_core::proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn import_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::UpdateProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::UpdateProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_provider_profile(
        &self,
        _request: tonic::Request<ryno_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteProviderProfileResponse>, Status> {
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
        _: tonic::Request<ryno_core::proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _: tonic::Request<ryno_core::proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<ryno_core::proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _: tonic::Request<ryno_core::proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<ryno_core::proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _: tonic::Request<ryno_core::proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteProviderRefreshResponse>, Status> {
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

    type WatchSandboxStream = tokio_stream::wrappers::ReceiverStream<
        Result<ryno_core::proto::SandboxStreamEvent, Status>,
    >;
    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::GatewayMessage, Status>>;

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::WatchSandboxRequest>,
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

    type ExecSandboxInteractiveStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    async fn exec_sandbox_interactive(
        &self,
        _request: tonic::Request<tonic::Streaming<ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_config(
        &self,
        _request: tonic::Request<ryno_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<ryno_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<ryno_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<ryno_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_sandbox_configuration(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportSandboxConfigurationRequest>,
    ) -> Result<Response<ryno_core::proto::ReportSandboxConfigurationResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<ryno_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<ryno_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<ryno_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<ryno_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<ryno_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<ryno_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<ryno_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<ryno_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<ryno_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<ryno_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<ryno_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn issue_sandbox_token(
        &self,
        _request: tonic::Request<ryno_core::proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<ryno_core::proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<ryno_core::proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<ryno_core::proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type PeerRelayStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::PeerRelayFrame, Status>>;

    async fn peer_relay(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::PeerRelayFrame>>,
    ) -> Result<Response<Self::PeerRelayStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::TcpForwardFrame, Status>>;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn create_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::CreateWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::CreateWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::GetWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::GetWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspaces(
        &self,
        _request: tonic::Request<ryno_core::proto::ListWorkspacesRequest>,
    ) -> Result<Response<ryno_core::proto::ListWorkspacesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::DeleteWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn add_workspace_member(
        &self,
        _request: tonic::Request<ryno_core::proto::AddWorkspaceMemberRequest>,
    ) -> Result<Response<ryno_core::proto::AddWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn remove_workspace_member(
        &self,
        _request: tonic::Request<ryno_core::proto::RemoveWorkspaceMemberRequest>,
    ) -> Result<Response<ryno_core::proto::RemoveWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspace_members(
        &self,
        _request: tonic::Request<ryno_core::proto::ListWorkspaceMembersRequest>,
    ) -> Result<Response<ryno_core::proto::ListWorkspaceMembersResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
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
            .add_service(RynoServer::new(TestRyno))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    addr
}

fn write_gateway_mtls_bundle(
    config_dir: &std::path::Path,
    gateway_name: &str,
    ca_cert: &str,
    client_cert: &str,
    client_key: &str,
) {
    let mtls = config_dir
        .join("ryno")
        .join("gateways")
        .join(gateway_name)
        .join("mtls");
    std::fs::create_dir_all(&mtls).unwrap();
    std::fs::write(mtls.join("ca.crt"), ca_cert).unwrap();
    std::fs::write(mtls.join("tls.crt"), client_cert).unwrap();
    std::fs::write(mtls.join("tls.key"), client_key).unwrap();
}

fn isolated_gateway_add_env(
    config_dir: &std::path::Path,
    state_dir: &std::path::Path,
) -> EnvVarGuard {
    let xdg_config = config_dir.to_string_lossy().into_owned();
    let xdg_state = state_dir.to_string_lossy().into_owned();
    let local_tls_dir = state_dir.join("no-package-managed-tls");
    let local_tls = local_tls_dir.to_string_lossy().into_owned();

    EnvVarGuard::set(&[
        ("XDG_CONFIG_HOME", xdg_config.as_str()),
        ("XDG_STATE_HOME", xdg_state.as_str()),
        ("HOME", xdg_state.as_str()),
        ("RYNO_LOCAL_TLS_DIR", local_tls.as_str()),
        ("RYNO_GATEWAY", "unused-by-named-gateway-add"),
    ])
}

#[tokio::test]
async fn gateway_add_mtls_loopback_uses_explicit_gateway_name() {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();
    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "k8s",
        &ca_cert,
        &client_cert,
        &client_key,
    );
    let _env = isolated_gateway_add_env(config_dir.path(), state_dir.path());

    let endpoint = format!("https://localhost:{}", addr.port());
    run::gateway_add(
        &endpoint,
        Some("k8s"),
        None,
        true,
        None,
        "ryno-cli",
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let metadata = get_gateway_metadata("k8s").unwrap();
    assert_eq!(metadata.name, "k8s");
    assert_eq!(metadata.gateway_endpoint, endpoint);
    assert_eq!(metadata.auth_mode.as_deref(), Some("mtls"));
    assert_eq!(load_active_gateway().as_deref(), Some("k8s"));
    assert!(get_gateway_metadata("ryno").is_none());
}

#[tokio::test]
async fn gateway_add_mtls_loopback_without_name_uses_ryno_default() {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();
    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "ryno",
        &ca_cert,
        &client_cert,
        &client_key,
    );
    let _env = isolated_gateway_add_env(config_dir.path(), state_dir.path());

    let endpoint = format!("https://localhost:{}", addr.port());
    run::gateway_add(
        &endpoint, None, None, true, None, "ryno-cli", None, None, false,
    )
    .await
    .unwrap();

    let metadata = get_gateway_metadata("ryno").unwrap();
    assert_eq!(metadata.name, "ryno");
    assert_eq!(metadata.gateway_endpoint, endpoint);
    assert_eq!(metadata.auth_mode.as_deref(), Some("mtls"));
    assert_eq!(load_active_gateway().as_deref(), Some("ryno"));
}

#[tokio::test]
async fn gateway_add_mtls_loopback_explicit_name_does_not_fallback_to_ryno_certs() {
    let (ca, ca_key) = build_ca();
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "ryno",
        &ca_cert,
        &client_cert,
        &client_key,
    );
    let _env = isolated_gateway_add_env(config_dir.path(), state_dir.path());

    let err = run::gateway_add(
        "https://localhost:1",
        Some("k8s"),
        None,
        true,
        None,
        "ryno-cli",
        None,
        None,
        false,
    )
    .await
    .expect_err("explicit name should require matching named mTLS material");

    assert!(err.to_string().contains("gateway 'k8s'"));
    assert!(get_gateway_metadata("k8s").is_none());
    assert!(load_active_gateway().is_none());
}

#[tokio::test]
async fn cli_connects_with_client_cert() {
    let _env = EnvVarGuard::set(&[]);

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
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let dir = tempdir().unwrap();
    // Point XDG_CONFIG_HOME at the isolated temp dir so that default_tls_dir
    // cannot discover real client certs from the developer's machine.
    let xdg_path = dir.path().to_string_lossy();
    let _xdg_env = EnvVarGuard::set(&[("XDG_CONFIG_HOME", &xdg_path)]);
    let ca_path = dir.path().join("ca.crt");
    std::fs::write(&ca_path, ca_cert).unwrap();

    let tls = TlsOptions::new(Some(ca_path), None, None);
    let endpoint = format!("https://localhost:{}", addr.port());
    let result = grpc_client(&endpoint, &tls).await;
    assert!(result.is_err());
}

async fn run_server_no_client_auth(
    server_cert: String,
    server_key: String,
) -> std::net::SocketAddr {
    let identity = Identity::from_pem(server_cert, server_key);
    let tls = ServerTlsConfig::new().identity(identity);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(RynoServer::new(TestRyno))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    addr
}

#[tokio::test]
async fn cli_connects_with_gateway_insecure() {
    let _env = EnvVarGuard::set(&[]);

    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);

    let addr = run_server_no_client_auth(server_cert, server_key).await;

    let mut tls = TlsOptions::default();
    tls.gateway_insecure = true;

    let endpoint = format!("https://localhost:{}", addr.port());
    let mut client = grpc_client(&endpoint, &tls).await.unwrap();
    let response = client.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);
}
