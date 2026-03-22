// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxRequest, GetGatewayConfigRequest, GetGatewayConfigResponse,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxesRequest, ListSandboxesResponse, ProviderResponse, RevokeSshSessionRequest,
    RevokeSshSessionResponse, SandboxResponse, SandboxStreamEvent, ServiceStatus,
    UpdateProviderRequest, WatchSandboxRequest,
    open_shell_client::OpenShellClient,
    open_shell_server::{OpenShell, OpenShellServer},
};
use openshell_server::{MultiplexedService, health_router};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};

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
}

#[tokio::test]
async fn serves_grpc_and_http_on_same_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_service, http_service);

    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let mut client = OpenShellClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let response = client.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}/healthz"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.abort();
}
