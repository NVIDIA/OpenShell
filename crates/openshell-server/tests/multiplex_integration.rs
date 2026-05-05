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
    ExecSandboxEvent, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxesRequest, ListSandboxesResponse,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, SupervisorMessage, UpdateProviderRequest,
    WatchSandboxRequest,
    inference_server::InferenceServer,
    open_shell_client::OpenShellClient,
    open_shell_server::{OpenShell, OpenShellServer},
};
use openshell_server::{
    GatewayGrpcRouter, GatewayStandardHealth, MultiplexedService, OPENSHELL_SERVICE_NAME,
    health_router,
};

mod common;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::Code;
use tonic::{Response, Status};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
};
use tonic_reflection::pb::v1::{
    ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
    server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
};

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

#[tokio::test]
async fn serves_grpc_and_http_on_same_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let standard_health = GatewayStandardHealth::server(common::MAX_GRPC_DECODE);
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(openshell_core::proto::FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();
    let openshell =
        OpenShellServer::new(TestOpenShell).max_decoding_message_size(common::MAX_GRPC_DECODE);
    let inference = InferenceServer::new(common::TestInference)
        .max_decoding_message_size(common::MAX_GRPC_DECODE);
    let grpc_router = GatewayGrpcRouter::new(standard_health, reflection, openshell, inference);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_router, http_service);

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

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut health = HealthClient::new(channel);
    let response = health
        .check(HealthCheckRequest {
            service: OPENSHELL_SERVICE_NAME.to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status, ServingStatus::Serving as i32);

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

/// Verify tonic metadata ↔ HTTP header roundtrip for `x-request-id`.
///
/// This intentionally constructs its own request-ID layers from
/// `tower-http`'s public API rather than reusing the production macro
/// (which is crate-private). Production middleware composition and
/// layer ordering are covered by the unit tests in `multiplex::tests`.
#[tokio::test]
#[allow(deprecated)] // Legacy `OpenShell/Health` still used here to exercise response metadata paths.
async fn grpc_response_propagates_request_id() {
    use tower::ServiceBuilder;
    use tower_http::request_id::{
        MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
    };

    #[derive(Clone)]
    struct TestUuidRequestId;

    impl MakeRequestId for TestUuidRequestId {
        fn make_request_id<B>(&mut self, _req: &Request<B>) -> Option<RequestId> {
            let id = uuid::Uuid::new_v4().to_string();
            Some(RequestId::new(http::HeaderValue::from_str(&id).unwrap()))
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let standard_health = GatewayStandardHealth::server(common::MAX_GRPC_DECODE);
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(openshell_core::proto::FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();
    let openshell =
        OpenShellServer::new(TestOpenShell).max_decoding_message_size(common::MAX_GRPC_DECODE);
    let inference = InferenceServer::new(common::TestInference)
        .max_decoding_message_size(common::MAX_GRPC_DECODE);
    let grpc_router = GatewayGrpcRouter::new(standard_health, reflection, openshell, inference);

    let x_request_id = http::HeaderName::from_static("x-request-id");
    let grpc_service = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(
            x_request_id.clone(),
            TestUuidRequestId,
        ))
        .layer(PropagateRequestIdLayer::new(x_request_id))
        .service(grpc_router);
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

    // Server generates a UUID when client omits x-request-id.
    let response = client.health(HealthRequest {}).await.unwrap();
    let generated = response
        .metadata()
        .get("x-request-id")
        .expect("gRPC response should include server-generated x-request-id");
    uuid::Uuid::parse_str(generated.to_str().unwrap()).expect("should be a valid UUID");

    // Server preserves a client-supplied x-request-id.
    let mut request = tonic::Request::new(HealthRequest {});
    request
        .metadata_mut()
        .insert("x-request-id", "grpc-corr-id".parse().unwrap());
    let response = client.health(request).await.unwrap();
    let echoed = response.metadata().get("x-request-id").unwrap();
    assert_eq!(echoed.to_str().unwrap(), "grpc-corr-id");

    server.abort();
}

#[tokio::test]
async fn standard_grpc_health_reflection_multiplexed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let standard_health = GatewayStandardHealth::server(common::MAX_GRPC_DECODE);
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(openshell_core::proto::FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();
    let openshell =
        OpenShellServer::new(TestOpenShell).max_decoding_message_size(common::MAX_GRPC_DECODE);
    let inference = InferenceServer::new(common::TestInference)
        .max_decoding_message_size(common::MAX_GRPC_DECODE);
    let grpc_router = GatewayGrpcRouter::new(standard_health, reflection, openshell, inference);
    let http_service = health_router();
    let service = MultiplexedService::new(grpc_router, http_service);

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

    let endpoint = format!("http://{addr}");
    let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut health = HealthClient::new(channel);

    let check = health
        .check(HealthCheckRequest {
            service: OPENSHELL_SERVICE_NAME.to_string(),
        })
        .await
        .expect("health check")
        .into_inner();
    assert_eq!(check.status, ServingStatus::Serving as i32);

    let check_agg = health
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("aggregate health check")
        .into_inner();
    assert_eq!(check_agg.status, ServingStatus::Serving as i32);

    let watch_res = health
        .watch(HealthCheckRequest {
            service: OPENSHELL_SERVICE_NAME.to_string(),
        })
        .await;
    let Err(watch_err) = watch_res else {
        panic!("watch should fail with UNIMPLEMENTED");
    };
    assert_eq!(watch_err.code(), Code::Unimplemented);

    let channel2 = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut refl = ServerReflectionClient::new(channel2);

    let req = tonic::Request::new(tokio_stream::once(ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    }));
    let mut inbound = refl
        .server_reflection_info(req)
        .await
        .expect("reflection")
        .into_inner();
    let msg = inbound
        .next()
        .await
        .expect("stream item")
        .expect("reflection response");
    let response = msg.message_response.expect("message_response");
    match response {
        MessageResponse::ListServicesResponse(list) => {
            let names: Vec<&str> = list.service.iter().map(|s| s.name.as_str()).collect();
            assert!(
                names.contains(&"openshell.v1.OpenShell"),
                "expected openshell.v1.OpenShell in reflection list, got {names:?}"
            );
            assert!(
                names.contains(&"grpc.health.v1.Health"),
                "expected grpc.health.v1.Health in reflection list, got {names:?}"
            );
        }
        other => panic!("unexpected reflection response: {other:?}"),
    }

    server.abort();
}
