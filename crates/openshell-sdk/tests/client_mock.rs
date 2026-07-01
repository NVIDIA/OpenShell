// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! High-level [`OpenShellClient`] tests against an in-process mock gateway.
//!
//! The mock binds an ephemeral plaintext TCP listener and serves the
//! `OpenShell` gRPC service. Tests dial it via `http://127.0.0.1:<port>` so
//! TLS and auth code paths are skipped — those are exercised by the CLI's
//! `mtls_integration` and OIDC tests.

use openshell_core::proto;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_sdk::{
    AuthConfig, ClientConfig, ExecOptions, ListOptions, OpenShellClient, Refresh, RefreshError,
    RefreshedToken, SandboxPhase, SandboxSpec, ServiceStatus as SdkServiceStatus,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Response, Status};

/// Captured fixture state — what the mock observed and the canned replies it
/// returned. One per test so assertions are scoped.
#[derive(Default)]
struct MockState {
    last_get_name: Mutex<Option<String>>,
    last_create: Mutex<Option<proto::CreateSandboxRequest>>,
    last_delete_name: Mutex<Option<String>>,
    last_list_request: Mutex<Option<proto::ListSandboxesRequest>>,
    last_exec_request: Mutex<Option<proto::ExecSandboxRequest>>,
    get_calls: AtomicU32,
    phase_sequence: Vec<proto::SandboxPhase>,
    get_returns_not_found: bool,
    not_found_after: Option<u32>,
    /// When set, `health` rejects any request whose `authorization` header
    /// does not match this exact value (e.g. `"Bearer fresh-token"`).
    require_bearer: Option<String>,
    /// Count of requests rejected by the `require_bearer` gate.
    unauth_hits: AtomicU32,
}

#[derive(Clone)]
struct TestOpenShell {
    state: Arc<MockState>,
}

fn sandbox_with_phase(name: &str, phase: proto::SandboxPhase) -> proto::Sandbox {
    proto::Sandbox {
        metadata: Some(proto::datamodel::v1::ObjectMeta {
            id: format!("id-{name}"),
            name: name.to_string(),
            created_at_ms: 0,
            labels: HashMap::new(),
            resource_version: 1,
        }),
        spec: None,
        status: Some(proto::SandboxStatus {
            phase: phase.into(),
            ..Default::default()
        }),
    }
}

#[tonic::async_trait]
impl OpenShell for TestOpenShell {
    async fn health(
        &self,
        request: tonic::Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        if let Some(expected) = &self.state.require_bearer {
            let got = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            if got != Some(expected.as_str()) {
                self.state.unauth_hits.fetch_add(1, Ordering::SeqCst);
                return Err(Status::unauthenticated("invalid or missing bearer token"));
            }
        }
        Ok(Response::new(proto::HealthResponse {
            status: proto::ServiceStatus::Healthy.into(),
            version: "test-1.2.3".to_string(),
        }))
    }

    async fn update_provider_profiles(
        &self,
        _: tonic::Request<proto::UpdateProviderProfilesRequest>,
    ) -> Result<Response<proto::UpdateProviderProfilesResponse>, Status> {
        Ok(Response::new(
            proto::UpdateProviderProfilesResponse::default(),
        ))
    }

    async fn create_sandbox(
        &self,
        request: tonic::Request<proto::CreateSandboxRequest>,
    ) -> Result<Response<proto::SandboxResponse>, Status> {
        let req = request.into_inner();
        let name = if req.name.is_empty() {
            "generated".to_string()
        } else {
            req.name.clone()
        };
        *self.state.last_create.lock().await = Some(req);
        Ok(Response::new(proto::SandboxResponse {
            sandbox: Some(sandbox_with_phase(&name, proto::SandboxPhase::Provisioning)),
        }))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<proto::GetSandboxRequest>,
    ) -> Result<Response<proto::SandboxResponse>, Status> {
        let name = request.into_inner().name;
        *self.state.last_get_name.lock().await = Some(name.clone());
        let count = self.state.get_calls.fetch_add(1, Ordering::SeqCst);

        if self.state.get_returns_not_found {
            return Err(Status::not_found(format!("sandbox '{name}' not found")));
        }
        if let Some(threshold) = self.state.not_found_after
            && count >= threshold
        {
            return Err(Status::not_found(format!("sandbox '{name}' not found")));
        }

        let phase = self
            .state
            .phase_sequence
            .get(count as usize)
            .copied()
            .or_else(|| self.state.phase_sequence.last().copied())
            .unwrap_or(proto::SandboxPhase::Ready);

        Ok(Response::new(proto::SandboxResponse {
            sandbox: Some(sandbox_with_phase(&name, phase)),
        }))
    }

    async fn list_sandboxes(
        &self,
        request: tonic::Request<proto::ListSandboxesRequest>,
    ) -> Result<Response<proto::ListSandboxesResponse>, Status> {
        *self.state.last_list_request.lock().await = Some(request.into_inner());
        Ok(Response::new(proto::ListSandboxesResponse {
            sandboxes: vec![
                sandbox_with_phase("alpha", proto::SandboxPhase::Ready),
                sandbox_with_phase("beta", proto::SandboxPhase::Provisioning),
            ],
        }))
    }

    async fn list_sandbox_providers(
        &self,
        _: tonic::Request<proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(proto::ListSandboxProvidersResponse::default()))
    }

    async fn attach_sandbox_provider(
        &self,
        _: tonic::Request<proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _: tonic::Request<proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            proto::DetachSandboxProviderResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        request: tonic::Request<proto::DeleteSandboxRequest>,
    ) -> Result<Response<proto::DeleteSandboxResponse>, Status> {
        let name = request.into_inner().name;
        *self.state.last_delete_name.lock().await = Some(name);
        Ok(Response::new(proto::DeleteSandboxResponse {
            deleted: true,
        }))
    }

    async fn create_ssh_session(
        &self,
        _: tonic::Request<proto::CreateSshSessionRequest>,
    ) -> Result<Response<proto::CreateSshSessionResponse>, Status> {
        Ok(Response::new(proto::CreateSshSessionResponse::default()))
    }

    async fn expose_service(
        &self,
        _: tonic::Request<proto::ExposeServiceRequest>,
    ) -> Result<Response<proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(proto::ServiceEndpointResponse::default()))
    }

    async fn get_service(
        &self,
        _: tonic::Request<proto::GetServiceRequest>,
    ) -> Result<Response<proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<proto::ListServicesRequest>,
    ) -> Result<Response<proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<proto::DeleteServiceRequest>,
    ) -> Result<Response<proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn revoke_ssh_session(
        &self,
        _: tonic::Request<proto::RevokeSshSessionRequest>,
    ) -> Result<Response<proto::RevokeSshSessionResponse>, Status> {
        Ok(Response::new(proto::RevokeSshSessionResponse::default()))
    }

    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::ExecSandboxEvent, Status>>;

    async fn exec_sandbox(
        &self,
        request: tonic::Request<proto::ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        *self.state.last_exec_request.lock().await = Some(request.into_inner());
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(proto::ExecSandboxEvent {
                    payload: Some(proto::exec_sandbox_event::Payload::Stdout(
                        proto::ExecSandboxStdout {
                            data: b"hello\n".to_vec(),
                        },
                    )),
                }))
                .await;
            let _ = tx
                .send(Ok(proto::ExecSandboxEvent {
                    payload: Some(proto::exec_sandbox_event::Payload::Stderr(
                        proto::ExecSandboxStderr {
                            data: b"warn\n".to_vec(),
                        },
                    )),
                }))
                .await;
            let _ = tx
                .send(Ok(proto::ExecSandboxEvent {
                    payload: Some(proto::exec_sandbox_event::Payload::Exit(
                        proto::ExecSandboxExit { exit_code: 7 },
                    )),
                }))
                .await;
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type ForwardTcpStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::TcpForwardFrame, Status>>;

    async fn forward_tcp(
        &self,
        _: tonic::Request<tonic::Streaming<proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type ExecSandboxInteractiveStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::ExecSandboxEvent, Status>>;

    async fn exec_sandbox_interactive(
        &self,
        _: tonic::Request<tonic::Streaming<proto::ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn create_provider(
        &self,
        _: tonic::Request<proto::CreateProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Ok(Response::new(proto::ProviderResponse::default()))
    }

    async fn get_provider(
        &self,
        _: tonic::Request<proto::GetProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Ok(Response::new(proto::ProviderResponse::default()))
    }

    async fn list_providers(
        &self,
        _: tonic::Request<proto::ListProvidersRequest>,
    ) -> Result<Response<proto::ListProvidersResponse>, Status> {
        Ok(Response::new(proto::ListProvidersResponse::default()))
    }

    async fn list_provider_profiles(
        &self,
        _: tonic::Request<proto::ListProviderProfilesRequest>,
    ) -> Result<Response<proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_provider_profile(
        &self,
        _: tonic::Request<proto::GetProviderProfileRequest>,
    ) -> Result<Response<proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn import_provider_profiles(
        &self,
        _: tonic::Request<proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn lint_provider_profiles(
        &self,
        _: tonic::Request<proto::LintProviderProfilesRequest>,
    ) -> Result<Response<proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn update_provider(
        &self,
        _: tonic::Request<proto::UpdateProviderRequest>,
    ) -> Result<Response<proto::ProviderResponse>, Status> {
        Ok(Response::new(proto::ProviderResponse::default()))
    }

    async fn get_provider_refresh_status(
        &self,
        _: tonic::Request<proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _: tonic::Request<proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _: tonic::Request<proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _: tonic::Request<proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<proto::DeleteProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider(
        &self,
        _: tonic::Request<proto::DeleteProviderRequest>,
    ) -> Result<Response<proto::DeleteProviderResponse>, Status> {
        Ok(Response::new(proto::DeleteProviderResponse::default()))
    }

    async fn delete_provider_profile(
        &self,
        _: tonic::Request<proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox_config(
        &self,
        _: tonic::Request<proto::GetSandboxConfigRequest>,
    ) -> Result<Response<proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(proto::GetSandboxConfigResponse::default()))
    }

    async fn get_gateway_config(
        &self,
        _: tonic::Request<proto::GetGatewayConfigRequest>,
    ) -> Result<Response<proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(proto::GetGatewayConfigResponse::default()))
    }

    async fn update_config(
        &self,
        _: tonic::Request<proto::UpdateConfigRequest>,
    ) -> Result<Response<proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _: tonic::Request<proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<proto::GetSandboxPolicyStatusResponse>, Status> {
        Ok(Response::new(
            proto::GetSandboxPolicyStatusResponse::default(),
        ))
    }

    async fn list_sandbox_policies(
        &self,
        _: tonic::Request<proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn report_policy_status(
        &self,
        _: tonic::Request<proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _: tonic::Request<proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<proto::GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            proto::GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn get_sandbox_logs(
        &self,
        _: tonic::Request<proto::GetSandboxLogsRequest>,
    ) -> Result<Response<proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn push_sandbox_logs(
        &self,
        _: tonic::Request<tonic::Streaming<proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type WatchSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::SandboxStreamEvent, Status>>;

    async fn watch_sandbox(
        &self,
        _: tonic::Request<proto::WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn submit_policy_analysis(
        &self,
        _: tonic::Request<proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_draft_policy(
        &self,
        _: tonic::Request<proto::GetDraftPolicyRequest>,
    ) -> Result<Response<proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn approve_draft_chunk(
        &self,
        _: tonic::Request<proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _: tonic::Request<proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn reject_draft_chunk(
        &self,
        _: tonic::Request<proto::RejectDraftChunkRequest>,
    ) -> Result<Response<proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn edit_draft_chunk(
        &self,
        _: tonic::Request<proto::EditDraftChunkRequest>,
    ) -> Result<Response<proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn undo_draft_chunk(
        &self,
        _: tonic::Request<proto::UndoDraftChunkRequest>,
    ) -> Result<Response<proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn clear_draft_chunks(
        &self,
        _: tonic::Request<proto::ClearDraftChunksRequest>,
    ) -> Result<Response<proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_draft_history(
        &self,
        _: tonic::Request<proto::GetDraftHistoryRequest>,
    ) -> Result<Response<proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type ConnectSupervisorStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::GatewayMessage, Status>>;

    async fn connect_supervisor(
        &self,
        _: tonic::Request<tonic::Streaming<proto::SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _: tonic::Request<tonic::Streaming<proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn issue_sandbox_token(
        &self,
        _: tonic::Request<proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn refresh_sandbox_token(
        &self,
        _: tonic::Request<proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

/// Spin up the mock gateway, return its endpoint URL.
async fn start_mock(state: Arc<MockState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{addr}");
    let stream = TcpListenerStream::new(listener);
    let svc = OpenShellServer::new(TestOpenShell { state });
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(stream)
            .await;
    });
    endpoint
}

async fn connect(endpoint: &str) -> OpenShellClient {
    OpenShellClient::connect(ClientConfig::new(endpoint))
        .await
        .expect("connect should succeed against local mock")
}

#[tokio::test]
async fn health_returns_curated_snapshot() {
    let state = Arc::new(MockState::default());
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let h = client.health().await.unwrap();
    assert_eq!(h.status, SdkServiceStatus::Healthy);
    assert_eq!(h.version, "test-1.2.3");
}

#[tokio::test]
async fn create_sandbox_passes_spec_through() {
    let state = Arc::new(MockState::default());
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let mut labels = HashMap::new();
    labels.insert("team".to_string(), "core".to_string());

    let spec = SandboxSpec {
        name: Some("my-box".to_string()),
        image: Some("ghcr.io/foo:bar".to_string()),
        labels: labels.clone(),
        gpu: true,
        ..Default::default()
    };

    let result = client.create_sandbox(spec).await.unwrap();
    assert_eq!(result.name, "my-box");
    assert_eq!(result.phase, SandboxPhase::Provisioning);

    let observed = state.last_create.lock().await.clone().unwrap();
    assert_eq!(observed.name, "my-box");
    assert_eq!(observed.labels, labels);
    let observed_spec = observed.spec.unwrap();
    assert!(
        observed_spec
            .resource_requirements
            .as_ref()
            .and_then(|r| r.gpu.as_ref())
            .is_some()
    );
    assert_eq!(
        observed_spec.template.as_ref().unwrap().image,
        "ghcr.io/foo:bar"
    );
}

#[tokio::test]
async fn get_sandbox_sends_name_and_maps_phase() {
    let state = Arc::new(MockState {
        phase_sequence: vec![proto::SandboxPhase::Ready],
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let sandbox = client.get_sandbox("my-box").await.unwrap();
    assert_eq!(sandbox.name, "my-box");
    assert_eq!(sandbox.id, "id-my-box");
    assert_eq!(sandbox.phase, SandboxPhase::Ready);

    let observed = state.last_get_name.lock().await.clone();
    assert_eq!(observed.as_deref(), Some("my-box"));
}

#[tokio::test]
async fn list_sandboxes_propagates_filters() {
    let state = Arc::new(MockState::default());
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let opts = ListOptions {
        limit: 25,
        offset: 5,
        label_selector: Some("team=core".to_string()),
    };
    let items = client.list_sandboxes(opts).await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].name, "alpha");
    assert_eq!(items[0].phase, SandboxPhase::Ready);
    assert_eq!(items[1].phase, SandboxPhase::Provisioning);

    let observed = state.last_list_request.lock().await.clone().unwrap();
    assert_eq!(observed.limit, 25);
    assert_eq!(observed.offset, 5);
    assert_eq!(observed.label_selector, "team=core");
}

#[tokio::test]
async fn delete_sandbox_returns_server_ack() {
    let state = Arc::new(MockState::default());
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let deleted = client.delete_sandbox("doomed").await.unwrap();
    assert!(deleted);

    let observed = state.last_delete_name.lock().await.clone();
    assert_eq!(observed.as_deref(), Some("doomed"));
}

#[tokio::test]
async fn wait_ready_transitions_through_phases() {
    let state = Arc::new(MockState {
        phase_sequence: vec![
            proto::SandboxPhase::Provisioning,
            proto::SandboxPhase::Provisioning,
            proto::SandboxPhase::Ready,
        ],
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let sandbox = client
        .wait_ready("my-box", std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(sandbox.phase, SandboxPhase::Ready);
    assert!(state.get_calls.load(Ordering::SeqCst) >= 3);
}

#[tokio::test]
async fn wait_ready_surfaces_error_phase() {
    let state = Arc::new(MockState {
        phase_sequence: vec![proto::SandboxPhase::Error],
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let err = client
        .wait_ready("my-box", std::time::Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "connect");
}

#[tokio::test]
async fn wait_deleted_returns_when_get_reports_not_found() {
    let state = Arc::new(MockState {
        phase_sequence: vec![proto::SandboxPhase::Deleting],
        not_found_after: Some(2),
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    client
        .wait_deleted("my-box", std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert!(state.get_calls.load(Ordering::SeqCst) >= 3);
}

#[tokio::test]
async fn get_sandbox_not_found_maps_to_typed_error() {
    let state = Arc::new(MockState {
        get_returns_not_found: true,
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let err = client.get_sandbox("missing").await.unwrap_err();
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn exec_buffers_stdout_stderr_and_exit() {
    let state = Arc::new(MockState {
        phase_sequence: vec![proto::SandboxPhase::Ready],
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;
    let client = connect(&endpoint).await;

    let result = client
        .exec(
            "my-box",
            &["echo".to_string(), "hello".to_string()],
            ExecOptions {
                workdir: Some("/work".to_string()),
                timeout: Some(std::time::Duration::from_secs(10)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 7);
    assert_eq!(result.stdout, b"hello\n");
    assert_eq!(result.stderr, b"warn\n");

    let observed = state.last_exec_request.lock().await.clone().unwrap();
    assert_eq!(observed.sandbox_id, "id-my-box");
    assert_eq!(
        observed.command,
        vec!["echo".to_string(), "hello".to_string()]
    );
    assert_eq!(observed.workdir, "/work");
    assert_eq!(observed.timeout_seconds, 10);
}

/// Refresher that hands out a fixed "fresh-token" and counts invocations.
struct OneShotRefresher {
    calls: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl Refresh for OneShotRefresher {
    async fn refresh(&self) -> Result<RefreshedToken, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        Ok(RefreshedToken::new("fresh-token").with_expires_at(far_future))
    }
}

/// A request rejected with `Unauthenticated` (revoked token that still looks
/// valid) must trigger a forced refresh and a single retry that succeeds.
#[tokio::test]
async fn reactive_refresh_recovers_from_unauthenticated() {
    let far_future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let state = Arc::new(MockState {
        require_bearer: Some("Bearer fresh-token".to_string()),
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;

    let calls = Arc::new(AtomicU32::new(0));
    let refresher = Arc::new(OneShotRefresher {
        calls: Arc::clone(&calls),
    });

    // Seed a stale-but-unexpired token: the proactive path won't refresh it
    // (expiry is far off), so only the reactive Unauthenticated path can.
    let mut config = ClientConfig::new(&endpoint);
    config.auth = Some(AuthConfig::Oidc {
        token: "stale-token".to_string(),
        expires_at: Some(far_future),
        refresh: Some(refresher),
    });
    let client = OpenShellClient::connect(config).await.unwrap();

    let health = client.health().await.unwrap();
    assert_eq!(health.status, SdkServiceStatus::Healthy);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "forced refresh should fire exactly once on Unauthenticated"
    );
    assert_eq!(
        state.unauth_hits.load(Ordering::SeqCst),
        1,
        "first request rejected with stale token, retry accepted with fresh token"
    );
}

/// Without a refresher, an `Unauthenticated` response is surfaced as an auth
/// error rather than retried in a loop.
#[tokio::test]
async fn unauthenticated_without_refresher_surfaces_error() {
    let state = Arc::new(MockState {
        require_bearer: Some("Bearer never-matches".to_string()),
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;

    let mut config = ClientConfig::new(&endpoint);
    config.auth = Some(AuthConfig::oidc("static-token"));
    let client = OpenShellClient::connect(config).await.unwrap();

    let err = client.health().await.unwrap_err();
    assert_eq!(err.code(), "auth", "expected an auth error, got: {err:?}");
    assert_eq!(
        state.unauth_hits.load(Ordering::SeqCst),
        1,
        "exactly one attempt; no retry without a refresher"
    );
}

/// Regression (P1): raw RPCs do not drive refresh. A call through the plain
/// `raw_grpc()` accessor keeps sending the seeded token, while
/// `raw_grpc_fresh()` proactively refreshes a near-expiry token into the
/// shared slot so the subsequent raw call is accepted.
#[tokio::test]
async fn raw_grpc_fresh_refreshes_before_raw_call() {
    let state = Arc::new(MockState {
        require_bearer: Some("Bearer fresh-token".to_string()),
        ..Default::default()
    });
    let endpoint = start_mock(state.clone()).await;

    let calls = Arc::new(AtomicU32::new(0));
    let refresher = Arc::new(OneShotRefresher {
        calls: Arc::clone(&calls),
    });

    // Near-expiry token so the proactive path will refresh it.
    let near = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5;
    let mut config = ClientConfig::new(&endpoint);
    config.auth = Some(AuthConfig::Oidc {
        token: "stale-token".to_string(),
        expires_at: Some(near),
        refresh: Some(refresher),
    });
    let client = OpenShellClient::connect(config).await.unwrap();

    // Plain raw accessor does not refresh: the seeded token is rejected.
    let err = client
        .raw_grpc()
        .health(proto::HealthRequest {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "raw_grpc must not trigger a refresh"
    );

    // _fresh accessor refreshes the near-expiry token first; the raw call is
    // then accepted with the fresh bearer.
    let mut grpc = client.raw_grpc_fresh().await.unwrap();
    grpc.health(proto::HealthRequest {}).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "raw_grpc_fresh must refresh the near-expiry token exactly once"
    );
}
