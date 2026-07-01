// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::{
    EnvVarGuard, build_ca, build_client_cert, build_server_cert, install_rustls_provider,
};
use openshell_bootstrap::load_last_sandbox;
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, ExecSandboxEvent,
    ExecSandboxInput, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, GpuResourceRequirements,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxProvidersRequest, ListSandboxProvidersResponse, ListSandboxesRequest,
    ListSandboxesResponse, PlatformEvent, ProviderResponse, RevokeSshSessionRequest,
    RevokeSshSessionResponse, Sandbox, SandboxCondition, SandboxLogLine, SandboxPhase,
    SandboxResponse, SandboxStatus, SandboxStreamEvent, ServiceStatus, SettingValue,
    SupervisorMessage, UpdateProviderRequest, WatchSandboxRequest, sandbox_stream_event,
    setting_value,
};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

#[derive(Clone, Default)]
struct SandboxState {
    deleted_names: Arc<Mutex<Vec<Vec<String>>>>,
    create_requests: Arc<Mutex<Vec<CreateSandboxRequest>>>,
    vm_error_after_started: Arc<AtomicBool>,
    vm_slow_progress_before_ready: Arc<AtomicBool>,
    vm_log_churn_before_ready: Arc<AtomicBool>,
    global_settings: Arc<Mutex<HashMap<String, SettingValue>>>,
}

#[derive(Clone, Default)]
struct TestOpenShell {
    state: SandboxState,
}

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
        request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let request = request.into_inner();
        let name = request.name.clone();
        self.state.create_requests.lock().await.push(request);
        let sandbox_name = if name.is_empty() {
            "test-sandbox".to_string()
        } else {
            name
        };

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("id-{sandbox_name}"),
                name: sandbox_name,
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
            }),
            ..Sandbox::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        Ok(Response::new(SandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let name = request.into_inner().name;
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("id-{name}"),
                name,
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
            }),
            ..Sandbox::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        Ok(Response::new(SandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse::default()))
    }

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<ListSandboxProvidersRequest>,
    ) -> Result<Response<ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(ListSandboxProvidersResponse::default()))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<AttachSandboxProviderRequest>,
    ) -> Result<Response<AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(AttachSandboxProviderResponse::default()))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<DetachSandboxProviderRequest>,
    ) -> Result<Response<DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(DetachSandboxProviderResponse::default()))
    }

    async fn delete_sandbox(
        &self,
        request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        self.state
            .deleted_names
            .lock()
            .await
            .push(vec![request.name]);
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
        Ok(Response::new(GetGatewayConfigResponse {
            settings: self.state.global_settings.lock().await.clone(),
            settings_revision: 1,
        }))
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
        request: tonic::Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;
        Ok(Response::new(CreateSshSessionResponse {
            sandbox_id,
            token: "test-token".to_string(),
            gateway_scheme: "https".to_string(),
            gateway_host: "localhost".to_string(),
            gateway_port: 443,
            ..CreateSshSessionResponse::default()
        }))
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
        Ok(Response::new(ProviderResponse::default()))
    }

    async fn get_provider(
        &self,
        _request: tonic::Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        Err(Status::not_found("provider not found"))
    }

    async fn list_providers(
        &self,
        _request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        Ok(Response::new(ListProvidersResponse::default()))
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

    async fn update_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::UpdateProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateProviderProfilesResponse>, Status> {
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
        Ok(Response::new(ProviderResponse::default()))
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
        Ok(Response::new(DeleteProviderResponse { deleted: true }))
    }

    type WatchSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream =
        tokio_stream::wrappers::ReceiverStream<Result<GatewayMessage, Status>>;

    async fn watch_sandbox(
        &self,
        request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let sandbox_id = request.into_inner().id;
        let (tx, rx) = mpsc::channel(4);
        let vm_error_after_started = self.state.vm_error_after_started.load(Ordering::SeqCst);
        let vm_slow_progress_before_ready = self
            .state
            .vm_slow_progress_before_ready
            .load(Ordering::SeqCst);
        let vm_log_churn_before_ready = self.state.vm_log_churn_before_ready.load(Ordering::SeqCst);

        tokio::spawn(async move {
            let mut provisioning = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: sandbox_id.clone(),
                    name: sandbox_id.trim_start_matches("id-").to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                }),
                ..Sandbox::default()
            };
            provisioning.set_phase(SandboxPhase::Provisioning as i32);
            let mut error = Sandbox {
                status: Some(SandboxStatus {
                    sandbox_name: sandbox_id.trim_start_matches("id-").to_string(),
                    conditions: vec![SandboxCondition {
                        r#type: "Ready".to_string(),
                        status: "False".to_string(),
                        reason: "ProcessExited".to_string(),
                        message: "VM process exited with status 0".to_string(),
                        last_transition_time: String::new(),
                    }],
                    ..Default::default()
                }),
                ..provisioning.clone()
            };
            error.set_phase(SandboxPhase::Error as i32);
            let mut ready = provisioning.clone();
            ready.set_phase(SandboxPhase::Ready as i32);

            let _ = tx
                .send(Ok(SandboxStreamEvent {
                    payload: Some(sandbox_stream_event::Payload::Sandbox(provisioning)),
                }))
                .await;
            if vm_error_after_started {
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                            source: "vm".to_string(),
                            reason: "Started".to_string(),
                            message: "Started VM launcher".to_string(),
                            ..PlatformEvent::default()
                        })),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Sandbox(error)),
                    }))
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                return;
            }
            if vm_log_churn_before_ready {
                for message in ["still booting", "still booting again"] {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    let _ = tx
                        .send(Ok(SandboxStreamEvent {
                            payload: Some(sandbox_stream_event::Payload::Log(SandboxLogLine {
                                sandbox_id: sandbox_id.clone(),
                                timestamp_ms: 0,
                                level: "INFO".to_string(),
                                target: "test".to_string(),
                                message: message.to_string(),
                                source: "gateway".to_string(),
                                fields: HashMap::new(),
                            })),
                        }))
                        .await;
                }
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Sandbox(ready)),
                    }))
                    .await;
                return;
            }
            if vm_slow_progress_before_ready {
                tokio::time::sleep(Duration::from_millis(600)).await;
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                            source: "vm".to_string(),
                            reason: "PreparingRootfs".to_string(),
                            message: "Preparing rootfs".to_string(),
                            ..PlatformEvent::default()
                        })),
                    }))
                    .await;
                tokio::time::sleep(Duration::from_millis(600)).await;
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                            source: "vm".to_string(),
                            reason: "CreatingRootDisk".to_string(),
                            message: "Formatting root disk".to_string(),
                            ..PlatformEvent::default()
                        })),
                    }))
                    .await;
                tokio::time::sleep(Duration::from_millis(600)).await;
                let _ = tx
                    .send(Ok(SandboxStreamEvent {
                        payload: Some(sandbox_stream_event::Payload::Sandbox(ready)),
                    }))
                    .await;
                return;
            }
            let _ = tx
                .send(Ok(SandboxStreamEvent {
                    payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                        reason: "Scheduled".to_string(),
                        message: "Sandbox scheduled".to_string(),
                        ..PlatformEvent::default()
                    })),
                }))
                .await;
            let _ = tx
                .send(Ok(SandboxStreamEvent {
                    payload: Some(sandbox_stream_event::Payload::Sandbox(ready)),
                }))
                .await;
        });

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
        _request: tonic::Request<openshell_core::proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<openshell_core::proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<openshell_core::proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<openshell_core::proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<openshell_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::TcpForwardFrame, Status>,
    >;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    openshell: TestOpenShell,
    _dir: TempDir,
}

async fn run_server() -> TestServer {
    install_rustls_provider();

    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let identity = Identity::from_pem(server_cert, server_key);
    let client_ca = TlsCertificate::from_pem(ca_cert.clone());
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);

    let openshell = TestOpenShell::default();
    let svc_openshell = openshell.clone();

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(OpenShellServer::new(svc_openshell))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.crt");
    let cert_path = dir.path().join("tls.crt");
    let key_path = dir.path().join("tls.key");
    fs::write(&ca_path, ca_cert).unwrap();
    fs::write(&cert_path, client_cert).unwrap();
    fs::write(&key_path, client_key).unwrap();

    let tls = TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path));
    let endpoint = format!("https://localhost:{}", addr.port());

    TestServer {
        endpoint,
        tls,
        openshell,
        _dir: dir,
    }
}

fn install_executable_script(
    dir: &TempDir,
    name: &str,
    contents: impl AsRef<[u8]>,
) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn install_fake_ssh(dir: &TempDir) -> std::path::PathBuf {
    install_executable_script(dir, "ssh", "#!/bin/sh\nexit 0\n")
}

fn install_fake_pgrep_no_match(dir: &TempDir) -> std::path::PathBuf {
    install_executable_script(dir, "pgrep", "#!/bin/sh\nexit 1\n")
}

fn install_fake_forward_process_helper(dir: &TempDir) -> std::path::PathBuf {
    // Linux validation reads exact `/proc` argv, so the fake child must look
    // like `ssh`, not Python or shell with appended tokens.
    let source_path = dir.path().join("fake-forward-process.rs");
    let binary_path = dir.path().join("fake-forward-process");
    fs::write(
        &source_path,
        r#"
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn main() {
    match std::env::var("OPENSHELL_FAKE_FORWARD_MODE").as_deref() {
        Ok("listen") => run_listener(),
        Ok("sleep") => loop {
            thread::sleep(Duration::from_secs(60));
        },
        _ => std::process::exit(2),
    }
}

fn run_listener() {
    let port = forward_port().expect("fake forward must receive an SSH -L argument");
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("fake forward must bind");
    for stream in listener.incoming() {
        let _ = stream;
    }
}

fn forward_port() -> Option<u16> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-L" {
            return args.get(index + 1).and_then(|value| local_port(value));
        }
        if let Some(value) = arg.strip_prefix("-L").filter(|value| !value.is_empty()) {
            return local_port(value);
        }
        index += 1;
    }
    None
}

fn local_port(forward: &str) -> Option<u16> {
    let (first, rest) = forward.split_once(':')?;
    if first.bytes().all(|byte| byte.is_ascii_digit()) {
        return first.parse().ok();
    }
    rest.split_once(':')?.0.parse().ok()
}
"#,
    )
    .unwrap();
    let status = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&source_path)
        .arg("-o")
        .arg(&binary_path)
        .status()
        .unwrap();
    assert!(status.success(), "failed to compile fake forward process");
    binary_path
}

fn install_fake_ps_for_pid_revalidation(
    dir: &TempDir,
    pid_path: &std::path::Path,
    command_path: &std::path::Path,
) {
    install_executable_script(
        dir,
        "ps",
        format!(
            r#"#!/bin/sh
set -eu

command_mode=0
requested_pid=""
previous=""

for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    if [ "$arg" = "command=" ]; then
      command_mode=1
    fi
    previous=""
    continue
  fi

  if [ "$previous" = "-p" ]; then
    requested_pid="$arg"
    previous=""
    continue
  fi

  case "$arg" in
    -o|-p)
      previous="$arg"
      ;;
  esac
done

expected_pid=""
if [ -s '{pid_path}' ]; then
  expected_pid="$(cat '{pid_path}')"
fi

if [ "$command_mode" = "1" ] && [ -n "$expected_pid" ] && [ "$requested_pid" = "$expected_pid" ] && [ -s '{command_path}' ]; then
  cat '{command_path}'
  printf '\n'
  exit 0
fi

exec /bin/ps "$@"
"#,
            pid_path = pid_path.display(),
            command_path = command_path.display(),
        ),
    );
}

async fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let output = std::process::Command::new("ps")
            .arg("-o")
            .arg("stat=")
            .arg("-p")
            .arg(pid.to_string())
            .stderr(std::process::Stdio::null())
            .output();
        let alive = output.is_ok_and(|output| {
            if !output.status.success() {
                return false;
            }
            let stat = String::from_utf8_lossy(&output.stdout);
            // Linux can leave the orphaned fake forward as a short-lived zombie
            // until the container's init process reaps it. A zombie has already
            // exited, so it satisfies this cleanup assertion.
            !stat.trim_start().starts_with('Z')
        });
        if !alive {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn install_fake_forwarding_ssh(dir: &TempDir) -> std::path::PathBuf {
    let pid_path = dir.path().join("fake-forward.pid");
    let command_path = dir.path().join("fake-forward.command");
    let helper_path = install_fake_forward_process_helper(dir);
    let ssh_path = install_executable_script(
        dir,
        "ssh",
        r#"#!/bin/sh
set -eu

forward=""
sandbox_id=""
saw_no_command=0
last_arg=""
previous=""

for arg in "$@"; do
  if [ "$previous" = "-L" ]; then
    forward="$arg"
    previous=""
    last_arg="$arg"
    continue
  fi

  if [ "$previous" = "-o" ]; then
    case "$arg" in
      ProxyCommand=*)
        sandbox_id="$(printf '%s\n' "$arg" | sed -n 's/.*--sandbox-id \([^ ]*\).*/\1/p')"
        ;;
    esac
    previous=""
    last_arg="$arg"
    continue
  fi

  case "$arg" in
    -N)
      saw_no_command=1
      ;;
    -L|-o)
      previous="$arg"
      ;;
  esac
  last_arg="$arg"
done

if [ -z "$forward" ]; then
  exit 0
fi

if [ "$saw_no_command" != "1" ] || [ "$last_arg" != "sandbox" ]; then
  exit 1
fi

first="${forward%%:*}"
rest="${forward#*:}"
case "$first" in
  ''|*[!0-9]*)
    port="${rest%%:*}"
    ;;
  *)
    port="$first"
    ;;
esac

if [ -z "$port" ] || [ -z "$sandbox_id" ]; then
  exit 1
fi

helper='@HELPER_PATH@'
echo "$$" > '@PID_PATH@'
printf '%s\n' "ssh -N -o ProxyCommand=/tmp/openshell ssh-proxy --gateway https://127.0.0.1:9443 --sandbox-id $sandbox_id --token test-token --gateway-name test-gateway -o ExitOnForwardFailure=yes -L $forward sandbox" > '@COMMAND_PATH@'
exec env OPENSHELL_FAKE_FORWARD_MODE=listen /bin/bash -c 'exec -a ssh "$0" "$@"' "$helper" -N -o "ProxyCommand=/tmp/openshell ssh-proxy --gateway https://127.0.0.1:9443 --sandbox-id $sandbox_id --token test-token --gateway-name test-gateway" -o ExitOnForwardFailure=yes -L "$forward" sandbox
"#
        .replace("@PID_PATH@", &pid_path.display().to_string())
        .replace("@COMMAND_PATH@", &command_path.display().to_string())
        .replace("@HELPER_PATH@", &helper_path.display().to_string()),
    );

    install_fake_ps_for_pid_revalidation(dir, &pid_path, &command_path);

    ssh_path
}

struct FakeUnreachableForward {
    log_path: std::path::PathBuf,
    pid_path: std::path::PathBuf,
}

fn install_fake_unreachable_forwarding_ssh(dir: &TempDir) -> FakeUnreachableForward {
    let log_path = dir.path().join("fake-forward.log");
    let pid_path = dir.path().join("fake-forward.pid");
    let helper_path = install_fake_forward_process_helper(dir);
    install_executable_script(
        dir,
        "ssh",
        r#"#!/bin/sh
set -eu

forward=""
sandbox_id=""
saw_no_command=0
last_arg=""
previous=""

for arg in "$@"; do
  if [ "$previous" = "-L" ]; then
    forward="$arg"
    previous=""
    last_arg="$arg"
    continue
  fi

  if [ "$previous" = "-o" ]; then
    case "$arg" in
      ProxyCommand=*)
        sandbox_id="$(printf '%s\n' "$arg" | sed -n 's/.*--sandbox-id \([^ ]*\).*/\1/p')"
        ;;
    esac
    previous=""
    last_arg="$arg"
    continue
  fi

  case "$arg" in
    -N)
      saw_no_command=1
      ;;
    -L|-o)
      previous="$arg"
      ;;
  esac
  last_arg="$arg"
done

if [ -z "$forward" ] || [ -z "$sandbox_id" ]; then
  exit 1
fi

if [ "$saw_no_command" != "1" ] || [ "$last_arg" != "sandbox" ]; then
  exit 1
fi

helper='@HELPER_PATH@'
echo "$$" > '@PID_PATH@'
exec env OPENSHELL_FAKE_FORWARD_MODE=sleep /bin/bash -c 'exec -a ssh "$0" "$@"' "$helper" -N -o "ProxyCommand=/tmp/openshell ssh-proxy --gateway https://127.0.0.1:9443 --sandbox-id $sandbox_id --token test-token --gateway-name test-gateway" -o ExitOnForwardFailure=yes -L "$forward" sandbox >'@LOG_PATH@' 2>&1
"#
        .replace("@LOG_PATH@", &log_path.display().to_string())
        .replace("@PID_PATH@", &pid_path.display().to_string())
        .replace("@HELPER_PATH@", &helper_path.display().to_string()),
    );

    FakeUnreachableForward { log_path, pid_path }
}

fn test_env(fake_ssh_dir: &TempDir, xdg_dir: &TempDir) -> EnvVarGuard {
    test_env_with(fake_ssh_dir, xdg_dir, &[])
}

fn test_env_with(
    fake_ssh_dir: &TempDir,
    xdg_dir: &TempDir,
    extra: &[(&'static str, String)],
) -> EnvVarGuard {
    let path = format!(
        "{}:{}",
        fake_ssh_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let xdg = xdg_dir.path().to_str().unwrap().to_string();

    let mut owned_pairs = vec![
        ("PATH", path),
        ("XDG_CONFIG_HOME", xdg.clone()),
        ("HOME", xdg),
    ];
    owned_pairs.extend(extra.iter().cloned());
    let pairs = owned_pairs
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();

    EnvVarGuard::set(&pairs)
}

async fn deleted_names(server: &TestServer) -> Vec<Vec<String>> {
    server.openshell.state.deleted_names.lock().await.clone()
}

async fn create_requests(server: &TestServer) -> Vec<CreateSandboxRequest> {
    server.openshell.state.create_requests.lock().await.clone()
}

async fn enable_providers_v2(server: &TestServer) {
    server.openshell.state.global_settings.lock().await.insert(
        openshell_core::settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
        SettingValue {
            value: Some(setting_value::Value::BoolValue(true)),
        },
    );
}

fn test_tls(server: &TestServer) -> TlsOptions {
    server.tls.with_gateway_name("openshell")
}

fn gpu_requirements(count: Option<u32>) -> GpuResourceRequirements {
    GpuResourceRequirements { count }
}

/// Shared defaults for integration tests. Note: `keep` is `true` here (most
/// tests expect persistent sandboxes) while `SandboxCreateConfig::default()`
/// sets `keep: false` (the safe production default). Tests that exercise
/// ephemeral behavior must explicitly override with `keep: false`.
fn test_config() -> run::SandboxCreateConfig<'static> {
    run::SandboxCreateConfig {
        keep: true,
        tty_override: Some(false),
        auto_providers_override: Some(false),
        ..Default::default()
    }
}

#[tokio::test]
async fn sandbox_create_keeps_command_sessions_by_default() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("default-command"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    assert!(deleted_names(&server).await.is_empty());
    assert_eq!(
        load_last_sandbox("openshell").as_deref(),
        Some("default-command"),
        "default sandboxes should be persisted as last-used"
    );
}

#[tokio::test]
async fn sandbox_create_sends_cpu_and_memory_limits_only() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("resources"),
            cpu: Some("500m"),
            memory: Some("2Gi"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    let requests = create_requests(&server).await;
    let resources = requests[0]
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.resources.as_ref())
        .expect("resource limits should be sent");
    let limits = resources
        .fields
        .get("limits")
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            prost_types::value::Kind::StructValue(inner) => Some(inner),
            _ => None,
        })
        .expect("limits should be a struct");

    assert_eq!(
        limits
            .fields
            .get("cpu")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                _ => None,
            }),
        Some("500m")
    );
    assert_eq!(
        limits
            .fields
            .get("memory")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                _ => None,
            }),
        Some("2Gi")
    );
    assert!(!resources.fields.contains_key("requests"));
}

#[tokio::test]
async fn sandbox_create_sends_driver_config_json() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("driver-config"),
            driver_config_json: Some(
                r#"{"kubernetes":{"pod":{"priority_class_name":"batch-low"}}}"#,
            ),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    let requests = create_requests(&server).await;
    let driver_config = requests[0]
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.driver_config.as_ref())
        .expect("driver config should be sent");
    let kubernetes = driver_config
        .fields
        .get("kubernetes")
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            prost_types::value::Kind::StructValue(inner) => Some(inner),
            _ => None,
        })
        .expect("kubernetes block should be a struct");
    let pod = kubernetes
        .fields
        .get("pod")
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            prost_types::value::Kind::StructValue(inner) => Some(inner),
            _ => None,
        })
        .expect("pod block should be a struct");

    assert_eq!(
        pod.fields
            .get("priority_class_name")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                _ => None,
            }),
        Some("batch-low")
    );
}

#[tokio::test]
async fn sandbox_create_sends_gpu_default_request() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("gpu-default"),
            gpu_requirements: Some(gpu_requirements(None)),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    let requests = create_requests(&server).await;
    let gpu = requests[0]
        .spec
        .as_ref()
        .and_then(|spec| spec.resource_requirements.as_ref())
        .and_then(|requirements| requirements.gpu.as_ref())
        .expect("GPU requirement should be sent");

    assert_eq!(gpu.count, None);
}

#[tokio::test]
async fn sandbox_create_sends_gpu_count_request() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("gpu-two"),
            gpu_requirements: Some(gpu_requirements(Some(2))),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    let requests = create_requests(&server).await;
    let gpu = requests[0]
        .spec
        .as_ref()
        .and_then(|spec| spec.resource_requirements.as_ref())
        .and_then(|requirements| requirements.gpu.as_ref())
        .expect("GPU requirement should be sent");

    assert_eq!(gpu.count, Some(2));
}

#[tokio::test]
async fn sandbox_create_does_not_infer_command_providers_when_v2_enabled() {
    let server = run_server().await;
    enable_providers_v2(&server).await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("v2-no-inferred-provider"),
            command: &["claude".into(), "--version".into()],
            tty_override: Some(true),
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed without inferred provider");

    let requests = create_requests(&server).await;
    let providers = requests[0]
        .spec
        .as_ref()
        .expect("sandbox spec should be sent")
        .providers
        .clone();
    assert!(
        providers.is_empty(),
        "providers v2 should not infer command providers, got {providers:?}"
    );
}

#[tokio::test]
async fn sandbox_create_returns_vm_error_without_waiting_for_timeout() {
    let server = run_server().await;
    server
        .openshell
        .state
        .vm_error_after_started
        .store(true, Ordering::SeqCst);
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env_with(
        &fake_ssh_dir,
        &xdg_dir,
        &[("OPENSHELL_PROVISION_TIMEOUT", "1".to_string())],
    );
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    let started_at = Instant::now();
    let err = run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("vm-error"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect_err("sandbox create should fail on terminal VM error");

    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "terminal VM errors should not wait for the provisioning timeout"
    );
    let rendered = err.to_string();
    assert!(rendered.contains("sandbox entered error phase while provisioning"));
    assert!(rendered.contains("ProcessExited: VM process exited with status 0"));
    assert!(!rendered.contains("timed out"));
}

#[tokio::test]
async fn sandbox_create_keeps_waiting_while_vm_progress_arrives() {
    let server = run_server().await;
    server
        .openshell
        .state
        .vm_slow_progress_before_ready
        .store(true, Ordering::SeqCst);
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env_with(
        &fake_ssh_dir,
        &xdg_dir,
        &[("OPENSHELL_PROVISION_TIMEOUT", "1".to_string())],
    );
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("vm-slow-progress"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should not time out while VM progress is active");
}

#[tokio::test]
async fn sandbox_create_times_out_when_only_logs_arrive() {
    let server = run_server().await;
    server
        .openshell
        .state
        .vm_log_churn_before_ready
        .store(true, Ordering::SeqCst);
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env_with(
        &fake_ssh_dir,
        &xdg_dir,
        &[("OPENSHELL_PROVISION_TIMEOUT", "1".to_string())],
    );
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    let started_at = Instant::now();
    let err = run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("vm-log-churn"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect_err("sandbox create should time out when only logs arrive");

    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "logs should not extend the provisioning timeout"
    );
    assert!(err.to_string().contains("sandbox provisioning timed out"));
}

#[tokio::test]
async fn sandbox_create_deletes_command_sessions_with_no_keep() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("ephemeral-command"),
            keep: false,
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    assert_eq!(
        deleted_names(&server).await,
        vec![vec!["ephemeral-command".to_string()]]
    );
    assert_eq!(
        load_last_sandbox("openshell"),
        None,
        "no-keep sandboxes should not be persisted as last-used"
    );
}

#[tokio::test]
async fn sandbox_create_deletes_shell_sessions_with_no_keep() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("ephemeral-shell"),
            keep: false,
            tty_override: Some(true),
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create shell should succeed");

    assert_eq!(
        deleted_names(&server).await,
        vec![vec!["ephemeral-shell".to_string()]]
    );
    assert_eq!(
        load_last_sandbox("openshell"),
        None,
        "no-keep shell sessions should not be persisted as last-used"
    );
}

#[tokio::test]
async fn sandbox_create_keeps_sandbox_with_hidden_keep_flag() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("persistent-keep"),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    assert!(deleted_names(&server).await.is_empty());
    assert_eq!(
        load_last_sandbox("openshell").as_deref(),
        Some("persistent-keep"),
        "persistent sandboxes should remain selectable as last-used"
    );
}

#[tokio::test]
async fn sandbox_create_keeps_sandbox_with_forwarding() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_forwarding_ssh(&fake_ssh_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = listener.local_addr().unwrap().port();
    drop(listener);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("persistent-forward"),
            keep: false,
            forward: Some(openshell_core::forward::ForwardSpec::new(forward_port)),
            command: &["echo".into(), "OK".into()],
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create with forward should succeed");

    assert!(deleted_names(&server).await.is_empty());
    let record = openshell_core::forward::read_forward_pid("persistent-forward", forward_port)
        .expect("fake forward should be tracked");
    let _ = std::process::Command::new("kill")
        .arg(record.pid.to_string())
        .status();
}

#[tokio::test]
async fn sandbox_forward_background_tracks_owned_child_when_pid_discovery_fails() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_forwarding_ssh(&fake_ssh_dir);
    install_fake_pgrep_no_match(&fake_ssh_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = listener.local_addr().unwrap().port();
    drop(listener);

    let spec = openshell_core::forward::ForwardSpec::new(forward_port);
    run::sandbox_forward(&server.endpoint, "owned-forward", &spec, true, &tls)
        .await
        .expect("background forward should track the owned SSH child without PID discovery");
    let record = openshell_core::forward::read_forward_pid("owned-forward", forward_port)
        .expect("owned background forward should write a PID file");

    assert!(
        openshell_core::forward::stop_forward("owned-forward", forward_port)
            .expect("tracked fake forward should stop"),
        "tracked fake forward should be recognized as alive and stopped",
    );
    assert!(
        wait_for_process_exit(record.pid, Duration::from_secs(2)).await,
        "tracked fake forward process should exit after stop"
    );
}

#[tokio::test]
async fn sandbox_forward_foreground_fails_when_ssh_exits_before_listener_opens() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = listener.local_addr().unwrap().port();
    drop(listener);

    let spec = openshell_core::forward::ForwardSpec::new(forward_port);
    let err = run::sandbox_forward(&server.endpoint, "foreground-forward", &spec, false, &tls)
        .await
        .expect_err("foreground forward should fail when ssh exits before listener readiness");
    let msg = format!("{err}");
    assert!(
        msg.contains("ssh exited before local forward listener opened"),
        "error should explain that ssh exited before listener readiness, got: {msg}",
    );
}

#[tokio::test]
async fn sandbox_forward_background_terminates_owned_child_when_listener_never_opens() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    let fake_forward = install_fake_unreachable_forwarding_ssh(&fake_ssh_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = listener.local_addr().unwrap().port();
    drop(listener);

    let spec = openshell_core::forward::ForwardSpec::new(forward_port);
    let err = run::sandbox_forward(&server.endpoint, "unreachable-forward", &spec, true, &tls)
        .await
        .expect_err("background forward should fail when the listener never opens");
    let msg = format!("{err}");
    assert!(
        msg.contains("ssh process started but local forward listener was not reachable"),
        "error should preserve listener startup context, got: {msg}",
    );
    assert!(
        openshell_core::forward::read_forward_pid("unreachable-forward", forward_port).is_none(),
        "unreachable background forwards must not write a PID file",
    );
    let pid = fs::read_to_string(&fake_forward.pid_path)
        .expect("fake forward should record a PID")
        .trim()
        .parse::<u32>()
        .expect("fake forward PID should be numeric");
    if !wait_for_process_exit(pid, Duration::from_secs(2)).await {
        let log = fs::read_to_string(&fake_forward.log_path).unwrap_or_default();
        let command = std::process::Command::new("ps")
            .arg("-ww")
            .arg("-o")
            .arg("command=")
            .arg("-p")
            .arg(pid.to_string())
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
            .unwrap_or_default();
        panic!(
            "owned background SSH child should exit after listener failure cleanup; pid={}, command={}, log={}",
            pid,
            command.trim(),
            log.trim(),
        );
    }
}

#[tokio::test]
async fn sandbox_create_sends_environment_variables() {
    let server = run_server().await;
    let fake_ssh_dir = tempfile::tempdir().unwrap();
    let xdg_dir = tempfile::tempdir().unwrap();
    let _env = test_env(&fake_ssh_dir, &xdg_dir);
    let tls = test_tls(&server);
    install_fake_ssh(&fake_ssh_dir);

    run::sandbox_create(
        &server.endpoint,
        "openshell",
        run::SandboxCreateConfig {
            name: Some("env-test"),
            command: &["echo".into(), "OK".into()],
            environment: HashMap::from([
                ("FOO".into(), "bar".into()),
                ("BAZ".into(), "qux=with=equals".into()),
            ]),
            ..test_config()
        },
        &tls,
    )
    .await
    .expect("sandbox create should succeed");

    let requests = create_requests(&server).await;
    let environment = &requests[0]
        .spec
        .as_ref()
        .expect("spec should be present")
        .environment;
    assert_eq!(environment.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(
        environment.get("BAZ").map(String::as_str),
        Some("qux=with=equals")
    );
    assert_eq!(environment.len(), 2);
}

#[tokio::test]
async fn sandbox_create_env_rejects_invalid_format() {
    let err = run::parse_key_value_pairs(
        &["VALID=ok".to_string(), "NOEQUALSSIGN".to_string()],
        "--env",
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("--env") && msg.contains("NOEQUALSSIGN"),
        "error should mention the flag and bad value, got: {msg}"
    );
}

#[tokio::test]
async fn sandbox_create_env_rejects_reserved_prefix() {
    let err = run::parse_env_pairs(&["VALID=ok".to_string(), "OPENSHELL_SECRET=bad".to_string()])
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("OPENSHELL_") && msg.contains("reserved"),
        "error should mention reserved prefix, got: {msg}"
    );
}

#[tokio::test]
async fn sandbox_create_env_rejects_invalid_key_name() {
    let err = run::parse_env_pairs(&["1BAD=value".to_string()]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("1BAD"),
        "error should mention invalid key, got: {msg}"
    );

    let err = run::parse_env_pairs(&["BAD-NAME=value".to_string()]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("BAD-NAME"),
        "error should mention invalid key, got: {msg}"
    );
}
