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
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxProvidersRequest,
    ListSandboxProvidersResponse, ListSandboxesRequest, ListSandboxesResponse, PlatformEvent,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, Sandbox, SandboxCondition,
    SandboxLogLine, SandboxPhase, SandboxResponse, SandboxStatus, SandboxStreamEvent,
    ServiceStatus, SupervisorMessage, UpdateProviderRequest, WatchSandboxRequest,
    sandbox_stream_event,
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

        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("id-{sandbox_name}"),
                    name: sandbox_name,
                    created_at_ms: 0,
                    labels: HashMap::new(),
                }),
                phase: SandboxPhase::Provisioning as i32,
                ..Sandbox::default()
            }),
        }))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let name = request.into_inner().name;
        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("id-{name}"),
                    name,
                    created_at_ms: 0,
                    labels: HashMap::new(),
                }),
                phase: SandboxPhase::Ready as i32,
                ..Sandbox::default()
            }),
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
            let provisioning = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: sandbox_id.clone(),
                    name: sandbox_id.trim_start_matches("id-").to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                }),
                phase: SandboxPhase::Provisioning as i32,
                ..Sandbox::default()
            };
            let error = Sandbox {
                phase: SandboxPhase::Error as i32,
                status: Some(SandboxStatus {
                    sandbox_name: sandbox_id.trim_start_matches("id-").to_string(),
                    agent_pod: String::new(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![SandboxCondition {
                        r#type: "Ready".to_string(),
                        status: "False".to_string(),
                        reason: "ProcessExited".to_string(),
                        message: "VM process exited with status 0".to_string(),
                        last_transition_time: String::new(),
                    }],
                }),
                ..provisioning.clone()
            };
            let ready = Sandbox {
                phase: SandboxPhase::Ready as i32,
                ..provisioning.clone()
            };

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

fn install_fake_ssh(dir: &TempDir) -> std::path::PathBuf {
    let ssh_path = dir.path().join("ssh");
    fs::write(&ssh_path, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&ssh_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&ssh_path, perms).unwrap();
    ssh_path
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

fn test_tls(server: &TestServer) -> TlsOptions {
    server.tls.with_gateway_name("openshell")
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
        Some("default-command"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("resources"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        Some("500m"),
        Some("2Gi"),
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("vm-error"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("vm-slow-progress"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("vm-log-churn"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("ephemeral-command"),
        None,
        "openshell",
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
        Some("ephemeral-shell"),
        None,
        "openshell",
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &[],
        Some(true),
        Some(false),
        &HashMap::new(),
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
        Some("persistent-keep"),
        None,
        "openshell",
        None,
        true,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
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
    install_fake_ssh(&fake_ssh_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = listener.local_addr().unwrap().port();
    drop(listener);

    run::sandbox_create(
        &server.endpoint,
        Some("persistent-forward"),
        None,
        "openshell",
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        &[],
        None,
        Some(openshell_core::forward::ForwardSpec::new(forward_port)),
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        &HashMap::new(),
        &tls,
    )
    .await
    .expect("sandbox create with forward should succeed");

    assert!(deleted_names(&server).await.is_empty());
}
