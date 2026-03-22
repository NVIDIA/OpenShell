// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_bootstrap::load_last_sandbox;
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxRequest, GetGatewayConfigRequest, GetGatewayConfigResponse,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxesRequest, ListSandboxesResponse, PlatformEvent, ProviderResponse,
    RevokeSshSessionRequest, RevokeSshSessionResponse, Sandbox, SandboxPhase, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, UpdateProviderRequest, WatchSandboxRequest,
    sandbox_stream_event,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct SavedVar {
    key: &'static str,
    original: Option<String>,
}

struct EnvVarGuard {
    vars: Vec<SavedVar>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    fn set(pairs: &[(&'static str, String)]) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut vars = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            let original = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            vars.push(SavedVar { key, original });
        }
        Self { vars, _lock: lock }
    }
}

#[allow(unsafe_code)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for var in &self.vars {
            if let Some(value) = &var.original {
                unsafe {
                    std::env::set_var(var.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(var.key);
                }
            }
        }
    }
}

#[derive(Clone, Default)]
struct SandboxState {
    deleted_names: Arc<Mutex<Vec<Vec<String>>>>,
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
        let name = request.into_inner().name;
        let sandbox_name = if name.is_empty() {
            "test-sandbox".to_string()
        } else {
            name
        };

        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                id: format!("id-{sandbox_name}"),
                name: sandbox_name,
                namespace: "default".to_string(),
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
                id: format!("id-{name}"),
                name,
                namespace: "default".to_string(),
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
            connect_path: "/connect/ssh".to_string(),
            ..CreateSshSessionResponse::default()
        }))
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

    async fn watch_sandbox(
        &self,
        request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let sandbox_id = request.into_inner().id;
        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            let provisioning = Sandbox {
                id: sandbox_id.clone(),
                name: sandbox_id.trim_start_matches("id-").to_string(),
                namespace: "default".to_string(),
                phase: SandboxPhase::Provisioning as i32,
                ..Sandbox::default()
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

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
    (cert.pem(), key_pair.serialize_pem())
}

fn build_client_cert(ca: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();
    (cert.pem(), key_pair.serialize_pem())
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
    let path = format!(
        "{}:{}",
        fake_ssh_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    EnvVarGuard::set(&[
        ("PATH", path),
        (
            "XDG_CONFIG_HOME",
            xdg_dir.path().to_str().unwrap().to_string(),
        ),
        ("HOME", xdg_dir.path().to_str().unwrap().to_string()),
    ])
}

async fn deleted_names(server: &TestServer) -> Vec<Vec<String>> {
    server.openshell.state.deleted_names.lock().await.clone()
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
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        Some(false),
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
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        Some(false),
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
        &[],
        None,
        None,
        &[],
        Some(true),
        Some(false),
        Some(false),
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
        &[],
        None,
        None,
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        Some(false),
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
        &[],
        None,
        Some(openshell_core::forward::ForwardSpec::new(8080)),
        &["echo".to_string(), "OK".to_string()],
        Some(false),
        Some(false),
        Some(false),
        &tls,
    )
    .await
    .expect("sandbox create with forward should succeed");

    assert!(deleted_names(&server).await.is_empty());
}
