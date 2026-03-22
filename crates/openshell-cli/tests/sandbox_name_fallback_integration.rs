// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_bootstrap::{load_last_sandbox, save_last_sandbox};
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
    ListSandboxesRequest, ListSandboxesResponse, ProviderResponse, Sandbox, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, UpdateProviderRequest, WatchSandboxRequest,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

// Serialise tests that mutate XDG_CONFIG_HOME so concurrent threads
// don't clobber each other's environment.
static XDG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
    _xdg_lock: std::sync::MutexGuard<'static, ()>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = XDG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self {
            key,
            original,
            _xdg_lock: lock,
        }
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
        // _xdg_lock drops here, releasing the mutex
    }
}

// ── mock OpenShell server ─────────────────────────────────────────────

/// Records which sandbox name was requested via `get_sandbox`.
#[derive(Clone, Default)]
struct SandboxState {
    last_get_name: Arc<Mutex<Option<String>>>,
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
        _request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let name = request.into_inner().name;
        *self.state.last_get_name.lock().await = Some(name.clone());
        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                id: "test-id".to_string(),
                name,
                namespace: "default".to_string(),
                ..Default::default()
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
        _request: tonic::Request<openshell_core::proto::RevokeSshSessionRequest>,
    ) -> Result<Response<openshell_core::proto::RevokeSshSessionResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::RevokeSshSessionResponse::default(),
        ))
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
        Ok(Response::new(ProviderResponse::default()))
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
        _request: tonic::Request<WatchSandboxRequest>,
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

// ── helpers ───────────────────────────────────────────────────────────

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
    std::fs::write(&ca_path, ca_cert).unwrap();
    std::fs::write(&cert_path, client_cert).unwrap();
    std::fs::write(&key_path, client_key).unwrap();

    let tls = TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path));
    let endpoint = format!("https://localhost:{}", addr.port());

    TestServer {
        endpoint,
        tls,
        openshell,
        _dir: dir,
    }
}

// ── tests ─────────────────────────────────────────────────────────────

/// Verify that `sandbox_get` works through a real gRPC round-trip and that the
/// mock records the correct name.
#[tokio::test]
async fn sandbox_get_sends_correct_name() {
    let ts = run_server().await;

    run::sandbox_get(&ts.endpoint, "my-sandbox", &ts.tls)
        .await
        .expect("sandbox_get should succeed");

    let recorded = ts.openshell.state.last_get_name.lock().await.clone();
    assert_eq!(
        recorded.as_deref(),
        Some("my-sandbox"),
        "mock should have recorded the requested sandbox name"
    );
}

/// End-to-end: save a last-used sandbox, load it back, then call `sandbox_get`
/// with the resolved name. This validates the persistence + gRPC wiring.
#[tokio::test]
async fn sandbox_get_with_persisted_last_sandbox() {
    let ts = run_server().await;
    let xdg_dir = tempfile::tempdir().unwrap();
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", xdg_dir.path().to_str().unwrap());

    // Persist a last-used sandbox for "integration-cluster".
    save_last_sandbox("integration-cluster", "persisted-sb")
        .expect("save_last_sandbox should succeed");

    // Resolve the name (simulates what the CLI does in main.rs).
    let resolved = load_last_sandbox("integration-cluster")
        .expect("load_last_sandbox should return the saved name");
    assert_eq!(resolved, "persisted-sb");

    // Call sandbox_get with the resolved name.
    run::sandbox_get(&ts.endpoint, &resolved, &ts.tls)
        .await
        .expect("sandbox_get should succeed");

    let recorded = ts.openshell.state.last_get_name.lock().await.clone();
    assert_eq!(
        recorded.as_deref(),
        Some("persisted-sb"),
        "the persisted sandbox name should flow through to the gRPC request"
    );
}

/// Verify that an explicit name takes precedence over the persisted one.
#[tokio::test]
async fn explicit_name_takes_precedence_over_persisted() {
    let ts = run_server().await;
    let xdg_dir = tempfile::tempdir().unwrap();
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", xdg_dir.path().to_str().unwrap());

    // Persist one name, but supply a different one explicitly.
    save_last_sandbox("my-cluster", "old-sandbox").expect("save should succeed");

    run::sandbox_get(&ts.endpoint, "explicit-sandbox", &ts.tls)
        .await
        .expect("sandbox_get should succeed");

    let recorded = ts.openshell.state.last_get_name.lock().await.clone();
    assert_eq!(
        recorded.as_deref(),
        Some("explicit-sandbox"),
        "explicit name should be used, not the persisted one"
    );
}
