// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ensure_required_providers` — verifies that explicit
//! `--provider` names are auto-created when they match a known provider type,
//! pass through when they already exist, and error for unrecognised names.

use navigator_cli::run;
use navigator_cli::tls::TlsOptions;
use navigator_core::proto::navigator_server::{Navigator, NavigatorServer};
use navigator_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxRequest, GetProviderRequest, GetSandboxPolicyRequest,
    GetSandboxPolicyResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxesRequest, ListSandboxesResponse,
    Provider, ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, UpdateProviderRequest, WatchSandboxRequest,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

// ── EnvVarGuard ──────────────────────────────────────────────────────

// Serialise tests that mutate environment variables so concurrent
// threads don't clobber each other.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct SavedVar {
    key: &'static str,
    original: Option<String>,
}

/// Holds the global env lock and restores all modified variables on drop.
struct EnvVarGuard {
    vars: Vec<SavedVar>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    /// Acquire the lock and set one or more environment variables.
    fn set(pairs: &[(&'static str, &str)]) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut vars = Vec::with_capacity(pairs.len());
        for &(key, value) in pairs {
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
        // _lock drops here, releasing the mutex
    }
}

// ── mock Navigator server ─────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
}

#[derive(Clone, Default)]
struct TestNavigator {
    state: ProviderState,
}

impl TestNavigator {
    /// Seed the mock with an existing provider.
    async fn seed_provider(&self, name: &str, provider_type: &str) {
        let mut providers = self.state.providers.lock().await;
        providers.insert(
            name.to_string(),
            Provider {
                id: format!("id-{name}"),
                name: name.to_string(),
                r#type: provider_type.to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        );
    }
}

#[tonic::async_trait]
impl Navigator for TestNavigator {
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

    async fn get_sandbox_policy(
        &self,
        _request: tonic::Request<GetSandboxPolicyRequest>,
    ) -> Result<Response<GetSandboxPolicyResponse>, Status> {
        Ok(Response::new(GetSandboxPolicyResponse::default()))
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
        request: tonic::Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let mut provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        let mut providers = self.state.providers.lock().await;
        if providers.contains_key(&provider.name) {
            return Err(Status::already_exists("provider already exists"));
        }
        if provider.id.is_empty() {
            provider.id = format!("id-{}", provider.name);
        }
        providers.insert(provider.name.clone(), provider.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
        }))
    }

    async fn get_provider(
        &self,
        request: tonic::Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let name = request.into_inner().name;
        let providers = self.state.providers.lock().await;
        let provider = providers
            .get(&name)
            .cloned()
            .ok_or_else(|| Status::not_found("provider not found"))?;
        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
        }))
    }

    async fn list_providers(
        &self,
        _request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        let providers = self
            .state
            .providers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        Ok(Response::new(ListProvidersResponse { providers }))
    }

    async fn update_provider(
        &self,
        request: tonic::Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;

        let mut providers = self.state.providers.lock().await;
        let existing = providers
            .get(&provider.name)
            .cloned()
            .ok_or_else(|| Status::not_found("provider not found"))?;
        // Merge semantics: empty map = no change, empty value = delete key.
        let merge = |mut base: std::collections::HashMap<String, String>,
                     incoming: std::collections::HashMap<String, String>|
         -> std::collections::HashMap<String, String> {
            if incoming.is_empty() {
                return base;
            }
            for (k, v) in incoming {
                if v.is_empty() {
                    base.remove(&k);
                } else {
                    base.insert(k, v);
                }
            }
            base
        };
        let updated = Provider {
            id: existing.id,
            name: provider.name,
            r#type: existing.r#type,
            credentials: merge(existing.credentials, provider.credentials),
            config: merge(existing.config, provider.config),
        };
        providers.insert(updated.name.clone(), updated.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(updated),
        }))
    }

    async fn delete_provider(
        &self,
        request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        let name = request.into_inner().name;
        let deleted = self.state.providers.lock().await.remove(&name).is_some();
        Ok(Response::new(DeleteProviderResponse { deleted }))
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

    async fn update_sandbox_policy(
        &self,
        _request: tonic::Request<navigator_core::proto::UpdateSandboxPolicyRequest>,
    ) -> Result<Response<navigator_core::proto::UpdateSandboxPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<navigator_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<navigator_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<navigator_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<navigator_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<navigator_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<navigator_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<navigator_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<navigator_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<navigator_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<navigator_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

// ── TLS helpers ──────────────────────────────────────────────────────

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

// ── test server fixture ──────────────────────────────────────────────

struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    navigator: TestNavigator,
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

    let navigator = TestNavigator::default();
    let svc_navigator = navigator.clone();

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(NavigatorServer::new(svc_navigator))
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
        navigator,
        _dir: dir,
    }
}

// ── tests ────────────────────────────────────────────────────────────

/// When `--provider nvidia` is passed and a provider named "nvidia" already
/// exists, `ensure_required_providers` should return it directly without
/// creating anything new.
#[tokio::test]
async fn explicit_provider_name_passes_through_when_it_exists() {
    let ts = run_server().await;
    ts.navigator.seed_provider("nvidia", "nvidia").await;

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        &[],
        Some(true), // --auto-providers (should not matter here)
    )
    .await
    .expect("should succeed");

    assert_eq!(result, vec!["nvidia".to_string()]);

    // Verify no extra providers were created.
    let providers = ts.navigator.state.providers.lock().await;
    assert_eq!(providers.len(), 1, "no new providers should be created");
}

/// When `--provider nvidia` is passed, no provider named "nvidia" exists, and
/// "nvidia" is a valid provider type, the CLI should auto-create a provider
/// named "nvidia" of type "nvidia" using discovered local credentials.
#[tokio::test]
async fn explicit_provider_name_auto_creates_when_valid_type() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-test-key")]);

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        &[],
        Some(true), // --auto-providers to skip interactive prompt
    )
    .await
    .expect("should auto-create the provider");

    assert_eq!(result, vec!["nvidia".to_string()]);

    // Verify the provider was created on the server with the right type.
    let providers = ts.navigator.state.providers.lock().await;
    let provider = providers
        .get("nvidia")
        .expect("nvidia provider should exist");
    assert_eq!(provider.r#type, "nvidia");
    assert_eq!(
        provider.credentials.get("NVIDIA_API_KEY"),
        Some(&"nvapi-test-key".to_string()),
    );
}

/// When `--provider my-custom-thing` is passed and "my-custom-thing" is not a
/// known provider type, the CLI should return an error.
#[tokio::test]
async fn explicit_provider_name_errors_for_unrecognised_name() {
    let ts = run_server().await;

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let err = run::ensure_required_providers(
        &mut client,
        &["my-custom-thing".to_string()],
        &[],
        Some(true),
    )
    .await
    .expect_err("should fail for unrecognised provider name");

    let msg = err.to_string();
    assert!(
        msg.contains("my-custom-thing"),
        "error should mention the name: {msg}"
    );
    assert!(
        msg.contains("not a recognized provider type"),
        "error should explain why it failed: {msg}"
    );
}

/// Inferred types (from the trailing command) that don't exist should be
/// auto-created, preserving the existing behaviour.
#[tokio::test]
async fn inferred_type_auto_creates_provider() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("ANTHROPIC_API_KEY", "sk-ant-test")]);

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &[],
        &["claude".to_string()],
        Some(true), // --auto-providers
    )
    .await
    .expect("should auto-create the inferred provider");

    assert_eq!(result, vec!["claude".to_string()]);

    let providers = ts.navigator.state.providers.lock().await;
    let provider = providers
        .get("claude")
        .expect("claude provider should exist");
    assert_eq!(provider.r#type, "claude");
}

/// When `--no-auto-providers` is set, missing explicit providers that would
/// otherwise be auto-created should be silently skipped.
#[tokio::test]
async fn no_auto_providers_skips_missing_explicit_provider() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-skip-test")]);

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        &[],
        Some(false), // --no-auto-providers
    )
    .await
    .expect("should succeed with empty list");

    assert!(
        result.is_empty(),
        "skipped providers should not appear in the result"
    );

    let providers = ts.navigator.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no providers should be created when --no-auto-providers is set"
    );
}

/// Both explicit names and inferred types should be resolved together,
/// deduplicating providers that appear in both lists.
#[tokio::test]
async fn explicit_and_inferred_providers_combined() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[
        ("NVIDIA_API_KEY", "nvapi-combo"),
        ("ANTHROPIC_API_KEY", "sk-ant-combo"),
    ]);

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        &["claude".to_string()],
        Some(true),
    )
    .await
    .expect("should create both providers");

    assert_eq!(result.len(), 2);
    assert!(result.contains(&"nvidia".to_string()));
    assert!(result.contains(&"claude".to_string()));

    let providers = ts.navigator.state.providers.lock().await;
    assert_eq!(providers.len(), 2);
    assert!(providers.contains_key("nvidia"));
    assert!(providers.contains_key("claude"));
}

/// When an explicit provider name matches an inferred type, the provider
/// should only appear once in the result.
#[tokio::test]
async fn explicit_and_inferred_deduplicates() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-dedup")]);

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    // Both explicit and inferred want "nvidia".
    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        &["nvidia".to_string()],
        Some(true),
    )
    .await
    .expect("should succeed");

    assert_eq!(
        result,
        vec!["nvidia".to_string()],
        "nvidia should appear exactly once"
    );

    let providers = ts.navigator.state.providers.lock().await;
    assert_eq!(
        providers.len(),
        1,
        "only one provider should be created on the server"
    );
}
