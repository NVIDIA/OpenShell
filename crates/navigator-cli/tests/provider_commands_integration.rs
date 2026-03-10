// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
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
    }
}

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
}

#[derive(Clone, Default)]
struct TestNavigator {
    state: ProviderState,
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

/// Test fixture: TLS-enabled server with matching client certs.
struct TestServer {
    endpoint: String,
    tls: TlsOptions,
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
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(NavigatorServer::new(TestNavigator::default()))
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
        _dir: dir,
    }
}

#[tokio::test]
async fn provider_cli_run_functions_support_full_crud_flow() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "my-claude",
        "claude",
        false,
        &["API_KEY=abc".to_string()],
        &["profile=dev".to_string()],
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::provider_get(&ts.endpoint, "my-claude", &ts.tls)
        .await
        .expect("provider get");
    run::provider_list(&ts.endpoint, 100, 0, false, &ts.tls)
        .await
        .expect("provider list");

    run::provider_update(
        &ts.endpoint,
        "my-claude",
        false,
        &["API_KEY=rotated".to_string()],
        &["profile=prod".to_string()],
        &ts.tls,
    )
    .await
    .expect("provider update");

    run::provider_delete(&ts.endpoint, &["my-claude".to_string()], &ts.tls)
        .await
        .expect("provider delete");
}

#[tokio::test]
async fn provider_create_rejects_key_only_credentials_without_local_env_value() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude",
        false,
        &["INVALID_PAIR".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect_err("invalid key=value should fail");

    assert!(
        err.to_string()
            .contains("requires local env var 'INVALID_PAIR' to be set to a non-empty value"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_supports_generic_type_and_env_lookup_credentials() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set("NAV_GENERIC_TEST_KEY", "generic-value");

    run::provider_create(
        &ts.endpoint,
        "my-generic",
        "generic",
        false,
        &["NAV_GENERIC_TEST_KEY".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect("provider create");

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let response = client
        .get_provider(GetProviderRequest {
            name: "my-generic".to_string(),
        })
        .await
        .expect("get provider should succeed")
        .into_inner();
    let provider = response.provider.expect("provider should exist");
    assert_eq!(provider.r#type, "generic");
    assert_eq!(
        provider.credentials.get("NAV_GENERIC_TEST_KEY"),
        Some(&"generic-value".to_string())
    );
}

#[tokio::test]
async fn provider_create_rejects_combined_from_existing_and_credentials() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude",
        true,
        &["API_KEY=abc".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect_err("from-existing and credentials should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-existing cannot be combined with --credential"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_rejects_empty_env_var_for_key_only_credential() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set("NAV_EMPTY_ENV_KEY", "");

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "generic",
        false,
        &["NAV_EMPTY_ENV_KEY".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect_err("empty env var should be rejected");

    assert!(
        err.to_string()
            .contains("requires local env var 'NAV_EMPTY_ENV_KEY' to be set to a non-empty value"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_supports_nvidia_type_with_nvidia_api_key() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set("NVIDIA_API_KEY", "nvapi-live-test");

    run::provider_create(
        &ts.endpoint,
        "my-nvidia",
        "nvidia",
        false,
        &["NVIDIA_API_KEY".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect("provider create");

    let mut client = navigator_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let response = client
        .get_provider(GetProviderRequest {
            name: "my-nvidia".to_string(),
        })
        .await
        .expect("get provider should succeed")
        .into_inner();
    let provider = response.provider.expect("provider should exist");
    assert_eq!(provider.r#type, "nvidia");
    assert_eq!(
        provider.credentials.get("NVIDIA_API_KEY"),
        Some(&"nvapi-live-test".to_string())
    );
}
