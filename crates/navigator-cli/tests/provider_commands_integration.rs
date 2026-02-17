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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
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
        let updated = Provider {
            id: existing.id,
            name: provider.name,
            r#type: provider.r#type,
            credentials: provider.credentials,
            config: provider.config,
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
}

async fn run_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .add_service(NavigatorServer::new(TestNavigator::default()))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    addr
}

#[tokio::test]
async fn provider_cli_run_functions_support_full_crud_flow() {
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();

    run::provider_create(
        &endpoint,
        "my-claude",
        "claude",
        false,
        &["API_KEY=abc".to_string()],
        &["profile=dev".to_string()],
        &tls,
    )
    .await
    .expect("provider create");

    run::provider_get(&endpoint, "my-claude", &tls)
        .await
        .expect("provider get");
    run::provider_list(&endpoint, 100, 0, false, &tls)
        .await
        .expect("provider list");

    run::provider_update(
        &endpoint,
        "my-claude",
        "claude",
        false,
        &["API_KEY=rotated".to_string()],
        &["profile=prod".to_string()],
        &tls,
    )
    .await
    .expect("provider update");

    run::provider_delete(&endpoint, &["my-claude".to_string()], &tls)
        .await
        .expect("provider delete");
}

#[tokio::test]
async fn provider_create_rejects_key_only_credentials_without_local_env_value() {
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();

    let err = run::provider_create(
        &endpoint,
        "bad-provider",
        "claude",
        false,
        &["INVALID_PAIR".to_string()],
        &[],
        &tls,
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
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();
    let _guard = EnvVarGuard::set("NAV_GENERIC_TEST_KEY", "generic-value");

    run::provider_create(
        &endpoint,
        "my-generic",
        "generic",
        false,
        &["NAV_GENERIC_TEST_KEY".to_string()],
        &[],
        &tls,
    )
    .await
    .expect("provider create");

    let mut client = navigator_cli::tls::grpc_client(&endpoint, &tls)
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
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();

    let err = run::provider_create(
        &endpoint,
        "bad-provider",
        "claude",
        true,
        &["API_KEY=abc".to_string()],
        &[],
        &tls,
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
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();
    let _guard = EnvVarGuard::set("NAV_EMPTY_ENV_KEY", "");

    let err = run::provider_create(
        &endpoint,
        "bad-provider",
        "generic",
        false,
        &["NAV_EMPTY_ENV_KEY".to_string()],
        &[],
        &tls,
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
    let addr = run_server().await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let tls = TlsOptions::default();
    let _guard = EnvVarGuard::set("NVIDIA_API_KEY", "nvapi-live-test");

    run::provider_create(
        &endpoint,
        "my-nvidia",
        "nvidia",
        false,
        &["NVIDIA_API_KEY".to_string()],
        &[],
        &tls,
    )
    .await
    .expect("provider create");

    let mut client = navigator_cli::tls::grpc_client(&endpoint, &tls)
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
