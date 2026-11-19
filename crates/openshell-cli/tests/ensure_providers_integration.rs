// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ensure_required_providers` — verifies that explicit
//! `--provider` names are auto-created when they match a known provider type,
//! pass through when they already exist, and error for unrecognised names.

mod helpers;

use helpers::TempDir;
use helpers::{Environment, build_ca, build_client_cert, build_server_cert};
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, ExecSandboxEvent,
    ExecSandboxRequest, GetGatewayConfigRequest, GetGatewayConfigResponse, GetProviderRequest,
    GetSandboxConfigRequest, GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxProvidersRequest,
    ListSandboxProvidersResponse, ListSandboxesRequest, ListSandboxesResponse, Provider,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, UpdateProviderRequest, WatchSandboxRequest,
};
use openshell_core::{ObjectId, ObjectName};
use openshell_server::test_support::grpc::open_shell_server::{OpenShell, OpenShellServer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

// ── mock OpenShell server ─────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
    list_requests: Arc<Mutex<Vec<ListProvidersRequest>>>,
}

#[derive(Clone, Default)]
struct TestOpenShell {
    state: ProviderState,
}

impl TestOpenShell {
    /// Seed the mock with an existing provider.
    async fn seed_provider(&self, name: &str, provider_type: &str) {
        let mut providers = self.state.providers.lock().await;
        providers.insert(
            name.to_string(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("id-{name}"),
                    name: name.to_string(),
                    created_time: None,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    deletion_time: None,
                }),
                r#type: provider_type.to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expiration_times: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        );
    }
}

#[tonic::async_trait]
impl OpenShell for TestOpenShell {
    async fn report_endpoint_status(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportEndpointStatusResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ReportEndpointStatusResponse {},
        ))
    }

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
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse {
            sandbox_id: String::new(),
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
        }))
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

    async fn expose_service(
        &self,
        _request: tonic::Request<openshell_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ServiceEndpointResponse::default(),
        ))
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
        let provider_name = provider.object_name().to_string();
        if providers.contains_key(&provider_name) {
            return Err(Status::already_exists("provider already exists"));
        }
        if provider.object_id().is_empty()
            && let Some(metadata) = &mut provider.metadata
        {
            metadata.id = format!("id-{provider_name}");
        }
        providers.insert(provider_name, provider.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
            ..Default::default()
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
            ..Default::default()
        }))
    }

    async fn list_providers(
        &self,
        request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        self.state
            .list_requests
            .lock()
            .await
            .push(request.into_inner());
        let providers = self
            .state
            .providers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        Ok(Response::new(ListProvidersResponse {
            providers,
            next_page_token: String::new(),
        }))
    }

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        let profiles = helpers::example_profiles()
            .iter()
            .map(openshell_providers::ProviderTypeProfile::to_proto)
            .collect();
        Ok(Response::new(
            openshell_core::proto::ListProviderProfilesResponse {
                profiles,
                next_page_token: String::new(),
            },
        ))
    }

    async fn get_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let profile = helpers::example_profiles()
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| Status::not_found("provider profile not found"))?
            .to_proto();
        Ok(Response::new(
            openshell_core::proto::ProviderProfileResponse {
                profile: Some(profile),
            },
        ))
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
            .get(provider.object_name())
            .cloned()
            .ok_or_else(|| Status::not_found("provider not found"))?;
        // Merge semantics: empty map = no change, empty value = delete key.
        let merge = |mut base: HashMap<String, String>,
                     incoming: HashMap<String, String>|
         -> HashMap<String, String> {
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
        let merge_expiry =
            |mut base: HashMap<String, prost_types::Timestamp>,
             incoming: HashMap<String, prost_types::Timestamp>| {
                if incoming.is_empty() {
                    return base;
                }
                base.extend(incoming);
                base
            };
        let existing_metadata = existing.metadata.clone().unwrap_or_default();
        let provider_metadata = provider.metadata.clone().unwrap_or_default();
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: existing_metadata.id,
                name: provider_metadata.name,
                created_time: existing_metadata.created_time,
                labels: existing_metadata.labels,
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: String::new(),
                deletion_time: None,
            }),
            r#type: existing.r#type,
            credentials: merge(existing.credentials, provider.credentials),
            config: merge(existing.config, provider.config),
            credential_expiration_times: merge_expiry(
                existing.credential_expiration_times,
                provider.credential_expiration_times,
            ),
            profile_workspace: existing.profile_workspace,
            credential_handles: if provider.credential_handles.is_empty() {
                existing.credential_handles
            } else {
                provider.credential_handles
            },
        };
        let updated_name = updated.object_name().to_string();
        providers.insert(updated_name, updated.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(updated),
            ..Default::default()
        }))
    }

    async fn delete_provider(
        &self,
        request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        let name = request.into_inner().name;
        let deleted = self.state.providers.lock().await.remove(&name).is_some();
        Ok(Response::new(DeleteProviderResponse {
            outcome: if deleted {
                openshell_core::proto::DeletionOutcome::Completed.into()
            } else {
                openshell_core::proto::DeletionOutcome::AlreadyAbsent.into()
            },
        }))
    }

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<tonic::codegen::BoxStream<SandboxStreamEvent>>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<ExecSandboxRequest>,
    ) -> Result<Response<tonic::codegen::BoxStream<ExecSandboxEvent>>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

// ── test server fixture ──────────────────────────────────────────────

struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    openshell: TestOpenShell,
    _dir: TempDir,
}

async fn run_server() -> TestServer {
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

    let dir = helpers::tempdir().unwrap();
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

// ── tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn provider_create_forwards_labels_for_explicit_and_discovered_credentials() {
    let ts = run_server().await;
    Environment::from_pairs(&[("NVIDIA_API_KEY", "nvapi-test-key")])
        .run_async(async {
            let labels = vec!["env=dev".to_string(), "team=ml".to_string()];
            let credentials = vec!["NVIDIA_API_KEY=test-explicit".to_string()];
            for (name, source, credentials) in [
                (
                    "explicit",
                    run::ProviderCreateCredentialSource::ExplicitCredentials,
                    credentials.as_slice(),
                ),
                (
                    "discovered",
                    run::ProviderCreateCredentialSource::Existing,
                    &[],
                ),
            ] {
                run::provider_create_with_options(run::ProviderCreateOptions {
                    server: &ts.endpoint,
                    name,
                    provider_type: "nvidia",
                    labels: &labels,
                    credentials,
                    credential_source: source,
                    config: &[],
                    workspace: "default",
                    profile_workspace: "",
                    tls: &ts.tls,
                })
                .await
                .unwrap();
                let providers = ts.openshell.state.providers.lock().await;
                let provider = &providers[name];
                assert_eq!(
                    provider.metadata.as_ref().unwrap().labels,
                    HashMap::from([("env".into(), "dev".into()), ("team".into(), "ml".into())])
                );
                assert!(provider.credentials.contains_key("NVIDIA_API_KEY"));
            }

            for label in ["no-equals-sign", "=no-key"] {
                let err = run::provider_create_with_options(run::ProviderCreateOptions {
                    server: &ts.endpoint,
                    name: "invalid",
                    provider_type: "nvidia",
                    labels: &[label.into()],
                    credentials: &credentials,
                    credential_source: run::ProviderCreateCredentialSource::ExplicitCredentials,
                    config: &[],
                    workspace: "default",
                    profile_workspace: "",
                    tls: &ts.tls,
                })
                .await
                .unwrap_err();
                assert!(err.to_string().contains("--label"));
            }
            assert!(
                !ts.openshell
                    .state
                    .providers
                    .lock()
                    .await
                    .contains_key("invalid")
            );
        })
        .await;
}

#[tokio::test]
async fn provider_list_forwards_selector_pagination_and_workspace_scope() {
    let ts = run_server().await;
    for all_workspaces in [false, true] {
        run::provider_list(
            &ts.endpoint,
            3,
            "cursor",
            "env=dev,team=ml",
            false,
            "json",
            "team-ml",
            all_workspaces,
            &ts.tls,
        )
        .await
        .unwrap();
        let requests = ts.openshell.state.list_requests.lock().await;
        let request = requests.last().unwrap();
        assert_eq!(request.page_size, 3);
        assert_eq!(request.page_token, "cursor");
        assert_eq!(request.label_selector, "env=dev,team=ml");
        let expected = if all_workspaces {
            openshell_core::proto::all_workspaces_selector()
        } else {
            openshell_core::proto::workspace_selector("team-ml")
        };
        assert_eq!(request.workspace_scope.as_ref(), Some(&expected));
    }
}

/// When `--provider nvidia` is passed and a provider named "nvidia" already
/// exists, `ensure_required_providers` should return it directly without
/// creating anything new.
#[tokio::test]
async fn explicit_provider_name_passes_through_when_it_exists() {
    let ts = run_server().await;
    ts.openshell.seed_provider("nvidia", "nvidia").await;

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        Some(true), // --auto-providers (should not matter here)
        "default",
    )
    .await
    .expect("should succeed");

    assert_eq!(result, vec!["nvidia".to_string()]);

    // Verify no extra providers were created.
    let providers = ts.openshell.state.providers.lock().await;
    assert_eq!(providers.len(), 1, "no new providers should be created");
}

/// When `--provider nvidia` is passed, no provider named "nvidia" exists, and
/// "nvidia" is a valid provider type, the CLI should auto-create a provider
/// named "nvidia" of type "nvidia" using discovered local credentials.
#[tokio::test]
async fn explicit_provider_name_auto_creates_when_valid_type() {
    let ts = run_server().await;

    Environment::from_pairs(&[("NVIDIA_API_KEY", "nvapi-test-key")])
        .run_async(async {
            let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
                .await
                .expect("grpc client");

            let result = run::ensure_required_providers(
                &mut client,
                &["nvidia".to_string()],
                Some(true), // --auto-providers to skip interactive prompt
                "default",
            )
            .await
            .expect("should auto-create the provider");

            assert_eq!(result, vec!["nvidia".to_string()]);

            // Verify the provider was created on the server with the right type.
            let providers = ts.openshell.state.providers.lock().await;
            let provider = providers
                .get("nvidia")
                .expect("nvidia provider should exist");
            assert_eq!(provider.r#type, "nvidia");
            assert_eq!(
                provider.credentials.get("NVIDIA_API_KEY"),
                Some(&"nvapi-test-key".to_string()),
            );
        })
        .await;
}

/// When `--provider my-custom-thing` is passed and "my-custom-thing" is not a
/// known provider type, the CLI should return an error.
#[tokio::test]
async fn explicit_provider_name_errors_for_unrecognised_name() {
    let ts = run_server().await;

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let err = run::ensure_required_providers(
        &mut client,
        &["my-custom-thing".to_string()],
        Some(true),
        "default",
    )
    .await
    .expect_err("should fail for unrecognised provider name");

    let msg = err.to_string();
    assert!(
        msg.contains("my-custom-thing"),
        "error should mention the name: {msg}"
    );
    assert!(
        msg.contains("no provider profile"),
        "error should explain why it failed: {msg}"
    );
}

/// When `--no-auto-providers` is set, missing explicit providers that would
/// otherwise be auto-created should be silently skipped.
#[tokio::test]
async fn no_auto_providers_skips_missing_explicit_provider() {
    let ts = run_server().await;

    Environment::from_pairs(&[("NVIDIA_API_KEY", "nvapi-skip-test")])
        .run_async(async {
            let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
                .await
                .expect("grpc client");

            let result = run::ensure_required_providers(
                &mut client,
                &["nvidia".to_string()],
                Some(false), // --no-auto-providers
                "default",
            )
            .await
            .expect("should succeed with empty list");

            assert!(
                result.is_empty(),
                "skipped providers should not appear in the result"
            );

            let providers = ts.openshell.state.providers.lock().await;
            assert!(
                providers.is_empty(),
                "no providers should be created when --no-auto-providers is set"
            );
        })
        .await;
}

/// Several explicit providers are all resolved and created.
#[tokio::test]
async fn multiple_explicit_providers_combined() {
    let ts = run_server().await;

    Environment::from_pairs(&[
        ("NVIDIA_API_KEY", "nvapi-combo"),
        ("ANTHROPIC_API_KEY", "sk-ant-combo"),
    ])
    .run_async(async {
        let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
            .await
            .expect("grpc client");

        let result = run::ensure_required_providers(
            &mut client,
            &["nvidia".to_string(), "claude-code".to_string()],
            Some(true),
            "default",
        )
        .await
        .expect("should create both providers");

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"nvidia".to_string()));
        assert!(result.contains(&"claude-code".to_string()));

        let providers = ts.openshell.state.providers.lock().await;
        assert_eq!(providers.len(), 2);
        assert!(providers.contains_key("nvidia"));
        assert!(providers.contains_key("claude-code"));
    })
    .await;
}

/// A provider named twice appears only once in the result.
#[tokio::test]
async fn repeated_explicit_provider_deduplicates() {
    let ts = run_server().await;

    Environment::from_pairs(&[("NVIDIA_API_KEY", "nvapi-dedup")])
        .run_async(async {
            let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
                .await
                .expect("grpc client");

            let result = run::ensure_required_providers(
                &mut client,
                &["nvidia".to_string(), "nvidia".to_string()],
                Some(true),
                "default",
            )
            .await
            .expect("should succeed");

            assert_eq!(
                result,
                vec!["nvidia".to_string()],
                "nvidia should appear exactly once"
            );

            let providers = ts.openshell.state.providers.lock().await;
            assert_eq!(
                providers.len(),
                1,
                "only one provider should be created on the server"
            );
        })
        .await;
}
