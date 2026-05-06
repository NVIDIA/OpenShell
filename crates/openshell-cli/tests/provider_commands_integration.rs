// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxesRequest, ListSandboxesResponse,
    Provider, ProviderProfile, ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse,
    SandboxResponse, SandboxStreamEvent, ServiceStatus, SupervisorMessage, UpdateProviderRequest,
    WatchSandboxRequest,
};
use openshell_core::{ObjectId, ObjectName};
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
    profiles: Arc<Mutex<HashMap<String, ProviderProfile>>>,
}

#[derive(Clone, Default)]
struct TestOpenShell {
    state: ProviderState,
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

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        let mut profiles = openshell_providers::default_profiles()
            .iter()
            .map(openshell_providers::ProviderTypeProfile::to_proto)
            .collect::<Vec<_>>();
        profiles.extend(self.state.profiles.lock().await.values().cloned());
        Ok(Response::new(
            openshell_core::proto::ListProviderProfilesResponse { profiles },
        ))
    }

    async fn get_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let profile = if let Some(profile) = openshell_providers::get_default_profile(&id) {
            profile.to_proto()
        } else {
            self.state
                .profiles
                .lock()
                .await
                .get(&id)
                .cloned()
                .ok_or_else(|| Status::not_found("provider profile not found"))?
        };
        Ok(Response::new(
            openshell_core::proto::ProviderProfileResponse {
                profile: Some(profile),
            },
        ))
    }

    async fn import_provider_profiles(
        &self,
        request: tonic::Request<openshell_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ImportProviderProfilesResponse>, Status> {
        let mut profiles = self.state.profiles.lock().await;
        let imported = request
            .into_inner()
            .profiles
            .into_iter()
            .filter_map(|item| item.profile)
            .inspect(|profile| {
                profiles.insert(profile.id.clone(), profile.clone());
            })
            .collect::<Vec<_>>();
        Ok(Response::new(
            openshell_core::proto::ImportProviderProfilesResponse {
                diagnostics: Vec::new(),
                profiles: imported,
                imported: true,
            },
        ))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::LintProviderProfilesResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::LintProviderProfilesResponse {
                diagnostics: Vec::new(),
                valid: true,
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
        let existing_metadata = existing.metadata.clone().unwrap_or_default();
        let provider_metadata = provider.metadata.clone().unwrap_or_default();
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: existing_metadata.id,
                name: provider_metadata.name,
                created_at_ms: existing_metadata.created_at_ms,
                labels: existing_metadata.labels,
            }),
            r#type: existing.r#type,
            credentials: merge(existing.credentials, provider.credentials),
            config: merge(existing.config, provider.config),
        };
        let updated_name = updated.object_name().to_string();
        providers.insert(updated_name, updated.clone());
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

    async fn delete_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let deleted = self.state.profiles.lock().await.remove(&id).is_some();
        Ok(Response::new(
            openshell_core::proto::DeleteProviderProfileResponse { deleted },
        ))
    }

    type WatchSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream =
        tokio_stream::wrappers::ReceiverStream<Result<GatewayMessage, Status>>;

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
    state: ProviderState,
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
    let state = ProviderState::default();
    let service = TestOpenShell {
        state: state.clone(),
    };
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(OpenShellServer::new(service))
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
        state,
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
async fn provider_list_profiles_cli_uses_profile_browsing_rpc() {
    let ts = run_server().await;

    run::provider_list_profiles(&ts.endpoint, "table", &ts.tls)
        .await
        .expect("provider list-profiles");
}

#[tokio::test]
async fn provider_profile_cli_run_functions_support_custom_profiles() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("custom-api.yaml");
    std::fs::write(
        &profile_path,
        r"
id: custom-api
display_name: Custom API
category: other
credentials:
  - name: api_key
    env_vars: [CUSTOM_API_KEY]
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: api.custom.example
    port: 443
binaries: [/usr/bin/custom]
",
    )
    .unwrap();

    run::provider_profile_lint(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile lint");
    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile import");
    run::provider_profile_export(&ts.endpoint, "custom-api", "yaml", &ts.tls)
        .await
        .expect("profile export");
    run::provider_list_profiles(&ts.endpoint, "json", &ts.tls)
        .await
        .expect("provider list-profiles json");
    run::provider_create(
        &ts.endpoint,
        "custom-provider",
        "custom-api",
        false,
        &["CUSTOM_API_KEY=abc".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect("custom profile provider create");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("custom-provider")
        .cloned()
        .expect("custom provider should be stored");
    assert_eq!(provider.r#type, "custom-api");

    run::provider_delete(&ts.endpoint, &["custom-provider".to_string()], &ts.tls)
        .await
        .expect("custom provider delete");
    run::provider_profile_delete(&ts.endpoint, "custom-api", &ts.tls)
        .await
        .expect("profile delete");
}

#[tokio::test]
async fn provider_profile_import_from_directory_imports_supported_profile_files() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-yaml.yaml"),
        r"
id: custom-yaml
display_name: Custom YAML
category: other
endpoints:
  - host: api.yaml.example
    port: 443
binaries: [/usr/bin/yaml-client]
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("custom-json.json"),
        r#"{
  "id": "custom-json",
  "display_name": "Custom JSON",
  "description": "",
  "category": "other",
  "credentials": [],
  "endpoints": [{"host": "api.json.example", "port": 443}],
  "binaries": ["/usr/bin/json-client"],
  "inference_capable": false
}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

    run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect("profile import --from");

    run::provider_profile_export(&ts.endpoint, "custom-yaml", "yaml", &ts.tls)
        .await
        .expect("custom-yaml should be imported");
    run::provider_profile_export(&ts.endpoint, "custom-json", "json", &ts.tls)
        .await
        .expect("custom-json should be imported");
}

#[tokio::test]
#[allow(deprecated)]
async fn provider_profile_import_preserves_advanced_network_policy_fields() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("advanced-api.yaml");
    std::fs::write(
        &profile_path,
        r"
id: advanced-api
display_name: Advanced API
category: other
endpoints:
  - host: api.advanced.example
    ports: [443, 8443]
    protocol: rest
    tls: terminate
    enforcement: enforce
    rules:
      - allow:
          method: GET
          path: /v1/**
    allowed_ips: [10.0.0.0/24]
    deny_rules:
      - method: POST
        path: /admin/**
    allow_encoded_slash: true
    path: /v1
binaries:
  - path: /usr/bin/advanced
    harness: true
",
    )
    .unwrap();

    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile import");

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let profile = client
        .get_provider_profile(openshell_core::proto::GetProviderProfileRequest {
            id: "advanced-api".to_string(),
        })
        .await
        .expect("get provider profile")
        .into_inner()
        .profile
        .expect("profile should exist");
    let endpoint = profile.endpoints.first().expect("endpoint should exist");
    assert_eq!(endpoint.ports, vec![443, 8443]);
    assert_eq!(endpoint.rules.len(), 1);
    assert_eq!(endpoint.deny_rules.len(), 1);
    assert_eq!(endpoint.allowed_ips, vec!["10.0.0.0/24"]);
    assert!(endpoint.allow_encoded_slash);
    assert_eq!(endpoint.path, "/v1");
    assert!(profile.binaries[0].harness);
}

#[tokio::test]
async fn provider_profile_import_from_directory_parse_error_prevents_partial_import() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-good.yaml"),
        r"
id: custom-good
display_name: Custom Good
category: other
endpoints:
  - host: api.good.example
    port: 443
",
    )
    .unwrap();
    std::fs::write(dir.path().join("broken.yaml"), "id: [\n").unwrap();

    let err = run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect_err("profile import --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile import failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", &ts.tls)
        .await
        .expect_err("valid profiles should not be partially imported after local parse errors");
}

#[tokio::test]
async fn provider_profile_lint_from_directory_reports_parse_errors_without_importing() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-good.yaml"),
        r"
id: custom-good
display_name: Custom Good
category: other
endpoints:
  - host: api.good.example
    port: 443
",
    )
    .unwrap();
    std::fs::write(dir.path().join("broken.yaml"), "id: [\n").unwrap();

    let err = run::provider_profile_lint(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect_err("profile lint --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile lint failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", &ts.tls)
        .await
        .expect_err("lint should not import valid profiles");
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

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
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

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
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
