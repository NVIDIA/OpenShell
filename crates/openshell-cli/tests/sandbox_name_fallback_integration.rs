// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::TempDir;
use helpers::{Environment, build_ca, build_client_cert, build_server_cert};
use openshell_bootstrap::{load_last_sandbox, save_last_sandbox};
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, ExecSandboxEvent,
    ExecSandboxRequest, GetGatewayConfigRequest, GetGatewayConfigResponse, GetProviderRequest,
    GetSandboxConfigRequest, GetSandboxConfigResponse, GetSandboxPolicyStatusRequest,
    GetSandboxPolicyStatusResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxProvidersRequest,
    ListSandboxProvidersResponse, ListSandboxesRequest, ListSandboxesResponse, NetworkEndpoint,
    NetworkPolicyRule, PolicyStatus, ProviderResponse, Sandbox, SandboxPolicy,
    SandboxPolicyRevision, SandboxResponse, SandboxStreamEvent, ServiceStatus,
    UpdateProviderRequest, WatchSandboxRequest,
};
use openshell_server::test_support::grpc::open_shell_server::{OpenShell, OpenShellServer};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

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
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let request = request.into_inner();
        let name = request.name.clone();
        *self.state.last_get_name.lock().await = Some(name.clone());
        Ok(Response::new(SandboxResponse {
            application_service_urls: std::collections::HashMap::new(),
            gateway_service_urls: std::collections::HashMap::new(),
            sandbox: Some(Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "test-id".to_string(),
                    name,
                    created_time: None,
                    labels: std::collections::HashMap::new(),
                    resource_version: 0,
                    annotations: std::collections::HashMap::new(),
                    workspace: String::new(),
                    deletion_time: None,
                }),
                ..Default::default()
            }),
            service_urls: std::collections::HashMap::new(),
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
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse {
            sandbox_id: String::new(),
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
        }))
    }

    async fn get_sandbox_config(
        &self,
        request: tonic::Request<GetSandboxConfigRequest>,
    ) -> Result<Response<GetSandboxConfigResponse>, Status> {
        let req = request.into_inner();
        assert!(!req.name.is_empty());
        Ok(Response::new(GetSandboxConfigResponse {
            policy: Some(SandboxPolicy {
                version: 1,
                network_policies: [
                    (
                        "user_api".to_string(),
                        NetworkPolicyRule {
                            name: "user_api".to_string(),
                            endpoints: vec![NetworkEndpoint {
                                host: "api.user.example.com".to_string(),
                                port: 443,
                                protocol: "rest".to_string(),
                                enforcement: openshell_core::proto::NetworkEnforcementMode::Enforce
                                    as i32,
                                access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    ),
                    (
                        "_provider_api".to_string(),
                        NetworkPolicyRule {
                            name: "_provider_api".to_string(),
                            endpoints: vec![NetworkEndpoint {
                                host: "api.provider.example.com".to_string(),
                                port: 443,
                                protocol: "rest".to_string(),
                                enforcement: openshell_core::proto::NetworkEnforcementMode::Enforce
                                    as i32,
                                access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            version: 9,
            policy_hash: "sha256:effective-policy".to_string(),
            config_revision: 42,
            policy_source: openshell_core::proto::PolicySource::Sandbox.into(),
            ..Default::default()
        }))
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
        Ok(Response::new(DeleteProviderResponse {
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
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

    async fn get_sandbox_policy_status(
        &self,
        request: tonic::Request<GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
        let req = request.into_inner();
        assert_eq!(req.sandbox, "my-sandbox");
        assert_eq!(req.version, 3);
        assert!(!req.global);

        let policy = SandboxPolicy {
            version: 1,
            network_policies: std::iter::once((
                "api".to_string(),
                NetworkPolicyRule {
                    name: "api".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        protocol: "rest".to_string(),
                        enforcement: openshell_core::proto::NetworkEnforcementMode::Enforce as i32,
                        access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };

        Ok(Response::new(GetSandboxPolicyStatusResponse {
            revision: Some(SandboxPolicyRevision {
                version: 7,
                policy_hash: "sha256:test-policy".to_string(),
                status: PolicyStatus::Loaded.into(),
                created_time: openshell_core::time::timestamp_from_millis(1_700_000_000_000).ok(),
                loaded_time: openshell_core::time::timestamp_from_millis(1_700_000_000_500).ok(),
                policy: Some(policy),
                ..Default::default()
            }),
            active_version: 7,
        }))
    }
}

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

// ── tests ─────────────────────────────────────────────────────────────

/// Verify that `sandbox_get` works through a real gRPC round-trip and that the
/// mock records the correct name.
#[tokio::test]
async fn sandbox_get_sends_correct_name() {
    let ts = run_server().await;

    run::sandbox_get(
        &ts.endpoint,
        "my-sandbox",
        false,
        "table",
        "default",
        &ts.tls,
    )
    .await
    .expect("sandbox_get should succeed");

    let recorded = ts.openshell.state.last_get_name.lock().await.clone();
    assert_eq!(
        recorded.as_deref(),
        Some("my-sandbox"),
        "mock should have recorded the requested sandbox name"
    );
}

/// `sandbox_get` with `policy_only` calls `GetSandboxConfig` and prints YAML from the response.
#[tokio::test]
async fn sandbox_get_policy_only_round_trip() {
    let ts = run_server().await;

    run::sandbox_get(
        &ts.endpoint,
        "my-sandbox",
        true,
        "table",
        "default",
        &ts.tls,
    )
    .await
    .expect("sandbox_get with policy_only should succeed");

    let recorded = ts.openshell.state.last_get_name.lock().await.clone();
    assert_eq!(recorded.as_deref(), Some("my-sandbox"));
}

/// End-to-end: save a last-used sandbox, load it back, then call `sandbox_get`
/// with the resolved name. This validates the persistence + gRPC wiring.
#[tokio::test]
async fn sandbox_get_with_persisted_last_sandbox() {
    let ts = run_server().await;
    let xdg_dir = helpers::tempdir().unwrap();

    Environment::from_pairs(&[("XDG_CONFIG_HOME", xdg_dir.path().to_str().unwrap())])
        .run_async(async {
            // Persist a last-used sandbox for "integration-cluster".
            save_last_sandbox("integration-cluster", "default", "persisted-sb")
                .expect("save_last_sandbox should succeed");

            // Resolve the name (simulates what the CLI does in main.rs).
            let resolved = load_last_sandbox("integration-cluster", "default")
                .expect("load_last_sandbox should return the saved name");
            assert_eq!(resolved, "persisted-sb");

            // Call sandbox_get with the resolved name.
            run::sandbox_get(&ts.endpoint, &resolved, false, "table", "default", &ts.tls)
                .await
                .expect("sandbox_get should succeed");

            let recorded = ts.openshell.state.last_get_name.lock().await.clone();
            assert_eq!(
                recorded.as_deref(),
                Some("persisted-sb"),
                "the persisted sandbox name should flow through to the gRPC request"
            );
        })
        .await;
}

#[tokio::test]
async fn policy_get_full_json_cli_prints_policy_payload() {
    let ts = run_server().await;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    run::sandbox_policy_get_to_writer(
        &ts.endpoint,
        "my-sandbox",
        0,
        run::PolicyGetView::Full,
        "json",
        "default",
        &ts.tls,
        (&mut stdout, &mut stderr),
    )
    .await
    .expect("policy get should succeed");

    assert!(
        stderr.is_empty(),
        "policy get should not print stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["scope"], "sandbox");
    assert_eq!(json["sandbox"], "my-sandbox");
    assert_eq!(json["version"], 9);
    assert_eq!(json["active_version"], 9);
    assert_eq!(json["hash"], "sha256:effective-policy");
    assert_eq!(json["status"], "effective");
    assert_eq!(json["config_revision"], 42);
    assert_eq!(json["policy_source"], "sandbox");
    assert_eq!(
        json["policy"]["network_policies"]["_provider_api"]["name"],
        "_provider_api"
    );
    assert_eq!(
        json["policy"]["network_policies"]["_provider_api"]["endpoints"][0]["host"],
        "api.provider.example.com"
    );
    assert_eq!(
        json["policy"]["network_policies"]["user_api"]["endpoints"][0]["host"],
        "api.user.example.com"
    );
}

#[tokio::test]
async fn policy_get_base_json_cli_prints_round_trippable_policy_payload() {
    let ts = run_server().await;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    run::sandbox_policy_get_to_writer(
        &ts.endpoint,
        "my-sandbox",
        0,
        run::PolicyGetView::Base,
        "json",
        "default",
        &ts.tls,
        (&mut stdout, &mut stderr),
    )
    .await
    .expect("policy get --base should succeed");

    assert!(
        stderr.is_empty(),
        "policy get --base should not print stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["scope"], "sandbox");
    assert_eq!(json["sandbox"], "my-sandbox");
    assert_eq!(json["status"], "effective");
    assert!(
        json["policy"]["network_policies"]
            .get("_provider_api")
            .is_none(),
        "base policy output must omit provider-composed policy entries"
    );
    assert_eq!(
        json["policy"]["network_policies"]["user_api"]["endpoints"][0]["host"],
        "api.user.example.com"
    );
}

#[tokio::test]
async fn policy_get_explicit_revision_uses_stored_policy_status() {
    let ts = run_server().await;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    run::sandbox_policy_get_to_writer(
        &ts.endpoint,
        "my-sandbox",
        3,
        run::PolicyGetView::Full,
        "json",
        "default",
        &ts.tls,
        (&mut stdout, &mut stderr),
    )
    .await
    .expect("policy get --rev should succeed");

    assert!(
        stderr.is_empty(),
        "policy get --rev should not print stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["scope"], "sandbox");
    assert_eq!(json["sandbox"], "my-sandbox");
    assert_eq!(json["version"], 7);
    assert_eq!(json["active_version"], 7);
    assert_eq!(json["hash"], "sha256:test-policy");
    assert_eq!(json["status"], "loaded");
    assert_eq!(json["policy"]["network_policies"]["api"]["name"], "api");
    assert_eq!(
        json["policy"]["network_policies"]["api"]["endpoints"][0]["host"],
        "api.example.com"
    );
}

/// Verify that an explicit name takes precedence over the persisted one.
#[tokio::test]
async fn explicit_name_takes_precedence_over_persisted() {
    let ts = run_server().await;
    let xdg_dir = helpers::tempdir().unwrap();

    Environment::from_pairs(&[("XDG_CONFIG_HOME", xdg_dir.path().to_str().unwrap())])
        .run_async(async {
            // Persist one name, but supply a different one explicitly.
            save_last_sandbox("my-cluster", "default", "old-sandbox").expect("save should succeed");

            run::sandbox_get(
                &ts.endpoint,
                "explicit-sandbox",
                false,
                "table",
                "default",
                &ts.tls,
            )
            .await
            .expect("sandbox_get should succeed");

            let recorded = ts.openshell.state.last_get_name.lock().await.clone();
            assert_eq!(
                recorded.as_deref(),
                Some("explicit-sandbox"),
                "explicit name should be used, not the persisted one"
            );
        })
        .await;
}
