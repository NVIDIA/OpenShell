// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::tempdir;
use helpers::{Environment, build_ca, build_client_cert, build_server_cert};
use openshell_bootstrap::{get_gateway_metadata, load_active_gateway};
use openshell_cli::{
    run,
    tls::{TlsOptions, grpc_client},
};
use openshell_core::proto::{
    CreateSshSessionRequest, CreateSshSessionResponse, ExecSandboxEvent, ExecSandboxRequest,
    HealthRequest, HealthResponse, RevokeSshSessionRequest, RevokeSshSessionResponse,
    ServiceStatus,
};
use openshell_server::test_support::grpc::open_shell_server::{OpenShell, OpenShellServer};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Response, Status,
    transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig},
};

#[derive(Clone, Default)]
struct TestOpenShell;

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
        _request: tonic::Request<openshell_core::proto::CreateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::SandboxResponse::default(),
        ))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxesResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxesResponse::default(),
        ))
    }

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxProvidersRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ListSandboxProvidersResponse::default(),
        ))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<openshell_core::proto::AttachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::AttachSandboxProviderResponse::default(),
        ))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<openshell_core::proto::DetachSandboxProviderRequest>,
    ) -> Result<Response<openshell_core::proto::DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DetachSandboxProviderResponse::default(),
        ))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::DeleteSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteSandboxResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::DeleteSandboxResponse {
                sandbox_id: String::new(),
                outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
            },
        ))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetSandboxConfigResponse::default(),
        ))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<openshell_core::proto::GetGatewayConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetGatewayConfigResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::GetGatewayConfigResponse::default(),
        ))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxProviderEnvironmentResponse>, Status>
    {
        Ok(Response::new(
            openshell_core::proto::GetSandboxProviderEnvironmentResponse::default(),
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

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::WatchSandboxRequest>,
    ) -> Result<
        Response<tonic::codegen::BoxStream<openshell_core::proto::SandboxStreamEvent>>,
        Status,
    > {
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

async fn run_server(
    server_cert: String,
    server_key: String,
    ca_cert: String,
) -> std::net::SocketAddr {
    let identity = Identity::from_pem(server_cert, server_key);
    let client_ca = TlsCertificate::from_pem(ca_cert);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(OpenShellServer::new(TestOpenShell))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    addr
}

fn write_gateway_mtls_bundle(
    config_dir: &std::path::Path,
    gateway_name: &str,
    ca_cert: &str,
    client_cert: &str,
    client_key: &str,
) {
    let mtls = config_dir
        .join("openshell")
        .join("gateways")
        .join(gateway_name)
        .join("mtls");
    std::fs::create_dir_all(&mtls).unwrap();
    std::fs::write(mtls.join("ca.crt"), ca_cert).unwrap();
    std::fs::write(mtls.join("tls.crt"), client_cert).unwrap();
    std::fs::write(mtls.join("tls.key"), client_key).unwrap();
}

fn isolated_gateway_add_env(
    config_dir: &std::path::Path,
    state_dir: &std::path::Path,
) -> Environment {
    let xdg_config = config_dir.to_string_lossy().into_owned();
    let xdg_state = state_dir.to_string_lossy().into_owned();
    let local_tls_dir = state_dir.join("no-package-managed-tls");
    let local_tls = local_tls_dir.to_string_lossy().into_owned();

    Environment::from_pairs(&[
        ("XDG_CONFIG_HOME", xdg_config.as_str()),
        ("XDG_STATE_HOME", xdg_state.as_str()),
        ("HOME", xdg_state.as_str()),
        ("OPENSHELL_LOCAL_TLS_DIR", local_tls.as_str()),
        ("OPENSHELL_GATEWAY", "unused-by-named-gateway-add"),
    ])
}

#[tokio::test]
async fn gateway_add_mtls_loopback_uses_explicit_gateway_name() {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();
    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "k8s",
        &ca_cert,
        &client_cert,
        &client_key,
    );

    isolated_gateway_add_env(config_dir.path(), state_dir.path())
        .run_async(async {
            let endpoint = format!("https://localhost:{}", addr.port());
            run::gateway_add(
                &endpoint,
                Some("k8s"),
                None,
                true,
                None,
                "openshell-cli",
                None,
                None,
                false,
            )
            .await
            .unwrap();

            let metadata = get_gateway_metadata("k8s").unwrap();
            assert_eq!(metadata.name, "k8s");
            assert_eq!(metadata.gateway_endpoint, endpoint);
            assert_eq!(metadata.auth_mode.as_deref(), Some("mtls"));
            assert_eq!(load_active_gateway().as_deref(), Some("k8s"));
            assert!(get_gateway_metadata("openshell").is_none());
        })
        .await;
}

#[tokio::test]
async fn gateway_add_mtls_loopback_without_name_uses_openshell_default() {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();
    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "openshell",
        &ca_cert,
        &client_cert,
        &client_key,
    );

    isolated_gateway_add_env(config_dir.path(), state_dir.path())
        .run_async(async {
            let endpoint = format!("https://localhost:{}", addr.port());
            run::gateway_add(
                &endpoint,
                None,
                None,
                true,
                None,
                "openshell-cli",
                None,
                None,
                false,
            )
            .await
            .unwrap();

            let metadata = get_gateway_metadata("openshell").unwrap();
            assert_eq!(metadata.name, "openshell");
            assert_eq!(metadata.gateway_endpoint, endpoint);
            assert_eq!(metadata.auth_mode.as_deref(), Some("mtls"));
            assert_eq!(load_active_gateway().as_deref(), Some("openshell"));
        })
        .await;
}

#[tokio::test]
async fn gateway_add_mtls_loopback_explicit_name_does_not_fallback_to_openshell_certs() {
    let (ca, ca_key) = build_ca();
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let config_dir = tempdir().unwrap();
    let state_dir = tempdir().unwrap();
    write_gateway_mtls_bundle(
        config_dir.path(),
        "openshell",
        &ca_cert,
        &client_cert,
        &client_key,
    );

    isolated_gateway_add_env(config_dir.path(), state_dir.path())
        .run_async(async {
            let err = run::gateway_add(
                "https://localhost:1",
                Some("k8s"),
                None,
                true,
                None,
                "openshell-cli",
                None,
                None,
                false,
            )
            .await
            .expect_err("explicit name should require matching named mTLS material");

            assert!(err.to_string().contains("gateway 'k8s'"));
            assert!(get_gateway_metadata("k8s").is_none());
            assert!(load_active_gateway().is_none());
        })
        .await;
}

#[tokio::test]
async fn cli_connects_with_client_cert() {
    Environment::from_pairs(&[])
        .run_async(async {
            let (ca, ca_key) = build_ca();
            let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
            let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
            let ca_cert = ca.pem();

            let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

            let dir = tempdir().unwrap();
            let ca_path = dir.path().join("ca.crt");
            let cert_path = dir.path().join("tls.crt");
            let key_path = dir.path().join("tls.key");
            std::fs::write(&ca_path, ca_cert).unwrap();
            std::fs::write(&cert_path, client_cert).unwrap();
            std::fs::write(&key_path, client_key).unwrap();

            let tls = TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path));
            let endpoint = format!("https://localhost:{}", addr.port());
            let mut client = grpc_client(&endpoint, &tls).await.unwrap();
            let response = client.health(HealthRequest {}).await.unwrap();
            assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);
        })
        .await;
}

#[tokio::test]
async fn cli_requires_client_cert_for_https() {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let addr = run_server(server_cert, server_key, ca_cert.clone()).await;

    let dir = tempdir().unwrap();
    // Point XDG_CONFIG_HOME at the isolated temp dir so that default_tls_dir
    // cannot discover real client certs from the developer's machine.
    let xdg_path = dir.path().to_string_lossy();

    Environment::from_pairs(&[("XDG_CONFIG_HOME", &xdg_path)])
        .run_async(async {
            let ca_path = dir.path().join("ca.crt");
            std::fs::write(&ca_path, ca_cert).unwrap();

            let tls = TlsOptions::new(Some(ca_path), None, None);
            let endpoint = format!("https://localhost:{}", addr.port());
            let result = grpc_client(&endpoint, &tls).await;
            assert!(result.is_err());
        })
        .await;
}

async fn run_server_no_client_auth(
    server_cert: String,
    server_key: String,
) -> std::net::SocketAddr {
    let identity = Identity::from_pem(server_cert, server_key);
    let tls = ServerTlsConfig::new().identity(identity);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(OpenShellServer::new(TestOpenShell))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    addr
}

#[tokio::test]
async fn cli_connects_with_gateway_insecure() {
    Environment::from_pairs(&[])
        .run_async(async {
            let (ca, ca_key) = build_ca();
            let (server_cert, server_key) = build_server_cert(&ca, &ca_key);

            let addr = run_server_no_client_auth(server_cert, server_key).await;

            let mut tls = TlsOptions::default();
            tls.gateway_insecure = true;

            let endpoint = format!("https://localhost:{}", addr.port());
            let mut client = grpc_client(&endpoint, &tls).await.unwrap();
            let response = client.health(HealthRequest {}).await.unwrap();
            assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);
        })
        .await;
}
