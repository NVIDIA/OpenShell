// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::{build_ca, build_client_cert, build_server_cert};
use openshell_cli::run;
use openshell_cli::tls::{TlsOptions, grpc_client};
use openshell_core::proto::open_shell_server::OpenShellServer;
use openshell_core::proto::{CreateSandboxRequest, SandboxSpec};
use openshell_server::test_support::{authenticate_as_dev_user, gateway_service_with_driver};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};

struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    _dir: TempDir,
}

async fn run_server() -> TestServer {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let tls_config = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(TlsCertificate::from_pem(ca_cert.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = gateway_service_with_driver("docker").await;

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(OpenShellServer::with_interceptor(
                service,
                authenticate_as_dev_user,
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
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

    TestServer {
        endpoint: format!("https://localhost:{}", addr.port()),
        tls: TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path)),
        _dir: dir,
    }
}

#[tokio::test]
async fn policy_only_preserves_all_process_identity_combinations_through_gateway() {
    let server = run_server().await;
    let cases = [
        ("neither", "process: {}", None),
        (
            "user-only",
            "process:\n  run_as_user: \"1500\"",
            Some(("1500", "")),
        ),
        (
            "group-only",
            "process:\n  run_as_group: \"1600\"",
            Some(("", "1600")),
        ),
        (
            "both",
            "process:\n  run_as_user: \"1500\"\n  run_as_group: \"1600\"",
            Some(("1500", "1600")),
        ),
    ];

    for (name, process_yaml, expected) in cases {
        let authored = format!("version: 1\n{process_yaml}\n");
        let policy = openshell_policy::parse_sandbox_policy(&authored)
            .unwrap_or_else(|error| panic!("{name}: authored policy should parse: {error}"));

        let mut client = grpc_client(&server.endpoint, &server.tls).await.unwrap();
        client
            .create_sandbox(CreateSandboxRequest {
                name: name.to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                workspace: "default".to_string(),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|error| panic!("{name}: gateway create should succeed: {error}"));

        let mut output = Vec::new();
        run::sandbox_get_to_writer(
            &server.endpoint,
            name,
            true,
            "table",
            "default",
            &server.tls,
            &mut output,
        )
        .await
        .unwrap_or_else(|error| panic!("{name}: --policy-only should succeed: {error}"));

        let output = String::from_utf8(output).unwrap();
        let exported = openshell_policy::parse_sandbox_policy(&output)
            .unwrap_or_else(|error| panic!("{name}: exported YAML should parse: {error}"));
        match expected {
            None => {
                assert!(
                    exported.process.is_none(),
                    "{name}: empty process must be omitted"
                );
                assert!(!output.contains("process:"), "{name}: {output}");
            }
            Some((user, group)) => {
                let process = exported
                    .process
                    .expect("partial process should be retained");
                assert_eq!(process.run_as_user, user, "{name}: {output}");
                assert_eq!(process.run_as_group, group, "{name}: {output}");
            }
        }
    }
}
