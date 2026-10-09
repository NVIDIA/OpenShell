// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_isolation_interface::contract::{
    BackendDescriptor, BackendRegistry, EnforcedProperty,
};

const EXTERNAL_NAME: &str = "external-test";
const OPAQUE_PAYLOAD: &[u8] = b"external-driver-v1\0\xffresource";

async fn external_backend(
    confirmation: openshell_isolation_interface::contract::BoundaryConfirmation,
) -> (DelegatedRuntimeBackend, tokio::task::JoinHandle<()>) {
    let certificate = test_certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client_tls = certificate.client_tls.clone();
    let server = tokio::spawn(async move {
        // Discovery and attachment deliberately use separate authenticated connections.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = certificate.server_config.clone();
            let confirmation = confirmation.clone();
            connections.spawn(async move {
                let stream = tokio_rustls::TlsAcceptor::from(tls)
                    .accept(stream)
                    .await
                    .unwrap();
                let service = TestGrpcBoundary {
                    wait_for_half_close: false,
                    expected_token: "a".repeat(32),
                    requests: Arc::default(),
                    mediation_failures: Arc::default(),
                    mediation_ready: false,
                    provider_environment_generation: 0,
                    confirmation,
                };
                tonic::transport::Server::builder()
                    .add_service(IsolationBackendServer::new(TestIsolationBackend {
                        backend_name: EXTERNAL_NAME.into(),
                        driver_descriptor: Some(OPAQUE_PAYLOAD.to_vec()),
                        ..TestIsolationBackend::default()
                    }))
                    .add_service(DelegatedIsolationBoundaryServer::new(service))
                    .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                        Box::new(stream),
                    ))]))
                    .await
                    .unwrap();
            });
        }
    });
    let descriptor = tls_runtime_descriptor(address, client_tls);
    let bearer = test_bearer(&"a".repeat(32));
    assert_eq!(
        DelegatedRuntimeBackend::discover_policy(
            EXTERNAL_NAME.into(),
            descriptor.clone(),
            OPAQUE_PAYLOAD.to_vec(),
            bearer.clone()
        )
        .await
        .unwrap(),
        (None, false)
    );
    let backend = DelegatedRuntimeBackend::new(
        EXTERNAL_NAME.into(),
        descriptor,
        OPAQUE_PAYLOAD.to_vec(),
        Arc::new(std::sync::Mutex::new(None)),
        openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
            0,
            HashMap::new(),
        ),
        bearer,
    )
    .unwrap();
    (backend, server)
}

fn external_confirmation() -> openshell_isolation_interface::contract::BoundaryConfirmation {
    let mut confirmation = test_confirmation();
    confirmation.backend_audit = serde_json::json!({"external_boundary": "verified-actor"});
    let property = EnforcedProperty::new(true, "external-actor-isolation");
    confirmation.properties = openshell_isolation_interface::contract::BoundaryProperties {
        filesystem_confinement: property.clone(),
        egress_interception: property.clone(),
        request_attribution: property.clone(),
        privilege_floor: property,
    };
    confirmation
}

async fn attach_external(backend: DelegatedRuntimeBackend) -> Box<dyn BoundBoundary> {
    let mut registry = BackendRegistry::new();
    registry.register(Arc::new(backend)).unwrap();
    let (backend, descriptor) = registry
        .resolve(
            BackendDescriptor {
                backend_name: EXTERNAL_NAME.into(),
                payload: OPAQUE_PAYLOAD.to_vec(),
            },
            EXTERNAL_NAME,
        )
        .unwrap();
    backend.attach(descriptor, sandbox()).await.unwrap()
}

#[tokio::test]
async fn external_protocol_backend_runs_without_native_linux_audit() {
    let (backend, server) = external_backend(external_confirmation()).await;
    let confirmed = attach_external(backend).await.confirm().await.unwrap();
    assert_eq!(
        confirmed.confirmation().backend_audit["external_boundary"],
        "verified-actor"
    );
    let running = confirmed.into_boundary().start_agent().await.unwrap();
    assert_eq!(
        running.agent().wait().await.unwrap(),
        BoundaryExitStatus::Exited(23)
    );
    running.agent().signal(BoundarySignal::Term).await.unwrap();
    running.terminate().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn external_confirmation_still_requires_common_guarantees_and_launch_binding() {
    for field in [
        "generation",
        "session",
        "identity",
        "fence",
        "fence_digest",
        "claims",
        "properties",
        "mechanism",
        "containment",
        "authentication",
    ] {
        let mut confirmation = external_confirmation();
        match field {
            "generation" => confirmation.generation = "other-generation".into(),
            "session" => confirmation.session_id = openshell_core::SandboxSessionId::new(),
            "identity" => confirmation.identity.uid += 1,
            "fence" => confirmation.outer_fence.generation = "other-generation".into(),
            "fence_digest" => {
                confirmation.outer_fence.evidence_digest = "f".repeat(64).parse().unwrap();
            }
            "claims" => {
                confirmation
                    .resource_claims
                    .insert("unexpected".into(), "claim".into());
            }
            "properties" => confirmation.properties.egress_interception.enforced = false,
            "mechanism" => confirmation
                .properties
                .egress_interception
                .mechanism
                .clear(),
            "containment" => confirmation.runtime_exit_terminates_workload = false,
            "authentication" => confirmation.authenticated_supervisor = false,
            _ => unreachable!(),
        }
        let (backend, server) = external_backend(confirmation).await;
        assert!(
            matches!(
                attach_external(backend).await.confirm().await,
                Err(BackendError::Confirm(_))
            ),
            "{field}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn delegated_backend_rejects_reserved_name_and_changed_payload_before_io() {
    let certificate = test_certificate();
    let descriptor = tls_runtime_descriptor("127.0.0.1:1".parse().unwrap(), certificate.client_tls);
    assert!(matches!(
        DelegatedRuntimeBackend::new(
            crate::BACKEND_NAME.into(),
            descriptor.clone(),
            OPAQUE_PAYLOAD.to_vec(),
            Arc::default(),
            openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(
                0,
                HashMap::new()
            ),
            test_bearer(&"a".repeat(32))
        ),
        Err(BackendError::Descriptor(_))
    ));
    assert!(matches!(
        DelegatedRuntimeBackend::discover_policy(
            crate::BACKEND_NAME.into(),
            descriptor,
            OPAQUE_PAYLOAD.to_vec(),
            test_bearer(&"a".repeat(32))
        )
        .await,
        Err(BackendError::Descriptor(_))
    ));
    let (backend, server) = external_backend(external_confirmation()).await;
    let mut registry = BackendRegistry::new();
    registry.register(Arc::new(backend)).unwrap();
    let (backend, descriptor) = registry
        .resolve(
            BackendDescriptor {
                backend_name: EXTERNAL_NAME.into(),
                payload: b"changed".to_vec(),
            },
            EXTERNAL_NAME,
        )
        .unwrap();
    assert!(matches!(backend.attach(descriptor, sandbox()).await,
        Err(BackendError::Descriptor(message)) if message.contains("payload changed")));
    server.abort();
}
