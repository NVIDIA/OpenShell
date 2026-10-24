// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio_stream::StreamExt as _;

#[derive(Clone)]
struct RenewingGrpcBoundary {
    inner: TestGrpcBoundary,
    expected_token: Arc<std::sync::RwLock<String>>,
    failures: Arc<std::sync::atomic::AtomicUsize>,
    failure_code: tonic::Code,
    confirmation: Arc<std::sync::RwLock<BoundaryConfirmation>>,
    attach_generation: Arc<std::sync::RwLock<String>>,
}

#[tonic::async_trait]
impl SandboxProtocol for RenewingGrpcBoundary {
    type ExchangeStream = TestGrpcStream;
    type MediateStream = TestGrpcStream<MediateFrame>;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<ExchangeFrame>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        if self
            .failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(tonic::Status::new(
                self.failure_code,
                "injected boundary failure",
            ));
        }
        let mut inner = self.inner.clone();
        inner.expected_token = self.expected_token.read().unwrap().clone();
        inner.confirmation = self.confirmation.read().unwrap().clone();
        inner.attach_generation = self.attach_generation.read().unwrap().clone();
        inner.exchange(request).await
    }

    async fn mediate(
        &self,
        request: tonic::Request<tonic::Streaming<MediateFrame>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        let mut inner = self.inner.clone();
        inner.expected_token = self.expected_token.read().unwrap().clone();
        inner.mediate(request).await
    }
}

async fn renewing_boundary_client(
    failure_code: tonic::Code,
) -> (
    Arc<BoundaryClient>,
    RenewingGrpcBoundary,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let certificate = test_certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = RenewingGrpcBoundary {
        inner: TestGrpcBoundary {
            attach_generation: "test-generation".to_string(),
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            provider_environment_generation: 0,
            confirmation: test_confirmation(),
        },
        expected_token: Arc::new(std::sync::RwLock::new("a".repeat(32))),
        failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        failure_code,
        confirmation: Arc::new(std::sync::RwLock::new(test_confirmation())),
        attach_generation: Arc::new(std::sync::RwLock::new("test-generation".to_string())),
    };
    let server_service = service.clone();
    let server_accepted = accepted.clone();
    let server = tokio::spawn(async move {
        // Aborting the fixture also closes every child TLS connection.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config.clone())
                .accept(stream)
                .await
                .unwrap();
            server_accepted.fetch_add(1, Ordering::AcqRel);
            let service = server_service.clone();
            connections.spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                    .add_service(SandboxProtocolServer::new(service))
                    .serve_with_incoming(
                        tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(Box::new(stream)))])
                            .chain(tokio_stream::pending()),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    let client = Arc::new(BoundaryClient::new(
        tls_runtime_descriptor(address, certificate.client_tls),
        test_bearer(&"a".repeat(32)),
    ));
    client
        .call_idempotent(Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
        })
        .await
        .unwrap();
    client.call_idempotent(Request::Confirm).await.unwrap();
    (client, service, accepted, server)
}

#[tokio::test]
async fn same_epoch_renewal_reauthenticates_without_closing_pending_stream() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    // Authenticate a stream that remains open across both bearer renewals.
    let mut pending = client
        .open_grpc_stream(GrpcStreamKind::Exchange)
        .await
        .unwrap();
    for (index, token) in ["b".repeat(32), "c".repeat(32)].into_iter().enumerate() {
        *service.expected_token.write().unwrap() = token.clone();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(token).unwrap(),
                i64::MAX,
                openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            )
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            client.ensure_current_credential_connection(),
        )
        .await
        .expect("renewal must complete")
        .unwrap();
        assert_eq!(
            service.inner.requests.load(Ordering::Acquire),
            3 + index,
            "each renewed bearer must authenticate a Confirm RPC"
        );
        assert_eq!(
            accepted.load(Ordering::Acquire),
            1,
            "renewal must reuse the physical connection"
        );
    }
    let request = BoundaryClient::prepare_request(Request::Wait {
        process_id: "pending".into(),
    })
    .unwrap();
    pending
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut pending),
    )
    .await
    .expect("pending stream must survive renewal")
    .unwrap();
    assert!(matches!(response.response, Response::Exited { .. }));
    server.abort();
}

#[tokio::test]
async fn failed_renewal_keeps_authenticated_fingerprint_and_retries() {
    for failure_code in [tonic::Code::Unavailable, tonic::Code::PermissionDenied] {
        let (client, service, accepted, server) = renewing_boundary_client(failure_code).await;
        let original = client.grpc_channel.lock().await.clone().unwrap();
        let renewed_token = "b".repeat(32);
        *service.expected_token.write().unwrap() = renewed_token.clone();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(renewed_token).unwrap(),
                i64::MAX,
                openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            )
            .unwrap();

        // A refused confirmation must remain visible to the monitor, including
        // an authentication denial; no fingerprint may suppress its next check.
        service.failures.store(1, Ordering::Release);
        let result = client.ensure_current_credential_connection().await;
        match failure_code {
            tonic::Code::PermissionDenied => {
                assert!(matches!(result, Err(BackendError::Denied(_))));
            }
            _ => assert!(matches!(result, Err(BackendError::Unavailable(_)))),
        }
        let failed = client.grpc_channel.lock().await.clone().unwrap();
        assert_eq!(failed.bearer_fingerprint, original.bearer_fingerprint);
        assert_eq!(failed.generation, original.generation);
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 2);

        client.ensure_current_credential_connection().await.unwrap();
        let confirmed = client.grpc_channel.lock().await.clone().unwrap();
        assert_ne!(confirmed.bearer_fingerprint, original.bearer_fingerprint);
        assert_eq!(confirmed.generation, original.generation);
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
        assert_eq!(accepted.load(Ordering::Acquire), 1);

        // The confirmed credential needs no further RPC until it changes.
        client.ensure_current_credential_connection().await.unwrap();
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
        server.abort();
    }
}

#[tokio::test]
async fn confirmation_authenticates_captured_bearer_after_slot_changes() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let credential = BoundaryCredential::capture(&client.sandbox_bearer).unwrap();
    // Race a later slot update with an already captured confirmation. The peer
    // still expects the captured token; rereading the slot would be rejected.
    client
        .sandbox_bearer
        .update(
            SecretJwt::parse("b".repeat(32)).unwrap(),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        )
        .unwrap();
    let channel = client
        .grpc_channel
        .lock()
        .await
        .as_ref()
        .unwrap()
        .channel
        .clone();
    let envelope = BoundaryClient::prepare_request(Request::Confirm).unwrap();
    let response = client
        .exchange_on_channel(channel, &envelope, &credential)
        .await
        .unwrap();
    assert!(matches!(response, Response::Confirmed { .. }));
    assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    server.abort();
}

type Mismatch = (&'static str, &'static str, fn(&mut BoundaryConfirmation));

/// A backend that loses its launch state answers with a confirmation that no
/// longer matches the launch. Each case names the field the error must report.
const CONFIRMATION_MISMATCHES: &[Mismatch] = &[
    ("identity", "identity", |c| {
        c.identity =
            ResolvedWorkloadIdentity::new(10_002, 10_001, Vec::new(), "test".into(), "x".into())
                .unwrap();
    }),
    ("empty generation", "generation (empty)", |c| {
        c.generation.clear();
    }),
    ("generation", "generation", |c| {
        c.generation = "other-generation".into();
    }),
    ("session", "session", |c| {
        c.session_id = "550e8400-e29b-41d4-a716-446655440001".parse().unwrap();
    }),
    ("resource claims", "resource claims", |c| {
        c.resource_claims.insert("claim".into(), "other".into());
    }),
    ("provisioning evidence", "provisioning evidence", |c| {
        c.provisioning_evidence_digest = openshell_isolation_interface::contract::ProvisioningEvidence::from_enforcement_evidence(
            "test-generation",
            b"other-evidence",
        )
        .unwrap()
        .evidence_digest;
    }),
];

#[tokio::test]
async fn renewal_rejects_mismatched_confirmation() {
    for (case, field, mutate) in CONFIRMATION_MISMATCHES {
        let (client, service, accepted, server) =
            renewing_boundary_client(tonic::Code::Unavailable).await;
        let original = client.grpc_channel.lock().await.clone().unwrap();
        mutate(&mut service.confirmation.write().unwrap());
        let renewed_token = "b".repeat(32);
        *service.expected_token.write().unwrap() = renewed_token.clone();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(renewed_token).unwrap(),
                i64::MAX,
                openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            )
            .unwrap();

        let result = client.ensure_current_credential_connection().await;
        assert!(
            matches!(&result, Err(BackendError::Confirm(message)) if message.contains(&format!("confirmation {field} does not match"))),
            "{case}: renewal must reject the confirmation: {result:?}"
        );
        let failed = client.grpc_channel.lock().await.clone().unwrap();
        assert_eq!(failed.bearer_fingerprint, original.bearer_fingerprint);
        assert!(
            failed.transport.is_aborted(),
            "{case}: a mismatched renewal must close the connection's live streams"
        );
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        server.abort();
    }
}

#[tokio::test]
async fn reconnect_rejects_mismatched_confirmation() {
    for (case, field, mutate) in CONFIRMATION_MISMATCHES {
        let (client, service, accepted, server) =
            renewing_boundary_client(tonic::Code::Unavailable).await;
        mutate(&mut service.confirmation.write().unwrap());

        // The liveness probe must not keep the connection, and the replacement
        // connection's replayed Confirm must not be accepted either.
        let result = client
            .recover_after_unavailable(client.connection_generation().await)
            .await;
        assert!(
            matches!(&result, Err(BackendError::Confirm(message)) if message.contains(&format!("confirmation {field} does not match"))),
            "{case}: reconnect must reject the confirmation: {result:?}"
        );
        assert_eq!(accepted.load(Ordering::Acquire), 2);
        server.abort();
    }
}

#[tokio::test]
async fn launch_checks_reject_wrong_response_variants() {
    let (client, _service, _accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let confirmed = || Response::Confirmed {
        confirmation: Box::new(test_confirmation()),
    };
    let attached = || Response::Attached {
        snapshot: crate::boundary_protocol::SessionSnapshotWire {
            generation: "test-generation".to_string(),
            processes: Vec::new(),
        },
    };
    assert!(client.check_attached(attached()).is_ok());
    assert!(client.launch_confirmation(confirmed()).is_ok());
    for wrong in [confirmed(), Response::Signaled, Response::Terminated] {
        assert!(matches!(
            client.check_attached(wrong),
            Err(BackendError::Process(message)) if message.contains("\"attached\"")
        ));
    }
    for wrong in [attached(), Response::Signaled, Response::Terminated] {
        assert!(matches!(
            client.launch_confirmation(wrong),
            Err(BackendError::Process(message)) if message.contains("\"confirmed\"")
        ));
    }
    server.abort();
}

#[tokio::test]
async fn reconnect_rejects_attach_for_another_generation() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let cached = client.grpc_channel.lock().await.clone().unwrap();
    cached.transport.abort();
    *service.attach_generation.write().unwrap() = "other-generation".to_string();

    let result = client
        .recover_after_unavailable(client.connection_generation().await)
        .await;
    assert!(
        matches!(&result, Err(BackendError::Confirm(message)) if message.contains("snapshot generation")),
        "reconnect must reject an Attach for another generation: {result:?}"
    );
    assert_eq!(accepted.load(Ordering::Acquire), 2);
    server.abort();
}
