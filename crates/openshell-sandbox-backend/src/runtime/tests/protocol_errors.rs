// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::proto::{exchange_frame, response_envelope};
use crate::protobuf::WireMessage as _;

#[derive(Clone)]
struct RejectingPeer {
    malformed_audit: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[tonic::async_trait]
impl SandboxProtocol for RejectingPeer {
    type ExchangeStream = TestGrpcStream;
    type MediateStream = TestGrpcStream<MediateFrame>;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<ExchangeFrame>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        let mut inbound = request.into_inner();
        test_bind(&mut inbound).await;
        let peer = self.clone();
        let (outbound, receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let frame = inbound.message().await.unwrap().unwrap();
            let Some(exchange_frame::Payload::Request(request)) = frame.payload else {
                panic!("expected a typed request");
            };
            peer.calls.fetch_add(1, Ordering::AcqRel);
            if peer.malformed_audit {
                let mut confirmation = test_confirmation().to_proto().unwrap();
                confirmation.backend_audit = b"not-json".to_vec();
                outbound
                    .send(Ok(ExchangeFrame {
                        payload: Some(exchange_frame::Payload::Response(
                            crate::proto::ResponseEnvelope {
                                request_id: request.request_id,
                                response: Some(response_envelope::Response::Confirmed(
                                    crate::proto::Confirmed {
                                        confirmation: Some(confirmation),
                                    },
                                )),
                            },
                        )),
                    }))
                    .await
                    .unwrap();
            } else {
                outbound
                    .send(Err(tonic::Status::unimplemented(
                        "provider files unsupported",
                    )))
                    .await
                    .unwrap();
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
            receiver,
        ))))
    }

    async fn mediate(
        &self,
        _: tonic::Request<tonic::Streaming<MediateFrame>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("unused"))
    }
}

#[tokio::test]
async fn protocol_failures_are_terminal_and_tcp_uses_configured_http_authority() {
    for malformed_audit in [true, false] {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut descriptor = tls_runtime_descriptor(address, certificate.client_tls.clone());
        let SandboxTransport::Tcp { authority, .. } = &mut descriptor.transport else {
            unreachable!();
        };
        *authority = "backend.route.test:7443".into();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_authorities = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = seen_authorities.clone();
        let peer = RejectingPeer {
            malformed_audit,
            calls: calls.clone(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            tonic::transport::Server::builder()
                .layer(tower::util::MapRequestLayer::new(
                    move |request: tonic::codegen::http::Request<_>| {
                        observed
                            .lock()
                            .unwrap()
                            .push(request.uri().authority().unwrap().to_string());
                        request
                    },
                ))
                .add_service(IsolationBackendServer::new(TestIsolationBackend::default()))
                .add_service(SandboxProtocolServer::new(peer))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                    Box::new(stream),
                ))]))
                .await
                .unwrap();
        });
        let client = BoundaryClient::new(descriptor, test_bearer(&"a".repeat(32)));
        let request = if malformed_audit {
            Request::Confirm
        } else {
            Request::UpdateProviderEnvironment {
                generation: 1,
                revision: 1,
                provider_env: HashMap::new(),
                provider_files: HashMap::from([(
                    "/run/openshell/providers/key".into(),
                    "value".into(),
                )]),
            }
        };
        let error = tokio::time::timeout(Duration::from_secs(5), client.call_idempotent(request))
            .await
            .expect("protocol errors must not enter transport recovery")
            .unwrap_err();
        if malformed_audit {
            assert!(matches!(error, BackendError::Descriptor(_)), "{error:?}");
            assert!(
                error
                    .to_string()
                    .contains("backend_audit must be UTF-8 JSON"),
                "{error}"
            );
        } else {
            assert!(matches!(error, BackendError::Unsupported(_)), "{error:?}");
            assert!(
                error.to_string().contains("provider files unsupported"),
                "{error}"
            );
        }
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "terminal failures must not replay"
        );
        let seen = seen_authorities.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(
            seen.iter().all(|value| value == "backend.route.test:7443"),
            "{seen:?}"
        );
        server.abort();
    }
}
