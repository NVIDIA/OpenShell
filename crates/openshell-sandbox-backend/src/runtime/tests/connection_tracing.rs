// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_otel_test_support::{OtlpTestServer, tracing_test_lock};
use std::collections::BTreeMap;
use std::future::Future;
#[cfg(unix)]
use std::future::poll_fn;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::Instrument as _;
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, Debug)]
struct ConnectionSpan {
    id: tracing::Id,
    parent: Option<tracing::Id>,
    fields: BTreeMap<&'static str, String>,
    closed: bool,
}

#[derive(Clone, Default)]
struct ConnectionSpans(Arc<Mutex<Vec<ConnectionSpan>>>);

impl ConnectionSpans {
    fn snapshot(&self) -> Vec<ConnectionSpan> {
        self.0.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct Fields(BTreeMap<&'static str, String>);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name(), value.to_string());
    }
}

impl<S: tracing::Subscriber + for<'span> LookupSpan<'span>> tracing_subscriber::Layer<S>
    for ConnectionSpans
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        context: LayerContext<'_, S>,
    ) {
        let span = context.span(id).unwrap();
        if span.name() != "supervisor.boundary.connect" {
            return;
        }
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        self.0.lock().unwrap().push(ConnectionSpan {
            id: id.clone(),
            parent: span.parent().map(|parent| parent.id()),
            fields: fields.0,
            closed: false,
        });
    }

    fn on_record(
        &self,
        id: &tracing::Id,
        values: &tracing::span::Record<'_>,
        _: LayerContext<'_, S>,
    ) {
        for span in self.0.lock().unwrap().iter_mut() {
            if &span.id == id {
                let mut fields = Fields::default();
                values.record(&mut fields);
                span.fields.extend(fields.0);
            }
        }
    }

    fn on_close(&self, id: tracing::Id, _: LayerContext<'_, S>) {
        for span in self.0.lock().unwrap().iter_mut() {
            if span.id == id {
                span.closed = true;
            }
        }
    }
}

#[derive(Debug)]
struct RetryingConnector {
    inner: ReverseTestConnector,
    attempts: Arc<AtomicUsize>,
    accepted: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl BoundaryTransportConnector for RetryingConnector {
    async fn connect(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) < 2 {
            return Err(BackendError::Unavailable(
                "boundary is starting".to_string(),
            ));
        }
        let stream = self.inner.connect(descriptor).await?;
        self.accepted.notify_one();
        Ok(stream)
    }
}

#[tokio::test]
async fn connection_span_exports_one_attempt_count_after_retries() {
    let _tracing_lock = tracing_test_lock().await;
    let collector = OtlpTestServer::start().await;
    let provider = openshell_otel::build_provider(&openshell_otel::OtlpExportConfig {
        endpoint: collector.endpoint(),
        service_name: openshell_otel::ServiceName::Fixed("openshell-supervisor"),
        service_version: None,
        resource_attributes: vec![],
    })
    .unwrap();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer(&provider, "openshell-supervisor"));

    let certificate = test_certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let descriptor = tls_runtime_descriptor(address, certificate.client_tls);
    let attempts = Arc::new(AtomicUsize::new(0));
    let transport = BoundaryTransport::connector(Arc::new(RetryingConnector {
        inner: ReverseTestConnector(listener),
        attempts: attempts.clone(),
        accepted: Arc::new(tokio::sync::Notify::new()),
    }));
    let runtime = async {
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(address)
            .await
            .unwrap();
        tokio_rustls::TlsAcceptor::from(certificate.server_config)
            .accept(stream)
            .await
            .unwrap()
    };
    let (connection, _runtime_stream) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            transport
                .connect(&descriptor, ATTACH_REQUEST_TIMEOUT)
                .with_subscriber(subscriber),
            runtime,
        )
    })
    .await
    .expect("boundary authenticates after two failed attempts");
    assert!(connection.is_ok());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);

    tokio::task::spawn_blocking(move || {
        provider.force_flush().unwrap();
        provider.shutdown().unwrap();
    })
    .await
    .unwrap();
    collector.wait_for_export().await;
    let received = collector.shutdown().await;
    let span = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.boundary.connect")
        .expect("collector receives the boundary connect span");
    let attempt_attributes: Vec<_> = span
        .attributes
        .iter()
        .filter(|attribute| attribute.key == "openshell.boundary.connect_attempts")
        .map(|attribute| &attribute.value)
        .collect();
    assert_eq!(
        attempt_attributes.len(),
        1,
        "expected one attempt count in OTLP, got {attempt_attributes:?}"
    );
}

#[tokio::test]
async fn connection_span_covers_authenticated_wait_and_cached_reuse() {
    let _tracing_lock = tracing_test_lock().await;
    for kind in [
        "dial",
        "backend",
        "routed",
        #[cfg(unix)]
        "runtime_initiated",
    ] {
        let certificate = test_certificate();
        let mut descriptor =
            tls_runtime_descriptor("127.0.0.1:1".parse().unwrap(), certificate.client_tls);
        let mut router = None;
        let attempts = Arc::new(AtomicUsize::new(0));
        let runtime: Pin<Box<dyn Future<Output = BoundaryDuplexStream> + Send>>;
        let transport = match kind {
            "dial" => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                descriptor.transport = SandboxTransport::Tcp {
                    authority: "sandbox.test".to_string(),
                    addresses: vec![listener.local_addr().unwrap()],
                };
                runtime = Box::pin(async move {
                    let stream: BoundaryDuplexStream = Box::new(listener.accept().await.unwrap().0);
                    stream
                });
                BoundaryTransport::default()
            }
            "backend" => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let accepted = Arc::new(tokio::sync::Notify::new());
                let runtime_accepted = accepted.clone();
                runtime = Box::pin(async move {
                    let stream: BoundaryDuplexStream = Box::new(
                        openshell_core::net::connect_tcp_nodelay_best_effort(address)
                            .await
                            .unwrap(),
                    );
                    runtime_accepted.notified().await;
                    stream
                });
                BoundaryTransport::connector(Arc::new(RetryingConnector {
                    inner: ReverseTestConnector(listener),
                    attempts: attempts.clone(),
                    accepted,
                }))
            }
            #[cfg(unix)]
            "runtime_initiated" => {
                let socket_path = PathBuf::from(format!("/tmp/ost-{}.sock", uuid::Uuid::new_v4()));
                descriptor.transport = SandboxTransport::RuntimeInitiatedUnix {
                    socket_path: socket_path.clone(),
                };
                let transport = BoundaryTransport::for_descriptor(&descriptor).unwrap();
                runtime = Box::pin(async move {
                    let stream: BoundaryDuplexStream =
                        Box::new(UnixStream::connect(socket_path).await.unwrap());
                    stream
                });
                transport
            }
            "routed" => {
                let listener =
                    crate::runtime_routed::RuntimeRouter::bind("127.0.0.1:0".parse().unwrap())
                        .unwrap();
                let address = listener.local_addr();
                let route = crate::runtime_routed::new_route_handle();
                descriptor.transport = SandboxTransport::RuntimeInitiatedRouted {
                    authority: "sandbox.test".to_string(),
                    route: route.clone(),
                };
                let registration = listener.register(&route, &descriptor.tls).unwrap();
                let transport = BoundaryTransport::routed(&descriptor, registration).unwrap();
                router = Some(listener);
                runtime = Box::pin(async move {
                    let mut stream = openshell_core::net::connect_tcp_nodelay_best_effort(address)
                        .await
                        .unwrap();
                    stream
                        .write_all(&crate::runtime_routed::encode_route_preface(&route).unwrap())
                        .await
                        .unwrap();
                    let stream: BoundaryDuplexStream = Box::new(stream);
                    stream
                });
                transport
            }
            _ => unreachable!(),
        };
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (authenticate_tx, authenticate_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = runtime.await;
            connected_tx.send(()).unwrap();
            authenticate_rx.await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                .accept(stream)
                .await
                .unwrap();
            serve_test_grpc(Box::new(stream), "a".repeat(32)).await;
        });
        let mut client = BoundaryClient::new(descriptor, test_bearer(&"a".repeat(32)));
        client.transport = transport;
        let spans = ConnectionSpans::default();
        let subscriber = tracing_subscriber::registry().with(spans.clone());
        let exercise = async {
            let discovery = tracing::info_span!("supervisor.boundary.discover_policy");
            let request = client.discover_policy().instrument(discovery.clone());
            tokio::pin!(request);
            tokio::select! {
                biased;
                result = &mut request => panic!("discovery finished before TLS: {result:?}"),
                result = connected_rx => result.unwrap(),
            }
            {
                let captured = spans.snapshot();
                assert_eq!(captured.len(), 1, "{kind}");
                assert_eq!(captured[0].parent, discovery.id(), "{kind}");
                assert!(!captured[0].closed, "TLS authentication is still pending");
                assert_eq!(
                    captured[0].fields,
                    BTreeMap::from([("openshell.boundary.transport", kind.to_string())])
                );
            }
            if kind == "backend" {
                assert_eq!(attempts.load(Ordering::SeqCst), 3);
            }
            authenticate_tx.send(()).unwrap();
            assert_eq!(request.await.unwrap(), (None, false));
            let captured = spans.snapshot();
            assert!(captured[0].closed);
            assert_eq!(captured[0].fields["otel.status_code"], "OK");
            assert_eq!(
                captured[0]
                    .fields
                    .get("openshell.boundary.connect_attempts")
                    .map(String::as_str),
                match kind {
                    "backend" => Some("3"),
                    "dial" => Some("1"),
                    _ => None,
                },
                "{kind}"
            );

            assert_eq!(client.discover_policy().await.unwrap(), (None, false));
            assert_eq!(spans.snapshot().len(), 1, "cached {kind} connection");
        }
        .with_subscriber(subscriber);
        tokio::time::timeout(Duration::from_secs(5), exercise)
            .await
            .expect("authenticated discovery completes after the handshake is released");
        server.abort();
        drop(client);
        drop(router);
    }
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn slow_discovery_exports_one_successful_connect_span() {
    let _tracing_lock = tracing_test_lock().await;
    for runtime_initiated in [false, true] {
        let certificate = test_certificate();
        let socket_path = PathBuf::from(format!("/tmp/ost-{}.sock", uuid::Uuid::new_v4()));
        let mut descriptor =
            tls_runtime_descriptor("127.0.0.1:1".parse().unwrap(), certificate.client_tls);
        descriptor.transport = if runtime_initiated {
            SandboxTransport::RuntimeInitiatedUnix {
                socket_path: socket_path.clone(),
            }
        } else {
            SandboxTransport::Unix {
                socket_path: socket_path.clone(),
            }
        };
        let mut client = BoundaryClient::new(descriptor.clone(), test_bearer(&"a".repeat(32)));
        client.transport = BoundaryTransport::for_descriptor(&descriptor).unwrap();
        let spans = ConnectionSpans::default();
        let subscriber = tracing_subscriber::registry().with(spans.clone());

        async {
            let discovery = tracing::info_span!("supervisor.boundary.discover_policy");
            let request = client.discover_policy().instrument(discovery.clone());
            tokio::pin!(request);
            for delay in [
                Duration::ZERO,
                CONNECT_RETRY_TIMEOUT + Duration::from_secs(1),
                Duration::from_millis(25),
                CONNECT_RETRY_TIMEOUT + Duration::from_secs(1),
                Duration::from_millis(25),
            ] {
                tokio::time::advance(delay).await;
                poll_fn(|context| {
                    assert!(request.as_mut().poll(context).is_pending());
                    Poll::Ready(())
                })
                .await;
            }

            // Drive real socket readiness and TLS without advancing the startup deadline.
            tokio::time::resume();
            let server = tokio::spawn(async move {
                let stream = if runtime_initiated {
                    UnixStream::connect(&socket_path).await.unwrap()
                } else {
                    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
                    let (stream, _) = listener.accept().await.unwrap();
                    std::fs::remove_file(&socket_path).unwrap();
                    stream
                };
                let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config)
                    .accept(stream)
                    .await
                    .unwrap();
                serve_test_grpc(Box::new(stream), "a".repeat(32)).await;
            });
            let result = tokio::time::timeout(Duration::from_secs(5), &mut request)
                .await
                .expect("discovery completes after the runtime starts");
            server.abort();
            assert_eq!(result.unwrap(), (None, false));
            tokio::time::pause();

            let captured = spans.snapshot();
            assert_eq!(captured.len(), 1, "{captured:?}");
            assert_eq!(captured[0].parent, discovery.id());
            assert!(captured[0].closed);
            assert_eq!(captured[0].fields["otel.status_code"], "OK");
        }
        .with_subscriber(subscriber)
        .await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn connection_span_closes_on_error_and_cancellation() {
    let _tracing_lock = tracing_test_lock().await;
    let certificate = test_certificate();
    let mut descriptor =
        tls_runtime_descriptor("127.0.0.1:1".parse().unwrap(), certificate.client_tls);
    descriptor.transport = SandboxTransport::RuntimeInitiatedUnix {
        socket_path: PathBuf::from(format!("/tmp/ost-{}.sock", uuid::Uuid::new_v4())),
    };
    let transport = BoundaryTransport::for_descriptor(&descriptor).unwrap();
    let spans = ConnectionSpans::default();
    let subscriber = tracing_subscriber::registry().with(spans.clone());
    async {
        let discovery = tracing::info_span!("supervisor.boundary.discover_policy");
        let mut waiting = Box::pin(
            transport
                .connect(&descriptor, ATTACH_REQUEST_TIMEOUT)
                .instrument(discovery.clone()),
        );
        poll_fn(|context| {
            assert!(waiting.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(spans.snapshot().len(), 1);
        assert!(!spans.snapshot()[0].closed);
        drop(waiting);
        assert!(spans.snapshot()[0].closed);

        let mut wrong_session = descriptor.clone();
        wrong_session.tls = test_certificate().client_tls;
        assert!(matches!(
            transport
                .connect(&wrong_session, ATTACH_REQUEST_TIMEOUT)
                .instrument(discovery.clone())
                .await,
            Err(BackendError::Descriptor(_))
        ));
        let captured = spans.snapshot();
        assert_eq!(captured.len(), 2);
        assert!(!captured[0].fields.contains_key("otel.status_code"));
        assert_eq!(captured[1].fields["otel.status_code"], "ERROR");
        for (index, span) in captured.iter().enumerate() {
            assert!(span.closed);
            assert_eq!(span.parent, discovery.id());
            assert_eq!(span.fields, {
                let mut expected = BTreeMap::from([(
                    "openshell.boundary.transport",
                    "runtime_initiated".to_string(),
                )]);
                if index == 1 {
                    expected.insert("otel.status_code", "ERROR".to_string());
                }
                expected
            });
        }
    }
    .with_subscriber(subscriber)
    .await;
}
