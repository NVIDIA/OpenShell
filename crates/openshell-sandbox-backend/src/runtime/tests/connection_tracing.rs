// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::BTreeMap;
use std::future::Future;
#[cfg(unix)]
use std::future::poll_fn;
use std::sync::Mutex;
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
        if span.name() != "boundary.connect" {
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

    fn on_close(&self, id: tracing::Id, _: LayerContext<'_, S>) {
        for span in self.0.lock().unwrap().iter_mut() {
            if span.id == id {
                span.closed = true;
            }
        }
    }
}

#[tokio::test]
async fn connection_span_covers_authenticated_wait_and_cached_reuse() {
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
                runtime = Box::pin(async move {
                    let stream: BoundaryDuplexStream =
                        Box::new(tokio::net::TcpStream::connect(address).await.unwrap());
                    stream
                });
                BoundaryTransport::connector(Arc::new(ReverseTestConnector(listener)))
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
                    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
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
                    BTreeMap::from([("transport", kind.to_string())])
                );
            }
            authenticate_tx.send(()).unwrap();
            assert_eq!(request.await.unwrap(), (None, false));
            assert!(spans.snapshot()[0].closed);

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
#[tokio::test]
async fn connection_span_closes_on_error_and_cancellation() {
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
        let mut waiting = Box::pin(transport.connect(&descriptor).instrument(discovery.clone()));
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
                .connect(&wrong_session)
                .instrument(discovery.clone())
                .await,
            Err(BackendError::Descriptor(_))
        ));
        let captured = spans.snapshot();
        assert_eq!(captured.len(), 2);
        for span in &captured {
            assert!(span.closed);
            assert_eq!(span.parent, discovery.id());
            assert_eq!(
                span.fields,
                BTreeMap::from([("transport", "runtime_initiated".to_string())])
            );
        }
    }
    .with_subscriber(subscriber)
    .await;
}
