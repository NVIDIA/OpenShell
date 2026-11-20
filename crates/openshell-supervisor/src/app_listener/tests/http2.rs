// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioExecutor;
use tonic::codegen::{BoxFuture, BoxStream};

async fn http2_client(f: &Fixture) -> hyper::client::conn::http2::SendRequest<Body> {
    let stream = openshell_core::net::connect_tcp_nodelay_best_effort(f.address)
        .await
        .unwrap();
    let mut config = (*f.tls).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from(HOST).unwrap(),
            stream,
        )
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    sender
}

#[tokio::test]
async fn http2_frontend_preserves_http1_routes_and_checks_authority_before_dialing() {
    let f = fixture();
    let mut client = http2_client(&f).await;
    let request = |host: &str| {
        Request::get(format!("https://{host}/hello?x=1"))
            .header(header::AUTHORIZATION, "Bearer app-token")
            .body(Body::empty())
            .unwrap()
    };
    let mismatch = client
        .send_request(request("default--sandbox-b--web.svc.openshell.internal"))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(f.connector.calls.load(Ordering::SeqCst), 0);

    let response = client.send_request(request(HOST)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        format!("/hello?x=1 {HOST} stripped absent")
    );
    assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);

    f.routes.install(&installed(vec![SandboxServiceRoute {
        backend_http_version: 2,
        ..f.route.clone()
    }]));
    let response = http2_client(&f)
        .await
        .send_request(request(HOST))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(f.connector.calls.load(Ordering::SeqCst), 2);
}

#[derive(Clone, PartialEq, prost::Message)]
struct Message {
    #[prost(string, tag = "1")]
    text: String,
}

struct Echo(Arc<tokio::sync::Notify>);

struct NotifyOnDrop(Arc<tokio::sync::Notify>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

impl tonic::server::StreamingService<Message> for Echo {
    type Response = Message;
    type ResponseStream = BoxStream<Message>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<tonic::Streaming<Message>>) -> Self::Future {
        let probe = NotifyOnDrop(self.0.clone());
        Box::pin(async move {
            let output = request.into_inner().map(|message| {
                let message = message?;
                if message.text == "finish" {
                    return Err(tonic::Status::failed_precondition("echo finished"));
                }
                Ok(message)
            });
            // A half-close alone leaves the response open. Only a reset drops it.
            let output = output
                .chain(futures::stream::pending())
                .map(move |message| {
                    let _probe = &probe;
                    message
                });
            let output: Self::ResponseStream = Box::pin(output);
            Ok(tonic::Response::new(output))
        })
    }
}

struct GrpcBackend(Arc<tokio::sync::Notify>);

#[tonic::async_trait]
impl rpc_test::BoundaryLoopbackConnector for GrpcBackend {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        assert_eq!(target.port(), 50051);
        let (client, server) = tokio::io::duplex(8192);
        let cancelled = self.0.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                let cancelled = cancelled.clone();
                async move {
                    assert_eq!(request.version(), Version::HTTP_2);
                    assert_eq!(request.headers()[header::TE], "trailers");
                    assert_eq!(request.headers()["grpc-timeout"], "30000000u");
                    let response = tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .streaming(Echo(cancelled), request)
                        .await;
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        Ok(Box::new(client))
    }
}

#[tokio::test]
async fn native_grpc_streams_preserve_deadlines_status_and_per_stream_cancellation() {
    use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

    const GRPC_HOST: &str = "default--sandbox-b--web.svc.openshell.internal";
    let f = fixture();
    let instance = f.host.router().instance("sandbox-b").unwrap();
    let routes = instance.routes.clone();
    let cancelled = Arc::new(tokio::sync::Notify::new());
    let _handle = instance.start(rpc_test::loopback(Arc::new(GrpcBackend(cancelled.clone()))));
    routes.install(&installed(vec![SandboxServiceRoute {
        endpoint_id: "endpoint-b".into(),
        target_port: 50051,
        backend_http_version: 2,
        ..f.route.clone()
    }]));

    let ca = Certificate::from_pem(std::fs::read(f.directory.path().join("cert.pem")).unwrap());
    let channel = Endpoint::from_shared(format!("https://{}", f.address))
        .unwrap()
        .origin(format!("https://{GRPC_HOST}").parse().unwrap())
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(GRPC_HOST)
                .ca_certificate(ca),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    let mut calls = Vec::new();
    for _ in 0..2 {
        let (tx, rx) = mpsc::channel(1);
        tx.send(Message {
            text: "hello".into(),
        })
        .await
        .unwrap();
        let mut request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        request.set_timeout(Duration::from_secs(30));
        grpc.ready().await.unwrap();
        let mut response = grpc
            .streaming(
                request,
                http::uri::PathAndQuery::from_static("/test.Echo/Stream"),
                tonic_prost::ProstCodec::<Message, Message>::default(),
            )
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.message().await.unwrap().unwrap().text, "hello");
        calls.push((tx, response));
    }

    let (cancel_tx, cancel_response) = calls.pop().unwrap();
    drop(cancel_tx);
    drop(cancel_response);
    tokio::time::timeout(Duration::from_secs(3), cancelled.notified())
        .await
        .expect("the cancelled stream was released at the backend");
    let (tx, mut response) = calls.pop().unwrap();
    tx.send(Message {
        text: "finish".into(),
    })
    .await
    .unwrap();
    let status = response.message().await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), "echo finished");
}
