// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod common;

use bytes::Bytes;
use common::TestOpenShell;
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    HealthRequest, ServiceStatus, open_shell_client::OpenShellClient,
    open_shell_server::OpenShellServer,
};
use openshell_server::{MultiplexedService, Store, health_router};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn serves_grpc_and_http_on_same_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router(test_health_store().await);
    let service = MultiplexedService::new(grpc_service, http_service);

    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let mut client = OpenShellClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let response = client.health(HealthRequest {}).await.unwrap();
    assert_eq!(response.get_ref().status, ServiceStatus::Healthy as i32);

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}/healthz"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.abort();
}

/// Verify tonic metadata ↔ HTTP header roundtrip for `x-request-id`.
///
/// This intentionally constructs its own request-ID layers from
/// `tower-http`'s public API rather than reusing the production macro
/// (which is crate-private). Production middleware composition and
/// layer ordering are covered by the unit tests in `multiplex::tests`.
#[tokio::test]
async fn grpc_response_propagates_request_id() {
    use tower::ServiceBuilder;
    use tower_http::request_id::{
        MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
    };

    #[derive(Clone)]
    struct TestUuidRequestId;

    impl MakeRequestId for TestUuidRequestId {
        fn make_request_id<B>(&mut self, _req: &Request<B>) -> Option<RequestId> {
            let id = uuid::Uuid::new_v4().to_string();
            Some(RequestId::new(http::HeaderValue::from_str(&id).unwrap()))
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let x_request_id = http::HeaderName::from_static("x-request-id");
    let grpc_service = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(
            x_request_id.clone(),
            TestUuidRequestId,
        ))
        .layer(PropagateRequestIdLayer::new(x_request_id))
        .service(OpenShellServer::new(TestOpenShell));
    let http_service = health_router(test_health_store().await);
    let service = MultiplexedService::new(grpc_service, http_service);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let mut client = OpenShellClient::connect(format!("http://{addr}"))
        .await
        .unwrap();

    // Server generates a UUID when client omits x-request-id.
    let response = client.health(HealthRequest {}).await.unwrap();
    let generated = response
        .metadata()
        .get("x-request-id")
        .expect("gRPC response should include server-generated x-request-id");
    uuid::Uuid::parse_str(generated.to_str().unwrap()).expect("should be a valid UUID");

    // Server preserves a client-supplied x-request-id.
    let mut request = tonic::Request::new(HealthRequest {});
    request
        .metadata_mut()
        .insert("x-request-id", "grpc-corr-id".parse().unwrap());
    let response = client.health(request).await.unwrap();
    let echoed = response.metadata().get("x-request-id").unwrap();
    assert_eq!(echoed.to_str().unwrap(), "grpc-corr-id");
}

/// Build an in-memory store sufficient for wiring `health_router` in tests
/// where the persistence layer itself is not under test.
async fn test_health_store() -> Arc<Store> {
    Arc::new(
        Store::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite store for tests"),
    )
}
