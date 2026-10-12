// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes API client construction.
//!
//! `kube::Client::try_from` applies `read_timeout` through `hyper-timeout`,
//! whose read timer starts when a pooled connection goes idle and is only
//! reset by a completed read. A request reusing a connection that has been
//! idle for nearly `read_timeout` then gets only the remainder of that window
//! and fails with `ServiceError: client error (SendRequest)`. This module
//! builds the same client stack but restarts the read timer whenever a
//! request is written, so every request gets the full `read_timeout`.

use hyper_timeout::TimeoutConnector;
use hyper_util::client::legacy::{Builder as HyperClientBuilder, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use kube::client::{Body, ConfigExt};
use kube::{Client, Config};
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;

use crate::driver::KubernetesDriverError;

/// Build a Kubernetes API client whose read timeout measures each request
/// rather than the connection's idle time.
pub fn kubernetes_client(config: Config) -> Result<Client, KubernetesDriverError> {
    if let Some(proxy_url) = config.proxy_url.as_ref() {
        return Err(KubernetesDriverError::Precondition(format!(
            "Kubernetes API proxy {proxy_url} is not supported"
        )));
    }

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = config
        .rustls_https_connector_with_connector(http)
        .map_err(KubernetesDriverError::from_kube)?;

    let mut connector = TimeoutConnector::new(https);
    connector.set_connect_timeout(config.connect_timeout);
    connector.set_read_timeout(config.read_timeout);
    connector.set_write_timeout(config.write_timeout);
    connector.set_reset_reader_on_write(true);

    let auth_layer = config
        .auth_layer()
        .map_err(KubernetesDriverError::from_kube)?;
    let extra_headers_layer = config
        .extra_headers_layer()
        .map_err(KubernetesDriverError::from_kube)?;
    let hyper_client = HyperClientBuilder::new(TokioExecutor::new()).build::<_, Body>(connector);
    let service = ServiceBuilder::new()
        .layer(config.base_uri_layer())
        .option_layer(auth_layer)
        .layer(extra_headers_layer)
        .layer(TraceLayer::new_for_http())
        .map_err(BoxError::from)
        .service(hyper_client);

    Ok(Client::new(service, config.default_namespace))
}

#[cfg(test)]
mod tests {
    use super::kubernetes_client;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use k8s_openapi::api::core::v1::Pod;
    use kube::{Api, Config};
    use tokio::net::TcpListener;

    const POD: &str =
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod","namespace":"default"}}"#;

    /// Serve Pod GETs, delaying any request for a Pod named `slow-<millis>`.
    async fn serve_pods() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|request: Request<Incoming>| async move {
                                let delay = request
                                    .uri()
                                    .path()
                                    .rsplit_once("/slow-")
                                    .and_then(|(_, millis)| millis.parse().ok())
                                    .map_or(Duration::ZERO, Duration::from_millis);
                                tokio::time::sleep(delay).await;
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from_static(POD.as_bytes())))
                                        .unwrap(),
                                )
                            }),
                        )
                        .await;
                });
            }
        });
        (addr, connections)
    }

    fn pods(addr: SocketAddr, read_timeout: Duration) -> Api<Pod> {
        let mut config = Config::new(format!("http://{addr}").parse().unwrap());
        config.read_timeout = Some(read_timeout);
        Api::namespaced(kubernetes_client(config).unwrap(), "default")
    }

    #[tokio::test]
    async fn reused_idle_connection_gets_full_read_timeout() {
        let (addr, connections) = serve_pods().await;
        let pods = pods(addr, Duration::from_secs(1));

        pods.get("warm").await.unwrap();
        // Idle long enough that the remaining idle-time budget is shorter
        // than the next response's latency.
        tokio::time::sleep(Duration::from_millis(800)).await;
        pods.get("slow-500").await.unwrap();

        assert_eq!(connections.load(Ordering::SeqCst), 1, "connection reused");
    }

    #[tokio::test]
    async fn read_timeout_still_bounds_slow_responses() {
        let (addr, _) = serve_pods().await;
        let pods = pods(addr, Duration::from_millis(300));

        let error = pods.get("slow-1500").await.unwrap_err();

        assert!(
            matches!(error, kube::Error::Service(_)),
            "expected transport timeout, got {error:?}"
        );
    }
}
