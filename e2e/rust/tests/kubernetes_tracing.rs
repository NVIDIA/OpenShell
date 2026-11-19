// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes trace export to a real collector.
//!
//! `e2e/with-kube-gateway.sh` deploys Jaeger when `OPENSHELL_E2E_KUBE_JAEGER=1`,
//! points the gateway's OTLP export at it, and exports the Jaeger query URL.
//! The test creates a sandbox and waits for Jaeger to report the gateway and
//! Kubernetes compute-driver spans for it.

#![cfg(feature = "e2e-kubernetes-tracing")]

use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;

const GATEWAY_SERVICE: &str = "openshell-gateway";
const DRIVER_SERVICE: &str = "openshell-driver-kubernetes";
const GATEWAY_REQUEST: &str = "openshell.v1.OpenShell/CreateSandbox";
const DRIVER_RPC: &str = "openshell.compute.v1.ComputeDriver/CreateSandbox";
const DRIVER_PROVISION: &str = "kubernetes.provision";
const EXPORT_TIMEOUT: Duration = Duration::from_secs(90);

fn query_url() -> url::Url {
    let base = std::env::var("OPENSHELL_E2E_JAEGER_QUERY_URL")
        .expect("OPENSHELL_E2E_JAEGER_QUERY_URL is set by e2e/with-kube-gateway.sh");
    url::Url::parse(&base).expect("OPENSHELL_E2E_JAEGER_QUERY_URL is a URL")
}

/// GET `url`, treating Jaeger's 404 for an empty search as no body.
#[allow(
    clippy::disallowed_methods,
    reason = "the e2e workspace does not depend on openshell-core"
)]
async fn get_json(url: &url::Url) -> Option<Value> {
    let host = url.host_str().expect("query URL host");
    let port = url.port_or_known_default().expect("query URL port");
    let stream = tokio::net::TcpStream::connect((host, port))
        .await
        .unwrap_or_else(|error| panic!("connect to Jaeger query at {url}: {error}"));
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("Jaeger query HTTP handshake");
    tokio::spawn(connection);

    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let request = hyper::Request::get(path)
        .header(hyper::header::HOST, format!("{host}:{port}"))
        .body(Empty::<Bytes>::new())
        .expect("Jaeger query request");
    let response = sender
        .send_request(request)
        .await
        .unwrap_or_else(|error| panic!("GET {url}: {error}"));
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("Jaeger query body")
        .to_bytes();
    if status == hyper::StatusCode::NOT_FOUND {
        return None;
    }
    assert!(
        status.is_success(),
        "GET {url} returned {status}: {}",
        String::from_utf8_lossy(&body)
    );
    Some(serde_json::from_slice(&body).expect("Jaeger query JSON"))
}

#[derive(Debug)]
struct Span {
    trace_id: String,
    service: String,
    name: String,
    resource: Value,
    attributes: Value,
    status: Value,
}

fn attribute<'a>(attributes: &'a Value, key: &str) -> Option<&'a str> {
    attributes
        .as_array()?
        .iter()
        .find(|attribute| attribute["key"] == key)?["value"]["stringValue"]
        .as_str()
}

/// Flatten an OTLP JSON `TracesData` result into spans.
fn spans(result: Option<Value>) -> Vec<Span> {
    let Some(result) = result else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    for resource_spans in result["result"]["resourceSpans"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let resource = &resource_spans["resource"]["attributes"];
        let service = attribute(resource, "service.name").unwrap_or_default();
        for scope_spans in resource_spans["scopeSpans"]
            .as_array()
            .into_iter()
            .flatten()
        {
            for span in scope_spans["spans"].as_array().into_iter().flatten() {
                spans.push(Span {
                    trace_id: span["traceId"].as_str().unwrap_or_default().to_string(),
                    service: service.to_string(),
                    name: span["name"].as_str().unwrap_or_default().to_string(),
                    resource: resource.clone(),
                    attributes: span["attributes"].clone(),
                    status: span["status"].clone(),
                });
            }
        }
    }
    spans
}

/// Spans of the traces Jaeger holds with a `service` span named `operation`.
async fn search(service: &str, operation: &str) -> Vec<Span> {
    let mut url = query_url();
    url.set_path("/api/v3/traces");
    url.query_pairs_mut()
        .append_pair("query.service_name", service)
        .append_pair("query.operation_name", operation)
        .append_pair("query.start_time_min", "1970-01-01T00:00:00Z")
        .append_pair("query.start_time_max", "2100-01-01T00:00:00Z");
    spans(get_json(&url).await)
}

async fn trace(trace_id: &str) -> Vec<Span> {
    let mut url = query_url();
    url.set_path(&format!("/api/v3/traces/{trace_id}"));
    spans(get_json(&url).await)
}

/// Poll until a `service` span named `operation` satisfies `matches`.
async fn wait_for_span(service: &str, operation: &str, matches: impl Fn(&Span) -> bool) -> Span {
    let deadline = Instant::now() + EXPORT_TIMEOUT;
    loop {
        if let Some(span) = search(service, operation)
            .await
            .into_iter()
            .find(|span| span.service == service && span.name == operation && matches(span))
        {
            return span;
        }
        if Instant::now() >= deadline {
            let mut services = query_url();
            services.set_path("/api/v3/services");
            panic!(
                "Jaeger received no matching {service} span {operation} within {EXPORT_TIMEOUT:?}; services seen: {:?}",
                get_json(&services).await
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Assert `span` succeeded and carries the resource of a Kubernetes gateway.
fn assert_exported(span: &Span) {
    let code = &span.status["code"];
    assert!(
        code != 2 && code != "STATUS_CODE_ERROR",
        "{} span {} has error status: {}",
        span.service,
        span.name,
        span.status
    );
    assert!(
        attribute(&span.resource, "service.version").is_some_and(|version| !version.is_empty()),
        "{} resource attributes lack service.version: {}",
        span.service,
        span.resource
    );
    assert_eq!(
        attribute(&span.resource, "openshell.gateway.compute_driver"),
        Some("kubernetes"),
        "{} resource attributes: {}",
        span.service,
        span.resource
    );
    assert!(
        attribute(&span.resource, "openshell.gateway.name").is_some_and(|name| !name.is_empty()),
        "{} resource attributes lack openshell.gateway.name: {}",
        span.service,
        span.resource
    );
}

#[tokio::test]
async fn gateway_and_driver_spans_reach_the_collector() {
    let mut sandbox = SandboxGuard::create(&["--", "true"])
        .await
        .expect("sandbox create should succeed");

    let provision = wait_for_span(DRIVER_SERVICE, DRIVER_PROVISION, |span| {
        attribute(&span.attributes, "sandbox.name") == Some(sandbox.name.as_str())
    })
    .await;
    assert_exported(&provision);

    let trace = trace(&provision.trace_id).await;
    let client = trace
        .iter()
        .find(|span| span.service == GATEWAY_SERVICE && span.name == DRIVER_RPC)
        .unwrap_or_else(|| {
            panic!(
                "provision trace lacks the gateway's {DRIVER_RPC} client span, so trace context did not reach the driver: {trace:#?}"
            )
        });
    assert_exported(client);

    let request = wait_for_span(GATEWAY_SERVICE, GATEWAY_REQUEST, |_| true).await;
    assert_exported(&request);

    sandbox.cleanup().await;
}
