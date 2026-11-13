// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Correlation contracts for the production single-config relay dispatch.

use super::L7EvalContext;
use crate::l7::L7EndpointConfig;
use crate::opa::{NetworkInput, OpaEngine, TunnelPolicyEngine};
use crate::test_support::request_tracing::RequestTracing;
use opentelemetry_sdk::trace::{Sampler, SpanData};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");

pub struct TracedOperation<T> {
    pub(crate) output: T,
    pub(crate) events: Vec<serde_json::Value>,
    pub(crate) spans: Vec<SpanData>,
    created: Vec<&'static str>,
}

impl<T> TracedOperation<T> {
    pub(crate) fn assert_no_deny_span(&self, sampled: bool) {
        assert!(!self.created.contains(&"supervisor.egress.deny"));
        assert_eq!(
            self.created
                .iter()
                .filter(|name| **name == "openshell.http.request")
                .count(),
            1
        );
        let roots: Vec<_> = self
            .spans
            .iter()
            .filter(|span| span.name == "openshell.http.request")
            .collect();
        assert_eq!(roots.len(), usize::from(sampled));
        if let Some(root) = roots.first() {
            let root_id = root.span_context.span_id();
            assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
            let by_id = self
                .spans
                .iter()
                .map(|span| (span.span_context.span_id(), span))
                .collect::<std::collections::HashMap<_, _>>();
            for span in &self.spans {
                assert_eq!(span.span_context.trace_id(), root.span_context.trace_id());
                if span.span_context.span_id() == root_id {
                    continue;
                }
                let mut parent = span.parent_span_id;
                for _ in 0..self.spans.len() {
                    if parent == root_id {
                        break;
                    }
                    parent = by_id
                        .get(&parent)
                        .expect("span parent is captured")
                        .parent_span_id;
                }
                assert_eq!(
                    parent, root_id,
                    "span parent graph reaches the request root"
                );
                if matches!(
                    span.name.as_ref(),
                    "openshell.policy.evaluate"
                        | "openshell.middleware.request"
                        | "openshell.middleware.websocket.preflight"
                        | "openshell.credential.prepare"
                        | "openshell.upstream.resolve"
                        | "openshell.upstream.connect"
                        | "openshell.upstream.send"
                        | "openshell.http.response"
                        | "openshell.middleware.response"
                ) {
                    assert_eq!(span.parent_span_id, root_id, "request stage parent");
                }
            }
            for event in self
                .events
                .iter()
                .filter(|event| event["class_uid"] == 4002)
            {
                assert_eq!(
                    event["trace"]["uid"],
                    root.span_context.trace_id().to_string()
                );
            }
        } else {
            assert!(self.spans.is_empty());
            assert!(self.events.iter().all(|event| event.get("trace").is_none()));
        }
    }
}

pub async fn capture_request_spans<T>(
    sampled: bool,
    operation: impl Future<Output = T>,
) -> TracedOperation<T> {
    capture_request(
        Some(if sampled {
            Sampler::AlwaysOn
        } else {
            Sampler::AlwaysOff
        }),
        operation,
    )
    .await
}

async fn capture_request<T>(
    sampler: Option<Sampler>,
    operation: impl Future<Output = T>,
) -> TracedOperation<T> {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let capture = RequestTracing::new(sampler);
    let output = Box::pin(operation.with_subscriber(capture.subscriber())).await;
    let spans = capture.spans();
    capture.shutdown();
    TracedOperation {
        output,
        events: capture.events.json_events(),
        spans,
        created: capture.created_span_names(),
    }
}

#[tokio::test]
async fn request_trace_capture_accepts_rpc_grandchildren() {
    let evidence = capture_request_spans(true, async {
        let request = tracing::info_span!(parent: None, "openshell.http.request");
        request.in_scope(|| {
            tracing::info_span!("openshell.middleware.request").in_scope(|| {
                tracing::info_span!("middleware.rpc").in_scope(|| {});
            });
        });
    })
    .await;
    assert_eq!(evidence.spans.len(), 3);
    evidence.assert_no_deny_span(true);
}

struct Fixture {
    config: L7EndpointConfig,
    tunnel_engine: TunnelPolicyEngine,
    middleware_engine: OpaEngine,
    ctx: L7EvalContext,
}

struct Exchange {
    response: Vec<u8>,
    forwarded: Vec<u8>,
}

fn fixture(data: &str, host: &str, policy_name: &str) -> Fixture {
    let middleware_engine = OpaEngine::from_strings(POLICY, data).expect("valid test policy");
    let input = NetworkInput {
        host: host.into(),
        port: 8000,
        binary_path: PathBuf::from("/usr/bin/python3"),
        binary_sha256: "unused".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (endpoint_config, generation) = middleware_engine
        .query_endpoint_config_with_generation(&input)
        .expect("query endpoint config");
    let config = crate::l7::parse_l7_config(
        &endpoint_config.expect("single configured endpoint should match"),
    )
    .expect("parse endpoint config");
    let tunnel_engine = middleware_engine
        .clone_engine_for_tunnel(generation)
        .expect("pin test policy generation");
    let ctx = L7EvalContext {
        host: host.into(),
        port: 8000,
        request_default_port: Some(8000),
        policy_name: policy_name.into(),
        binary_path: "/usr/bin/python3".into(),
        ..Default::default()
    };
    Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    }
}

async fn read_http_message<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut message = Vec::new();
    let mut byte = [0_u8; 1];
    while !message.ends_with(b"\r\n\r\n") {
        reader
            .read_exact(&mut byte)
            .await
            .expect("complete HTTP headers");
        message.push(byte[0]);
    }
    let headers = std::str::from_utf8(&message).expect("ASCII test headers");
    let body_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("numeric content length")
            })
        })
        .unwrap_or_default();
    let header_len = message.len();
    message.resize(header_len + body_len, 0);
    reader
        .read_exact(&mut message[header_len..])
        .await
        .expect("complete HTTP body");
    message
}

fn request_id(response: &[u8]) -> &str {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete response headers");
    std::str::from_utf8(&response[..headers_end])
        .expect("ASCII response headers")
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-openshell-request-id")
                .then(|| value.trim())
        })
        .expect("response carries a request receipt")
}

async fn run_allowed(
    fixture: Fixture,
    request: Vec<u8>,
    upstream_response: &'static [u8],
) -> TracedOperation<Exchange> {
    capture_request(
        None,
        Box::pin(run_exchange(fixture, request, Some(upstream_response))),
    )
    .await
}

async fn run_denied(fixture: Fixture, request: Vec<u8>) -> TracedOperation<Exchange> {
    capture_request(None, Box::pin(run_exchange(fixture, request, None))).await
}

async fn run_exchange(
    fixture: Fixture,
    request: Vec<u8>,
    upstream_response: Option<&'static [u8]>,
) -> Exchange {
    let (mut app, mut relay_client) = tokio::io::duplex(32 * 1024);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(32 * 1024);
    let Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    } = fixture;

    let exchange = async {
        tracing::callsite::rebuild_interest_cache();
        tokio::join!(
            async {
                let result = crate::proxy::relay_inspected_http_stream_for_test(
                    &mut relay_client,
                    &mut relay_upstream,
                    vec![config],
                    tunnel_engine,
                    &middleware_engine,
                    &ctx,
                )
                .await;
                drop(relay_upstream);
                result
            },
            async {
                app.write_all(&request).await.expect("send request");
                app.flush().await.expect("flush request");
                read_http_message(&mut app).await
            },
            async {
                if let Some(response) = upstream_response {
                    let forwarded = read_http_message(&mut upstream).await;
                    upstream
                        .write_all(response)
                        .await
                        .expect("send upstream response");
                    upstream.flush().await.expect("flush upstream response");
                    forwarded
                } else {
                    let mut forwarded = Vec::new();
                    upstream
                        .read_to_end(&mut forwarded)
                        .await
                        .expect("relay closes upstream");
                    forwarded
                }
            },
        )
    };
    let (relay, response, forwarded) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("single-config relay exchange completes");
    relay.expect("relay succeeds");
    Exchange {
        response,
        forwarded,
    }
}

fn assert_primary_record<'a>(
    exchange: &'a TracedOperation<Exchange>,
    engine_type: &str,
    status: u16,
    action: &str,
    path: &str,
) -> &'a serde_json::Value {
    let receipt = request_id(&exchange.output.response);
    assert!(
        uuid::Uuid::parse_str(receipt).is_ok(),
        "canonical receipt: {receipt}"
    );
    let primary: Vec<_> = exchange
        .events
        .iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect();
    assert_eq!(primary.len(), 1, "one HTTP Activity: {:?}", exchange.events);
    let event = primary[0];
    assert_eq!(event["metadata"]["correlation_uid"], receipt);
    assert_eq!(event["firewall_rule"]["type"], engine_type);
    assert_eq!(event["http_response"]["code"], status);
    assert_eq!(event["action"], action);
    assert_eq!(event["http_request"]["url"]["path"], path);
    assert!(
        event.get("trace").is_none(),
        "receipts must work without tracing"
    );
    event
}

fn mcp_fixture() -> Fixture {
    fixture(
        r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: ["2025-11-25"]
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
"#,
        "mcp.example.test",
        "mcp_api",
    )
}

fn request(host: &str, path: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:8000\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
    .into_bytes()
}

struct BlockingRequestMiddleware;

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for BlockingRequestMiddleware {
    async fn describe(&self) -> openshell_core::proto::MiddlewareManifest {
        use openshell_core::proto::{
            MiddlewareBinding, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
        };
        openshell_core::proto::MiddlewareManifest {
            name: "test/block-request".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-block-request",
                "test",
                [],
            )),
            ..Default::default()
        }
    }

    async fn validate_config(&self, _: &str, _: &prost_types::Struct) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<openshell_core::proto::HttpRequestResult> {
        Ok(openshell_core::proto::HttpRequestResult {
            decision: openshell_core::proto::Decision::Deny as i32,
            reason_code: "test_block".into(),
            ..Default::default()
        })
    }
}

fn rest_fixture(block_middleware: bool) -> Fixture {
    let middleware = if block_middleware {
        "network_middlewares:\n  request:\n    middleware: test/block-request\n    on_error: fail_closed\n    endpoints:\n      include: [rest.example.test]\n"
    } else {
        ""
    };
    let fixture = fixture(
        &format!(
            r"{middleware}
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: rest.example.test
        port: 8000
        path: /item
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {{ method: POST, path: /item }}
    binaries:
      - {{ path: /usr/bin/python3 }}
"
        ),
        "rest.example.test",
        "rest_api",
    );
    if block_middleware {
        fixture.middleware_engine.set_middleware_runner_for_tests(
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingRequestMiddleware)),
        );
    }
    fixture
}

#[tokio::test]
async fn inspected_allow_creates_only_the_stages_that_run() {
    for sampled in [true, false] {
        let evidence = capture_request_spans(
            sampled,
            Box::pin(run_exchange(
                rest_fixture(false),
                request("rest.example.test", "/item", "", "{}"),
                Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            )),
        )
        .await;
        evidence.assert_no_deny_span(sampled);
        assert!(
            evidence
                .output
                .forwarded
                .starts_with(b"POST /item HTTP/1.1\r\n")
        );
        if sampled {
            let names: Vec<_> = evidence
                .spans
                .iter()
                .map(|span| span.name.as_ref())
                .collect();
            assert!(names.contains(&"openshell.policy.evaluate"), "{names:?}");
            assert!(names.contains(&"openshell.upstream.send"), "{names:?}");
            assert!(names.contains(&"openshell.http.response"), "{names:?}");
            assert!(
                !names.contains(&"openshell.middleware.request"),
                "{names:?}"
            );
            assert!(
                !names.contains(&"openshell.middleware.response"),
                "{names:?}"
            );
            assert!(
                !names.contains(&"openshell.credential.prepare"),
                "{names:?}"
            );
        }
        let records: Vec<_> = evidence
            .events
            .iter()
            .filter(|event| event["class_uid"] == 4002)
            .collect();
        assert_eq!(records.len(), 1, "{:?}", evidence.events);
        assert_eq!(records[0]["unmapped"]["http_event_kind"], "request");
        assert_eq!(
            records[0]["metadata"]["correlation_uid"],
            request_id(&evidence.output.response)
        );
        assert_eq!(records[0]["action"], "Allowed");
    }
}

#[tokio::test]
async fn request_middleware_block_never_creates_a_denial_only_span() {
    for sampled in [true, false] {
        let evidence = capture_request_spans(
            sampled,
            Box::pin(run_exchange(
                rest_fixture(true),
                request("rest.example.test", "/item", "", "{}"),
                None,
            )),
        )
        .await;
        evidence.assert_no_deny_span(sampled);
        assert!(evidence.output.forwarded.is_empty());
        assert!(
            evidence
                .output
                .response
                .starts_with(b"HTTP/1.1 403 Forbidden\r\n")
        );
        if sampled {
            assert_eq!(
                evidence
                    .spans
                    .iter()
                    .filter(|span| span.name == "openshell.middleware.request")
                    .count(),
                1
            );
            assert!(
                evidence
                    .spans
                    .iter()
                    .all(|span| span.name != "openshell.upstream.send")
            );
        }
        let records: Vec<_> = evidence
            .events
            .iter()
            .filter(|event| event["class_uid"] == 4002)
            .collect();
        assert_eq!(records.len(), 2, "{:?}", evidence.events);
        let companions: Vec<_> = records
            .iter()
            .filter(|event| event["unmapped"]["http_event_kind"] == "middleware_invocation")
            .collect();
        assert_eq!(companions.len(), 1);
        assert_eq!(companions[0]["unmapped"]["middleware_phase"], "request");
        assert_eq!(companions[0]["action"], "Denied");
        assert!(companions[0].get("http_response").is_none());
        let records: Vec<_> = records
            .into_iter()
            .filter(|event| event["unmapped"]["http_event_kind"] == "request")
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["metadata"]["correlation_uid"],
            request_id(&evidence.output.response)
        );
        assert_eq!(records[0]["action"], "Denied");
        assert_eq!(records[0]["http_response"]["code"], 403);
    }
}

#[tokio::test]
async fn inspected_keep_alive_requests_have_distinct_receipts_without_tracing() {
    let Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    } = fixture(
        r"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: rest.example.test
        port: 8000
        path: /item
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: /item }
    binaries:
      - { path: /usr/bin/python3 }
",
        "rest.example.test",
        "rest_api",
    );
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let (mut app, mut relay_client) = tokio::io::duplex(8192);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
    let exchange = async {
        tokio::join!(
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                let mut responses = Vec::new();
                for (sampled, connection) in [("01", "keep-alive"), ("00", "close")] {
                    let request = format!(
                        "GET /item HTTP/1.1\r\nHost: rest.example.test:8000\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{sampled}\r\nConnection: {connection}\r\n\r\n",
                    );
                    app.write_all(request.as_bytes()).await.expect("send request");
                    app.flush().await.expect("flush request");
                    responses.push(read_http_message(&mut app).await);
                }
                responses
            },
            async {
                for connection in ["keep-alive", "close"] {
                    let request = read_http_message(&mut upstream).await;
                    assert!(request.starts_with(b"GET /item HTTP/1.1\r\n"));
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: {connection}\r\n\r\n");
                    upstream.write_all(response.as_bytes()).await.expect("upstream response");
                    upstream.flush().await.expect("flush response");
                }
            },
        )
    }.with_subscriber(subscriber);
    let (relay, responses, ()) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("two inspected requests complete");
    relay.expect("inspected relay");
    let receipts: Vec<_> = responses
        .iter()
        .map(|response| request_id(response))
        .collect();
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0], receipts[1]);
    let records: Vec<_> = capture
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect();
    assert_eq!(
        records.len(),
        2,
        "one primary per inspected request: {records:?}"
    );
    for (record, receipt) in records.iter().zip(receipts) {
        assert!(uuid::Uuid::parse_str(receipt).is_ok());
        assert_eq!(record["metadata"]["correlation_uid"], receipt);
        assert_eq!(record["action"], "Allowed");
        assert_eq!(record["http_response"]["code"], 200);
        assert_eq!(record["http_request"]["url"]["path"], "/item");
        assert!(record.get("trace").is_none());
        assert!(
            !record
                .to_string()
                .contains("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }
}

#[tokio::test]
async fn production_single_mcp_allow_correlates_record_and_response_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let exchange = Box::pin(run_allowed(
        mcp_fixture(),
        request("mcp.example.test", "/mcp", "", body),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ))
    .await;

    assert!(
        exchange
            .output
            .forwarded
            .starts_with(b"POST /mcp HTTP/1.1\r\n")
    );
    assert!(exchange.output.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_primary_record(&exchange, "l7-mcp", 200, "Allowed", "/mcp");
}

#[tokio::test]
async fn production_single_mcp_invalid_version_correlates_denial_and_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let exchange = Box::pin(run_denied(
        mcp_fixture(),
        request(
            "mcp.example.test",
            "/mcp",
            "MCP-Protocol-Version: 1900-01-01\r\n",
            body,
        ),
    ))
    .await;

    assert!(exchange.output.forwarded.is_empty());
    assert!(
        exchange
            .output
            .response
            .starts_with(b"HTTP/1.1 400 Bad Request\r\n")
    );
    assert!(
        String::from_utf8_lossy(&exchange.output.response)
            .contains("unsupported_mcp_protocol_version")
    );
    assert_primary_record(&exchange, "l7-mcp", 400, "Denied", "/mcp");
}

#[tokio::test]
async fn production_single_mcp_policy_deny_correlates_record_and_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let exchange = Box::pin(run_denied(
        mcp_fixture(),
        request(
            "mcp.example.test",
            "/mcp",
            "MCP-Protocol-Version: 2025-11-25\r\n",
            body,
        ),
    ))
    .await;

    assert!(exchange.output.forwarded.is_empty());
    assert!(
        exchange
            .output
            .response
            .starts_with(b"HTTP/1.1 403 Forbidden\r\n")
    );
    let event = assert_primary_record(&exchange, "l7-mcp", 403, "Denied", "/mcp");
    assert!(
        event["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("JSONRPC_L7_REQUEST decision=deny"))
    );
}

#[tokio::test]
async fn production_single_graphql_allow_correlates_record_and_response_receipt() {
    let graphql = fixture(
        r"
network_policies:
  graphql_api:
    name: graphql_api
    endpoints:
      - host: graphql.example.test
        port: 8000
        path: /graphql
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/python3 }
",
        "graphql.example.test",
        "graphql_api",
    );
    let body = r#"{"query":"query { viewer }"}"#;
    let exchange = Box::pin(run_allowed(
        graphql,
        request("graphql.example.test", "/graphql", "", body),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{\"data\":{\"viewer\":{}}}",
    ))
    .await;

    assert!(
        exchange
            .output
            .forwarded
            .starts_with(b"POST /graphql HTTP/1.1\r\n")
    );
    assert!(exchange.output.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_primary_record(&exchange, "l7-graphql", 200, "Allowed", "/graphql");
}
