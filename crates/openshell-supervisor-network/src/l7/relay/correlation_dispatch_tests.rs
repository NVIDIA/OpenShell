// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Correlation contracts for the production single-config relay dispatch.

use super::L7EvalContext;
use crate::l7::L7EndpointConfig;
use crate::opa::{NetworkInput, OpaEngine, TunnelPolicyEngine};
use opentelemetry_sdk::trace::{InMemorySpanExporter, InMemorySpanExporterBuilder};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");

struct Fixture {
    config: L7EndpointConfig,
    tunnel_engine: TunnelPolicyEngine,
    middleware_engine: OpaEngine,
    ctx: L7EvalContext,
}

struct Exchange {
    response: Vec<u8>,
    forwarded: Vec<u8>,
    span_attributes: BTreeMap<String, String>,
    ocsf_events: Vec<serde_json::Value>,
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

fn enforcement_span_attributes(exporter: &InMemorySpanExporter) -> BTreeMap<String, String> {
    exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.http.request")
        .expect("HTTP enforcement span")
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect()
}

async fn run_allowed(
    fixture: Fixture,
    request: Vec<u8>,
    upstream_response: &'static [u8],
) -> Exchange {
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "single-config-correlation-test",
    ));
    let subscriber = subscriber.with(ocsf.clone());
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
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                app.write_all(&request).await.expect("send request");
                app.flush().await.expect("flush request");
                read_http_message(&mut app).await
            },
            async {
                let forwarded = read_http_message(&mut upstream).await;
                upstream
                    .write_all(upstream_response)
                    .await
                    .expect("send upstream response");
                upstream.flush().await.expect("flush upstream response");
                forwarded
            },
        )
    }
    .with_subscriber(subscriber);
    let (relay, response, forwarded) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("single-config relay exchange completes");
    relay.expect("relay succeeds");
    provider.force_flush().expect("flush spans");
    Exchange {
        response,
        forwarded,
        span_attributes: enforcement_span_attributes(&exporter),
        ocsf_events: ocsf.json_events(),
    }
}

async fn run_denied(fixture: Fixture, request: Vec<u8>) -> Exchange {
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "single-config-correlation-test",
    ));
    let subscriber = subscriber.with(ocsf.clone());
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
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                app.write_all(&request).await.expect("send request");
                app.flush().await.expect("flush request");
                read_http_message(&mut app).await
            },
            async {
                let mut forwarded = Vec::new();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    upstream.read_to_end(&mut forwarded),
                )
                .await;
                forwarded
            },
        )
    }
    .with_subscriber(subscriber);
    let (relay, response, forwarded) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("single-config denial completes");
    relay.expect("relay succeeds");
    provider.force_flush().expect("flush spans");
    Exchange {
        response,
        forwarded,
        span_attributes: enforcement_span_attributes(&exporter),
        ocsf_events: ocsf.json_events(),
    }
}

fn assert_receipt_matches_span(exchange: &Exchange) {
    let receipt = request_id(&exchange.response);
    assert!(
        uuid::Uuid::parse_str(receipt).is_ok(),
        "canonical receipt: {receipt}"
    );
    assert_eq!(exchange.span_attributes["openshell.request.id"], receipt);
}

fn assert_policy_event_matches_receipt(exchange: &Exchange, engine_type: &str) {
    let receipt = request_id(&exchange.response);
    let event = exchange
        .ocsf_events
        .iter()
        .find(|event| event["firewall_rule"]["type"] == engine_type)
        .unwrap_or_else(|| {
            panic!(
                "missing {engine_type} policy event: {:?}",
                exchange.ocsf_events
            )
        });
    assert_eq!(event["metadata"]["correlation_uid"], receipt);
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

#[tokio::test]
async fn production_single_mcp_allow_correlates_span_and_response_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let exchange = Box::pin(run_allowed(
        mcp_fixture(),
        request("mcp.example.test", "/mcp", "", body),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ))
    .await;

    assert!(exchange.forwarded.starts_with(b"POST /mcp HTTP/1.1\r\n"));
    assert!(exchange.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_receipt_matches_span(&exchange);
    assert_policy_event_matches_receipt(&exchange, "l7-mcp");
    assert_eq!(
        exchange.span_attributes["openshell.policy.decision"],
        "allow"
    );
    assert_eq!(
        exchange.span_attributes["openshell.enforcement.action"],
        "allow"
    );
    assert_eq!(
        exchange.span_attributes["openshell.http.outcome"],
        "allowed"
    );
    assert_eq!(exchange.span_attributes["http.response.status_code"], "200");
    assert_eq!(exchange.span_attributes["openshell.target.reached"], "true");
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

    assert!(exchange.forwarded.is_empty());
    assert!(
        exchange
            .response
            .starts_with(b"HTTP/1.1 400 Bad Request\r\n")
    );
    assert!(
        String::from_utf8_lossy(&exchange.response).contains("unsupported_mcp_protocol_version")
    );
    assert_receipt_matches_span(&exchange);
    assert_policy_event_matches_receipt(&exchange, "l7-mcp");
    assert_eq!(
        exchange.span_attributes["openshell.policy.decision"],
        "deny"
    );
    assert_eq!(
        exchange.span_attributes["openshell.enforcement.action"],
        "block"
    );
    assert_eq!(exchange.span_attributes["openshell.http.outcome"], "denied");
    assert_eq!(exchange.span_attributes["http.response.status_code"], "400");
    assert!(
        !exchange
            .span_attributes
            .contains_key("openshell.error.stage")
    );
    assert_eq!(
        exchange.span_attributes["openshell.target.reached"],
        "false"
    );
}

#[tokio::test]
async fn production_single_mcp_policy_deny_correlates_span_event_and_receipt() {
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

    assert!(exchange.forwarded.is_empty());
    assert!(exchange.response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert_receipt_matches_span(&exchange);
    assert_policy_event_matches_receipt(&exchange, "l7-mcp");
    assert!(exchange.ocsf_events.iter().any(|event| {
        event["firewall_rule"]["type"] == "l7-mcp"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("JSONRPC_L7_REQUEST decision=deny"))
    }));
    assert_eq!(
        exchange.span_attributes["openshell.policy.decision"],
        "deny"
    );
    assert_eq!(
        exchange.span_attributes["openshell.enforcement.action"],
        "block"
    );
    assert_eq!(exchange.span_attributes["openshell.http.outcome"], "denied");
    assert_eq!(exchange.span_attributes["http.response.status_code"], "403");
    assert_eq!(
        exchange.span_attributes["openshell.target.reached"],
        "false"
    );
}

#[tokio::test]
async fn production_single_graphql_allow_correlates_span_and_response_receipt() {
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
            .forwarded
            .starts_with(b"POST /graphql HTTP/1.1\r\n")
    );
    assert!(exchange.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_receipt_matches_span(&exchange);
    assert_policy_event_matches_receipt(&exchange, "l7-graphql");
    assert_eq!(
        exchange.span_attributes["openshell.policy.decision"],
        "allow"
    );
    assert_eq!(
        exchange.span_attributes["openshell.enforcement.action"],
        "allow"
    );
    assert_eq!(
        exchange.span_attributes["openshell.http.outcome"],
        "allowed"
    );
    assert_eq!(exchange.span_attributes["http.response.status_code"], "200");
    assert_eq!(exchange.span_attributes["openshell.target.reached"], "true");
}
