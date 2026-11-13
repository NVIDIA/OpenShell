// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::request_tracing::RequestTracing;
use opentelemetry_sdk::trace::Sampler;
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

const WORKLOAD_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const WORKLOAD_SPAN_ID: &str = "00f067aa0ba902b7";

#[derive(Clone, Copy)]
enum Outcome {
    Allowed,
    PolicyDenied,
    AuditDenied,
    UpstreamClosed,
}

async fn forward_case(ip: Ipv4Addr, outcome: Outcome, sampler: Option<Sampler>, flags: &str) {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mode = if matches!(outcome, Outcome::AuditDenied) {
        "audit"
    } else {
        "enforce"
    };
    let path = if matches!(outcome, Outcome::PolicyDenied | Outcome::AuditDenied) {
        "/blocked"
    } else {
        "/allowed"
    };
    let engine = Arc::new(
        native_identity_engine(
            include_str!("../../../data/sandbox-policy.rego"),
            &format!(
                r#"
network_policies:
  traced_api:
    name: traced_api
    endpoints:
      - host: "{ip}"
        port: {port}
        allowed_ips: ["{ip}/32"]
        protocol: rest
        enforcement: {mode}
        rules:
          - allow: {{ method: GET, path: /allowed }}
    binaries:
      - path: /usr/bin/python3
"#
            ),
        )
        .unwrap(),
    );
    let identity = Ok(ContractBinaryIdentity {
        executable: ContractExecutableIdentity {
            path: executable_path("/usr/bin/python3"),
            digest: Some("00".repeat(32).parse().unwrap()),
        },
        ancestors: Vec::new(),
        cmdline_paths: vec![executable_path("/workspace/investigate.py")],
    });
    let expect_export = matches!(sampler, Some(Sampler::AlwaysOn));
    let capture = RequestTracing::new(sampler);
    let subscriber = capture
        .subscriber()
        .with(openshell_otel::supervisor_span_filter("info"));
    let (mut app, proxy) = tokio::io::duplex(8192);
    let mut proxy: ProxyClient = tokio::io::BufReader::new(Box::new(proxy));
    let target = format!("http://{ip}:{port}{path}?token=SENTINEL-QUERY");
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {ip}:{port}\r\ntraceparent: 00-{WORKLOAD_TRACE_ID}-{WORKLOAD_SPAN_ID}-{flags}\r\ntracestate: vendor=SENTINEL-VENDOR\r\nx-openshell-request-id: forged-receipt\r\nConnection: close\r\n\r\n"
    );
    let exchange = async {
        tokio::join!(
            async {
                let result = Box::pin(handle_forward_proxy(
                    "GET",
                    &target,
                    request.as_bytes(),
                    request.len(),
                    &mut proxy,
                    Some(&identity),
                    Some((
                        "192.0.2.20:42123".parse().unwrap(),
                        "192.0.2.10:3128".parse().unwrap(),
                    )),
                    engine,
                    Arc::new(BinaryIdentityCache::new()),
                    Arc::new(AtomicU32::new(0)),
                    None,
                    AgentProposals::default(),
                    Arc::new(None),
                    Arc::new(None),
                    None,
                    None,
                    None,
                    None,
                    None,
                ))
                .await;
                drop(proxy);
                result
            },
            async {
                if matches!(outcome, Outcome::PolicyDenied) {
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(50),
                            listener.accept()
                        )
                        .await
                        .is_err(),
                        "policy denial reached upstream"
                    );
                } else {
                    let (mut upstream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        bytes.push(upstream.read_u8().await.unwrap());
                    }
                    assert!(
                        String::from_utf8_lossy(&bytes)
                            .starts_with(&format!("GET {path}?token=SENTINEL-QUERY HTTP/1.1\r\n"))
                    );
                    assert!(!String::from_utf8_lossy(&bytes).contains("forged-receipt"));
                    if !matches!(outcome, Outcome::UpstreamClosed) {
                        upstream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                    }
                }
            },
            async {
                let mut response = Vec::new();
                app.read_to_end(&mut response).await.unwrap();
                response
            },
        )
    };
    let (result, (), response) =
        async { tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange)).await }
            .with_subscriber(subscriber)
            .await
            .unwrap();
    result.unwrap();
    let spans = capture.spans();
    let expected = (!matches!(outcome, Outcome::UpstreamClosed)).then_some(
        if matches!(outcome, Outcome::PolicyDenied) {
            403
        } else {
            200
        },
    );
    let response = String::from_utf8(response).unwrap();
    let records = capture
        .events
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "{records:?}");
    let receipt = records[0]["metadata"]["correlation_uid"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(receipt).is_ok());
    if let Some(expected) = expected {
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected} ")),
            "{response}"
        );
        let wire_receipt = response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-openshell-request-id")
                    .then(|| value.trim())
            })
            .expect("inspected response receipt");
        assert_eq!(wire_receipt, receipt);
        assert_eq!(records[0]["http_response"]["code"], expected);
    } else {
        assert!(
            response.is_empty(),
            "upstream EOF must not synthesize a response"
        );
        assert!(records[0].get("http_response").is_none());
        assert_eq!(records[0]["status_id"], 2);
    }
    assert_eq!(
        records[0]["action_id"],
        if matches!(outcome, Outcome::PolicyDenied) {
            2
        } else {
            1
        }
    );
    let created = capture.created_span_names();
    assert!(
        !created.contains(&"supervisor.egress.deny"),
        "inspected paths must never create a deny-only span"
    );
    assert_eq!(
        created
            .iter()
            .filter(|name| **name == "openshell.http.request")
            .count(),
        1
    );
    let roots = spans
        .iter()
        .filter(|span| span.name == "openshell.http.request")
        .collect::<Vec<_>>();
    assert_eq!(
        roots.len(),
        usize::from(expect_export),
        "local sampler/export configuration controls request span export"
    );
    if roots.is_empty() {
        assert!(spans.is_empty());
        assert!(records[0].get("trace").is_none());
    } else {
        assert_eq!(roots.len(), 1);
        let root = roots[0];
        assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        assert_ne!(root.span_context.trace_id().to_string(), WORKLOAD_TRACE_ID);
        assert_eq!(root.links.links.len(), 1);
        assert_eq!(
            root.links.links[0].span_context.trace_id().to_string(),
            WORKLOAD_TRACE_ID
        );
        assert_eq!(
            root.links.links[0].span_context.span_id().to_string(),
            WORKLOAD_SPAN_ID
        );
        assert!(
            root.links.links[0]
                .span_context
                .trace_state()
                .header()
                .is_empty()
        );
        assert_eq!(
            records[0]["trace"]["uid"],
            root.span_context.trace_id().to_string()
        );
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "openshell.request.id" && attribute.value.as_str() == receipt
        }));
        let stages = spans
            .iter()
            .filter(|span| span.parent_span_id == root.span_context.span_id())
            .collect::<Vec<_>>();
        assert!(
            stages
                .iter()
                .any(|span| span.name == "openshell.policy.evaluate")
        );
        assert_eq!(
            stages
                .iter()
                .any(|span| span.name == "openshell.upstream.connect"),
            !matches!(outcome, Outcome::PolicyDenied)
        );
        assert_eq!(
            stages
                .iter()
                .any(|span| span.name == "openshell.upstream.resolve"),
            !matches!(outcome, Outcome::PolicyDenied)
        );
        assert_eq!(
            matches!(root.status, opentelemetry::trace::Status::Error { .. }),
            matches!(outcome, Outcome::UpstreamClosed),
            "a policy refusal is an outcome, not an operational tracing failure"
        );
        assert!(
            stages
                .iter()
                .all(|span| span.span_context.trace_id() == root.span_context.trace_id())
        );
        assert!(!format!("{spans:?}").contains("SENTINEL"));
    }
    capture.shutdown();
}

#[tokio::test]
async fn inspected_forward_traces_all_outcomes_without_sampling_or_export_dependencies() {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let ip = non_loopback_test_ipv4()
        .expect("FORWARD trace qualification requires a non-loopback IPv4 address");
    for outcome in [
        Outcome::Allowed,
        Outcome::PolicyDenied,
        Outcome::AuditDenied,
        Outcome::UpstreamClosed,
    ] {
        for flags in ["00", "01"] {
            for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
                forward_case(ip, outcome, sampler, flags).await;
            }
        }
    }
}

#[tokio::test]
async fn inspected_forward_http_trace_ends_before_websocket_session() {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let ip = non_loopback_test_ipv4()
        .expect("FORWARD trace qualification requires a non-loopback IPv4 address");
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let engine = Arc::new(
        native_identity_engine(
            include_str!("../../../data/sandbox-policy.rego"),
            &format!(
                r#"
network_policies:
  traced_websocket:
    name: traced_websocket
    endpoints:
      - host: "{ip}"
        port: {port}
        allowed_ips: ["{ip}/32"]
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: {{ method: GET, path: /ws }}
          - allow: {{ method: WEBSOCKET_TEXT, path: /ws }}
    binaries:
      - path: /usr/bin/python3
"#
            ),
        )
        .unwrap(),
    );
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    let subscriber = capture
        .subscriber()
        .with(openshell_otel::supervisor_span_filter("info"));
    let (mut app, proxy) = tokio::io::duplex(8192);
    let target = format!("http://{ip}:{port}/ws");
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\ntraceparent: 00-{WORKLOAD_TRACE_ID}-{WORKLOAD_SPAN_ID}-01\r\n\r\n"
    );
    let handler = tokio::spawn(
        async move {
            let identity = Ok(ContractBinaryIdentity {
                executable: ContractExecutableIdentity {
                    path: executable_path("/usr/bin/python3"),
                    digest: Some("00".repeat(32).parse().unwrap()),
                },
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            });
            let mut proxy: ProxyClient = tokio::io::BufReader::new(Box::new(proxy));
            Box::pin(handle_forward_proxy(
                "GET",
                &target,
                request.as_bytes(),
                request.len(),
                &mut proxy,
                Some(&identity),
                Some((
                    "192.0.2.20:42123".parse().unwrap(),
                    "192.0.2.10:3128".parse().unwrap(),
                )),
                engine,
                Arc::new(BinaryIdentityCache::new()),
                Arc::new(AtomicU32::new(0)),
                None,
                AgentProposals::default(),
                Arc::new(None),
                Arc::new(None),
                None,
                None,
                None,
                None,
                None,
            ))
            .await
        }
        .with_subscriber(subscriber),
    );
    let (release, released) = tokio::sync::oneshot::channel();
    let (activity, observed_activity) = tokio::sync::oneshot::channel();
    let (handshake, ready) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut upstream, _) = listener.accept().await.unwrap();
        let request = read_http_headers(&mut upstream).await;
        assert!(String::from_utf8_lossy(&request).starts_with("GET /ws HTTP/1.1\r\n"));
        upstream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
            .await
            .unwrap();
        handshake.send(()).unwrap();
        let frame = crate::l7::websocket::read_frame_for_test(&mut upstream).await;
        assert_eq!(frame, masked_text_frame(b"after-http-root"));
        activity.send(std::time::SystemTime::now()).unwrap();
        upstream.write_all(b"\x81\x02ok").await.unwrap();
        released.await.unwrap();
    });
    let scenario = async {
        ready.await.unwrap();
        let response = read_http_headers(&mut app).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101 "));
        let root = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(root) = capture
                    .spans()
                    .into_iter()
                    .find(|span| span.name == "openshell.http.request")
                {
                    break root;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP root must finish while the upgraded connection is still open");
        assert!(!handler.is_finished());
        assert!(!upstream.is_finished());
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "http.response.status_code"
                && attribute.value == opentelemetry::Value::I64(101)
        }));
        assert!(root.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "openshell.request.outcome"
                && attribute.value.as_str() == "upgraded"
        }));
        app.write_all(&masked_text_frame(b"after-http-root"))
            .await
            .unwrap();
        assert!(root.end_time <= observed_activity.await.unwrap());
        let mut frame = [0; 4];
        app.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x81\x02ok");
        assert!(!handler.is_finished());
        release.send(()).unwrap();
        drop(app);
        upstream.await.unwrap();
        handler.await.unwrap().unwrap();
        let records = capture.events.json_events();
        assert_eq!(
            records
                .iter()
                .filter(|event| event["class_uid"] == 4002 && event["http_response"]["code"] == 101)
                .count(),
            1
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), scenario)
        .await
        .unwrap();
    capture.shutdown();
}
