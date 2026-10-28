// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use openshell_otel_test_support::{OtlpTestServer, ReceivedTraces, tracing_test_lock};
use tracing_subscriber::prelude::*;

#[derive(Clone)]
struct Writer(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Capture the actual OCSF dispatch and receive spans over OTLP/gRPC.
pub async fn exported(
    log_level: &str,
    emit: impl FnOnce(),
) -> (Vec<serde_json::Value>, ReceivedTraces) {
    static REGISTER: LazyLock<()> = LazyLock::new(|| {
        assert!(openshell_ocsf::register_trace_correlation_extractor(
            openshell_otel::current_ocsf_trace_correlation
        ));
    });
    let _lock = tracing_test_lock().await;
    LazyLock::force(&REGISTER);
    let collector = OtlpTestServer::start().await;
    let (provider, error) = openshell_otel::provider_for(Some(openshell_otel::OtlpExportConfig {
        endpoint: collector.endpoint(),
        service_name: openshell_otel::ServiceName::Fixed("openshell-supervisor"),
        service_version: None,
        resource_attributes: vec![],
    }));
    assert!(error.is_none());
    let provider = provider.unwrap();
    let bytes = Arc::new(Mutex::new(vec![]));
    let subscriber = tracing_subscriber::registry()
        .with(
            openshell_ocsf::OcsfJsonlLayer::new(Writer(bytes.clone()))
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        )
        .with(
            openshell_otel::layer(&provider, "openshell-supervisor")
                .with_filter(openshell_otel::supervisor_span_filter(log_level)),
        )
        // The shared test registry keeps callsites enabled process-wide.
        // Gate this subscriber too, so the default case also checks a disabled
        // DEBUG connect handle, as well as absence from the OTLP export.
        .with(openshell_otel::supervisor_span_filter(log_level));
    tracing::subscriber::with_default(subscriber, emit);
    provider.force_flush().unwrap();
    collector.wait_for_export().await;
    provider.shutdown().unwrap();
    let received = collector.shutdown().await;
    let events = String::from_utf8(bytes.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (events, received)
}

pub fn assert_deny_resolves(events: &[serde_json::Value], received: &ReceivedTraces, root: bool) {
    use opentelemetry_proto::tonic::common::v1::any_value::Value;

    assert!(!events.is_empty());
    for event in events {
        let uid = event["trace"]["uid"]
            .as_str()
            .expect("emission was inside sampled deny span");
        assert_eq!(uid.len(), 32);
        assert!(
            event["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "trace")
        );
        let span = received
            .spans
            .iter()
            .find(|span| {
                span.name == "supervisor.egress.deny" && hex::encode(&span.trace_id) == uid
            })
            .expect("OCSF trace.uid resolves to exported deny span");
        if root {
            assert!(span.parent_span_id.is_empty());
            assert_eq!(
                received
                    .spans
                    .iter()
                    .filter(|other| other.trace_id == span.trace_id)
                    .count(),
                1
            );
        }
        let attributes = span
            .attributes
            .iter()
            .map(|kv| kv.key.as_str())
            .collect::<Vec<_>>();
        for key in ["openshell.policy.decision", "ocsf.class_uid"] {
            assert!(attributes.contains(&key), "deny span carries {key}");
        }
        let class_uid = span
            .attributes
            .iter()
            .find(|attribute| attribute.key == "ocsf.class_uid")
            .and_then(|attribute| attribute.value.as_ref()?.value.as_ref());
        assert!(
            matches!(class_uid, Some(Value::IntValue(_))),
            "deny span exports ocsf.class_uid as an integer: {class_uid:?}"
        );
    }
}

pub fn assert_deny_attribute(received: &ReceivedTraces, key: &str, expected: &str) {
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    let deny = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.egress.deny")
        .unwrap();
    let attribute = deny
        .attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .unwrap();
    assert_eq!(
        attribute.value.as_ref().unwrap().value.as_ref().unwrap(),
        &Value::StringValue(expected.to_string())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn companion_emissions_reuse_an_active_decision_scope() {
    let (events, received) = exported("warn", || {
        let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                "blocked.example",
                443,
            ))
            .build();
        let finding =
            openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx()).build();
        let scope = super::deny_span(&event, None);
        scope.in_scope(|| {
            super::emit(event, None, false);
            super::emit(finding, None, true);
        });
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_eq!(received.spans.len(), 1);
    assert_eq!(events[0]["trace"]["uid"], events[1]["trace"]["uid"]);
    assert_deny_resolves(&events, &received, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_decisions_keep_companions_and_request_contexts_separate() {
    for level in ["warn", "debug"] {
        let (events, received) = exported(level, || {
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|threads| {
                for host in ["alpha.example", "beta.example"] {
                    let dispatch = &dispatch;
                    let barrier = &barrier;
                    threads.spawn(move || {
                        tracing::dispatcher::with_default(dispatch, || {
                            let outside = openshell_ocsf::ctx::ctx().sandbox_id.clone();
                            let mut context = (*openshell_ocsf::ctx::ctx()).clone();
                            context.sandbox_id = host.to_string();
                            context.sandbox_name = format!("sandbox-{host}");
                            openshell_ocsf::ctx::bind_thread_ctx(Some(Arc::new(context)));
                            let connect = tracing::debug_span!("supervisor.egress.connect");
                            connect.in_scope(|| {
                                for attempt in 0..2 {
                                    let decision = format!("{host}:{attempt}");
                                    let event = openshell_ocsf::NetworkActivityBuilder::new(
                                        openshell_ocsf::ctx::ctx(),
                                    )
                                    .action(openshell_ocsf::ActionId::Denied)
                                    .dst_endpoint(openshell_ocsf::Endpoint::from_domain(host, 443))
                                    .status_detail(&decision)
                                    .message(&decision)
                                    .build();
                                    let finding = openshell_ocsf::DetectionFindingBuilder::new(
                                        openshell_ocsf::ctx::ctx(),
                                    )
                                    .message(&decision)
                                    .build();
                                    let scope = super::deny_span(&event, None);
                                    scope.in_scope(|| {
                                        super::emit(event, None, false);
                                        // Both threads keep different deny scopes entered
                                        // while their companion records interleave.
                                        barrier.wait();
                                        super::emit(finding, None, true);
                                        barrier.wait();
                                    });
                                }
                            });
                            openshell_ocsf::ctx::bind_thread_ctx(None);
                            assert_eq!(openshell_ocsf::ctx::ctx().sandbox_id, outside);
                        });
                    });
                }
            });
        })
        .await;

        assert_eq!(events.len(), 8);
        assert_deny_resolves(&events, &received, level == "warn");
        let denies = received
            .spans
            .iter()
            .filter(|span| span.name == "supervisor.egress.deny")
            .collect::<Vec<_>>();
        assert_eq!(denies.len(), 4);
        assert_eq!(received.spans.len(), if level == "debug" { 6 } else { 4 });
        let attribute = |span: &opentelemetry_proto::tonic::trace::v1::Span, key: &str| {
            use opentelemetry_proto::tonic::common::v1::any_value::Value;
            match span
                .attributes
                .iter()
                .find(|attribute| attribute.key == key)
                .and_then(|attribute| attribute.value.as_ref())
                .and_then(|value| value.value.as_ref())
            {
                Some(Value::StringValue(value)) => value.clone(),
                other => panic!("expected string attribute {key}, got {other:?}"),
            }
        };
        let mut traces_by_host = Vec::new();
        for host in ["alpha.example", "beta.example"] {
            let mut traces = Vec::new();
            for attempt in 0..2 {
                let decision = format!("{host}:{attempt}");
                let pair = events
                    .iter()
                    .filter(|event| event["message"] == decision)
                    .collect::<Vec<_>>();
                assert_eq!(pair.len(), 2);
                for event in &pair {
                    assert_eq!(event["container"]["uid"], host);
                    assert_eq!(event["container"]["name"], format!("sandbox-{host}"));
                }
                assert_eq!(pair[0]["trace"]["uid"], pair[1]["trace"]["uid"]);
                let spans = denies
                    .iter()
                    .filter(|span| attribute(span, "openshell.policy.reason") == decision)
                    .collect::<Vec<_>>();
                assert_eq!(spans.len(), 1);
                let deny = spans[0];
                assert_eq!(attribute(deny, "server.address"), host);
                assert_eq!(pair[0]["trace"]["uid"], hex::encode(&deny.trace_id));
                if level == "debug" {
                    let connect = received
                        .spans
                        .iter()
                        .find(|span| span.span_id == deny.parent_span_id)
                        .unwrap();
                    assert_eq!(connect.name, "supervisor.egress.connect");
                    assert_eq!(connect.trace_id, deny.trace_id);
                }
                traces.push(deny.trace_id.clone());
            }
            if level == "debug" {
                assert_eq!(traces[0], traces[1]);
            } else {
                assert_ne!(traces[0], traces[1]);
            }
            traces_by_host.push(traces);
        }
        for alpha in &traces_by_host[0] {
            for beta in &traces_by_host[1] {
                assert_ne!(
                    alpha, beta,
                    "independent request contexts must stay separate"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_deny_context_leaves_optional_attributes_unset() {
    let (events, received) = exported("warn", || {
        let finding = openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .message("diagnostic text is not a policy reason")
            .build();
        super::emit(finding, None, false);
        let network = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .dst_endpoint(openshell_ocsf::Endpoint {
                name: None,
                domain: None,
                ip: None,
                port: None,
            })
            .build();
        super::emit(network, None, false);
    })
    .await;
    assert_deny_resolves(&events, &received, true);
    assert_eq!(events.len(), 2);
    assert_eq!(received.spans.len(), 2);
    for span in &received.spans {
        for key in [
            "openshell.policy.name",
            "openshell.policy.reason",
            "server.address",
            "server.port",
        ] {
            assert!(
                span.attributes.iter().all(|kv| kv.key != key),
                "{key} stays unset"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_emissions_do_not_create_info_deny_spans() {
    let (events, received) = exported("warn", || {
        let allowed = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Allowed)
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                "allowed.example",
                443,
            ))
            .build();
        super::emit(allowed, None, false);
        crate::l7::middleware::emit_middleware_uninspectable(
            &crate::l7::relay::L7EvalContext::default(),
            "unknown protocol",
            false,
        );
        // Flush an unrelated INFO span so the collector wait is bounded by an export.
        tracing::info_span!("test.export-barrier").in_scope(|| {});
    })
    .await;
    assert_eq!(events.len(), 2);
    for event in events {
        assert!(event.get("trace").is_none());
    }
    assert!(
        !received
            .spans
            .iter()
            .any(|span| span.name == "supervisor.egress.deny")
    );
}
