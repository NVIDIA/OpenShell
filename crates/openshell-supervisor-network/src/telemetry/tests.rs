// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use openshell_otel_test_support::{OtlpTestServer, ReceivedTraces, tracing_test_lock};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::trace::v1::Span;
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

/// Capture the actual OCSF dispatch and the spans an in-memory exporter
/// receives through the supervisor's span filter.
pub async fn exported(
    log_level: &str,
    emit: impl FnOnce(),
) -> (Vec<serde_json::Value>, ReceivedTraces) {
    let _lock = tracing_test_lock().await;
    LazyLock::force(&REGISTER);
    super::reset_deny_span_limiter();
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let events = capture(log_level, &provider, emit);
    provider.force_flush().unwrap();
    let spans = exporter
        .get_finished_spans()
        .unwrap()
        .into_iter()
        .map(Into::into)
        .collect();
    provider.shutdown().unwrap();
    (
        events,
        ReceivedTraces {
            spans,
            ..ReceivedTraces::default()
        },
    )
}

/// Capture the actual OCSF dispatch and receive spans over OTLP/gRPC.
pub async fn exported_over_otlp(
    log_level: &str,
    emit: impl FnOnce(),
) -> (Vec<serde_json::Value>, ReceivedTraces) {
    let _lock = tracing_test_lock().await;
    LazyLock::force(&REGISTER);
    super::reset_deny_span_limiter();
    let collector = OtlpTestServer::start().await;
    let (provider, error) = openshell_otel::provider_for(Some(openshell_otel::OtlpExportConfig {
        endpoint: collector.endpoint(),
        service_name: openshell_otel::ServiceName::Fixed("openshell-supervisor"),
        service_version: None,
        resource_attributes: vec![],
    }));
    assert!(error.is_none());
    let provider = provider.unwrap();
    let events = capture(log_level, &provider, emit);
    provider.force_flush().unwrap();
    collector.wait_for_export().await;
    provider.shutdown().unwrap();
    (events, collector.shutdown().await)
}

static REGISTER: LazyLock<()> = LazyLock::new(|| {
    assert!(openshell_ocsf::register_trace_correlation_extractor(
        openshell_otel::current_ocsf_trace_correlation
    ));
});

fn capture(
    log_level: &str,
    provider: &opentelemetry_sdk::trace::SdkTracerProvider,
    emit: impl FnOnce(),
) -> Vec<serde_json::Value> {
    let bytes = Arc::new(Mutex::new(vec![]));
    let subscriber = tracing_subscriber::registry()
        .with(
            openshell_ocsf::OcsfJsonlLayer::new(Writer(bytes.clone()))
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        )
        .with(
            openshell_otel::layer(provider, "openshell-supervisor")
                .with_filter(openshell_otel::supervisor_span_filter(log_level)),
        )
        // The shared test registry keeps callsites enabled process-wide.
        // Gate this subscriber too, so the default case also checks a disabled
        // DEBUG connect handle, as well as absence from the OTLP export.
        .with(openshell_otel::supervisor_span_filter(log_level));
    tracing::subscriber::with_default(subscriber, emit);
    String::from_utf8(bytes.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

pub fn assert_deny_resolves(events: &[serde_json::Value], received: &ReceivedTraces, root: bool) {
    assert!(events.iter().any(|event| event["class_uid"] == 4002));
    for event in events {
        if event["class_uid"] != 4002 {
            assert!(
                event.get("trace").is_none(),
                "only HTTP Activity carries trace"
            );
            continue;
        }
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
        let span = deny_spans(received)
            .into_iter()
            .find(|span| hex::encode(&span.trace_id) == uid)
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
        let class_uid = span_attribute(span, "ocsf.class_uid");
        assert!(
            matches!(class_uid, Some(Value::IntValue(_))),
            "deny span exports ocsf.class_uid as an integer: {class_uid:?}"
        );
    }
}

pub fn http_deny(host: &str, decision: &str) -> openshell_ocsf::OcsfEvent {
    openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .action(openshell_ocsf::ActionId::Denied)
        .http_request(openshell_ocsf::HttpRequest::new(
            "GET",
            openshell_ocsf::Url::new("https", host, "/", 443),
        ))
        .dst_endpoint(openshell_ocsf::Endpoint::from_domain(host, 443))
        .status_detail(decision)
        .message(decision)
        .build()
}

pub fn deny_spans(received: &ReceivedTraces) -> Vec<&Span> {
    received
        .spans
        .iter()
        .filter(|span| span.name == "supervisor.egress.deny")
        .collect()
}

/// Assert that no record carries `trace` and no deny span was exported.
pub fn assert_no_deny(events: &[serde_json::Value], received: &ReceivedTraces) {
    for event in events {
        assert!(event.get("trace").is_none(), "{event}");
    }
    assert!(deny_spans(received).is_empty());
}

pub fn span_attribute<'a>(span: &'a Span, key: &str) -> Option<&'a Value> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| attribute.value.as_ref()?.value.as_ref())
}

pub fn assert_deny_attribute(received: &ReceivedTraces, key: &str, expected: &str) {
    assert_eq!(
        span_attribute(deny_spans(received)[0], key),
        Some(&Value::StringValue(expected.to_string()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn companion_records_share_one_deny_span() {
    let (events, received) = exported("warn", || {
        let event = http_deny("blocked.example", "denied");
        let finding =
            openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx()).build();
        super::emit_decision([event, finding], None);
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_eq!(received.spans.len(), 1);
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
                                    let event = http_deny(host, &decision);
                                    let finding = openshell_ocsf::DetectionFindingBuilder::new(
                                        openshell_ocsf::ctx::ctx(),
                                    )
                                    .message(&decision)
                                    .build();
                                    super::emit_decision([event, finding], None);
                                    // Both threads finish each decision before either
                                    // starts the next.
                                    barrier.wait();
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
        let denies = deny_spans(&received);
        assert_eq!(denies.len(), 4);
        assert_eq!(received.spans.len(), if level == "debug" { 6 } else { 4 });
        let attribute = |span: &Span, key: &str| match span_attribute(span, key) {
            Some(Value::StringValue(value)) => value.clone(),
            other => panic!("expected string attribute {key}, got {other:?}"),
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
                    assert_eq!(event["device"]["container"]["uid"], host);
                    assert_eq!(
                        event["device"]["container"]["name"],
                        format!("sandbox-{host}")
                    );
                }
                let http = pair
                    .iter()
                    .find(|event| event["class_uid"] == 4002)
                    .unwrap();
                let spans = denies
                    .iter()
                    .filter(|span| attribute(span, "openshell.policy.reason") == decision)
                    .collect::<Vec<_>>();
                assert_eq!(spans.len(), 1);
                let deny = spans[0];
                assert_eq!(attribute(deny, "server.address"), host);
                assert_eq!(http["trace"]["uid"], hex::encode(&deny.trace_id));
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
async fn deny_span_describes_the_denied_http_record() {
    let (events, received) = exported("warn", || {
        let allowed = openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Allowed)
            .http_request(openshell_ocsf::HttpRequest::new(
                "GET",
                openshell_ocsf::Url::new("https", "allowed.example", "/", 443),
            ))
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                "allowed.example",
                443,
            ))
            .build();
        super::emit_decision([allowed, http_deny("blocked.example", "denied")], None);
    })
    .await;
    assert_deny_resolves(&events, &received, true);
    assert_deny_attribute(&received, "server.address", "blocked.example");
    assert_deny_attribute(&received, "openshell.policy.reason", "denied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_deny_context_leaves_optional_attributes_unset() {
    let (events, received) = exported("warn", || {
        let http = openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .http_request(openshell_ocsf::HttpRequest {
                http_method: "GET".parse().unwrap(),
                url: None,
            })
            .message("diagnostic text is not a policy reason")
            .build();
        super::egress_emit!(http);
    })
    .await;
    assert_deny_resolves(&events, &received, true);
    assert_eq!(events.len(), 1);
    assert_eq!(received.spans.len(), 1);
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
async fn denials_without_an_http_record_do_not_open_deny_spans() {
    let (events, received) = exported("warn", || {
        let network = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                "blocked.example",
                443,
            ))
            .build();
        let finding = openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .build();
        super::emit_decision([network, finding], None);
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_no_deny(&events, &received);
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
        super::egress_emit!(allowed);
        crate::l7::middleware::emit_middleware_uninspectable(
            &crate::l7::relay::L7EvalContext::default(),
            "unknown protocol",
            false,
        );
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_no_deny(&events, &received);
}

#[test]
fn deny_span_limiter_bounds_each_destination_and_refills() {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let mut limiter = super::DenySpanLimiter::new(2, Duration::from_secs(1), 8);
    assert!(limiter.allow("a:443", start));
    assert!(limiter.allow("a:443", start));
    assert!(!limiter.allow("a:443", start));
    assert!(
        limiter.allow("b:443", start),
        "destinations are independent"
    );
    assert!(!limiter.allow("a:443", start + Duration::from_millis(999)));
    assert!(limiter.allow("a:443", start + Duration::from_secs(1)));
    assert!(!limiter.allow("a:443", start + Duration::from_secs(1)));
    let later = start + Duration::from_mins(1);
    assert!(limiter.allow("a:443", later));
    assert!(limiter.allow("a:443", later));
    assert!(!limiter.allow("a:443", later), "refill stops at the burst");
}

#[test]
fn deny_span_limiter_bounds_tracked_destinations() {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let mut limiter = super::DenySpanLimiter::new(1, Duration::from_secs(1), 2);
    assert!(limiter.allow("a", start));
    assert!(limiter.allow("b", start));
    assert!(
        !limiter.allow("c", start),
        "untracked destinations wait for room"
    );
    // Full buckets are idle and can be evicted.
    assert!(limiter.allow("c", start + Duration::from_secs(1)));
}

#[test]
fn deny_span_limiter_bounds_aggregate_bursts_and_refills() {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let mut limiter = super::DenySpanLimiter::with_global_limit(
        1,
        Duration::from_secs(1),
        8,
        2,
        Duration::from_millis(100),
    );
    assert!(limiter.allow("a", start));
    assert!(
        !limiter.allow("a", start),
        "a destination rejection spends no global token"
    );
    assert!(limiter.allow("b", start));
    assert!(
        !limiter.allow("c", start),
        "rotating destinations cannot exceed the global burst"
    );
    assert!(!limiter.allow("c", start + Duration::from_millis(99)));
    assert!(limiter.allow("c", start + Duration::from_millis(100)));
    assert!(!limiter.allow("d", start + Duration::from_millis(100)));
    let later = start + Duration::from_secs(10);
    assert!(limiter.allow("a", later));
    assert!(limiter.allow("b", later));
    assert!(
        !limiter.allow("c", later),
        "global refill stops at its burst"
    );
}

#[test]
fn destination_capacity_rejections_spend_no_global_tokens() {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let mut limiter = super::DenySpanLimiter::with_global_limit(
        10,
        Duration::from_secs(1),
        1,
        2,
        Duration::from_secs(1),
    );
    assert!(limiter.allow("a", start));
    assert!(!limiter.allow("b", start));
    assert!(limiter.allow("a", start));
    assert!(!limiter.allow("a", start));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_deny_limit_preserves_every_audit_record() {
    let (events, received) = exported("warn", || {
        *super::LIMITER.lock().unwrap() = super::DenySpanLimiter::with_global_limit(
            10,
            std::time::Duration::from_secs(1),
            1024,
            3,
            std::time::Duration::MAX,
        );
        for index in 0..12 {
            super::egress_emit!(http_deny(&format!("host-{index}.example"), "denied"));
        }
    })
    .await;
    assert_eq!(
        events.len(),
        12,
        "the span budget never suppresses audit records"
    );
    assert!(events.iter().all(|event| event["action_id"] == 2));
    assert_eq!(deny_spans(&received).len(), 3);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.get("trace").is_some())
            .count(),
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limited_denial_keeps_an_active_sampled_connect_trace() {
    let (events, received) = exported("debug", || {
        *super::LIMITER.lock().unwrap() = super::DenySpanLimiter::with_global_limit(
            1,
            std::time::Duration::MAX,
            1024,
            100,
            std::time::Duration::MAX,
        );
        tracing::debug_span!("supervisor.egress.connect").in_scope(|| {
            super::egress_emit!(http_deny("blocked.example", "first"));
            super::egress_emit!(http_deny("blocked.example", "limited"));
        });
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_eq!(deny_spans(&received).len(), 1);
    let connect = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.egress.connect")
        .unwrap();
    assert_eq!(events[1]["trace"]["uid"], hex::encode(&connect.trace_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_denials_to_one_destination_export_bounded_spans() {
    let (events, received) = exported("warn", || {
        for _ in 0..(super::DENY_SPAN_BURST + 5) {
            super::egress_emit!(http_deny("loop.example", "denied"));
        }
        super::egress_emit!(http_deny("other.example", "denied"));
    })
    .await;
    let denies = deny_spans(&received).len();
    assert_eq!(denies, super::DENY_SPAN_BURST as usize + 1);
    let traced = events
        .iter()
        .filter(|event| event.get("trace").is_some())
        .count();
    assert_eq!(traced, denies, "limited records carry no trace.uid");
    assert_eq!(events.len(), super::DENY_SPAN_BURST as usize + 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_deny_spans_spend_no_tokens() {
    let _lock = tracing_test_lock().await;
    super::reset_deny_span_limiter();
    let subscriber =
        tracing_subscriber::registry().with(tracing_subscriber::filter::LevelFilter::WARN);
    tracing::subscriber::with_default(subscriber, || {
        super::egress_emit!(http_deny("quiet.example", "denied"));
    });
    assert!(super::LIMITER.lock().unwrap().buckets.is_empty());
    assert!(super::LIMITER.lock().unwrap().global.is_none());
}
