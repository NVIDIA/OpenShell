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
