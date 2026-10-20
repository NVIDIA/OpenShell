// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! W3C trace-context propagation for HTTP and tonic transports.

use std::collections::BTreeMap;

use http::HeaderMap;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// Reads OpenTelemetry propagation fields from HTTP headers.
#[derive(Debug, Clone, Copy)]
pub struct HeaderMapExtractor<'a>(&'a HeaderMap);

impl<'a> HeaderMapExtractor<'a> {
    #[must_use]
    pub fn new(headers: &'a HeaderMap) -> Self {
        Self(headers)
    }
}

impl Extractor for HeaderMapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(http::HeaderName::as_str).collect()
    }
}

/// Writes OpenTelemetry propagation fields to tonic metadata.
#[derive(Debug)]
pub struct MetadataMapInjector<'a>(&'a mut tonic::metadata::MetadataMap);

impl<'a> MetadataMapInjector<'a> {
    #[must_use]
    pub fn new(metadata: &'a mut tonic::metadata::MetadataMap) -> Self {
        Self(metadata)
    }
}

impl Injector for MetadataMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let Ok(key) = key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>() else {
            return;
        };
        let Ok(value) = value.parse() else {
            return;
        };
        self.0.insert(key, value);
    }
}

#[derive(Debug)]
struct TraceContextMapInjector<'a>(&'a mut BTreeMap<String, String>);

impl Injector for TraceContextMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

/// Serialize the active span's W3C propagation fields into a string map.
///
/// Returns `None` when the current span has no valid OpenTelemetry context.
#[must_use]
pub fn current_trace_context_carrier() -> Option<BTreeMap<String, String>> {
    let context = tracing::Span::current().context();
    let mut carrier = BTreeMap::new();
    TraceContextPropagator::new()
        .inject_context(&context, &mut TraceContextMapInjector(&mut carrier));
    carrier.contains_key("traceparent").then_some(carrier)
}

/// Environment variable carrying a W3C `traceparent` into a child process.
pub const TRACEPARENT_ENV: &str = "TRACEPARENT";

/// Environment variable carrying a W3C `tracestate` into a child process.
pub const TRACESTATE_ENV: &str = "TRACESTATE";

/// Map W3C propagation fields to child-process environment variables.
#[must_use]
pub fn trace_context_environment(
    carrier: &BTreeMap<String, String>,
) -> Vec<(&'static str, String)> {
    [
        ("traceparent", TRACEPARENT_ENV),
        ("tracestate", TRACESTATE_ENV),
    ]
    .into_iter()
    .filter_map(|(field, name)| {
        carrier
            .get(field)
            .filter(|value| !value.is_empty())
            .map(|value| (name, value.clone()))
    })
    .collect()
}

/// Environment carrying the active span's trace context to a child process.
///
/// Empty when the current span has no valid OpenTelemetry context.
#[must_use]
pub fn current_trace_context_environment() -> Vec<(&'static str, String)> {
    current_trace_context_carrier()
        .map(|carrier| trace_context_environment(&carrier))
        .unwrap_or_default()
}

/// Parent `span` under the trace context in `TRACEPARENT` and `TRACESTATE`.
///
/// Leaves `span` unchanged when the environment carries no valid context.
pub fn set_parent_from_environment(span: &tracing::Span) {
    let carrier = [
        ("traceparent", TRACEPARENT_ENV),
        ("tracestate", TRACESTATE_ENV),
    ]
    .into_iter()
    .filter_map(|(field, name)| {
        std::env::var(name)
            .ok()
            .map(|value| (field.to_string(), value))
    })
    .collect::<BTreeMap<_, _>>();
    set_parent_from_carrier(span, &carrier);
}

fn set_parent_from_carrier(span: &tracing::Span, carrier: &BTreeMap<String, String>) {
    use opentelemetry::trace::TraceContextExt as _;

    let parent = TraceContextPropagator::new().extract(&TraceContextMapExtractor(carrier));
    if parent.span().span_context().is_valid() {
        let _ = span.set_parent(parent);
    }
}

struct TraceContextMapExtractor<'a>(&'a BTreeMap<String, String>);

impl Extractor for TraceContextMapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Injects the active W3C trace context into an outbound tonic request.
#[derive(Debug, Clone, Copy)]
pub struct TraceContextInterceptor;

impl tonic::service::Interceptor for TraceContextInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let context = tracing::Span::current().context();
        TraceContextPropagator::new().inject_context(
            &context,
            &mut MetadataMapInjector::new(request.metadata_mut()),
        );
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_test_exporter() -> (
        opentelemetry_sdk::trace::SdkTracerProvider,
        opentelemetry_sdk::trace::InMemorySpanExporter,
        impl tracing::Subscriber + Send + Sync,
    ) {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "env-test"));
        (provider, exporter, subscriber)
    }

    #[test]
    fn environment_carrier_parents_a_span_in_the_same_trace() {
        use opentelemetry::trace::TraceContextExt as _;

        let _tracing_lock = crate::test_lock();
        let (_provider, exporter, subscriber) = env_test_exporter();

        let (parent, environment) = tracing::subscriber::with_default(subscriber, || {
            let parent = tracing::info_span!("parent");
            let environment = parent
                .in_scope(|| trace_context_environment(&current_trace_context_carrier().unwrap()));
            let child = tracing::info_span!("child");
            let carrier = environment
                .iter()
                .map(|(name, value)| {
                    let field = if *name == TRACEPARENT_ENV {
                        "traceparent"
                    } else {
                        "tracestate"
                    };
                    (field.to_string(), value.clone())
                })
                .collect();
            set_parent_from_carrier(&child, &carrier);
            drop(child);
            (parent.context().span().span_context().clone(), environment)
        });

        assert_eq!(environment.len(), 1, "empty tracestate is omitted");
        assert_eq!(environment[0].0, TRACEPARENT_ENV);
        let spans = exporter.get_finished_spans().unwrap();
        let child = spans.iter().find(|span| span.name == "child").unwrap();
        assert_eq!(child.span_context.trace_id(), parent.trace_id());
        assert_eq!(child.parent_span_id, parent.span_id());
    }

    #[test]
    #[allow(unsafe_code)]
    fn environment_traceparent_parents_a_span() {
        let _tracing_lock = crate::test_lock();
        let (_provider, exporter, subscriber) = env_test_exporter();
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let span_id = "00f067aa0ba902b7";
        let original = std::env::var(TRACEPARENT_ENV).ok();
        unsafe {
            std::env::set_var(TRACEPARENT_ENV, format!("00-{trace_id}-{span_id}-01"));
        }

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("child");
            set_parent_from_environment(&span);
        });

        unsafe {
            match original {
                Some(value) => std::env::set_var(TRACEPARENT_ENV, value),
                None => std::env::remove_var(TRACEPARENT_ENV),
            }
        }
        let spans = exporter.get_finished_spans().unwrap();
        let child = spans.iter().find(|span| span.name == "child").unwrap();
        assert_eq!(child.span_context.trace_id().to_string(), trace_id);
        assert_eq!(child.parent_span_id.to_string(), span_id);
    }

    #[test]
    fn invalid_environment_carrier_leaves_the_span_unparented() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::test_lock();
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "env-test"));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("orphan");
            let carrier = BTreeMap::from([("traceparent".to_string(), "invalid".to_string())]);
            set_parent_from_carrier(&span, &carrier);
        });

        let spans = exporter.get_finished_spans().unwrap();
        let orphan = spans.iter().find(|span| span.name == "orphan").unwrap();
        assert_eq!(orphan.parent_span_id, opentelemetry::trace::SpanId::INVALID);
    }

    #[test]
    fn interceptor_adds_traceparent_only_inside_an_exported_span() {
        use tonic::service::Interceptor as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::test_lock();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "rpc-test"));

        let (outside, inside) = tracing::subscriber::with_default(subscriber, || {
            let outside = TraceContextInterceptor
                .call(tonic::Request::new(()))
                .unwrap();
            let span = tracing::info_span!("client");
            let _entered = span.enter();
            let inside = TraceContextInterceptor
                .call(tonic::Request::new(()))
                .unwrap();
            (outside, inside)
        });

        assert!(outside.metadata().get("traceparent").is_none());
        assert!(inside.metadata().get("traceparent").is_some());
    }

    #[test]
    fn header_map_extractor_reads_valid_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "00-abc-def-01".parse().unwrap());
        let extractor = HeaderMapExtractor::new(&headers);

        assert_eq!(extractor.get("traceparent"), Some("00-abc-def-01"));
        assert_eq!(extractor.keys(), ["traceparent"]);
    }

    #[test]
    fn metadata_map_injector_writes_ascii_metadata() {
        let mut metadata = tonic::metadata::MetadataMap::new();
        MetadataMapInjector::new(&mut metadata).set("traceparent", "value".to_string());

        assert_eq!(
            metadata
                .get("traceparent")
                .and_then(|value| value.to_str().ok()),
            Some("value")
        );
    }
}
