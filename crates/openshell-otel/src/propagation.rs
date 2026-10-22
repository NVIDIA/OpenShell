// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! W3C trace-context propagation for HTTP and tonic transports.

use std::collections::BTreeMap;

use http::HeaderMap;
use opentelemetry::Context;
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
/// Reads the environment the same way [`EnvTraceContextInterceptor`] does:
/// both spellings are accepted, whitespace is trimmed, and blank values are
/// treated as unset.
///
/// Leaves `span` unchanged when the environment carries no valid context.
pub fn set_parent_from_environment(span: &tracing::Span) {
    let carrier = [
        ("traceparent", read_env(TRACEPARENT_ENV)),
        ("tracestate", read_env(TRACESTATE_ENV)),
    ]
    .into_iter()
    .filter_map(|(field, value)| value.map(|value| (field.to_string(), value)))
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

/// Reads W3C trace-context propagation fields from process environment
/// variables (`TRACEPARENT` and `TRACESTATE`).
///
/// CI systems (GitHub Actions, GitLab CI, Jenkins OpenTelemetry plugins)
/// export these variables to propagate the pipeline trace to child processes.
/// Both upper-case and lower-case spellings are accepted; blank values are
/// treated as unset.
#[derive(Debug, Clone, Default)]
struct EnvTraceContext {
    traceparent: Option<String>,
    tracestate: Option<String>,
}

impl EnvTraceContext {
    fn from_env() -> Self {
        Self {
            traceparent: read_env(TRACEPARENT_ENV),
            tracestate: read_env(TRACESTATE_ENV),
        }
    }
}

/// Read one environment variable, trimming whitespace and discarding blanks.
fn read_one(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Read an environment variable by its upper-case name, falling back to the
/// lower-case spelling, trimming whitespace and discarding blank values.
///
/// Each spelling is normalized before the fallback, so a blank upper-case
/// value never shadows a valid lower-case one.
fn read_env(upper: &str) -> Option<String> {
    read_one(upper).or_else(|| read_one(&upper.to_ascii_lowercase()))
}

impl Extractor for EnvTraceContext {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "traceparent" => self.traceparent.as_deref(),
            "tracestate" => self.tracestate.as_deref(),
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        let mut keys = Vec::new();
        if self.traceparent.is_some() {
            keys.push("traceparent");
        }
        if self.tracestate.is_some() {
            keys.push("tracestate");
        }
        keys
    }
}

/// Passively forwards a W3C trace context captured from the process
/// environment onto outbound tonic requests.
///
/// Unlike [`TraceContextInterceptor`], this does not require an active
/// OpenTelemetry span or an `SdkTracerProvider`; it reads `TRACEPARENT`
/// (and optionally `TRACESTATE`) once at construction and injects them as
/// gRPC metadata. This lets short-lived clients (e.g. the CLI on a CI runner)
/// extend a pipeline trace to the gateway without any collector configuration.
///
/// When `TRACEPARENT` is unset or invalid the captured context carries no
/// valid span, so injection is a no-op.
#[derive(Debug, Clone)]
pub struct EnvTraceContextInterceptor {
    context: Context,
}

impl EnvTraceContextInterceptor {
    /// Capture the W3C trace context from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let env = EnvTraceContext::from_env();
        let context = context_from(&env);
        if env.traceparent.is_some() && !span_context_is_valid(&context) {
            tracing::debug!("TRACEPARENT is set but invalid; not forwarding trace context");
        }
        Self { context }
    }
}

/// Extract a [`Context`] from an [`Extractor`] using a fresh base context, so
/// the result depends only on the extractor and not on any ambient context.
fn context_from(extractor: &impl Extractor) -> Context {
    TraceContextPropagator::new().extract_with_context(&Context::new(), extractor)
}

fn span_context_is_valid(context: &Context) -> bool {
    use opentelemetry::trace::TraceContextExt as _;

    context.span().span_context().is_valid()
}

impl tonic::service::Interceptor for EnvTraceContextInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        TraceContextPropagator::new().inject_context(
            &self.context,
            &mut MetadataMapInjector::new(request.metadata_mut()),
        );
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::service::Interceptor as _;

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

    fn interceptor_with(extractor: EnvTraceContext) -> EnvTraceContextInterceptor {
        EnvTraceContextInterceptor {
            context: context_from(&extractor),
        }
    }

    fn snapshot_env(names: &[&'static str]) -> Vec<(&'static str, Option<String>)> {
        names
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect()
    }

    #[allow(unsafe_code)]
    fn restore_env(saved: &[(&'static str, Option<String>)]) {
        for (name, value) in saved {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn env_trace_context_from_env_reads_both_spellings_and_skips_blanks() {
        let _tracing_lock = crate::test_lock();
        let saved = snapshot_env(&[TRACEPARENT_ENV, "traceparent", TRACESTATE_ENV, "tracestate"]);
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        // Upper-case spelling with surrounding whitespace.
        unsafe {
            std::env::set_var(TRACEPARENT_ENV, format!("  {traceparent}  "));
            std::env::set_var(TRACESTATE_ENV, " vendor=value ");
        }
        let padded = EnvTraceContext::from_env();
        assert_eq!(padded.traceparent.as_deref(), Some(traceparent));
        assert_eq!(padded.tracestate.as_deref(), Some("vendor=value"));

        // Lower-case-only spelling.
        unsafe {
            std::env::remove_var(TRACEPARENT_ENV);
            std::env::remove_var(TRACESTATE_ENV);
            std::env::set_var("traceparent", traceparent);
            std::env::set_var("tracestate", "vendor=value");
        }
        let lower = EnvTraceContext::from_env();
        assert_eq!(lower.traceparent.as_deref(), Some(traceparent));
        assert_eq!(lower.tracestate.as_deref(), Some("vendor=value"));

        // A blank upper-case value must not shadow a valid lower-case one.
        unsafe {
            std::env::set_var(TRACEPARENT_ENV, "   ");
            std::env::remove_var("tracestate");
        }
        let shadowed = EnvTraceContext::from_env();
        assert_eq!(shadowed.traceparent.as_deref(), Some(traceparent));
        assert_eq!(shadowed.tracestate, None);

        // Blank values in both spellings are treated as unset.
        unsafe {
            std::env::set_var("traceparent", "");
        }
        let blank = EnvTraceContext::from_env();
        assert_eq!(blank.traceparent, None);

        restore_env(&saved);
    }

    #[test]
    fn env_interceptor_forwards_valid_traceparent() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut interceptor = interceptor_with(EnvTraceContext {
            traceparent: Some(traceparent.to_string()),
            tracestate: Some("vendor=value".to_string()),
        });

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert_eq!(
            request
                .metadata()
                .get("traceparent")
                .and_then(|value| value.to_str().ok()),
            Some(traceparent)
        );
        assert_eq!(
            request
                .metadata()
                .get("tracestate")
                .and_then(|value| value.to_str().ok()),
            Some("vendor=value")
        );
    }

    #[test]
    fn env_interceptor_is_noop_without_traceparent() {
        let mut interceptor = interceptor_with(EnvTraceContext::default());

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert!(request.metadata().get("traceparent").is_none());
        assert!(request.metadata().get("tracestate").is_none());
    }

    #[test]
    fn env_interceptor_is_noop_for_invalid_traceparent() {
        let mut interceptor = interceptor_with(EnvTraceContext {
            traceparent: Some("not-a-valid-traceparent".to_string()),
            tracestate: Some("vendor=value".to_string()),
        });

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert!(request.metadata().get("traceparent").is_none());
        assert!(request.metadata().get("tracestate").is_none());
    }
}
