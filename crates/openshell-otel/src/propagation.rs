// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! W3C trace-context propagation for HTTP and tonic transports.

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
            traceparent: read_env("TRACEPARENT"),
            tracestate: read_env("TRACESTATE"),
        }
    }
}

/// Read an environment variable by its upper-case name, falling back to the
/// lower-case spelling, trimming whitespace and discarding blank values.
fn read_env(upper: &str) -> Option<String> {
    std::env::var(upper)
        .ok()
        .or_else(|| std::env::var(upper.to_ascii_lowercase()).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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
        Self {
            context: context_from(&EnvTraceContext::from_env()),
        }
    }
}

/// Extract a [`Context`] from an [`Extractor`] using a fresh base context, so
/// the result depends only on the extractor and not on any ambient context.
fn context_from(extractor: &impl Extractor) -> Context {
    TraceContextPropagator::new().extract_with_context(&Context::new(), extractor)
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
            tracestate: None,
        });

        let request = interceptor.call(tonic::Request::new(())).unwrap();

        assert!(request.metadata().get("traceparent").is_none());
    }
}
