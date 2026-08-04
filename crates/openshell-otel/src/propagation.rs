// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! W3C trace-context propagation for HTTP and tonic transports.

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
