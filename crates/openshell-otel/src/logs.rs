// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC log export support.

use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::{LogExporter, WithTonicConfig};

use crate::{OtlpTarget, SetupError};

impl OtlpTarget {
    /// Build a log exporter for this target. Callers attach
    /// [`Self::resource`] to it.
    pub fn log_exporter(&self) -> Result<LogExporter, SetupError> {
        self.log_exporter_with_headers(None)
    }

    /// Build a log exporter that sends `headers`, in the
    /// `OTEL_EXPORTER_OTLP_HEADERS` format, with every request. Headers from
    /// the process environment still apply and take precedence.
    pub fn log_exporter_with_headers(
        &self,
        headers: Option<&str>,
    ) -> Result<LogExporter, SetupError> {
        let mut builder = self.configure(LogExporter::builder().with_tonic());
        if let Some(headers) = headers {
            builder = builder.with_metadata(header_metadata(headers));
        }
        Ok(builder.build()?)
    }
}

/// Parse headers the way the SDK parses `OTEL_EXPORTER_OTLP_HEADERS`:
/// comma-separated `key=value` pairs with percent-encoded values. Entries
/// that are empty or not valid gRPC metadata are skipped.
fn header_metadata(headers: &str) -> MetadataMap {
    let mut metadata = HeaderMap::new();
    for (key, value) in headers.split_terminator(',').filter_map(|entry| {
        let (key, value) = entry.trim().split_once('=')?;
        let (key, value) = (key.trim(), value.trim());
        let value = percent_decode(value).unwrap_or_else(|| value.to_string());
        (!key.is_empty() && !value.is_empty()).then_some((key.to_string(), value))
    }) {
        if let (Ok(key), Ok(value)) = (
            HeaderName::try_from(key),
            HeaderValue::try_from(value.as_str()),
        ) {
            metadata.insert(key, value);
        }
    }
    MetadataMap::from_headers(metadata)
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use crate::{OtlpExportConfig, OtlpTarget, ServiceName, SetupError};

    fn config(endpoint: &str) -> OtlpExportConfig<'_> {
        OtlpExportConfig {
            endpoint,
            service_name: ServiceName::Fixed("openshell-gateway"),
            service_version: Some("1.2.3"),
            resource_attributes: Vec::new(),
        }
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        assert!(matches!(
            OtlpTarget::new(&config("  ")),
            Err(SetupError::EmptyEndpoint)
        ));
    }

    #[test]
    fn malformed_endpoint_is_rejected() {
        assert!(matches!(
            OtlpTarget::new(&config("not a uri")),
            Err(SetupError::InvalidEndpoint { .. })
        ));
    }

    #[test]
    fn headers_parse_like_the_sdk_environment_variable() {
        let metadata = super::header_metadata(
            "authorization=Bearer%20secret, x-tenant = blue ,=empty-key,no-value=,bad",
        );
        assert_eq!(
            metadata.get("authorization").unwrap().to_str().unwrap(),
            "Bearer secret"
        );
        assert_eq!(metadata.get("x-tenant").unwrap().to_str().unwrap(), "blue");
        assert_eq!(metadata.len(), 2);
    }

    #[test]
    fn malformed_percent_encoding_is_kept_verbatim() {
        let metadata = super::header_metadata("token=abc%zz");
        assert_eq!(metadata.get("token").unwrap().to_str().unwrap(), "abc%zz");
    }

    #[tokio::test]
    async fn every_signal_shares_the_target_resource() {
        let target = OtlpTarget::new(&config("http://127.0.0.1:4317")).unwrap();
        target.log_exporter().expect("log exporter");
        target.tracer_provider().expect("tracer provider");
        let value = |key| {
            target
                .resource()
                .get(&opentelemetry::Key::from_static_str(key))
                .map(|value| value.to_string())
        };
        assert_eq!(value("service.name").as_deref(), Some("openshell-gateway"));
        assert_eq!(value("service.version").as_deref(), Some("1.2.3"));
    }
}
