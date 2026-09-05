// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Span enrichment: injects sandbox resource attributes into OTLP trace data.

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;

use super::SandboxMetadata;

/// Content type of the incoming OTLP request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Protobuf,
    Json,
}

/// Enrich spans with sandbox resource attributes. Input can be protobuf or
/// JSON-encoded `ExportTraceServiceRequest`. Output is always protobuf.
///
/// When `enrichment_enabled` is false, sandbox metadata attributes are skipped
/// but `openshell.telemetry.source: "agent"` is always injected (relay marker).
pub fn enrich_spans(
    raw: &[u8],
    content_type: ContentType,
    attrs: &SandboxMetadata,
    enrichment_enabled: bool,
) -> Result<Vec<u8>, EnrichmentError> {
    let mut request = match content_type {
        ContentType::Protobuf => {
            ExportTraceServiceRequest::decode(raw).map_err(EnrichmentError::ProtobufDecode)?
        }
        ContentType::Json => serde_json::from_slice::<ExportTraceServiceRequest>(raw)
            .map_err(EnrichmentError::JsonDecode)?,
    };

    let extra_attrs = build_attributes(attrs, enrichment_enabled);

    for resource_spans in &mut request.resource_spans {
        let resource = resource_spans
            .resource
            .get_or_insert_with(Resource::default);

        for attr in &extra_attrs {
            resource.attributes.push(attr.clone());
        }
    }

    Ok(request.encode_to_vec())
}

fn build_attributes(meta: &SandboxMetadata, enrichment_enabled: bool) -> Vec<KeyValue> {
    let mut attrs = Vec::new();

    // Always inject the relay routing marker regardless of enrichment toggle
    attrs.push(kv("openshell.telemetry.source", "agent"));

    if enrichment_enabled {
        attrs.push(kv("openshell.sandbox.id", &meta.sandbox_id));
        attrs.push(kv("openshell.workspace.id", &meta.workspace_id));
        attrs.push(kv("openshell.sandbox.policy", &meta.policy));
        attrs.push(kv("openshell.sandbox.user", &meta.user));
        attrs.push(kv("openshell.sandbox.image", &meta.image));
        attrs.push(kv("openshell.sandbox.driver", &meta.driver));
    }

    attrs
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(
                opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                    value.to_string(),
                ),
            ),
        }),
        key_strindex: 0,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrichmentError {
    #[error("protobuf decode failed: {0}")]
    ProtobufDecode(prost::DecodeError),
    #[error("JSON decode failed: {0}")]
    JsonDecode(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;

    fn test_metadata() -> SandboxMetadata {
        SandboxMetadata {
            sandbox_id: "sb-123".into(),
            workspace_id: "ws-456".into(),
            policy: "default".into(),
            user: "test-user".into(),
            image: "test-image:latest".into(),
            driver: "docker".into(),
        }
    }

    fn make_trace_request() -> Vec<u8> {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        name: "test-span".into(),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        req.encode_to_vec()
    }

    #[test]
    fn enrichment_adds_all_attributes() {
        let raw = make_trace_request();
        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), true).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();

        let attr_keys: Vec<&str> = resource.attributes.iter().map(|a| a.key.as_str()).collect();
        assert!(attr_keys.contains(&"openshell.sandbox.id"));
        assert!(attr_keys.contains(&"openshell.workspace.id"));
        assert!(attr_keys.contains(&"openshell.telemetry.source"));
    }

    #[test]
    fn enrichment_disabled_only_adds_source() {
        let raw = make_trace_request();
        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), false).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();

        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "openshell.telemetry.source");
    }
}
