// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resource attribution for relayed agent traces.
//!
//! Every forwarded `ResourceSpans` entry carries exactly two supervisor-owned
//! attributes. Agent-supplied values for those keys are always discarded so
//! a workload cannot impersonate another sandbox or pose as infrastructure.
//!
//! Enrichment works at the protobuf wire level. Only each entry's `resource`
//! field is decoded and re-encoded, which drops unknown fields inside it;
//! scopes, spans, and every other field, known or unknown, are copied byte
//! for byte. The agent controls the body, so a full decode would let a 2 MiB
//! request of empty messages materialise hundreds of MiB of structs, and a
//! request of a million empty `ResourceSpans` entries would grow fifty-fold
//! once each gained the two attributes. [`MAX_RESOURCE_BYTES`] and
//! [`MAX_RESOURCE_ATTRIBUTES`] bound the decoded working set per request and
//! [`MAX_RESOURCE_SPANS`] bounds the growth.
//!
//! Memory: the output is the only allocation proportional to the request,
//! sized once for the worst-case growth and shrunk to its length before it
//! is buffered. Each entry is walked twice, once to merge its resource and
//! size the output, once to copy the remaining fields straight into it.

use bytes::{Buf, Bytes};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::encoding::{
    WireType, decode_key, decode_varint, encode_key, encode_varint, encoded_len_varint, key_len,
};
use prost::{DecodeError, Message};

/// Resource attribute carrying the sandbox identifier. Matches the value the
/// supervisor attaches to its own spans.
pub const SANDBOX_ID_KEY: &str = "openshell.sandbox.id";
/// Resource attribute marking the batch as agent-originated.
pub const SOURCE_KEY: &str = "openshell.telemetry.source";
/// Value of [`SOURCE_KEY`] on every relayed batch.
pub const SOURCE_VALUE: &str = "agent";

/// Maximum `ResourceSpans` entries per request.
///
/// An SDK exports one entry per resource; a collector sidecar or a
/// multi-process agent can produce one per distinct resource. The cap bounds
/// how much the two added attributes can grow a request. For batches with
/// many resources [`MAX_RESOURCE_ATTRIBUTES`] binds first: at this many
/// entries each resource may carry about eight attributes.
pub const MAX_RESOURCE_SPANS: usize = 512;
/// Upper bound on the bytes attribution adds to one entry.
///
/// The two string attributes encode to 67 bytes plus the sandbox id, an
/// entry without a resource gains a `resource` field header, and the length
/// prefixes may widen by a byte each: 160 covers sandbox ids of up to 80
/// bytes. Ids are UUID strings today. `growth_bound_holds_at_the_maximum_id`
/// pins it.
pub const ATTRIBUTION_BYTES_PER_ENTRY: usize = 160;
/// Longest sandbox id [`ATTRIBUTION_BYTES_PER_ENTRY`] accounts for.
pub const MAX_SANDBOX_ID_BYTES: usize = 80;
/// Maximum total encoded size of the `resource` fields in one request.
///
/// These are the only bytes that are decoded. Real resources are a few KiB
/// of attributes, so this leaves room for hundreds of distinct resources.
pub const MAX_RESOURCE_BYTES: usize = 256 * 1024;
/// Maximum decoded resource elements in one request, across all entries.
///
/// Counts every `KeyValue`, `AnyValue`, and `EntityRef` the resource decode
/// would materialise, including values nested in `kvlist_value` and
/// `array_value` lists. An empty element is two wire bytes but 32 to 96
/// bytes decoded, so the byte budget alone would admit 130 thousand of them
/// (8 to 12 MiB). Counting them on the wire before decoding keeps the
/// decoded set under about 1 MiB, including the doubling when the two
/// attribution attributes are pushed.
pub const MAX_RESOURCE_ATTRIBUTES: usize = 8192;
/// Nesting depth of attribute values beyond which a resource is rejected as
/// malformed. prost's own limit is 100; real attributes nest once or twice.
pub const MAX_VALUE_DEPTH: usize = 32;

/// `ExportTraceServiceRequest.resource_spans`.
const RESOURCE_SPANS_TAG: u32 = 1;
/// `ResourceSpans.resource`.
const RESOURCE_TAG: u32 = 1;
/// `Resource.attributes`.
const ATTRIBUTES_TAG: u32 = 1;
/// `Resource.entity_refs`.
const ENTITY_REFS_TAG: u32 = 3;
/// `KeyValue.value`.
const KEY_VALUE_VALUE_TAG: u32 = 2;
/// `AnyValue.array_value`.
const ANY_VALUE_ARRAY_TAG: u32 = 5;
/// `AnyValue.kvlist_value`.
const ANY_VALUE_KVLIST_TAG: u32 = 6;
/// `ArrayValue.values` and `KeyValueList.values`.
const LIST_VALUES_TAG: u32 = 1;

const BUFFER_UNDERFLOW: &str = "buffer underflow";

/// The request could not be enriched.
#[derive(Debug)]
pub enum EnrichError {
    /// The bytes are not a well-formed protobuf message for this schema.
    Malformed(String),
    /// More than [`MAX_RESOURCE_SPANS`] entries.
    TooManyResourceSpans,
    /// More than [`MAX_RESOURCE_ATTRIBUTES`] resource attributes in total.
    TooManyResourceAttributes,
    /// The `resource` fields of the request exceed [`MAX_RESOURCE_BYTES`].
    ResourceTooLarge,
}

impl std::fmt::Display for EnrichError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed ExportTraceServiceRequest: {error}"),
            Self::TooManyResourceSpans => {
                write!(f, "more than {MAX_RESOURCE_SPANS} resource_spans entries")
            }
            Self::TooManyResourceAttributes => {
                write!(f, "more than {MAX_RESOURCE_ATTRIBUTES} resource attributes")
            }
            Self::ResourceTooLarge => {
                write!(
                    f,
                    "resource fields exceed {MAX_RESOURCE_BYTES} bytes in total"
                )
            }
        }
    }
}

impl std::error::Error for EnrichError {}

impl From<DecodeError> for EnrichError {
    fn from(error: DecodeError) -> Self {
        Self::Malformed(error.to_string())
    }
}

/// Attributes every resource of a protobuf `ExportTraceServiceRequest`.
///
/// Replaces the two attribution attributes on each `ResourceSpans.resource`
/// and returns the re-encoded request. Everything other than the resources
/// is copied unchanged.
pub fn enrich(raw: &[u8], sandbox_id: &str) -> Result<Bytes, EnrichError> {
    enrich_sized(raw, sandbox_id).map(Bytes::from)
}

/// [`enrich`] as a `Vec` whose capacity equals its length, so the buffer
/// never holds growth slack.
fn enrich_sized(raw: &[u8], sandbox_id: &str) -> Result<Vec<u8>, EnrichError> {
    let mut out = enrich_to_vec(raw, sandbox_id)?;
    out.shrink_to_fit();
    Ok(out)
}

/// [`enrich`] before the final shrink, sized once for the worst-case growth
/// so no entry triggers a doubling reallocation.
fn enrich_to_vec(raw: &[u8], sandbox_id: &str) -> Result<Vec<u8>, EnrichError> {
    let mut out = Vec::with_capacity(raw.len() + MAX_RESOURCE_SPANS * ATTRIBUTION_BYTES_PER_ENTRY);
    let mut entries = 0usize;
    let mut budget = DecodeBudget {
        resource_bytes: MAX_RESOURCE_BYTES,
        elements: MAX_RESOURCE_ATTRIBUTES,
    };
    for_each_field(raw, |tag, wire_type, value, field| {
        if tag == RESOURCE_SPANS_TAG {
            if wire_type != WireType::LengthDelimited {
                return Err(EnrichError::Malformed(
                    "resource_spans is not length-delimited".into(),
                ));
            }
            entries += 1;
            if entries > MAX_RESOURCE_SPANS {
                return Err(EnrichError::TooManyResourceSpans);
            }
            enrich_resource_spans(value, sandbox_id, &mut budget, &mut out)
        } else {
            out.extend_from_slice(field);
            Ok(())
        }
    })?;
    Ok(out)
}

/// What one request may still decode: `resource` bytes and the elements
/// inside them, both counted on the wire before any decoding happens.
struct DecodeBudget {
    resource_bytes: usize,
    elements: usize,
}

impl DecodeBudget {
    fn charge(&mut self, resource: &[u8]) -> Result<(), EnrichError> {
        self.resource_bytes = self
            .resource_bytes
            .checked_sub(resource.len())
            .ok_or(EnrichError::ResourceTooLarge)?;
        let mut elements = 0usize;
        for_each_field(resource, |tag, wire_type, value, _| {
            if wire_type != WireType::LengthDelimited {
                return Ok(());
            }
            match tag {
                ATTRIBUTES_TAG => elements += 1 + key_value_elements(value, 0)?,
                // One `EntityRef` plus each of its repeated id and
                // description keys.
                ENTITY_REFS_TAG => elements += 1 + length_delimited_fields(value)?,
                _ => {}
            }
            Ok(())
        })?;
        self.elements = self
            .elements
            .checked_sub(elements)
            .ok_or(EnrichError::TooManyResourceAttributes)?;
        Ok(())
    }
}

/// Decoded elements nested inside one `KeyValue`: its value and whatever
/// that value lists.
fn key_value_elements(key_value: &[u8], depth: usize) -> Result<usize, EnrichError> {
    let mut elements = 0usize;
    for_each_field(key_value, |tag, wire_type, value, _| {
        if tag == KEY_VALUE_VALUE_TAG && wire_type == WireType::LengthDelimited {
            elements += any_value_elements(value, depth + 1)?;
        }
        Ok(())
    })?;
    Ok(elements)
}

/// Decoded elements for one `AnyValue`: itself plus any list it holds.
fn any_value_elements(any_value: &[u8], depth: usize) -> Result<usize, EnrichError> {
    if depth > MAX_VALUE_DEPTH {
        return Err(EnrichError::Malformed(
            "attribute value nesting too deep".into(),
        ));
    }
    let mut elements = 1usize;
    for_each_field(any_value, |tag, wire_type, list, _| {
        if wire_type != WireType::LengthDelimited {
            return Ok(());
        }
        match tag {
            ANY_VALUE_ARRAY_TAG => for_each_field(list, |tag, wire_type, value, _| {
                if tag == LIST_VALUES_TAG && wire_type == WireType::LengthDelimited {
                    elements += any_value_elements(value, depth + 1)?;
                }
                Ok(())
            })?,
            ANY_VALUE_KVLIST_TAG => for_each_field(list, |tag, wire_type, value, _| {
                if tag == LIST_VALUES_TAG && wire_type == WireType::LengthDelimited {
                    elements += 1 + key_value_elements(value, depth + 1)?;
                }
                Ok(())
            })?,
            _ => {}
        }
        Ok(())
    })?;
    Ok(elements)
}

/// Number of length-delimited fields directly inside `message`.
fn length_delimited_fields(message: &[u8]) -> Result<usize, EnrichError> {
    let mut fields = 0usize;
    for_each_field(message, |_, wire_type, _, _| {
        if wire_type == WireType::LengthDelimited {
            fields += 1;
        }
        Ok(())
    })?;
    Ok(fields)
}

/// Appends one `ResourceSpans` entry to `out` with its resource attributed.
fn enrich_resource_spans(
    entry: &[u8],
    sandbox_id: &str,
    budget: &mut DecodeBudget,
    out: &mut Vec<u8>,
) -> Result<(), EnrichError> {
    // Pass 1: merge the resource and measure everything else.
    let mut resource = Resource::default();
    let mut rest_len = 0usize;
    for_each_field(entry, |tag, wire_type, value, field| {
        if tag == RESOURCE_TAG {
            if wire_type != WireType::LengthDelimited {
                return Err(EnrichError::Malformed(
                    "resource is not length-delimited".into(),
                ));
            }
            budget.charge(value)?;
            // Repeated occurrences of an embedded message merge, as in any
            // protobuf parser.
            resource.merge(value)?;
        } else {
            rest_len += field.len();
        }
        Ok(())
    })?;

    resource
        .attributes
        .retain(|attribute| attribute.key != SANDBOX_ID_KEY && attribute.key != SOURCE_KEY);
    resource
        .attributes
        .push(string_attribute(SANDBOX_ID_KEY, sandbox_id));
    resource
        .attributes
        .push(string_attribute(SOURCE_KEY, SOURCE_VALUE));

    // Pass 2: write the entry header, the resource, then the rest verbatim.
    let resource_len = resource.encoded_len();
    let entry_len =
        key_len(RESOURCE_TAG) + encoded_len_varint(resource_len as u64) + resource_len + rest_len;
    encode_key(RESOURCE_SPANS_TAG, WireType::LengthDelimited, out);
    encode_varint(entry_len as u64, out);
    encode_key(RESOURCE_TAG, WireType::LengthDelimited, out);
    resource
        .encode_length_delimited(out)
        .expect("Vec<u8> grows on demand");
    for_each_field(entry, |tag, _, _, field| {
        if tag != RESOURCE_TAG {
            out.extend_from_slice(field);
        }
        Ok(())
    })
}

/// Walks the top-level fields of `message`, calling `visit(tag, wire_type,
/// value, field)` for each. `value` is the payload of a length-delimited
/// field and empty otherwise; `field` is the complete key-plus-value
/// encoding, for verbatim copying.
fn for_each_field<'a>(
    message: &'a [u8],
    mut visit: impl FnMut(u32, WireType, &'a [u8], &'a [u8]) -> Result<(), EnrichError>,
) -> Result<(), EnrichError> {
    let mut cursor = message;
    while cursor.has_remaining() {
        let start = message.len() - cursor.remaining();
        let (tag, wire_type) = decode_key(&mut cursor)?;
        let value: &'a [u8] = match wire_type {
            WireType::Varint => {
                decode_varint(&mut cursor)?;
                &[]
            }
            WireType::SixtyFourBit => {
                skip(&mut cursor, 8)?;
                &[]
            }
            WireType::ThirtyTwoBit => {
                skip(&mut cursor, 4)?;
                &[]
            }
            WireType::LengthDelimited => {
                let len = usize::try_from(decode_varint(&mut cursor)?)
                    .map_err(|_| EnrichError::Malformed(BUFFER_UNDERFLOW.into()))?;
                if len > cursor.remaining() {
                    return Err(EnrichError::Malformed(BUFFER_UNDERFLOW.into()));
                }
                let value = &cursor[..len];
                cursor.advance(len);
                value
            }
            WireType::StartGroup | WireType::EndGroup => {
                return Err(EnrichError::Malformed("groups are not supported".into()));
            }
        };
        let end = message.len() - cursor.remaining();
        visit(tag, wire_type, value, &message[start..end])?;
    }
    Ok(())
}

fn skip(cursor: &mut &[u8], len: usize) -> Result<(), EnrichError> {
    if cursor.remaining() < len {
        return Err(EnrichError::Malformed(BUFFER_UNDERFLOW.into()));
    }
    cursor.advance(len);
    Ok(())
}

fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        key_strindex: 0,
    }
}

#[cfg(test)]
pub mod test_util {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;

    /// Builds a protobuf-encoded request with one span named `span_name` and
    /// the given string resource attributes.
    pub fn encoded_request(span_name: &str, attributes: &[(&str, &str)]) -> Vec<u8> {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: attributes
                        .iter()
                        .map(|(key, value)| KeyValue {
                            key: (*key).to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue((*value).to_string())),
                            }),
                            key_strindex: 0,
                        })
                        .collect(),
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: span_name.to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    /// Builds a protobuf-encoded request with one span carrying a span
    /// attribute of `payload_bytes` bytes, so the body is large while the
    /// resource stays small.
    pub fn encoded_request_with_large_span(span_name: &str, payload_bytes: usize) -> Vec<u8> {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource::default()),
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: span_name.to_string(),
                        attributes: vec![KeyValue {
                            key: "payload".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "x".repeat(payload_bytes),
                                )),
                            }),
                            key_strindex: 0,
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    /// String-valued resource attributes of the first `ResourceSpans` entry.
    pub fn resource_attributes(encoded: &[u8]) -> Vec<(String, String)> {
        let decoded = ExportTraceServiceRequest::decode(encoded).expect("decodes");
        let resource = decoded.resource_spans[0]
            .resource
            .as_ref()
            .expect("resource present");
        resource
            .attributes
            .iter()
            .filter_map(|attribute| {
                let value = attribute.value.as_ref()?.value.as_ref()?;
                let any_value::Value::StringValue(value) = value else {
                    return None;
                };
                Some((attribute.key.clone(), value.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::InstrumentationScope;
    use opentelemetry_proto::tonic::trace::v1::span::Event;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
    use prost::Message;

    use super::test_util::{encoded_request, resource_attributes};
    use super::*;

    /// Wraps `payload` as one length-delimited field with `tag`.
    fn field(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_key(tag, WireType::LengthDelimited, &mut out);
        encode_varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    /// A `ResourceSpans` entry whose `resource` is `attributes` worth of
    /// empty `KeyValue`s (`0a 00`), the densest decode per wire byte.
    fn entry_with_empty_attributes(attributes: usize) -> Vec<u8> {
        field(
            RESOURCE_SPANS_TAG,
            &field(RESOURCE_TAG, &[0x0a, 0x00].repeat(attributes)),
        )
    }

    #[test]
    fn adds_both_attributes_to_an_empty_resource() {
        let raw = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "s".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();

        let enriched = enrich(&raw, "sb-1").unwrap();
        let attributes = resource_attributes(&enriched);
        assert_eq!(
            attributes,
            vec![
                (SANDBOX_ID_KEY.to_string(), "sb-1".to_string()),
                (SOURCE_KEY.to_string(), SOURCE_VALUE.to_string()),
            ]
        );
    }

    #[test]
    fn replaces_spoofed_values() {
        let raw = encoded_request(
            "s",
            &[(SANDBOX_ID_KEY, "evil"), (SOURCE_KEY, "infrastructure")],
        );
        let enriched = enrich(&raw, "sb-real").unwrap();
        let attributes = resource_attributes(&enriched);
        assert_eq!(
            attributes
                .iter()
                .filter(|(key, _)| key == SANDBOX_ID_KEY)
                .count(),
            1
        );
        assert_eq!(
            attributes
                .iter()
                .filter(|(key, _)| key == SOURCE_KEY)
                .count(),
            1
        );
        assert!(attributes.contains(&(SANDBOX_ID_KEY.to_string(), "sb-real".to_string())));
        assert!(attributes.contains(&(SOURCE_KEY.to_string(), SOURCE_VALUE.to_string())));
        assert!(!attributes.iter().any(|(_, value)| value == "evil"));
        assert!(
            !attributes
                .iter()
                .any(|(_, value)| value == "infrastructure")
        );
    }

    #[test]
    fn replaces_spoofed_keys_regardless_of_value_type() {
        let spoofed = Resource {
            attributes: vec![KeyValue {
                key: SANDBOX_ID_KEY.to_string(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::IntValue(7)),
                }),
                key_strindex: 0,
            }],
            ..Default::default()
        };
        let raw = field(
            RESOURCE_SPANS_TAG,
            &field(RESOURCE_TAG, &spoofed.encode_to_vec()),
        );
        let enriched = enrich(&raw, "sb-real").unwrap();
        let decoded = ExportTraceServiceRequest::decode(enriched.as_ref()).unwrap();
        let keys: Vec<&str> = decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect();
        assert_eq!(keys, vec![SANDBOX_ID_KEY, SOURCE_KEY]);
    }

    #[test]
    fn preserves_other_attributes_and_all_spans() {
        let raw = encoded_request("keep-me", &[("service.name", "unit-agent")]);
        let enriched = enrich(&raw, "sb-1").unwrap();
        let attributes = resource_attributes(&enriched);
        assert!(attributes.contains(&("service.name".to_string(), "unit-agent".to_string())));
        assert_eq!(attributes.len(), 3);

        let decoded = ExportTraceServiceRequest::decode(enriched.as_ref()).unwrap();
        let spans: Vec<&Span> = decoded
            .resource_spans
            .iter()
            .flat_map(|rs| rs.scope_spans.iter())
            .flat_map(|ss| ss.spans.iter())
            .collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name, "keep-me");
    }

    #[test]
    fn copies_scopes_spans_and_schema_url_verbatim() {
        let span = Span {
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            name: "detailed".into(),
            start_time_unix_nano: 10,
            end_time_unix_nano: 20,
            attributes: vec![string_attribute("http.method", "GET")],
            events: vec![Event {
                name: "retry".into(),
                time_unix_nano: 15,
                ..Default::default()
            }],
            status: Some(Status {
                code: 2,
                message: "boom".into(),
            }),
            ..Default::default()
        };
        let original = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![string_attribute("service.name", "a")],
                    dropped_attributes_count: 3,
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "lib".into(),
                        version: "1.2".into(),
                        ..Default::default()
                    }),
                    spans: vec![span],
                    schema_url: "https://schema/scope".into(),
                }],
                schema_url: "https://schema/resource".into(),
            }],
        };

        let enriched = enrich(&original.encode_to_vec(), "sb-1").unwrap();
        let decoded = ExportTraceServiceRequest::decode(enriched.as_ref()).unwrap();
        let entry = &decoded.resource_spans[0];
        assert_eq!(entry.scope_spans, original.resource_spans[0].scope_spans);
        assert_eq!(entry.schema_url, "https://schema/resource");
        let resource = entry.resource.as_ref().unwrap();
        assert_eq!(resource.dropped_attributes_count, 3);
        assert_eq!(resource.attributes.len(), 3);
        assert_eq!(resource.attributes[0].key, "service.name");
    }

    #[test]
    fn copies_unknown_fields_of_every_wire_type_verbatim() {
        // Unknown fields inside an entry, one per wire type, plus an unknown
        // varint field at the request level.
        let mut varint_field = Vec::new();
        encode_key(7, WireType::Varint, &mut varint_field);
        encode_varint(300, &mut varint_field);
        let mut fixed64_field = Vec::new();
        encode_key(8, WireType::SixtyFourBit, &mut fixed64_field);
        fixed64_field.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut fixed32_field = Vec::new();
        encode_key(9, WireType::ThirtyTwoBit, &mut fixed32_field);
        fixed32_field.extend_from_slice(&[9, 10, 11, 12]);
        let delimited_field = field(10, b"opaque");
        let mut entry = Vec::new();
        entry.extend_from_slice(&varint_field);
        entry.extend_from_slice(&field(RESOURCE_TAG, &Resource::default().encode_to_vec()));
        entry.extend_from_slice(&fixed64_field);
        entry.extend_from_slice(&fixed32_field);
        entry.extend_from_slice(&delimited_field);
        let mut request_varint = Vec::new();
        encode_key(2, WireType::Varint, &mut request_varint);
        encode_varint(1, &mut request_varint);
        let mut raw = field(RESOURCE_SPANS_TAG, &entry);
        raw.extend_from_slice(&request_varint);

        let enriched = enrich(&raw, "sb-1").unwrap();
        assert!(ExportTraceServiceRequest::decode(enriched.as_ref()).is_ok());
        let contains = |needle: &[u8]| enriched.windows(needle.len()).any(|w| w == needle);
        for unknown in [
            &varint_field,
            &fixed64_field,
            &fixed32_field,
            &delimited_field,
            &request_varint,
        ] {
            assert!(contains(unknown), "missing {unknown:?}");
        }
        // The non-resource fields keep their relative order after the
        // resource, which is written first.
        let tail: Vec<u8> = [
            varint_field.as_slice(),
            fixed64_field.as_slice(),
            fixed32_field.as_slice(),
            delimited_field.as_slice(),
            request_varint.as_slice(),
        ]
        .concat();
        assert!(enriched.ends_with(&tail));
    }

    #[test]
    fn merges_repeated_resource_fields_like_a_protobuf_parser() {
        // Two `resource` occurrences in one entry: attributes concatenate.
        let first = Resource {
            attributes: vec![string_attribute("a", "1")],
            ..Default::default()
        };
        let second = Resource {
            attributes: vec![string_attribute("b", "2")],
            ..Default::default()
        };
        let mut entry = field(RESOURCE_TAG, &first.encode_to_vec());
        entry.extend_from_slice(&field(RESOURCE_TAG, &second.encode_to_vec()));
        let raw = field(RESOURCE_SPANS_TAG, &entry);

        let enriched = enrich(&raw, "sb-1").unwrap();
        let attributes = resource_attributes(&enriched);
        assert_eq!(
            attributes,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
                (SANDBOX_ID_KEY.to_string(), "sb-1".to_string()),
                (SOURCE_KEY.to_string(), SOURCE_VALUE.to_string()),
            ]
        );
    }

    #[test]
    fn rejects_invalid_bytes() {
        let malformed = |raw: &[u8]| matches!(enrich(raw, "sb-1"), Err(EnrichError::Malformed(_)));
        assert!(malformed(&[0xff, 0xfe, 0xfd, 0xfc]), "invalid key");
        assert!(malformed(&[0x0a, 0x10, 0x00]), "length past the end");
        assert!(malformed(&[0x0b]), "group");
        assert!(malformed(&[0x41, 0x01]), "truncated fixed64");
        assert!(malformed(&[0x4d, 0x01]), "truncated fixed32");
        assert!(
            malformed(&[0x08, 0x01]),
            "resource_spans with a varint wire type"
        );
        assert!(
            malformed(&field(RESOURCE_SPANS_TAG, &[0x08, 0x01])),
            "resource with a varint wire type"
        );
        assert!(
            malformed(&field(
                RESOURCE_SPANS_TAG,
                &field(RESOURCE_TAG, &[0xff, 0xff])
            )),
            "garbage inside the resource"
        );
    }

    #[test]
    fn rejects_more_resource_spans_than_the_cap_before_decoding_them() {
        // Entry MAX+1 carries a malformed resource: the cap trips first, so
        // the error is the cap, not a decode failure.
        let mut raw = [0x0a, 0x00].repeat(MAX_RESOURCE_SPANS);
        raw.extend_from_slice(&field(
            RESOURCE_SPANS_TAG,
            &field(RESOURCE_TAG, &[0xff, 0xff]),
        ));
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::TooManyResourceSpans)
        ));

        let at_cap: Vec<u8> = [0x0a, 0x00].repeat(MAX_RESOURCE_SPANS);
        let enriched = enrich(&at_cap, "sb-1").unwrap();
        let decoded = ExportTraceServiceRequest::decode(enriched.as_ref()).unwrap();
        assert_eq!(decoded.resource_spans.len(), MAX_RESOURCE_SPANS);
    }

    #[test]
    fn growth_bound_holds_at_the_maximum_id() {
        // Resource-less entries gain the most: two attributes plus a new
        // `resource` header plus prefix widening.
        let at_cap: Vec<u8> = [0x0a, 0x00].repeat(MAX_RESOURCE_SPANS);
        let id = "x".repeat(MAX_SANDBOX_ID_BYTES);
        let enriched = enrich(&at_cap, &id).unwrap();
        assert!(
            enriched.len() <= at_cap.len() + MAX_RESOURCE_SPANS * ATTRIBUTION_BYTES_PER_ENTRY,
            "grew by {} per entry, bound is {ATTRIBUTION_BYTES_PER_ENTRY}",
            (enriched.len() - at_cap.len()) / MAX_RESOURCE_SPANS
        );
        let single = enrich(&[0x0a, 0x00], &id).unwrap();
        assert!(single.len() - 2 <= ATTRIBUTION_BYTES_PER_ENTRY);
    }

    #[test]
    fn output_carries_no_spare_capacity_into_the_buffer() {
        // 500 entries (not a power of two, so doubling could not land
        // exactly on the bound) each gaining the attributes: well past the
        // slack an unsized Vec would start with.
        let entries = 500;
        let raw: Vec<u8> = field(
            RESOURCE_SPANS_TAG,
            &field(2, &[0x12, 0x00].repeat(2000)), // a 4 KiB scope_spans
        )
        .repeat(entries);
        let out = enrich_to_vec(&raw, "sb-1").unwrap();
        // Any reallocation would have at least doubled the capacity, so the
        // initial size must still be exact.
        assert_eq!(
            out.capacity(),
            raw.len() + MAX_RESOURCE_SPANS * ATTRIBUTION_BYTES_PER_ENTRY,
            "the output was reallocated"
        );
        let sized = enrich_sized(&raw, "sb-1").unwrap();
        assert_eq!(sized.capacity(), sized.len());
        assert_eq!(sized.len(), out.len());
    }

    #[test]
    fn rejects_nested_elements_beyond_the_cap_before_decoding_them() {
        // One top-level attribute whose value is a list of empty entries:
        // the top-level count is 1, but every entry decodes to a struct. The
        // last entry is a KeyValue prost would reject (its key encoded as a
        // varint), so the result proves the cap tripped before any decoding.
        let mut entries = [0x0a, 0x00].repeat(MAX_RESOURCE_ATTRIBUTES);
        entries.extend_from_slice(&field(LIST_VALUES_TAG, &[0x08, 0x01]));
        let kvlist = field(ANY_VALUE_KVLIST_TAG, &entries);
        let attribute = field(ATTRIBUTES_TAG, &field(KEY_VALUE_VALUE_TAG, &kvlist));
        let raw = field(RESOURCE_SPANS_TAG, &field(RESOURCE_TAG, &attribute));
        assert!(raw.len() < MAX_RESOURCE_BYTES);
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::TooManyResourceAttributes)
        ));

        // Exact boundary: the attribute, its value, and the entries sum to
        // the cap (accepted) or one over it (refused), so the nested count
        // is pinned from both sides.
        let nested_budget = |entries: usize| {
            let kvlist = field(ANY_VALUE_KVLIST_TAG, &[0x0a, 0x00].repeat(entries));
            let attribute = field(ATTRIBUTES_TAG, &field(KEY_VALUE_VALUE_TAG, &kvlist));
            enrich(
                &field(RESOURCE_SPANS_TAG, &field(RESOURCE_TAG, &attribute)),
                "sb-1",
            )
        };
        assert!(nested_budget(MAX_RESOURCE_ATTRIBUTES - 2).is_ok());
        assert!(matches!(
            nested_budget(MAX_RESOURCE_ATTRIBUTES - 1),
            Err(EnrichError::TooManyResourceAttributes)
        ));

        // The same through an array of empty values.
        let array = field(
            ANY_VALUE_ARRAY_TAG,
            &[0x0a, 0x00].repeat(MAX_RESOURCE_ATTRIBUTES + 1),
        );
        let attribute = field(ATTRIBUTES_TAG, &field(KEY_VALUE_VALUE_TAG, &array));
        let raw = field(RESOURCE_SPANS_TAG, &field(RESOURCE_TAG, &attribute));
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::TooManyResourceAttributes)
        ));

        // Entity references are decoded too and count the same way.
        let entity_refs: Vec<u8> = [0x1a, 0x00].repeat(MAX_RESOURCE_ATTRIBUTES + 1);
        let raw = field(RESOURCE_SPANS_TAG, &field(RESOURCE_TAG, &entity_refs));
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::TooManyResourceAttributes)
        ));

        // A realistic nested attribute survives enrichment intact.
        let nested = Resource {
            attributes: vec![KeyValue {
                key: "process.command_args".into(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::ArrayValue(
                        opentelemetry_proto::tonic::common::v1::ArrayValue {
                            values: ["python3", "-c", "main()"]
                                .into_iter()
                                .map(|arg| AnyValue {
                                    value: Some(any_value::Value::StringValue(arg.into())),
                                })
                                .collect(),
                        },
                    )),
                }),
                key_strindex: 0,
            }],
            ..Default::default()
        };
        let raw = field(
            RESOURCE_SPANS_TAG,
            &field(RESOURCE_TAG, &nested.encode_to_vec()),
        );
        let enriched = enrich(&raw, "sb-1").unwrap();
        let decoded = ExportTraceServiceRequest::decode(enriched.as_ref()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();
        assert_eq!(resource.attributes.len(), 3);
        assert_eq!(resource.attributes[0], nested.attributes[0]);
    }

    /// `levels` nested arrays, each holding one `AnyValue`: the innermost
    /// value sits at depth `levels + 1` in the element walk. Arrays cost two
    /// prost nesting levels per array level, so prost's own limit of 100 is
    /// never the one that trips here.
    fn array_nested(levels: usize) -> Vec<u8> {
        let mut value = Vec::new(); // an empty AnyValue
        for _ in 0..levels {
            value = field(ANY_VALUE_ARRAY_TAG, &field(LIST_VALUES_TAG, &value));
        }
        let attribute = field(ATTRIBUTES_TAG, &field(KEY_VALUE_VALUE_TAG, &value));
        field(RESOURCE_SPANS_TAG, &field(RESOURCE_TAG, &attribute))
    }

    #[test]
    fn attribute_value_depth_is_bounded_exactly() {
        assert!(enrich(&array_nested(MAX_VALUE_DEPTH - 1), "sb-1").is_ok());
        assert!(matches!(
            enrich(&array_nested(MAX_VALUE_DEPTH), "sb-1"),
            Err(EnrichError::Malformed(message)) if message.contains("nesting too deep")
        ));
    }

    #[test]
    fn rejects_more_resource_attributes_than_the_cap_before_decoding_them() {
        // Within the byte budget but far over the attribute count: each
        // empty attribute would decode to a 64-byte struct.
        let raw = entry_with_empty_attributes(MAX_RESOURCE_ATTRIBUTES + 1);
        assert!(raw.len() < MAX_RESOURCE_BYTES);
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::TooManyResourceAttributes)
        ));
        // The count is cumulative across entries.
        let half = entry_with_empty_attributes(MAX_RESOURCE_ATTRIBUTES / 2 + 1);
        let two: Vec<u8> = half.repeat(2);
        assert!(matches!(
            enrich(&two, "sb-1"),
            Err(EnrichError::TooManyResourceAttributes)
        ));
        let at_cap = entry_with_empty_attributes(MAX_RESOURCE_ATTRIBUTES);
        assert!(enrich(&at_cap, "sb-1").is_ok());
    }

    /// A `ResourceSpans` entry whose `resource` is one string attribute with
    /// a `payload`-byte value: byte-heavy, attribute-light.
    fn entry_with_large_resource(payload: usize) -> Vec<u8> {
        field(RESOURCE_SPANS_TAG, &large_resource(payload))
    }

    /// A `resource` field holding one string attribute of `payload` bytes.
    fn large_resource(payload: usize) -> Vec<u8> {
        let resource = Resource {
            attributes: vec![string_attribute("blob", &"x".repeat(payload))],
            ..Default::default()
        };
        field(RESOURCE_TAG, &resource.encode_to_vec())
    }

    #[test]
    fn resource_budget_is_cumulative_across_occurrences_and_entries() {
        // One entry, one resource over the budget.
        let over = entry_with_large_resource(MAX_RESOURCE_BYTES);
        assert!(matches!(
            enrich(&over, "sb-1"),
            Err(EnrichError::ResourceTooLarge)
        ));

        // One entry, two resource occurrences that only together exceed it.
        let half = large_resource(MAX_RESOURCE_BYTES / 2);
        let mut entry = half.clone();
        entry.extend_from_slice(&half);
        assert!(matches!(
            enrich(&field(RESOURCE_SPANS_TAG, &entry), "sb-1"),
            Err(EnrichError::ResourceTooLarge)
        ));

        // Many entries whose resources together exceed it.
        let each = entry_with_large_resource(MAX_RESOURCE_BYTES / 4);
        let raw: Vec<u8> = each.repeat(5);
        assert!(matches!(
            enrich(&raw, "sb-1"),
            Err(EnrichError::ResourceTooLarge)
        ));

        // Just under the budget it is accepted.
        let under = entry_with_large_resource(MAX_RESOURCE_BYTES - 64);
        assert!(enrich(&under, "sb-1").is_ok());
    }

    #[test]
    fn a_body_of_a_million_empty_spans_is_copied_verbatim() {
        // One entry holding ~1M empty spans plus one unknown field inside the
        // scope. A decode-and-re-encode implementation would drop the unknown
        // field; the wire-level copy keeps every byte.
        let mut scope: Vec<u8> = [0x12, 0x00].repeat(1024 * 1024); // ScopeSpans.spans, empty
        scope.extend_from_slice(&field(15, b"opaque"));
        let entry = field(2, &scope); // ResourceSpans.scope_spans
        let raw = field(RESOURCE_SPANS_TAG, &entry);

        let enriched = enrich(&raw, "sb-1").unwrap();
        assert!(
            enriched.len() <= raw.len() + ATTRIBUTION_BYTES_PER_ENTRY,
            "growth is two attributes"
        );
        assert!(enriched.ends_with(&entry));
    }
}
