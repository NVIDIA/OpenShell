// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/HTTP JSON request bodies.
//!
//! Enrichment works on protobuf bytes, so a JSON body is first transcoded to
//! protobuf with the serde impls of `opentelemetry-proto`. Those impls decode
//! the whole request, and what a body allocates grows with the number of
//! values it holds times how deeply they nest, not with its size: serde
//! buffers each `AnyValue` and copies that buffer again at every nested
//! `arrayValue` or `kvlistValue`. [`check_shape`] therefore scans the body
//! without allocating and refuses one that nests deeper than [`MAX_DEPTH`] or
//! holds more than [`MAX_VALUES`] values before anything is decoded.
//!
//! Memory: within both limits, decoding and re-encoding peaked at about 44 MiB
//! in the worst shape tried (a list of about 49 thousand strings inside an
//! `arrayValue` nested seven levels deep), about 17 MiB for 50 thousand empty
//! spans, and under 3 MiB for span batches of a realistic shape with the same
//! value count.
//!
//! The decoder follows the proto3 JSON mapping with two known gaps in
//! `opentelemetry-proto` 0.33: an `arrayValue` or `kvlistValue` must carry
//! its `values` field even when empty, and a `doubleValue` must be a JSON
//! number, so `"NaN"` is refused. Both answer 400.

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message as _;

use super::enrichment::EnrichError;

/// Deepest container nesting a JSON body may have, counting the request
/// object itself. A span attribute's value sits ten levels down, so seven
/// levels of nested `AnyValue` fit.
pub const MAX_DEPTH: usize = 32;
/// Most values a JSON body may hold, counted as every `{`, `[` and `,`
/// outside strings: the containers plus the separators. A batch of 512
/// spans with ten attributes each holds about 25 thousand.
pub const MAX_VALUES: usize = 100_000;
/// Longest decoder message returned to the agent. `serde_json` echoes the
/// offending string, which can be as long as the body.
const MAX_ERROR_BYTES: usize = 1024;

/// Converts an OTLP/HTTP JSON body to the protobuf wire format that
/// enrichment works on.
pub fn transcode(body: &[u8]) -> Result<Vec<u8>, EnrichError> {
    check_shape(body)?;
    serde_json::from_slice::<ExportTraceServiceRequest>(body)
        .map(|request| request.encode_to_vec())
        .map_err(|error| EnrichError::Malformed(bounded(error.to_string())))
}

/// Rejects a body that nests deeper than [`MAX_DEPTH`] or holds more than
/// [`MAX_VALUES`] values, in one pass that allocates nothing. Invalid JSON
/// passes; the decoder reports it.
fn check_shape(body: &[u8]) -> Result<(), EnrichError> {
    let (mut depth, mut values, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for &byte in body {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                values += 1;
                if depth > MAX_DEPTH {
                    return Err(EnrichError::JsonTooComplex);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' => values += 1,
            _ => {}
        }
        if values > MAX_VALUES {
            return Err(EnrichError::JsonTooComplex);
        }
    }
    Ok(())
}

/// Cuts `message` to [`MAX_ERROR_BYTES`] on a character boundary.
fn bounded(mut message: String) -> String {
    if message.len() > MAX_ERROR_BYTES {
        message.truncate(message.floor_char_boundary(MAX_ERROR_BYTES));
        message.push_str("...");
    }
    message
}

#[cfg(test)]
pub mod test_util {
    /// A request whose single span has one attribute with the given JSON
    /// `AnyValue`.
    pub fn with_attribute_value(value: &str) -> String {
        format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{"attributes":[{{"key":"k","value":{value}}}]}}]}}]}}]}}"#
        )
    }

    /// A request whose attribute holds `zeros` scalars inside `levels`
    /// nested `arrayValue`s. It has few braces, so counting `{` alone admits
    /// it, but decoding it copies the scalars once per level.
    pub fn nested_attribute_body(levels: usize, zeros: usize) -> String {
        let mut value = format!(r#"{{"x":[{}]}}"#, vec!["0"; zeros].join(","));
        for _ in 0..levels {
            value = format!(r#"{{"arrayValue":{{"values":[{value}]}}}}"#);
        }
        with_attribute_value(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::{nested_attribute_body, with_attribute_value};
    use super::*;

    fn too_complex(body: &str) -> bool {
        matches!(
            check_shape(body.as_bytes()),
            Err(EnrichError::JsonTooComplex)
        )
    }

    #[test]
    fn depth_limit_is_inclusive() {
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(!too_complex(&nested(MAX_DEPTH)));
        assert!(too_complex(&nested(MAX_DEPTH + 1)));
    }

    #[test]
    fn value_limit_is_inclusive() {
        // `[` plus one comma per further element is one value per element.
        let list = |elements: usize| format!("[{}]", vec!["0"; elements].join(","));
        assert!(!too_complex(&list(MAX_VALUES)));
        assert!(too_complex(&list(MAX_VALUES + 1)));
    }

    #[test]
    fn brackets_and_commas_inside_strings_are_not_counted() {
        let text = "{[,".repeat(MAX_VALUES);
        assert!(!too_complex(&format!(r#"{{"stringValue":"{text}"}}"#)));
        // An escaped quote does not end the string.
        let escaped = r#"\",{[,"#.repeat(MAX_VALUES);
        assert!(!too_complex(&format!(r#"{{"stringValue":"{escaped}"}}"#)));
    }

    #[test]
    fn nested_values_are_refused_before_decoding() {
        assert!(matches!(
            transcode(nested_attribute_body(39, 20_000).as_bytes()),
            Err(EnrichError::JsonTooComplex)
        ));
    }

    /// Shaped like the JSON written by the JavaScript OTLP exporter that
    /// Claude Code uses: integer and string 64-bit values, hex IDs of either
    /// case, every `AnyValue` variant, events, links and a status.
    const EXPORTER_SHAPED: &str = r#"{
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "claude-code"}},
                    {"key": "process.pid", "value": {"intValue": 4242}}
                ],
                "droppedAttributesCount": 0
            },
            "scopeSpans": [{
                "scope": {"name": "claude-code.tracing", "version": "1.0.0"},
                "spans": [{
                    "traceId": "5B8EFFF798038103D269B633813FC60C",
                    "spanId": "eee19b7ec3c1b174",
                    "parentSpanId": "eee19b7ec3c1b173",
                    "name": "llm_request",
                    "kind": 3,
                    "startTimeUnixNano": "1544712660000000000",
                    "endTimeUnixNano": 1544712661000000000,
                    "attributes": [
                        {"key": "tokens", "value": {"intValue": "123"}},
                        {"key": "cost", "value": {"doubleValue": 0.25}},
                        {"key": "ok", "value": {"boolValue": true}},
                        {"key": "blob", "value": {"bytesValue": "AQID"}},
                        {"key": "list", "value": {"arrayValue": {"values": [
                            {"stringValue": "a"}, {"intValue": 1}
                        ]}}},
                        {"key": "map", "value": {"kvlistValue": {"values": [
                            {"key": "inner", "value": {"stringValue": "b"}}
                        ]}}}
                    ],
                    "droppedAttributesCount": 0,
                    "events": [{
                        "timeUnixNano": "1544712660500000000",
                        "name": "prompt",
                        "attributes": [],
                        "droppedAttributesCount": 0
                    }],
                    "droppedEventsCount": 0,
                    "links": [{
                        "traceId": "5b8efff798038103d269b633813fc60c",
                        "spanId": "eee19b7ec3c1b172",
                        "attributes": [],
                        "droppedAttributesCount": 0
                    }],
                    "droppedLinksCount": 0,
                    "status": {"code": 1}
                }]
            }]
        }]
    }"#;

    #[test]
    fn exporter_shaped_payload_is_transcoded() {
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};

        let protobuf = transcode(EXPORTER_SHAPED.as_bytes()).expect("transcoded");
        let request = ExportTraceServiceRequest::decode(protobuf.as_slice()).expect("protobuf");
        let resource = &request.resource_spans[0];
        let process_pid = &resource.resource.as_ref().expect("resource").attributes[1];
        assert_eq!(
            process_pid.value,
            Some(AnyValue {
                value: Some(Value::IntValue(4242))
            })
        );
        let span = &resource.scope_spans[0].spans[0];
        assert_eq!(span.name, "llm_request");
        assert_eq!(span.kind, 3);
        assert_eq!(span.start_time_unix_nano, 1_544_712_660_000_000_000);
        assert_eq!(span.end_time_unix_nano, 1_544_712_661_000_000_000);
        assert_eq!(span.trace_id[0], 0x5b);
        assert_eq!(span.trace_id[15], 0x0c);
        assert_eq!(span.parent_span_id[7], 0x73);
        let attribute = |index: usize| -> &KeyValue { &span.attributes[index] };
        let value = |index: usize| attribute(index).value.clone().expect("value").value;
        assert_eq!(value(0), Some(Value::IntValue(123)));
        assert_eq!(value(1), Some(Value::DoubleValue(0.25)));
        assert_eq!(value(2), Some(Value::BoolValue(true)));
        assert_eq!(value(3), Some(Value::BytesValue(vec![1, 2, 3])));
        assert!(matches!(value(4), Some(Value::ArrayValue(list)) if list.values.len() == 2));
        assert!(matches!(value(5), Some(Value::KvlistValue(map)) if map.values.len() == 1));
        assert_eq!(span.events[0].name, "prompt");
        assert_eq!(span.links[0].span_id[7], 0x72);
        assert_eq!(span.status.as_ref().expect("status").code, 1);
    }

    #[test]
    fn known_decoder_gaps_answer_malformed() {
        // Valid OTLP/JSON that `opentelemetry-proto` 0.33 cannot decode. This
        // pins the documented behavior so a dependency update that lifts the
        // gaps updates the docs with it.
        for value in [
            r#"{"arrayValue":{}}"#,
            r#"{"kvlistValue":{}}"#,
            r#"{"doubleValue":"NaN"}"#,
        ] {
            assert!(
                matches!(
                    transcode(with_attribute_value(value).as_bytes()),
                    Err(EnrichError::Malformed(_))
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn decoder_message_is_bounded() {
        let text = "\u{200b}".repeat(300_000);
        let body = format!(r#"{{"resourceSpans":"{text}"}}"#);
        let Err(EnrichError::Malformed(message)) = transcode(body.as_bytes()) else {
            panic!("a string is not a list of resource spans");
        };
        assert!(message.len() <= MAX_ERROR_BYTES + 3, "{}", message.len());
        assert!(message.ends_with("..."));
    }
}
