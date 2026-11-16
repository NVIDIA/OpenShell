// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF trace correlation and optional enrichment at emission.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// W3C trace ID of the span active when an OCSF event was emitted.
///
/// This is a correlation hint, not an identity assertion: gateway context may
/// inherit a caller's traceparent, including before authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TraceFields")]
pub struct TraceCorrelation {
    uid: String,
}

#[derive(Deserialize)]
struct TraceFields {
    uid: String,
}

impl TryFrom<TraceFields> for TraceCorrelation {
    type Error = &'static str;

    fn try_from(fields: TraceFields) -> Result<Self, Self::Error> {
        let uid = fields.uid;
        let hex = uid.len() == 32 && uid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !hex || uid.bytes().all(|b| b == b'0') {
            return Err("trace.uid must be a non-zero W3C trace ID in lowercase hex");
        }
        Ok(Self { uid })
    }
}

impl TraceCorrelation {
    /// Returns `None` for the invalid all-zero trace ID.
    #[must_use]
    pub fn from_trace_id(trace_id: [u8; 16]) -> Option<Self> {
        if trace_id == [0; 16] {
            return None;
        }
        Some(Self {
            uid: format!("{:032x}", u128::from_be_bytes(trace_id)),
        })
    }

    /// The trace ID as 32 lowercase hexadecimal characters.
    #[must_use]
    pub fn uid(&self) -> &str {
        &self.uid
    }
}

static EXTRACTOR: OnceLock<fn() -> Option<TraceCorrelation>> = OnceLock::new();

/// Register the process-wide trace extractor at startup.
///
/// Returns `false` if an extractor is already registered. Without an extractor,
/// events carry no trace correlation.
pub fn register_trace_correlation_extractor(extractor: fn() -> Option<TraceCorrelation>) -> bool {
    EXTRACTOR.set(extractor).is_ok()
}

/// HTTP Activity and API Activity: the classes OCSF 1.8.0 declares the Trace
/// profile for.
pub const fn accepts_trace(class_uid: u32) -> bool {
    matches!(class_uid, 4002 | 6003)
}

pub fn enrich(event: &mut crate::OcsfEvent) {
    if accepts_trace(event.class_uid())
        && event.base().trace.is_none()
        && let Some(trace) = EXTRACTOR.get().and_then(|extract| extract())
    {
        event.base_mut().set_trace(trace);
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use openshell_ocsf_validate::validate_event;

    const TRACE_ID: [u8; 16] = [
        0x0a, 0xf7, 0x65, 0x19, 0x16, 0xcd, 0x43, 0xdd, 0x84, 0x48, 0xeb, 0x21, 0x1c, 0x80, 0x31,
        0x9c,
    ];

    fn trace() -> TraceCorrelation {
        TraceCorrelation::from_trace_id(TRACE_ID).unwrap()
    }

    #[test]
    fn trace_id_renders_as_lowercase_w3c_hex() {
        assert_eq!(trace().uid(), "0af7651916cd43dd8448eb211c80319c");
        assert!(TraceCorrelation::from_trace_id([0; 16]).is_none());
    }

    #[test]
    fn deserialization_rejects_malformed_trace_ids() {
        let valid = serde_json::json!({"uid": "0af7651916cd43dd8448eb211c80319c"});
        assert_eq!(
            serde_json::from_value::<TraceCorrelation>(valid).unwrap(),
            trace()
        );
        for uid in [
            "",
            "0AF7651916CD43DD8448EB211C80319C",
            "0af7651916cd43dd8448eb211c80319",
            "0af7651916cd43dd8448eb211c80319cz",
            "00000000000000000000000000000000",
        ] {
            assert!(
                serde_json::from_value::<TraceCorrelation>(serde_json::json!({ "uid": uid }))
                    .is_err(),
                "{uid:?} accepted"
            );
        }
    }

    #[test]
    fn production_event_shapes_validate_with_and_without_trace() {
        let ctx = builders::test_sandbox_context();
        for (class, mut event) in builders::sample_events(&ctx) {
            let plain = event.to_json().unwrap();
            validate_event(&plain).unwrap_or_else(|e| panic!("{class} without trace: {e}"));
            event.base_mut().set_trace(trace());
            let correlated = event.to_json().unwrap();
            validate_event(&correlated).unwrap_or_else(|e| panic!("{class} with trace: {e}"));
            if matches!(class, "http_activity" | "api_activity") {
                assert_eq!(correlated["trace"]["uid"], trace().uid(), "{class}");
            } else {
                assert_eq!(correlated, plain, "{class}");
            }
            let decoded: OcsfEvent = serde_json::from_value(correlated.clone()).unwrap();
            assert_eq!(decoded.to_json().unwrap(), correlated);
        }
    }

    #[test]
    fn deserialized_trace_is_dropped_from_classes_without_the_profile() {
        let ctx = builders::test_sandbox_context();
        let (_, event) = builders::sample_events(&ctx)
            .into_iter()
            .find(|(class, _)| *class == "network_activity")
            .unwrap();
        let mut value = event.to_json().unwrap();
        value["trace"] = serde_json::json!({"uid": trace().uid()});
        let decoded: OcsfEvent = serde_json::from_value(value).unwrap();
        assert!(decoded.to_json().unwrap().get("trace").is_none());
    }

    #[test]
    fn gateway_api_activity_shapes_validate_with_trace() {
        let ctx = builders::test_gateway_context();
        let events = [
            ApiActivityBuilder::new(&ctx, "CreateSandbox").build(),
            ApiActivityBuilder::new(&ctx, "CreateSandbox")
                .action(ActionId::Denied)
                .build(),
            ApiActivityBuilder::new(&ctx, "chat.completions")
                .ai_model(AiModel::new("model", "provider"))
                .build(),
        ];
        for mut event in events {
            event.base_mut().set_trace(trace());
            let correlated = event.to_json().unwrap();
            validate_event(&correlated).unwrap_or_else(|e| panic!("{correlated}: {e}"));
            assert_eq!(correlated["trace"]["uid"], trace().uid());
        }
    }

    #[test]
    fn exported_schema_checks_trace_shape_and_declared_profile() {
        let ctx = builders::test_sandbox_context();
        let (_, mut event) = builders::sample_events(&ctx)
            .into_iter()
            .find(|(class, _)| *class == "http_activity")
            .unwrap();
        event.base_mut().set_trace(trace());
        let mut value = event.to_json().unwrap();
        validate_event(&value).unwrap_or_else(|e| panic!("{e}"));
        value["trace"]["uid"] = serde_json::json!(42);
        assert!(matches!(
            validate_event(&value),
            Err(openshell_ocsf_validate::Error::Invalid(_))
        ));
        value["trace"] = serde_json::json!({});
        assert!(matches!(
            validate_event(&value),
            Err(openshell_ocsf_validate::Error::Invalid(_))
        ));
        value["trace"] =
            serde_json::json!({"uid": "0af7651916cd43dd8448eb211c80319c", "bogus": true});
        assert!(matches!(
            validate_event(&value),
            Err(openshell_ocsf_validate::Error::Invalid(_))
        ));
        value["trace"].as_object_mut().unwrap().remove("bogus");
        value["metadata"]["profiles"]
            .as_array_mut()
            .unwrap()
            .retain(|name| name != "trace");
        assert!(matches!(
            validate_event(&value),
            Err(openshell_ocsf_validate::Error::Invalid(_))
        ));
    }

    #[test]
    fn plain_event_omits_trace_profile_and_object() {
        let ctx = builders::test_sandbox_context();
        let value = BaseEventBuilder::new(&ctx).build().to_json().unwrap();
        assert!(value.get("trace").is_none());
        assert!(
            !value["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "trace")
        );
    }
}
