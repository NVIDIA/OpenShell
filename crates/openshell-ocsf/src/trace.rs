// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF trace correlation and optional enrichment at emission.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Trace ID supplied by an OCSF producer.
///
/// The registered extractor returns valid, sampled context from the active
/// span. Gateway context may inherit a caller's traceparent, including before
/// authentication: this value is a correlation hint, not an identity assertion.
/// Explicit callers are responsible for validating their trace IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCorrelation {
    /// W3C trace ID: 32 lowercase hexadecimal characters.
    pub uid: String,
}

static EXTRACTOR: OnceLock<fn() -> Option<TraceCorrelation>> = OnceLock::new();

/// Register the process-wide trace extractor at startup.
///
/// Returns `false` if an extractor is already registered. Without an extractor,
/// events receive only explicitly supplied correlation.
pub fn register_trace_correlation_extractor(extractor: fn() -> Option<TraceCorrelation>) -> bool {
    EXTRACTOR.set(extractor).is_ok()
}

pub fn enrich(event: &mut crate::OcsfEvent) {
    if event.base().trace.is_none()
        && let Some(trace) = EXTRACTOR.get().and_then(|extract| extract())
    {
        event.base_mut().set_trace(trace);
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use openshell_ocsf_validate::validate_event;

    #[test]
    fn all_builders_preserve_explicit_trace_through_typestate_and_roundtrip() {
        let ctx = builders::test_sandbox_context();
        let trace = TraceCorrelation {
            uid: "0af7651916cd43dd8448eb211c80319c".to_string(),
        };
        for context in [
            ContextRef::from(&ctx),
            ContextRef::from(std::sync::Arc::new(ctx.clone())),
        ] {
            let events = [
                NetworkActivityBuilder::new(context.clone())
                    .trace(trace.clone())
                    .dst_endpoint(Endpoint::from_domain("example.com", 443))
                    .build(),
                HttpActivityBuilder::new(context.clone())
                    .trace(trace.clone())
                    .http_request(HttpRequest::new(
                        "GET",
                        Url::new("https", "example.com", "/", 443),
                    ))
                    .build(),
                BaseEventBuilder::new(context.clone())
                    .trace(trace.clone())
                    .build(),
                AppLifecycleBuilder::new(context.clone())
                    .trace(trace.clone())
                    .build(),
                ConfigStateChangeBuilder::new(context.clone())
                    .trace(trace.clone())
                    .build(),
                DetectionFindingBuilder::new(context.clone())
                    .trace(trace.clone())
                    .build(),
                ProcessActivityBuilder::new(context.clone())
                    .trace(trace.clone())
                    .actor_process(Process::new("openshell-sandbox", 1))
                    .process(Process::new("workload", 2))
                    .build(),
                SshActivityBuilder::new(context.clone())
                    .trace(trace.clone())
                    .dst_endpoint(Endpoint::from_ip("192.0.2.1".parse().unwrap(), 22))
                    .build(),
                AuthenticationBuilder::new(
                    context.clone(),
                    User::unidentified(),
                    Service::new("openshell-gateway"),
                )
                .trace(trace.clone())
                .build(),
                ApiActivityBuilder::new(context, "GET /")
                    .trace(trace.clone())
                    .build(),
            ];
            for event in events {
                let value = event.to_json().unwrap();
                assert_eq!(value["device"]["hostname"], ctx.hostname);
                if value["class_uid"] == 3002 {
                    // Authentication's schema does not allow the container profile.
                    assert!(value.get("container").is_none());
                } else {
                    assert_eq!(value["container"]["uid"], ctx.sandbox_id);
                    assert_eq!(value["container"]["name"], ctx.sandbox_name);
                }
                validate_event(&value).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(value["trace"]["uid"], trace.uid);
                assert_eq!(value["trace"].as_object().unwrap().len(), 1);
                let decoded: OcsfEvent = serde_json::from_value(value.clone()).unwrap();
                assert_eq!(decoded.to_json().unwrap(), value);
                assert_eq!(
                    value["metadata"]["profiles"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|p| *p == "trace")
                        .count(),
                    1
                );
                let mut plain = value;
                plain.as_object_mut().unwrap().remove("trace");
                plain["metadata"]["profiles"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|name| name != "trace");
                validate_event(&plain).unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }

    #[test]
    fn production_event_shapes_validate_with_and_without_trace() {
        let trace = TraceCorrelation {
            uid: "0af7651916cd43dd8448eb211c80319c".to_string(),
        };
        for ctx in [
            builders::test_sandbox_context(),
            builders::test_gateway_context(),
        ] {
            for (class, mut event) in builders::sample_events(&ctx) {
                let plain = event.to_json().unwrap();
                validate_event(&plain).unwrap_or_else(|e| panic!("{class} without trace: {e}"));
                event.base_mut().set_trace(trace.clone());
                let correlated = event.to_json().unwrap();
                validate_event(&correlated).unwrap_or_else(|e| panic!("{class} with trace: {e}"));
            }
        }
    }

    #[test]
    fn required_typestate_transitions_allow_replacing_explicit_trace() {
        let ctx = builders::test_sandbox_context();
        let initial = TraceCorrelation {
            uid: "0af7651916cd43dd8448eb211c80319c".to_string(),
        };
        let replacement = TraceCorrelation {
            uid: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        };
        let events = [
            ProcessActivityBuilder::new(&ctx)
                .trace(initial.clone())
                .actor_process(Process::new("openshell-sandbox", 1))
                .trace(replacement.clone())
                .build(),
            SshActivityBuilder::new(&ctx)
                .trace(initial.clone())
                .src_endpoint_addr("192.0.2.1".parse().unwrap(), 22)
                .trace(replacement.clone())
                .dst_endpoint(Endpoint::from_domain("sandbox.local", 22))
                .build(),
            SshActivityBuilder::new(&ctx)
                .trace(initial)
                .dst_endpoint(Endpoint::from_domain("sandbox.local", 22))
                .trace(replacement.clone())
                .src_endpoint_addr("192.0.2.1".parse().unwrap(), 22)
                .build(),
        ];
        for event in events {
            let value = event.to_json().unwrap();
            assert_eq!(value["trace"]["uid"], replacement.uid);
            validate_event(&value).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn exported_schema_checks_trace_shape_and_declared_profile() {
        let ctx = builders::test_sandbox_context();
        let mut value = BaseEventBuilder::new(&ctx)
            .trace(TraceCorrelation {
                uid: "0af7651916cd43dd8448eb211c80319c".to_string(),
            })
            .build()
            .to_json()
            .unwrap();
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
