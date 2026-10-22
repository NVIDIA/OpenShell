// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF trace correlation and optional enrichment at emission.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Trace ID supplied by a trusted producer.
///
/// The registered extractor must return valid, sampled context from trusted
/// spans. Explicit callers are responsible for validating their trace IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCorrelation {
    /// W3C trace ID: 32 lowercase hexadecimal characters.
    pub uid: String,
}

static EXTRACTOR: OnceLock<fn() -> Option<TraceCorrelation>> = OnceLock::new();

/// Register the process-wide trusted trace extractor at startup.
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
    use crate::validation::schema::{
        load_class_schema, load_object_schema, validate_known_fields, validate_required_fields,
    };
    use crate::*;

    #[test]
    fn all_builders_preserve_explicit_trace_through_typestate_and_roundtrip() {
        let ctx = builders::test_sandbox_context();
        let trace = TraceCorrelation {
            uid: "0af7651916cd43dd8448eb211c80319c".to_string(),
        };
        let events = [
            NetworkActivityBuilder::new(&ctx)
                .trace(trace.clone())
                .dst_endpoint(Endpoint::from_domain("example.com", 443))
                .build(),
            HttpActivityBuilder::new(&ctx)
                .trace(trace.clone())
                .http_request(HttpRequest::new(
                    "GET",
                    Url::new("https", "example.com", "/", 443),
                ))
                .build(),
            BaseEventBuilder::new(&ctx).trace(trace.clone()).build(),
            AppLifecycleBuilder::new(&ctx).trace(trace.clone()).build(),
            ConfigStateChangeBuilder::new(&ctx)
                .trace(trace.clone())
                .build(),
            DetectionFindingBuilder::new(&ctx)
                .trace(trace.clone())
                .build(),
            ProcessActivityBuilder::new(&ctx)
                .trace(trace.clone())
                .actor_process(Process::new("openshell-sandbox", 1))
                .process(Process::new("workload", 2))
                .build(),
            SshActivityBuilder::new(&ctx)
                .trace(trace.clone())
                .dst_endpoint(Endpoint::from_ip("192.0.2.1".parse().unwrap(), 22))
                .build(),
            AuthenticationBuilder::new(
                &ctx,
                User::unidentified(),
                Service::new("openshell-gateway"),
            )
            .trace(trace.clone())
            .build(),
            ApiActivityBuilder::new(&ctx, "GET /")
                .trace(trace.clone())
                .build(),
        ];
        let schema = load_object_schema("trace");
        let profile: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/ocsf/v1.8.0/profiles/trace.json"))
                .unwrap();
        assert_eq!(profile["attributes"]["trace"]["object_type"], "trace");
        for event in events {
            let value = event.to_json().unwrap();
            let class = match value["class_uid"].as_u64().unwrap() {
                0 => "base_event",
                4001 => "network_activity",
                4002 => "http_activity",
                4007 => "ssh_activity",
                1007 => "process_activity",
                3002 => "authentication",
                2004 => "detection_finding",
                6002 => "application_lifecycle",
                5019 => "device_config_state_change",
                6003 => "api_activity",
                uid => panic!("missing schema coverage for class {uid}"),
            };
            let class_schema = load_class_schema(class);
            validate_required_fields(&value, &class_schema);
            // Check correlation separately from native conformance work in #4283.
            validate_known_fields(
                &serde_json::json!({
                    "metadata": value["metadata"],
                    "trace": value["trace"],
                }),
                &class_schema,
            );
            validate_required_fields(&value["trace"], &schema);
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
            validate_required_fields(&plain, &class_schema);
        }
    }

    #[test]
    fn every_event_class_vendors_the_optional_trace_profile_attribute() {
        let profile: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/ocsf/v1.8.0/profiles/trace.json"))
                .unwrap();
        let mut attribute = profile["attributes"]["trace"].clone();
        attribute["profiles"] = serde_json::json!(["trace"]);
        for class in [
            "base_event",
            "network_activity",
            "http_activity",
            "ssh_activity",
            "process_activity",
            "detection_finding",
            "application_lifecycle",
            "device_config_state_change",
            "api_activity",
            "authentication",
        ] {
            let schema = load_class_schema(class);
            assert_eq!(schema["attributes"]["trace"], attribute, "{class}");
            assert_ne!(schema["attributes"]["trace"]["requirement"], "required");
            assert!(
                schema["profiles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == "trace"),
                "{class} must support the Trace profile"
            );
        }
    }

    #[test]
    fn trace_profile_object_references_are_vendored() {
        let mut pending = vec!["trace".to_string()];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let schema = load_object_schema(&name);
            for attribute in schema["attributes"].as_object().unwrap().values() {
                if let Some(object) = attribute["object_type"].as_str() {
                    pending.push(object.to_string());
                }
            }
        }
        assert!(seen.contains("span"));
        let span = load_object_schema("span");
        for field in ["start_time", "end_time"] {
            assert_eq!(span["attributes"][field]["requirement"], "required");
        }
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
