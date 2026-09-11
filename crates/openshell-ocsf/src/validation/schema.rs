// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema loading and validation helpers.

use serde_json::Value;
use std::fs;

/// Load a vendored OCSF class schema by name.
///
/// # Panics
///
/// Panics if the schema file is missing or contains invalid JSON.
#[must_use]
pub fn load_class_schema(class: &str) -> Value {
    let path = format!(
        "{}/schemas/ocsf/v1.8.0/classes/{class}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Missing vendored schema: {path}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("Invalid JSON in {path}: {e}"))
}

/// Load a vendored OCSF object schema by name.
///
/// # Panics
///
/// Panics if the schema file is missing or contains invalid JSON.
#[must_use]
pub fn load_object_schema(object: &str) -> Value {
    let path = format!(
        "{}/schemas/ocsf/v1.8.0/objects/{object}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Missing vendored schema: {path}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("Invalid JSON in {path}: {e}"))
}

/// Validate required fields and the schema's `at_least_one` constraint.
///
/// The OCSF schema stores attributes as an object where each key is a field name
/// and the value contains a `requirement` field.
pub fn validate_required_fields(event: &Value, schema: &Value) {
    let attrs = match schema.get("attributes") {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|item| item.as_object())
            .flat_map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect::<Vec<_>>(),
        _ => return,
    };

    if let Some(fields) = schema
        .get("constraints")
        .and_then(|constraints| constraints.get("at_least_one"))
        .and_then(Value::as_array)
    {
        assert!(
            fields
                .iter()
                .filter_map(Value::as_str)
                .any(|field| { event.get(field).is_some_and(|value| !value.is_null()) }),
            "Missing at_least_one field from {fields:?}"
        );
    }

    for (name, def) in &attrs {
        let is_required = def.get("requirement").and_then(|r| r.as_str()) == Some("required");
        let is_profile_field = def.get("profile").is_some() || def.get("profiles").is_some();
        if is_required && !is_profile_field {
            assert!(
                event.get(name).is_some_and(|value| !value.is_null()),
                "Missing required field '{name}' in OCSF event. Event keys: {:?}",
                event.as_object().map(|o| o.keys().collect::<Vec<_>>())
            );
        }
    }
}

/// Validate that an enum field in the event has a valid value per the schema.
///
/// Checks the `enum` map in the schema attribute definition.
pub fn validate_enum_value(event: &Value, field: &str, schema: &Value) {
    if let Some(val) = event.get(field)
        && let Some(attrs) = schema.get("attributes").and_then(|a| a.as_object())
        && let Some(def) = attrs.get(field)
        && let Some(enum_map) = def.get("enum").and_then(|e| e.as_object())
    {
        let key = val.to_string();
        let key = key.trim_matches('"');
        assert!(
            enum_map.contains_key(key),
            "Invalid enum value {val} for field '{field}'. Valid: {:?}",
            enum_map.keys().collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_and_http_require_at_least_one_non_null_field() {
        for (class, fields) in [
            ("network_activity", ["src_endpoint", "dst_endpoint"]),
            ("http_activity", ["http_request", "http_response"]),
        ] {
            let schema = load_class_schema(class);
            let mut event = serde_json::json!({
                "class_uid": schema["uid"], "severity_id": 1, "metadata": {},
                "time": 12345, "type_uid": 0, "activity_id": 0, "category_uid": 4
            });
            assert!(
                std::panic::catch_unwind(|| validate_required_fields(&event, &schema)).is_err()
            );
            for field in fields {
                event[field] = Value::Null;
                assert!(
                    std::panic::catch_unwind(|| validate_required_fields(&event, &schema)).is_err()
                );
                event[field] = serde_json::json!({});
                validate_required_fields(&event, &schema);
                event.as_object_mut().unwrap().remove(field);
            }
        }
    }

    #[test]
    fn test_load_class_schemas() {
        // These tests only pass when the vendored schemas are present
        let classes = [
            "network_activity",
            "http_activity",
            "ssh_activity",
            "process_activity",
            "detection_finding",
            "application_lifecycle",
            "device_config_state_change",
            "base_event",
        ];

        for class in &classes {
            let schema = load_class_schema(class);
            // Every class schema should have a caption and attributes
            assert!(
                schema.get("caption").is_some(),
                "Schema '{class}' missing 'caption'"
            );
            assert!(
                schema.get("attributes").is_some(),
                "Schema '{class}' missing 'attributes'"
            );
        }
    }

    #[test]
    fn test_validate_required_fields_passes() {
        let event = serde_json::json!({
            "class_uid": 0,
            "severity_id": 1,
            "metadata": {},
            "time": 12345,
            "type_uid": 99,
            "activity_id": 99,
            "category_uid": 0
        });
        let schema = load_class_schema("base_event");
        // This should not panic — base_event has few required fields
        validate_required_fields(&event, &schema);
    }

    #[test]
    fn test_validate_enum_value_valid() {
        let event = serde_json::json!({ "severity_id": 1 });
        let schema = load_class_schema("base_event");
        validate_enum_value(&event, "severity_id", &schema);
    }
}
