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
        "{}/schemas/ocsf/v1.7.0/classes/{class}.json",
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
        "{}/schemas/ocsf/v1.7.0/objects/{object}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Missing vendored schema: {path}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("Invalid JSON in {path}: {e}"))
}

/// Validate that all required fields from the schema are present in the event JSON.
///
/// The OCSF schema stores attributes as an object where each key is a field name
/// and the value contains a `requirement` field.
pub fn validate_required_fields(event: &Value, schema: &Value) {
    if let Some(attrs) = schema.get("attributes").and_then(|a| a.as_object()) {
        for (name, def) in attrs {
            if def.get("requirement").and_then(|r| r.as_str()) == Some("required") {
                assert!(
                    event.get(name).is_some(),
                    "Missing required field '{name}' in OCSF event. Event keys: {:?}",
                    event.as_object().map(|o| o.keys().collect::<Vec<_>>())
                );
            }
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
