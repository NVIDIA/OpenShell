// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema loading and validation helpers.

use serde_json::Value;

/// Load a vendored OCSF class schema by name.
///
/// # Panics
///
/// Panics if the schema name is unknown or the file contains invalid JSON.
#[must_use]
pub fn load_class_schema(class: &str) -> Value {
    let data = match class {
        "application_lifecycle" => {
            include_str!("../../schemas/ocsf/v1.7.0/classes/application_lifecycle.json")
        }
        "base_event" => include_str!("../../schemas/ocsf/v1.7.0/classes/base_event.json"),
        "detection_finding" => {
            include_str!("../../schemas/ocsf/v1.7.0/classes/detection_finding.json")
        }
        "device_config_state_change" => {
            include_str!("../../schemas/ocsf/v1.7.0/classes/device_config_state_change.json")
        }
        "http_activity" => include_str!("../../schemas/ocsf/v1.7.0/classes/http_activity.json"),
        "network_activity" => {
            include_str!("../../schemas/ocsf/v1.7.0/classes/network_activity.json")
        }
        "process_activity" => {
            include_str!("../../schemas/ocsf/v1.7.0/classes/process_activity.json")
        }
        "ssh_activity" => include_str!("../../schemas/ocsf/v1.7.0/classes/ssh_activity.json"),
        _ => panic!("Unknown OCSF class schema: {class}"),
    };
    serde_json::from_str(data).unwrap_or_else(|e| panic!("Invalid JSON in schema {class}: {e}"))
}

/// Load a vendored OCSF object schema by name.
///
/// # Panics
///
/// Panics if the schema name is unknown or the file contains invalid JSON.
#[must_use]
pub fn load_object_schema(object: &str) -> Value {
    let data = match object {
        "actor" => include_str!("../../schemas/ocsf/v1.7.0/objects/actor.json"),
        "attack" => include_str!("../../schemas/ocsf/v1.7.0/objects/attack.json"),
        "connection_info" => {
            include_str!("../../schemas/ocsf/v1.7.0/objects/connection_info.json")
        }
        "container" => include_str!("../../schemas/ocsf/v1.7.0/objects/container.json"),
        "device" => include_str!("../../schemas/ocsf/v1.7.0/objects/device.json"),
        "evidences" => include_str!("../../schemas/ocsf/v1.7.0/objects/evidences.json"),
        "finding_info" => include_str!("../../schemas/ocsf/v1.7.0/objects/finding_info.json"),
        "firewall_rule" => include_str!("../../schemas/ocsf/v1.7.0/objects/firewall_rule.json"),
        "http_request" => include_str!("../../schemas/ocsf/v1.7.0/objects/http_request.json"),
        "http_response" => include_str!("../../schemas/ocsf/v1.7.0/objects/http_response.json"),
        "metadata" => include_str!("../../schemas/ocsf/v1.7.0/objects/metadata.json"),
        "network_endpoint" => {
            include_str!("../../schemas/ocsf/v1.7.0/objects/network_endpoint.json")
        }
        "network_proxy" => include_str!("../../schemas/ocsf/v1.7.0/objects/network_proxy.json"),
        "process" => include_str!("../../schemas/ocsf/v1.7.0/objects/process.json"),
        "product" => include_str!("../../schemas/ocsf/v1.7.0/objects/product.json"),
        "remediation" => include_str!("../../schemas/ocsf/v1.7.0/objects/remediation.json"),
        "url" => include_str!("../../schemas/ocsf/v1.7.0/objects/url.json"),
        _ => panic!("Unknown OCSF object schema: {object}"),
    };
    serde_json::from_str(data).unwrap_or_else(|e| panic!("Invalid JSON in schema {object}: {e}"))
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
