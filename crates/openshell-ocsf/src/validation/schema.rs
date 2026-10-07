// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema loading and validation helpers.

use serde_json::Value;

/// Load a vendored OCSF class schema by name.
///
/// # Panics
///
/// Panics if the schema file is missing or contains invalid JSON.
#[must_use]
pub fn load_class_schema(class: &str) -> Value {
    load_schema(crate::OCSF_VERSION, "classes", class)
}

/// Load a vendored OCSF object schema by name.
///
/// # Panics
///
/// Panics if the schema file is missing or contains invalid JSON.
#[must_use]
pub fn load_object_schema(object: &str) -> Value {
    load_schema(crate::OCSF_VERSION, "objects", object)
}

/// Load a vendored OCSF class schema for a specific schema version.
///
/// # Panics
///
/// Panics if the schema file is missing or contains invalid JSON.
#[must_use]
pub fn load_class_schema_for_version(version: &str, class: &str) -> Value {
    load_schema(version, "classes", class)
}

/// Schemas are compiled into the binary so that relocated test binaries, such
/// as a nextest archive run on another machine, need no files at run time.
fn load_schema(version: &str, kind: &str, name: &str) -> Value {
    let key = format!("v{version}/{kind}/{name}");
    let Some((_, data)) = super::embedded::SCHEMAS
        .iter()
        .find(|(path, _)| *path == key)
    else {
        panic!("Missing vendored schema: schemas/ocsf/{key}.json");
    };
    serde_json::from_str(data).unwrap_or_else(|e| panic!("Invalid JSON in {key}: {e}"))
}

/// Attribute definitions keyed by name; the schema server emits them as an
/// object or as an array of single-entry objects.
fn attribute_map(schema: &Value) -> serde_json::Map<String, Value> {
    match schema.get("attributes") {
        Some(Value::Object(map)) => map.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_object)
            .flat_map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect(),
        _ => serde_json::Map::new(),
    }
}

/// Validate an OCSF event against a vendored class schema.
///
/// Checks, recursively through nested objects: every required attribute is
/// present (profile attributes only when the event declares that profile),
/// `at_least_one` constraints hold, and no attribute is undefined. Object
/// schemas are loaded for the version in the event's `metadata.version`.
pub fn validate_required_fields(event: &Value, schema: &Value) {
    let version = event
        .pointer("/metadata/version")
        .and_then(Value::as_str)
        .unwrap_or(crate::OCSF_VERSION);
    let profiles: Vec<&str> = event
        .pointer("/metadata/profiles")
        .and_then(Value::as_array)
        .map(|p| p.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    validate_attributes(event, schema, version, &profiles, "event");
}

/// Top-level attributes `OpenShell` emits that no OCSF version defines, pending a
/// design decision. Remove an entry once the emitters stop producing it.
/// - `container`: identifies the affected sandbox (NVIDIA/OpenShell#4283).
const KNOWN_UNDEFINED_EVENT_ATTRIBUTES: &[&str] = &["container"];

fn validate_attributes(
    value: &Value,
    schema: &Value,
    version: &str,
    profiles: &[&str],
    path: &str,
) {
    let attrs = attribute_map(schema);
    let Some(obj) = value.as_object() else {
        return;
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
                .any(|field| { obj.get(field).is_some_and(|value| !value.is_null()) }),
            "Missing at_least_one field from {fields:?} in '{path}'"
        );
    }

    for name in obj.keys() {
        if path == "event" && KNOWN_UNDEFINED_EVENT_ATTRIBUTES.contains(&name.as_str()) {
            continue;
        }
        assert!(
            attrs.contains_key(name),
            "Undefined attribute '{path}.{name}' in OCSF {version}"
        );
    }

    for (name, def) in &attrs {
        let is_required = def.get("requirement").and_then(|r| r.as_str()) == Some("required");
        // An attribute added by profiles applies only when the event declares one of them.
        let applies = match def.get("profiles").or_else(|| def.get("profile")) {
            Some(Value::Array(names)) => names
                .iter()
                .filter_map(Value::as_str)
                .any(|name| profiles.contains(&name)),
            Some(Value::String(name)) => profiles.contains(&name.as_str()),
            _ => true,
        };
        if is_required && applies {
            assert!(
                obj.get(name).is_some_and(|value| !value.is_null()),
                "Missing required field '{path}.{name}' in OCSF {version}. Keys: {:?}",
                obj.keys().collect::<Vec<_>>()
            );
        }

        let Some(object_type) = def.get("object_type").and_then(Value::as_str) else {
            continue;
        };
        let Some(child) = obj.get(name) else {
            continue;
        };
        if object_type == "object" {
            continue;
        }
        let child_schema = load_schema(version, "objects", object_type);
        let child_path = format!("{path}.{name}");
        match child {
            Value::Array(items) => {
                for item in items {
                    validate_attributes(item, &child_schema, version, profiles, &child_path);
                }
            }
            other => validate_attributes(other, &child_schema, version, profiles, &child_path),
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
                "class_uid": schema["uid"], "severity_id": 1,
                "metadata": {"version": "1.8.0", "product": {"name": "OpenShell", "vendor_name": "NVIDIA"}},
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
                event[field] = match field {
                    "http_request" => serde_json::json!({"http_method": "GET"}),
                    "http_response" => serde_json::json!({"code": 200}),
                    _ => serde_json::json!({"ip": "10.0.0.1"}),
                };
                validate_required_fields(&event, &schema);
                event.as_object_mut().unwrap().remove(field);
            }
        }
    }

    fn minimal_base_event() -> Value {
        serde_json::json!({
            "class_uid": 0, "severity_id": 1, "metadata": {"version": "1.8.0", "product": {"name": "OpenShell", "vendor_name": "NVIDIA"}},
            "time": 12345, "type_uid": 99, "activity_id": 99, "category_uid": 0
        })
    }

    #[test]
    fn rejects_attributes_the_class_does_not_define() {
        let schema = load_class_schema("base_event");
        let mut event = minimal_base_event();
        validate_required_fields(&event, &schema);
        event["is_src_dst_assignment_known"] = Value::Bool(true);
        assert!(std::panic::catch_unwind(|| validate_required_fields(&event, &schema)).is_err());
    }

    #[test]
    fn rejects_missing_required_attributes_in_nested_objects() {
        let schema = load_class_schema("base_event");
        let mut event = minimal_base_event();
        event["device"] = serde_json::json!({
            "hostname": "h", "type_id": 99, "os": {"name": "Linux", "type_id": 200}
        });
        validate_required_fields(&event, &schema);
        event["device"]["os"]
            .as_object_mut()
            .unwrap()
            .remove("type_id");
        assert!(std::panic::catch_unwind(|| validate_required_fields(&event, &schema)).is_err());
    }

    /// Regenerate with `UPDATE_OCSF_EMBEDDED_SCHEMAS=1 cargo test -p openshell-ocsf embedded_schemas`.
    #[test]
    fn embedded_schemas_match_vendored_files() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/ocsf");
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|ext| ext == "json") {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    files.push(relative.trim_end_matches(".json").to_string());
                }
            }
        }
        files.sort();

        let mut expected = String::from(
            "// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.\n\
             // SPDX-License-Identifier: Apache-2.0\n\n\
             //! Vendored OCSF schemas compiled into the binary.\n//!\n\
             //! @generated from `schemas/ocsf/`. Do not edit; regenerate with\n\
             //! `UPDATE_OCSF_EMBEDDED_SCHEMAS=1 cargo test -p openshell-ocsf embedded_schemas`.\n\n\
             #[rustfmt::skip]\npub(super) static SCHEMAS: &[(&str, &str)] = &[\n",
        );
        for file in &files {
            use std::fmt::Write as _;
            writeln!(
                expected,
                "    (\"{file}\", include_str!(\"../../schemas/ocsf/{file}.json\")),"
            )
            .unwrap();
        }
        expected.push_str("];\n");

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/validation/embedded.rs");
        if std::env::var_os("UPDATE_OCSF_EMBEDDED_SCHEMAS").is_some() {
            std::fs::write(path, &expected).unwrap();
        }
        let actual = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            actual == expected,
            "embedded.rs is out of date; rerun with UPDATE_OCSF_EMBEDDED_SCHEMAS=1"
        );
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
            "metadata": {"version": "1.8.0", "product": {"name": "OpenShell", "vendor_name": "NVIDIA"}},
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
