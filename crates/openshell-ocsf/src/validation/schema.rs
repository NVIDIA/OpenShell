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

/// Profiles that add an attribute, or `None` when the attribute is part of the
/// base class or object.
fn attribute_profiles(def: &Value) -> Option<Vec<&str>> {
    match def.get("profiles").or_else(|| def.get("profile")) {
        Some(Value::Array(names)) => Some(names.iter().filter_map(Value::as_str).collect()),
        Some(Value::String(name)) => Some(vec![name.as_str()]),
        _ => None,
    }
}

fn declared_profiles(event: &Value) -> Vec<&str> {
    event
        .pointer("/metadata/profiles")
        .and_then(Value::as_array)
        .map(|p| p.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Validate an OCSF event or object against a vendored schema.
///
/// Checks, recursively through nested objects: every required attribute is
/// present, `at_least_one` constraints hold, and no attribute is undefined.
/// For an event class schema the event must also be labelled with
/// [`crate::OCSF_VERSION`], profile attributes are required only when the event
/// declares that profile, and every profile attribute present must belong to a
/// declared profile. An object schema carries no profile declarations, so
/// profile membership is checked only from an event.
pub fn validate_required_fields(value: &Value, schema: &Value) {
    validate(value, schema, true);
}

/// Validate that every attribute is defined by the schema, recursively.
///
/// For an event class schema, profile attributes must also belong to a profile
/// the event declares in `metadata.profiles` (none when absent).
pub fn validate_known_fields(value: &Value, schema: &Value) {
    validate(value, schema, false);
}

fn validate(value: &Value, schema: &Value, check_required: bool) {
    let is_event = schema.get("uid").is_some();
    if is_event && let Some(version) = value.pointer("/metadata/version") {
        assert!(
            version == crate::OCSF_VERSION,
            "OCSF records must be labelled {}, found {version}",
            crate::OCSF_VERSION
        );
    }
    let declared = is_event.then(|| declared_profiles(value));
    let root = if is_event {
        "event"
    } else {
        schema["name"].as_str().unwrap_or("object")
    };
    validate_attributes(
        value,
        schema,
        declared.as_deref(),
        root,
        is_event,
        check_required,
    );
}

/// Top-level attributes `OpenShell` emits that no OCSF version defines, pending a
/// design decision. Remove an entry once the emitters stop producing it.
/// - `container`: identifies the affected sandbox (NVIDIA/OpenShell#4283).
const KNOWN_UNDEFINED_EVENT_ATTRIBUTES: &[&str] = &["container"];

fn validate_attributes(
    value: &Value,
    schema: &Value,
    declared: Option<&[&str]>,
    path: &str,
    event_root: bool,
    check_required: bool,
) {
    let attrs = attribute_map(schema);
    let Some(obj) = value.as_object() else {
        return;
    };

    if check_required
        && let Some(fields) = schema
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
        if event_root && KNOWN_UNDEFINED_EVENT_ATTRIBUTES.contains(&name.as_str()) {
            continue;
        }
        let Some(def) = attrs.get(name) else {
            panic!("Undefined attribute '{path}.{name}'");
        };
        if let (Some(declared), Some(profiles)) = (declared, attribute_profiles(def)) {
            assert!(
                profiles.iter().any(|profile| declared.contains(profile)),
                "Attribute '{path}.{name}' requires one of the profiles {profiles:?}, declared {declared:?}"
            );
        }
    }

    for (name, def) in &attrs {
        let is_required = def.get("requirement").and_then(|r| r.as_str()) == Some("required");
        // An attribute added by profiles applies only when the event declares one of them.
        let applies = attribute_profiles(def).is_none_or(|profiles| {
            declared.is_some_and(|declared| profiles.iter().any(|p| declared.contains(p)))
        });
        if check_required && is_required && applies {
            assert!(
                obj.get(name).is_some_and(|value| !value.is_null()),
                "Missing required field '{path}.{name}'. Keys: {:?}",
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
        let child_schema = load_schema(crate::OCSF_VERSION, "objects", object_type);
        let child_path = format!("{path}.{name}");
        match child {
            Value::Array(items) => {
                for item in items {
                    validate_attributes(
                        item,
                        &child_schema,
                        declared,
                        &child_path,
                        false,
                        check_required,
                    );
                }
            }
            other => validate_attributes(
                other,
                &child_schema,
                declared,
                &child_path,
                false,
                check_required,
            ),
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
    fn rejects_missing_required_attributes_in_nested_objects() {
        let schema = load_class_schema("base_event");
        let mut event = minimal_base_event();
        event["metadata"]["profiles"] = serde_json::json!(["host"]);
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

    fn panic_message(result: std::thread::Result<()>) -> String {
        let panic = result.expect_err("validation should fail");
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
            .unwrap_or_default()
    }

    #[test]
    fn rejects_nested_attributes_of_undeclared_profiles() {
        let schema = load_class_schema("base_event");
        let mut event = minimal_base_event();
        event["device"] = serde_json::json!({
            "hostname": "h", "type_id": 99, "os": {"name": "Linux", "type_id": 200},
            "container": {"name": "sandbox"}
        });
        event["metadata"]["profiles"] = serde_json::json!(["host", "container"]);
        validate_required_fields(&event, &schema);

        event["metadata"]["profiles"] = serde_json::json!(["host"]);
        let message = panic_message(std::panic::catch_unwind(|| {
            validate_required_fields(&event, &schema);
        }));
        assert!(message.contains("event.device.container"), "{message}");
        assert!(message.contains("container"), "{message}");
    }

    #[test]
    fn object_schemas_are_validated_as_objects_not_events() {
        let device = load_object_schema("device");
        // An object carries no `metadata.profiles`, so profile membership is
        // not checked: only the event that contains it knows its profiles.
        let value = serde_json::json!({
            "hostname": "h", "type_id": 99, "os": {"name": "Linux", "type_id": 200},
            "namespace_pid": 7
        });
        validate_required_fields(&value, &device);

        // The top-level `container` exemption applies to events only, so an
        // object whose schema does not define `container` rejects it.
        let user = load_object_schema("user");
        let value = serde_json::json!({"name": "u", "container": {"name": "sandbox"}});
        let message = panic_message(std::panic::catch_unwind(|| {
            validate_required_fields(&value, &user);
        }));
        assert!(message.contains("user.container"), "{message}");
    }

    #[test]
    fn rejects_records_labelled_with_another_version() {
        let schema = load_class_schema("base_event");
        let mut event = minimal_base_event();
        event["metadata"]["version"] = Value::from("1.1.0");
        let message = panic_message(std::panic::catch_unwind(|| {
            validate_required_fields(&event, &schema);
        }));
        assert!(message.contains("must be labelled 1.8.0"), "{message}");
        assert!(message.contains("1.1.0"), "{message}");
    }

    #[test]
    fn known_fields_rejects_undefined_attributes_in_nested_objects() {
        let schema = load_class_schema("authentication");
        let mut event = serde_json::json!({
            "class_uid": 3002,
            "metadata": {"profiles": []},
            "user": {"name": "operator"}
        });
        validate_known_fields(&event, &schema);

        event["user"]["bogus"] = Value::from(1);
        let message = panic_message(std::panic::catch_unwind(|| {
            validate_known_fields(&event, &schema);
        }));
        assert!(message.contains("user.bogus"), "{message}");
    }

    /// Table key for a schema path relative to `schemas/ocsf`, joined with `/` on
    /// every platform so the generated table is the same on Windows and Unix.
    fn embedded_schema_key(relative: &std::path::Path) -> String {
        let joined = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        joined.trim_end_matches(".json").to_string()
    }

    #[test]
    fn embedded_schema_keys_use_forward_slashes_on_every_platform() {
        // `join` uses the native separator, so on Windows this path has backslashes.
        let relative = std::path::Path::new("v1.8.0")
            .join("classes")
            .join("api_activity.json");
        assert_eq!(
            embedded_schema_key(&relative),
            "v1.8.0/classes/api_activity"
        );
    }

    /// Regenerate with `UPDATE_OCSF_EMBEDDED_SCHEMAS=1 cargo test -p openshell-ocsf embedded_schemas`.
    #[test]
    fn embedded_schemas_match_vendored_files() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/ocsf");
        // This compares source files, so it needs the build checkout. Relocated
        // test binaries (such as a nextest archive) skip it; validation itself
        // uses the embedded table and needs no source files.
        if !std::path::Path::new(root).is_dir() {
            eprintln!("skipping: source checkout not found at {root}");
            return;
        }
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|ext| ext == "json") {
                    files.push(embedded_schema_key(path.strip_prefix(root).unwrap()));
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
        // Windows checkouts can convert the generated file to CRLF.
        let actual = std::fs::read_to_string(path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert!(
            actual == expected,
            "embedded.rs is out of date; rerun with UPDATE_OCSF_EMBEDDED_SCHEMAS=1"
        );
    }

    #[test]
    fn known_fields_rejects_attributes_outside_the_schema() {
        let schema = load_class_schema("base_event");
        let mut event = serde_json::json!({"class_uid": 0, "severity_id": 1});
        validate_known_fields(&event, &schema);

        event["not_an_ocsf_attribute"] = Value::Bool(true);
        assert!(std::panic::catch_unwind(|| validate_known_fields(&event, &schema)).is_err());
    }

    #[test]
    fn known_fields_rejects_attributes_of_undeclared_profiles() {
        let schema = load_class_schema("authentication");
        let mut event = serde_json::json!({
            "class_uid": 3002,
            "metadata": {"profiles": ["host"]},
            "device": {}
        });
        validate_known_fields(&event, &schema);

        event["api"] = serde_json::json!({"operation": "Op"});
        assert!(std::panic::catch_unwind(|| validate_known_fields(&event, &schema)).is_err());
    }

    #[test]
    fn known_fields_treats_missing_profile_declarations_as_none() {
        let schema = load_class_schema("authentication");
        let event = serde_json::json!({
            "class_uid": 3002,
            "metadata": {},
            "api": {"operation": "Op"}
        });
        assert!(std::panic::catch_unwind(|| validate_known_fields(&event, &schema)).is_err());
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
            "api_activity",
            "authentication",
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
