// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validate OCSF events against JSON Schemas exported by the OCSF schema
//! server, one per event class and declared profile combination.

use std::sync::{LazyLock, OnceLock};

use serde_json::Value;

/// `(version, file stem, schema)` for every file under `schemas/v<version>/`.
const SCHEMAS: &[(&str, &str, &str)] = include!(concat!(env!("OUT_DIR"), "/schemas.rs"));

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("event has no integer class_uid")]
    MissingClassUid,
    #[error("event has no string metadata.version")]
    MissingVersion,
    #[error("no vendored schemas for OCSF {0}")]
    UnsupportedVersion(String),
    #[error(
        "no vendored OCSF {version} schema for class_uid {class_uid} with profiles {profiles:?}{}",
        vendor_hint(.file)
    )]
    UnknownSchema {
        version: String,
        class_uid: u64,
        profiles: Vec<String>,
        /// Repository path to vendor the missing schema at, when the class name is known.
        file: Option<String>,
    },
    #[error("{}", format_violations(.0))]
    Invalid(Vec<Violation>),
}

/// One schema violation at a JSON pointer into the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub message: String,
}

const SCHEMA_DIR: &str = "crates/openshell-ocsf-validate/schemas";

fn vendor_hint(file: &Option<String>) -> String {
    file.as_ref()
        .map(|file| format!("; vendor it with:\n  {SCHEMA_DIR}/update.sh {file}"))
        .unwrap_or_default()
}

fn format_violations(violations: &[Violation]) -> String {
    violations
        .iter()
        .map(|v| format!("{}: {}", v.path, v.message))
        .collect::<Vec<_>>()
        .join("\n")
}

struct Schema {
    version: &'static str,
    class: &'static str,
    class_uid: u64,
    profiles: Vec<String>,
    json: Value,
    validator: OnceLock<jsonschema::Validator>,
}

impl Schema {
    fn validator(&self) -> &jsonschema::Validator {
        self.validator
            .get_or_init(|| jsonschema::draft7::new(&self.json).expect("vendored schema compiles"))
    }
}

static INDEX: LazyLock<Vec<Schema>> = LazyLock::new(|| {
    SCHEMAS
        .iter()
        .map(|&(version, name, data)| {
            let json: Value = serde_json::from_str(data)
                .unwrap_or_else(|e| panic!("vendored schema v{version}/{name} is not JSON: {e}"));
            let class_uid = json
                .pointer("/properties/class_uid/const")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("vendored schema v{version}/{name} has no class_uid"));
            let (class, profiles) = name.split_once('@').unwrap_or((name, ""));
            let profiles = profiles
                .split('+')
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect();
            Schema {
                version,
                class,
                class_uid,
                profiles,
                json,
                validator: OnceLock::new(),
            }
        })
        .collect()
});

/// The exported schemas type `type_uid` only as an integer, so check that it
/// equals `class_uid * 100 + activity_id`.
fn type_uid_violation(event: &Value, class_uid: u64) -> Option<Violation> {
    let type_uid = event.get("type_uid")?.as_u64()?;
    let activity_id = event.get("activity_id")?.as_u64()?;
    let expected = class_uid * 100 + activity_id;
    (type_uid != expected).then(|| Violation {
        path: "/type_uid".to_string(),
        message: format!(
            "{type_uid} is not class_uid * 100 + activity_id ({class_uid} * 100 + {activity_id} = {expected})"
        ),
    })
}

/// Validate an OCSF event against the schema for its `metadata.version`,
/// class, and declared `metadata.profiles`.
pub fn validate_event(event: &Value) -> Result<(), Error> {
    let class_uid = event
        .get("class_uid")
        .and_then(Value::as_u64)
        .ok_or(Error::MissingClassUid)?;
    let version = event
        .pointer("/metadata/version")
        .and_then(Value::as_str)
        .ok_or(Error::MissingVersion)?;
    if !INDEX.iter().any(|s| s.version == version) {
        return Err(Error::UnsupportedVersion(version.to_string()));
    }
    let mut profiles: Vec<String> = event
        .pointer("/metadata/profiles")
        .and_then(Value::as_array)
        .map(|p| {
            p.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    profiles.sort();

    let Some(schema) = INDEX
        .iter()
        .find(|s| s.version == version && s.class_uid == class_uid && s.profiles == profiles)
    else {
        let class = INDEX
            .iter()
            .find(|s| s.class_uid == class_uid)
            .map(|s| s.class.to_string())
            .or_else(|| {
                event
                    .get("class_name")
                    .and_then(Value::as_str)
                    .map(|name| name.to_lowercase().replace(' ', "_"))
            });
        let file = class.map(|class| {
            let stem = if profiles.is_empty() {
                class
            } else {
                format!("{class}@{}", profiles.join("+"))
            };
            format!("{SCHEMA_DIR}/v{version}/{stem}.json")
        });
        return Err(Error::UnknownSchema {
            version: version.to_string(),
            class_uid,
            profiles,
            file,
        });
    };
    let mut violations: Vec<Violation> = schema
        .validator()
        .iter_errors(event)
        .map(|e| Violation {
            path: e.instance_path().to_string(),
            message: e.to_string(),
        })
        .collect();
    violations.extend(type_uid_violation(event, class_uid));
    if violations.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid(violations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_event() -> Value {
        json!({
            "activity_id": 0,
            "category_uid": 0,
            "class_uid": 0,
            "severity_id": 1,
            "time": 1_775_014_138_811_u64,
            "type_uid": 0,
            "metadata": {
                "version": "1.8.0",
                "profiles": ["container", "host"],
                "product": {"name": "OpenShell"}
            }
        })
    }

    fn violations(event: &Value) -> Vec<Violation> {
        match validate_event(event) {
            Err(Error::Invalid(violations)) => violations,
            other => panic!("expected violations, got {other:?}"),
        }
    }

    fn assert_violation(event: &Value, path: &str, needle: &str) {
        let violations = violations(event);
        assert!(
            violations
                .iter()
                .any(|v| v.path == path && v.message.contains(needle)),
            "no violation at {path:?} mentioning {needle:?}: {violations:?}"
        );
    }

    #[test]
    fn accepts_conformant_event() {
        validate_event(&base_event()).unwrap();
    }

    #[test]
    fn profile_order_does_not_matter() {
        let mut event = base_event();
        event["metadata"]["profiles"] = json!(["host", "container"]);
        validate_event(&event).unwrap();
    }

    #[test]
    fn rejects_undefined_nested_attribute() {
        let mut event = base_event();
        event["metadata"]["product"]["bogus"] = json!(1);
        assert_violation(&event, "/metadata/product", "bogus");
    }

    #[test]
    fn rejects_attribute_of_undeclared_profile() {
        let mut event = base_event();
        event["cloud"] = json!({"provider": "aws"});
        assert_violation(&event, "", "cloud");
    }

    #[test]
    fn rejects_missing_required_attribute() {
        let mut event = base_event();
        event.as_object_mut().unwrap().remove("time");
        assert_violation(&event, "", "time");
    }

    #[test]
    fn rejects_unsatisfied_at_least_one() {
        let mut event = base_event();
        event["metadata"]["product"] = json!({"vendor_name": "NVIDIA"});
        violations(&event)
            .iter()
            .find(|v| v.path == "/metadata/product")
            .expect("product needs a name or uid");
    }

    #[test]
    fn rejects_out_of_range_enum_and_wrong_type() {
        let mut event = base_event();
        event["activity_id"] = json!(42);
        event["time"] = json!("now");
        let violations = violations(&event);
        assert!(
            violations.iter().any(|v| v.path == "/activity_id"),
            "{violations:?}"
        );
        assert!(
            violations.iter().any(|v| v.path == "/time"),
            "{violations:?}"
        );
    }

    #[test]
    fn rejects_type_uid_inconsistent_with_class_and_activity() {
        let mut event = base_event();
        event["type_uid"] = json!(999_999);
        assert_violation(&event, "/type_uid", "999999");

        event["activity_id"] = json!(99);
        event["type_uid"] = json!(0);
        assert_violation(&event, "/type_uid", "99");
        event["type_uid"] = json!(99);
        validate_event(&event).unwrap();
    }

    #[test]
    fn rejects_category_uid_of_another_category() {
        let mut event = base_event();
        event["category_uid"] = json!(4);
        violations(&event)
            .iter()
            .find(|v| v.path == "/category_uid")
            .expect("base_event belongs to category 0");
    }

    #[test]
    fn validates_every_array_element() {
        let mut event = base_event();
        event["observables"] = json!([{"type_id": 1}, {"type_id": 1, "bogus": 1}, {}]);
        assert_violation(&event, "/observables/1", "bogus");
        assert_violation(&event, "/observables/2", "type_id");
    }

    #[test]
    fn rejects_top_level_container() {
        let mut event = base_event();
        event["container"] = json!({"name": "sandbox"});
        assert_violation(&event, "", "container");
    }

    #[test]
    fn rejects_profile_combination_without_vendored_schema() {
        let mut event = base_event();
        event["metadata"]["profiles"] = json!(["host"]);
        let error = validate_event(&event).unwrap_err();
        let Error::UnknownSchema {
            version,
            class_uid,
            profiles,
            file,
        } = &error
        else {
            panic!("expected UnknownSchema, got {error:?}");
        };
        assert_eq!(version, "1.8.0");
        assert_eq!(*class_uid, 0);
        assert_eq!(profiles, &["host"]);
        let expected = "crates/openshell-ocsf-validate/schemas/v1.8.0/base_event@host.json";
        assert_eq!(file.as_deref(), Some(expected));
        assert!(
            error.to_string().contains(&format!(
                "crates/openshell-ocsf-validate/schemas/update.sh {expected}"
            )),
            "{error}"
        );
    }

    #[test]
    fn names_the_schema_file_for_an_unvendored_class_from_its_class_name() {
        let mut event = base_event();
        event["class_uid"] = json!(9999);
        event["class_name"] = json!("Made Up Activity");
        match validate_event(&event) {
            Err(Error::UnknownSchema { file, .. }) => assert_eq!(
                file.as_deref(),
                Some(
                    "crates/openshell-ocsf-validate/schemas/v1.8.0/made_up_activity@container+host.json"
                )
            ),
            other => panic!("expected UnknownSchema, got {other:?}"),
        }

        event.as_object_mut().unwrap().remove("class_name");
        match validate_event(&event) {
            Err(error @ Error::UnknownSchema { file: None, .. }) => {
                assert!(!error.to_string().contains("update.sh"), "{error}");
            }
            other => panic!("expected UnknownSchema without a file, got {other:?}"),
        }
    }

    #[test]
    fn rejects_versions_without_vendored_schemas() {
        let mut event = base_event();
        event["metadata"]["version"] = json!("1.1.0");
        assert!(
            matches!(validate_event(&event), Err(Error::UnsupportedVersion(found)) if found == "1.1.0")
        );
    }

    #[test]
    fn rejects_event_without_version() {
        let mut event = base_event();
        event["metadata"].as_object_mut().unwrap().remove("version");
        assert!(matches!(validate_event(&event), Err(Error::MissingVersion)));
    }

    #[test]
    fn rejects_event_without_class_uid() {
        let mut event = base_event();
        event.as_object_mut().unwrap().remove("class_uid");
        assert!(matches!(
            validate_event(&event),
            Err(Error::MissingClassUid)
        ));
    }

    #[test]
    fn vendored_files_are_class_exports_named_by_sorted_profiles() {
        for (version, name, data) in SCHEMAS {
            let file = format!("v{version}/{name}");
            let schema: Value =
                serde_json::from_str(data).unwrap_or_else(|e| panic!("{file}: {e}"));
            let (class, profiles) = name.split_once('@').unwrap_or((name, ""));
            let id = schema["$id"].as_str().unwrap_or_default();
            assert!(
                id.ends_with(&format!("/classes/{class}")),
                "{file}: $id {id:?}"
            );
            assert!(
                schema
                    .pointer("/properties/class_uid/const")
                    .is_some_and(Value::is_u64),
                "{file}"
            );
            let profiles: Vec<&str> = profiles.split('+').filter(|p| !p.is_empty()).collect();
            assert!(profiles.is_sorted(), "{file}: profiles must be sorted");
        }
    }
}
