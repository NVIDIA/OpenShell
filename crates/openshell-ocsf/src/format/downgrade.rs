// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF schema version downgrade.
//!
//! Rewrites a serialized native OCSF event for an older target version using
//! per-version attribute definitions generated from the vendored OCSF schemas
//! (`downgrade_defs.rs`). Attributes the target does not define are moved under
//! `unmapped.downgraded_attributes`. The event is labelled with the target
//! version only when it then meets every requirement of that version;
//! otherwise it is left unchanged at the native version, because satisfying
//! the requirement would mean inventing data.

use serde_json::{Map, Value};

use super::downgrade_defs::VERSIONS;

/// Result of [`downgrade_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowngradeOutcome {
    /// The target is the native version or newer; the event is unchanged.
    NotNeeded,
    /// The event was rewritten and labelled with the target version.
    Downgraded,
    /// The event cannot conform to the target version; it is unchanged at the
    /// native version.
    KeptNative {
        /// Why the event cannot conform, e.g. the first missing requirement.
        reason: String,
    },
}

/// An attribute definition for one OCSF version.
pub(super) struct AttributeDef {
    pub name: &'static str,
    /// Object type for object attributes; `None` for scalars and free-form objects.
    pub object: Option<&'static str>,
    pub required: bool,
    /// Profiles that add the attribute; empty when it is always defined.
    pub profiles: &'static [&'static str],
}

pub(super) const fn attr(
    name: &'static str,
    object: Option<&'static str>,
    required: bool,
    profiles: &'static [&'static str],
) -> AttributeDef {
    AttributeDef {
        name,
        object,
        required,
        profiles,
    }
}

/// The attributes of a class or object in one OCSF version.
pub(super) struct TypeDef {
    pub name: &'static str,
    pub attributes: &'static [AttributeDef],
    pub at_least_one: &'static [&'static str],
}

/// An event class in one OCSF version.
pub(super) struct ClassDef {
    pub uid: u64,
    /// Profiles the class supports.
    pub profiles: &'static [&'static str],
    pub def: TypeDef,
}

/// Every class and object definition `OpenShell` needs for one OCSF version.
pub(super) struct VersionDefs {
    pub version: &'static str,
    pub classes: &'static [ClassDef],
    pub objects: &'static [TypeDef],
}

/// Downgrade a serialized OCSF event to `target_version` (`"1.1"` or `"1.1.0"`).
///
/// On [`DowngradeOutcome::Downgraded`] the event conforms to the target
/// version. On any other outcome the event is left unchanged.
pub fn downgrade_event(event: &mut Value, target_version: &str) -> DowngradeOutcome {
    let target = parse_version(target_version);
    if target >= parse_version(crate::OCSF_VERSION) {
        return DowngradeOutcome::NotNeeded;
    }
    let version = format!("{}.{}.{}", target.0, target.1, target.2);
    let Some(defs) = VERSIONS.iter().find(|defs| defs.version == version) else {
        return DowngradeOutcome::KeptNative {
            reason: format!("OpenShell has no definitions for OCSF {version}"),
        };
    };
    match rewrite(event, defs) {
        Ok(rewritten) => {
            *event = rewritten;
            DowngradeOutcome::Downgraded
        }
        Err(reason) => DowngradeOutcome::KeptNative { reason },
    }
}

/// Events kept at the native version since start, and the latest reason.
static KEPT_NATIVE: std::sync::Mutex<(u64, Option<String>)> = std::sync::Mutex::new((0, None));

/// Record an event that [`downgrade_event`] kept at the native version.
///
/// Writers call this from inside the tracing dispatch, where logging is not
/// reliable; the supervisor reports the tally from its settings poll loop.
pub fn record_kept_native(reason: &str) {
    if let Ok(mut tally) = KEPT_NATIVE.lock() {
        tally.0 += 1;
        tally.1 = Some(reason.to_string());
    }
}

/// Number of events kept at the native version since start, and the latest reason.
#[must_use]
pub fn kept_native_tally() -> (u64, Option<String>) {
    KEPT_NATIVE
        .lock()
        .map(|tally| tally.clone())
        .unwrap_or_default()
}

fn rewrite(event: &Value, defs: &VersionDefs) -> Result<Value, String> {
    let mut rewritten = event.clone();
    let obj = rewritten
        .as_object_mut()
        .ok_or_else(|| "event is not a JSON object".to_string())?;
    let class_uid = obj
        .get("class_uid")
        .and_then(Value::as_u64)
        .ok_or_else(|| "event has no class_uid".to_string())?;
    let class = defs
        .classes
        .iter()
        .find(|class| class.uid == class_uid)
        .ok_or_else(|| format!("class {class_uid} is not defined in OCSF {}", defs.version))?;

    let metadata = obj
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "event has no metadata".to_string())?;
    let native_version = metadata
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or(crate::OCSF_VERSION)
        .to_string();
    let mut profiles = Vec::new();
    if let Some(Value::Array(declared)) = metadata.get_mut("profiles") {
        declared.retain(|p| p.as_str().is_some_and(|p| class.profiles.contains(&p)));
        profiles.extend(
            declared
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string),
        );
    }

    let mut removed = Map::new();
    prune(obj, &class.def, defs, &profiles, "", &mut removed)?;
    check(obj, &class.def, defs, &profiles, "")?;

    if let Some(metadata) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.insert(
            "version".to_string(),
            Value::String(defs.version.to_string()),
        );
    }
    let unmapped = obj
        .entry("unmapped")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "unmapped is not an object".to_string())?;
    unmapped.insert("downgraded_from".to_string(), Value::String(native_version));
    if !removed.is_empty() {
        unmapped.insert("downgraded_attributes".to_string(), Value::Object(removed));
    }
    Ok(rewritten)
}

fn applies(attribute: &AttributeDef, profiles: &[String]) -> bool {
    attribute.profiles.is_empty()
        || attribute
            .profiles
            .iter()
            .any(|p| profiles.iter().any(|declared| declared == p))
}

fn object_def<'a>(defs: &'a VersionDefs, name: &str, path: &str) -> Result<&'a TypeDef, String> {
    defs.objects
        .iter()
        .find(|object| object.name == name)
        .ok_or_else(|| {
            format!(
                "OpenShell has no OCSF {} definition for object {name} at {path}",
                defs.version
            )
        })
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{path}.{name}")
    }
}

/// Move attributes the target does not define, at any depth, into `removed`.
fn prune(
    obj: &mut Map<String, Value>,
    def: &TypeDef,
    defs: &VersionDefs,
    profiles: &[String],
    path: &str,
    removed: &mut Map<String, Value>,
) -> Result<(), String> {
    let keys: Vec<String> = obj.keys().cloned().collect();
    for key in keys {
        let full = join(path, &key);
        let Some(attribute) = def
            .attributes
            .iter()
            .find(|a| a.name == key && applies(a, profiles))
        else {
            if let Some(value) = obj.remove(&key) {
                removed.insert(full, value);
            }
            continue;
        };
        let Some(object) = attribute.object else {
            continue;
        };
        match obj.get_mut(&key) {
            Some(Value::Object(child)) => {
                prune(
                    child,
                    object_def(defs, object, &full)?,
                    defs,
                    profiles,
                    &full,
                    removed,
                )?;
            }
            Some(Value::Array(items)) => {
                for (i, item) in items.iter_mut().enumerate() {
                    if let Value::Object(child) = item {
                        let item_path = format!("{full}[{i}]");
                        let child_def = object_def(defs, object, &item_path)?;
                        prune(child, child_def, defs, profiles, &item_path, removed)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Confirm every requirement of the target holds, at any depth.
fn check(
    obj: &Map<String, Value>,
    def: &TypeDef,
    defs: &VersionDefs,
    profiles: &[String],
    path: &str,
) -> Result<(), String> {
    let present = |name: &str| obj.get(name).is_some_and(|value| !value.is_null());
    for attribute in def
        .attributes
        .iter()
        .filter(|a| a.required && applies(a, profiles))
    {
        if !present(attribute.name) {
            return Err(format!(
                "{} is required by OCSF {}",
                join(path, attribute.name),
                defs.version
            ));
        }
    }
    if !def.at_least_one.is_empty() && !def.at_least_one.iter().any(|name| present(name)) {
        return Err(format!(
            "{} requires one of {:?} in OCSF {}",
            if path.is_empty() { def.name } else { path },
            def.at_least_one,
            defs.version
        ));
    }
    for attribute in def.attributes {
        let (Some(object), Some(value)) = (attribute.object, obj.get(attribute.name)) else {
            continue;
        };
        let full = join(path, attribute.name);
        let child_def = object_def(defs, object, &full)?;
        match value {
            Value::Object(child) => check(child, child_def, defs, profiles, &full)?,
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if let Value::Object(child) = item {
                        check(child, child_def, defs, profiles, &format!("{full}[{i}]"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_version(v: &str) -> (u32, u32, u32) {
    let parts: Vec<u32> = v.split('.').filter_map(|s| s.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::{sample_events, test_sandbox_context};

    const TARGETS: [&str; 2] = ["1.1.0", "1.3.0"];

    fn schema_class_name(class_uid: u64) -> &'static str {
        match class_uid {
            4001 => "network_activity",
            4002 => "http_activity",
            4007 => "ssh_activity",
            1007 => "process_activity",
            2004 => "detection_finding",
            6002 => "application_lifecycle",
            6003 => "api_activity",
            5019 => "device_config_state_change",
            _ => "base_event",
        }
    }

    /// Downgrade `event` and assert it validates against whichever schema
    /// version its `metadata.version` claims afterwards.
    fn downgrade_and_check(event: &crate::OcsfEvent, target: &str) -> (Value, DowngradeOutcome) {
        let mut json = event.to_json().expect("serialize");
        let original = json.clone();
        let outcome = downgrade_event(&mut json, target);
        if !matches!(outcome, DowngradeOutcome::Downgraded) {
            assert_eq!(
                json, original,
                "an event that is not downgraded must be unchanged"
            );
        }
        let version = json["metadata"]["version"].as_str().unwrap().to_string();
        let class = schema_class_name(json["class_uid"].as_u64().unwrap());
        let schema = crate::validation::load_class_schema_for_version(&version, class);
        crate::validation::validate_required_fields(&json, &schema);
        (json, outcome)
    }

    fn peer() -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))
    }

    fn http(response: bool) -> crate::OcsfEvent {
        let ctx = test_sandbox_context();
        let builder = crate::HttpActivityBuilder::new(&ctx)
            .action(crate::ActionId::Denied)
            .http_request(crate::HttpRequest::new(
                "GET",
                crate::Url::new("https", "api.example.com", "/v1", 443),
            ))
            .src_endpoint(crate::Endpoint::from_ip(peer(), 51234))
            .dst_endpoint(crate::Endpoint::from_domain("api.example.com", 443));
        if response {
            builder
                .http_response(crate::HttpResponse { code: 403 })
                .build()
        } else {
            builder.build()
        }
    }

    fn network(src: bool, dst: bool) -> crate::OcsfEvent {
        let ctx = test_sandbox_context();
        let builder = crate::NetworkActivityBuilder::new(&ctx);
        let builder = if dst {
            builder.dst_endpoint(crate::Endpoint::from_domain("api.example.com", 443))
        } else {
            builder.src_endpoint_addr(peer(), 51234)
        };
        let builder = if src && dst {
            builder.src_endpoint_addr(peer(), 51234)
        } else {
            builder
        };
        builder.action(crate::ActionId::Allowed).build()
    }

    #[test]
    fn every_sample_event_claims_a_version_it_conforms_to() {
        let ctx = test_sandbox_context();
        for target in TARGETS {
            for (class, event) in sample_events(&ctx) {
                let (json, outcome) = downgrade_and_check(&event, target);
                let expected = if outcome == DowngradeOutcome::Downgraded {
                    target
                } else {
                    crate::OCSF_VERSION
                };
                assert_eq!(json["metadata"]["version"], expected, "{class} -> {target}");
            }
        }
    }

    #[test]
    fn complete_http_and_network_events_are_downgraded() {
        for target in TARGETS {
            for event in [http(true), network(true, true)] {
                let (_, outcome) = downgrade_and_check(&event, target);
                assert_eq!(outcome, DowngradeOutcome::Downgraded, "{target}");
            }
        }
    }

    #[test]
    fn request_only_http_stays_native() {
        for target in TARGETS {
            let (json, outcome) = downgrade_and_check(&http(false), target);
            assert!(
                matches!(&outcome, DowngradeOutcome::KeptNative { reason } if reason.contains("http_response")),
                "{outcome:?}"
            );
            assert!(json.pointer("/unmapped/downgraded_from").is_none());
        }
    }

    #[test]
    fn network_endpoint_requirements_follow_target_version() {
        // 1.3 requires only dst_endpoint; 1.1 requires both endpoints.
        let (_, outcome) = downgrade_and_check(&network(false, true), "1.3.0");
        assert_eq!(outcome, DowngradeOutcome::Downgraded);
        let (_, outcome) = downgrade_and_check(&network(false, true), "1.1.0");
        assert!(matches!(outcome, DowngradeOutcome::KeptNative { .. }));
        let (_, outcome) = downgrade_and_check(&network(true, false), "1.3.0");
        assert!(matches!(outcome, DowngradeOutcome::KeptNative { .. }));
    }

    #[test]
    fn removed_attributes_are_kept_under_unmapped() {
        let (json, outcome) = downgrade_and_check(&network(true, true), "1.3.0");
        assert_eq!(outcome, DowngradeOutcome::Downgraded);
        assert!(json.get("is_src_dst_assignment_known").is_none());
        assert_eq!(
            json["unmapped"]["downgraded_attributes"]["is_src_dst_assignment_known"],
            true
        );
        assert_eq!(json["unmapped"]["downgraded_from"], crate::OCSF_VERSION);
        let profiles = json["metadata"]["profiles"].as_array().unwrap();
        assert!(profiles.iter().any(|p| p == "security_control"));
    }

    #[test]
    fn short_target_versions_are_labelled_in_full() {
        let mut json = http(true).to_json().unwrap();
        assert_eq!(
            downgrade_event(&mut json, "1.1"),
            DowngradeOutcome::Downgraded
        );
        assert_eq!(json["metadata"]["version"], "1.1.0");
    }

    #[test]
    fn current_or_newer_targets_are_not_needed() {
        for target in [crate::OCSF_VERSION, "1.9.0"] {
            let mut json = http(false).to_json().unwrap();
            let original = json.clone();
            assert_eq!(
                downgrade_event(&mut json, target),
                DowngradeOutcome::NotNeeded
            );
            assert_eq!(json, original);
        }
    }

    #[test]
    fn unsupported_target_versions_stay_native() {
        let mut json = http(true).to_json().unwrap();
        let original = json.clone();
        assert!(matches!(
            downgrade_event(&mut json, "1.2.0"),
            DowngradeOutcome::KeptNative { .. }
        ));
        assert_eq!(json, original);
    }

    #[test]
    fn vendored_schemas_cover_the_native_version_and_every_target() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/ocsf");
        for version in std::iter::once(crate::OCSF_VERSION).chain(TARGETS) {
            let recorded =
                std::fs::read_to_string(format!("{root}/v{version}/VERSION")).unwrap_or_default();
            assert_eq!(
                recorded.trim(),
                version,
                "vendor schemas/ocsf/v{version}; see schemas/ocsf/README.md"
            );
        }
        for target in TARGETS {
            assert!(
                parse_version(target) < parse_version(crate::OCSF_VERSION),
                "{target}"
            );
        }
        let generated: Vec<&str> = VERSIONS.iter().map(|defs| defs.version).collect();
        assert_eq!(generated, TARGETS);
    }

    /// Regenerate with `UPDATE_OCSF_DOWNGRADE_DEFS=1 cargo test -p openshell-ocsf downgrade_definitions`.
    #[test]
    fn downgrade_definitions_match_vendored_schemas() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/format/downgrade_defs.rs");
        let expected = render_definitions();
        if std::env::var_os("UPDATE_OCSF_DOWNGRADE_DEFS").is_some() {
            std::fs::write(path, &expected).unwrap();
        }
        let actual = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            actual == expected,
            "downgrade_defs.rs is out of date; rerun with UPDATE_OCSF_DOWNGRADE_DEFS=1"
        );
    }

    fn attribute_entries(schema: &Value) -> Vec<(String, Value)> {
        let mut entries: Vec<(String, Value)> = match schema.get("attributes") {
            Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_object)
                .flat_map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())))
                .collect(),
            _ => Vec::new(),
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    fn quoted(names: &[String]) -> String {
        names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn strings(value: Option<&Value>) -> Vec<String> {
        match value {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    fn render_type(name: &str, schema: &Value, indent: &str) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "{indent}TypeDef {{\n{indent}    name: \"{name}\",\n{indent}    attributes: &[\n"
        );
        for (attr_name, def) in attribute_entries(schema) {
            let object = match def.get("object_type").and_then(Value::as_str) {
                Some(o) if o != "object" => format!("Some(\"{o}\")"),
                _ => "None".to_string(),
            };
            let required = def.get("requirement").and_then(Value::as_str) == Some("required");
            let profiles = strings(def.get("profiles").or_else(|| def.get("profile")));
            writeln!(
                out,
                "{indent}        attr(\"{attr_name}\", {object}, {required}, &[{}]),",
                quoted(&profiles)
            )
            .unwrap();
        }
        let at_least_one = strings(schema.pointer("/constraints/at_least_one"));
        write!(
            out,
            "{indent}    ],\n{indent}    at_least_one: &[{}],\n{indent}}}",
            quoted(&at_least_one)
        )
        .unwrap();
        out
    }

    fn sorted_schema_files(dir: &str) -> Vec<(String, Value)> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        files.sort();
        files
            .into_iter()
            .map(|p| {
                let name = p.file_stem().unwrap().to_string_lossy().to_string();
                let value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
                (name, value)
            })
            .collect()
    }

    fn render_definitions() -> String {
        use std::fmt::Write as _;
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/ocsf");
        let mut out = String::from(
            "// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.\n\
             // SPDX-License-Identifier: Apache-2.0\n\n\
             //! OCSF attribute definitions for downgrade targets.\n//!\n\
             //! @generated from the vendored schemas in `schemas/ocsf/`. Do not edit; regenerate with\n\
             //! `UPDATE_OCSF_DOWNGRADE_DEFS=1 cargo test -p openshell-ocsf downgrade_definitions`.\n\n\
             use super::downgrade::{ClassDef, TypeDef, VersionDefs, attr};\n\n\
             #[rustfmt::skip]\npub(super) static VERSIONS: &[VersionDefs] = &[\n",
        );
        for version in TARGETS {
            write!(
                out,
                "    VersionDefs {{\n        version: \"{version}\",\n        classes: &[\n"
            )
            .unwrap();
            for (name, schema) in sorted_schema_files(&format!("{root}/v{version}/classes")) {
                let uid = schema["uid"].as_u64().unwrap();
                let profiles = strings(schema.get("profiles"));
                write!(out,
                    "            ClassDef {{\n                uid: {uid},\n                profiles: &[{}],\n                def: {},\n            }},\n",
                    quoted(&profiles),
                    render_type(&name, &schema, "                ").trim_start()
                ).unwrap();
            }
            out.push_str("        ],\n        objects: &[\n");
            for (name, schema) in sorted_schema_files(&format!("{root}/v{version}/objects")) {
                out.push_str(&render_type(&name, &schema, "            "));
                out.push_str(",\n");
            }
            out.push_str("        ],\n    },\n");
        }
        out.push_str("];\n");
        out
    }
}
