// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML compatibility at `OpenShell`'s authored-data boundaries.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_yml::{Error, Value};

/// Load authored YAML with bounded parsing and duplicate-key rejection.
pub fn from_str<T: DeserializeOwned>(source: &str) -> Result<T, Error> {
    from_str_with_object_paths(source, &[])
}

/// Reject null at schema-declared object paths before ordinary typed decoding.
///
/// A `*` selects each sequence element or mapping value. Missing fields are
/// left to Serde defaults; optional objects should not be listed themselves.
pub fn from_str_with_object_paths<T: DeserializeOwned>(
    source: &str,
    paths: &[&str],
) -> Result<T, Error> {
    let config =
        serde_yml::ParserConfig::new().duplicate_key_policy(serde_yml::DuplicateKeyPolicy::Error);
    let value: Value = serde_yml::from_str_with_config(source, &config)?;
    reject_null_objects(&value, paths)?;
    T::deserialize(serde_yml::Deserializer::new(&value))
}

/// Validate only declared schema objects, not arbitrary user-data mappings.
pub fn reject_null_objects(value: &Value, paths: &[&str]) -> Result<(), Error> {
    reject_null_at_path(value, "", "")?;
    for path in paths {
        reject_null_at_path(value, path, "")?;
    }
    Ok(())
}

fn reject_null_at_path(value: &Value, remaining: &str, location: &str) -> Result<(), Error> {
    if let Value::Tagged(tagged) = value {
        return reject_null_at_path(tagged.value(), remaining, location);
    }
    if remaining.is_empty() {
        return if value.is_null() {
            Err(Error::Parse(format!(
                "{}: null is not an object",
                if location.is_empty() {
                    ".".to_owned()
                } else {
                    crate::bound_path(location.to_owned())
                }
            )))
        } else {
            Ok(())
        };
    }
    let (field, rest) = remaining.split_once('.').unwrap_or((remaining, ""));
    if field == "*" {
        if let Some(mapping) = value.as_mapping() {
            for (key, child) in mapping {
                reject_null_at_path(child, rest, &format!("{location}[{:?}]", key.as_str()))?;
            }
        } else if let Some(sequence) = value.as_sequence() {
            for (index, child) in sequence.iter().enumerate() {
                reject_null_at_path(child, rest, &format!("{location}[{index}]"))?;
            }
        }
    } else if let Some(child) = value.as_mapping().and_then(|mapping| mapping.get(field)) {
        let path = if location.is_empty() {
            field.to_owned()
        } else {
            format!("{location}.{field}")
        };
        reject_null_at_path(child, rest, &path)?;
    }
    Ok(())
}

/// Preserve authored strings even for YAML 1.1 readers (dates, timestamps,
/// underscore-separated integers, and legacy boolean words).
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    let value = serde_yml::to_value(&value)?;
    let mut yaml = serde_yml::to_string(&value)?;
    let mut strings = Vec::new();
    collect_strings(&value, "", &mut strings);
    if strings.is_empty() {
        return Ok(yaml);
    }
    // This is our already-emitted output, not a fresh untrusted input. Size the
    // formatting walk to that output so an otherwise valid large export does
    // not acquire the input parser's collection or byte limits.
    let mut config = serde_yml::ParserConfig::new();
    config.max_document_length = config.max_document_length.max(yaml.len());
    config.max_total_scalar_bytes = config.max_total_scalar_bytes.max(yaml.len());
    config.max_events = config.max_events.max(yaml.len().saturating_mul(4));
    config.max_nodes = config.max_nodes.max(yaml.len().saturating_mul(2));
    config.max_mapping_keys = config.max_mapping_keys.max(yaml.len());
    config.max_sequence_length = config.max_sequence_length.max(yaml.len());
    let document = serde_yml::cst::parse_document_with_config(&yaml, &config)?;
    let mut edits = Vec::new();
    for (path, string, is_key) in strings {
        let (start, end) = if is_key {
            document.key_span(&path)
        } else {
            document.span_at(&path)
        }
        .ok_or_else(|| Error::Parse("serialized YAML string missing".into()))?;
        // Already quoted or block-styled strings retain their emitter style.
        if !yaml[start..end].starts_with(['\'', '"', '|', '>']) {
            let quoted = serde_yml::to_string_with_config(
                &string,
                &serde_yml::SerializerConfig::new().quote_all(true),
            )?;
            edits.push((start, end, quoted.trim_end().to_owned()));
        }
    }
    edits.sort_unstable_by_key(|(start, _, _)| *start);
    for (start, end, quoted) in edits.into_iter().rev() {
        yaml.replace_range(start..end, &quoted);
    }
    Ok(yaml)
}

fn collect_strings<'a>(value: &'a Value, path: &str, result: &mut Vec<(String, &'a str, bool)>) {
    match value {
        Value::String(string) if needs_legacy_quotes(string) => {
            result.push((path.into(), string, false));
        }
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let child_path = format!("{path}{}", serde_yml::path::quote_key(key.as_str()));
                if needs_legacy_quotes(key.as_str()) {
                    result.push((child_path.clone(), key.as_str(), true));
                }
                collect_strings(child, &child_path, result);
            }
        }
        Value::Sequence(sequence) => {
            for (index, child) in sequence.iter().enumerate() {
                collect_strings(child, &format!("{path}[{index}]"), result);
            }
        }
        Value::Tagged(tagged) => collect_strings(tagged.value(), path, result),
        _ => {}
    }
}

fn needs_legacy_quotes(string: &str) -> bool {
    let unsigned = string.trim_start_matches(['+', '-']);
    (unsigned.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && unsigned.bytes().all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'_' | b'.'
                        | b':'
                        | b'/'
                        | b'+'
                        | b'-'
                        | b' '
                        | b'T'
                        | b't'
                        | b'Z'
                        | b'z'
                        | b'E'
                        | b'e'
                        | b'X'
                        | b'x'
                        | b'O'
                        | b'o'
                        | b'B'
                        | b'b'
                )
        }))
        || matches!(
            string.to_ascii_lowercase().as_str(),
            "yes" | "no" | "on" | "off" | "y" | "n"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Debug, Deserialize)]
    struct Document {
        #[serde(default)]
        entries: std::collections::BTreeMap<String, Entry>,
    }
    #[derive(Debug, Default, Deserialize)]
    struct Entry {
        #[serde(default)]
        config: std::collections::BTreeMap<String, serde_json::Value>,
    }

    #[test]
    fn null_objects_are_rejected_but_user_data_null_is_retained() {
        for source in [
            "entries: null",
            "entries: {x: null}",
            "entries: {x: {config: null}}",
        ] {
            assert!(
                from_str_with_object_paths::<Document>(
                    source,
                    &["entries", "entries.*", "entries.*.config"]
                )
                .is_err(),
                "{source}"
            );
        }
        let parsed: Document = from_str_with_object_paths(
            "entries: {x: {config: {optional: null}}}",
            &["entries", "entries.*", "entries.*.config"],
        )
        .unwrap();
        assert!(parsed.entries["x"].config["optional"].is_null());
    }
    #[test]
    fn duplicate_fields_are_rejected() {
        assert!(from_str::<Document>("entries: {}\nentries: {x: {}}").is_err());
    }
    #[test]
    fn empty_documents_do_not_become_default_objects() {
        for source in ["", "# comment only", "null", "~"] {
            assert!(from_str::<Document>(source).is_err(), "{source}");
        }
        assert!(from_str::<Document>("{}").is_ok());
    }

    #[test]
    fn object_paths_preserve_optional_nulls_and_visit_sequence_elements() {
        #[derive(Debug, Deserialize)]
        struct Profile {
            optional: Option<Entry>,
            endpoints: Vec<Entry>,
        }
        let paths = ["endpoints.*", "endpoints.*.config", "optional.config"];
        let parsed: Profile = from_str_with_object_paths(
            "optional: null\nendpoints: [{config: {data: null}}]",
            &paths,
        )
        .unwrap();
        assert!(parsed.optional.is_none());
        assert!(parsed.endpoints[0].config["data"].is_null());
        for source in [
            "optional: null\nendpoints: [null]",
            "optional: {config: null}\nendpoints: []",
        ] {
            assert!(
                from_str_with_object_paths::<Profile>(source, &paths).is_err(),
                "{source}"
            );
        }
        let source = "entries: {'key.with.dots': null}";
        let error = from_str_with_object_paths::<Document>(source, &["entries.*"]).unwrap_err();
        assert!(error.to_string().contains("key.with.dots"));
    }
    #[test]
    fn legacy_reader_sensitive_strings_are_quoted_without_changing_values() {
        let value = serde_json::json!({"versions": ["2025-11-25"], "timestamp": "2026-01-01T00:00:00Z", "number": "1_000", "boolean": "yes", "duration": "1.500s", "actual_number": 1000, "data": null});
        let yaml = to_string(&value).unwrap();
        for string in ["2025-11-25", "2026-01-01T00:00:00Z", "1_000", "yes"] {
            assert!(
                yaml.contains(&format!("\"{string}\"")) || yaml.contains(&format!("'{string}'")),
                "{yaml}"
            );
        }
        assert_eq!(from_str::<serde_json::Value>(&yaml).unwrap(), value);
    }
}
