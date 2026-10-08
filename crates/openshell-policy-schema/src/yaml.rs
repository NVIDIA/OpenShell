// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML compatibility at `OpenShell`'s authored-data boundaries.

use serde::Serialize;
use serde::de::{DeserializeOwned, IntoDeserializer, Visitor};
use serde_yml::{Error, Value};

/// Reject duplicate keys before typed decoding and retain the previous rule
/// that a null scalar cannot stand in for a mapping or a struct.
pub fn from_str<T: DeserializeOwned>(source: &str) -> Result<T, Error> {
    let config =
        serde_yml::ParserConfig::new().duplicate_key_policy(serde_yml::DuplicateKeyPolicy::Error);
    let value: Value = serde_yml::from_str_with_config(source, &config)?;
    T::deserialize(Deserializer::new(&value))
}

/// A type-directed adapter: null remains valid for options and untyped data,
/// but is rejected when a typed consumer requests a map or struct.
pub struct Deserializer<'a>(&'a Value);

impl<'a> Deserializer<'a> {
    pub fn new(value: &'a Value) -> Self {
        // YAML tags are transparent to typed consumers, as in noyalib.
        match value {
            Value::Tagged(tagged) => Self::new(tagged.value()),
            _ => Self(value),
        }
    }
}

impl<'de> IntoDeserializer<'de, Error> for Deserializer<'de> {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

macro_rules! delegate {
    ($($method:ident),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            serde::Deserializer::$method(serde_yml::Deserializer::new(self.0), visitor)
        })*
    };
}

impl<'de> serde::Deserializer<'de> for Deserializer<'de> {
    type Error = Error;

    delegate!(
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier,
        deserialize_ignored_any
    );

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Mapping(_) => self.deserialize_map(visitor),
            Value::Sequence(_) => self.deserialize_seq(visitor),
            _ => {
                serde::Deserializer::deserialize_any(serde_yml::Deserializer::new(self.0), visitor)
            }
        }
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let Value::Mapping(mapping) = self.0 else {
            if !self.0.is_null() {
                return serde::Deserializer::deserialize_map(
                    serde_yml::Deserializer::new(self.0),
                    visitor,
                );
            }
            return Err(Error::TypeMismatch {
                expected: "mapping",
                found: "null".into(),
            });
        };
        let mut access = serde::de::value::MapDeserializer::new(
            mapping
                .iter()
                .map(|(key, value)| (key.as_str(), Self::new(value))),
        );
        let result = visitor.visit_map(&mut access)?;
        access.end()?;
        Ok(result)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let Value::Sequence(sequence) = self.0 else {
            return serde::Deserializer::deserialize_seq(
                serde_yml::Deserializer::new(self.0),
                visitor,
            );
        };
        let mut access = serde::de::value::SeqDeserializer::new(sequence.iter().map(Self::new));
        let result = visitor.visit_seq(&mut access)?;
        access.end()?;
        Ok(result)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_tuple(len, visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        serde::Deserializer::deserialize_unit_struct(
            serde_yml::Deserializer::new(self.0),
            name,
            visitor,
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        // Authored OpenShell enums are scalar enums or untagged enums. The
        // latter recurse through deserialize_any above.
        serde::Deserializer::deserialize_enum(
            serde_yml::Deserializer::new(self.0),
            name,
            variants,
            visitor,
        )
    }
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
            assert!(from_str::<Document>(source).is_err(), "{source}");
        }
        let parsed: Document = from_str("entries: {x: {config: {optional: null}}}").unwrap();
        assert!(parsed.entries["x"].config["optional"].is_null());
    }
    #[test]
    fn duplicate_fields_are_rejected() {
        assert!(from_str::<Document>("entries: {}\nentries: {x: {}}").is_err());
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
