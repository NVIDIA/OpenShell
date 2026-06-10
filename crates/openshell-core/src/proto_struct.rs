// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for decoding `google.protobuf.Struct` values.

/// Convert a protobuf Struct into a JSON object for typed serde decoding.
#[must_use]
pub fn struct_to_json_object(
    config: &prost_types::Struct,
) -> serde_json::Map<String, serde_json::Value> {
    config
        .fields
        .iter()
        .map(|(key, value)| (key.clone(), value_to_json(value)))
        .collect()
}

/// Convert a protobuf Struct into a JSON value for typed serde decoding.
#[must_use]
pub fn struct_to_json_value(config: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(struct_to_json_object(config))
}

/// Convert a protobuf Value into a JSON value for typed serde decoding.
#[must_use]
pub fn value_to_json(value: &prost_types::Value) -> serde_json::Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NumberValue(num)) => serde_json::Number::from_f64(*num)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(prost_types::value::Kind::StringValue(val)) => serde_json::Value::String(val.clone()),
        Some(prost_types::value::Kind::BoolValue(val)) => serde_json::Value::Bool(*val),
        Some(prost_types::value::Kind::StructValue(val)) => {
            serde_json::Value::Object(struct_to_json_object(val))
        }
        Some(prost_types::value::Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.iter().map(value_to_json).collect())
        }
        Some(prost_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
    }
}
