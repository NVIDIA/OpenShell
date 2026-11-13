// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for converting `google.protobuf.Struct` values to and from JSON.

/// Errors converting JSON values into protobuf well-known types.
#[derive(Debug, thiserror::Error)]
pub enum ProtoStructError {
    /// A JSON number cannot be represented exactly by protobuf's double value.
    #[error("JSON number {0} cannot be represented exactly as a protobuf double")]
    UnrepresentableNumber(serde_json::Number),
}

/// Convert a JSON object into a protobuf Struct.
pub fn json_object_to_struct(
    object: serde_json::Map<String, serde_json::Value>,
) -> Result<prost_types::Struct, ProtoStructError> {
    Ok(prost_types::Struct {
        fields: object
            .into_iter()
            .map(|(key, value)| json_value_to_proto(value).map(|value| (key, value)))
            .collect::<Result<_, _>>()?,
    })
}

/// Convert a JSON value into a protobuf Value.
pub fn json_value_to_proto(
    value: serde_json::Value,
) -> Result<prost_types::Value, ProtoStructError> {
    use prost_types::{ListValue, Value, value::Kind};

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(value),
        serde_json::Value::Number(value) => Kind::NumberValue(number_to_f64_exact(&value)?),
        serde_json::Value::String(value) => Kind::StringValue(value),
        serde_json::Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(json_value_to_proto)
                .collect::<Result<_, _>>()?,
        }),
        serde_json::Value::Object(object) => Kind::StructValue(json_object_to_struct(object)?),
    };

    Ok(Value { kind: Some(kind) })
}

fn number_to_f64_exact(value: &serde_json::Number) -> Result<f64, ProtoStructError> {
    let number = value
        .as_f64()
        .ok_or_else(|| ProtoStructError::UnrepresentableNumber(value.clone()))?;

    let exact = value.as_i64().map_or_else(
        || value.as_u64().is_none_or(integer_is_exact_in_f64),
        |integer| integer_is_exact_in_f64(integer.unsigned_abs()),
    );

    exact
        .then_some(number)
        .ok_or_else(|| ProtoStructError::UnrepresentableNumber(value.clone()))
}

fn integer_is_exact_in_f64(integer: u64) -> bool {
    integer == 0
        || (u64::BITS - integer.leading_zeros()).saturating_sub(integer.trailing_zeros())
            <= f64::MANTISSA_DIGITS
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_proto_values_round_trip() {
        let json = serde_json::json!({
            "null": null,
            "bool": true,
            "number": 42.5,
            "string": "value",
            "list": [1.0, {"nested": "value"}],
        });
        let serde_json::Value::Object(object) = json.clone() else {
            unreachable!();
        };

        let proto = json_object_to_struct(object).unwrap();

        assert_eq!(struct_to_json_value(&proto), json);
    }

    #[test]
    fn rejects_integer_that_cannot_round_trip_through_protobuf_double() {
        let value = serde_json::json!(9_007_199_254_740_993_u64);

        let err = json_value_to_proto(value).expect_err("lossy integer must be rejected");

        assert!(err.to_string().contains("9007199254740993"));
        assert!(err.to_string().contains("exactly"));
    }

    #[test]
    fn accepts_integer_that_round_trips_through_protobuf_double() {
        let value = serde_json::json!(9_007_199_254_740_992_u64);

        let proto = json_value_to_proto(value.clone()).expect("integer should be exact");

        assert_eq!(
            value_to_json(&proto).as_f64(),
            value.as_f64(),
            "protobuf Struct stores all numbers as doubles"
        );
    }
}
