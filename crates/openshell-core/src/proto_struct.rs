// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for converting `google.protobuf.Struct` values to and from JSON.

use serde::{Deserialize, Deserializer, de::Error as _};

/// Errors converting JSON values into protobuf well-known types.
#[derive(Debug, thiserror::Error)]
pub enum ProtoStructError {
    /// A JSON number cannot be represented exactly by protobuf's double value.
    #[error("JSON number {0} cannot be represented exactly as a protobuf double")]
    UnrepresentableNumber(serde_json::Number),
}

/// A non-finite protobuf number cannot be used as typed configuration.
#[derive(Debug, thiserror::Error)]
#[error("protobuf configuration contains a non-finite number")]
pub struct TypedProtoStructError;

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

/// Convert protobuf configuration into JSON for typed serde decoding.
///
/// Finite integral doubles in the JSON integer range become integers; fractions
/// and larger finite numbers remain floats. This preserves exactly represented
/// large integers accepted by [`json_value_to_proto`]. A receiver cannot detect
/// precision already lost before transport; the producer must enforce exactness.
/// General-purpose conversions keep their existing float and null behavior.
///
/// # Errors
///
/// Reject non-finite numbers anywhere in the configuration instead of turning
/// them into null, which could silently clear an optional constraint.
pub fn struct_to_typed_json_value(
    config: &prost_types::Struct,
) -> Result<serde_json::Value, TypedProtoStructError> {
    config
        .fields
        .iter()
        .map(|(key, value)| typed_value_to_json(value).map(|value| (key.clone(), value)))
        .collect::<Result<serde_json::Map<_, _>, _>>()
        .map(serde_json::Value::Object)
}

// The casts below are preceded by finite, integral and exclusive range guards.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn typed_value_to_json(
    value: &prost_types::Value,
) -> Result<serde_json::Value, TypedProtoStructError> {
    use prost_types::value::Kind;
    use serde_json::{Number, Value};

    Ok(match value.kind.as_ref() {
        Some(Kind::NumberValue(number)) => {
            if !number.is_finite() {
                return Err(TypedProtoStructError);
            }
            // Exclusive upper bounds are intentional: u64::MAX and i64::MAX
            // round UP when converted to f64. Guard before any integer cast.
            let integer = if number.fract() == 0.0 {
                if *number >= 0.0 && *number < u64::MAX as f64 {
                    Some(Number::from(*number as u64))
                } else if *number >= i64::MIN as f64 && *number < 0.0 {
                    Some(Number::from(*number as i64))
                } else {
                    None
                }
            } else {
                None
            };
            Value::Number(
                integer
                    .or_else(|| Number::from_f64(*number))
                    .ok_or(TypedProtoStructError)?,
            )
        }
        Some(Kind::StructValue(config)) => struct_to_typed_json_value(config)?,
        Some(Kind::ListValue(list)) => Value::Array(
            list.values
                .iter()
                .map(typed_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        // Only numeric values differ from the compatible general conversion.
        _ => value_to_json(value),
    })
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

/// Deserialize a present field as a non-empty list of non-empty strings.
///
/// Use with `#[serde(default, deserialize_with = "...")]` on
/// `Option<Vec<String>>` fields. Missing fields use the option default; present
/// fields must be arrays and cannot be empty.
pub fn deserialize_optional_non_empty_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(D::Error::custom("must be a non-empty list of strings"));
    }

    for (idx, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            return Err(D::Error::custom(format!(
                "[{idx}] must be a non-empty string"
            )));
        }
    }

    Ok(Some(values))
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

    #[test]
    fn typed_configuration_round_trips_recursive_integer_fields() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Limits {
            max_processes: Option<u32>,
            max_resident_bytes: u64,
        }
        #[derive(Debug, Deserialize, PartialEq)]
        struct Config {
            service_ports: Vec<u16>,
            limits: Limits,
            nested: Vec<Limits>,
        }
        let json = serde_json::json!({
            "service_ports": [8080, 65535],
            "limits": {"max_processes": 128, "max_resident_bytes": 1_073_741_824},
            "nested": [{"max_processes": null, "max_resident_bytes": 0}]
        });
        let expected: Config = serde_json::from_value(json.clone()).unwrap();
        let proto = json_object_to_struct(json.as_object().unwrap().clone()).unwrap();
        let actual: Config =
            serde_json::from_value(struct_to_typed_json_value(&proto).unwrap()).unwrap();
        assert_eq!(actual, expected);
        // The general-purpose conversion retains its existing float semantics.
        assert!(struct_to_json_value(&proto)["service_ports"][0].is_f64());
    }

    #[test]
    fn typed_configuration_rejects_nonfinite_numbers() {
        for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut proto = json_object_to_struct(
                serde_json::json!({"limits": [{"max_processes": 128}]})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap();
            let Some(prost_types::value::Kind::ListValue(list)) =
                proto.fields.get_mut("limits").unwrap().kind.as_mut()
            else {
                unreachable!();
            };
            let Some(prost_types::value::Kind::StructValue(limits)) = list.values[0].kind.as_mut()
            else {
                unreachable!();
            };
            limits.fields.get_mut("max_processes").unwrap().kind =
                Some(prost_types::value::Kind::NumberValue(number));
            assert!(struct_to_typed_json_value(&proto).is_err());
            assert!(struct_to_json_value(&proto)["limits"][0]["max_processes"].is_null());
        }
    }

    #[test]
    fn typed_configuration_preserves_numeric_boundaries() {
        for integer in [
            0,
            9_007_199_254_740_992,
            9_007_199_254_740_994,
            1_u64 << 63,
            u64::MAX - 2047,
        ] {
            let proto = json_object_to_struct(
                serde_json::json!({"limit": integer})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap();
            let value = struct_to_typed_json_value(&proto).unwrap();
            assert_eq!(
                serde_json::from_value::<u64>(value["limit"].clone()).unwrap(),
                integer
            );
        }
        let proto = json_object_to_struct(
            serde_json::json!({"limit": i64::MIN})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        let value = struct_to_typed_json_value(&proto).unwrap();
        assert_eq!(
            serde_json::from_value::<i64>(value["limit"].clone()).unwrap(),
            i64::MIN
        );
        // Fractions and doubles outside the integer range must not be truncated
        // or saturated into a valid integer configuration value.
        for number in [1.5, -1.0, 18_446_744_073_709_551_616.0, f64::MAX] {
            let proto = prost_types::Struct {
                fields: [(
                    "limit".to_owned(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::NumberValue(number)),
                    },
                )]
                .into(),
            };
            let value = struct_to_typed_json_value(&proto).unwrap();
            assert!(serde_json::from_value::<u64>(value["limit"].clone()).is_err());
        }
        let below_i64_min = prost_types::Struct {
            fields: [(
                "limit".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(
                        -9_223_372_036_854_777_856.0,
                    )),
                },
            )]
            .into(),
        };
        let value = struct_to_typed_json_value(&below_i64_min).unwrap();
        assert!(serde_json::from_value::<i64>(value["limit"].clone()).is_err());
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    struct TestConfig {
        #[serde(
            default,
            deserialize_with = "deserialize_optional_non_empty_string_list"
        )]
        devices: Option<Vec<String>>,
    }

    #[test]
    fn optional_non_empty_string_list_defaults_when_absent() {
        let config: TestConfig = serde_json::from_value(serde_json::json!({})).unwrap();

        assert_eq!(config.devices, None);
    }

    #[test]
    fn optional_non_empty_string_list_parses_present_list() {
        let config: TestConfig =
            serde_json::from_value(serde_json::json!({"devices": ["nvidia.com/gpu=0"]})).unwrap();

        assert_eq!(config.devices, Some(vec!["nvidia.com/gpu=0".to_string()]));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_list() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": []})).unwrap_err();

        assert!(err.to_string().contains("non-empty list"));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_string() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": [""]})).unwrap_err();

        assert!(err.to_string().contains("non-empty string"));
    }
}
